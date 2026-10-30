//! Native cohort acceptance uses the same held pipe reads on every backend.
#![cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]

mod coordination_support;

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use coordination_support::native::{Completion, Error, Scope};
use tree_fucker::coordination::authority::{self, Budget, Config, Origin, Request};
use tree_fucker::coordination::protocol::{self, Limits, Work};

const TIMEOUT: Duration = Duration::from_secs(60);
const WORKERS: usize = 20;
// Keep each twenty-process history concurrent within one authority without
// multiplying the machine's process load by libtest's test-thread count.
static COHORT: Mutex<()> = Mutex::new(());

fn config() -> Config {
    let budget = Budget { refill_ns_per_second: 1_000_000_000, burst_ns: 10_000_000_000 };
    Config {
        ownership: Limits { participants: 32, operations: 64, physical: 2 },
        domains: 64,
        background: budget,
        foreground: budget,
        domain_background: budget,
        domain_foreground: budget,
        bootstrap_ns: 10_000_000_000,
        per_domain_physical: 2,
        initial_estimate_ns: 1_000,
        stuck_after_ns: 1_000_000_000,
        failure_surcharge_ns: 1_000,
    }
}

fn request(work: Work) -> Request {
    Request { work, origin: Origin::Foreground, domain: None, required: 1, desired: 0, ceiling_ns: u64::MAX }
}

fn worker_scope(root: &Path, index: usize) -> Arc<Scope> {
    fs::write(root.join(format!("opening-{index}")), []).unwrap();
    let scope = retry(|| Scope::open(root.join("scope"), config()));
    fs::write(root.join(format!("opened-{index}")), []).unwrap();
    scope
}

fn retry<T>(mut operation: impl FnMut() -> Result<T, Error>) -> T {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match operation() {
            Ok(result) => return result,
            Err(Error::Busy) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(Error::Io(ref error)) if error.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("coordination failed: {error}"),
        }
    }
}

fn wait_for(root: &Path, prefix: &str, count: usize) {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if markers(root, prefix) >= count {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {count} {prefix} markers");
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn markers(root: &Path, prefix: &str) -> usize {
    fs::read_dir(root)
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
        .count()
}

fn counts(root: &Path, change: i64) -> (u64, u64) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join("physical-count"))
        .unwrap();
    // This independent test counter observes callback dispatch. It does not
    // consult the authority's occupancy or hold its bookkeeping lock.
    file.lock().unwrap();
    let mut bytes = [0; 16];
    if file.metadata().unwrap().len() != 0 {
        file.read_exact(&mut bytes).unwrap();
    }
    let current = u64::from_le_bytes(bytes[..8].try_into().unwrap()).checked_add_signed(change).unwrap();
    let maximum = u64::from_le_bytes(bytes[8..].try_into().unwrap()).max(current);
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&current.to_le_bytes()).unwrap();
    file.write_all(&maximum.to_le_bytes()).unwrap();
    file.unlock().unwrap();
    (current, maximum)
}

fn held_read(root: &Path, index: usize) {
    let (current, _) = counts(root, 1);
    assert!(current <= 2, "more than two filesystem callbacks physically dispatched");
    fs::write(root.join(format!("started-{index}")), []).unwrap();
    // Stdio::piped gives each independently launched child a kernel pipe.
    // This read remains blocked in read(2)/ReadFile until the parent writes.
    std::io::stdin().lock().read_exact(&mut [0]).unwrap();
    counts(root, -1);
}

#[test]
#[ignore = "native-operation subprocess fixture launched by cohort acceptance"]
fn physical_process_fixture() {
    let root = std::env::var_os("TF_COORDINATION_FIXTURE").expect("fixture root");
    let root = Path::new(&root);
    let index: usize = std::env::var("TF_COORDINATION_INDEX").unwrap().parse().unwrap();
    let scope = worker_scope(root, index);
    let client = retry(|| scope.join());
    let work = match index % 3 {
        0 => Work::Bootstrap,
        1 => Work::LazyRead,
        _ => Work::WatchRelease,
    };
    let mut prepared = retry(|| client.prepare(request(work)));
    fs::write(root.join(format!("joined-{index}")), []).unwrap();
    wait_for(root, "dispatch", 1);
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match prepared.try_run(|admission| {
            assert_eq!(admission.operations, 1);
            held_read(root, index);
            Completion { value: (), operations: 1, failed: false }
        }) {
            Ok(()) => return,
            Err(
                Error::Busy
                | Error::Authority(
                    authority::Error::Protocol(protocol::Error::PhysicalCapacity) | authority::Error::DomainPhysical,
                ),
            ) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
            Err(error) => panic!("physical admission failed: {error}"),
        }
    }
}

#[test]
#[ignore = "real Scan subprocess fixture launched by cohort acceptance"]
fn scan_process_fixture() {
    use tree_fucker::{HostConfig, HostGovernor, LoadAll, Scan, ScanEvent, ScanOptions, SystemClock};

    let root = std::env::var_os("TF_COORDINATION_FIXTURE").expect("fixture root");
    let root = Path::new(&root);
    let index: usize = std::env::var("TF_COORDINATION_INDEX").unwrap().parse().unwrap();
    let scope = worker_scope(root, index);
    let host = retry(|| HostGovernor::with_coordination(&HostConfig::default(), scope.clone()));
    let directory = root.join(format!("tree-{index}"));
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("leaf"), b"data").unwrap();
    let mut scan = Scan::open_outside_host_governor(
        Arc::new(tree_fucker::std_fs::StdFileSystem::new()),
        directory,
        Arc::new(LoadAll),
        ScanOptions { ceiling: Duration::MAX, ..ScanOptions::default() },
        host.clone(),
        Arc::new(SystemClock),
    )
    .unwrap();
    let ScanEvent::Entry(entry) = scan.next().unwrap().unwrap() else { panic!("root observation") };
    fs::write(root.join(format!("joined-{index}")), []).unwrap();
    wait_for(root, "dispatch", 1);
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match scan.read(&entry, |_| {
            held_read(root, index);
            Ok(())
        }) {
            Ok(()) => break,
            Err(tree_fucker::Error::Stuck) if Instant::now() < deadline => {
                // A scan reports shared quarantine instead of waiting forever.
                // The caller may explicitly retry after the stuck owner
                // settles.
                fs::write(root.join(format!("quarantined-{index}")), []).unwrap();
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("scan read failed: {error}"),
        }
    }
    assert!(host.coordination_error().is_none());
}

#[cfg(feature = "tokio")]
struct HeldFilesystem {
    inner: tree_fucker::testing::FakeFileSystem,
    root: std::path::PathBuf,
    index: usize,
}

#[cfg(feature = "tokio")]
impl tree_fucker::FileSystem for HeldFilesystem {
    fn capabilities(&self) -> tree_fucker::FsCapabilities {
        self.inner.capabilities()
    }

    fn canonicalize(&self, path: &Path) -> Result<std::path::PathBuf, tree_fucker::FsError> {
        if self.index % 3 == 0 {
            held_read(&self.root, self.index);
        }
        self.inner.canonicalize(path)
    }

    fn resolve_domain(
        &self,
        root: &Path,
        path: &tree_fucker::RelativePath,
        parent: Option<&tree_fucker::domain::ProbeResult>,
    ) -> Result<tree_fucker::domain::ProbeResult, tree_fucker::FsError> {
        self.inner.resolve_domain(root, path, parent)
    }

    fn metadata(
        &self,
        root: &Path,
        path: &tree_fucker::RelativePath,
    ) -> Result<tree_fucker::EntryInfo, tree_fucker::FsError> {
        self.inner.metadata(root, path)
    }

    fn open_listing(
        &self,
        root: &Path,
        path: &tree_fucker::RelativePath,
        ceilings: tree_fucker::Ceilings,
        cancel: tree_fucker::CancellationToken,
    ) -> Box<dyn tree_fucker::ListingSession> {
        self.inner.open_listing(root, path, ceilings, cancel)
    }

    fn enrich(
        &self,
        root: &Path,
        path: &tree_fucker::RelativePath,
        batch: &tree_fucker::EnrichmentBatch,
    ) -> Result<tree_fucker::Enrichment, tree_fucker::FsError> {
        self.inner.enrich(root, path, batch)
    }

    fn watch(
        &self,
        root: &Path,
        path: &tree_fucker::RelativePath,
        recursive: bool,
        sink: Arc<dyn tree_fucker::WatcherSink>,
    ) -> Result<tree_fucker::WatchId, tree_fucker::FsError> {
        self.inner.watch(root, path, recursive, sink)
    }

    fn unwatch(&self, watch: tree_fucker::WatchId) {
        held_read(&self.root, self.index);
        self.inner.unwatch(watch);
    }
}

#[test]
#[cfg(feature = "tokio")]
#[ignore = "mixed Scan and Tree subprocess fixture launched by the acceptance test"]
fn mixed_api_process_fixture() {
    use tree_fucker::{
        HostConfig, HostGovernor, LoadAll, Scan, ScanEvent, ScanOptions, SystemClock, Tree, WatcherKind,
    };
    let root = std::env::var_os("TF_COORDINATION_FIXTURE").expect("fixture root");
    let root = Path::new(&root);
    let index: usize = std::env::var("TF_COORDINATION_INDEX").unwrap().parse().unwrap();
    let scope = worker_scope(root, index);
    let host = retry(|| HostGovernor::with_coordination(&HostConfig::default(), scope.clone()));
    let filesystem = Arc::new(HeldFilesystem {
        inner: tree_fucker::testing::FakeFileSystem::new(WatcherKind::Recursive),
        root: root.to_path_buf(),
        index,
    });
    let ready = || {
        fs::write(root.join(format!("joined-{index}")), []).unwrap();
        wait_for(root, "dispatch", 1);
    };
    match index % 3 {
        0 => {
            ready();
            Scan::open_outside_host_governor(
                filesystem.clone(),
                filesystem.inner.root().to_path_buf(),
                Arc::new(LoadAll),
                ScanOptions { ceiling: Duration::MAX, ..ScanOptions::default() },
                host.clone(),
                Arc::new(SystemClock),
            )
            .unwrap();
        }
        1 => {
            let mut scan = Scan::open_outside_host_governor(
                filesystem.clone(),
                filesystem.inner.root().to_path_buf(),
                Arc::new(LoadAll),
                ScanOptions { ceiling: Duration::MAX, ..ScanOptions::default() },
                host.clone(),
                Arc::new(SystemClock),
            )
            .unwrap();
            let ScanEvent::Entry(entry) = scan.next().unwrap().unwrap() else { panic!("root observation") };
            ready();
            scan.read(&entry, |_| {
                held_read(root, index);
                Ok(())
            })
            .unwrap();
        }
        _ => {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
            let adapter = Arc::new(tree_fucker::runtime::TokioRuntime::new(runtime.handle().clone()));
            let (handle, _stream) = runtime
                .block_on(Tree::open_outside_host_governor(
                    filesystem.clone(),
                    filesystem.inner.root().to_path_buf(),
                    Arc::new(LoadAll),
                    tree_fucker::Config::default(),
                    adapter,
                    host.clone(),
                ))
                .unwrap();
            runtime.block_on(handle.initial_scan_complete()).unwrap();
            assert_eq!(filesystem.inner.watch_count(), 1);
            ready();
            runtime.block_on(handle.shutdown()).unwrap();
            runtime.block_on(async {
                let deadline = Instant::now() + Duration::from_secs(15);
                while filesystem.inner.watch_count() != 0 {
                    assert!(Instant::now() < deadline, "watch cleanup did not finish");
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            });
        }
    }
    assert!(host.coordination_error().is_none());
}

struct Children(Vec<Child>);

impl Children {
    fn wait_for(&mut self, root: &Path, prefix: &str, count: usize) {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if markers(root, prefix) >= count {
                return;
            }
            for child in &mut self.0 {
                assert!(child.try_wait().unwrap().is_none(), "worker exited before {prefix}");
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {count} {prefix} workers: {} ready, {} opening, {} opened",
                markers(root, prefix),
                markers(root, "opening-"),
                markers(root, "opened-"),
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn finish(&mut self) {
        let deadline = Instant::now() + TIMEOUT;
        for child in &mut self.0 {
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "cohort worker failed: {status}");
                    break;
                }
                assert!(Instant::now() < deadline, "cohort did not complete after release");
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
}

impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn twenty_independent_processes_hold_at_most_two_filesystem_calls() {
    twenty_processes("physical_process_fixture");
}

#[test]
fn twenty_real_scans_hold_at_most_two_lazy_filesystem_reads() {
    twenty_processes("scan_process_fixture");
}

#[test]
#[cfg(feature = "tokio")]
fn twenty_applications_share_bootstrap_lazy_read_and_watch_cleanup_capacity() {
    twenty_processes("mixed_api_process_fixture");
}

#[test]
fn killing_one_physical_owner_retains_the_other_and_recovers_only_its_slot() {
    let _cohort = COHORT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for fixture in [
        "physical_process_fixture",
        "scan_process_fixture",
        #[cfg(feature = "tokio")]
        "mixed_api_process_fixture",
    ] {
        let root = fixture_root();
        let mut children = Children((0..2).map(|index| spawn_worker(root.path(), index, fixture)).collect());
        children.wait_for(root.path(), "joined-", 2);
        fs::write(root.path().join("dispatch"), []).unwrap();
        children.wait_for(root.path(), "started-", 2);
        let scope = retry(|| Scope::open(root.path().join("scope"), config()));
        let generation = retry(|| scope.diagnostics()).generation;
        assert_eq!(counts(root.path(), 0), (2, 2));

        let mut victim = children.0.remove(0);
        victim.kill().unwrap();
        assert!(!victim.wait().unwrap().success());
        // No third caller exists until this confirmed process exit has been
        // reflected in the independent callback counter.
        assert_eq!(counts(root.path(), -1), (1, 2));
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let view = retry(|| scope.view());
            if view.physical == 1 {
                assert_eq!(view.participants, 1);
                break;
            }
            assert!(Instant::now() < deadline, "dead owner was not recovered");
            assert_eq!(view.physical, 2, "the surviving blocked call must retain ownership");
            std::thread::sleep(Duration::from_millis(2));
        }

        // A new process can consume the reclaimed slot while the survivor
        // remains blocked in its original call and retains the same authority.
        children.0.push(spawn_worker(root.path(), 2, fixture));
        children.wait_for(root.path(), "started-", 3);
        assert_eq!(retry(|| scope.view()).physical, 2);
        assert_eq!(counts(root.path(), 0), (2, 2));
        for child in &mut children.0 {
            child.stdin.take().unwrap().write_all(&[1]).unwrap();
        }
        children.finish();
        assert_eq!(counts(root.path(), 0), (0, 2));
        verify_retained(root.path(), scope, generation);
    }
}

fn fixture_root() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    builder.prefix("tree-fucker-cohort-");
    #[cfg(windows)]
    let root = builder.tempdir().unwrap();
    #[cfg(not(windows))]
    let root = builder.tempdir_in(coordination_support::RENDEZVOUS).unwrap();
    root
}

fn spawn_worker(root: &Path, index: usize, fixture: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", fixture, "--ignored", "--nocapture"])
        .env("TF_COORDINATION_FIXTURE", root)
        .env("TF_COORDINATION_INDEX", index.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

fn twenty_processes(fixture: &str) {
    let _cohort = COHORT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let root = fixture_root();
    // Children race through initial publication; the controller does not
    // pre-create an authority that would conceal first-join races.
    let mut children = Children((0..WORKERS).map(|index| spawn_worker(root.path(), index, fixture)).collect());
    children.wait_for(root.path(), "joined-", WORKERS);
    fs::write(root.path().join("dispatch"), []).unwrap();
    let scope = retry(|| Scope::open(root.path().join("scope"), config()));
    let generation = retry(|| scope.diagnostics()).generation;
    children.wait_for(root.path(), "started-", 2);
    assert_eq!(counts(root.path(), 0), (2, 2));
    // A stuck timeout cannot free the two physical pipe reads.
    std::thread::sleep(Duration::from_millis(1100));
    #[cfg(target_os = "linux")]
    if fixture == "scan_process_fixture" {
        // These native scans share a mount identity. Every waiting caller
        // must observe quarantine while the two original reads retain slots.
        children.wait_for(root.path(), "quarantined-", WORKERS - 2);
    }
    assert_eq!(retry(|| scope.view()).physical, 2);
    assert_eq!(counts(root.path(), 0), (2, 2));
    for child in &mut children.0 {
        child.stdin.take().unwrap().write_all(&[1]).unwrap();
    }
    children.finish();
    assert_eq!(markers(root.path(), "started-"), WORKERS, "each worker physically dispatched once");
    assert_eq!(counts(root.path(), 0), (0, 2));
    verify_retained(root.path(), scope, generation);
}

fn verify_retained(root: &Path, scope: Arc<Scope>, generation: protocol::Generation) {
    // Final-close recovery is bounded and can need several transactions to
    // retire every independently launched participant.
    let mut view = retry(|| scope.view());
    for _ in 0..8 {
        if view.participants == 0 && view.physical == 0 && view.prepared == 0 {
            break;
        }
        view = retry(|| scope.view());
    }
    assert_eq!((view.participants, view.physical, view.prepared), (0, 0, 0));
    assert!(view.charged_ns > 0);
    drop(scope);
    let reopened = retry(|| Scope::open(root.join("scope"), config()));
    assert_eq!(retry(|| reopened.diagnostics()).generation, generation);
    assert_eq!(retry(|| reopened.view()).charged_ns, view.charged_ns);
}
