#![cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos"))]

#[path = "coordination_support/fifo.rs"]
mod native_fifo;

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use coordination_support::native::{Completion, Error, Scope};
use rustix::fs::{FlockOperation, flock};
use tree_fucker::coordination::authority::{self, Budget, Config, Origin, Request};
use tree_fucker::coordination::protocol::{self, Limits, Work};

#[path = "coordination_processes/crashes.rs"]
mod crashes;

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

fn retry<T>(mut operation: impl FnMut() -> Result<T, Error>) -> T {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match operation() {
            Ok(result) => return result,
            Err(Error::Busy) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
            Err(error) => panic!("coordination failed: {error}"),
        }
    }
}

fn fixture() -> (tempfile::TempDir, Arc<Scope>) {
    let root = tempfile::Builder::new()
        .prefix("tree-fucker-coordination-")
        .tempdir_in(coordination_support::RENDEZVOUS)
        .unwrap();
    let scope = Scope::open(root.path().join("scope"), config()).unwrap();
    (root, scope)
}

#[test]
fn prepared_abort_and_last_participant_exit_preserve_accounting() {
    let (root, scope) = fixture();
    let client = retry(|| scope.join());
    let old = client.participant();
    drop(client.prepare(request(Work::Listing)).unwrap());
    assert_eq!(retry(|| scope.view()).prepared, 0);
    assert_eq!(retry(|| scope.view()).charged_ns, 0);
    client
        .prepare(request(Work::LazyRead))
        .unwrap()
        .try_run(|_| Completion { value: (), operations: 1, failed: false })
        .unwrap();
    let charged = retry(|| scope.view()).charged_ns;
    assert!(charged >= 1_000);
    drop(client);
    drop(scope);
    let replacement = Scope::open(root.path().join("scope"), config()).unwrap();
    let client = retry(|| replacement.join());
    assert_eq!(client.participant().generation, old.generation);
    assert_ne!(client.participant().incarnation, old.incarnation);
    assert_eq!(retry(|| replacement.view()).charged_ns, charged);
}

#[test]
fn replaced_state_or_directory_cannot_create_another_authority() {
    let (root, scope) = fixture();
    fs::rename(root.path().join("scope"), root.path().join("retained")).unwrap();
    assert!(matches!(scope.view(), Err(Error::Replaced)));
    assert!(matches!(Scope::open(root.path().join("scope"), config()), Err(Error::Replaced)));
    // The persistent anchor survives replacing the directory.
    assert!(root.path().join("scope.authority.lock").is_file());

    let (root, scope) = fixture();
    let state = root.path().join("scope/authority.state");
    fs::remove_file(&state).unwrap();
    assert!(matches!(scope.view(), Err(Error::Replaced)));
    assert!(matches!(Scope::open(root.path().join("scope"), config()), Err(Error::Replaced)));
    assert!(!state.exists());
}

#[test]
fn replaced_owner_is_not_proof_of_process_death() {
    let (root, scope) = fixture();
    let client = retry(|| scope.join());
    fs::remove_file(root.path().join(format!("scope/owner-{}", client.participant().slot))).unwrap();
    // Recovery rotates across bounded batches; it must encounter the missing
    // live owner's slot, never reclaim it as if its lock had been released.
    let mut rejected = false;
    for _ in 0..8 {
        if matches!(scope.view(), Err(Error::Replaced | Error::Failed)) {
            rejected = true;
            break;
        }
    }
    assert!(rejected);
}

#[test]
fn unsafe_permissions_and_configuration_disagreement_are_explicit() {
    let (root, _scope) = fixture();
    let mut other = config();
    other.ownership.physical = 3;
    assert!(matches!(Scope::open(root.path().join("scope"), other), Err(Error::Incompatible)));
    fs::set_permissions(root.path().join("scope"), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(Scope::open(root.path().join("scope"), config()), Err(Error::InvalidScope)));
}

#[test]
fn busy_bookkeeping_does_not_block_admission_or_drop() {
    let (root, scope) = fixture();
    let client = retry(|| scope.join());
    let prepared = client.prepare(request(Work::Listing)).unwrap();
    let anchor = OpenOptions::new().read(true).write(true).open(root.path().join("scope.authority.lock")).unwrap();
    flock(&anchor, FlockOperation::LockExclusive).unwrap();
    let started = Instant::now();
    let before = scope.diagnostics().unwrap().access;
    assert!(matches!(client.prepare(request(Work::Listing)), Err(Error::Busy)));
    let denied = scope.diagnostics().unwrap().access;
    assert_eq!(denied.attempts, before.attempts + 1);
    assert_eq!(denied.busy, before.busy + 1);
    assert_eq!(denied.acquired, before.acquired);
    drop(prepared);
    assert!(started.elapsed() < Duration::from_secs(1));
    flock(&anchor, FlockOperation::Unlock).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while retry(|| scope.view()).prepared != 0 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn unwind_settles_physical_ownership_and_keeps_failure_charge() {
    let (_root, scope) = fixture();
    let client = retry(|| scope.join());
    let mut prepared = client.prepare(request(Work::LazyRead)).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), Error> = prepared.try_run(|_| panic!("physical callback failed"));
    }));
    assert!(result.is_err());
    let view = retry(|| scope.view());
    assert_eq!(view.physical, 0);
    assert!(view.surcharged_ns > 0);
}

#[test]
fn duplicated_description_keeps_its_lock_after_original_and_unrelated_closes() {
    let (root, scope) = fixture();
    let client = scope.join().unwrap();
    let path = root.path().join("scope.authority.lock");
    let original = OpenOptions::new().read(true).write(true).open(&path).unwrap();
    flock(&original, FlockOperation::LockExclusive).unwrap();
    let duplicate = original.try_clone().unwrap();
    drop(original);
    drop(OpenOptions::new().read(true).write(true).open(&path).unwrap());
    assert!(matches!(client.prepare(request(Work::LazyRead)), Err(Error::Busy)));
    drop(duplicate);
    drop(retry(|| client.prepare(request(Work::LazyRead))));
    let view = retry(|| scope.view());
    assert_eq!((view.prepared, view.physical, view.charged_ns), (0, 0, 0));
}

#[test]
fn invalid_completion_fences_the_connection_instead_of_returning_success() {
    let (_root, scope) = fixture();
    let client = scope.join().unwrap();
    let mut prepared = client.prepare(request(Work::LazyRead)).unwrap();
    assert!(matches!(
        prepared.try_run(|_| Completion { value: (), operations: 2, failed: false }),
        Err(Error::Authority(authority::Error::Protocol(protocol::Error::InvalidProgress)))
    ));
    assert!(scope.diagnostics().unwrap().failed);
    assert!(matches!(scope.view(), Err(Error::Failed)));
}

#[test]
fn actual_debt_survives_closing_every_handle_and_reopening() {
    let root =
        tempfile::Builder::new().prefix("tree-fucker-debt-").tempdir_in(coordination_support::RENDEZVOUS).unwrap();
    let mut cfg = config();
    let budget = Budget { refill_ns_per_second: 1, burst_ns: 1_000_000 };
    cfg.background = budget;
    cfg.foreground = budget;
    cfg.domain_background = budget;
    cfg.domain_foreground = budget;
    let scope = Scope::open(root.path().join("scope"), cfg).unwrap();
    let client = scope.join().unwrap();
    client
        .prepare(request(Work::LazyRead))
        .unwrap()
        .try_run(|_| {
            std::thread::sleep(Duration::from_millis(5));
            Completion { value: (), operations: 1, failed: false }
        })
        .unwrap();
    let debt = scope.view().unwrap().foreground_level_ns;
    assert!(debt < 0);
    drop(client);
    drop(scope);
    let scope = Scope::open(root.path().join("scope"), cfg).unwrap();
    let client = scope.join().unwrap();
    assert_eq!(scope.view().unwrap().foreground_level_ns, debt);
    assert!(matches!(client.prepare(request(Work::LazyRead)), Err(Error::Authority(authority::Error::Budget))));
}

#[test]
fn only_unpublished_initialization_can_be_reinitialized() {
    let (root, scope) = fixture();
    drop(scope);
    let mut anchor = OpenOptions::new().read(true).write(true).open(root.path().join("scope.authority.lock")).unwrap();
    anchor.seek(SeekFrom::Start(12)).unwrap();
    anchor.write_all(&[0x5a]).unwrap(); // Crash before the final READY byte.
    let state = root.path().join("scope/authority.state");
    OpenOptions::new().write(true).open(&state).unwrap().set_len(35).unwrap();
    let scope = Scope::open(root.path().join("scope"), config()).unwrap();
    assert_eq!(scope.view().unwrap().charged_ns, 0);
    drop(scope);
    // Identical damage after READY must never reset accounting.
    OpenOptions::new().write(true).open(&state).unwrap().set_len(35).unwrap();
    assert!(matches!(Scope::open(root.path().join("scope"), config()), Err(Error::Journal(_))));
    assert_eq!(fs::metadata(&state).unwrap().len(), 35);
}

#[test]
fn preparing_anchor_never_discards_an_existing_committed_account() {
    let (root, scope) = fixture();
    let client = scope.join().unwrap();
    client
        .prepare(request(Work::LazyRead))
        .unwrap()
        .try_run(|_| Completion { value: (), operations: 1, failed: false })
        .unwrap();
    let charged = scope.view().unwrap().charged_ns;
    drop(client);
    drop(scope);
    let mut anchor = OpenOptions::new().write(true).open(root.path().join("scope.authority.lock")).unwrap();
    anchor.seek(SeekFrom::Start(12)).unwrap();
    anchor.write_all(&[0x5a]).unwrap();
    let scope = Scope::open(root.path().join("scope"), config()).unwrap();
    assert_eq!(scope.view().unwrap().charged_ns, charged);
}

struct Children(Vec<Child>);

impl Drop for Children {
    fn drop(&mut self) {
        // Ensure failed assertions cannot leave blocked test subprocesses.
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn spawn(root: &Path, index: usize) -> Child {
    spawn_fixture(root, index, "physical_process_fixture")
}

fn spawn_fixture(root: &Path, index: usize, fixture: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", fixture, "--ignored", "--nocapture"])
        .env("TF_COORDINATION_FIXTURE", root)
        .env("TF_COORDINATION_INDEX", index.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

#[test]
#[ignore = "real Scan subprocess fixture launched by the acceptance test"]
fn scan_process_fixture() {
    use tree_fucker::{HostConfig, HostGovernor, LoadAll, Scan, ScanEvent, ScanOptions, SystemClock};

    let root = std::env::var_os("TF_COORDINATION_FIXTURE").expect("fixture root");
    let root = Path::new(&root);
    let index: usize = std::env::var("TF_COORDINATION_INDEX").unwrap().parse().unwrap();
    let scope = retry(|| Scope::open(root.join("scope"), config()));
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
    let ScanEvent::Entry(entry) = scan.next().unwrap().unwrap() else {
        panic!("root observation");
    };
    fs::write(root.join(format!("joined-{index}")), []).unwrap();
    wait_for(root, "dispatch", 1);
    scan.read(&entry, |_| {
        let mut gate = File::open(root.join(format!("gate-{index}"))).unwrap();
        let (current, _) = counts(root, 1);
        assert!(current <= 2, "more than two Scan callbacks physically dispatched");
        fs::write(root.join(format!("started-{index}")), []).unwrap();
        gate.read_exact(&mut [0]).unwrap();
        counts(root, -1);
        Ok(())
    })
    .unwrap();
    assert!(host.coordination_error().is_none());
}

fn fifo(root: &Path, index: usize) -> File {
    let path = root.join(format!("gate-{index}"));
    native_fifo::create(&path).unwrap();
    // Keep both ends open: children block in read(2), not on test setup.
    OpenOptions::new().read(true).write(true).open(path).unwrap()
}

fn counts(root: &Path, change: i64) -> (u64, u64) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(root.join("physical-count"))
        .unwrap();
    flock(&file, FlockOperation::LockExclusive).unwrap();
    let mut bytes = [0; 16];
    if file.metadata().unwrap().len() != 0 {
        file.read_exact(&mut bytes).unwrap();
    }
    let current = u64::from_le_bytes(bytes[..8].try_into().unwrap()).checked_add_signed(change).unwrap();
    let maximum = u64::from_le_bytes(bytes[8..].try_into().unwrap()).max(current);
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&current.to_le_bytes()).unwrap();
    file.write_all(&maximum.to_le_bytes()).unwrap();
    flock(&file, FlockOperation::Unlock).unwrap();
    (current, maximum)
}

fn held_read(root: &Path, index: usize) {
    let mut gate = File::open(root.join(format!("gate-{index}"))).unwrap();
    let (current, _) = counts(root, 1);
    assert!(current <= 2, "more than two filesystem callbacks physically dispatched");
    fs::write(root.join(format!("started-{index}")), []).unwrap();
    gate.read_exact(&mut [0]).unwrap();
    counts(root, -1);
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
    let scope = retry(|| Scope::open(root.join("scope"), config()));
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

#[test]
#[ignore = "subprocess fixture launched by the acceptance tests"]
fn physical_process_fixture() {
    let root = std::env::var_os("TF_COORDINATION_FIXTURE").expect("fixture root");
    let root = Path::new(&root);
    let index: usize = std::env::var("TF_COORDINATION_INDEX").unwrap().parse().unwrap();
    let scope = retry(|| Scope::open(root.join("scope"), config()));
    let client = retry(|| scope.join());
    let work = match index % 3 {
        0 => Work::Bootstrap,
        1 => Work::LazyRead,
        _ => Work::WatchRelease,
    };
    let mut prepared = retry(|| client.prepare(request(work)));
    fs::write(root.join(format!("joined-{index}")), []).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let result = prepared.try_run(|admission| {
            assert_eq!(admission.operations, 1);
            let mut fifo = File::open(root.join(format!("gate-{index}"))).unwrap();
            let (current, _) = counts(root, 1);
            assert!(current <= 2, "more than two callbacks physically dispatched");
            fs::write(root.join(format!("started-{index}")), []).unwrap();
            let mut byte = [0];
            fifo.read_exact(&mut byte).unwrap(); // Actual held filesystem call.
            counts(root, -1);
            Completion { value: (), operations: 1, failed: false }
        });
        match result {
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

fn wait_for(root: &Path, prefix: &str, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let found = fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
            .count();
        if found >= count {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {count} {prefix} files; got {found}");
        std::thread::sleep(Duration::from_millis(2));
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

fn twenty_processes(fixture: &str) {
    // No process pre-creates the authority: this also exercises racing joins
    // through the same initial anchor and journal publication.
    let root =
        tempfile::Builder::new().prefix("tree-fucker-creation-").tempdir_in(coordination_support::RENDEZVOUS).unwrap();
    let mut gates: Vec<_> = (0..20).map(|index| fifo(root.path(), index)).collect();
    let mut children = Children((0..20).map(|index| spawn_fixture(root.path(), index, fixture)).collect());
    wait_for(root.path(), "joined-", 20);
    fs::write(root.path().join("dispatch"), []).unwrap();
    let scope = retry(|| Scope::open(root.path().join("scope"), config()));
    wait_for(root.path(), "started-", 2);
    assert_eq!(counts(root.path(), 0), (2, 2));
    // Crossing the stuck threshold must not release the physical slots.
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(retry(|| scope.view()).physical, 2);
    assert_eq!(counts(root.path(), 0), (2, 2));
    for gate in &mut gates {
        gate.write_all(&[1]).unwrap();
    }
    for child in &mut children.0 {
        assert!(child.wait().unwrap().success());
    }
    assert_eq!(counts(root.path(), 0), (0, 2));
    // A process may exit with a queued settlement. All lifetime handles have
    // closed after wait(), but bounded recovery need not visit its slot on
    // the very first access.
    for _ in 0..8 {
        let view = retry(|| scope.view());
        if view.physical == 0 && view.prepared == 0 {
            break;
        }
    }
    let view = retry(|| scope.view());
    assert_eq!(view.physical, 0);
    assert_eq!(view.prepared, 0);
}

#[test]
#[ignore = "bounded recovery fixture launched by the acceptance test"]
fn abandoned_preparations_fixture() {
    let root = std::env::var_os("TF_COORDINATION_FIXTURE").expect("fixture root");
    let scope = Scope::open(Path::new(&root).join("scope"), config()).unwrap();
    let client = scope.join().unwrap();
    let preparations: Vec<_> = (0..16).map(|_| client.prepare(request(Work::Listing)).unwrap()).collect();
    assert_eq!(preparations.len(), 16);
    // Abrupt process exit, with no Prepared or participant destructors.
    std::process::exit(0);
}

#[test]
fn owner_recovery_retires_only_a_bounded_batch_per_access() {
    let (root, scope) = fixture();
    let mut children = Children(vec![
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "abandoned_preparations_fixture", "--ignored", "--nocapture"])
            .env("TF_COORDINATION_FIXTURE", root.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    ]);
    assert!(children.0[0].wait().unwrap().success());
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut remaining = 16;
    let view = loop {
        let view = retry(|| scope.view());
        assert!(view.prepared <= remaining);
        assert!(remaining - view.prepared <= 8, "one access exceeded the recovery batch");
        remaining = view.prepared;
        if remaining == 0 {
            break view;
        }
        // Recovery requires a successful lifetime-lock acquisition. Counting
        // tight polling iterations does not give other processes time to close
        // inherited descriptions, including close-on-exec ones during spawn.
        assert!(Instant::now() < deadline, "abandoned preparations were not recovered");
        std::thread::sleep(Duration::from_millis(2));
    };
    assert_eq!(view.participants, 0);
    assert_eq!(view.charged_ns, 0);
}

#[test]
fn killed_blocked_owner_is_recovered_by_kernel_lifetime_evidence() {
    let (root, scope) = fixture();
    let _gate = fifo(root.path(), 0);
    let mut children = Children(vec![spawn(root.path(), 0)]);
    wait_for(root.path(), "started-", 1);
    assert_eq!(retry(|| scope.view()).physical, 1);
    children.0[0].kill().unwrap();
    assert!(!children.0[0].wait().unwrap().success());
    for _ in 0..8 {
        if retry(|| scope.view()).physical == 0 {
            break;
        }
    }
    let view = retry(|| scope.view());
    assert_eq!(view.physical, 0);
    assert!(view.charged_ns > 0);
    assert!(view.surcharged_ns > 0);
}

#[test]
fn suspended_owner_keeps_its_physical_permission() {
    let (root, scope) = fixture();
    let _gate = fifo(root.path(), 0);
    let mut children = Children(vec![spawn(root.path(), 0)]);
    wait_for(root.path(), "started-", 1);
    let pid = rustix::process::Pid::from_raw(children.0[0].id() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::STOP).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(retry(|| scope.view()).physical, 1);
    rustix::process::kill_process(pid, rustix::process::Signal::CONT).unwrap();
    children.0[0].kill().unwrap();
    children.0[0].wait().unwrap();
}

#[test]
#[ignore = "fork lifetime fixture launched by the acceptance test"]
fn inherited_owner_fixture() {
    let root = std::env::var_os("TF_COORDINATION_FIXTURE").expect("fixture root");
    let root = Path::new(&root);
    let scope = retry(|| Scope::open(root.join("scope"), config()));
    let client = retry(|| scope.join());
    let mut child_gate = File::open(root.join("gate-1")).unwrap();
    let mut parent_gate = File::open(root.join("gate-0")).unwrap();
    let mut prepared = client.prepare(request(Work::LazyRead)).unwrap();
    prepared
        .try_run(|_| {
            // The fork child performs only the PID rejection and
            // async-signal-safe syscalls. No inherited mutex,
            // allocator, or Rust destructor is used.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                if !matches!(scope.view(), Err(Error::Forked)) {
                    unsafe { libc::_exit(91) };
                }
                let mut byte = 0u8;
                unsafe {
                    libc::read(child_gate.as_raw_fd(), (&mut byte as *mut u8).cast(), 1);
                    libc::_exit(0);
                }
            }
            fs::write(root.join("descendant"), pid.to_string()).unwrap();
            let mut byte = [0];
            parent_gate.read_exact(&mut byte).unwrap();
            // Normally unreachable: the acceptance parent kills this process.
            child_gate.read_exact(&mut byte).unwrap();
            Completion { value: (), operations: 1, failed: false }
        })
        .unwrap();
}

#[test]
fn inherited_description_prevents_reclamation_after_original_owner_dies() {
    let (root, scope) = fixture();
    let _parent_gate = fifo(root.path(), 0);
    let mut child_gate = fifo(root.path(), 1);
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "inherited_owner_fixture", "--ignored", "--nocapture"])
        .env("TF_COORDINATION_FIXTURE", root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut children = Children(vec![child]);
    wait_for(root.path(), "descendant", 1);
    // Releasing the inherited FIFO wakes exactly this descendant, including
    // during assertion unwinding. This avoids signalling a reusable PID and
    // works on both native backends without a platform-specific process handle.
    struct Descendant(File);
    impl Drop for Descendant {
        fn drop(&mut self) {
            let _ = self.0.write_all(&[1]);
        }
    }
    let _descendant = Descendant(child_gate.try_clone().unwrap());
    children.0[0].kill().unwrap();
    children.0[0].wait().unwrap();
    for _ in 0..8 {
        assert_eq!(retry(|| scope.view()).physical, 1, "inherited lifetime handle must still fence recovery");
    }
    child_gate.write_all(&[1]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while retry(|| scope.view()).physical != 0 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos"))]
mod coordination_support;
