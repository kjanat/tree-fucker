//! Completion, cancellation and failure through the public composed Scan, Tree
//! and HostGovernor APIs.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Condvar, Mutex};
use std::time::Instant;

use tree_fucker::coordination::authority::View;
use tree_fucker::core::{Command, JobResult, Work};
use tree_fucker::testing::{FakeFileSystem, FakeOp, Harness};
use tree_fucker::{
    CancellationToken, Ceilings, Clock, Continuation, Enrichment, EnrichmentBatch, EntryInfo, Error, FileSystem,
    FsCapabilities, FsError, Lease, ListingExecutor, ListingSession, LoadAll, ProbeResult, Scan, ScanEvent,
    ScanOptions, SessionCost, SessionOutcome, SessionStep, SystemClock, WatchId, WatcherKind, WatcherSink,
};

use super::*;

const TIMEOUT: Duration = Duration::from_secs(15);
/// `failure_surcharge_ns` configured by `fixture`.
const SHARED_SURCHARGE: u128 = 1_000;

fn local_surcharge() -> Duration {
    host_config().failure_surcharge
}

/// Waits for deferred settlement, then reads the committed authority.
fn drained(scope: &Scope) -> View {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let diagnostics = scope.diagnostics().unwrap();
        assert!(!diagnostics.failed);
        if diagnostics.pending_settlements == 0 && !diagnostics.bookkeeping_active {
            match scope.view() {
                Ok(view) => return view,
                Err(coordination_support::native::Error::Busy) => {}
                Err(error) => panic!("authority could not be inspected: {error}"),
            }
        }
        assert!(Instant::now() < deadline, "deferred settlement did not drain");
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn eventually(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !condition() {
        assert!(Instant::now() < deadline, "condition did not become true");
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Barriers establish physical start and completion; timeouts only bound a
/// broken test.
struct Gate {
    entered: Sender<()>,
    released: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn new() -> (Arc<Self>, Receiver<()>) {
        let (entered, receiver) = mpsc::channel();
        (Arc::new(Self { entered, released: Mutex::new(false), changed: Condvar::new() }), receiver)
    }

    fn wait(&self) {
        self.entered.send(()).expect("start notification");
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.changed.wait(released).unwrap();
        }
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

/// Opens the gate even when an assertion unwinds, so no worker stays blocked.
struct Release(Arc<Gate>);

impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct GatedSession {
    inner: Box<dyn ListingSession>,
    gate: Arc<Gate>,
}

impl ListingSession for GatedSession {
    fn resume(self: Box<Self>, lease: Lease) -> (Continuation, SessionCost) {
        self.gate.wait();
        self.inner.resume(lease)
    }
}

/// Blocks the first physical listing of `a` inside its adapter call.
struct GatedListing {
    inner: Arc<FakeFileSystem>,
    gate: Arc<Gate>,
}

impl FileSystem for GatedListing {
    fn capabilities(&self) -> FsCapabilities {
        self.inner.capabilities()
    }
    fn canonicalize(&self, root: &Path) -> Result<PathBuf, FsError> {
        self.inner.canonicalize(root)
    }
    fn resolve_domain(
        &self,
        root: &Path,
        path: &RelativePath,
        parent: Option<&ProbeResult>,
    ) -> Result<ProbeResult, FsError> {
        self.inner.resolve_domain(root, path, parent)
    }
    fn metadata(&self, root: &Path, path: &RelativePath) -> Result<EntryInfo, FsError> {
        self.inner.metadata(root, path)
    }
    fn open_listing(
        &self,
        root: &Path,
        path: &RelativePath,
        ceilings: Ceilings,
        cancel: CancellationToken,
    ) -> Box<dyn ListingSession> {
        let inner = self.inner.open_listing(root, path, ceilings, cancel);
        match path.to_string() == "a" {
            true => Box::new(GatedSession { inner, gate: self.gate.clone() }),
            false => inner,
        }
    }
    fn enrich(&self, root: &Path, path: &RelativePath, batch: &EnrichmentBatch) -> Result<Enrichment, FsError> {
        self.inner.enrich(root, path, batch)
    }
    fn watch(
        &self,
        root: &Path,
        path: &RelativePath,
        recursive: bool,
        sink: Arc<dyn WatcherSink>,
    ) -> Result<WatchId, FsError> {
        self.inner.watch(root, path, recursive, sink)
    }
    fn unwatch(&self, watch: WatchId) {
        self.inner.unwatch(watch);
    }
}

/// RFC section 13.1 charges a cancelled attempt one surcharge. A session that
/// completes its physical listing after logical cancellation reports no
/// failure; one that observes the token returns `Cancelled` and is charged.
/// An executor lets the Scan return before the adapter does. Inline execution
/// runs the adapter on the Scan's own thread, so its result waits for it.
#[test]
fn cancelling_a_running_composed_scan_listing_keeps_both_slots_until_physical_completion() {
    for (executor, observes_cancellation) in [(true, false), (true, true), (false, false), (false, true)] {
        let context = format!("executor={executor} observes={observes_cancellation}");
        let (_root, scope) = fixture();
        let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
        let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
        fs.mkdir("a");
        fs.create_file("a/x", 1);
        fs.ignore_cancellation(!observes_cancellation);
        let (gate, entered) = Gate::new();
        let release = Release(gate.clone());
        let scan = Scan::open_outside_host_governor(
            Arc::new(GatedListing { inner: fs.clone(), gate }),
            fs.root().to_path_buf(),
            Arc::new(LoadAll),
            ScanOptions { ceiling: Duration::MAX, ..ScanOptions::default() },
            host.clone(),
            Arc::new(SystemClock),
        )
        .unwrap();
        let cancel = scan.cancellation();
        let (done, results) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut scan = match executor {
                true => scan.with_listing_executor(ListingExecutor::new(2).unwrap()),
                false => scan,
            };
            let result = scan.by_ref().collect::<Result<Vec<_>, _>>();
            drop(scan);
            done.send(result).unwrap();
        });
        entered.recv_timeout(TIMEOUT).expect("gated listing started physically");
        assert_eq!(host.view(NOW).in_flight, 1, "{context}");
        assert_eq!(scope.view().unwrap().physical, 1, "{context}");
        cancel.cancel();
        let inline_worker = if executor {
            let result = results.recv_timeout(TIMEOUT).expect("logical cancellation must not wait for the adapter");
            assert!(matches!(result, Err(Error::Cancelled)), "{context}: {result:?}");
            worker.join().unwrap();
            None
        } else {
            // The gate is still closed, so the adapter call on the Scan's own
            // thread has not returned and that thread cannot have sent a
            // result.
            assert!(matches!(results.try_recv(), Err(mpsc::TryRecvError::Empty)), "{context}");
            Some(worker)
        };
        // The adapter call is still blocked: neither authority may reuse its
        // slot.
        assert_eq!(host.view(NOW).in_flight, 1, "{context}");
        let held = scope.view().unwrap();
        assert_eq!((held.physical, held.prepared, held.surcharged_ns), (1, 0, 0), "{context}");
        assert_eq!(host.view(NOW).surcharged, Duration::ZERO, "{context}");
        drop(release);
        if let Some(worker) = inline_worker {
            let result = results.recv_timeout(TIMEOUT).expect("inline listing returns after physical completion");
            assert!(matches!(result, Err(Error::Cancelled)), "{context}: {result:?}");
            worker.join().unwrap();
        }
        eventually(|| host.grants().is_empty());
        let local = host.view(NOW);
        let shared = drained(&scope);
        assert_eq!((local.in_flight, local.preparations), (0, 0), "{context}");
        assert_eq!((shared.physical, shared.prepared), (0, 0), "{context}");
        let (local_expected, shared_expected) = match observes_cancellation {
            true => (local_surcharge(), SHARED_SURCHARGE),
            false => (Duration::ZERO, 0),
        };
        assert_eq!(local.surcharged, local_expected, "{context}");
        assert_eq!(shared.surcharged_ns, shared_expected, "{context}");
        assert!(host.coordination_error().is_none());
    }
}

/// Signals each entry into a Scan wait so the test acts only once the scan is
/// provably waiting.
struct NotifyingClock(Sender<()>);

impl Clock for NotifyingClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, duration: Duration) {
        let _ = self.0.send(());
        std::thread::sleep(duration.min(Duration::from_millis(10)));
    }
    fn wait_for_change(&self, host: &HostGovernor, seen: u64, timeout: Duration) {
        let _ = self.0.send(());
        host.wait_for_change(seen, timeout.min(Duration::from_millis(10)));
    }
}

#[test]
fn cancelling_a_scan_waiting_for_peer_physical_capacity_retires_its_preparations_uncharged() {
    let (root, _) = fixture();
    let local = host_config();
    let mut config = Config::from_host(&local, 8, 16, 16).unwrap();
    config.ownership.physical = 1;
    config.per_domain_physical = 1;
    // A one-hour shared price keeps the peer's real occupancy below its
    // reservation, so cumulative shared charges are stable while it waits.
    let hour = 3_600_000_000_000;
    config.initial_estimate_ns = hour;
    config.bootstrap_ns = 100 * hour;
    for budget in
        [&mut config.background, &mut config.foreground, &mut config.domain_background, &mut config.domain_foreground]
    {
        budget.burst_ns = 100 * hour;
    }
    config.failure_surcharge_ns = 1_000;
    let scope = Scope::open(root.path().join("capacity"), config).unwrap();
    let host = HostGovernor::with_coordination(&local, scope.clone()).unwrap();
    let peer = HostGovernor::with_coordination(&local, scope.clone()).unwrap();
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.create_file("file", 1);
    let (waiting, waits) = mpsc::channel();
    let mut scan = Scan::open_outside_host_governor(
        fs.clone(),
        fs.root().to_path_buf(),
        Arc::new(LoadAll),
        ScanOptions { ceiling: Duration::MAX, ..ScanOptions::default() },
        host.clone(),
        Arc::new(NotifyingClock(waiting)),
    )
    .unwrap()
    .with_listing_executor(ListingExecutor::new(1).unwrap());
    let Some(Ok(ScanEvent::Entry(entry))) = scan.next() else { panic!("root entry") };
    assert!(entry.path.path().is_root());
    while waits.try_recv().is_ok() {}
    let held = request(&peer);
    peer.try_admit(held.clone(), NOW).unwrap();
    peer.try_start(held.id, NOW).unwrap();
    let cancel = scan.cancellation();
    let (done, results) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = scan.next();
        drop(scan);
        done.send(result).unwrap();
    });
    waits.recv_timeout(TIMEOUT).expect("scan entered the physical-capacity wait");
    assert_eq!(fs.count_ops(FakeOp::ReadDir, ""), 0, "the root listing must not have started");
    assert_eq!(host.view(NOW).preparations, 1);
    // The waiting Scan can retry admission concurrently with this observation.
    // Bookkeeping contention is expected and must not make the test flaky.
    let waiting = drained(&scope);
    assert_eq!((waiting.prepared, waiting.physical), (1, 1));
    let local_charged = host.view(NOW).charged;
    cancel.cancel();
    let result = results.recv_timeout(TIMEOUT).expect("cancellation must end the wait");
    assert!(matches!(result, Some(Err(Error::Cancelled))), "{result:?}");
    worker.join().unwrap();
    let local = host.view(NOW);
    let shared = drained(&scope);
    assert_eq!((local.preparations, local.in_flight), (0, 0));
    assert_eq!(local.charged, local_charged, "the unstarted listing must not be charged locally");
    assert_eq!(local.surcharged, Duration::ZERO);
    assert_eq!((shared.prepared, shared.physical), (0, 1));
    assert_eq!(shared.charged_ns, waiting.charged_ns, "the unstarted listing must not be charged by the authority");
    assert_eq!(shared.surcharged_ns, 0);
    assert_eq!(fs.count_ops(FakeOp::ReadDir, ""), 0);
    peer.release(held.id, NOW);
    let settled = drained(&scope);
    assert_eq!((settled.prepared, settled.physical, settled.surcharged_ns), (0, 0, 0));
    assert!(host.coordination_error().is_none());
}

/// Dropping the last governor clone drops its physical completion owner, which
/// settles the operation as failed (`Physical::drop` in
/// `src/coordination/client.rs`). No local observer survives that drop.
#[test]
fn dropping_the_last_governor_with_started_work_settles_one_shared_failure() {
    let (_root, scope) = fixture();
    let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let reservation = request(&host);
    host.try_admit(reservation.clone(), NOW).unwrap();
    host.try_start(reservation.id, NOW).unwrap();
    assert_eq!(host.view(NOW).in_flight, 1);
    let running = scope.view().unwrap();
    assert_eq!((running.participants, running.prepared, running.physical, running.surcharged_ns), (1, 0, 1, 0));
    drop(host);
    let settled = drained(&scope);
    assert_eq!((settled.participants, settled.prepared, settled.physical), (0, 0, 0));
    assert_eq!(settled.surcharged_ns, SHARED_SURCHARGE);
    assert!(settled.charged_ns >= running.charged_ns, "settlement must retain the committed reservation");
    assert_eq!(drained(&scope).surcharged_ns, SHARED_SURCHARGE, "a later read cannot reapply the failure");
    // A new participant's successful work leaves the earlier failure intact.
    let next = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let reservation = request(&next);
    next.try_admit(reservation.clone(), NOW).unwrap();
    next.try_start(reservation.id, NOW).unwrap();
    next.release(reservation.id, NOW);
    next.release(reservation.id, NOW);
    assert_eq!(next.view(NOW).surcharged, Duration::ZERO);
    assert_eq!(drained(&scope).surcharged_ns, SHARED_SURCHARGE);
}

#[test]
fn a_failed_foreground_tree_refresh_is_surcharged_once_by_each_authority() {
    let (_root, scope) = fixture();
    let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.create_file("file", 1);
    let mut harness = Harness::open_under(
        fs,
        Arc::new(LoadAll),
        tree_fucker::Config { fixed_interval: Some(Duration::from_secs(86_400)), ..tree_fucker::Config::default() },
        host.clone(),
    )
    .unwrap();
    let initial = harness.command(Command::InitialScanComplete);
    for _ in 0..20 {
        if harness.result(initial).is_some() {
            break;
        }
        assert!(harness.complete_next_job(), "initial scan must make progress");
    }
    assert_eq!(harness.result(initial), Some(Ok(())));
    while harness.complete_next_job() {}
    assert_eq!(host.view(NOW).surcharged, Duration::ZERO);
    assert_eq!(drained(&scope).surcharged_ns, 0);

    harness.command(Command::Refresh(vec![RelativePath::root()]));
    let job = harness.pending_job_for("").expect("refresh listing dispatched");
    assert!(matches!(job.work, Work::Listing(_)));
    let started: Vec<_> = host.grants().into_iter().filter(|grant| grant.started.is_some()).collect();
    assert_eq!(started.len(), 1);
    assert_eq!(started[0].origin, WorkOrigin::Foreground, "a Refresh draws on the foreground allowance");
    let grant = started[0].id;
    assert!(harness.complete_job_with(
        job.id,
        JobResult::Listing(SessionStep::finished(
            SessionCost { listing_operations: 1, ..SessionCost::default() },
            SessionOutcome::Failed(FsError::PermissionDenied)
        ))
    ));
    assert_eq!(host.view(NOW).surcharged, local_surcharge());
    assert_eq!(drained(&scope).surcharged_ns, SHARED_SURCHARGE);

    host.release(grant, NOW);
    harness.command(Command::Shutdown);
    for outstanding in harness.outstanding_jobs() {
        assert!(harness.complete_outstanding_job(outstanding.id));
    }
    drop(harness);
    let settled = drained(&scope);
    assert_eq!((settled.prepared, settled.physical), (0, 0));
    assert_eq!(settled.surcharged_ns, SHARED_SURCHARGE, "replay, shutdown and drop cannot add a failure");
    assert_eq!(host.view(NOW).surcharged, local_surcharge());
    assert!(host.coordination_error().is_none());
}

#[test]
fn a_failed_scan_lazy_read_is_surcharged_once_by_each_authority() {
    let (_root, scope) = fixture();
    let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    for index in 0..3 {
        fs.create_file(&format!("file-{index}"), 1);
    }
    let mut scan = Scan::open_outside_host_governor(
        fs.clone(),
        fs.root().to_path_buf(),
        Arc::new(LoadAll),
        ScanOptions { ceiling: Duration::MAX, ..ScanOptions::default() },
        host.clone(),
        Arc::new(SystemClock),
    )
    .unwrap();
    let mut reads = 0;
    while let Some(event) = scan.next() {
        let ScanEvent::Entry(entry) = event.unwrap() else { continue };
        if entry.path.path().is_root() {
            continue;
        }
        if reads == 0 {
            assert!(scan.read(&entry, |_| Err::<(), _>(FsError::PermissionDenied)).is_err());
            assert_eq!(host.view(NOW).surcharged, local_surcharge());
            assert_eq!(drained(&scope).surcharged_ns, SHARED_SURCHARGE);
        } else {
            scan.read(&entry, |_| Ok(())).unwrap();
        }
        reads += 1;
    }
    assert_eq!(reads, 3);
    drop(scan);
    let settled = drained(&scope);
    assert_eq!((settled.prepared, settled.physical), (0, 0));
    assert_eq!(settled.surcharged_ns, SHARED_SURCHARGE, "later reads and drop cannot add a failure");
    assert_eq!(host.view(NOW).surcharged, local_surcharge());
    assert!(host.coordination_error().is_none());
}
