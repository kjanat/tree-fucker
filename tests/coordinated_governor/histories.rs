//! One public composed event stream, executed by one participant and by three.
//!
//! Every shared reservation is priced at a one-hour estimate, so real native
//! occupancy never exceeds a charged reservation and cumulative shared charges
//! are exact. Every started grant is released exactly one estimate later on the
//! caller's clock, so each local bootstrap estimator only ever samples that
//! same estimate and local prices cannot diverge between topologies.

use std::fs::{File, OpenOptions};
use std::sync::mpsc;
use std::time::Instant;

use tree_fucker::WatchReleaseId;
use tree_fucker::coordination::journal::Journal;

use super::*;

const ESTIMATE: Duration = Duration::from_secs(3600);
const SURCHARGE: Duration = Duration::from_secs(1);
const TIMEOUT: Duration = Duration::from_secs(15);

fn local_config() -> HostConfig {
    let allowance = ESTIMATE * 100;
    HostConfig {
        maximum_in_flight: 4,
        per_domain_concurrency: 4,
        background_duty: 1.0,
        domain_background_duty: 1.0,
        foreground_duty: 1.0,
        domain_foreground_duty: 1.0,
        background_burst: allowance,
        domain_background_burst: allowance,
        foreground_burst: allowance,
        domain_foreground_burst: allowance,
        bootstrap_allowance: allowance,
        initial_cost_estimate: ESTIMATE,
        stuck_threshold: allowance,
        failure_surcharge: SURCHARGE,
        ..HostConfig::default()
    }
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap()
}

/// Exact accounting facts after one boundary. Participant count is excluded
/// because it differs between the topologies by design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Accounting {
    local_preparations: usize,
    local_prepared: Duration,
    local_in_flight: usize,
    local_charged: Duration,
    local_surcharged: Duration,
    shared_prepared: usize,
    shared_physical: u32,
    shared_charged_ns: u128,
    shared_surcharged_ns: u128,
    shared_bootstrap_reserved_ns: u128,
    shared_withheld_ns: u128,
    pending_settlements: usize,
}

/// Local columns: preparations, prepared estimates, in flight, charged
/// estimates, surcharges. Shared columns: prepared, physical, charged
/// estimates, surcharges, bootstrap-reserved estimates, pending settlements.
fn row(label: &'static str, local: [u32; 5], shared: [u32; 6]) -> (&'static str, Accounting) {
    let [preparations, prepared, in_flight, charged, surcharged] = local;
    let [shared_prepared, physical, shared_charged, shared_surcharged, bootstrap, pending] = shared;
    let ns = |duration: Duration, count: u32| (duration * count).as_nanos();
    (
        label,
        Accounting {
            local_preparations: preparations as usize,
            local_prepared: ESTIMATE * prepared,
            local_in_flight: in_flight as usize,
            local_charged: ESTIMATE * charged,
            local_surcharged: SURCHARGE * surcharged,
            shared_prepared: shared_prepared as usize,
            shared_physical: physical,
            shared_charged_ns: ns(ESTIMATE, shared_charged),
            shared_surcharged_ns: ns(SURCHARGE, shared_surcharged),
            shared_bootstrap_reserved_ns: ns(ESTIMATE, bootstrap),
            shared_withheld_ns: 0,
            pending_settlements: pending as usize,
        },
    )
}

fn expected() -> Vec<(&'static str, Accounting)> {
    vec![
        row("A background admitted", [1, 1, 0, 0, 0], [1, 0, 0, 0, 1, 0]),
        row("A background started", [0, 0, 1, 1, 0], [0, 1, 1, 0, 1, 0]),
        row("A duplicate start", [0, 0, 1, 1, 0], [0, 1, 1, 0, 1, 0]),
        row("A background released", [0, 0, 0, 1, 0], [0, 0, 1, 0, 0, 0]),
        row("A duplicate release", [0, 0, 0, 1, 0], [0, 0, 1, 0, 0, 0]),
        row("B foreground admitted", [1, 1, 0, 1, 0], [1, 0, 1, 0, 1, 0]),
        row("B foreground started", [0, 0, 1, 2, 0], [0, 1, 2, 0, 1, 0]),
        // Local failure is charged once when detected; the shared authority
        // learns of it only from the failed completion.
        row("B marked stuck", [0, 0, 1, 2, 1], [0, 1, 2, 0, 1, 0]),
        row("B failed release", [0, 0, 0, 2, 1], [0, 0, 2, 1, 0, 0]),
        row("C local preparation", [1, 1, 0, 2, 1], [0, 0, 2, 1, 0, 0]),
        row("C preparation dropped", [0, 0, 0, 2, 1], [0, 0, 2, 1, 0, 0]),
        row("A memory denial", [0, 0, 0, 2, 1], [0, 0, 2, 1, 0, 0]),
        row("B bootstrap holder admitted", [1, 2, 0, 2, 1], [1, 0, 2, 1, 2, 0]),
        row("C ordinary admission denied", [1, 2, 0, 2, 1], [1, 0, 2, 1, 2, 0]),
        // Three estimates exceed the two-estimate shared bootstrap cap.
        row("C cleanup admitted", [2, 3, 0, 2, 1], [2, 0, 2, 1, 3, 0]),
        row("C cleanup started", [1, 2, 1, 3, 1], [1, 1, 3, 1, 3, 0]),
        row("C cleanup released", [1, 2, 0, 3, 1], [1, 0, 3, 1, 2, 0]),
        row("B holder released", [0, 0, 0, 3, 1], [0, 0, 3, 1, 0, 0]),
        row("A background admitted again", [1, 1, 0, 3, 1], [1, 0, 3, 1, 1, 0]),
        row("A background started again", [0, 0, 1, 4, 1], [0, 1, 4, 1, 1, 0]),
        row("B foreground admitted again", [1, 1, 1, 4, 1], [1, 1, 4, 1, 2, 0]),
        row("B start denied by physical capacity", [1, 1, 1, 4, 1], [1, 1, 4, 1, 2, 0]),
        row("A released again", [1, 1, 0, 4, 1], [1, 0, 4, 1, 1, 0]),
        row("B start retried", [0, 0, 1, 5, 1], [0, 1, 5, 1, 1, 0]),
        row("B release deferred", [0, 0, 0, 5, 1], [0, 1, 5, 1, 1, 1]),
        row("B duplicate deferred release", [0, 0, 0, 5, 1], [0, 1, 5, 1, 1, 1]),
        row("B settlement drained", [0, 0, 0, 5, 1], [0, 0, 5, 1, 0, 0]),
        row("B duplicate settled release", [0, 0, 0, 5, 1], [0, 0, 5, 1, 0, 0]),
    ]
}

struct History {
    root: tempfile::TempDir,
    scope: Arc<Scope>,
    hosts: Vec<HostGovernor>,
    trace: Vec<(&'static str, Accounting)>,
}

/// Bookkeeping exclusion held by the controller, as in the acquisition matrix.
/// `File::lock` conflicts with the backend's bookkeeping lock on every backend.
struct Bookkeeping {
    _file: File,
}

fn nonblocking<T: Send + 'static>(operation: impl FnOnce() -> T + Send + 'static) -> T {
    let (send, receive) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || send.send(operation()).unwrap());
    let result = receive.recv_timeout(TIMEOUT).expect("governor operation waited for the bookkeeping lock");
    worker.join().unwrap();
    result
}

impl History {
    fn open(participants: usize) -> Self {
        let mut builder = tempfile::Builder::new();
        builder.prefix("tree-fucker-histories-");
        #[cfg(windows)]
        let root = builder.tempdir().unwrap();
        #[cfg(not(windows))]
        let root = builder.tempdir_in(coordination_support::RENDEZVOUS).unwrap();
        let local = local_config();
        let mut limits = Config::from_host(&local, 8, 16, 16).unwrap();
        limits.ownership.physical = 1;
        limits.per_domain_physical = 1;
        limits.bootstrap_ns = nanos(ESTIMATE * 2);
        let scope = Scope::open(root.path().join("scope"), limits).unwrap();
        let hosts =
            (0..participants).map(|_| HostGovernor::with_coordination(&local, scope.clone()).unwrap()).collect();
        Self { root, scope, hosts, trace: Vec::new() }
    }

    /// Actors A, B and C share one governor or use one governor each.
    fn host(&self, actor: usize) -> &HostGovernor {
        &self.hosts[actor % self.hosts.len()]
    }

    fn ordinary(&self, actor: usize, origin: WorkOrigin, reads: u32) -> Reservation {
        let host = self.host(actor);
        Reservation { id: GrantId::Bootstrap(host.next_bootstrap()), reads, origin, ..request(host) }
    }

    fn cleanup(&self, actor: usize, origin: WorkOrigin) -> Reservation {
        let host = self.host(actor);
        Reservation { id: GrantId::WatchRelease(host.next_tree(), WatchReleaseId::new(1)), origin, ..request(host) }
    }

    fn snapshot(&self, shared: tree_fucker::coordination::authority::View) -> Accounting {
        let views: Vec<_> = self.hosts.iter().map(|host| host.view(NOW)).collect();
        Accounting {
            local_preparations: views.iter().map(|view| view.preparations).sum(),
            local_prepared: views.iter().map(|view| view.prepared).sum(),
            local_in_flight: views.iter().map(|view| view.in_flight).sum(),
            local_charged: views.iter().map(|view| view.charged).sum(),
            local_surcharged: views.iter().map(|view| view.surcharged).sum(),
            shared_prepared: shared.prepared,
            shared_physical: shared.physical,
            shared_charged_ns: shared.charged_ns,
            shared_surcharged_ns: shared.surcharged_ns,
            shared_bootstrap_reserved_ns: shared.bootstrap_reserved_ns,
            shared_withheld_ns: shared.withheld_ns,
            pending_settlements: self.scope.diagnostics().unwrap().pending_settlements,
        }
    }

    fn record(&mut self, label: &'static str) {
        let diagnostics = self.scope.diagnostics().unwrap();
        assert!(!diagnostics.failed, "{label}");
        assert_eq!(diagnostics.pending_settlements, 0, "{label}: an uncontended update was deferred");
        let shared = self.scope.view().unwrap();
        let accounting = self.snapshot(shared);
        self.trace.push((label, accounting));
    }

    fn lock(&self) -> Bookkeeping {
        let file =
            OpenOptions::new().read(true).write(true).open(self.root.path().join("scope.authority.lock")).unwrap();
        file.lock().unwrap();
        Bookkeeping { _file: file }
    }

    /// The native view is correctly Busy under exclusion; the controller reads
    /// the committed journal directly instead.
    fn record_locked(&mut self, label: &'static str, _lock: &Bookkeeping) {
        let state =
            OpenOptions::new().read(true).write(true).open(self.root.path().join("scope/authority.state")).unwrap();
        let shared = Journal::open(state).unwrap().load().unwrap().view();
        let accounting = self.snapshot(shared);
        self.trace.push((label, accounting));
    }

    fn drain(&self) {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let diagnostics = self.scope.diagnostics().unwrap();
            assert!(!diagnostics.failed);
            if diagnostics.pending_settlements == 0 && !diagnostics.bookkeeping_active {
                return;
            }
            assert!(Instant::now() < deadline, "deferred settlement did not drain");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

const A: usize = 0;
const B: usize = 1;
const C: usize = 2;

fn run(participants: usize) -> Vec<(&'static str, Accounting)> {
    let mut history = History::open(participants);
    let mut now = NOW;

    // Background success, with replayed start and release.
    let a = history.ordinary(A, WorkOrigin::Background, 1);
    history.host(A).try_admit(a.clone(), now).unwrap();
    history.record("A background admitted");
    history.host(A).try_start(a.id, now).unwrap();
    history.record("A background started");
    assert_eq!(history.host(A).try_start(a.id, now), Ok(()));
    history.record("A duplicate start");
    now = now + ESTIMATE;
    history.host(A).release(a.id, now);
    history.record("A background released");
    history.host(A).release(a.id, now);
    history.record("A duplicate release");

    // Foreground physical failure through the public stuck transition.
    let b = history.ordinary(B, WorkOrigin::Foreground, 1);
    history.host(B).try_admit(b.clone(), now).unwrap();
    history.record("B foreground admitted");
    history.host(B).try_start(b.id, now).unwrap();
    history.record("B foreground started");
    history.host(B).mark_stuck(b.id, now);
    history.host(B).mark_stuck(b.id, now);
    history.record("B marked stuck");
    now = now + ESTIMATE;
    history.host(B).release(b.id, now);
    history.record("B failed release");

    // Reversible local preparation and a local memory denial.
    let c = history.ordinary(C, WorkOrigin::Background, 1);
    let prepared = history.host(C).try_prepare(c, now).unwrap();
    history.record("C local preparation");
    drop(prepared);
    history.record("C preparation dropped");
    let host = history.host(A);
    let tree = host.next_tree();
    host.report_memory(tree, host.memory_ceiling() + 1, 0);
    let denied = history.ordinary(A, WorkOrigin::Background, 1);
    assert_eq!(history.host(A).try_admit(denied, now), Err(ThrottleCause::Memory));
    history.host(A).report_memory(tree, 0, 0);
    history.record("A memory denial");

    // Ordinary work is refused at the shared bootstrap cap; cleanup is not.
    assert_eq!(history.scope.diagnostics().unwrap().config.bootstrap_ns, nanos(ESTIMATE * 2));
    let holder = history.ordinary(B, WorkOrigin::Background, 2);
    history.host(B).try_admit(holder.clone(), now).unwrap();
    history.record("B bootstrap holder admitted");
    let ordinary = history.ordinary(C, WorkOrigin::Foreground, 1);
    assert_eq!(history.host(C).try_admit(ordinary, now), Err(ThrottleCause::Coordination));
    history.record("C ordinary admission denied");
    let cleanup = history.cleanup(C, WorkOrigin::Foreground);
    history.host(C).try_admit(cleanup.clone(), now).unwrap();
    history.record("C cleanup admitted");
    history.host(C).try_start(cleanup.id, now).unwrap();
    history.record("C cleanup started");
    now = now + ESTIMATE;
    history.host(C).release(cleanup.id, now);
    history.record("C cleanup released");
    history.host(B).release(holder.id, now);
    history.record("B holder released");

    // Shared physical capacity denies a start until the holder completes.
    let a = history.ordinary(A, WorkOrigin::Background, 1);
    history.host(A).try_admit(a.clone(), now).unwrap();
    history.record("A background admitted again");
    history.host(A).try_start(a.id, now).unwrap();
    history.record("A background started again");
    let b = history.ordinary(B, WorkOrigin::Foreground, 1);
    history.host(B).try_admit(b.clone(), now).unwrap();
    history.record("B foreground admitted again");
    assert_eq!(history.host(B).try_start(b.id, now), Err(ThrottleCause::Coordination));
    history.record("B start denied by physical capacity");
    now = now + ESTIMATE;
    history.host(A).release(a.id, now);
    history.record("A released again");
    history.host(B).try_start(b.id, now).unwrap();
    history.record("B start retried");

    // Settlement deferred behind bookkeeping exclusion, then replayed.
    now = now + ESTIMATE;
    let lock = history.lock();
    for label in ["B release deferred", "B duplicate deferred release"] {
        let owner = history.host(B).clone();
        let id = b.id;
        nonblocking(move || owner.release(id, now));
        history.record_locked(label, &lock);
    }
    drop(lock);
    history.drain();
    history.record("B settlement drained");
    history.host(B).release(b.id, now);
    history.record("B duplicate settled release");

    history.trace
}

#[test]
fn one_and_three_participants_produce_the_expected_accounting_history() {
    let expected = expected();
    let single = run(1);
    let three = run(3);
    assert_eq!(single.len(), expected.len());
    for ((label, one), (_, many)) in single.iter().zip(&three) {
        assert_eq!(one, many, "{label}: topologies diverged");
    }
    for ((label, actual), (expected_label, expected)) in single.iter().zip(&expected) {
        assert_eq!(label, expected_label);
        assert_eq!(actual, expected, "{label}");
    }
    assert_eq!(three, expected);
}
