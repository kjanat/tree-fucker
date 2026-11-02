//! Composed admission and deferred completion under native lock contention.
#![cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]

mod coordination_support;

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use coordination_support::native::{Error, Scope};
use tree_fucker::coordination::authority::{Authority, Config, View};
use tree_fucker::coordination::journal::Journal;
use tree_fucker::core::{GrantId, MonotonicTime, Reported, Reservation, WorkOrigin};
use tree_fucker::{DomainCapabilities, HostConfig, HostGovernor, RelativePath, StorageDomainId, ThrottleCause};

const NOW: MonotonicTime = MonotonicTime::ZERO;
const TIMEOUT: Duration = Duration::from_secs(15);

fn host_config() -> HostConfig {
    HostConfig {
        maximum_in_flight: 2,
        per_domain_concurrency: 2,
        background_duty: 1.0,
        domain_background_duty: 1.0,
        foreground_duty: 1.0,
        domain_foreground_duty: 1.0,
        background_burst: Duration::from_secs(1),
        domain_background_burst: Duration::from_secs(1),
        foreground_burst: Duration::from_secs(1),
        domain_foreground_burst: Duration::from_secs(1),
        bootstrap_allowance: Duration::from_secs(1),
        stuck_threshold: Duration::from_secs(60),
        initial_cost_estimate: Duration::from_millis(1),
        ..HostConfig::default()
    }
}

fn fixture() -> (tempfile::TempDir, Arc<Scope>, HostGovernor, HostGovernor) {
    let mut builder = tempfile::Builder::new();
    builder.prefix("tree-fucker-acquisition-");
    #[cfg(windows)]
    let root = builder.tempdir().unwrap();
    #[cfg(not(windows))]
    let root = builder.tempdir_in(coordination_support::RENDEZVOUS).unwrap();
    let local = host_config();
    let mut limits = Config::from_host(&local, 8, 16, 16).unwrap();
    limits.ownership.physical = 1;
    limits.per_domain_physical = 1;
    let scope = Scope::open(root.path().join("scope"), limits).unwrap();
    let host = HostGovernor::with_coordination(&local, scope.clone()).unwrap();
    let peer = HostGovernor::with_coordination(&local, scope.clone()).unwrap();
    (root, scope, host, peer)
}

fn request(host: &HostGovernor, origin: WorkOrigin, operations: u32) -> Reservation {
    Reservation {
        id: GrantId::Bootstrap(host.next_bootstrap()),
        path: RelativePath::root(),
        reads: 1,
        registrations: 0,
        operations,
        ceiling: None,
        lease: 0,
        domain: None,
        origin,
        listing: false,
    }
}

struct Bookkeeping {
    _file: File,
}

impl Bookkeeping {
    fn lock(root: &Path) -> Self {
        let file = OpenOptions::new().read(true).write(true).open(root.join("scope.authority.lock")).unwrap();
        // File::lock uses flock on the Unix backends and LockFileEx on Windows.
        // Its full-file range conflicts with the backend's bookkeeping byte.
        file.lock().unwrap();
        Self { _file: file }
    }

    fn authority(&self, root: &Path) -> Authority {
        let file = OpenOptions::new().read(true).write(true).open(root.join("scope/authority.state")).unwrap();
        // This controller owns bookkeeping exclusion, so the raw journal is a
        // stable oracle even while native Scope::view correctly returns Busy.
        Journal::open(file).unwrap().load().unwrap()
    }
}

fn nonblocking<T: Send + 'static>(operation: impl FnOnce() -> T + Send + 'static) -> T {
    let (send, receive) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || send.send(operation()).unwrap());
    let result = receive.recv_timeout(TIMEOUT).expect("governor operation waited for the bookkeeping lock");
    worker.join().unwrap();
    result
}

fn drained(scope: &Scope) -> View {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let diagnostics = scope.diagnostics().unwrap();
        assert!(!diagnostics.failed);
        if diagnostics.pending_settlements == 0 && !diagnostics.bookkeeping_active {
            match scope.view() {
                Ok(view) => return view,
                Err(Error::Busy) => {}
                Err(error) => panic!("authority could not be inspected: {error}"),
            }
        }
        assert!(Instant::now() < deadline, "deferred ownership did not drain");
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[derive(Clone, Copy, Debug)]
enum Boundary {
    LocalPreparationDenied,
    LocalPreparation,
    PublicCommitDenied,
    SharedPreparation,
    LocalStartDenied,
    SharedStartDenied,
    SharedCapacityDenied,
    PhysicalCompletion,
    ReportedCompletion,
}

const BOUNDARIES: [Boundary; 9] = [
    Boundary::LocalPreparationDenied,
    Boundary::LocalPreparation,
    Boundary::PublicCommitDenied,
    Boundary::SharedPreparation,
    Boundary::LocalStartDenied,
    Boundary::SharedStartDenied,
    Boundary::SharedCapacityDenied,
    Boundary::PhysicalCompletion,
    Boundary::ReportedCompletion,
];

/// Which ownership the history holds when the controller takes bookkeeping
/// exclusion. Every expected accounting fact below derives from this table.
#[derive(Clone, Copy)]
struct Held {
    local_preparation: bool,
    shared_preparation: bool,
    physical: bool,
}

impl Boundary {
    fn held(self) -> Held {
        let (local_preparation, shared_preparation, physical) = match self {
            Self::LocalPreparationDenied => (false, false, false),
            Self::LocalPreparation | Self::PublicCommitDenied => (true, false, false),
            Self::SharedPreparation | Self::LocalStartDenied | Self::SharedStartDenied | Self::SharedCapacityDenied => {
                (true, true, false)
            }
            Self::PhysicalCompletion | Self::ReportedCompletion => (false, false, true),
        };
        Held { local_preparation, shared_preparation, physical }
    }
}

/// Shared facts that native elapsed time cannot change.
#[derive(Debug, PartialEq, Eq)]
struct Shared {
    participants: usize,
    domains: usize,
    prepared: usize,
    physical: u32,
    surcharged_ns: u128,
    withheld_ns: u128,
    bootstrap_reserved_ns: u128,
}

impl Shared {
    fn of(view: &View) -> Self {
        Self {
            participants: view.participants,
            domains: view.domains,
            prepared: view.prepared,
            physical: view.physical,
            surcharged_ns: view.surcharged_ns,
            withheld_ns: view.withheld_ns,
            bootstrap_reserved_ns: view.bootstrap_reserved_ns,
        }
    }
}

/// Local holds and charges summed over every governor in one history.
#[derive(Debug, Default, PartialEq, Eq)]
struct Local {
    preparations: usize,
    prepared: Duration,
    in_flight: usize,
    charged: Duration,
    surcharged: Duration,
}

fn local_holds(governors: &[&HostGovernor]) -> Local {
    governors.iter().map(|governor| governor.view(NOW)).fold(Local::default(), |sum, view| Local {
        preparations: sum.preparations + view.preparations,
        prepared: sum.prepared + view.prepared,
        in_flight: sum.in_flight + view.in_flight,
        charged: sum.charged + view.charged,
        surcharged: sum.surcharged + view.surcharged,
    })
}

/// The clock the Unix backends timestamp authority transitions with
/// (`now` in `src/coordination/unix.rs`). Rust's `Instant` differs on Darwin.
#[cfg(unix)]
struct NativeClock;

#[cfg(unix)]
impl NativeClock {
    fn new() -> Self {
        Self
    }

    fn now_ns(&self) -> u128 {
        let time = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        u128::try_from(time.tv_sec).unwrap() * 1_000_000_000 + u128::try_from(time.tv_nsec).unwrap()
    }

    /// POSIX CLOCK_MONOTONIC never runs backwards across threads.
    fn cross_thread_slack_ns(&self) -> u128 {
        0
    }
}

/// The performance counter scaled by the same floored integer division as
/// `Epoch::nanos` in `src/coordination/windows/clock.rs`. A connection's
/// binding offset is constant, so it cancels in every occupancy interval.
#[cfg(windows)]
struct NativeClock {
    frequency: u128,
}

#[cfg(windows)]
impl NativeClock {
    fn new() -> Self {
        let mut frequency = 0;
        // SAFETY: live, correctly sized output.
        assert_ne!(unsafe { windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut frequency) }, 0);
        Self { frequency: u128::try_from(frequency).unwrap() }
    }

    fn now_ns(&self) -> u128 {
        let mut ticks = 0;
        // SAFETY: live, correctly sized output.
        assert_ne!(unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut ticks) }, 0);
        u128::try_from(ticks).unwrap() * 1_000_000_000 / self.frequency
    }

    /// The backend clamps readings because QPC on different threads can
    /// differ by one tick (`now_at` in `src/coordination/windows/mod.rs`).
    /// Allow one tick at each end of the window.
    fn cross_thread_slack_ns(&self) -> u128 {
        2 * 1_000_000_000_u128.div_ceil(self.frequency)
    }
}

/// The native authority charges each authorized operation the larger of its
/// reservation and its measured occupancy. With one physical permit those
/// occupancies are disjoint and lie inside the native-clock window that
/// starts at `opened`. Work that was never authorized accrues nothing.
fn assert_charged(view: &View, reserved: Duration, clock: &NativeClock, opened: u128, context: &str) {
    let charged = view.charged_ns;
    let reserved = reserved.as_nanos();
    if reserved == 0 {
        assert_eq!(charged, 0, "{context}: no operation was authorized");
        return;
    }
    let window = clock.now_ns() - opened + clock.cross_thread_slack_ns();
    assert!(
        (reserved..=reserved + window).contains(&charged),
        "{context}: charged {charged}, reserved {reserved}, native window {window}"
    );
}

#[test]
fn abort_and_completion_at_each_composed_boundary_do_not_wait_or_lose_accounting() {
    let mut histories = 0;
    for origin in [WorkOrigin::Background, WorkOrigin::Foreground] {
        for operations in [0, 4] {
            for known_domain in [false, true] {
                for boundary in BOUNDARIES {
                    history(boundary, origin, operations, known_domain);
                    histories += 1;
                }
            }
        }
    }
    assert_eq!(histories, 72);
}

fn history(boundary: Boundary, origin: WorkOrigin, operations: u32, known_domain: bool) {
    let context = format!("{boundary:?} {origin:?} operations={operations} known_domain={known_domain}");
    let clock = NativeClock::new();
    let opened = clock.now_ns();
    let (root, scope, host, peer) = fixture();
    let mut reservation = request(&host, origin, operations);
    if known_domain {
        let domain = StorageDomainId::fresh();
        host.register_domain(domain, &DomainCapabilities::default(), NOW);
        reservation.domain = Some(domain);
    }
    let id = reservation.id;
    let held = boundary.held();
    // Both authorities start from a 1 ms estimate with second-long buckets, so
    // every requested optional operation is permitted at that unit price.
    let cost = Duration::from_millis(u64::from(1 + operations));
    let peer_cost =
        if matches!(boundary, Boundary::SharedCapacityDenied) { Duration::from_millis(1) } else { Duration::ZERO };
    let host_charge = if held.physical { cost } else { Duration::ZERO };
    let shared_owner = held.shared_preparation || held.physical;
    let expected_shared = |prepared: usize, host_live: bool| Shared {
        participants: 2,
        domains: usize::from(known_domain && shared_owner),
        prepared,
        physical: u32::from(host_live && held.physical) + u32::from(!peer_cost.is_zero()),
        surcharged_ns: 0,
        withheld_ns: 0,
        bootstrap_reserved_ns: peer_cost.as_nanos()
            + if host_live && shared_owner && !known_domain { cost.as_nanos() } else { 0 },
    };
    let released_local =
        Local { in_flight: usize::from(!peer_cost.is_zero()), charged: host_charge + peer_cost, ..Local::default() };
    let held_local = Local {
        preparations: usize::from(held.local_preparation),
        prepared: if held.local_preparation { cost } else { Duration::ZERO },
        in_flight: usize::from(held.physical) + released_local.in_flight,
        ..released_local
    };
    let mut local = None;
    let mut denied = None;
    let peer_id = if matches!(boundary, Boundary::SharedCapacityDenied) {
        let busy = request(&peer, origin, 0);
        let peer_id = busy.id;
        peer.try_admit(busy, NOW).unwrap();
        peer.try_start(peer_id, NOW).unwrap();
        Some(peer_id)
    } else {
        None
    };
    match boundary {
        Boundary::LocalPreparationDenied => {
            host.report_memory(host.next_tree(), host.memory_ceiling() + 1, 0);
            denied = Some(reservation);
        }
        Boundary::LocalPreparation | Boundary::PublicCommitDenied => {
            local = Some(host.try_prepare(reservation, NOW).unwrap());
        }
        _ => {
            host.try_admit(reservation, NOW).unwrap();
        }
    }
    match boundary {
        Boundary::LocalStartDenied => {
            host.report_memory(host.next_tree(), host.memory_ceiling() + 1, 0);
            let access = scope.diagnostics().unwrap().access;
            assert_eq!(host.try_start(id, NOW), Err(ThrottleCause::Memory));
            assert_eq!(scope.diagnostics().unwrap().access, access, "local rejection must not authorize shared work");
        }
        Boundary::SharedCapacityDenied => {
            assert_eq!(host.try_start(id, NOW), Err(ThrottleCause::Coordination));
        }
        Boundary::PhysicalCompletion | Boundary::ReportedCompletion => {
            host.try_start(id, NOW).unwrap();
            if matches!(boundary, Boundary::ReportedCompletion) {
                host.report(id, Reported { blocking: Some(Duration::from_millis(5)), operations: 1 + operations }, NOW);
            }
        }
        _ => {}
    }
    let lock = Bookkeeping::lock(root.path());
    let before = lock.authority(root.path());
    let observer = scope.clone();
    assert!(matches!(nonblocking(move || observer.view()), Err(Error::Busy)));
    assert_eq!(Shared::of(&before.view()), expected_shared(usize::from(held.shared_preparation), true), "{context}");
    assert_charged(&before.view(), host_charge + peer_cost, &clock, opened, &context);
    assert_eq!(local_holds(&[&host, &peer]), held_local, "{context}");
    assert_eq!(scope.diagnostics().unwrap().pending_settlements, 0, "{context}");
    if let Some(reservation) = denied {
        let access = scope.diagnostics().unwrap().access;
        let owner = host.clone();
        assert_eq!(nonblocking(move || owner.try_admit(reservation, NOW)), Err(ThrottleCause::Memory));
        assert_eq!(scope.diagnostics().unwrap().access, access, "local denial must not attempt shared preparation");
        assert_eq!(local_holds(&[&host, &peer]), held_local, "{context}: local denial must hold nothing");
        assert_eq!(scope.diagnostics().unwrap().pending_settlements, 0, "{context}");
    }
    if held.physical {
        // Replaying start for running work must reuse the committed shared
        // permission without a native attempt or a second local charge.
        let access = scope.diagnostics().unwrap().access;
        let owner = host.clone();
        assert_eq!(nonblocking(move || owner.try_start(id, NOW)), Ok(()));
        assert_eq!(scope.diagnostics().unwrap().access, access, "{context}: replayed start reached the authority");
        assert_eq!(local_holds(&[&host, &peer]), held_local, "{context}: replayed start changed local accounting");
    }
    if matches!(boundary, Boundary::SharedStartDenied) {
        let access = scope.diagnostics().unwrap().access;
        let owner = host.clone();
        assert_eq!(nonblocking(move || owner.try_start(id, NOW)), Err(ThrottleCause::Coordination));
        let denied = scope.diagnostics().unwrap().access;
        assert_eq!(
            (denied.attempts, denied.busy, denied.acquired),
            (access.attempts + 1, access.busy + 1, access.acquired)
        );
        assert_eq!(host.view(NOW).in_flight, 0, "shared denial must roll back the local physical hold");
        assert_eq!(local_holds(&[&host, &peer]), held_local, "{context}: shared denial changed local accounting");
    }
    match boundary {
        Boundary::LocalPreparation => {
            nonblocking(move || drop(local.unwrap()));
        }
        Boundary::PublicCommitDenied => {
            assert_eq!(nonblocking(move || local.unwrap().commit(NOW)), Err(ThrottleCause::Coordination));
        }
        _ => {
            let owner = host.clone();
            nonblocking(move || owner.release(id, NOW));
        }
    }
    let queued = shared_owner;
    let diagnostics = scope.diagnostics().unwrap();
    assert_eq!(diagnostics.pending_settlements, usize::from(queued), "boundary={boundary:?}");
    assert!(!diagnostics.failed);
    assert_eq!(lock.authority(root.path()), before, "no shared state can change while exclusion is held");
    assert_eq!(local_holds(&[&host, &peer]), released_local, "{context}: release must return every local hold");
    // A duplicate release must neither enqueue a second update nor release a
    // different participant's ownership.
    let owner = host.clone();
    nonblocking(move || owner.release(id, NOW));
    assert_eq!(scope.diagnostics().unwrap().pending_settlements, usize::from(queued));
    assert_eq!(lock.authority(root.path()), before);
    assert_eq!(local_holds(&[&host, &peer]), released_local, "{context}: duplicate release changed local accounting");
    let view = host.view(NOW);
    assert_eq!((view.preparations, view.in_flight), (0, 0));
    assert_eq!(view.surcharged, Duration::ZERO);
    let completed = matches!(boundary, Boundary::PhysicalCompletion | Boundary::ReportedCompletion);
    if completed {
        assert_eq!(view.charged, Duration::from_millis(u64::from(1 + operations)));
        assert_eq!(before.view().physical, 1);
    } else {
        assert_eq!(view.charged, Duration::ZERO);
    }
    drop(lock);
    let settled = drained(&scope);
    assert_eq!((settled.prepared, settled.physical), (0, u32::from(peer_id.is_some())));
    assert_eq!(settled.surcharged_ns, 0);
    assert!(settled.charged_ns >= before.view().charged_ns, "settlement must retain committed charges");
    if !completed && peer_id.is_none() {
        assert_eq!(settled.charged_ns, 0);
    }
    assert_eq!(Shared::of(&settled), expected_shared(0, false), "{context}: settlement");
    assert_charged(&settled, host_charge + peer_cost, &clock, opened, &context);
    if let Some(peer_id) = peer_id {
        peer.release(peer_id, NOW);
    } else {
        host.release(id, NOW);
        assert_eq!(drained(&scope).charged_ns, settled.charged_ns, "duplicate completion cannot charge twice");
    }
    drop((host, peer));
    let retired = drained(&scope);
    assert_eq!((retired.participants, retired.prepared, retired.physical), (0, 0, 0));
    assert_eq!(
        (retired.surcharged_ns, retired.withheld_ns, retired.bootstrap_reserved_ns),
        (0, 0, 0),
        "{context}: retirement"
    );
    assert_charged(&retired, host_charge + peer_cost, &clock, opened, &context);
}

#[test]
fn tree_shutdown_keeps_running_ownership_until_completion_even_when_settlement_is_busy() {
    use tree_fucker::core::Command;
    use tree_fucker::testing::{FakeFileSystem, Harness};
    use tree_fucker::{LoadAll, WatcherKind};

    let (root, scope, host, peer) = fixture();
    let mut harness = Harness::open_under(
        Arc::new(FakeFileSystem::new(WatcherKind::None)),
        Arc::new(LoadAll),
        tree_fucker::Config::default(),
        host.clone(),
    )
    .unwrap();
    assert_eq!(host.view(NOW).in_flight, 1);
    let lock = Bookkeeping::lock(root.path());
    let before = lock.authority(root.path());
    let mut harness = nonblocking(move || {
        harness.command(Command::Shutdown);
        harness
    });
    assert_eq!(host.view(NOW).in_flight, 1);
    assert_eq!(scope.diagnostics().unwrap().pending_settlements, 0);
    assert_eq!(lock.authority(root.path()), before, "logical cancellation cannot release physical ownership");
    let outstanding = harness.outstanding_jobs();
    assert_eq!(outstanding.len(), 1);
    let job = outstanding[0].id;
    let harness = nonblocking(move || {
        assert!(harness.complete_outstanding_job(job));
        harness
    });
    assert_eq!(host.view(NOW).in_flight, 0);
    assert_eq!(scope.diagnostics().unwrap().pending_settlements, 1);
    assert_eq!(lock.authority(root.path()), before, "shared ownership remains until settlement commits");
    drop(harness);
    drop(lock);
    let settled = drained(&scope);
    assert_eq!((settled.prepared, settled.physical, settled.surcharged_ns), (0, 0, 0));
    assert!(settled.charged_ns >= before.view().charged_ns);
    assert!(host.coordination_error().is_none());
    drop((host, peer));
    let retired = drained(&scope);
    assert_eq!((retired.participants, retired.prepared, retired.physical), (0, 0, 0));
}

#[test]
fn all_three_participant_release_orders_retain_pending_owners_and_settle_once() {
    for origin in [WorkOrigin::Background, WorkOrigin::Foreground] {
        for operations in [0, 4] {
            for order in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
                let (root, scope, host, peer) = fixture();
                let third = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
                let mut actors = [Some(host), Some(peer), Some(third)];
                let ids: Vec<_> = actors
                    .iter()
                    .map(|host| {
                        let host = host.as_ref().unwrap();
                        let reservation = request(host, origin, operations);
                        let id = reservation.id;
                        host.try_admit(reservation, NOW).unwrap();
                        id
                    })
                    .collect();
                actors[0].as_ref().unwrap().try_start(ids[0], NOW).unwrap();
                let lock = Bookkeeping::lock(root.path());
                let before = lock.authority(root.path());
                assert_eq!((before.view().participants, before.view().prepared, before.view().physical), (3, 2, 1));
                for (released, index) in order.into_iter().enumerate() {
                    let host = actors[index].take().unwrap();
                    let id = ids[index];
                    let local = nonblocking(move || {
                        host.release(id, NOW);
                        // The application's final client reference disappears
                        // here. Its pending update must retain native
                        // ownership.
                        host.view(NOW)
                    });
                    assert_eq!((local.preparations, local.in_flight), (0, 0));
                    assert_eq!(local.surcharged, Duration::ZERO);
                    let charge =
                        if index == 0 { Duration::from_millis(u64::from(1 + operations)) } else { Duration::ZERO };
                    assert_eq!(local.charged, charge);
                    assert_eq!(scope.diagnostics().unwrap().pending_settlements, released + 1);
                    assert_eq!(lock.authority(root.path()), before, "order={order:?}, released={released}");
                }
                drop(lock);
                let settled = drained(&scope);
                assert_eq!((settled.participants, settled.prepared, settled.physical), (0, 0, 0));
                assert_eq!((settled.surcharged_ns, settled.bootstrap_reserved_ns), (0, 0));
                assert!(settled.charged_ns >= before.view().charged_ns);
            }
        }
    }
}
