#![cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]

use std::sync::Arc;
use std::time::Duration;

use coordination_support::native::Scope;
use tree_fucker::coordination::authority::{Budget, Config};
use tree_fucker::coordination::protocol::Limits;
use tree_fucker::core::{GrantId, MonotonicTime, Reported, Reservation, WorkOrigin};
use tree_fucker::{HostConfig, HostGovernor, RelativePath, ThrottleCause};

const NOW: MonotonicTime = MonotonicTime::ZERO;

#[path = "coordinated_governor/denials.rs"]
mod denials;

#[path = "coordinated_governor/tree_denials.rs"]
mod tree_denials;

#[path = "coordinated_governor/leases.rs"]
mod leases;

#[test]
fn tree_failure_outcomes_reach_shared_settlement_once() {
    use tree_fucker::core::{JobResult, Work};
    use tree_fucker::testing::{FakeFileSystem, Harness};
    use tree_fucker::{FsError, LoadAll, SessionCost, SessionOutcome, SessionStep, WatcherKind};
    for lost in [false, true] {
        let (_root, scope) = fixture();
        let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
        let filesystem = Arc::new(FakeFileSystem::new(WatcherKind::None));
        let mut harness =
            Harness::open_under(filesystem, Arc::new(LoadAll), tree_fucker::Config::default(), host).unwrap();
        let listing = (0..10)
            .find_map(|_| {
                if let Some(job) = harness.pending_job_for("")
                    && matches!(job.work, Work::Listing(_))
                {
                    return Some(job);
                }
                harness.complete_next_job();
                None
            })
            .expect("root listing dispatched");
        if lost {
            assert!(harness.lose_job(listing.id));
        } else {
            assert!(harness.complete_job_with(
                listing.id,
                JobResult::Listing(SessionStep::finished(
                    SessionCost { listing_operations: 1, ..SessionCost::default() },
                    SessionOutcome::Failed(FsError::PermissionDenied)
                ))
            ));
        }
        assert_eq!(scope.view().unwrap().surcharged_ns, 1_000, "lost={lost}");
    }
}

#[test]
fn cancelling_a_tree_queued_behind_shared_capacity_spends_no_budget() {
    use tree_fucker::core::Command;
    use tree_fucker::testing::{FakeFileSystem, Harness};
    use tree_fucker::{LoadAll, WatcherKind};
    let (_root, scope) = fixture();
    let busy = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let reservation = request(&busy);
    let id = reservation.id;
    busy.try_admit(reservation, NOW).unwrap();
    busy.try_start(id, NOW).unwrap();
    let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let mut harness = Harness::open_under(
        Arc::new(FakeFileSystem::new(WatcherKind::None)),
        Arc::new(LoadAll),
        tree_fucker::Config::default(),
        host.clone(),
    )
    .unwrap();
    assert_eq!(host.view(NOW).preparations, 1);
    harness.command(Command::Shutdown);
    let local = host.view(NOW);
    assert_eq!(local.preparations, 0);
    assert_eq!(local.charged, Duration::ZERO);
    assert_eq!(local.surcharged, Duration::ZERO);
    assert_eq!(scope.view().unwrap().prepared, 0);
    busy.release(id, NOW);
}

#[test]
fn cancelling_running_tree_work_retains_shared_ownership_until_completion() {
    use tree_fucker::core::Command;
    use tree_fucker::testing::{FakeFileSystem, Harness};
    use tree_fucker::{LoadAll, WatcherKind};
    let (_root, scope) = fixture();
    let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let mut harness = Harness::open_under(
        Arc::new(FakeFileSystem::new(WatcherKind::None)),
        Arc::new(LoadAll),
        tree_fucker::Config::default(),
        host,
    )
    .unwrap();
    assert_eq!(scope.view().unwrap().physical, 1);
    harness.command(Command::Shutdown);
    assert_eq!(scope.view().unwrap().physical, 1);
    let outstanding = harness.outstanding_jobs();
    assert_eq!(outstanding.len(), 1);
    assert!(harness.complete_outstanding_job(outstanding[0].id));
    let shared = scope.view().unwrap();
    assert_eq!(shared.physical, 0);
    assert_eq!(shared.surcharged_ns, 0, "logical shutdown is not a physical failure");
}

#[test]
fn listing_confirmation_requires_a_new_physical_admission() {
    use tree_fucker::core::{JobResult, Work};
    use tree_fucker::testing::{FakeFileSystem, Harness};
    use tree_fucker::{FsError, LoadAll, SessionCost, SessionOutcome, SessionStep, WatcherKind};
    let (_root, scope) = fixture();
    let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let filesystem = Arc::new(FakeFileSystem::new(WatcherKind::None));
    filesystem.mkdir("dir");
    let mut harness = Harness::open_under(filesystem, Arc::new(LoadAll), tree_fucker::Config::default(), host).unwrap();
    let listing = (0..10)
        .find_map(|_| {
            if let Some(job) = harness.pending_job_for("dir")
                && matches!(job.work, Work::Listing(_))
            {
                return Some(job);
            }
            harness.complete_next_job();
            None
        })
        .expect("child listing dispatched");
    assert!(harness.complete_job_with(
        listing.id,
        JobResult::Listing(SessionStep::finished(
            SessionCost { listing_operations: 1, ..SessionCost::default() },
            SessionOutcome::Failed(FsError::NotDirectory)
        ))
    ));
    let confirmation = harness.pending_job_for("dir").expect("confirmation dispatched");
    assert!(matches!(confirmation.work, Work::Metadata));
    assert_eq!(scope.view().unwrap().physical, 1, "confirmation must own a shared physical slot");
    assert_eq!(harness.governor().in_flight, 1, "confirmation must own a local physical slot");
    assert!(harness.complete_job(confirmation.id));
    assert_eq!(scope.view().unwrap().physical as usize, harness.governor().in_flight);
}

fn host_config() -> HostConfig {
    HostConfig {
        initial_cost_estimate: Duration::from_millis(1),
        foreground_burst: Duration::from_secs(1),
        bootstrap_allowance: Duration::from_secs(1),
        ..Default::default()
    }
}

fn fixture() -> (tempfile::TempDir, Arc<Scope>) {
    let mut builder = tempfile::Builder::new();
    builder.prefix("tree-fucker-composition-");
    #[cfg(windows)]
    let root = builder.tempdir().unwrap();
    #[cfg(not(windows))]
    let root = builder.tempdir_in(coordination_support::RENDEZVOUS).unwrap();
    let budget = Budget { refill_ns_per_second: 1_000_000_000, burst_ns: 1_000_000_000 };
    let config = Config {
        ownership: Limits { participants: 8, operations: 16, physical: 1 },
        domains: 16,
        background: budget,
        foreground: budget,
        domain_background: budget,
        domain_foreground: budget,
        bootstrap_ns: 1_000_000_000,
        per_domain_physical: 1,
        initial_estimate_ns: 1_000_000,
        stuck_after_ns: 10_000_000_000,
        failure_surcharge_ns: 1_000,
    };
    let scope = Scope::open(root.path().join("scope"), config).unwrap();
    (root, scope)
}

fn request(host: &HostGovernor) -> Reservation {
    Reservation {
        id: GrantId::Bootstrap(host.next_bootstrap()),
        path: RelativePath::root(),
        reads: 1,
        registrations: 0,
        operations: 0,
        ceiling: None,
        lease: 0,
        domain: None,
        origin: WorkOrigin::Foreground,
        listing: false,
    }
}

#[test]
fn cancelling_queued_work_aborts_both_budgets() {
    let (_root, scope) = fixture();
    let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    for _ in 0..100 {
        let reservation = request(&host);
        let id = reservation.id;
        host.try_admit(reservation, NOW).unwrap();
        assert_eq!(host.view(NOW).charged, Duration::ZERO);
        assert_eq!(host.view(NOW).in_flight, 0);
        host.release(id, NOW);
    }
    assert_eq!(host.view(NOW).preparations, 0);
    assert_eq!(host.view(NOW).charged, Duration::ZERO);
    assert_eq!(scope.view().unwrap().charged_ns, 0);
}

#[test]
fn shared_start_denial_releases_local_physical_hold_without_charging() {
    let (_root, scope) = fixture();
    let first = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let second = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let a = request(&first);
    let b = request(&second);
    let (a_id, b_id) = (a.id, b.id);
    first.try_admit(a, NOW).unwrap();
    first.try_start(a_id, NOW).unwrap();
    second.try_admit(b, NOW).unwrap();
    let mut now = NOW;
    for delay_us in [3000, 6000, 10_000, 10_000] {
        assert_eq!(second.try_start(b_id, now), Err(ThrottleCause::Coordination));
        let delay = Duration::from_micros(delay_us);
        let retry = now + delay;
        assert_eq!(second.coordination_retry_at(now), Some(retry));
        assert_eq!(second.coordination_retry_at(now + delay / 2), Some(retry), "queries must not move the deadline");
        assert_eq!(second.coordination_retry_at(retry), Some(retry + delay), "expired hints must not busy-poll");
        let view = second.view(now);
        assert_eq!(view.in_flight, 0);
        assert_eq!(view.charged, Duration::ZERO);
        assert_eq!(view.preparations, 1);
        now = retry;
    }
    first.release(a_id, NOW);
    second.try_start(b_id, now).unwrap();
    assert_eq!(second.coordination_retry_at(now), None);
    assert_eq!(second.view(now).in_flight, 1);
    assert_eq!(second.view(now).charged, Duration::from_millis(1));
    second.release(b_id, now);
    assert!(second.coordination_error().is_none());

    let a = request(&first);
    let b = request(&second);
    let (a_id, b_id) = (a.id, b.id);
    first.try_admit(a, NOW).unwrap();
    first.try_start(a_id, NOW).unwrap();
    second.try_admit(b, now).unwrap();
    assert_eq!(second.try_start(b_id, now), Err(ThrottleCause::Coordination));
    assert_eq!(second.coordination_retry_at(now), Some(now + Duration::from_millis(3)), "progress resets backoff");
    second.release(b_id, now);
    first.release(a_id, NOW);
}

#[test]
fn shared_start_rechecks_local_budget_after_another_operation_overruns() {
    use tree_fucker::{DomainCapabilities, StorageDomainId};
    for origin in [WorkOrigin::Background, WorkOrigin::Foreground] {
        for known_domain in [false, true] {
            let (_root, scope) = fixture();
            let config = HostConfig {
                background_duty: 0.01,
                domain_background_duty: 0.01,
                foreground_duty: 0.01,
                domain_foreground_duty: 0.01,
                background_burst: Duration::from_millis(10),
                domain_background_burst: Duration::from_millis(10),
                foreground_burst: Duration::from_millis(10),
                domain_foreground_burst: Duration::from_millis(10),
                stuck_threshold: Duration::from_secs(60),
                ..host_config()
            };
            let host = HostGovernor::with_coordination(&config, scope.clone()).unwrap();
            let domain = known_domain.then(StorageDomainId::fresh);
            if let Some(domain) = domain {
                host.register_domain(domain, &DomainCapabilities::default(), NOW);
            }
            let mut running = request(&host);
            running.origin = origin;
            running.domain = domain;
            let running_id = running.id;
            host.try_admit(running, NOW).unwrap();
            host.try_start(running_id, NOW).unwrap();
            let mut waiting = request(&host);
            waiting.origin = origin;
            waiting.domain = domain;
            let waiting_id = waiting.id;
            host.try_admit(waiting, NOW).unwrap();
            assert!(matches!(
                host.try_start(waiting_id, NOW),
                Err(ThrottleCause::Coordination | ThrottleCause::Concurrency)
            ));
            let later = NOW + Duration::from_millis(40);
            host.release(running_id, later);
            let local_before = host.view(later);
            let shared_before = scope.view().unwrap();
            let expected = match origin {
                WorkOrigin::Background => ThrottleCause::DutyBudget,
                WorkOrigin::Foreground => ThrottleCause::ForegroundCeiling,
            };
            assert_eq!(host.try_start(waiting_id, later), Err(expected), "origin={origin:?}, domain={domain:?}");
            assert_eq!(host.view(later).charged, local_before.charged);
            assert_eq!(host.view(later).preparations, 1);
            assert_eq!(scope.view().unwrap().charged_ns, shared_before.charged_ns);
            assert_eq!(scope.view().unwrap().physical, 0);
            let refilled = later + Duration::from_secs(5);
            host.try_start(waiting_id, refilled).unwrap();
            host.release(waiting_id, refilled);
        }
    }
}

#[test]
fn shared_start_excludes_its_own_preparation_from_local_affordability() {
    let (_root, scope) = fixture();
    let host = HostGovernor::with_coordination(
        &HostConfig { foreground_burst: Duration::from_millis(1), ..host_config() },
        scope,
    )
    .unwrap();
    let reservation = request(&host);
    let id = reservation.id;
    host.try_admit(reservation, NOW).unwrap();
    host.try_start(id, NOW).unwrap();
    host.release(id, NOW);
}

#[test]
fn shared_budget_denials_keep_the_longer_retry_without_spending_local_budget() {
    use tree_fucker::coordination::authority::{Origin, Request};
    use tree_fucker::coordination::protocol::Work;

    let (_root, scope) = fixture();
    let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let holder = scope.join().unwrap();
    let prepared = holder
        .prepare(Request {
            work: Work::Bootstrap,
            origin: Origin::Foreground,
            domain: None,
            required: 1000,
            desired: 0,
            ceiling_ns: u64::MAX,
        })
        .unwrap();
    let reservation = request(&host);
    for _ in 0..10 {
        assert_eq!(host.try_admit(reservation.clone(), NOW), Err(ThrottleCause::Coordination));
        assert_eq!(host.coordination_retry_at(NOW), Some(NOW + Duration::from_millis(10)));
        let view = host.view(NOW);
        assert_eq!(view.preparations, 0);
        assert_eq!(view.in_flight, 0);
        assert_eq!(view.charged, Duration::ZERO);
    }
    drop(prepared);
    host.try_admit(reservation.clone(), NOW).unwrap();
    host.try_start(reservation.id, NOW).unwrap();
    assert_eq!(host.coordination_retry_at(NOW), None);
    host.release(reservation.id, NOW);
}

#[test]
fn composed_lease_is_limited_by_the_smaller_authority() {
    let (_root, scope) = fixture();
    let config = HostConfig { initial_cost_estimate: Duration::from_micros(100), ..host_config() };
    let host = HostGovernor::with_coordination(&config, scope.clone()).unwrap();
    let mut reservation = request(&host);
    reservation.operations = 64;
    reservation.ceiling = Some(Duration::from_millis(13));
    let id = reservation.id;
    let admitted = host.try_admit(reservation, NOW).unwrap();
    assert_eq!(admitted.operations, 12);
    assert_eq!(admitted.cost, Duration::from_micros(1_300));
    let started = std::time::Instant::now();
    host.try_start(id, NOW).unwrap();
    host.report(id, Reported { blocking: None, operations: 13 }, NOW);
    host.release(id, NOW);
    assert!(host.coordination_error().is_none());
    let charged = scope.view().unwrap().charged_ns;
    // The native authority also accounts actual occupancy. A descheduled test
    // can exceed the estimate even though the local test clock remains zero.
    let maximum = started.elapsed().as_nanos().max(13_000_000);
    assert!((13_000_000..=maximum).contains(&charged), "charged {charged}, maximum {maximum}");
}

#[test]
fn memory_change_before_start_does_not_commit_either_reservation() {
    let (_root, scope) = fixture();
    let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let reservation = request(&host);
    let id = reservation.id;
    host.try_admit(reservation, NOW).unwrap();
    host.report_memory(host.next_tree(), host.memory_ceiling() + 1, 0);
    assert_eq!(host.try_start(id, NOW), Err(ThrottleCause::Memory));
    host.release(id, NOW);
    assert_eq!(host.view(NOW).charged, Duration::ZERO);
    assert_eq!(scope.view().unwrap().charged_ns, 0);
}

#[test]
#[cfg(not(windows))]
fn replaced_authority_fences_new_work_and_reports_failure() {
    let (root, scope) = fixture();
    let host = HostGovernor::with_coordination(&host_config(), scope).unwrap();
    std::fs::rename(root.path().join("scope"), root.path().join("old")).unwrap();
    assert_eq!(host.try_admit(request(&host), NOW), Err(ThrottleCause::CoordinationFailed));
    assert!(host.coordination_error().is_some());
    assert_eq!(host.view(NOW).preparations, 0);
    assert_eq!(host.view(NOW).charged, Duration::ZERO);
    assert_eq!(host.try_admit(request(&host), NOW), Err(ThrottleCause::CoordinationFailed));
}

#[test]
fn public_preparation_commit_composes_shared_admission() {
    let (_root, scope) = fixture();
    let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let reservation = request(&host);
    let id = reservation.id;
    host.try_prepare(reservation, NOW).unwrap().commit(NOW).unwrap();
    assert_eq!(scope.view().unwrap().prepared, 1);
    assert_eq!(host.view(NOW).preparations, 1);
    host.try_start(id, NOW).unwrap();
    assert_eq!(scope.view().unwrap().physical, 1);
    host.release(id, NOW);
    assert_eq!(scope.view().unwrap().physical, 0);
}

#[test]
fn dropping_local_preparation_aborts_before_shared_admission() {
    let (_root, scope) = fixture();
    let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let prepared = host.try_prepare(request(&host), NOW).unwrap();
    assert_eq!(host.view(NOW).preparations, 1);
    assert_eq!(scope.view().unwrap().prepared, 0, "shared admission waits for local commit");

    drop(prepared);

    let local = host.view(NOW);
    let shared = scope.view().unwrap();
    assert_eq!(local.preparations, 0);
    assert_eq!(local.charged, Duration::ZERO);
    assert_eq!(local.surcharged, Duration::ZERO);
    assert_eq!((shared.prepared, shared.physical, shared.charged_ns, shared.surcharged_ns), (0, 0, 0, 0));

    // The returned capacity remains usable after cancellation.
    let reservation = request(&host);
    let id = reservation.id;
    host.try_prepare(reservation, NOW).unwrap().commit(NOW).unwrap();
    host.try_start(id, NOW).unwrap();
    host.release(id, NOW);
    assert!(host.coordination_error().is_none());
}

#[test]
fn actual_scan_lists_and_reads_under_the_shared_authority() {
    use tree_fucker::{DomainCrossing, LoadAll, Scan, ScanEvent, ScanOptions, SystemClock};

    let (_root, scope) = fixture();
    let tree = tempfile::tempdir().unwrap();
    for i in 0..20 {
        std::fs::write(tree.path().join(format!("file-{i}")), b"content").unwrap();
    }
    let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let mut scan = Scan::open_outside_host_governor(
        Arc::new(tree_fucker::std_fs::StdFileSystem::new()),
        tree.path().to_path_buf(),
        Arc::new(LoadAll),
        ScanOptions {
            crossing: DomainCrossing::Follow,
            entries_per_lease: 3,
            streaming: true,
            ceiling: Duration::MAX,
            ..ScanOptions::default()
        },
        host.clone(),
        Arc::new(SystemClock),
    )
    .unwrap();
    let mut entries = 0;
    while let Some(event) = scan.next() {
        match event.unwrap() {
            ScanEvent::Entry(entry) => {
                entries += 1;
                scan.read(&entry, |_| {
                    assert_eq!(scope.view().unwrap().physical, 1);
                    Ok(())
                })
                .unwrap();
            }
            ScanEvent::Unlisted { failure, .. } => panic!("unlisted: {failure:?}"),
            _ => {}
        }
    }
    assert_eq!(entries, 21);
    assert!(host.coordination_error().is_none());
    assert_eq!(host.view(MonotonicTime(Duration::from_secs(1))).in_flight, 0);
    let shared = scope.view().unwrap();
    assert_eq!(shared.physical, 0);
    assert_eq!(shared.prepared, 0);
    assert!(shared.charged_ns > 0);
}

#[test]
fn persistent_tree_runs_listing_watch_registration_and_shutdown_with_shared_admission() {
    use tree_fucker::testing::{DeterministicRuntime, FakeFileSystem};
    use tree_fucker::{LoadAll, Tree, WatcherKind};

    let (_root, scope) = fixture();
    let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let runtime = Arc::new(DeterministicRuntime::new());
    let filesystem = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    filesystem.mkdir("dir");
    filesystem.create_file("dir/leaf", 4);
    let (handle, _) = runtime
        .block_on(Tree::open_outside_host_governor(
            filesystem.clone(),
            filesystem.root().to_path_buf(),
            Arc::new(LoadAll),
            tree_fucker::Config::default(),
            runtime.clone(),
            host.clone(),
        ))
        .unwrap();
    runtime.block_on(handle.initial_scan_complete()).unwrap();
    assert!(handle.snapshot().get(&RelativePath::parse("dir/leaf").unwrap()).is_some());
    runtime.block_on(handle.shutdown()).unwrap();
    runtime.run_until_stalled();
    let local = host.view(NOW);
    assert!(local.watch_registration_grants > 0);
    assert!(local.watch_release_grants > 0);
    assert_eq!(local.in_flight, 0);
    assert!(host.coordination_error().is_none());
    let shared = scope.view().unwrap();
    assert_eq!(shared.prepared, 0);
    assert_eq!(shared.physical, 0);
    assert!(shared.charged_ns > 0);
}

mod coordination_support;

#[test]
#[cfg(not(windows))]
fn terminal_coordination_failure_does_not_retain_the_tree_actor_for_undispatchable_unwatch() {
    use std::future::Future;

    use tree_fucker::testing::{DeterministicRuntime, FakeFileSystem, HoldingRuntime};
    use tree_fucker::{LoadAll, Tree, WatcherKind};
    for (held_worker, fail_before_shutdown) in [(false, false), (false, true), (true, false), (true, true)] {
        let (root, scope) = fixture();
        let host = HostGovernor::with_coordination(&host_config(), scope).unwrap();
        let inner = Arc::new(DeterministicRuntime::new());
        let runtime = Arc::new(HoldingRuntime::new(inner.clone()));
        let filesystem = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
        let (handle, _stream) = inner
            .block_on(Tree::open_outside_host_governor(
                filesystem.clone(),
                filesystem.root().to_path_buf(),
                Arc::new(LoadAll),
                tree_fucker::Config::default(),
                runtime.clone(),
                host.clone(),
            ))
            .unwrap();
        inner.block_on(handle.initial_scan_complete()).unwrap();
        assert_eq!(filesystem.watch_count(), 1);
        let mut refresh = std::pin::pin!(handle.refresh(vec![RelativePath::root()]));
        if held_worker {
            runtime.hold_next(1);
            let mut context = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
            assert!(refresh.as_mut().poll(&mut context).is_pending());
            inner.run_until_stalled();
            assert_eq!(runtime.held(), 1);
            assert_eq!(host.view(NOW).in_flight, 1);
        }
        std::fs::rename(root.path().join("scope"), root.path().join("old")).unwrap();
        if fail_before_shutdown {
            assert_eq!(host.try_admit(request(&host), NOW), Err(ThrottleCause::CoordinationFailed));
        }
        inner.block_on(handle.shutdown()).unwrap();
        inner.run_until_stalled();
        assert_eq!(host.view(NOW).watch_release_grants, 0, "failed authority cannot authorize new cleanup I/O");
        if held_worker {
            assert_eq!(host.view(NOW).in_flight, 1, "terminal cleanup must retain dispatched ownership");
            assert!(Arc::strong_count(&filesystem) > 1);
            runtime.release();
            inner.run_until_stalled();
        }
        assert_eq!(host.view(NOW).in_flight, 0);
        assert_eq!(
            Arc::strong_count(&filesystem),
            1,
            "terminal actor must release its filesystem after dispatched workers finish"
        );
    }
}
