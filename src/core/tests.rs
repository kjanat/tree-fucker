use std::sync::Arc;
use std::time::Duration;

use super::types::{
    Class, DegradedCause, EntryState, EntryStates, InitialScan, MonotonicTime, Reasons, RetryPhase, RetryRecord,
};
use super::{Command, Coordinator};
use crate::config::{Config, WatchRegistrationFailure};
use crate::entry::EntryKind;
use crate::error::Error;
use crate::fs::{FsError, WatcherKind};
use crate::ids::{EntryId, LoadGeneration, ReconciliationGeneration};
use crate::path::RelativePath;
use crate::policy::LoadAll;
use crate::testing::{FailureMode, FakeFileSystem, FakeOp, Harness};
use crate::update::InitialScanState;

fn path(p: &str) -> RelativePath {
    RelativePath::parse(p).expect("valid path")
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
#[test]
fn cancelled_shared_preparations_refund_only_the_unstarted_command_lease() {
    use super::{GrantId, JobPhase, JobResult, Reservation, WorkOrigin};
    use crate::coordination::{authority, native::Scope};
    use crate::{DomainCapabilities, HostConfig, HostGovernor, SessionCost, SessionStep};

    for resumed in [false, true] {
        for load in [false, true] {
            #[cfg(target_os = "linux")]
            let root = tempfile::tempdir_in("/dev/shm").unwrap();
            #[cfg(any(target_os = "freebsd", target_os = "illumos", target_os = "macos"))]
            let root = tempfile::tempdir_in("/var/run/tree-fucker").unwrap();
            #[cfg(windows)]
            let root = tempfile::tempdir().unwrap();
            let config = HostConfig { maximum_in_flight: 2, per_domain_concurrency: 2, ..Default::default() };
            let scope =
                Scope::open(root.path().join("commands"), authority::Config::from_host(&config, 8, 16, 16).unwrap())
                    .unwrap();
            let host = HostGovernor::with_coordination(&config, scope.clone()).unwrap();
            let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
            fs.set_default_capabilities(DomainCapabilities::inline());
            fs.mkdir("child");
            let mut h = Harness::open_under(fs, Arc::new(LoadAll), Config::default(), host.clone()).unwrap();
            h.run_until_idle();
            if load {
                h.command(Command::Unload(path("child")));
            }
            // Keep the Tree's dispatch ceiling at one while another holder
            // uses the shared host. This lets a resumed lease queue as well.
            h.coordinator.maximum_in_flight = 1;
            let held = GrantId::Bootstrap(host.next_bootstrap());
            let hold = |now| {
                host.try_admit(
                    Reservation {
                        id: held,
                        path: RelativePath::root(),
                        reads: 1,
                        registrations: 0,
                        operations: 0,
                        ceiling: None,
                        lease: 0,
                        domain: None,
                        origin: WorkOrigin::Background,
                        listing: false,
                    },
                    now,
                )
                .unwrap();
                host.try_start(held, now).unwrap();
            };
            if !resumed {
                hold(h.now());
            }
            let command = if load { Command::Load(path("child")) } else { Command::Refresh(vec![path("child")]) };
            let ticket = h.command(command);
            let spent = if resumed {
                let spent = h.coordinator.commands.get(&ticket.0).unwrap().admitted;
                let job = h.pending_job_for("child").unwrap();
                hold(h.now());
                assert!(h.complete_job_with(
                    job.id,
                    JobResult::Listing(SessionStep::suspended(SessionCost {
                        listing_operations: 1,
                        ..Default::default()
                    }))
                ));
                spent
            } else {
                Duration::ZERO
            };
            let queued = h.coordinator.jobs.values().find(|job| job.path == path("child")).unwrap();
            assert_eq!(queued.phase, JobPhase::Queued);
            let id = queued.id;
            assert!(h.coordinator.commands.get(&ticket.0).unwrap().admitted > spent);
            let ceiling = h.coordinator.config.foreground_ceiling_per_command;
            h.coordinator.config.foreground_ceiling_per_command =
                h.coordinator.commands.get(&ticket.0).unwrap().admitted;
            h.coordinator.enforce_command_ceilings();
            assert!(h.coordinator.commands.contains_key(&ticket.0), "a reversible hold cannot exhaust the command");
            h.coordinator.config.foreground_ceiling_per_command = ceiling;
            h.coordinator.cancel_job(id);
            assert_eq!(
                h.coordinator.commands.get(&ticket.0).unwrap().admitted,
                spent,
                "resumed={resumed}, load={load}"
            );
            assert_eq!(host.view(h.now()).preparations, 0);
            assert_eq!(h.result(ticket), None);
            host.release(held, h.now());
            h.advance(Duration::ZERO);
            h.run_until_idle();
            assert_eq!(h.result(ticket), Some(Ok(())));
            h.command(Command::Shutdown);
            assert_eq!((scope.view().unwrap().prepared, scope.view().unwrap().physical), (0, 0));
        }
    }
}

fn scanned_coverage_pending(coordinator: &Coordinator) -> bool {
    coordinator.min_recon > ReconciliationGeneration::new(0)
        && coordinator.snapshot.loaded_directories().any(|dir| {
            coordinator.entries.covered_through(dir.id).map(|covered| covered < coordinator.min_recon).unwrap_or(true)
        })
}

#[test]
fn a_persistently_failing_target_retains_no_barrier_for_a_finished_command() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("a");
    fs.create_file("a/f", 1);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    let id = h.entry("a").expect("a is represented").id;
    fs.fail("a", FakeOp::ReadDir, FailureMode::Always(FsError::Transient("io".into())));
    for _ in 0..12 {
        let ticket = h.command(Command::Refresh(vec![path("a")]));
        h.run_until_idle();
        assert!(matches!(h.result(ticket), Some(Err(Error::Io(FsError::Transient(_))))), "{:?}", h.result(ticket));
        h.advance(Duration::from_secs(1));
    }
    let record = h.coordinator.entries.retry(id).expect("retry record for a");
    assert!(record.barriers.is_empty(), "{:?}", record.barriers);
}

#[test]
fn a_completed_initial_scan_retains_no_terminal_obligation() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    for i in 0..200 {
        fs.mkdir(&format!("d{i:03}"));
    }
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    assert!(matches!(h.health().initial_scan, InitialScanState::Complete { .. }));
    assert_eq!(h.coordinator.initial_scan.open_obligations(), 0);
    h.run_round();
    h.run_round();
    assert!(matches!(h.health().initial_scan, InitialScanState::Complete { .. }));
    assert_eq!(h.coordinator.initial_scan.open_obligations(), 0);
}

#[test]
fn a_successful_watch_registration_advances_the_retry_phase_to_listing() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    fs.mkdir("c");
    fs.fail("c", FakeOp::Watch, FailureMode::Once(FsError::Transient("busy".into())));
    fs.fail("c", FakeOp::ReadDir, FailureMode::Always(FsError::Transient("io".into())));
    let config =
        Config { watch_registration_failure_mode: WatchRegistrationFailure::RequireWatcher, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    h.advance(Duration::from_secs(120));
    let id = h.entry("c").expect("c is represented").id;
    assert_eq!(fs.watch_count(), 2);
    assert!(fs.count_ops(FakeOp::ReadDir, "c") >= 2);
    let record = h.coordinator.entries.retry(id).expect("retry record for c");
    assert_eq!(record.phase, RetryPhase::Listing);
}

#[test]
fn a_retry_after_a_successful_watch_registration_uses_the_retry_class() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    fs.mkdir("c");
    fs.fail("c", FakeOp::Watch, FailureMode::Once(FsError::Transient("busy".into())));
    fs.fail("c", FakeOp::ReadDir, FailureMode::Always(FsError::Transient("io".into())));
    let config =
        Config { watch_registration_failure_mode: WatchRegistrationFailure::RequireWatcher, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    h.advance(Duration::from_secs(120));
    let id = h.entry("c").expect("c is represented").id;
    let record = h.coordinator.entries.retry(id).expect("retry record for c");
    assert_eq!(record.phase, RetryPhase::Listing);
    assert_eq!(record.reasons.expedited_class(), Class::Retry);
}

#[test]
fn a_retry_after_a_failed_refresh_uses_the_retry_class() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("a");
    fs.create_file("a/f", 1);
    let config = Config { fixed_interval: Some(Duration::from_secs(3600)), ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    let id = h.entry("a").expect("a is represented").id;
    fs.fail("a", FakeOp::ReadDir, FailureMode::Always(FsError::Transient("io".into())));
    let ticket = h.command(Command::Refresh(vec![path("a")]));
    h.run_until_idle();
    assert!(matches!(h.result(ticket), Some(Err(Error::Io(FsError::Transient(_))))), "{:?}", h.result(ticket));
    let record = h.coordinator.entries.retry(id).expect("retry record for a");
    assert_eq!(record.reasons.expedited_class(), Class::Retry);
    h.advance(Duration::from_secs(30));
    let record = h.coordinator.entries.retry(id).expect("retry record for a");
    assert_eq!(record.reasons.expedited_class(), Class::Retry);
}

#[test]
fn a_retry_after_a_failed_watcher_hint_uses_the_retry_class() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::Recursive));
    fs.mkdir("a");
    fs.create_file("a/f", 1);
    let config = Config { fixed_interval: Some(Duration::from_secs(3600)), ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    let id = h.entry("a").expect("a is represented").id;
    fs.fail("a", FakeOp::ReadDir, FailureMode::Always(FsError::Transient("io".into())));
    fs.create_file("a/g", 2);
    h.run_until_idle();
    let record = h.coordinator.entries.retry(id).expect("retry record for a");
    assert_eq!(record.reasons.expedited_class(), Class::Retry);
    h.advance(Duration::from_secs(30));
    let record = h.coordinator.entries.retry(id).expect("retry record for a");
    assert_eq!(record.reasons.expedited_class(), Class::Retry);
}

#[test]
fn an_untimed_failure_replaces_an_armed_transient_deadline() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("a");
    fs.create_file("a/f", 1);
    let config = Config { fixed_interval: Some(Duration::from_secs(3600)), ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    let id = h.entry("a").expect("a is represented").id;
    fs.fail("a", FakeOp::ReadDir, FailureMode::Once(FsError::Transient("io".into())));
    let ticket = h.command(Command::Refresh(vec![path("a")]));
    h.run_until_idle();
    assert!(matches!(h.result(ticket), Some(Err(Error::Io(FsError::Transient(_))))), "{:?}", h.result(ticket));
    assert!(h.coordinator.entries.retry(id).expect("retry record for a").due.is_some());
    fs.fail("a", FakeOp::ReadDir, FailureMode::Once(FsError::PermissionDenied));
    let ticket = h.command(Command::Refresh(vec![path("a")]));
    h.run_until_idle();
    assert!(matches!(h.result(ticket), Some(Err(Error::Io(FsError::PermissionDenied)))), "{:?}", h.result(ticket));
    let record = h.coordinator.entries.retry(id).expect("retry record for a");
    assert_eq!(record.phase, RetryPhase::Listing);
    assert_eq!(record.due, None);
    assert_eq!(h.coordinator.entries.earliest_retry(), None);
}

#[test]
fn coverage_pending_tracks_the_loaded_directory_set_after_an_overflow() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::Recursive));
    fs.mkdir("a");
    fs.mkdir("a/b");
    fs.mkdir("c");
    fs.create_file("a/b/f", 1);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    assert_eq!(h.health().reconciliation.coverage_pending, scanned_coverage_pending(&h.coordinator));
    h.run_round();
    assert_eq!(h.health().reconciliation.coverage_pending, scanned_coverage_pending(&h.coordinator));
    fs.emit_overflow();
    h.run_until_idle();
    assert!(h.health().reconciliation.coverage_pending);
    assert_eq!(h.health().reconciliation.coverage_pending, scanned_coverage_pending(&h.coordinator));
    let ticket = h.command(Command::Unload(path("a")));
    assert_eq!(h.result(ticket), Some(Ok(())));
    assert_eq!(h.health().reconciliation.coverage_pending, scanned_coverage_pending(&h.coordinator));
    let ticket = h.command(Command::Load(path("a")));
    h.run_until_idle();
    assert_eq!(h.result(ticket), Some(Ok(())));
    assert_eq!(h.health().reconciliation.coverage_pending, scanned_coverage_pending(&h.coordinator));
    fs.remove_silently("c");
    h.run_round();
    assert_eq!(h.health().reconciliation.coverage_pending, scanned_coverage_pending(&h.coordinator));
    h.run_round();
    assert!(!h.health().reconciliation.coverage_pending);
    assert_eq!(h.health().reconciliation.coverage_pending, scanned_coverage_pending(&h.coordinator));
    fs.remove_silently("a/b");
    fs.add_silently("a/b", EntryKind::File);
    h.run_round();
    h.run_until_idle();
    assert_eq!(h.health().reconciliation.coverage_pending, scanned_coverage_pending(&h.coordinator));
}

#[test]
fn a_degradation_cause_cannot_outlive_its_entry_state() {
    let mut states = EntryStates::default();
    let id = EntryId::new(7);
    states.set_degraded(id, Some(DegradedCause::Transient));
    assert_eq!(states.degraded_ids().count(), 0);
    states.entry_mut(id);
    states.set_degraded(id, Some(DegradedCause::Transient));
    assert_eq!(states.degraded_ids().collect::<Vec<EntryId>>(), vec![id]);
    states.remove(id);
    assert_eq!(states.degraded_ids().count(), 0);
    states.set_degraded(id, Some(DegradedCause::PermissionDenied));
    assert_eq!(states.degraded_ids().count(), 0);
}

#[test]
fn an_inserted_state_keeps_its_retry_deadline_schedulable() {
    let mut states = EntryStates::default();
    let id = EntryId::new(11);
    states.entry_mut(id);
    let due = MonotonicTime::ZERO + Duration::from_secs(5);
    states.set_retry(
        id,
        RetryRecord {
            phase: RetryPhase::Listing,
            attempts: 1,
            due: Some(due),
            reasons: Reasons::default(),
            barriers: Vec::new(),
        },
    );
    assert_eq!(states.earliest_retry(), Some(due));
    let carried = states.get(id).cloned().expect("state for the entry");
    states.insert(id, carried);
    assert_eq!(states.retry(id).and_then(|r| r.due), Some(due));
    assert_eq!(states.earliest_retry(), Some(due));
    assert_eq!(states.retries_due(due), vec![id]);
}

#[test]
fn an_inserted_state_keeps_its_degradation_reported() {
    let mut states = EntryStates::default();
    let id = EntryId::new(12);
    states.entry_mut(id);
    states.set_degraded(id, Some(DegradedCause::PermissionDenied));
    let carried = states.get(id).cloned().expect("state for the entry");
    states.insert(id, carried);
    assert_eq!(states.degraded_ids().collect::<Vec<EntryId>>(), vec![id]);
}

#[test]
fn a_directory_losing_its_kind_releases_its_coverage() {
    let mut states = EntryStates::default();
    let id = EntryId::new(13);
    states.insert(id, EntryState::directory());
    states.mark_loaded(id);
    assert!(states.coverage_pending(ReconciliationGeneration::new(1)));
    states.set_directory(id, false);
    assert!(!states.coverage_pending(ReconciliationGeneration::new(1)));
}

#[test]
fn an_accepted_listing_resolves_an_unsatisfied_initial_scan_obligation() {
    let mut scan = InitialScan::new();
    let id = EntryId::new(3);
    let generation = LoadGeneration::new(1);
    scan.record_pending(id, generation);
    scan.resolve_unsatisfied(id, path("a"));
    assert!(scan.any_unsatisfied());
    scan.resolve_accepted(id, generation.next());
    assert!(scan.any_unsatisfied());
    scan.resolve_accepted(id, generation);
    assert!(!scan.any_unsatisfied());
    assert!(!scan.any_pending());
    assert_eq!(scan.open_obligations(), 0);
}
