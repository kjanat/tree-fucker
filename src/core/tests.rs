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
