use std::sync::Arc;
use std::time::Duration;

use tree_fucker::core::{Command, JobOperation};
use tree_fucker::testing::{FailureMode, FakeFileSystem, FakeOp, Harness};
use tree_fucker::update::{
    ErrorCause, InitialScanState, Operation, RecoverableError, RootAvailability, RoundResult, UpdateEvent,
};
use tree_fucker::{
    Config, EntryKind, Error, FsError, LoadAll, LoadDepth, LoadState, MetadataFields, PathChange, RelativePath,
    WatcherKind,
};

fn path(p: &str) -> RelativePath {
    RelativePath::parse(p).expect("valid path")
}

fn sizes() -> Config {
    Config { metadata_fields: MetadataFields { size: true, ..MetadataFields::NONE }, ..Default::default() }
}

fn populated(watcher: WatcherKind) -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(watcher));
    fs.mkdir("a");
    fs.mkdir("a/b");
    fs.create_file("a/b/f1", 10);
    fs.create_file("a/f2", 20);
    fs.mkdir("c");
    fs.create_file("root.txt", 5);
    fs
}

#[test]
fn initial_scan_builds_tree() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), sizes()).expect("open");
    h.run_until_idle();
    assert_eq!(h.paths(), [".", "a", "a/b", "a/b/f1", "a/f2", "c", "root.txt"]);
    assert!(matches!(h.health().initial_scan, InitialScanState::Complete { .. }));
    let t = h.command(Command::InitialScanComplete);
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(h.entry("a/b").map(|e| e.load_state()), Some(Some(LoadState::Loaded)));
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(Some(20)));
    let versions: Vec<u64> = h.events().iter().filter_map(|e| e.version().map(|v| v.get())).collect();
    assert!(versions.windows(2).all(|w| w[0] <= w[1]));
}

#[test]
fn depth_policy_leaves_deeper_directories_unloaded_until_loaded() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadDepth { depth: 1 }));
    h.run_until_idle();
    assert_eq!(h.paths(), [".", "a", "c", "root.txt"]);
    assert_eq!(h.entry("a").and_then(|e| e.load_state()), Some(LoadState::Unloaded));
    let t = h.command(Command::Load(path("a")));
    assert_eq!(h.result(t), None);
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(h.entry("a").and_then(|e| e.load_state()), Some(LoadState::Loaded));
    assert_eq!(h.paths(), [".", "a", "a/b", "a/f2", "c", "root.txt"]);
    assert_eq!(h.entry("a/b").and_then(|e| e.load_state()), Some(LoadState::Unloaded));
    let t = h.command(Command::Unload(path("a")));
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(h.paths(), [".", "a", "c", "root.txt"]);
    let t = h.command(Command::Load(path("root.txt")));
    assert_eq!(h.result(t), Some(Err(Error::NotDirectory)));
    let t = h.command(Command::Load(path("nope")));
    assert_eq!(h.result(t), Some(Err(Error::NotFound)));
}

#[test]
fn reconciliation_round_detects_changes_without_events_or_mtime() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), sizes()).expect("open");
    h.run_until_idle();
    let mtime = fs.mtime("a").expect("mtime");
    fs.add_silently("a/new", EntryKind::File);
    fs.remove_silently("a/f2");
    fs.set_size_silently("a/b/f1", 99);
    assert_eq!(fs.mtime("a"), Some(mtime));
    assert!(!h.paths().contains(&"a/new".to_string()));
    h.run_round();
    assert!(h.paths().contains(&"a/new".to_string()));
    assert!(!h.paths().contains(&"a/f2".to_string()));
    h.run_until_idle();
    assert_eq!(h.entry("a/b/f1").map(|e| e.metadata.size), Some(Some(99)));
    h.run_round();
    assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful));
    assert!(fs.count_ops(FakeOp::ReadDir, "a") >= 2);
}

#[test]
fn watcher_hint_schedules_listing_before_round() {
    let fs = populated(WatcherKind::Recursive);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    assert_eq!(fs.watch_count(), 1);
    fs.create_file("c/late", 1);
    h.run_until_idle();
    assert!(h.paths().contains(&"c/late".to_string()));
    assert!(h.stats().last_round.is_none());
}

#[test]
fn dropped_watcher_events_are_repaired_by_reconciliation() {
    let fs = populated(WatcherKind::Recursive);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    fs.drop_events(true);
    fs.mkdir("c/d");
    fs.create_file("c/d/x", 1);
    fs.remove("root.txt");
    h.run_until_idle();
    assert!(!h.paths().contains(&"c/d".to_string()));
    h.run_round();
    h.run_until_idle();
    assert!(h.paths().contains(&"c/d/x".to_string()));
    assert!(!h.paths().contains(&"root.txt".to_string()));
}

#[test]
fn refresh_target_resolution() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open(fs.clone(), Arc::new(LoadDepth { depth: 1 }), sizes()).expect("open");
    h.run_until_idle();
    let t = h.command(Command::Refresh(vec![path("missing/deeper")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    let t = h.command(Command::Refresh(vec![path("a/b/f1")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Err(Error::NotLoaded)));
    fs.add_silently("late", EntryKind::File);
    let t = h.command(Command::Refresh(vec![path("late")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert!(h.paths().contains(&"late".to_string()));
    let t = h.command(Command::Refresh(vec![path("root.txt/child")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Err(Error::NotDirectory)));
    fs.set_size_silently("root.txt", 77);
    let t = h.command(Command::Refresh(vec![path("root.txt")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(h.entry("root.txt").map(|e| e.metadata.size), Some(Some(77)));
}

#[test]
fn refresh_of_removed_entry_commits_removal() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    fs.remove_silently("a/f2");
    let t = h.command(Command::Refresh(vec![path("a/f2")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert!(!h.paths().contains(&"a/f2".to_string()));
}

#[test]
fn path_changes_follow_canonical_order() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), sizes()).expect("open");
    h.run_until_idle();
    h.take_events();
    fs.remove_silently("a/b");
    fs.add_silently("a/z", EntryKind::File);
    fs.set_size_silently("a/f2", 1);
    let t = h.command(Command::Refresh(vec![path("a")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    let deltas: Vec<&UpdateEvent> = h.events().iter().filter(|e| matches!(e, UpdateEvent::Delta(_))).collect();
    assert_eq!(deltas.len(), 1);
    let UpdateEvent::Delta(update) = deltas[0] else { panic!("delta") };
    let rendered: Vec<(u8, String)> = update.changes.iter().map(|c| (c.phase(), c.path().to_string())).collect();
    assert_eq!(rendered, [(0, "a/b/f1".into()), (0, "a/b".into()), (4, "a/z".into()), (5, "a/f2".into())]);
    assert!(matches!(update.changes[3], PathChange::MetadataChanged { .. }));
    assert_eq!(update.previous_version.next(), update.new_version);
}

#[test]
fn transient_failure_degrades_round_on_first_attempt_and_retries() {
    let fs = populated(WatcherKind::None);
    let config = Config { fixed_interval: Some(Duration::from_secs(10)), ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    fs.fail("c", FakeOp::ReadDir, FailureMode::Once(FsError::Transient("flaky".into())));
    h.run_round();
    assert_eq!(
        h.health().reconciliation.last_round,
        Some(RoundResult::Degraded { unsatisfied: [path("c")].into_iter().collect() })
    );
    assert!(h.health().reconciliation.degraded_paths.is_empty());
    h.advance(Duration::from_secs(600));
    assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful));
}

#[test]
fn permission_denied_marks_path_degraded_and_keeps_children() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    fs.fail("a", FakeOp::ReadDir, FailureMode::Always(FsError::PermissionDenied));
    h.run_round();
    assert!(h.health().reconciliation.degraded_paths.contains(&path("a")));
    assert!(h.paths().contains(&"a/b/f1".to_string()));
    fs.clear_failures();
    h.run_round();
    assert!(h.health().reconciliation.degraded_paths.is_empty());
}

#[test]
fn root_loss_publishes_empty_snapshot_and_recovers_with_new_incarnation() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    let old_root_id = h.entry("").expect("root").id;
    let old_health = h.health();
    let RootAvailability::Available { incarnation: first } = old_health.root else { panic!("available") };
    fs.remove_root();
    h.fire_timer();
    assert!(h.snapshot().is_empty());
    assert_eq!(h.health().root, RootAvailability::Unavailable { last: first });
    assert_eq!(h.health().initial_scan, InitialScanState::Unavailable);
    let t = h.command(Command::Load(path("a")));
    assert_eq!(h.result(t), Some(Err(Error::RootUnavailable)));
    fs.restore_root();
    fs.mkdir("fresh");
    h.advance(Duration::from_secs(600));
    assert_eq!(h.paths(), [".", "fresh"]);
    let RootAvailability::Available { incarnation: second } = h.health().root else { panic!("recovered") };
    assert!(second > first);
    assert_ne!(h.entry("").expect("root").id, old_root_id);
}

#[test]
fn unload_cancels_in_flight_work_and_stale_results_never_commit() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    fs.add_silently("a/late", EntryKind::File);
    let t = h.command(Command::Refresh(vec![path("a")]));
    let job = h.pending_job_for("a").expect("listing job in flight");
    let u = h.command(Command::Unload(path("a")));
    assert_eq!(h.result(u), Some(Ok(())));
    assert!(h.cancelled().contains(&job.id));
    h.run_until_idle();
    assert!(!h.paths().contains(&"a/late".to_string()));
    assert!(h.result(t).is_some());
}

#[test]
fn a_cancelled_worker_keeps_its_physical_slot_until_it_returns() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("d0");
    fs.mkdir("d1");
    fs.mkdir("d2");
    let config = Config { batch_size: 4, max_in_flight: 2, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    let t = h.command(Command::Refresh(vec![path("d0"), path("d1"), path("d2")]));
    assert_eq!(h.pending_jobs().len(), 2);
    assert_eq!(h.stats().blocking_slots_held, 2);
    let cancelled = h.pending_job_for("d0").expect("d0 listing in flight");
    let u = h.command(Command::Unload(path("d0")));
    assert_eq!(h.result(u), Some(Ok(())));
    assert!(h.cancelled().contains(&cancelled.id));
    assert_eq!(h.outstanding_jobs(), vec![cancelled.clone()]);
    assert!(h.pending_job_for("d2").is_none(), "a replacement job took the slot of a worker that never returned");
    assert_eq!(h.stats().in_flight_jobs, 1);
    assert_eq!(h.stats().blocking_slots_held, 2);
    let held = h.stats().blocking_slots;
    let slot = held.iter().find(|s| s.job == cancelled.id).expect("cancelled worker still holds a slot");
    assert_eq!(slot.path, path("d0"));
    assert_eq!(slot.operation, JobOperation::Listing);
    assert_eq!(slot.started, h.now());
    assert!(h.complete_outstanding_job(cancelled.id));
    assert!(h.stats().blocking_slots.iter().all(|s| s.job != cancelled.id));
    assert!(h.pending_job_for("d2").is_some(), "the released slot admitted no queued job");
    assert_eq!(h.stats().blocking_slots_held, 2);
    h.run_until_idle();
    assert_eq!(h.stats().blocking_slots_held, 0);
    assert!(h.result(t).is_some());
}

#[test]
fn shutdown_keeps_a_started_worker_slot_held_until_the_worker_returns() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    let t = h.command(Command::Refresh(vec![path("a")]));
    let job = h.pending_job_for("a").expect("listing in flight");
    assert_eq!(h.stats().blocking_slots_held, 1);
    let s = h.command(Command::Shutdown);
    assert_eq!(h.result(s), Some(Ok(())));
    assert!(h.stopped());
    assert_eq!(h.result(t), Some(Err(Error::Shutdown)));
    assert_eq!(h.stats().in_flight_jobs, 0);
    assert_eq!(h.stats().blocking_slots_held, 1);
    assert_eq!(h.stats().blocking_slots[0].job, job.id);
    assert_eq!(h.stats().blocking_slots[0].path, path("a"));
    assert!(h.complete_outstanding_job(job.id));
    assert_eq!(h.stats().blocking_slots_held, 0);
    assert!(!h.paths().contains(&"a/late".to_string()));
}

#[test]
fn overflow_requires_new_coverage_generation() {
    let fs = populated(WatcherKind::Recursive);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    h.run_round();
    assert!(!h.health().reconciliation.coverage_pending);
    fs.emit_overflow();
    h.run_until_idle();
    assert!(h.health().reconciliation.coverage_pending);
    h.run_round();
    assert!(!h.health().reconciliation.coverage_pending);
}

#[test]
fn entries_per_directory_limit_degrades_without_truncating() {
    let fs = populated(WatcherKind::None);
    let config = Config { entries_per_directory: 2, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    assert_eq!(h.paths(), ["."]);
    assert!(matches!(h.health().initial_scan, InitialScanState::Degraded { .. }));
    let t = h.command(Command::InitialScanComplete);
    assert!(matches!(h.result(t), Some(Err(Error::InitialScanDegraded(_)))));
    assert!(h.health().reconciliation.degraded_paths.contains(&path("")));
}

#[test]
fn invalid_child_name_rejects_the_whole_listing_and_degrades_the_round() {
    let fs = populated(WatcherKind::None);
    fs.create_file("a/f3", 30);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    assert!(h.paths().contains(&"a/f3".to_string()));
    h.take_events();
    fs.remove_silently("a/f3");
    fs.inject_child("a", "..", EntryKind::File);
    h.run_round();
    assert!(h.paths().contains(&"a/f3".to_string()));
    assert!(h.paths().contains(&"a/b".to_string()));
    assert!(h.paths().contains(&"a/f2".to_string()));
    let removals: Vec<&PathChange> = h
        .events()
        .iter()
        .filter_map(|e| match e {
            UpdateEvent::Delta(update) => Some(&update.changes),
            _ => None,
        })
        .flatten()
        .filter(|c| matches!(c, PathChange::Removed { .. }))
        .collect();
    assert!(removals.is_empty(), "{removals:?}");
    let invalid: Vec<&RecoverableError> = h
        .events()
        .iter()
        .filter_map(|e| match e {
            UpdateEvent::Delta(update) => Some(&update.errors),
            UpdateEvent::Health { errors, .. } => Some(errors),
            _ => None,
        })
        .flatten()
        .filter(|e| matches!(e.error, ErrorCause::InvalidName(_)))
        .collect();
    assert_eq!(invalid.len(), 1);
    assert_eq!(invalid[0].path, path("a"));
    assert_eq!(invalid[0].operation, Operation::Listing);
    assert_eq!(
        h.health().reconciliation.last_round,
        Some(RoundResult::Degraded { unsatisfied: [path("a")].into_iter().collect() })
    );
    assert!(h.health().reconciliation.degraded_paths.is_empty());
    fs.clear_injected_children();
    h.run_round();
    assert!(!h.paths().contains(&"a/f3".to_string()));
    h.run_round();
    assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful));
}

#[test]
fn duplicate_child_name_is_skipped_and_reported_without_rejecting_the_listing() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    h.take_events();
    fs.remove_silently("a/f2");
    fs.inject_child("a", "b", EntryKind::File);
    h.run_round();
    assert!(!h.paths().contains(&"a/f2".to_string()));
    assert_eq!(h.entry("a/b").map(|e| e.kind()), Some(EntryKind::Directory));
    assert!(h.paths().contains(&"a/b/f1".to_string()));
    let duplicate: Vec<&RecoverableError> = h
        .events()
        .iter()
        .filter_map(|e| match e {
            UpdateEvent::Delta(update) => Some(&update.errors),
            UpdateEvent::Health { errors, .. } => Some(errors),
            _ => None,
        })
        .flatten()
        .filter(|e| matches!(e.error, ErrorCause::DuplicateName(_)))
        .collect();
    assert_eq!(duplicate.len(), 1);
    assert_eq!(duplicate[0].path, path("a"));
    assert_eq!(duplicate[0].operation, Operation::Listing);
    assert!(h.health().reconciliation.degraded_paths.is_empty());
    h.run_round();
    assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful));
    fs.clear_injected_children();
    h.run_round();
    assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful));
}

#[test]
fn shutdown_publishes_terminal_and_rejects_later_commands() {
    let fs = populated(WatcherKind::Recursive);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    let t = h.command(Command::Shutdown);
    assert_eq!(h.result(t), Some(Ok(())));
    assert!(h.stopped());
    assert!(matches!(h.events().last(), Some(UpdateEvent::Terminal { .. })));
    assert_eq!(fs.watch_count(), 0);
    let t = h.command(Command::Refresh(vec![path("")]));
    assert_eq!(h.result(t), Some(Err(Error::Shutdown)));
}

#[test]
fn symlinks_are_represented_without_traversal() {
    let fs = populated(WatcherKind::None);
    fs.create_symlink("link");
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    assert_eq!(h.entry("link").map(|e| e.kind()), Some(EntryKind::Symlink));
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "link"), 0);
}

#[test]
fn kind_change_removes_descendants_and_reports_kind_change() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    h.take_events();
    fs.remove_silently("a/b");
    fs.add_silently("a/b", EntryKind::File);
    let t = h.command(Command::Refresh(vec![path("a/b")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(h.entry("a/b").map(|e| e.kind()), Some(EntryKind::File));
    assert!(!h.paths().contains(&"a/b/f1".to_string()));
}

#[test]
fn priority_directories_get_listed_each_periodic_cycle() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    let t = h.command(Command::SetPriority(vec![path("c")]));
    assert_eq!(h.result(t), Some(Ok(())));
    fs.clear_ops();
    h.fire_timer();
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "c"), 1);
}

#[test]
fn invalid_config_is_rejected() {
    let fs = populated(WatcherKind::None);
    let config = Config { batch_size: 1, ..Default::default() };
    assert!(matches!(Harness::open(fs, Arc::new(LoadAll), config), Err(Error::InvalidConfig(_))));
}

#[test]
fn lost_designated_worker_degrades_round_keeps_snapshot_and_retries_with_backoff() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    h.take_events();
    h.fire_timer_only();
    let a_job = h.pending_job_for("a").expect("a job");
    assert!(h.lose_job(a_job.id));
    assert!(!h.lose_job(a_job.id));
    let lost: Vec<&RecoverableError> = h
        .events()
        .iter()
        .filter_map(|e| match e {
            UpdateEvent::Health { errors, .. } => Some(errors),
            _ => None,
        })
        .flatten()
        .filter(|e| e.error == ErrorCause::WorkerLost)
        .collect();
    assert_eq!(lost.len(), 1);
    assert_eq!(lost[0].path, path("a"));
    assert_eq!(lost[0].operation, Operation::Listing);
    assert_eq!(h.stats().lost_workers, 1);
    assert!(h.pending_job_for("a").is_none());
    h.complete_all_jobs();
    assert_eq!(
        h.health().reconciliation.last_round,
        Some(RoundResult::Degraded { unsatisfied: [path("a")].into_iter().collect() })
    );
    assert!(h.health().reconciliation.degraded_paths.is_empty());
    assert!(h.paths().contains(&"a/b/f1".to_string()));
    assert!(h.pending_jobs().is_empty());
    let before = fs.count_ops(FakeOp::ReadDir, "a");
    let due = h.timer().map(|(_, at)| at).expect("retry timer armed");
    assert!(due > h.now());
    h.advance(Duration::from_secs(60));
    assert!(fs.count_ops(FakeOp::ReadDir, "a") > before);
    assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful));
}

#[test]
fn lost_worker_keeps_the_refresh_barrier_and_completes_it_on_retry() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    fs.add_silently("c/late", EntryKind::File);
    let t = h.command(Command::Refresh(vec![path("c")]));
    let job = h.pending_job_for("c").expect("c listing");
    assert!(h.lose_job(job.id));
    assert_eq!(h.result(t), None);
    h.advance(Duration::from_secs(60));
    assert_eq!(h.result(t), Some(Ok(())));
    assert!(h.paths().contains(&"c/late".to_string()));
}

#[test]
fn a_metadata_read_does_not_satisfy_a_refresh_that_still_needs_a_listing() {
    let fs = populated(WatcherKind::Recursive);
    fs.fail("a", FakeOp::ReadDir, FailureMode::Once(FsError::Transient("io".into())));
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    assert_eq!(h.entry("a").and_then(|e| e.load_state()), Some(LoadState::Loading));
    let t = h.command(Command::Refresh(vec![path("a")]));
    let job = h.pending_job_for("a").expect("a listing");
    assert!(h.lose_job(job.id));
    assert_eq!(h.result(t), None);
    fs.touch("a");
    h.deliver_watcher_events();
    let metadata = h.pending_job_for("a").expect("a metadata read");
    assert_eq!(metadata.operation, JobOperation::Metadata);
    h.complete_job(metadata.id);
    assert_eq!(h.result(t), None);
    assert_eq!(h.entry("a").and_then(|e| e.load_state()), Some(LoadState::Loading));
    h.advance(Duration::from_secs(60));
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(h.entry("a").and_then(|e| e.load_state()), Some(LoadState::Loaded));
    assert!(h.paths().contains(&"a/b".to_string()));
}

#[test]
fn a_lost_metadata_worker_keeps_the_stronger_listing_requirement() {
    let fs = populated(WatcherKind::Recursive);
    fs.fail("a", FakeOp::ReadDir, FailureMode::Once(FsError::Transient("io".into())));
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    let t = h.command(Command::Refresh(vec![path("a")]));
    let listing = h.pending_job_for("a").expect("a listing");
    assert!(h.lose_job(listing.id));
    fs.touch("a");
    h.deliver_watcher_events();
    let metadata = h.pending_job_for("a").expect("a metadata read");
    assert_eq!(metadata.operation, JobOperation::Metadata);
    assert!(h.lose_job(metadata.id));
    assert_eq!(h.result(t), None);
    h.advance(Duration::from_secs(60));
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(h.entry("a").and_then(|e| e.load_state()), Some(LoadState::Loaded));
    assert!(h.paths().contains(&"a/b".to_string()));
}

#[test]
fn a_failed_metadata_read_keeps_the_refresh_barrier_and_the_listing_requirement() {
    let fs = populated(WatcherKind::Recursive);
    fs.fail("a", FakeOp::ReadDir, FailureMode::Once(FsError::Transient("io".into())));
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    assert_eq!(h.entry("a").and_then(|e| e.load_state()), Some(LoadState::Loading));
    let t = h.command(Command::Refresh(vec![path("a")]));
    let listing = h.pending_job_for("a").expect("a listing");
    assert!(h.lose_job(listing.id));
    fs.fail("a", FakeOp::Metadata, FailureMode::Once(FsError::Transient("io".into())));
    fs.touch("a");
    h.deliver_watcher_events();
    let metadata = h.pending_job_for("a").expect("a metadata read");
    assert_eq!(metadata.operation, JobOperation::Metadata);
    assert!(h.complete_job(metadata.id));
    assert_eq!(h.result(t), None);
    h.advance(Duration::from_secs(600));
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(h.entry("a").and_then(|e| e.load_state()), Some(LoadState::Loaded));
    assert!(h.paths().contains(&"a/b".to_string()));
}

#[test]
fn a_failed_metadata_read_keeps_the_initial_scan_recovery_reason() {
    let fs = populated(WatcherKind::Recursive);
    fs.fail("a", FakeOp::ReadDir, FailureMode::Once(FsError::Transient("io".into())));
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    assert!(matches!(h.health().initial_scan, InitialScanState::Degraded { .. }));
    fs.fail("a", FakeOp::Metadata, FailureMode::Once(FsError::Transient("io".into())));
    fs.touch("a");
    h.deliver_watcher_events();
    let metadata = h.pending_job_for("a").expect("a metadata read");
    assert_eq!(metadata.operation, JobOperation::Metadata);
    assert!(h.complete_job(metadata.id));
    h.advance(Duration::from_secs(600));
    assert_eq!(h.entry("a").and_then(|e| e.load_state()), Some(LoadState::Loaded));
    assert!(h.paths().contains(&"a/b/f1".to_string()));
    assert!(matches!(h.health().initial_scan, InitialScanState::Complete { .. }));
}

#[test]
fn retry_deadlines_stay_armed_through_merge_clearing_and_removal() {
    let fs = populated(WatcherKind::None);
    let config = Config { fixed_interval: Some(Duration::from_secs(600)), ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    fs.fail("a", FakeOp::ReadDir, FailureMode::Always(FsError::Transient("io".into())));
    fs.fail("c", FakeOp::ReadDir, FailureMode::Once(FsError::Transient("io".into())));
    h.run_round();
    let installed_at = h.now();
    let installed = h.timer().map(|(_, at)| at).expect("retry timer armed");
    assert!(installed <= installed_at + Duration::from_secs(3), "{installed:?}");
    let before = fs.count_ops(FakeOp::ReadDir, "a");
    h.advance(Duration::from_secs(3));
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a"), before + 1);
    let merged_at = h.now();
    let merged = h.timer().map(|(_, at)| at).expect("merged retry timer armed");
    assert!(merged.saturating_sub(merged_at) > installed.saturating_sub(installed_at), "{merged:?} {installed:?}");
    fs.clear_failures();
    fs.remove_silently("a");
    let t = h.command(Command::Refresh(vec![path("a")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert!(!h.paths().contains(&"a".to_string()));
    let remaining = h.timer().map(|(_, at)| at).expect("periodic timer armed");
    assert!(remaining > h.now() + Duration::from_secs(300), "{remaining:?}");
    h.advance(Duration::from_secs(1800));
    assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful));
}

#[test]
fn lost_initial_scan_worker_keeps_the_obligation_pending_and_recovers() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    let root_job = h.pending_job_for("").expect("root listing");
    let t = h.command(Command::InitialScanComplete);
    assert!(h.lose_job(root_job.id));
    assert!(matches!(h.health().initial_scan, InitialScanState::Running { .. }));
    assert_eq!(h.result(t), None);
    assert!(h.pending_jobs().is_empty());
    h.advance(Duration::from_secs(60));
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(h.paths().len(), 7);
    assert!(matches!(h.health().initial_scan, InitialScanState::Complete { .. }));
}

#[test]
fn lost_root_probe_worker_schedules_another_probe() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    fs.remove_root();
    h.fire_timer();
    assert!(h.snapshot().is_empty());
    fs.restore_root();
    h.advance(Duration::from_secs(1));
    let probe = loop {
        if let Some(job) = h.pending_job_for("") {
            break job;
        }
        assert!(h.fire_timer_only(), "probe never dispatched");
    };
    assert!(h.lose_job(probe.id));
    assert!(!h.snapshot().is_empty() || h.pending_jobs().is_empty());
    h.advance(Duration::from_secs(600));
    assert!(h.paths().contains(&".".to_string()));
    assert!(matches!(h.health().root, tree_fucker::update::RootAvailability::Available { .. }));
}
