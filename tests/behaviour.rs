use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tree_fucker::core::Command;
use tree_fucker::fs::{DirectoryListing, EntryInfo, FsCapabilities};
use tree_fucker::policy::{PolicyContext, ScanDecision, ScanPolicy};
use tree_fucker::testing::{FailureMode, FakeFileSystem, FakeOp, Harness};
use tree_fucker::update::{ErrorCause, InitialScanState, Operation, RoundResult, UpdateEvent, WatcherHealth};
use tree_fucker::{
    CaseSensitivity, Config, EntryKind, Error, FsError, LoadAll, LoadState, PathChange, PathPredicate, PolicyRevision,
    RelativePath, WatchRegistrationFailure, WatcherKind,
};

fn path(p: &str) -> RelativePath {
    RelativePath::parse(p).expect("valid path")
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
fn per_directory_watcher_registers_before_each_first_listing() {
    let fs = populated(WatcherKind::NonRecursive);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    assert_eq!(fs.watch_count(), 4);
    let ops = fs.ops();
    for dir in ["", "a", "a/b", "c"] {
        let watch = ops.iter().position(|(op, p)| *op == FakeOp::Watch && *p == path(dir));
        let list = ops.iter().position(|(op, p)| *op == FakeOp::ReadDir && *p == path(dir));
        assert!(watch < list, "watch must precede listing for {dir}");
    }
    fs.create_file("c/late", 1);
    h.run_until_idle();
    assert!(h.paths().contains(&"c/late".to_string()));
    let t = h.command(Command::Unload(path("a")));
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(fs.watch_count(), 2);
}

#[test]
fn require_watcher_fails_open_when_root_registration_fails() {
    let fs = populated(WatcherKind::Recursive);
    fs.fail("", FakeOp::Watch, FailureMode::Always(FsError::Unsupported("nope".into())));
    let config = Config { watch_registration_failure: WatchRegistrationFailure::RequireWatcher, ..Default::default() };
    let result = Harness::open(fs, Arc::new(LoadAll), config);
    assert!(matches!(result, Err(Error::WatcherRegistrationFailed)));
}

#[test]
fn reconcile_only_degrades_watcher_health_and_continues() {
    let fs = populated(WatcherKind::Recursive);
    fs.fail("", FakeOp::Watch, FailureMode::Always(FsError::Unsupported("nope".into())));
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    assert!(matches!(h.health().watcher, WatcherHealth::Degraded { .. }));
    assert_eq!(h.paths().len(), 7);
    fs.add_silently("late", EntryKind::File);
    h.run_round();
    assert!(h.paths().contains(&"late".to_string()));
}

#[test]
fn require_watcher_blocks_listing_for_failed_directory_registration() {
    let fs = populated(WatcherKind::NonRecursive);
    fs.fail("c", FakeOp::Watch, FailureMode::Times(2, FsError::Transient("busy".into())));
    let config = Config { watch_registration_failure: WatchRegistrationFailure::RequireWatcher, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    assert_eq!(h.entry("c").and_then(|e| e.load_state()), Some(LoadState::Loading));
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "c"), 0);
    assert!(matches!(h.health().initial_scan, InitialScanState::Degraded { .. }));
    h.advance(Duration::from_secs(120));
    assert_eq!(h.entry("c").and_then(|e| e.load_state()), Some(LoadState::Loaded));
    assert!(matches!(h.health().initial_scan, InitialScanState::Complete { .. }));
}

#[test]
fn watcher_failure_restarts_with_new_coverage_generation() {
    let fs = populated(WatcherKind::Recursive);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    h.run_round();
    fs.emit_watcher_failure("inotify queue broke");
    h.run_until_idle();
    assert!(matches!(h.health().watcher, WatcherHealth::Degraded { .. }));
    assert!(h.health().reconciliation.coverage_pending);
    h.advance(Duration::from_secs(30));
    assert!(matches!(h.health().watcher, WatcherHealth::Healthy { .. }));
    assert_eq!(fs.watch_count(), 1);
    fs.create_file("after", 1);
    h.run_until_idle();
    assert!(h.paths().contains(&"after".to_string()));
}

struct DepthByMarker {
    revision: AtomicU64,
}

impl ScanPolicy for DepthByMarker {
    fn revision(&self) -> PolicyRevision {
        PolicyRevision::new(self.revision.load(Ordering::SeqCst))
    }

    fn root_context(&self, _root: &EntryInfo) -> PolicyContext {
        PolicyContext::new(1, true)
    }

    fn classify(&self, parent: &PolicyContext, _path: &RelativePath, _info: &EntryInfo) -> ScanDecision {
        let load = parent.get::<bool>().copied().unwrap_or(false);
        ScanDecision::Eligible { initially_loaded: load }
    }

    fn child_context(&self, parent: &PolicyContext, _path: &RelativePath, listing: &DirectoryListing) -> PolicyContext {
        let inherited = parent.get::<bool>().copied().unwrap_or(false);
        let stop = listing.entries.iter().any(|e| e.name == ".stop");
        let value = inherited && !stop;
        PolicyContext::new(u64::from(value), value)
    }
}

#[test]
fn derived_context_change_reevaluates_descendants() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(DepthByMarker { revision: AtomicU64::new(0) }));
    h.run_until_idle();
    assert_eq!(h.paths().len(), 7);
    fs.add_silently("a/.stop", EntryKind::File);
    let t = h.command(Command::Refresh(vec![path("a")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(h.entry("a/b").and_then(|e| e.load_state()), Some(LoadState::Unloaded));
    assert!(!h.paths().contains(&"a/b/f1".to_string()));
    fs.remove_silently("a/.stop");
    let t = h.command(Command::Refresh(vec![path("a")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(h.entry("a/b").and_then(|e| e.load_state()), Some(LoadState::Loaded));
    assert!(h.paths().contains(&"a/b/f1".to_string()));
}

#[test]
fn invalidate_policy_applies_new_decisions_and_waits_for_listings() {
    let fs = populated(WatcherKind::None);
    let policy = Arc::new(PathPredicate::new(|p: &RelativePath, _k| {
        if p.to_string() == "a" {
            ScanDecision::Eligible { initially_loaded: false }
        } else {
            ScanDecision::Eligible { initially_loaded: true }
        }
    }));
    let mut h = Harness::open_default(fs.clone(), policy.clone());
    h.run_until_idle();
    assert_eq!(h.entry("a").and_then(|e| e.load_state()), Some(LoadState::Unloaded));
    let excluded = Arc::new(PathPredicate::new(|p: &RelativePath, _k| {
        if p.to_string() == "c" { ScanDecision::Excluded } else { ScanDecision::Eligible { initially_loaded: true } }
    }));
    let mut h2 = Harness::open_default(fs.clone(), excluded.clone());
    h2.run_until_idle();
    assert_eq!(h2.entry("c").and_then(|e| e.load_state()), Some(LoadState::Excluded));
    let t = h2.command(Command::Load(path("c")));
    assert_eq!(h2.result(t), Some(Err(Error::PolicyDenied)));
    let t = h2.command(Command::InvalidatePolicy(vec![path("")]));
    h2.run_until_idle();
    assert_eq!(h2.result(t), Some(Ok(())));
    let policy2 =
        Arc::new(PathPredicate::new(|_p: &RelativePath, _k| ScanDecision::Eligible { initially_loaded: true }));
    let mut h3 = Harness::open_default(fs.clone(), policy2);
    h3.run_until_idle();
    let t = h3.command(Command::Unload(path("a")));
    assert_eq!(h3.result(t), Some(Ok(())));
    let t = h3.command(Command::InvalidatePolicy(vec![path("")]));
    h3.run_until_idle();
    assert_eq!(h3.result(t), Some(Ok(())));
    assert_eq!(h3.entry("a").and_then(|e| e.load_state()), Some(LoadState::Unloaded));
}

#[test]
fn policy_invalidation_loads_newly_selected_directories() {
    let fs = populated(WatcherKind::None);
    let switch = Arc::new(AtomicU64::new(0));
    let flag = switch.clone();
    let policy = Arc::new(PathPredicate::new(move |p: &RelativePath, _k| {
        if p.to_string() == "a" && flag.load(Ordering::SeqCst) == 0 {
            ScanDecision::Eligible { initially_loaded: false }
        } else {
            ScanDecision::Eligible { initially_loaded: true }
        }
    }));
    let mut h = Harness::open_default(fs.clone(), policy.clone());
    h.run_until_idle();
    assert_eq!(h.entry("a").and_then(|e| e.load_state()), Some(LoadState::Unloaded));
    switch.store(1, Ordering::SeqCst);
    policy.bump_revision();
    let t = h.command(Command::InvalidatePolicy(vec![path("a")]));
    assert_eq!(h.result(t), None);
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(h.entry("a/b").and_then(|e| e.load_state()), Some(LoadState::Loaded));
    assert!(h.paths().contains(&"a/b/f1".to_string()));
}

#[test]
fn priority_set_larger_than_batch_does_not_starve_baseline() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    for i in 0..12 {
        fs.mkdir(&format!("p{i:02}"));
    }
    fs.mkdir("zz");
    let config = Config { batch_size: 4, max_in_flight: 2, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    let priority: Vec<RelativePath> = (0..12).map(|i| path(&format!("p{i:02}"))).collect();
    let t = h.command(Command::SetPriority(priority));
    assert_eq!(h.result(t), Some(Ok(())));
    fs.add_silently("zz/found", EntryKind::File);
    h.run_round();
    h.run_until_idle();
    assert!(h.paths().contains(&"zz/found".to_string()));
    assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful));
    assert!(fs.count_ops(FakeOp::ReadDir, "p00") >= 1);
}

#[test]
fn pre_barrier_listing_does_not_satisfy_refresh() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    fs.add_silently("c/first", EntryKind::File);
    h.fire_timer_only();
    let first = h.pending_job_for("c").expect("baseline listing of c in flight");
    let t = h.command(Command::Refresh(vec![path("c")]));
    fs.add_silently("c/second", EntryKind::File);
    h.complete_job(first.id);
    assert_eq!(h.result(t), None);
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert!(h.paths().contains(&"c/second".to_string()));
}

#[test]
fn closed_batch_admits_nothing_until_every_member_settles() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    for i in 0..6 {
        fs.mkdir(&format!("d{i}"));
    }
    let config = Config { batch_size: 3, max_in_flight: 8, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    let root_job = h.pending_job_for("").expect("root listing");
    h.complete_job(root_job.id);
    let pending = h.pending_jobs();
    assert_eq!(pending.len(), 3);
    h.complete_job(pending[2].id);
    assert_eq!(h.pending_jobs().len(), 2);
    h.complete_job(pending[0].id);
    assert_eq!(h.pending_jobs().len(), 1);
    h.complete_job(pending[1].id);
    assert_eq!(h.pending_jobs().len(), 3);
    h.run_until_idle();
    assert_eq!(h.paths().len(), 7);
}

#[test]
fn case_insensitive_filesystem_folds_lookups() {
    let fs = Arc::new(FakeFileSystem::with_capabilities(FsCapabilities {
        case: CaseSensitivity::Insensitive,
        stable_identity: true,
        watcher: WatcherKind::None,
    }));
    fs.mkdir("Docs");
    fs.create_file("Docs/Readme.MD", 1);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    assert!(h.entry("docs/readme.md").is_some());
    assert_eq!(h.entry("DOCS").map(|e| e.path.to_string()), Some("Docs".into()));
    fs.rename("Docs/Readme.MD", "Docs/README.md");
    let t = h.command(Command::Refresh(vec![path("Docs")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(h.entry("docs/readme.md").map(|e| e.path.to_string()), Some("Docs/README.md".into()));
}

fn case_insensitive_fs(stable_identity: bool) -> Arc<FakeFileSystem> {
    Arc::new(FakeFileSystem::with_capabilities(FsCapabilities {
        case: CaseSensitivity::Insensitive,
        stable_identity,
        watcher: WatcherKind::None,
    }))
}

fn published_changes(h: &Harness) -> Vec<PathChange> {
    h.events()
        .iter()
        .filter_map(|e| match e {
            UpdateEvent::Delta(update) => Some(update.changes.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

#[test]
fn case_only_rename_with_matching_identity_keeps_the_entry_id() {
    let fs = case_insensitive_fs(true);
    fs.mkdir("Docs");
    fs.create_file("Docs/Readme.MD", 1);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    let old = h.entry("Docs/Readme.MD").expect("file").id;
    h.take_events();
    fs.rename("Docs/Readme.MD", "Docs/README.md");
    let t = h.command(Command::Refresh(vec![path("Docs")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    let entry = h.entry("docs/readme.md").expect("renamed file");
    assert_eq!(entry.id, old);
    assert_eq!(entry.path.to_string(), "Docs/README.md");
    let changes = published_changes(&h);
    assert!(changes.iter().any(|c| matches!(c, PathChange::Renamed { id, .. } if *id == old)), "{changes:?}");
    assert!(!changes.iter().any(|c| matches!(c, PathChange::Removed { .. } | PathChange::Added { .. })), "{changes:?}");
}

#[test]
fn case_only_rename_without_stable_identity_replaces_the_entry() {
    let fs = case_insensitive_fs(false);
    fs.mkdir("Docs");
    fs.create_file("Docs/Readme.MD", 1);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    let old = h.entry("Docs/Readme.MD").expect("file").id;
    h.take_events();
    fs.rename("Docs/Readme.MD", "Docs/README.md");
    let t = h.command(Command::Refresh(vec![path("Docs")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    let entry = h.entry("docs/readme.md").expect("replaced file");
    assert_ne!(entry.id, old);
    assert_eq!(entry.path.to_string(), "Docs/README.md");
    let deltas: Vec<&UpdateEvent> = h.events().iter().filter(|e| matches!(e, UpdateEvent::Delta(_))).collect();
    assert_eq!(deltas.len(), 1);
    let UpdateEvent::Delta(update) = deltas[0] else { panic!("delta") };
    let changes = &update.changes;
    assert!(!changes.iter().any(|c| matches!(c, PathChange::Renamed { .. })), "{changes:?}");
    let removed = changes.iter().position(|c| matches!(c, PathChange::Removed { id, .. } if *id == old));
    let added = changes.iter().position(|c| matches!(c, PathChange::Added { id, .. } if *id == entry.id));
    assert!(removed.is_some() && added.is_some(), "{changes:?}");
    assert!(removed < added, "{changes:?}");
}

#[test]
fn case_only_rename_with_a_different_identity_replaces_the_subtree() {
    let fs = case_insensitive_fs(true);
    fs.mkdir("Docs");
    fs.mkdir("Docs/Sub");
    fs.create_file("Docs/Sub/inner", 1);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    let old_dir = h.entry("Docs/Sub").expect("directory").id;
    let old_inner = h.entry("Docs/Sub/inner").expect("file").id;
    h.take_events();
    fs.remove_silently("Docs/Sub");
    fs.add_silently("Docs/sub", EntryKind::Directory);
    fs.add_silently("Docs/sub/inner", EntryKind::File);
    let t = h.command(Command::Refresh(vec![path("Docs")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    let dir = h.entry("docs/sub").expect("directory");
    assert_ne!(dir.id, old_dir);
    assert_eq!(dir.path.to_string(), "Docs/sub");
    let inner = h.entry("docs/sub/inner").expect("file");
    assert_ne!(inner.id, old_inner);
    let changes = published_changes(&h);
    assert!(!changes.iter().any(|c| matches!(c, PathChange::Renamed { .. })), "{changes:?}");
    assert!(changes.iter().any(|c| matches!(c, PathChange::Removed { id, .. } if *id == old_dir)), "{changes:?}");
    assert!(changes.iter().any(|c| matches!(c, PathChange::Removed { id, .. } if *id == old_inner)), "{changes:?}");
    assert!(changes.iter().any(|c| matches!(c, PathChange::Added { id, .. } if *id == dir.id)), "{changes:?}");
}

#[test]
fn case_only_rename_without_an_observed_identity_replaces_the_entry() {
    let fs = case_insensitive_fs(true);
    fs.mkdir("Docs");
    fs.create_file("Docs/Readme.MD", 1);
    fs.clear_identity("Docs/Readme.MD");
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    let old = h.entry("Docs/Readme.MD").expect("file");
    assert_eq!(old.identity, None);
    let old = old.id;
    h.take_events();
    fs.rename("Docs/Readme.MD", "Docs/README.md");
    let t = h.command(Command::Refresh(vec![path("Docs")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    let entry = h.entry("docs/readme.md").expect("replaced file");
    assert_ne!(entry.id, old);
    let changes = published_changes(&h);
    assert!(!changes.iter().any(|c| matches!(c, PathChange::Renamed { .. })), "{changes:?}");
    assert!(changes.iter().any(|c| matches!(c, PathChange::Removed { id, .. } if *id == old)), "{changes:?}");
    assert!(changes.iter().any(|c| matches!(c, PathChange::Added { id, .. } if *id == entry.id)), "{changes:?}");
}

#[test]
fn replaced_entry_with_new_identity_gets_new_entry_id() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    let old = h.entry("root.txt").expect("file").id;
    fs.remove_silently("root.txt");
    fs.add_silently("root.txt", EntryKind::File);
    h.run_round();
    let new = h.entry("root.txt").expect("file").id;
    assert_ne!(old, new);
}

#[test]
fn empty_and_large_directories() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("empty");
    fs.mkdir("big");
    for i in 0..500 {
        fs.create_file(&format!("big/f{i}"), 1);
    }
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    assert_eq!(h.snapshot().len(), 503);
    assert_eq!(h.snapshot().child_count(h.entry("empty").expect("empty").id), 0);
    assert!(h.stats().listings >= 3);
}

#[test]
fn command_capacity_and_path_limits_fail_before_acceptance() {
    let fs = populated(WatcherKind::None);
    let config = Config { command_capacity: 1, paths_per_command: 2, priority_set_limit: 1, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    let first = h.command(Command::Refresh(vec![path("a")]));
    assert_eq!(h.result(first), None);
    let second = h.command(Command::Refresh(vec![path("c")]));
    assert_eq!(h.result(second), Some(Err(Error::Capacity)));
    h.run_until_idle();
    assert_eq!(h.result(first), Some(Ok(())));
    let many = h.command(Command::Refresh(vec![path("a"), path("c"), path("root.txt")]));
    assert_eq!(h.result(many), Some(Err(Error::PathLimit)));
    let prio = h.command(Command::SetPriority(vec![path("a"), path("c")]));
    assert_eq!(h.result(prio), Some(Err(Error::PathLimit)));
}

#[test]
fn initial_scan_degraded_then_recovers_to_complete() {
    let fs = populated(WatcherKind::None);
    fs.fail("a/b", FakeOp::ReadDir, FailureMode::Times(2, FsError::Transient("busy".into())));
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    assert!(matches!(h.health().initial_scan, InitialScanState::Degraded { .. }));
    let t = h.command(Command::InitialScanComplete);
    assert!(matches!(h.result(t), Some(Err(Error::InitialScanDegraded(_)))));
    h.advance(Duration::from_secs(60));
    assert!(matches!(h.health().initial_scan, InitialScanState::Complete { .. }));
    let t = h.command(Command::InitialScanComplete);
    assert_eq!(h.result(t), Some(Ok(())));
    assert!(h.paths().contains(&"a/b/f1".to_string()));
}

#[test]
fn fatal_error_terminates_tree() {
    let fs = populated(WatcherKind::None);
    fs.fail("c", FakeOp::ReadDir, FailureMode::Once(FsError::Fatal("disk on fire".into())));
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    assert!(h.stopped());
    let t = h.command(Command::Refresh(vec![path("")]));
    assert_eq!(h.result(t), Some(Err(Error::TreeTerminated)));
}

#[test]
fn removal_during_in_flight_listing_never_resurrects() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    h.fire_timer_only();
    let child_job = h.pending_job_for("a/b").expect("child listing in flight");
    let parent_job = h.pending_job_for("a").expect("parent listing in flight");
    fs.remove_silently("a");
    h.complete_job(parent_job.id);
    assert!(!h.paths().contains(&"a".to_string()));
    assert!(h.cancelled().contains(&child_job.id));
    let _ = h.complete_job(child_job.id);
    h.run_until_idle();
    assert!(!h.paths().contains(&"a/b".to_string()));
    assert!(!h.paths().contains(&"a".to_string()));
}

#[test]
fn malformed_listing_fails_the_refresh_and_keeps_the_previous_children() {
    let fs = populated(WatcherKind::None);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    fs.remove_silently("a/f2");
    fs.inject_child("a", "", EntryKind::File);
    let t = h.command(Command::Refresh(vec![path("a")]));
    h.run_until_idle();
    assert!(matches!(h.result(t), Some(Err(Error::Io(FsError::Transient(_))))));
    assert!(h.paths().contains(&"a/f2".to_string()));
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a"), 2);
    fs.clear_injected_children();
    let t = h.command(Command::Refresh(vec![path("a")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert!(!h.paths().contains(&"a/f2".to_string()));
}

#[test]
fn lost_registration_worker_is_reported_and_the_listing_proceeds_without_a_watch() {
    let fs = populated(WatcherKind::NonRecursive);
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.auto_register = false;
    let root_job = h.pending_job_for("").expect("root listing");
    h.complete_job(root_job.id);
    let (request, _, _) =
        h.pending_registrations().into_iter().find(|(_, p, _)| *p == path("c")).expect("c registration");
    assert!(h.lose_registration(request));
    assert!(!h.lose_registration(request));
    assert!(matches!(h.health().watcher, WatcherHealth::Degraded { .. }));
    let reported = h.events().iter().any(|e| match e {
        UpdateEvent::Health { errors, .. } | UpdateEvent::Reset { errors, .. } => errors.iter().any(|e| {
            e.path == path("c") && e.operation == Operation::WatchRegistration && e.error == ErrorCause::WorkerLost
        }),
        UpdateEvent::Delta(u) => u.errors.iter().any(|e| e.error == ErrorCause::WorkerLost),
        UpdateEvent::Terminal { .. } => false,
    });
    assert!(reported);
    h.auto_register = true;
    h.run_until_idle();
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "c"), 1);
    assert_eq!(h.entry("c").and_then(|e| e.load_state()), Some(LoadState::Loaded));
    assert_eq!(fs.watch_count(), 3);
}
