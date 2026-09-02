use std::sync::Arc;

use tree_fucker::core::{Command, JobResult};
use tree_fucker::testing::{FakeFileSystem, FakeOp, Harness};
use tree_fucker::update::{RoundResult, UpdateEvent};
use tree_fucker::{
    EntryKind, FileSystem, FsError, LoadAll, LoadState, PathPredicate, RelativePath, ScanDecision, WatcherKind,
};

fn path(p: &str) -> RelativePath {
    RelativePath::parse(p).expect("valid path")
}

fn populated() -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("a");
    fs.mkdir("a/b");
    fs.create_file("a/b/f1", 10);
    fs.create_file("a/f2", 20);
    fs.mkdir("c");
    fs.create_file("root.txt", 5);
    fs
}

fn scanned(fs: &Arc<FakeFileSystem>) -> Harness {
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    h.run_until_idle();
    h
}

fn load_everything() -> Arc<PathPredicate<impl Fn(&RelativePath, EntryKind) -> ScanDecision + Send + Sync>> {
    Arc::new(PathPredicate::new(|_p: &RelativePath, _k| ScanDecision::Eligible { initially_loaded: true }))
}

#[test]
fn policy_revision_bump_stales_the_in_flight_listing_which_is_listed_again() {
    let fs = populated();
    let policy = load_everything();
    let mut h = Harness::open_default(fs.clone(), policy.clone());
    h.run_until_idle();
    fs.add_silently("c/late", EntryKind::File);
    let t = h.command(Command::Refresh(vec![path("c")]));
    let job = h.pending_job_for("c").expect("c listing in flight");
    policy.bump_revision();
    h.complete_job(job.id);
    assert_eq!(h.stats().stale_results, 1);
    assert!(!h.paths().contains(&"c/late".to_string()));
    assert_eq!(h.result(t), None);
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert!(h.paths().contains(&"c/late".to_string()));
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "c"), 3);
}

#[test]
fn policy_revision_bump_stales_the_designated_round_listing_and_degrades_the_round() {
    let fs = populated();
    let policy = load_everything();
    let mut h = Harness::open_default(fs.clone(), policy.clone());
    h.run_until_idle();
    h.fire_timer_only();
    let c_job = h.pending_job_for("c").expect("c job");
    policy.bump_revision();
    h.complete_job(c_job.id);
    assert_eq!(h.stats().stale_results, 1);
    h.complete_all_jobs();
    assert!(matches!(
        h.health().reconciliation.last_round,
        Some(RoundResult::Degraded { ref unsatisfied }) if unsatisfied.contains(&path("c"))
    ));
    h.run_until_idle();
    h.run_round();
    assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful));
}

#[test]
fn policy_invalidation_fences_in_flight_work_without_a_revision_change() {
    let fs = populated();
    let mut h = scanned(&fs);
    fs.add_silently("c/late", EntryKind::File);
    let t = h.command(Command::Refresh(vec![path("c")]));
    let job = h.pending_job_for("c").expect("c listing in flight");
    let inv = h.command(Command::InvalidatePolicy(vec![path("")]));
    h.complete_job(job.id);
    assert_eq!(h.stats().stale_results, 1);
    assert!(!h.paths().contains(&"c/late".to_string()));
    h.run_until_idle();
    assert_eq!(h.result(inv), Some(Ok(())));
    assert_eq!(h.result(t), Some(Ok(())));
    assert!(h.paths().contains(&"c/late".to_string()));
}

#[test]
fn wide_initial_scan_lists_every_sibling_once_without_stale_retries() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    for i in 0..20 {
        fs.mkdir(&format!("d{i:02}"));
    }
    let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
    let root_job = h.pending_job_for("").expect("root listing");
    h.complete_job(root_job.id);
    assert_eq!(h.stats().queued_jobs + h.stats().in_flight_jobs, 20);
    h.complete_all_jobs();
    assert_eq!(h.stats().stale_results, 0);
    assert!(h.pending_jobs().is_empty());
    for i in 0..20 {
        let name = format!("d{i:02}");
        assert_eq!(fs.count_ops(FakeOp::ReadDir, &name), 1, "{name} listed once");
        assert_eq!(h.entry(&name).and_then(|e| e.load_state()), Some(LoadState::Loaded));
    }
    assert_eq!(h.health().reconciliation.last_round, None);
}

#[test]
fn sibling_metadata_load_and_descendant_changes_leave_sibling_guards_valid() {
    let fs = populated();
    let mut h = scanned(&fs);
    h.fire_timer_only();
    let root_job = h.pending_job_for("").expect("root job");
    let a_job = h.pending_job_for("a").expect("a job");
    let ab_job = h.pending_job_for("a/b").expect("a/b job");
    let c_job = h.pending_job_for("c").expect("c job");
    fs.set_size_silently("a/f2", 21);
    fs.add_silently("a/b/x", EntryKind::File);
    h.complete_job(a_job.id);
    h.complete_job(c_job.id);
    h.complete_job(ab_job.id);
    h.complete_job(root_job.id);
    assert_eq!(h.stats().stale_results, 0);
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(Some(21)));
    assert!(h.entry("a/b/x").is_some());
    assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful));
}

#[test]
fn membership_changes_invalidate_containing_directory_binding_guards() {
    let fs = populated();
    let mut h = scanned(&fs);
    h.fire_timer_only();
    let root_job = h.pending_job_for("").expect("root job");
    let a_job = h.pending_job_for("a").expect("a job");
    let ab_job = h.pending_job_for("a/b").expect("a/b job");
    let c_job = h.pending_job_for("c").expect("c job");
    fs.add_silently("n", EntryKind::File);
    h.complete_job(root_job.id);
    assert!(h.entry("n").is_some());
    h.complete_job(a_job.id);
    assert_eq!(h.stats().stale_results, 1);
    h.complete_job(ab_job.id);
    assert_eq!(h.stats().stale_results, 1);
    h.complete_job(c_job.id);
    assert_eq!(h.stats().stale_results, 2);
    h.run_until_idle();
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a"), 3);
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "c"), 3);
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a/b"), 2);
}

fn frozen_parent_listing(fs: &FakeFileSystem, stale_size: u64) -> JobResult {
    let mut listing = fs.read_dir(fs.root(), &path("a")).expect("listing");
    for entry in &mut listing.entries {
        if entry.name == "f2" {
            entry.info.metadata.size = Some(stale_size);
        }
    }
    JobResult::Listing(Ok(listing))
}

#[test]
fn child_metadata_committed_first_is_not_overwritten_by_older_parent_listing() {
    let fs = populated();
    let mut h = scanned(&fs);
    fs.set_size_silently("a/f2", 2);
    let t = h.command(Command::Refresh(vec![path("a"), path("a/f2")]));
    let parent = h.pending_job_for("a").expect("parent listing");
    let child = h.pending_job_for("a/f2").expect("child metadata");
    h.complete_job(child.id);
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(Some(2)));
    h.complete_job_with(parent.id, frozen_parent_listing(&fs, 3));
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(Some(2)));
    assert_eq!(h.stats().stale_results, 1);
    assert_eq!(h.result(t), None);
    h.run_until_idle();
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(Some(2)));
    assert_eq!(h.result(t), Some(Ok(())));
}

#[test]
fn older_parent_listing_committed_first_stales_the_child_read_which_rereads() {
    let fs = populated();
    let mut h = scanned(&fs);
    fs.set_size_silently("a/f2", 2);
    let t = h.command(Command::Refresh(vec![path("a"), path("a/f2")]));
    let parent = h.pending_job_for("a").expect("parent listing");
    let child = h.pending_job_for("a/f2").expect("child metadata");
    h.complete_job_with(parent.id, frozen_parent_listing(&fs, 3));
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(Some(3)));
    h.complete_job(child.id);
    assert_eq!(h.stats().stale_results, 1);
    h.run_until_idle();
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(Some(2)));
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(fs.count_ops(FakeOp::Metadata, "a/f2"), 2);
}

#[test]
fn replacement_during_delayed_child_listing_never_resurrects_old_subtree() {
    let fs = populated();
    let mut h = scanned(&fs);
    let old_id = h.entry("a").expect("a").id;
    h.fire_timer_only();
    let root_job = h.pending_job_for("").expect("root job");
    let a_job = h.pending_job_for("a").expect("a job");
    let ab_job = h.pending_job_for("a/b").expect("a/b job");
    fs.remove_silently("a");
    fs.add_silently("a", EntryKind::Directory);
    h.complete_job(root_job.id);
    assert!(h.cancelled().contains(&a_job.id));
    assert!(h.cancelled().contains(&ab_job.id));
    assert!(!h.paths().contains(&"a/b".to_string()));
    h.run_until_idle();
    let new = h.entry("a").expect("replacement");
    assert_ne!(new.id, old_id);
    assert_eq!(new.load_state(), Some(LoadState::Loaded));
    assert_eq!(h.paths(), [".", "a", "c", "root.txt"]);
}

#[test]
fn later_dispatch_stales_only_its_own_target() {
    let fs = populated();
    let mut h = scanned(&fs);
    h.fire_timer_only();
    let a_job = h.pending_job_for("a").expect("a job");
    let c_job = h.pending_job_for("c").expect("c job");
    let t = h.command(Command::Refresh(vec![path("c")]));
    h.complete_job(a_job.id);
    assert_eq!(h.stats().stale_results, 0);
    h.complete_job(c_job.id);
    assert_eq!(h.stats().stale_results, 1);
    assert_eq!(h.result(t), None);
    h.complete_all_jobs();
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert!(matches!(
        h.health().reconciliation.last_round,
        Some(RoundResult::Degraded { ref unsatisfied }) if unsatisfied.len() == 1 && unsatisfied.contains(&path("c"))
    ));
}

#[test]
fn fatal_completion_terminates_even_when_guards_are_stale() {
    let fs = populated();
    let mut h = scanned(&fs);
    h.fire_timer_only();
    let root_job = h.pending_job_for("").expect("root job");
    let a_job = h.pending_job_for("a").expect("a job");
    let c_job = h.pending_job_for("c").expect("c job");
    fs.add_silently("n", EntryKind::File);
    h.complete_job(root_job.id);
    h.complete_job_with(c_job.id, JobResult::Listing(Err(FsError::Transient("blip".into()))));
    assert_eq!(h.stats().stale_results, 1);
    assert!(!h.stopped());
    assert!(h.health().reconciliation.degraded_paths.is_empty());
    assert!(h.events().iter().all(|e| match e {
        UpdateEvent::Delta(u) => u.errors.is_empty(),
        UpdateEvent::Health { errors, .. } => errors.is_empty(),
        _ => true,
    }));
    h.complete_job_with(a_job.id, JobResult::Listing(Err(FsError::Fatal("device gone".into()))));
    assert!(h.stopped());
    assert!(matches!(h.events().last(), Some(UpdateEvent::Terminal { .. })));
    assert!(h.paths().contains(&"a/b/f1".to_string()));
}
