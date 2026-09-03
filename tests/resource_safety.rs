use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tree_fucker::core::{Class, Command, JobSpec, MonotonicTime};
use tree_fucker::testing::{Admission, CostScope, DomainId, FailureMode, FakeFileSystem, FakeOp, Harness};
use tree_fucker::update::{ErrorCause, RoundResult, UpdateEvent};
use tree_fucker::{Config, EntryKind, FsError, HintKind, LoadAll, RelativePath, WatcherKind};

const BACKGROUND_DUTY_GLOBAL: f64 = 0.02;
const BACKGROUND_BURST_GLOBAL: Duration = Duration::from_millis(500);
const INITIAL_COST_ESTIMATE: Duration = Duration::from_millis(20);
const STUCK_THRESHOLD: Duration = Duration::from_secs(30);
const MAXIMUM_PERIOD: Duration = Duration::from_secs(300);

const HOME: DomainId = DomainId::new(1);
const MEDIA: DomainId = DomainId::new(2);

fn path(p: &str) -> RelativePath {
    RelativePath::parse(p).expect("valid path")
}

fn tree(dirs: &[&str]) -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    for dir in dirs {
        fs.mkdir(dir);
        fs.create_file(&format!("{dir}/f"), 1);
    }
    fs
}

fn numbered(prefix: &str, count: usize) -> Vec<String> {
    (0..count).map(|i| format!("{prefix}{i}")).collect()
}

fn borrowed(names: &[String]) -> Vec<&str> {
    names.iter().map(|n| n.as_str()).collect()
}

fn envelope(duty: f64, burst: Duration, window: Duration) -> Duration {
    Duration::from_secs_f64(window.as_secs_f64() * duty) + burst
}

fn worst_window(h: &Harness, window: Duration) -> (MonotonicTime, Duration) {
    let charges = h.charges();
    let mut worst = (MonotonicTime::ZERO, Duration::ZERO);
    let mut oldest = 0;
    let mut total = Duration::ZERO;
    for index in 0..charges.len() {
        let end = charges[index].at;
        total += charges[index].cost;
        while charges[oldest].at.0 + window <= end.0 {
            total -= charges[oldest].cost;
            oldest += 1;
        }
        if total > worst.1 {
            worst = (end, total);
        }
    }
    worst
}

fn run_one_round(h: &mut Harness) {
    let before = h.stats().last_round;
    for _ in 0..4000 {
        let next = h.now() + Duration::from_secs(5);
        h.run_jobs_until(next);
        if h.stats().last_round != before {
            return;
        }
    }
    panic!("no reconciliation round completed");
}

fn dispatched_job(h: &mut Harness, p: &str) -> JobSpec {
    for _ in 0..1200 {
        if let Some(job) = h.pending_job_for(p) {
            return job;
        }
        let next = h.now() + Duration::from_secs(1);
        h.run_jobs_until(next);
    }
    panic!("no filesystem job for {p} was dispatched");
}

fn scanned(fs: Arc<FakeFileSystem>, config: Config) -> Harness {
    let mut h = Harness::open(fs, Arc::new(LoadAll), config).expect("open");
    h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(120));
    h
}

fn by_batch(admissions: &[Admission]) -> BTreeMap<usize, Vec<Admission>> {
    let mut grouped: BTreeMap<usize, Vec<Admission>> = BTreeMap::new();
    for admission in admissions {
        grouped.entry(admission.batch).or_default().push(admission.clone());
    }
    grouped
}

#[test]
fn every_listing_and_metadata_op_correlates_with_a_logged_admission() {
    let fs = tree(&["a", "a/b", "c"]);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, INITIAL_COST_ESTIMATE);
    fs.set_cost(CostScope::Everything, FakeOp::Metadata, Duration::from_millis(2));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    fs.clear_ops();
    h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(120));
    let t = h.command(Command::Refresh(vec![path("a"), path("c"), path("a/b/f")]));
    let target = h.now() + Duration::from_secs(120);
    h.run_jobs_until(target);
    assert_eq!(h.result(t), Some(Ok(())));

    let mut granted: BTreeMap<RelativePath, usize> = BTreeMap::new();
    for admission in h.admissions() {
        *granted.entry(admission.entry).or_default() += 1;
    }
    let mut performed: BTreeMap<RelativePath, usize> = BTreeMap::new();
    for (op, target) in fs.ops() {
        if op == FakeOp::Watch {
            continue;
        }
        *performed.entry(target).or_default() += 1;
    }
    assert!(!performed.is_empty(), "the workload performed no filesystem operation");
    for (target, count) in &performed {
        let grants = granted.get(target).copied().unwrap_or(0);
        assert!(
            grants >= *count,
            "RFC 15.1 item 1: {count} filesystem operations ran for {target} against {grants} logged admissions"
        );
    }
}

#[test]
fn watch_registration_correlates_with_a_governor_admission() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    for dir in ["a", "a/b", "c"] {
        fs.mkdir(dir);
        fs.create_file(&format!("{dir}/f"), 1);
    }
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, INITIAL_COST_ESTIMATE);
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(120));

    let registered = fs.ops().iter().filter(|(op, _)| *op == FakeOp::Watch).count() as u64;
    let granted = h.governor().watch_registration_grants;
    assert!(registered > 0, "the workload registered no watch");
    assert!(
        granted >= registered,
        "RFC 15.1 item 1: {registered} watch registrations ran against {granted} governor grants"
    );
}

#[test]
fn a_running_worker_is_charged_its_occupancy_before_it_completes() {
    let fs = tree(&["held"]);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    fs.set_cost(CostScope::path("held"), FakeOp::ReadDir, Duration::from_secs(36_000));
    let config = Config { stuck_threshold: Duration::from_secs(36_000), ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    let started = dispatched_job(&mut h, "held");
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let start = h.now();

    let target = start + Duration::from_secs(60);
    h.run_jobs_until(target);
    assert!(
        h.pending_jobs().iter().any(|job| job.id == started.id),
        "the ten hour listing returned, so there is no running occupancy to account"
    );

    let view = h.governor();
    assert!(
        view.running_occupancy >= Duration::from_secs(60),
        "RFC 15.2: a running operation is charged its occupancy so far at every accounting point; the \
         governor reports {:?} of running occupancy sixty seconds after the worker started",
        view.running_occupancy
    );
    assert!(
        view.charged >= Duration::from_secs(60),
        "RFC 15.2: the bucket must carry the occupancy of an operation that has not completed; it carries {:?}",
        view.charged
    );
    assert!(
        view.debt > Duration::ZERO,
        "RFC 15.3: occupancy beyond the reservation puts the bucket in debt; the bucket reports level {:?}",
        view.level
    );
    assert!(
        h.charges().iter().all(|charge| charge.job != started.id),
        "the harness completion log records a charge only when work settles, so it cannot be the source of \
         truth for a running worker"
    );
    let admitted: Vec<Admission> = h.admissions().into_iter().filter(|a| a.at > start).collect();
    assert!(
        admitted.is_empty(),
        "RFC 15.3: a bucket in debt admits nothing; {} jobs were admitted while the worker ran",
        admitted.len()
    );
}

#[test]
fn expedited_classes_never_occupy_the_baseline_reservation_in_a_cycle() {
    let names = numbered("d", 8);
    let fs = tree(&borrowed(&names));
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, INITIAL_COST_ESTIMATE);
    let config = Config { batch_size: 4, ..Default::default() };
    let reservation = config.baseline_reservation();
    let batch_size = config.batch_size;
    let mut h = scanned(fs, config);
    let targets: Vec<RelativePath> = names.iter().map(|n| path(n)).collect();
    let t = h.command(Command::Refresh(targets));
    let target = h.now() + Duration::from_secs(600);
    h.run_jobs_until(target);
    assert_eq!(h.result(t), Some(Ok(())));

    for (batch, members) in by_batch(&h.admissions()) {
        let baseline = members.iter().filter(|a| a.class == Class::Baseline).count();
        let expedited = members.len() - baseline;
        assert!(
            members.len() <= batch_size,
            "RFC 11.3: cycle {batch} admitted {} jobs into a batch of {batch_size}",
            members.len()
        );
        if baseline > 0 {
            assert!(
                expedited <= batch_size - reservation,
                "RFC 11.3: cycle {batch} gave {expedited} of {batch_size} slots to expedited classes, \
                 leaving less than the baseline reservation of {reservation}"
            );
        }
    }
}

#[test]
fn charged_work_stays_within_the_duty_budget_over_every_sliding_window() {
    let names = numbered("d", 12);
    let fs = tree(&borrowed(&names));
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, INITIAL_COST_ESTIMATE);
    let mut h = Harness::open(fs, Arc::new(LoadAll), Config::default()).expect("open");
    h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(1800));

    let budget = envelope(BACKGROUND_DUTY_GLOBAL, BACKGROUND_BURST_GLOBAL, MAXIMUM_PERIOD);
    let (at, worst) = worst_window(&h, MAXIMUM_PERIOD);
    assert!(
        worst <= budget,
        "RFC 15.3 with the RFC 9.2 host defaults: background worker time over the {MAXIMUM_PERIOD:?} window \
         ending at {at:?} was {worst:?}, above the rate times window plus burst budget of {budget:?} \
         (total charged {:?})",
        h.charged_work()
    );
}

fn period_and_next_cycle(cost: Duration) -> (Duration, usize) {
    let names = numbered("d", 8);
    let fs = tree(&borrowed(&names));
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, cost);
    let mut h = scanned(fs, Config::default());
    run_one_round(&mut h);
    let gap = h.timer().map(|(_, at)| at.saturating_sub(h.now())).expect("periodic timer armed");
    let before = h.admissions().len();
    run_one_round(&mut h);
    let admitted = h.admissions();
    let cycle = admitted[before..].iter().filter(|a| a.class == Class::Baseline).count();
    (gap, cycle)
}

#[test]
fn a_slow_batch_pushes_out_the_next_period_and_the_bucket_bounds_the_next_cycle() {
    let (fast_gap, fast_cycle) = period_and_next_cycle(Duration::from_millis(1));
    let (slow_gap, slow_cycle) = period_and_next_cycle(Duration::from_millis(200));
    assert!(
        slow_gap > fast_gap,
        "RFC 12: a slower batch must push out the next period; fast {fast_gap:?} against slow {slow_gap:?}"
    );
    assert!(
        slow_cycle >= 1 && slow_cycle <= fast_cycle,
        "RFC 15.3: the bucket, not the previous batch's duration, bounds the next cycle; it admitted \
         {slow_cycle} against the fast tree's {fast_cycle}"
    );
}

#[test]
fn a_refresh_burst_admits_at_most_batch_size_jobs_per_cycle() {
    let names = numbered("d", 20);
    let fs = tree(&borrowed(&names));
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, INITIAL_COST_ESTIMATE);
    let config = Config { batch_size: 4, ..Default::default() };
    let batch_size = config.batch_size;
    let mut h = scanned(fs, config);
    let targets: Vec<RelativePath> = names.iter().map(|n| path(n)).collect();
    let t = h.command(Command::Refresh(targets));
    let target = h.now() + Duration::from_secs(600);
    h.run_jobs_until(target);
    assert_eq!(h.result(t), Some(Ok(())));

    let grouped = by_batch(&h.admissions());
    for (batch, members) in &grouped {
        assert!(
            members.len() <= batch_size,
            "RFC 11.3: cycle {batch} admitted {} jobs into a batch of {batch_size}",
            members.len()
        );
    }
    assert!(grouped.len() > 5, "the burst settled in {} cycles, too few to bound", grouped.len());
}

#[test]
fn a_priority_burst_cannot_raise_charged_work_above_the_budget() {
    let names = numbered("d", 12);
    let fs = tree(&borrowed(&names));
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, INITIAL_COST_ESTIMATE);
    let mut h = scanned(fs, Config::default());
    let targets: Vec<RelativePath> = names.iter().map(|n| path(n)).collect();
    let t = h.command(Command::SetPriority(targets));
    assert_eq!(h.result(t), Some(Ok(())));
    let target = h.now() + Duration::from_secs(1800);
    h.run_jobs_until(target);

    let budget = envelope(BACKGROUND_DUTY_GLOBAL, BACKGROUND_BURST_GLOBAL, MAXIMUM_PERIOD);
    let (at, worst) = worst_window(&h, MAXIMUM_PERIOD);
    assert!(
        worst <= budget,
        "RFC 15.1 item 4 and 15.4: priority work is background work, so a priority burst must not raise \
         admitted worker time above the envelope; the {MAXIMUM_PERIOD:?} window ending at {at:?} charged \
         {worst:?} against a budget of {budget:?}"
    );
}

#[test]
fn the_baseline_cursor_advances_while_every_expedited_class_stays_ready() {
    let names = numbered("keep", 4);
    let fs = tree(&borrowed(&names));
    fs.mkdir("flaky");
    fs.create_file("flaky/f", 1);
    fs.fail("flaky", FakeOp::ReadDir, FailureMode::Always(FsError::Transient("busy".into())));
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(5));
    let mut h = scanned(fs.clone(), Config::default());
    let t = h.command(Command::SetPriority(vec![path("keep0"), path("keep1")]));
    assert_eq!(h.result(t), Some(Ok(())));

    let mut rounds = 0;
    let mut last = h.stats().last_round;
    for step in 0..40 {
        fs.mkdir(&format!("fresh{step}"));
        let t = h.command(Command::Refresh(vec![path("keep2")]));
        let target = h.now() + Duration::from_secs(60);
        h.run_jobs_until(target);
        assert!(h.result(t).is_some(), "refresh {step} never settled");
        if h.stats().last_round != last {
            last = h.stats().last_round;
            rounds += 1;
        }
    }

    let classes: BTreeSet<Class> = h.admissions().iter().map(|a| a.class).collect();
    for class in [Class::Baseline, Class::Control, Class::Refresh, Class::Retry, Class::Priority] {
        assert!(classes.contains(&class), "{class:?} work never became ready; observed {classes:?}");
    }
    assert!(
        rounds >= 2,
        "RFC 17.3: baseline cursor progress must stay finite under sustained expedited work; {rounds} rounds completed"
    );
}

#[test]
fn a_round_completes_under_continuous_watcher_and_retry_pressure() {
    let names = numbered("d", 4);
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::Recursive));
    for name in &names {
        fs.mkdir(name);
        fs.create_file(&format!("{name}/f"), 1);
    }
    fs.fail("d0", FakeOp::ReadDir, FailureMode::Times(2, FsError::Transient("busy".into())));
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(5));
    let mut h = scanned(fs.clone(), Config::default());
    let target = h.now() + Duration::from_secs(120);
    let emitted = h.flood_hints_until(&borrowed(&names), HintKind::Modify, target);
    assert!(emitted > 100, "the storm emitted only {emitted} hints");
    let target = h.now() + Duration::from_secs(120);
    h.run_jobs_until(target);
    assert_eq!(
        h.health().reconciliation.last_round,
        Some(RoundResult::Successful),
        "RFC 5.1 and 17.5: a round must still reach a successful outcome under continuous watcher and retry pressure"
    );
}

fn storm_worst_window(storm: bool) -> (Duration, Duration) {
    let names = numbered("d", 3);
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::Recursive));
    for name in &names {
        fs.mkdir(name);
        fs.create_file(&format!("{name}/f"), 1);
    }
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(5));
    let mut h = scanned(fs, Config::default());
    let target = h.now() + Duration::from_secs(120);
    if storm {
        h.flood_hints_until(&borrowed(&names), HintKind::Modify, target);
    } else {
        h.run_jobs_until(target);
    }
    (worst_window(&h, MAXIMUM_PERIOD).1, h.charged_work())
}

#[test]
fn an_unbounded_watcher_storm_does_not_increase_charged_listing_time() {
    let budget = envelope(BACKGROUND_DUTY_GLOBAL, BACKGROUND_BURST_GLOBAL, MAXIMUM_PERIOD);
    let (quiet_worst, quiet_total) = storm_worst_window(false);
    assert!(
        quiet_worst <= budget,
        "RFC 15.3: the quiet baseline already exceeds the envelope: {quiet_worst:?} against {budget:?}"
    );
    let (storm_worst, storm_total) = storm_worst_window(true);
    assert!(
        storm_worst <= budget,
        "RFC 15.1 item 3: a watcher storm must admit no more background work than the same envelope; \
         the {MAXIMUM_PERIOD:?} window charged {storm_worst:?} under a storm against a budget of {budget:?} \
         (totals: quiet {quiet_total:?}, storm {storm_total:?})"
    );
}

#[test]
fn a_storm_is_absorbed_by_the_coalesced_and_dropped_hint_counters() {
    let names = numbered("d", 16);
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::Recursive));
    for name in &names {
        fs.mkdir(name);
        fs.create_file(&format!("{name}/f"), 1);
    }
    let config = Config { watcher_path_limit: 8, ..Default::default() };
    let mut h = scanned(fs.clone(), config);
    let admitted_before = h.admissions().len();

    let repeated = fs.emit_storm(&borrowed(&names[..4]), HintKind::Modify, 6);
    assert_eq!(h.deliver_watcher_events_capped(6), 6, "the coordinator did not receive the repeated hints");
    assert!(
        h.stats().coalesced_hints > 0,
        "RFC 11.2: repeated hints for one directory must coalesce into its pending read"
    );

    let widened = fs.emit_storm(&borrowed(&names[4..]), HintKind::Modify, 3);
    assert_eq!(h.deliver_watcher_events_capped(3), 3, "the coordinator did not receive the widened hints");
    assert!(
        h.stats().dropped_hints > 0,
        "RFC 13.6: hints beyond the configured watcher path limit must be dropped after counting"
    );

    let hints = repeated + widened;
    let admitted = h.admissions().len() - admitted_before;
    assert!(admitted < hints, "RFC 15.1 item 3: {hints} hints admitted {admitted} jobs, so the storm was not absorbed");
}

#[test]
fn a_job_delayed_past_a_newer_dispatch_for_its_target_is_discarded() {
    let fs = tree(&["a"]);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let mut h = scanned(fs.clone(), Config::default());
    fs.set_cost(CostScope::path("a"), FakeOp::ReadDir, Duration::from_secs(5));

    let first = h.command(Command::Refresh(vec![path("a")]));
    let delayed = dispatched_job(&mut h, "a");
    let target = h.now() + Duration::from_secs(1);
    h.run_jobs_until(target);
    assert!(h.pending_job_for("a").is_some_and(|j| j.id == delayed.id), "the delayed listing already returned");

    let stale_before = h.stats().stale_results;
    let second = h.command(Command::Refresh(vec![path("a")]));
    fs.add_silently("a/ghost", EntryKind::File);
    let target = h.now() + Duration::from_secs(4);
    h.run_jobs_until(target);
    assert_eq!(
        h.stats().stale_results,
        stale_before + 1,
        "RFC 11.4: the delayed result must be discarded once a newer dispatch for its target exists"
    );
    assert!(
        !h.paths().contains(&"a/ghost".to_string()),
        "RFC 11.4 and 17.5: a result delayed past a newer dispatch for its target committed"
    );

    let target = h.now() + Duration::from_secs(1200);
    h.run_jobs_until(target);
    assert_eq!(h.result(first), Some(Ok(())));
    assert_eq!(h.result(second), Some(Ok(())));
    assert!(h.paths().contains(&"a/ghost".to_string()));
}

fn limited_tree() -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("big");
    fs.create_file("big/f0", 1);
    fs.create_file("big/f1", 1);
    fs.mkdir("small");
    fs
}

fn grow_beyond_limit(fs: &FakeFileSystem) {
    for i in 2..5 {
        fs.add_silently(&format!("big/f{i}"), EntryKind::File);
    }
}

#[test]
fn a_listing_over_the_directory_limit_leaves_the_previous_children_intact() {
    let fs = limited_tree();
    let config = Config { entries_per_directory: 3, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    assert!(h.paths().contains(&"big/f0".to_string()));
    grow_beyond_limit(&fs);
    h.run_round();
    assert!(
        h.paths().contains(&"big/f0".to_string()) && h.paths().contains(&"big/f1".to_string()),
        "RFC 20 and 17.5: a listing over the entry ceiling must retain the previous children, not truncate them"
    );
    assert!(!h.paths().contains(&"big/f2".to_string()), "a rejected listing published part of its result");
    assert_eq!(
        h.health().reconciliation.last_round,
        Some(RoundResult::Degraded { unsatisfied: [path("big")].into_iter().collect() })
    );
}

#[test]
fn a_snapshot_handle_taken_before_a_rejected_listing_still_reads_its_own_version() {
    let fs = limited_tree();
    let config = Config { entries_per_directory: 3, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    let held = h.snapshot();
    let version = held.version();
    grow_beyond_limit(&fs);
    h.run_round();
    assert_eq!(held.version(), version, "RFC 7.3 and 17.5: a published snapshot must be immutable");
    assert!(held.get(&path("big/f0")).is_some(), "the held snapshot lost an entry it published");
    assert!(held.get(&path("big/f2")).is_none(), "the held snapshot gained an entry from a rejected listing");
    assert_eq!(h.snapshot().version(), version, "a rejected listing published a new version");
}

#[test]
fn a_directory_over_its_entry_limit_reports_a_degraded_path_and_a_limit_cause() {
    let fs = limited_tree();
    let config = Config { entries_per_directory: 3, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    h.take_events();
    grow_beyond_limit(&fs);
    h.run_round();
    assert!(
        h.health().reconciliation.degraded_paths.contains(&path("big")),
        "RFC 15.6: a listing over a configured limit must report its path as degraded"
    );
    let limits: Vec<RelativePath> = h
        .events()
        .iter()
        .filter_map(|e| match e {
            UpdateEvent::Delta(update) => Some(update.errors.clone()),
            UpdateEvent::Health { errors, .. } | UpdateEvent::Reset { errors, .. } => Some(errors.clone()),
            UpdateEvent::Terminal { .. } => None,
        })
        .flatten()
        .filter(|e| e.error == ErrorCause::LimitExceeded)
        .map(|e| e.path)
        .collect();
    assert_eq!(limits, vec![path("big")], "RFC 13.1: the resource-limit cause must name the directory that hit it");
}

#[test]
fn opening_with_a_higher_entry_limit_accepts_the_previously_rejected_listing() {
    let fs = limited_tree();
    let mut low =
        Harness::open(fs.clone(), Arc::new(LoadAll), Config { entries_per_directory: 3, ..Default::default() })
            .expect("open");
    low.run_until_idle();
    grow_beyond_limit(&fs);
    low.run_round();
    assert!(!low.paths().contains(&"big/f4".to_string()));

    let mut raised =
        Harness::open(fs.clone(), Arc::new(LoadAll), Config { entries_per_directory: 8, ..Default::default() })
            .expect("open");
    raised.run_until_idle();
    raised.run_round();
    assert!(
        raised.paths().contains(&"big/f4".to_string()),
        "RFC 9.2 and 13.1: a raised entry limit must let the retry accept the listing that was rejected"
    );
    assert_eq!(raised.health().reconciliation.last_round, Some(RoundResult::Successful));
    assert!(raised.health().reconciliation.degraded_paths.is_empty());
}

fn listings_under(fs: &FakeFileSystem, paths: &[&str]) -> u32 {
    paths.iter().map(|p| fs.count_ops(FakeOp::ReadDir, p) as u32).sum()
}

#[test]
fn a_listing_under_a_remounted_path_is_charged_to_the_new_domain() {
    let fs = tree(&["sub", "sub/inner", "other"]);
    fs.set_domain("", HOME);
    fs.set_cost(CostScope::Domain(HOME), FakeOp::ReadDir, Duration::from_millis(10));
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_millis(40));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(5));
    let before = h.charged_work_by_domain();
    assert_eq!(before.get(&MEDIA), None, "the media domain was charged before it existed");

    fs.clear_ops();
    fs.remount("sub", MEDIA);
    run_one_round(&mut h);
    let after = h.charged_work_by_domain();
    let media = after.get(&MEDIA).copied().unwrap_or_default();
    let home = after.get(&HOME).copied().unwrap_or_default() - before.get(&HOME).copied().unwrap_or_default();
    let moved = listings_under(&fs, &["sub", "sub/inner"]);
    let stayed = listings_under(&fs, &["", "other"]);
    assert!(moved >= 2, "the remounted subtree was listed {moved} times");
    assert_eq!(
        media,
        Duration::from_millis(40) * moved,
        "RFC 15.3 and 17.5: the {moved} listings under a remounted subtree must be charged to the new domain \
         at its own cost; the round charged {media:?} to it"
    );
    assert_eq!(home, Duration::from_millis(10) * stayed, "the old domain was charged for listings it no longer owns");
}

#[test]
fn descending_into_a_child_domain_charges_the_child_domain() {
    let fs = tree(&["sub", "sub/inner", "other"]);
    fs.set_domain("", HOME);
    fs.set_domain("sub", MEDIA);
    fs.set_cost(CostScope::Domain(HOME), FakeOp::ReadDir, Duration::from_millis(10));
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_millis(40));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(5));
    let charged = h.charged_work_by_domain();
    let child = listings_under(&fs, &["sub", "sub/inner"]);
    let parent = listings_under(&fs, &["", "other"]);
    assert!(child >= 2, "the child domain was listed {child} times");
    assert_eq!(
        charged.get(&MEDIA).copied(),
        Some(Duration::from_millis(40) * child),
        "RFC 17.5: a domain crossing must charge the child domain from its first listing; charged {charged:?}"
    );
    assert_eq!(charged.get(&HOME).copied(), Some(Duration::from_millis(10) * parent), "{charged:?}");
}

#[test]
fn a_slow_domain_does_not_delay_the_fast_domains_baseline_coverage() {
    let fast = numbered("fast", 3);
    let slow = numbered("slow/s", 4);
    let mut dirs: Vec<String> = fast.clone();
    dirs.push("slow".into());
    dirs.extend(slow);
    let fs = tree(&borrowed(&dirs));
    fs.set_domain("", HOME);
    fs.set_domain("slow", MEDIA);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let config = Config { max_in_flight: 2, batch_size: 8, ..Default::default() };
    let mut h = scanned(fs.clone(), config);
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_secs(120));

    let slow_job = dispatched_job(&mut h, "slow");
    let dispatched_at = h.now();
    let batch = h.coordinator.open_batch().map(|view| view.members).unwrap_or_default();
    assert!(batch.contains(&slow_job.id), "the slow listing was not admitted into a closed batch");

    let crossed = dispatched_at + STUCK_THRESHOLD + Duration::from_secs(1);
    h.run_jobs_until(crossed);
    assert!(
        h.stats().blocking_slots.iter().any(|slot| slot.job == slow_job.id),
        "RFC 13.5: the slow worker returned before it could cross the stuck threshold"
    );
    assert!(
        h.stats().stuck_workers.iter().any(|slot| slot.job == slow_job.id),
        "RFC 13.5: an operation past the stuck threshold must be reported as a stuck worker"
    );
    assert!(
        h.coordinator.open_batch().map(|view| !view.members.contains(&slow_job.id)).unwrap_or(true),
        "RFC 11.3 and 13.5: a stuck logical job must leave its closed batch"
    );

    let fast_before: BTreeSet<RelativePath> =
        h.admissions().iter().filter(|a| a.at > crossed).map(|a| a.entry.clone()).collect();
    let returns_at = dispatched_at + Duration::from_secs(120);
    let target = returns_at.saturating_sub(h.now()) / 2;
    let target = h.now() + target;
    h.run_jobs_until(target);
    assert!(
        h.stats().blocking_slots.iter().any(|slot| slot.job == slow_job.id),
        "the slow worker returned before the window this test measures"
    );
    let fast_after: Vec<RelativePath> = h
        .admissions()
        .iter()
        .filter(|a| a.at > crossed && !a.entry.starts_with(&path("slow")))
        .map(|a| a.entry.clone())
        .collect();
    assert!(
        !fast_after.is_empty(),
        "RFC 13.5 and 17.5: a stuck worker on one domain must not delay another domain's baseline work; \
         between {crossed:?} and {target:?} the fast domain was admitted {} times while the slow worker \
         still held its slot (already seen: {fast_before:?})",
        fast_after.len()
    );
}

#[test]
fn a_stuck_worker_quarantines_its_domain_until_it_returns() {
    let fast = numbered("fast", 3);
    let mut dirs: Vec<String> = fast;
    dirs.push("stuck".into());
    dirs.push("stuck/child".into());
    let fs = tree(&borrowed(&dirs));
    fs.set_domain("", HOME);
    fs.set_domain("stuck", MEDIA);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let mut h = scanned(fs.clone(), Config::default());
    fs.set_cost(CostScope::path("stuck/child"), FakeOp::ReadDir, Duration::from_secs(36_000));

    let target = h.now() + Duration::from_secs(600);
    h.run_jobs_until(target);

    let admissions = h.admissions();
    let stuck_at = admissions
        .iter()
        .filter(|a| a.entry == path("stuck/child"))
        .map(|a| a.at)
        .next_back()
        .expect("the stuck listing was admitted");
    let deadline = stuck_at + STUCK_THRESHOLD;
    assert!(
        h.stats().blocking_slots.iter().any(|slot| slot.path == path("stuck/child")),
        "RFC 13.5: a stuck worker keeps its physical slot until its call returns"
    );
    let after: Vec<&Admission> = admissions.iter().filter(|a| a.at > deadline).collect();
    let quarantined = after.iter().filter(|a| a.entry.starts_with(&path("stuck"))).count();
    assert_eq!(quarantined, 0, "RFC 13.5: a domain with a stuck worker must admit no further work");
    let elsewhere = after.iter().filter(|a| !a.entry.starts_with(&path("stuck"))).count();
    assert!(
        elsewhere > 0,
        "RFC 13.5 and 17.5: a stuck worker must quarantine only its own domain; {} jobs were admitted anywhere \
         after the worker on {MEDIA} passed the {STUCK_THRESHOLD:?} threshold at {deadline:?}",
        after.len()
    );
}

#[test]
fn throttling_is_reported_in_the_resource_health_field_and_never_as_degradation() {
    let names = numbered("d", 12);
    let fs = tree(&borrowed(&names));
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, INITIAL_COST_ESTIMATE);
    let mut h = Harness::open(fs, Arc::new(LoadAll), Config::default()).expect("open");
    h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(1800));

    let health = h.health();
    assert!(
        health.reconciliation.degraded_paths.is_empty(),
        "RFC 15.1 item 5: a path that merely waited for capacity must not be reported as degraded: {:?}",
        health.reconciliation.degraded_paths
    );
    let budget = envelope(BACKGROUND_DUTY_GLOBAL, BACKGROUND_BURST_GLOBAL, MAXIMUM_PERIOD);
    let (at, worst) = worst_window(&h, MAXIMUM_PERIOD);
    assert!(
        worst <= budget,
        "RFC 15.6 and 15.1 item 7: with no resource health field the tree never throttles; it charged {worst:?} \
         over the {MAXIMUM_PERIOD:?} window ending at {at:?} against a budget of {budget:?} and still reported \
         {:?}, a successful reconciliation over work a governor would have deferred",
        health.reconciliation.last_round
    );
}

#[test]
fn a_domain_that_becomes_fast_again_converges_within_one_round() {
    let fs = tree(&["media", "media/inner"]);
    fs.set_domain("media", MEDIA);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_secs(60));
    let config = Config { stuck_threshold: Duration::from_secs(300), ..Default::default() };
    let mut h = scanned(fs.clone(), config);
    run_one_round(&mut h);

    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_millis(5));
    fs.add_silently("media/inner/late", EntryKind::File);
    run_one_round(&mut h);
    assert!(
        h.paths().contains(&"media/inner/late".to_string()),
        "RFC 15.5 and 17.5: a domain that measures fast again must converge within one round"
    );
    assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful));
}

#[test]
fn a_simulated_day_of_reconciliation_costs_no_real_time() {
    let names = numbered("d", 3);
    let fs = tree(&borrowed(&names));
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, INITIAL_COST_ESTIMATE);
    let config = Config { fixed_interval: Some(Duration::from_secs(60)), ..Default::default() };
    let mut h = Harness::open(fs, Arc::new(LoadAll), config).expect("open");

    let day = Duration::from_secs(86_400);
    let started = Instant::now();
    h.run_jobs_until(MonotonicTime::ZERO + day);
    let elapsed = started.elapsed();

    assert_eq!(h.now(), MonotonicTime::ZERO + day);
    assert!(h.charged_work() > Duration::from_secs(1), "the simulated day charged {:?}", h.charged_work());
    assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful));
    assert!(
        elapsed < Duration::from_secs(1),
        "RFC 17.5: no test may depend on wall-clock sleeps; a simulated day took {elapsed:?} of real time"
    );
}
