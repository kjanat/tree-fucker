use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use tree_fucker::core::{Class, Command, DomainStat, JobOperation, JobResult, JobSpec, MonotonicTime, WorkOrigin};
use tree_fucker::testing::{Admission, CostScope, DomainId, FailureMode, FakeFileSystem, FakeOp, Harness};
use tree_fucker::update::{
    ErrorCause, InitialScanState, ResourceHealth, ResourceLimit, RoundResult, ThrottleCause, UpdateEvent,
};
use tree_fucker::{
    AccessTopology, CancellationToken, Ceilings, Config, Continuation, DegradedCause, DomainCapabilities,
    DomainCrossing, DomainIdentity, EntryKind, FileSystem, FilesystemInstance, FilesystemSemantics, FsError, HintKind,
    HostConfig, IdentitySource, KindSource, Lease, LoadAll, MediaHint, MetadataSource, MetadataSources, RelativePath,
    SessionOutcome, SessionStep, TransportHint, WatcherKind, entry_bytes,
};

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
    let before = h.last_round();
    for _ in 0..4000 {
        let next = h.now() + Duration::from_secs(5);
        h.run_jobs_until(next);
        if h.last_round() != before {
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

fn dispatched_job_under(h: &mut Harness, prefix: &str) -> JobSpec {
    let prefix = path(prefix);
    for _ in 0..1200 {
        if let Some(job) = h.pending_jobs().into_iter().find(|job| job.path.starts_with(&prefix)) {
            return job;
        }
        let next = h.now() + Duration::from_secs(1);
        h.run_jobs_until(next);
    }
    panic!("no filesystem job under {prefix} was dispatched");
}

fn scanned(fs: Arc<FakeFileSystem>, config: Config) -> Harness {
    scanned_under(fs, HostConfig::default(), config)
}

fn scanned_under(fs: Arc<FakeFileSystem>, host: HostConfig, config: Config) -> Harness {
    let mut h = Harness::open_with_host(fs, Arc::new(LoadAll), host, config).expect("open");
    h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(120));
    h
}

fn stuck_after(threshold: Duration) -> HostConfig {
    HostConfig { stuck_threshold: threshold, ..Default::default() }
}

fn one_worker() -> HostConfig {
    HostConfig { maximum_in_flight: 1, per_domain_concurrency: 1, ..Default::default() }
}

fn follow() -> Config {
    Config { domain_crossing: DomainCrossing::Follow, ..Default::default() }
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

    let registered = u64::try_from(fs.ops().iter().filter(|(op, _)| *op == FakeOp::Watch).count()).unwrap_or(u64::MAX);
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
    let host = stuck_after(Duration::from_secs(36_000));
    let mut h = Harness::open_with_host(fs.clone(), Arc::new(LoadAll), host, Config::default()).expect("open");
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
    let mut last = h.last_round();
    for step in 0..40 {
        fs.mkdir(&format!("fresh{step}"));
        let t = h.command(Command::Refresh(vec![path("keep2")]));
        let target = h.now() + Duration::from_secs(60);
        h.run_jobs_until(target);
        assert!(h.result(t).is_some(), "refresh {step} never settled");
        if h.last_round() != last {
            last = h.last_round();
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
        .filter(|e| matches!(e.error, ErrorCause::ResourceLimited(_)))
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
    paths.iter().map(|p| u32::try_from(fs.count_ops(FakeOp::ReadDir, p)).unwrap_or(u32::MAX)).sum()
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
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), follow()).expect("open");
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
    let host = HostConfig { maximum_in_flight: 2, per_domain_concurrency: 2, ..Default::default() };
    let config = Config { batch_size: 8, ..follow() };
    let mut h = scanned_under(fs.clone(), host, config);
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_secs(120));

    let slow_job = dispatched_job_under(&mut h, "slow");
    let dispatched_at = h.now();
    let batch = h.coordinator.open_batch().map(|view| view.members).unwrap_or_default();
    assert!(batch.contains(&slow_job.id), "the slow listing was not admitted into a closed batch");

    let crossed = dispatched_at + STUCK_THRESHOLD + Duration::from_secs(1);
    h.run_jobs_until(crossed);
    assert!(
        h.stats().blocking_slots.iter().any(|slot| slot.job() == Some(slow_job.id)),
        "RFC 13.5: the slow worker returned before it could cross the stuck threshold"
    );
    assert!(
        h.stats().stuck_workers.iter().any(|slot| slot.job() == Some(slow_job.id)),
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
        h.stats().blocking_slots.iter().any(|slot| slot.job() == Some(slow_job.id)),
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
    let mut h = scanned(fs.clone(), follow());
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
    let mut h = scanned_under(fs.clone(), stuck_after(Duration::from_secs(300)), follow());
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
    h.run_jobs_until(MonotonicTime::ZERO + day);

    assert_eq!(h.now(), MonotonicTime::ZERO + day);
    assert_eq!(
        h.injected(),
        day,
        "RFC 17.5: no test may depend on wall-clock sleeps; every second of the simulated day must come from an \
         injected advance, and {:?} of the {day:?} did",
        h.injected()
    );
    assert!(h.charged_work() > Duration::from_secs(1), "the simulated day charged {:?}", h.charged_work());
    assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful));
    assert!(
        h.real_elapsed() < Duration::from_secs(10),
        "the injected-advance total above is the invariant; this is a loose sanity bound and a simulated day took \
         {:?} of real time",
        h.real_elapsed()
    );
}

fn wide(children: usize) -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("aaa");
    for i in 0..children {
        fs.create_file(&format!("aaa/f{i}"), 1);
    }
    fs.mkdir("zzz");
    fs.create_file("zzz/f", 1);
    fs
}

#[test]
fn a_listing_session_yields_at_every_lease_boundary_and_performs_no_operation_beyond_its_lease() {
    let fs = wide(7);
    fs.set_chunk_size(1);
    let mut session = fs.open_listing(fs.root(), &path("aaa"), Ceilings::entries(1000), CancellationToken::new());
    let lease = Lease { entries: 2, operations: 4 };
    let entry_lease = u64::try_from(lease.entries).unwrap_or(u64::MAX);
    let operation_lease = u32::try_from(lease.operations).unwrap_or(u32::MAX);

    let mut suspensions = 0;
    let mut enumerated = 0;
    let listing = loop {
        let (continuation, cost) = session.resume(lease);
        assert!(
            cost.entries_enumerated <= entry_lease,
            "RFC 10.2 and 17.5: a session must perform no operation beyond its lease; one step enumerated {} \
             entries under a lease of {}",
            cost.entries_enumerated,
            lease.entries
        );
        assert!(
            cost.per_child_operations() <= operation_lease,
            "RFC 10.2: a session must perform no per-child read beyond its lease; one step performed {} against \
             a lease of {}",
            cost.per_child_operations(),
            lease.operations
        );
        enumerated += cost.entries_enumerated;
        match continuation {
            Continuation::Suspended(next) => {
                suspensions += 1;
                assert_eq!(cost.entries_enumerated, entry_lease, "RFC 10.2: a session yields only at a lease boundary");
                session = next;
            }
            Continuation::Finished(SessionOutcome::Complete(listing)) => break listing,
            Continuation::Finished(other) => panic!("the session ended {other:?} instead of completing"),
        }
    };

    assert_eq!(enumerated, 7);
    assert_eq!(listing.entries.len(), 7);
    assert_eq!(
        suspensions, 3,
        "RFC 10.2: a seven-entry directory under a two-entry lease must yield at every lease boundary"
    );
    assert_eq!(
        fs.count_ops(FakeOp::ReadDir, "aaa"),
        1,
        "RFC 10.2: one session enumerates one directory, however many leases it consumes"
    );
}

#[test]
fn a_session_suspended_between_leases_holds_no_worker_slot() {
    let fs = wide(8);
    fs.set_chunk_size(1);
    fs.set_cost(CostScope::path("aaa"), FakeOp::ReadDir, Duration::from_secs(5));
    let config = Config { entries_per_lease: 2, ..Default::default() };
    let mut h = Harness::open_with_host(fs.clone(), Arc::new(LoadAll), one_worker(), config).expect("open");
    assert!(h.advance_to_next_completion(), "the root listing never ran");
    let big = h.pending_job_for("aaa").expect("the wide listing started");
    assert!(
        h.stats().blocking_slots.iter().any(|slot| slot.job() == Some(big.id)),
        "the wide listing never occupied a worker slot"
    );
    assert!(h.pending_job_for("zzz").is_none(), "a max_in_flight of one dispatched two workers");

    assert!(h.advance_to_next_completion(), "the first lease never returned");
    let stats = h.stats();
    assert_eq!(
        stats.suspended_sessions, 1,
        "RFC 10.2: a session whose lease is exhausted and whose renewal the governor denies stays suspended"
    );
    assert!(
        !stats.blocking_slots.iter().any(|slot| slot.job() == Some(big.id)),
        "RFC 10.2: a session waiting for a subsequent lease MUST NOT occupy a physical filesystem-worker slot; \
         it held {:?}",
        stats.blocking_slots
    );
    assert!(
        h.pending_job_for("zzz").is_some(),
        "RFC 10.2: yielding a lease returns physical execution capacity to the host governor, so the freed slot \
         must be available to another job"
    );
    assert!(
        stats.resource.is_throttled(),
        "RFC 15.6: a session waiting on the duty budget must be reported as throttled"
    );
}

#[test]
fn cancellation_between_enumeration_chunks_ends_the_session_cancelled_carrying_no_children() {
    let fs = wide(6);
    fs.set_chunk_size(1);
    let cancel = CancellationToken::new();
    let session = fs.open_listing(fs.root(), &path("aaa"), Ceilings::entries(1000), cancel.clone());
    let lease = Lease { entries: 2, operations: 8 };
    let Continuation::Suspended(session) = session.resume(lease).0 else {
        panic!("the session finished before the cancellation could land between chunks");
    };

    cancel.cancel();
    let (continuation, cost) = session.resume(lease);
    let Continuation::Finished(outcome) = continuation else {
        panic!("the session did not end after its cancellation token was set");
    };
    assert_eq!(
        outcome,
        SessionOutcome::Cancelled,
        "RFC 10.2: a session whose cancellation token was set between chunks ends Cancelled, and only a Complete \
         outcome carries children"
    );
    assert_eq!(
        cost.entries_enumerated, 0,
        "RFC 10.2: the worst-case latency of cooperative cancellation is one chunk of enumeration, so no further \
         chunk may run after the token is set"
    );
}

#[test]
fn a_cancelled_listing_session_commits_nothing_and_retains_its_retry() {
    let fs = tree(&["a"]);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(5));
    let mut h = scanned(fs.clone(), Config::default());
    let t = h.command(Command::Refresh(vec![path("a")]));
    let job = dispatched_job(&mut h, "a");
    fs.add_silently("a/late", EntryKind::File);
    let version = h.snapshot().version();
    assert!(h.complete_job_with(job.id, JobResult::Listing(SessionStep::cancelled())));
    assert_eq!(
        h.snapshot().version(),
        version,
        "RFC 10.2 and 11.5: a Complete session outcome is the only one that reaches the apply procedure, so a \
         Cancelled session commits nothing"
    );
    assert!(!h.paths().contains(&"a/late".to_string()), "a cancelled session published part of its enumeration");
    assert_eq!(h.stats().cancelled_sessions, 1);

    let target = h.now() + Duration::from_secs(600);
    h.run_jobs_until(target);
    assert!(
        h.paths().contains(&"a/late".to_string()),
        "RFC 13.1 and 13.5: a cancelled read leaves its target queued again, so work never disappears silently"
    );
    assert_eq!(h.result(t), Some(Ok(())));
}

#[test]
fn a_listing_at_the_entry_ceiling_stops_within_one_chunk_and_reports_the_count_seen() {
    let fs = wide(10);
    fs.set_chunk_size(2);
    let ceiling = 3;
    let mut session = fs.open_listing(fs.root(), &path("aaa"), Ceilings::entries(ceiling), CancellationToken::new());
    let outcome = loop {
        match session.resume(Lease { entries: 64, operations: 64 }).0 {
            Continuation::Suspended(next) => session = next,
            Continuation::Finished(outcome) => break outcome,
        }
    };
    let SessionOutcome::ResourceLimited(limited) = outcome else {
        panic!("RFC 10.2: a session that reaches the entry ceiling ends ResourceLimited, not {outcome:?}");
    };
    assert_eq!(limited.limit, ResourceLimit::EntriesPerDirectory);
    let seen = usize::try_from(limited.observed).expect("count");
    assert_eq!(
        seen, 4,
        "RFC 10.2: the ResourceLimited outcome carries the count seen so far, and an adapter MUST NOT accumulate \
         more than the entry ceiling plus one chunk before stopping"
    );
    assert!(seen <= ceiling + fs.chunk_size());
}

#[test]
fn a_listing_over_the_entry_ceiling_reports_the_count_seen_and_the_configured_limit() {
    let fs = limited_tree();
    let config = Config { entries_per_directory: 3, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    grow_beyond_limit(&fs);
    h.run_round();

    let events = h.stats().resource_limits;
    let event = events
        .iter()
        .find(|e| e.path == path("big"))
        .unwrap_or_else(|| panic!("RFC 15.6 and 16: a resource-limit event must name the directory that hit it"));
    assert_eq!(event.limited.limit, ResourceLimit::EntriesPerDirectory);
    assert_eq!(
        (event.limited.observed, event.limited.configured),
        (5, 3),
        "RFC 13.1 and 16: a resource-limit event names the resource, the count seen, and the configured limit"
    );
}

#[test]
fn worker_loss_during_a_chunked_listing_leaves_the_previous_snapshot_and_schedules_the_retry() {
    let fs = tree(&["wide"]);
    for i in 0..6 {
        fs.create_file(&format!("wide/f{i}"), 1);
    }
    let config = Config { entries_per_lease: 2, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    let version = h.snapshot().version();
    let before = h.paths();
    fs.add_silently("wide/late", EntryKind::File);

    let t = h.command(Command::Refresh(vec![path("wide")]));
    let first = h.pending_job_for("wide").expect("the refresh listing started");
    assert!(h.complete_job(first.id), "the first lease never ran");
    assert!(
        h.stats().lease_grants >= 1,
        "a seven-entry directory under a two-entry lease must take a further lease grant"
    );
    let resumed = h.pending_job_for("wide").expect("the suspended session never resumed");
    let lost_before = h.stats().lost_workers;
    assert!(h.lose_job(resumed.id));

    assert_eq!(
        h.snapshot().version(),
        version,
        "RFC 10.2 and 13.5: a session lost mid-enumeration leaves the previous snapshot intact"
    );
    assert_eq!(h.paths(), before, "a lost chunked listing published part of its enumeration");
    assert_eq!(h.stats().lost_workers, lost_before + 1);

    let target = h.now() + Duration::from_secs(600);
    h.run_jobs_until(target);
    assert!(
        h.paths().contains(&"wide/late".to_string()),
        "RFC 13.5: a lost worker must return its read target to schedulable state, so work never disappears silently"
    );
    assert_eq!(h.result(t), Some(Ok(())));
}

#[test]
fn a_directory_larger_than_one_lease_is_charged_per_lease_within_the_reserved_envelope() {
    let fs = wide(24);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, INITIAL_COST_ESTIMATE);
    fs.set_cost(CostScope::Everything, FakeOp::Chunk, INITIAL_COST_ESTIMATE);
    let config = Config { entries_per_lease: 4, ..Default::default() };
    let mut h = Harness::open(fs, Arc::new(LoadAll), config).expect("open");
    h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(1800));

    let leases: Vec<Admission> = h.admissions().into_iter().filter(|a| a.entry == path("aaa")).collect();
    let renewals = leases.iter().filter(|a| a.lease > 0).count();
    assert!(
        renewals >= 5,
        "RFC 10.2 and 15.2: a directory larger than one lease is charged per lease; twenty-four children under a \
         four-entry lease took {renewals} further lease grants"
    );

    let budget = envelope(BACKGROUND_DUTY_GLOBAL, BACKGROUND_BURST_GLOBAL, MAXIMUM_PERIOD);
    let (at, worst) = h.worst_reserved_window(MAXIMUM_PERIOD);
    assert!(
        worst <= budget,
        "RFC 15.3: worker time reserved at admission over the {MAXIMUM_PERIOD:?} window ending at {at:?} was \
         {worst:?}, above the rate times window plus burst budget of {budget:?}, with every lease charged"
    );
}

#[test]
fn the_periodic_timer_is_due_no_later_than_the_maximum_period_while_capacity_exists() {
    let fs = tree(&["a"]);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(1));
    let maximum = Duration::from_secs(60);
    let config =
        Config { fixed_interval: Some(Duration::from_secs(600)), maximum_period: maximum, ..Default::default() };
    let mut h = scanned(fs, config);
    run_one_round(&mut h);

    assert!(!h.stats().resource.is_throttled(), "the tree was throttled, so this test measures nothing");
    let (_, due) = h.timer().expect("periodic timer armed");
    assert!(
        due <= h.now() + maximum,
        "RFC 12: when capacity exists the periodic timer is due no later than now plus maximum_period, however \
         long the configured fixed interval is; it was armed for {due:?} at {:?}",
        h.now()
    );
}

#[test]
fn a_throttled_periodic_timer_waits_for_the_governor_beyond_the_maximum_period() {
    let fs = tree(&["slow"]);
    fs.set_cost(CostScope::path("slow"), FakeOp::ReadDir, Duration::from_secs(30));
    let maximum = Duration::from_secs(60);
    let config = Config { maximum_period: maximum, ..Default::default() };
    let host = stuck_after(Duration::from_secs(300));
    let mut h = Harness::open_with_host(fs, Arc::new(LoadAll), host, config).expect("open");
    h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(60));

    assert!(h.governor().debt > Duration::ZERO, "the slow listing left no debt, so nothing throttles the timer");
    assert!(h.stats().resource.is_throttled());
    let (_, due) = h.timer().expect("timer armed");
    assert!(
        due > h.now() + maximum,
        "RFC 12 and 15.3: the periodic timer MUST NOT fire earlier than the resume time the governor reports, \
         even when that is later than maximum_period; it was armed for {due:?} at {:?}",
        h.now()
    );
}

#[test]
fn a_session_reports_its_blocking_time_and_result_bytes_with_every_lease() {
    let fs = wide(6);
    fs.set_chunk_size(1);
    fs.set_cost(CostScope::path("aaa"), FakeOp::ReadDir, Duration::from_millis(30));
    fs.set_cost(CostScope::path("aaa"), FakeOp::Chunk, Duration::from_millis(5));
    let session = fs.open_listing(fs.root(), &path("aaa"), Ceilings::entries(1000), CancellationToken::new());
    let lease = Lease { entries: 2, operations: 8 };

    let (continuation, first) = session.resume(lease);
    assert_eq!(
        first.blocking,
        Some(Duration::from_millis(30)),
        "RFC 15.2: the adapter reports the blocking time occupied by the job with every lease it consumes"
    );
    assert!(first.bytes > 0, "RFC 15.2: the adapter reports the bytes owned by the returned result");
    let Continuation::Suspended(session) = continuation else {
        panic!("a six-entry directory under a two-entry lease did not yield");
    };

    let (_, second) = session.resume(lease);
    assert_eq!(
        second.blocking,
        Some(Duration::from_millis(5)),
        "RFC 15.2: every lease reports its own cost, not the session's total"
    );
    assert!(
        second.bytes > first.bytes,
        "RFC 15.2: the reported byte count covers the result the session holds; it went from {} to {}",
        first.bytes,
        second.bytes
    );
}

#[test]
fn the_coordinator_records_reported_blocking_and_the_bytes_a_session_holds() {
    let fs = wide(8);
    fs.set_chunk_size(1);
    fs.set_cost(CostScope::path("aaa"), FakeOp::ReadDir, Duration::from_secs(5));
    fs.set_cost(CostScope::path("aaa"), FakeOp::Chunk, Duration::from_millis(10));
    let config = Config { entries_per_lease: 2, ..Default::default() };
    let mut h = Harness::open_with_host(fs.clone(), Arc::new(LoadAll), one_worker(), config).expect("open");
    assert!(h.advance_to_next_completion(), "the root listing never ran");
    let big = h.pending_job_for("aaa").expect("the wide listing started");
    assert!(h.advance_to_next_completion(), "the first lease never returned");

    let suspended = h.stats();
    assert_eq!(suspended.suspended_sessions, 1, "the first lease did not leave the session suspended");
    assert!(
        suspended.in_flight_listing_bytes > 0,
        "RFC 15.2 and 16: the bytes a suspended session holds must be visible while it waits"
    );
    assert_eq!(
        suspended.reported_blocking,
        Duration::from_secs(5),
        "RFC 15.2: the coordinator records the blocking time the adapter reported"
    );
    assert!(
        suspended.governor.charged >= Duration::from_secs(5),
        "RFC 15.2: a job whose reported blocking time is at most its occupancy is charged for it"
    );

    fs.set_cost(CostScope::path("aaa"), FakeOp::ReadDir, Duration::from_millis(1));
    fs.set_cost(CostScope::path("aaa"), FakeOp::Chunk, Duration::from_millis(1));
    for _ in 0..200 {
        if h.held_listing_sessions() == 0 && h.pending_jobs().is_empty() {
            break;
        }
        let next = h.now() + Duration::from_secs(30);
        h.run_jobs_until(next);
    }
    assert_eq!(h.held_listing_sessions(), 0, "no session finished within the horizon this test allows");

    let settled = h.stats();
    assert_eq!(
        settled.in_flight_listing_bytes, 0,
        "RFC 15.2: a session that reached a terminal outcome holds no result bytes"
    );
    assert!(
        settled.listing_bytes >= suspended.in_flight_listing_bytes,
        "RFC 16: the bytes a finished session produced must be observable; it produced {} against the {} it held \
         while suspended",
        settled.listing_bytes,
        suspended.in_flight_listing_bytes
    );
    assert!(h.admissions().iter().any(|a| a.job == big.id && a.lease > 0));
}

#[test]
fn a_suspended_session_whose_guards_go_stale_is_discarded_and_holds_no_session() {
    let fs = wide(8);
    fs.set_chunk_size(1);
    fs.set_cost(CostScope::path("aaa"), FakeOp::ReadDir, Duration::from_secs(5));
    let config = Config { entries_per_lease: 2, ..Default::default() };
    let mut h = Harness::open_with_host(fs.clone(), Arc::new(LoadAll), one_worker(), config).expect("open");
    assert!(h.advance_to_next_completion(), "the root listing never ran");
    let big = h.pending_job_for("aaa").expect("the wide listing started");
    assert!(h.advance_to_next_completion(), "the first lease never returned");
    assert_eq!(h.stats().suspended_sessions, 1, "the first lease did not leave the session suspended");
    assert_eq!(h.held_listing_sessions(), 1, "the suspended session was not held for its next lease");

    let stale_before = h.stats().stale_results;
    h.command(Command::InvalidatePolicy(vec![RelativePath::root()]));

    assert_eq!(
        h.stats().stale_results,
        stale_before + 1,
        "RFC 11.4: a suspended session whose publication guard is stale must be discarded"
    );
    assert!(
        h.cancelled().contains(&big.id),
        "RFC 10.2: a discarded suspended session must be cancelled so its handle and buffer are released"
    );
    assert_eq!(
        h.held_listing_sessions(),
        0,
        "RFC 10.2: a session that outlives its job keeps an open handle and a partial buffer for nothing"
    );
}

fn domain_stat(h: &Harness, domain: DomainId) -> DomainStat {
    h.stats()
        .domains
        .into_iter()
        .find(|stat| stat.identity == DomainIdentity::Known(FakeFileSystem::domain_key(domain)))
        .unwrap_or_else(|| panic!("{domain} was never entered"))
}

fn admissions_under(h: &Harness, prefix: &str, since: usize) -> usize {
    let prefix = path(prefix);
    h.admissions().iter().skip(since).filter(|a| a.entry.starts_with(&prefix)).count()
}

fn admissions_outside(h: &Harness, prefix: &str, since: usize) -> usize {
    let prefix = path(prefix);
    h.admissions().iter().skip(since).filter(|a| !a.entry.starts_with(&prefix)).count()
}

fn indebted_media(cost: Duration) -> (Arc<FakeFileSystem>, Harness) {
    let fs = tree(&["fast0", "fast1", "media", "media/inner"]);
    fs.set_domain("", HOME);
    fs.set_domain("media", MEDIA);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let host = HostConfig {
        background_duty: 1.0,
        background_burst: Duration::from_secs(300),
        domain_background_duty: 0.02,
        domain_background_burst: Duration::from_millis(500),
        foreground_duty: 1.0,
        foreground_burst: Duration::from_secs(300),
        domain_foreground_duty: 0.02,
        stuck_threshold: Duration::from_secs(3600),
        ..Default::default()
    };
    let mut h = scanned_under(fs.clone(), host, follow());
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, cost);
    h.run_jobs_until(h.now() + cost + Duration::from_secs(30));
    (fs, h)
}

fn domain_resume(h: &Harness, domain: DomainId) -> MonotonicTime {
    match domain_stat(h, domain).resource {
        ResourceHealth::Throttled { cause: ThrottleCause::DutyBudget, resume: Some(at) } => at,
        other => panic!("RFC 15.6: a domain whose bucket is in debt reports a computable resume time; {other:?}"),
    }
}

#[test]
fn one_domains_debt_never_reduces_another_domains_admissible_rate() {
    let (_fs, mut h) = indebted_media(Duration::from_secs(5));
    let media = domain_stat(&h, MEDIA);
    let home = domain_stat(&h, HOME);
    assert!(
        media.debt > Duration::from_secs(2),
        "the media domain never went into debt, so nothing separates the two domains: {media:?}"
    );
    assert_eq!(home.debt, Duration::ZERO, "RFC 15.3: one domain's overshoot must not put another domain in debt");

    let from = h.now();
    let since = h.admissions().len();
    let t = h.command(Command::Refresh(vec![path("fast0"), path("fast1")]));
    h.run_jobs_until(from + Duration::from_secs(120));
    assert_eq!(
        h.result(t),
        Some(Ok(())),
        "RFC 17.5: one domain's debt never reduces another domain's admissible rate; the healthy domain's reads \
         were still waiting {:?} after the media domain went into debt",
        h.now().saturating_sub(from)
    );
    assert_eq!(
        admissions_under(&h, "media", since),
        0,
        "the indebted domain was admitted while its bucket was {:?} in debt",
        domain_stat(&h, MEDIA).debt
    );
    assert!(admissions_outside(&h, "media", since) >= 2, "the healthy domain was not admitted at all");
}

#[test]
fn a_governor_denial_for_one_domain_still_admits_another_domains_ready_work() {
    let (_fs, mut h) = indebted_media(Duration::from_secs(5));
    let charged = h.now();
    h.command(Command::Refresh(vec![path("media")]));
    h.run_jobs_until(charged + Duration::from_secs(30));
    assert!(
        domain_stat(&h, MEDIA).foreground_debt > Duration::ZERO,
        "RFC 15.4: a refresh read draws on the foreground buckets, and this one left no debt behind"
    );
    let from = h.now();
    let since = h.admissions().len();
    let denials = h.governor().denials;
    h.command(Command::Refresh(vec![path("fast0"), path("fast1"), path("media"), path("media/inner")]));
    h.run_jobs_until(from + Duration::from_secs(60));
    assert!(
        h.governor().denials > denials,
        "RFC 15.3: the indebted domain's reads were never denied, so no cycle had a denial to skip past"
    );
    assert!(
        admissions_outside(&h, "media", since) > 0,
        "RFC 11.3 and 15.3: a governor denial for one domain must skip that domain's ready work and continue with \
         the other domains; the cycle admitted nothing after the denial"
    );
}

#[test]
fn a_labelled_domain_that_measures_slow_converges_to_a_window_of_one() {
    let dirs = numbered("media/d", 6);
    let mut all: Vec<String> = vec!["media".into()];
    all.extend(dirs.clone());
    let fs = tree(&borrowed(&all));
    fs.set_domain("media", MEDIA);
    fs.set_capabilities(
        MEDIA,
        DomainCapabilities {
            topology: AccessTopology::Local,
            media: MediaHint::SolidState,
            transport: TransportHint::Nvme,
            ..DomainCapabilities::inline()
        },
    );
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(1));
    let mut h = scanned_under(fs.clone(), stuck_after(Duration::from_secs(3600)), follow());
    let warm = domain_stat(&h, MEDIA);
    assert!(
        warm.window > 1,
        "RFC 15.5: a domain measuring low latency must raise its window above its conservative start; it reports \
         {warm:?}"
    );

    for (index, dir) in dirs.iter().enumerate() {
        let cost = if index.is_multiple_of(2) { Duration::from_millis(1) } else { Duration::from_secs(5) };
        fs.set_cost(CostScope::path(dir), FakeOp::ReadDir, cost);
    }
    for _ in 0..6 {
        run_one_round(&mut h);
    }
    let slow = domain_stat(&h, MEDIA);
    assert_eq!(
        slow.window, 1,
        "RFC 15.5 and 17.5: a domain labelled local NVMe solid state that measures a tail of {:?} against a \
         standing delay of {:?} must converge to a window of one; it reports {slow:?}",
        slow.latency.tail, slow.latency.minimum
    );
    assert_eq!(
        slow.capabilities.topology,
        AccessTopology::Local,
        "the label must be unchanged; measured behaviour outranks it rather than rewriting it"
    );
}

#[test]
fn a_window_never_exceeds_the_ceiling_whatever_labels_say() {
    let dirs = numbered("local/d", 8);
    let remote = numbered("remote/d", 8);
    let mut all: Vec<String> = vec!["local".into(), "remote".into()];
    all.extend(dirs);
    all.extend(remote);
    let fs = tree(&borrowed(&all));
    fs.set_domain("local", HOME);
    fs.set_domain("remote", MEDIA);
    fs.set_capabilities(
        HOME,
        DomainCapabilities {
            topology: AccessTopology::Local,
            media: MediaHint::SolidState,
            transport: TransportHint::Nvme,
            ..DomainCapabilities::inline()
        },
    );
    fs.set_capabilities(
        MEDIA,
        DomainCapabilities {
            topology: AccessTopology::Remote,
            transport: TransportHint::Network,
            ..DomainCapabilities::inline()
        },
    );
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(1));
    let host =
        HostConfig { per_domain_concurrency: 3, stuck_threshold: Duration::from_secs(3600), ..Default::default() };
    let mut h = scanned_under(fs.clone(), host, follow());
    for _ in 0..8 {
        run_one_round(&mut h);
    }
    let local = domain_stat(&h, HOME);
    let remote = domain_stat(&h, MEDIA);
    assert_eq!(
        local.ceiling, 3,
        "RFC 15.5: the ceiling is the smallest of the configured per-domain maximum, the global in-flight limit \
         and the topology ceiling; the local domain reports {local:?}"
    );
    assert_eq!(
        remote.ceiling, 2,
        "RFC 15.1 item 8: a label may lower a ceiling and never raise one; the remote domain reports {remote:?}"
    );
    for stat in [&local, &remote] {
        assert!(
            stat.window <= stat.ceiling,
            "RFC 15.5: a window never exceeds the ceiling whatever labels or measurements say; {stat:?}"
        );
        assert!(stat.in_flight <= stat.window, "RFC 15.3: physical concurrency never exceeds the domain window");
    }
}

#[test]
fn a_fast_domains_estimate_falls_to_its_measured_cost_and_raises_its_throughput() {
    fn run(cost: Duration) -> (Harness, DomainStat) {
        let names = numbered("d", 8);
        let fs = tree(&borrowed(&names));
        fs.set_cost(CostScope::Everything, FakeOp::ReadDir, cost);
        let mut h = Harness::open(fs, Arc::new(LoadAll), Config::default()).expect("open");
        h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(600));
        let stat = h.stats().domains.into_iter().next().unwrap_or_else(|| panic!("the tree entered no storage domain"));
        (h, stat)
    }

    let (fast, fast_stat) = run(Duration::from_millis(1));
    let (slow, slow_stat) = run(INITIAL_COST_ESTIMATE);
    let (_, dear_stat) = run(Duration::from_millis(200));
    assert!(
        dear_stat.estimate >= dear_stat.latency.minimum,
        "RFC 15.3: a reservation never drops below the domain's measured moving minimum of {:?}; the domain \
         reserves {:?}",
        dear_stat.latency.minimum,
        dear_stat.estimate
    );
    assert!(
        fast_stat.estimate <= Duration::from_millis(2) && fast_stat.estimate >= fast_stat.latency.minimum,
        "RFC 15.3 and 15.5: a domain whose listings measure {:?} must stop reserving the RFC 9.2 estimate of \
         {INITIAL_COST_ESTIMATE:?} and must never reserve below its measured moving minimum of {:?}; it reserves \
         {:?}",
        fast_stat.latency.median,
        fast_stat.latency.minimum,
        fast_stat.estimate
    );
    assert_eq!(
        slow_stat.estimate, INITIAL_COST_ESTIMATE,
        "a domain that measures the initial estimate keeps it: {slow_stat:?}"
    );
    assert!(
        fast.stats().listings > slow.stats().listings,
        "RFC 15.5: a domain whose estimate falls to its measured cost admits more work in the same window; the \
         fast domain listed {} times against the slow domain's {}",
        fast.stats().listings,
        slow.stats().listings
    );
    let budget = envelope(BACKGROUND_DUTY_GLOBAL, BACKGROUND_BURST_GLOBAL, MAXIMUM_PERIOD);
    let (at, worst) = fast.worst_reserved_window(MAXIMUM_PERIOD);
    assert!(
        worst <= budget,
        "RFC 15.3: the raised throughput must stay inside the envelope; the window ending at {at:?} reserved \
         {worst:?} against {budget:?}"
    );
}

#[test]
fn convergence_resumes_when_capacity_returns() {
    let fs = tree(&["media", "media/inner"]);
    fs.set_domain("media", MEDIA);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let mut h = scanned_under(fs.clone(), stuck_after(Duration::from_secs(3600)), follow());
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_secs(60));
    h.run_jobs_until(h.now() + Duration::from_secs(90));
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_millis(10));
    fs.add_silently("media/inner/late", EntryKind::File);

    let throttled = domain_stat(&h, MEDIA);
    assert!(throttled.debt > Duration::ZERO, "the media domain carries no debt to repay: {throttled:?}");
    let resume = match throttled.resource {
        ResourceHealth::Throttled { cause: ThrottleCause::DutyBudget, resume: Some(at) } => at,
        other => {
            panic!("RFC 15.6: a domain whose bucket is in debt reports a computable resume time; it reports {other:?}")
        }
    };
    assert!(
        !h.paths().contains(&"media/inner/late".to_string()),
        "the silent addition converged before the domain was throttled, so the test never observed a throttle"
    );

    h.run_jobs_until(resume + Duration::from_secs(120));
    run_one_round(&mut h);
    assert!(
        h.paths().contains(&"media/inner/late".to_string()),
        "RFC 5.2 and 17.5: convergence must resume once the buckets refill; the tree is at {:?} against a \
         reported resume of {resume:?} and reports {:?}",
        h.now(),
        domain_stat(&h, MEDIA)
    );
}

#[test]
fn a_repeatedly_failing_target_is_admitted_later_each_time_and_its_domain_carries_the_surcharge() {
    fn attempts(surcharge: Duration) -> (usize, Duration, Duration) {
        let fs = tree(&["media", "media/inner"]);
        fs.set_domain("media", MEDIA);
        fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
        let host = HostConfig {
            failure_surcharge: surcharge,
            stuck_threshold: Duration::from_secs(3600),
            ..Default::default()
        };
        let mut h = scanned_under(fs.clone(), host, follow());
        let charged = domain_stat(&h, MEDIA).charged;
        fs.fail("media/inner", FakeOp::ReadDir, FailureMode::Always(FsError::Transient("blip".into())));
        let from = h.now();
        h.run_jobs_until(from + Duration::from_secs(1800));
        let tries = h.admissions().iter().filter(|a| a.at > from && a.entry == path("media/inner")).count();
        (tries, h.governor().surcharged, domain_stat(&h, MEDIA).charged - charged)
    }

    let (free, unsurcharged, _) = attempts(Duration::ZERO);
    let (charged_attempts, surcharged, charged) = attempts(Duration::from_millis(20));
    assert_eq!(unsurcharged, Duration::ZERO, "a zero surcharge must charge nothing");
    assert!(free >= 3, "the failing target was retried {free} times without a surcharge, too few to compare");
    assert!(
        charged_attempts < free,
        "RFC 13.1 and 15.1 item 6: a failed attempt is charged a surcharge against its domain, so the admission          time of each retry is monotone non-decreasing in the cost already consumed; the target was admitted          {charged_attempts} times with the surcharge against {free} without it"
    );
    let expected = Duration::from_millis(20) * u32::try_from(charged_attempts).unwrap_or(u32::MAX);
    assert!(
        surcharged >= expected,
        "RFC 13.1: {charged_attempts} failed attempts carry at least {expected:?} of surcharge; the governor          charged {surcharged:?}"
    );
    assert!(
        charged >= expected,
        "RFC 13.1: the surcharge is charged against the failing target's domain; its bucket carries {charged:?}          over {charged_attempts} attempts"
    );
}

#[test]
fn a_conservative_topology_starts_at_a_window_of_one_and_local_block_storage_starts_at_two() {
    for (topology, media, expected) in [
        (AccessTopology::Remote, MediaHint::Unknown, 1),
        (AccessTopology::Unknown, MediaHint::Unknown, 1),
        (AccessTopology::Local, MediaHint::Removable, 1),
        (AccessTopology::Local, MediaHint::SolidState, 2),
    ] {
        let fs = tree(&[]);
        fs.set_default_capabilities(DomainCapabilities { topology, media, ..DomainCapabilities::inline() });
        let mut h = Harness::open(fs, Arc::new(LoadAll), Config::default()).expect("open");
        assert!(h.complete_next_job(), "the root listing was never dispatched");
        let stat = h.stats().domains.into_iter().next().expect("the root domain was never entered");
        assert_eq!(
            stat.window, expected,
            "RFC 15.5: a domain whose topology is {topology:?} and whose media is {media:?} starts with a window              of {expected}; it reports {stat:?}"
        );
    }
}

#[test]
fn a_dead_domain_never_gains_a_second_stuck_worker() {
    let fs = tree(&["fast0", "media", "media/one", "media/two"]);
    fs.set_domain("", HOME);
    fs.set_domain("media", MEDIA);
    fs.set_capabilities(
        MEDIA,
        DomainCapabilities {
            topology: AccessTopology::Remote,
            transport: TransportHint::Network,
            ..DomainCapabilities::inline()
        },
    );
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let host = HostConfig { per_domain_concurrency: 1, ..Default::default() };
    let mut h = scanned_under(fs.clone(), host, follow());
    assert_eq!(
        domain_stat(&h, MEDIA).window,
        1,
        "RFC 15.5: the window never exceeds the configured per-domain maximum, so only one worker can be inside          the media domain"
    );
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_secs(36_000));
    h.run_jobs_until(h.now() + Duration::from_secs(1800));

    let stat = domain_stat(&h, MEDIA);
    assert_eq!(
        stat.stuck, 1,
        "RFC 13.5 and 17.5: a dead domain never gains a second stuck worker; the domain reports {stat:?}"
    );
    assert_eq!(stat.in_flight, 1, "RFC 13.5: the stuck worker keeps its domain slot and no replacement is started");
    assert_eq!(h.stats().stuck_workers.len(), 1, "the tree reports {:?}", h.stats().stuck_workers);
}

#[test]
fn resource_health_names_the_domain_the_cause_and_the_resume_time() {
    let fs = tree(&["fast0", "media", "media/inner"]);
    fs.set_domain("", HOME);
    fs.set_domain("media", MEDIA);
    fs.set_capabilities(MEDIA, DomainCapabilities { topology: AccessTopology::Remote, ..DomainCapabilities::inline() });
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let host = HostConfig {
        domain_background_duty: 0.5,
        domain_background_burst: Duration::from_secs(30),
        ..Default::default()
    };
    let mut h = scanned_under(fs.clone(), host, follow());
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_secs(36_000));
    h.run_jobs_until(h.now() + Duration::from_secs(600));

    let media = domain_stat(&h, MEDIA).id;
    let home = domain_stat(&h, HOME).id;
    let health = h.health();
    assert_eq!(
        health.resource_domains.get(&media).copied(),
        Some(ResourceHealth::Throttled { cause: ThrottleCause::StuckWorker, resume: None }),
        "RFC 15.6: a quarantined domain reports StuckWorker with no computable resume time; health is {:?}",
        health.resource_domains
    );
    assert_eq!(
        health.resource_domains.get(&home).copied(),
        Some(ResourceHealth::Nominal),
        "RFC 13.5 and 15.6: the quarantine names one domain and leaves the others nominal; health is {:?}",
        health.resource_domains
    );
    assert!(
        health.reconciliation.degraded_paths.is_empty(),
        "RFC 15.1 item 5: throttling is never reported as a degraded path: {:?}",
        health.reconciliation.degraded_paths
    );
}

#[test]
fn per_domain_statistics_report_window_bucket_latency_and_counts() {
    let fs = tree(&["fast0", "fast1", "media", "media/inner"]);
    fs.set_domain("", HOME);
    fs.set_domain("media", MEDIA);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_secs(20));
    let mut h = scanned_under(fs.clone(), stuck_after(Duration::from_secs(3600)), follow());
    h.run_jobs_until(h.now() + Duration::from_secs(300));

    for stat in h.stats().domains {
        assert!(stat.window >= 1 && stat.window <= stat.ceiling, "RFC 16: {stat:?}");
        assert!(stat.granted > Duration::ZERO, "RFC 16: per-domain worker time granted is missing: {stat:?}");
        assert!(stat.charged > Duration::ZERO, "RFC 16: per-domain worker time consumed is missing: {stat:?}");
        assert!(stat.latency.samples > 0, "RFC 16: per-domain latency summaries are missing: {stat:?}");
        assert!(stat.estimate > Duration::ZERO, "RFC 16: the per-domain estimate is missing: {stat:?}");
        assert!(stat.listings > 0, "RFC 16: per-domain listing counts are missing: {stat:?}");
        assert!(stat.entries_enumerated > 0, "RFC 16: per-domain enumeration counts are missing: {stat:?}");
        assert!(stat.effective_duty > 0.0, "RFC 16: the effective background duty is missing: {stat:?}");
        assert!(
            stat.level == Duration::ZERO || stat.debt == Duration::ZERO,
            "RFC 16: a bucket reports either a level or a debt, never both: {stat:?}"
        );
        assert!(
            stat.capacity > Duration::ZERO,
            "RFC 16: the statistics must name the configured limit the domain was measured against: {stat:?}"
        );
    }
    let media = domain_stat(&h, MEDIA);
    assert!(
        media.charged >= Duration::from_secs(20),
        "RFC 15.3: completion reconciles the actual occupancy against the domain bucket in full; the domain \
         carries {:?} for a listing that occupied twenty seconds",
        media.charged
    );
    assert!(
        media.throttled_jobs > 0 && media.throttled_duration > Duration::ZERO,
        "RFC 16: the throttled job count and total throttled duration are missing for the indebted domain: \
         {media:?}"
    );
    assert!(
        media.debt > Duration::ZERO,
        "RFC 16: the per-domain bucket debt is missing for a domain that overshot its reservation: {media:?}"
    );
}

#[test]
fn a_domain_in_debt_is_not_admitted_before_the_reported_resume_time() {
    let (_fs, mut h) = indebted_media(Duration::from_secs(5));
    let resume = domain_resume(&h, MEDIA);
    let from = h.now();
    let since = h.admissions().len();
    assert!(resume > from + Duration::from_secs(30), "the reported resume of {resume:?} is too near {from:?}");

    h.run_jobs_until(MonotonicTime(resume.0.saturating_sub(Duration::from_secs(5))));
    assert_eq!(
        admissions_under(&h, "media", since),
        0,
        "RFC 12 and 15.3: the governor reports {resume:?} as the earliest time it can grant the next background          job on the media domain, so nothing on that domain may be admitted before it"
    );

    h.run_jobs_until(resume + Duration::from_secs(120));
    assert!(
        admissions_under(&h, "media", since) > 0,
        "RFC 15.3: admission resumes once the reported refill time passes; the tree is at {:?} against a          reported resume of {resume:?}",
        h.now()
    );
}

#[test]
fn dropped_watcher_events_under_throttling_are_repaired_by_the_next_admitted_round() {
    let names = numbered("d", 12);
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::Recursive));
    for name in &names {
        fs.mkdir(name);
        fs.create_file(&format!("{name}/f"), 1);
    }
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let config = Config { watcher_path_limit: 4, ..Default::default() };
    let mut h = scanned(fs.clone(), config);

    fs.set_cost(CostScope::path("d0"), FakeOp::ReadDir, Duration::from_secs(120));
    let slow = dispatched_job(&mut h, "d0");
    h.run_jobs_until(h.now() + Duration::from_secs(180));
    assert!(h.charges().iter().any(|c| c.job == slow.id), "the slow listing never returned");
    assert!(h.stats().resource.is_throttled(), "the slow listing left the tree unthrottled, so nothing is dropped");
    fs.set_cost(CostScope::path("d0"), FakeOp::ReadDir, Duration::from_millis(10));

    let dropped_before = h.stats().dropped_hints;
    let admitted_before = h.admissions().len();
    for name in &names {
        fs.add_silently(&format!("{name}/late"), EntryKind::File);
    }
    let hints = fs.emit_storm(&borrowed(&names), HintKind::Modify, 4);
    assert_eq!(h.deliver_watcher_events_capped(4), 4, "the coordinator did not receive the storm");
    assert!(
        h.stats().dropped_hints > dropped_before,
        "RFC 13.6: hints beyond the configured watcher path limit are dropped after counting"
    );
    let admitted = h.admissions().len() - admitted_before;
    assert!(
        admitted < hints,
        "RFC 15.1 item 3: a storm under throttling must admit no more work than the envelope allows; {hints} hints \
         admitted {admitted} jobs"
    );

    for _ in 0..40 {
        run_one_round(&mut h);
        if names.iter().all(|name| h.paths().contains(&format!("{name}/late"))) {
            break;
        }
    }
    for name in &names {
        assert!(
            h.paths().contains(&format!("{name}/late")),
            "RFC 5.3 and 17.5: suppressing watcher events under throttling must not invalidate the directory \
             guarantee; {name}/late never converged"
        );
    }
}

#[test]
fn a_retry_during_throttling_keeps_its_record_and_is_admitted_once_capacity_returns() {
    let fs = tree(&["fast", "flaky"]);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let mut h = scanned(fs.clone(), Config::default());

    fs.fail("flaky", FakeOp::ReadDir, FailureMode::Always(FsError::Transient("blip".into())));
    for _ in 0..20 {
        run_one_round(&mut h);
        if h.health().reconciliation.degraded_paths.contains(&path("flaky")) {
            break;
        }
    }
    assert!(
        h.health().reconciliation.degraded_paths.contains(&path("flaky")),
        "RFC 13.1: a transient failure degrades the round on its first attempt and retains retry work"
    );
    fs.clear_failures();

    fs.set_cost(CostScope::path("fast"), FakeOp::ReadDir, Duration::from_secs(120));
    let slow = dispatched_job(&mut h, "fast");
    h.run_jobs_until(h.now() + Duration::from_secs(180));
    assert!(h.charges().iter().any(|c| c.job == slow.id), "the slow listing never returned");
    fs.set_cost(CostScope::path("fast"), FakeOp::ReadDir, Duration::from_millis(10));
    assert!(h.stats().resource.is_throttled(), "the slow listing left the tree unthrottled");

    let throttled_at = h.now();
    let resume = h.governor().next_admissible.expect("a throttled governor names its resume time");
    assert!(resume > throttled_at, "the governor reported an immediate resume while in debt");
    let half = throttled_at + (resume.saturating_sub(throttled_at) / 2);
    h.run_jobs_until(half);
    let during: Vec<Admission> = h.admissions().into_iter().filter(|a| a.at > throttled_at && a.at <= half).collect();
    assert!(
        during.is_empty(),
        "RFC 15.1 item 6 and 15.3: a retry under throttling must not be admitted before its budget refills; {} were",
        during.len()
    );
    assert!(
        h.health().reconciliation.degraded_paths.contains(&path("flaky")),
        "RFC 15.3: denial changes no retry record, so the degraded path is still retained"
    );

    fs.add_silently("flaky/late", EntryKind::File);
    for _ in 0..40 {
        run_one_round(&mut h);
        if h.paths().contains(&"flaky/late".to_string()) {
            break;
        }
    }
    assert!(
        h.paths().contains(&"flaky/late".to_string()),
        "RFC 5.2 and 17.5: a retry deferred by the governor is admitted once its buckets refill"
    );
    assert!(
        !h.health().reconciliation.degraded_paths.contains(&path("flaky")),
        "RFC 13.1: an accepted recovery read clears the path's degradation"
    );
}

#[test]
fn a_resource_limit_reached_while_the_publication_guards_go_stale_publishes_nothing() {
    let fs = wide(8);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    fs.set_cost(CostScope::path("aaa"), FakeOp::ReadDir, Duration::from_secs(5));
    let config = Config { entries_per_directory: 3, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(120));

    let version = h.stats().version;
    let paths = h.paths();
    let limits_before = h.stats().resource_limits.len();
    let stale_before = h.stats().stale_results;
    let over = dispatched_job(&mut h, "aaa");

    h.command(Command::InvalidatePolicy(vec![RelativePath::root()]));
    h.run_jobs_until(h.now() + Duration::from_secs(30));
    assert!(h.charges().iter().any(|c| c.job == over.id), "the over-limit listing never returned");

    assert!(
        h.stats().stale_results > stale_before,
        "RFC 11.4: a result whose publication guard went stale is discarded in full before its outcome is read"
    );
    assert_eq!(
        h.stats().resource_limits.len(),
        limits_before,
        "RFC 11.4: a discarded result records nothing, not even its resource limit"
    );
    assert_eq!(h.stats().version, version, "RFC 15.6 and 17.5: a listing over a ceiling publishes nothing");
    assert_eq!(h.paths(), paths, "RFC 15.6 and 17.5: a listing over a ceiling publishes nothing");

    for _ in 0..200 {
        h.run_jobs_until(h.now() + Duration::from_secs(600));
        if h.stats().resource_limits.len() > limits_before {
            break;
        }
    }
    let event = h
        .stats()
        .resource_limits
        .last()
        .cloned()
        .expect("RFC 13.1: the requeued listing reaches the ceiling again and records its event");
    assert_eq!(event.path, path("aaa"));
    assert_eq!(event.limited.limit, ResourceLimit::EntriesPerDirectory);
    assert!(
        h.health().reconciliation.degraded_paths.contains(&path("aaa")),
        "RFC 15.6: the path is reported degraded with a resource-limit cause"
    );
    assert!(
        !h.paths().contains(&"aaa/f0".to_string()),
        "RFC 20: a directory over its limit is degraded, not truncated"
    );
}

#[test]
fn a_subtree_whose_domain_changes_in_place_under_load_charges_the_new_domain_and_converges() {
    let fs = tree(&["moving", "moving/inner", "other"]);
    fs.set_domain("", HOME);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let mut h = scanned(fs.clone(), follow());
    let home_before = domain_stat(&h, HOME).charged;

    let flooded =
        h.flood_hints_until(&["moving", "moving/inner", "other"], HintKind::Modify, h.now() + Duration::from_secs(30));
    assert!(flooded > 0, "the load generated no watcher hints");
    fs.remount("moving", MEDIA);
    fs.add_silently("moving/inner/late", EntryKind::File);
    h.flood_hints_until(&["moving", "moving/inner"], HintKind::Modify, h.now() + Duration::from_secs(60));

    for _ in 0..40 {
        run_one_round(&mut h);
        if h.paths().contains(&"moving/inner/late".to_string()) {
            break;
        }
    }
    assert!(
        h.paths().contains(&"moving/inner/late".to_string()),
        "RFC 5.2 and 17.5: a subtree whose domain changes in place under load still converges"
    );
    let media = domain_stat(&h, MEDIA);
    assert!(
        media.charged > Duration::ZERO,
        "RFC 15.2 and 17.5: a listing under a remounted path is charged to the new domain, {media:?}"
    );
    assert!(media.listings > 0, "RFC 16: the new domain reports the listings it performed, {media:?}");
    assert!(domain_stat(&h, HOME).charged >= home_before, "RFC 15.3: charged worker time is monotone per domain");
}

#[test]
fn cancellation_between_chunks_with_a_domain_change_commits_nothing_and_relists_under_the_new_domain() {
    let fs = wide(8);
    fs.set_domain("", HOME);
    fs.set_chunk_size(1);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    fs.set_cost(CostScope::path("aaa"), FakeOp::ReadDir, Duration::from_secs(5));
    let config = Config { entries_per_lease: 2, ..follow() };
    let mut h = Harness::open_with_host(fs.clone(), Arc::new(LoadAll), one_worker(), config).expect("open");
    assert!(h.advance_to_next_completion(), "the root listing never ran");
    let big = h.pending_job_for("aaa").expect("the wide listing started");
    assert!(h.advance_to_next_completion(), "the first lease never returned");
    assert_eq!(h.stats().suspended_sessions, 1, "the first lease did not leave the session suspended");

    let version = h.stats().version;
    let cancelled_before = h.stats().cancelled_sessions;
    let stale_before = h.stats().stale_results;
    fs.remount("aaa", MEDIA);
    h.command(Command::InvalidatePolicy(vec![RelativePath::root()]));

    assert!(
        h.cancelled().contains(&big.id),
        "RFC 10.2: a suspended session whose job ends is cancelled so its handle and buffer are released"
    );
    assert_eq!(h.held_listing_sessions(), 0, "RFC 10.2: no session outlives its job");
    assert!(
        h.stats().cancelled_sessions + h.stats().stale_results > cancelled_before + stale_before,
        "RFC 10.2 and 11.4: the interrupted session ended without carrying children"
    );
    assert_eq!(h.stats().version, version, "RFC 10.2: only a Complete outcome carries children, so nothing commits");
    assert!(!h.paths().contains(&"aaa/f0".to_string()), "RFC 11.5: a cancelled session commits nothing");

    for _ in 0..60 {
        run_one_round(&mut h);
        if h.paths().contains(&"aaa/f0".to_string()) {
            break;
        }
    }
    assert!(
        h.paths().contains(&"aaa/f0".to_string()),
        "RFC 5.2 and 17.5: the cancelled listing is scheduled again and converges"
    );
    let media = domain_stat(&h, MEDIA);
    assert!(
        media.charged > Duration::ZERO && media.listings > 0,
        "RFC 14.3 and 15.2: the relisting is charged to the domain the subtree now belongs to, {media:?}"
    );
}

#[test]
fn an_initial_scan_larger_than_the_budget_takes_longer_and_never_exceeds_the_envelope() {
    let names = numbered("d", 60);
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    for name in &names {
        fs.mkdir(name);
        fs.mkdir(&format!("{name}/inner"));
        fs.create_file(&format!("{name}/inner/f"), 1);
    }
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(200));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");

    let window = MAXIMUM_PERIOD;
    h.run_jobs_until(MonotonicTime::ZERO + window);
    assert!(
        matches!(h.health().initial_scan, InitialScanState::Running { .. }),
        "RFC 11.1 and 17.5: a tree larger than the budget permits takes longer to scan, it does not scan faster; \
         the scan reported {:?} within {window:?}",
        h.health().initial_scan
    );
    let (at, worst) = h.worst_reserved_window(window);
    let budget = envelope(BACKGROUND_DUTY_GLOBAL, BACKGROUND_BURST_GLOBAL, window);
    assert!(
        worst <= budget,
        "RFC 11.1 and 15.3: the initial scan is background work admitted under the same envelope; the {window:?} \
         window ending at {at:?} reserved {worst:?} against a budget of {budget:?}"
    );

    for _ in 0..400 {
        if matches!(h.health().initial_scan, InitialScanState::Complete { .. }) {
            break;
        }
        h.run_jobs_until(h.now() + Duration::from_secs(600));
    }
    assert!(
        matches!(h.health().initial_scan, InitialScanState::Complete { .. }),
        "RFC 5.2: the scan converges once the budget permits, it reported {:?}",
        h.health().initial_scan
    );
    let (at, worst) = h.worst_reserved_window(window);
    assert!(
        worst <= budget,
        "RFC 15.3: the bound holds over every window; the {window:?} window ending at {at:?} reserved {worst:?} \
         against a budget of {budget:?}"
    );
}

#[test]
fn a_governor_denial_changes_no_obligation_cursor_barrier_or_retry_state() {
    let fs = tree(&["a", "b", "flaky"]);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let host = HostConfig {
        foreground_duty: BACKGROUND_DUTY_GLOBAL,
        foreground_burst: BACKGROUND_BURST_GLOBAL,
        domain_foreground_duty: 0.01,
        domain_foreground_burst: Duration::from_millis(250),
        stuck_threshold: Duration::from_secs(3600),
        ..Default::default()
    };
    let mut h = scanned_under(fs.clone(), host, Config::default());
    fs.fail("flaky", FakeOp::ReadDir, FailureMode::Always(FsError::Transient("blip".into())));
    for _ in 0..20 {
        run_one_round(&mut h);
        if h.health().reconciliation.degraded_paths.contains(&path("flaky")) {
            break;
        }
    }
    let degraded = h.health().reconciliation.degraded_paths.clone();
    assert!(degraded.contains(&path("flaky")), "the fixture produced no retry record");

    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_secs(120));
    h.run_jobs_until(h.now() + Duration::from_secs(1200));
    assert!(h.governor().debt > Duration::ZERO, "the fixture left the background bucket solvent");
    let first = h.command(Command::Refresh(vec![path("a")]));
    for _ in 0..200 {
        h.run_jobs_until(h.now() + Duration::from_secs(60));
        if h.result(first).is_some() {
            break;
        }
    }
    assert_eq!(h.result(first), Some(Ok(())), "the fixture's foreground read never completed");
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    assert!(h.governor().debt > Duration::ZERO, "the fixture repaid the background bucket");
    assert!(h.governor().foreground_debt > Duration::ZERO, "the fixture left the foreground bucket solvent");

    let ticket = h.command(Command::Refresh(vec![path("b")]));
    let before = h.stats();
    let denials_before = before.governor.denials;
    let throttled_at = h.now();
    let resume = h.governor().next_admissible.expect("a throttled governor names its resume time");
    let half = throttled_at + (resume.saturating_sub(throttled_at) / 2);
    h.run_jobs_until(half);
    let after = h.stats();

    let admitted: Vec<Admission> = h.admissions().into_iter().filter(|a| a.at > throttled_at).collect();
    assert!(
        admitted.is_empty(),
        "RFC 15.3: no admission may occur while both buckets are in debt, {} were",
        admitted.len()
    );
    assert!(after.governor.denials > denials_before, "RFC 15.3: the fixture recorded no denial to observe");
    assert_eq!(
        (after.baseline_cursor, after.obligations),
        (before.baseline_cursor, before.obligations),
        "RFC 15.3: denial leaves every obligation and the cursor unchanged"
    );
    assert_eq!(after.version, before.version, "RFC 15.3: a denied job performs no I/O and publishes nothing");
    assert_eq!(h.result(ticket), None, "RFC 15.3: a command barrier attached to a denied job remains attached");
    assert_eq!(
        h.health().reconciliation.degraded_paths,
        degraded,
        "RFC 15.3: denial keeps a retry record's phase, reasons and barriers"
    );

    fs.clear_failures();
    for _ in 0..400 {
        h.run_jobs_until(h.now() + Duration::from_secs(600));
        if h.result(ticket).is_some() {
            break;
        }
    }
    assert_eq!(h.result(ticket), Some(Ok(())), "RFC 5.2: the deferred command completes once capacity returns");
}

fn local_nvme() -> DomainCapabilities {
    DomainCapabilities {
        topology: AccessTopology::Local,
        media: MediaHint::SolidState,
        transport: TransportHint::Nvme,
        ..DomainCapabilities::inline()
    }
}

fn remote_network() -> DomainCapabilities {
    DomainCapabilities {
        topology: AccessTopology::Remote,
        transport: TransportHint::Network,
        ..DomainCapabilities::inline()
    }
}

fn warm_media(rounds: usize) -> (Arc<FakeFileSystem>, Harness) {
    let dirs = numbered("media/d", 8);
    let mut all: Vec<String> = vec!["media".into()];
    all.extend(dirs);
    let fs = tree(&borrowed(&all));
    fs.set_domain("media", MEDIA);
    fs.set_capabilities(MEDIA, local_nvme());
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(1));
    let mut h = scanned_under(fs.clone(), stuck_after(Duration::from_secs(3600)), follow());
    for _ in 0..rounds {
        run_one_round(&mut h);
    }
    (fs, h)
}

#[test]
fn a_stuck_worker_keeps_charging_its_domain_and_is_charged_in_full_globally_when_it_returns() {
    let fs = tree(&["fast0", "media", "media/inner"]);
    fs.set_domain("", HOME);
    fs.set_domain("media", MEDIA);
    fs.set_capabilities(MEDIA, remote_network());
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let mut h = scanned_under(fs.clone(), HostConfig::default(), follow());
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_secs(120));
    let slow = dispatched_job_under(&mut h, "media");
    let started = h.now();

    h.run_jobs_until(started + Duration::from_secs(60));
    assert!(
        h.stats().stuck_workers.iter().any(|slot| slot.job() == Some(slow.id)),
        "the slow listing never crossed the stuck threshold"
    );
    let media = domain_stat(&h, MEDIA);
    assert!(
        media.charged >= Duration::from_secs(60),
        "RFC 13.5: a stuck worker continues to accrue worker time against its domain until its call returns; the \
         domain carries {:?}",
        media.charged
    );
    assert!(
        h.governor().debt < Duration::from_secs(1),
        "RFC 15.3: from the moment of declaration the further occupancy is charged to the domain bucket alone and \
         the global overshoot is refunded; the global bucket reports {:?} of debt",
        h.governor().debt
    );

    h.run_jobs_until(started + Duration::from_secs(121));
    assert!(h.charges().iter().any(|charge| charge.job == slow.id), "the slow listing never returned");
    assert!(
        h.governor().debt >= Duration::from_secs(100),
        "RFC 15.3: a worker that returns is charged in full against both buckets; the global bucket reports {:?} of \
         debt after a 120 second occupancy",
        h.governor().debt
    );
    assert!(domain_stat(&h, MEDIA).charged >= Duration::from_secs(120));
}

#[test]
fn held_listing_sessions_never_exceed_the_batch_size() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    for i in 0..6 {
        fs.mkdir(&format!("w{i}"));
        for j in 0..8 {
            fs.create_file(&format!("w{i}/f{j}"), 1);
        }
    }
    fs.set_chunk_size(1);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(200));
    fs.set_cost(CostScope::Everything, FakeOp::Chunk, Duration::from_millis(200));
    let config = Config { batch_size: 2, entries_per_lease: 2, ..Default::default() };
    let mut h = Harness::open_with_host(fs, Arc::new(LoadAll), one_worker(), config).expect("open");
    let mut peak = 0;
    for _ in 0..600 {
        h.run_jobs_until(h.now() + Duration::from_secs(1));
        let held = h.held_listing_sessions();
        peak = peak.max(held);
        assert!(
            held <= 2,
            "RFC 10.2 and 15.7: a suspended session stays a member of its closed batch, so open listing handles \
             never exceed batch_size; {held} sessions were held"
        );
    }
    assert!(peak >= 1, "no session was ever suspended, so the bound was never exercised");
}

#[test]
fn a_window_halves_on_an_error_and_on_a_stuck_worker() {
    let (fs, mut h) = warm_media(4);
    let warm = domain_stat(&h, MEDIA).window;
    assert!(warm >= 2, "the fixture never raised the window above one: {warm}");
    fs.fail("media/d3", FakeOp::ReadDir, FailureMode::Once(FsError::Transient("blip".into())));
    let failing = dispatched_job(&mut h, "media/d3");
    assert!(h.complete_job(failing.id), "the failing listing never ran");
    assert!(
        h.health().reconciliation.degraded_paths.contains(&path("media/d3"))
            || h.health().reconciliation.last_round
                == Some(RoundResult::Degraded { unsatisfied: [path("media/d3")].into_iter().collect() })
            || h.stats().listing_failures > 0,
        "the injected failure was not observed"
    );
    let after_error = domain_stat(&h, MEDIA).window;
    assert!(
        after_error <= warm / 2,
        "RFC 15.5: the window decreases promptly, by at least half, on an error in the recent history; it went from \
         {warm} to {after_error}"
    );

    let (fs, mut h) = warm_media(4);
    let warm = domain_stat(&h, MEDIA).window;
    assert!(warm >= 2, "the fixture never raised the window above one: {warm}");
    fs.set_cost(CostScope::path("media/d3"), FakeOp::ReadDir, Duration::from_secs(36_000));
    let held = dispatched_job(&mut h, "media/d3");
    h.run_jobs_until(h.now() + Duration::from_secs(3601));
    assert!(
        h.stats().stuck_workers.iter().any(|slot| slot.job() == Some(held.id)),
        "the held listing never became stuck"
    );
    let after_stuck = domain_stat(&h, MEDIA).window;
    assert!(
        after_stuck <= warm / 2,
        "RFC 15.5: the window decreases promptly, by at least half, on a worker beyond the stuck threshold; it went \
         from {warm} to {after_stuck}"
    );
}

#[test]
fn every_scheduler_class_reserves_within_one_background_envelope() {
    fn fixture(config: Config) -> (Arc<FakeFileSystem>, Vec<String>, Harness) {
        let names = numbered("d", 6);
        let fs = Arc::new(FakeFileSystem::new(WatcherKind::Recursive));
        for name in &names {
            fs.mkdir(name);
            fs.create_file(&format!("{name}/f"), 1);
        }
        fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(5));
        let h = scanned(fs.clone(), config);
        (fs, names, h)
    }
    let horizon = Duration::from_secs(600);
    let budget = envelope(BACKGROUND_DUTY_GLOBAL, BACKGROUND_BURST_GLOBAL, MAXIMUM_PERIOD);
    let check = |label: &str, h: &Harness, class: Class| {
        let classes: BTreeSet<Class> = h.admissions().iter().map(|a| a.class).collect();
        assert!(classes.contains(&class), "the {label} scenario admitted no {class:?} work: {classes:?}");
        let (at, worst) = h.worst_reserved_window_of(MAXIMUM_PERIOD, Some(WorkOrigin::Background));
        assert!(
            worst <= budget,
            "RFC 15.1 item 3 and 15.3: the {label} scenario reserved {worst:?} of background worker time over the \
             {MAXIMUM_PERIOD:?} window ending at {at:?} against an envelope of {budget:?}"
        );
    };

    let (_, _, mut h) = fixture(Config::default());
    h.run_jobs_until(h.now() + horizon);
    check("baseline only", &h, Class::Baseline);

    let (_, names, mut h) = fixture(Config::default());
    let hints = h.flood_hints_until(&borrowed(&names), HintKind::Modify, h.now() + horizon);
    assert!(hints > 1000, "the watcher storm emitted only {hints} hints");
    check("watcher storm", &h, Class::Watcher);

    let (_, names, mut h) = fixture(Config::default());
    let t = h.command(Command::SetPriority(names.iter().map(|n| path(n)).collect()));
    assert_eq!(h.result(t), Some(Ok(())));
    h.run_jobs_until(h.now() + horizon);
    check("priority storm", &h, Class::Priority);

    let (fs, names, mut h) = fixture(Config { fixed_interval: Some(Duration::from_secs(60)), ..Default::default() });
    fs.fail("d0", FakeOp::ReadDir, FailureMode::Always(FsError::Transient("busy".into())));
    h.flood_hints_until(&borrowed(&names[1..]), HintKind::Modify, h.now() + horizon);
    check("retry storm", &h, Class::Retry);
    let retries = h.admissions().iter().filter(|a| a.entry == path("d0") && a.class == Class::Retry).count();
    assert!(
        retries >= 3,
        "RFC 13.1: retry work receives finite service under a watcher storm that keeps the domain bucket empty; the \
         failing target was admitted through the retry class {retries} times in {horizon:?}"
    );
}

#[test]
fn a_stuck_domain_absorbs_watcher_and_refresh_floods_without_a_replacement_call() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::Recursive));
    for dir in ["fast0", "media", "media/one", "media/two"] {
        fs.mkdir(dir);
        fs.create_file(&format!("{dir}/f"), 1);
    }
    fs.set_domain("", HOME);
    fs.set_domain("media", MEDIA);
    fs.set_capabilities(MEDIA, remote_network());
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let mut h = scanned_under(fs.clone(), HostConfig::default(), follow());
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_secs(36_000));
    let held = dispatched_job_under(&mut h, "media");
    h.run_jobs_until(h.now() + STUCK_THRESHOLD + Duration::from_secs(1));
    assert!(
        h.stats().stuck_workers.iter().any(|slot| slot.job() == Some(held.id)),
        "the media listing never became stuck"
    );

    let reads = |fs: &FakeFileSystem| listings_under(fs, &["media", "media/one", "media/two"]);
    let before = reads(&fs);
    let since = h.admissions().len();
    let hints =
        h.flood_hints_until(&["media", "media/one", "media/two"], HintKind::Modify, h.now() + Duration::from_secs(60));
    assert!(hints > 100, "the storm emitted only {hints} hints");
    let refresh = h.command(Command::Refresh(vec![path("media/one"), path("media/two")]));
    h.run_jobs_until(h.now() + Duration::from_secs(120));

    assert_eq!(
        reads(&fs),
        before,
        "RFC 13.5 and 17.5: no replacement physical call is issued on a quarantined domain, whatever hints or \
         refreshes arrive"
    );
    assert_eq!(admissions_under(&h, "media", since), 0, "the quarantined domain admitted work");
    assert_eq!(domain_stat(&h, MEDIA).in_flight, 1, "RFC 13.5: exactly the one stuck worker is inside the domain");
    assert!(
        h.stats().blocking_slots_held <= HostConfig::default().maximum_in_flight,
        "RFC 15.3: the physical ceiling holds under the flood"
    );
    assert_eq!(
        h.result(refresh),
        None,
        "RFC 15.3: the refresh waits for the quarantine to lift instead of bypassing it"
    );
    assert!(admissions_outside(&h, "media", since) > 0, "the healthy domain stopped receiving work");
}

#[test]
fn rising_listing_latency_never_raises_the_window() {
    let (fs, mut h) = warm_media(4);
    let mut window = domain_stat(&h, MEDIA).window;
    assert!(window >= 2, "the fixture never raised the window above one: {window}");
    let mut cost = Duration::from_millis(1);
    for _ in 0..8 {
        cost *= 3;
        fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, cost);
        run_one_round(&mut h);
        let now = domain_stat(&h, MEDIA).window;
        assert!(
            now <= window,
            "RFC 15.5 and 17.5: rising latency makes the controller retreat and never catch up by adding \
             concurrency; the window went from {window} to {now} at {cost:?} per listing"
        );
        window = now;
    }
    assert_eq!(window, 1, "RFC 15.5: sustained latency growth converges to a window of one");
}

#[test]
fn a_latency_cliff_throttles_a_domain_whatever_its_label_says() {
    let (fs, mut h) = warm_media(4);
    let warm = domain_stat(&h, MEDIA);
    assert!(warm.window >= 2, "the fixture never raised the window above one: {warm:?}");
    assert_eq!(warm.resource, ResourceHealth::Nominal, "{warm:?}");
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_secs(5));
    run_one_round(&mut h);
    let cliff = domain_stat(&h, MEDIA);
    assert_eq!(
        cliff.window, 1,
        "RFC 15.5 and 17.5: a latency jump past a working-set threshold halves the window down to one; {cliff:?}"
    );
    assert!(
        matches!(cliff.resource, ResourceHealth::Throttled { cause: ThrottleCause::DutyBudget, .. })
            && cliff.debt > Duration::ZERO,
        "RFC 15.3 and 15.6: the observed cost puts the domain in debt and reports it throttled; {cliff:?}"
    );
    assert_eq!(cliff.capabilities.topology, AccessTopology::Local, "the label is unchanged and outranked");
}

#[test]
fn a_watch_registration_that_never_returns_is_a_stuck_worker_that_quarantines_its_domain() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    for dir in ["fast", "media"] {
        fs.mkdir(dir);
        fs.create_file(&format!("{dir}/f"), 1);
    }
    fs.set_domain("", HOME);
    fs.set_domain("media", MEDIA);
    fs.set_capabilities(MEDIA, remote_network());
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), follow()).expect("open");
    h.auto_register = false;
    let root = h.pending_job_for("").expect("root listing");
    assert!(h.complete_job(root.id));
    let (fast_request, fast_path, fast_recursive) = h.take_registration("fast").expect("fast registration");
    h.complete_registration(fast_request, &fast_path, fast_recursive);
    let (media_request, media_path, media_recursive) = h.take_registration("media").expect("media registration");
    assert!(
        h.stats()
            .blocking_slots
            .iter()
            .any(|slot| slot.path == path("media") && slot.operation == JobOperation::WatchRegistration),
        "RFC 15.1 item 1 and 15.3: a blocking watch registration occupies a physical worker slot; {:?}",
        h.stats().blocking_slots
    );

    h.run_jobs_until(h.now() + STUCK_THRESHOLD + Duration::from_secs(1));
    assert!(
        h.stats()
            .stuck_workers
            .iter()
            .any(|slot| slot.path == path("media") && slot.operation == JobOperation::WatchRegistration),
        "RFC 13.5: a registration whose call never returns is reported as a stuck worker; {:?}",
        h.stats().stuck_workers
    );
    let media = domain_stat(&h, MEDIA);
    assert_eq!(
        h.health().resource_domains.get(&media.id).copied(),
        Some(ResourceHealth::Throttled { cause: ThrottleCause::StuckWorker, resume: None }),
        "RFC 13.5: the stuck registration quarantines its domain"
    );
    assert!(h.paths().contains(&"fast/f".to_string()), "the healthy domain was not listed: {:?}", h.paths());
    assert!(!h.paths().contains(&"media/f".to_string()), "a listing ran behind a registration that never returned");

    h.auto_register = true;
    h.complete_registration(media_request, &media_path, media_recursive);
    h.run_until_idle();
    assert_eq!(domain_stat(&h, MEDIA).stuck, 0, "RFC 13.5: the quarantine lifts when the stuck call returns");
    assert!(h.paths().contains(&"media/f".to_string()), "the domain never recovered: {:?}", h.paths());
}

#[test]
fn a_standalone_watch_registration_that_never_returns_is_reported_stuck_and_released_on_return() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    fs.mkdir("a");
    fs.create_file("a/f", 1);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let mut h = scanned(fs.clone(), Config::default());
    assert!(fs.watch_count() >= 2, "the tree registered {} watches", fs.watch_count());
    h.auto_register = false;
    h.inject_watcher_event(tree_fucker::fs::WatcherEvent::Failed { message: "backend gone".into(), path: None });
    for _ in 0..20 {
        if !h.pending_registrations().is_empty() {
            break;
        }
        h.advance(Duration::from_secs(5));
    }
    let (request, watch_path, recursive) = h.pending_registrations().into_iter().next().expect("restart registration");
    assert!(
        h.stats()
            .blocking_slots
            .iter()
            .any(|slot| slot.path == watch_path && slot.operation == JobOperation::WatchRegistration),
        "RFC 15.3: a standalone registration occupies a physical slot; {:?}",
        h.stats().blocking_slots
    );
    h.run_jobs_until(h.now() + STUCK_THRESHOLD + Duration::from_secs(1));
    assert!(
        h.stats()
            .stuck_workers
            .iter()
            .any(|slot| slot.path == watch_path && slot.operation == JobOperation::WatchRegistration),
        "RFC 13.5: a standalone registration past the stuck threshold is reported with its path and operation; {:?}",
        h.stats().stuck_workers
    );
    assert!(
        h.health().resource_domains.values().any(|health| health.cause() == Some(ThrottleCause::StuckWorker)),
        "RFC 13.5: the stuck registration quarantines its domain; {:?}",
        h.health().resource_domains
    );
    h.take_registration(watch_path.to_string().as_str());
    h.auto_register = true;
    h.complete_registration(request, &watch_path, recursive);
    h.run_until_idle();
    assert!(h.stats().stuck_workers.is_empty(), "RFC 13.5: the returned registration is no longer stuck");
    assert!(
        !h.stats().blocking_slots.iter().any(|slot| slot.operation == JobOperation::WatchRegistration),
        "the returned registration released its slot; {:?}",
        h.stats().blocking_slots
    );
}

fn release_charge(h: &Harness) -> Duration {
    h.stats().grants.iter().filter(|grant| grant.id.release().is_some()).map(|grant| grant.charged).sum()
}

fn two_domain_watched_tree() -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    for dir in ["fast", "media"] {
        fs.mkdir(dir);
        fs.create_file(&format!("{dir}/f"), 1);
    }
    fs.set_domain("", HOME);
    fs.set_domain("media", MEDIA);
    fs.set_capabilities(MEDIA, remote_network());
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    fs
}

#[test]
fn an_unwatch_that_never_returns_is_a_stuck_worker_that_quarantines_its_domain() {
    let fs = two_domain_watched_tree();
    let mut h = scanned(fs.clone(), follow());
    assert!(h.stats().paths_watched > 0, "the tree registered no watch, so no removal can be exercised");
    h.auto_release = false;

    h.command(Command::Unload(path("media")));
    h.run_until_idle();
    let held = h
        .stats()
        .blocking_slots
        .into_iter()
        .find(|slot| slot.operation == JobOperation::WatchRelease)
        .expect("RFC 15.1 item 1: a watch removal is a governed physical operation and occupies a worker slot");
    assert_eq!(held.path, path("media"), "the removal reports the path whose watch it drops");
    let estimate = release_charge(&h);

    h.run_jobs_until(h.now() + STUCK_THRESHOLD + Duration::from_secs(1));
    assert!(
        h.stats().stuck_workers.iter().any(|slot| slot.operation == JobOperation::WatchRelease),
        "RFC 13.5: a removal whose call never returns is reported as a stuck worker; {:?}",
        h.stats().stuck_workers
    );
    let media = domain_stat(&h, MEDIA);
    assert_eq!(
        media.in_flight, 1,
        "RFC 13.5: the stuck removal keeps its in-flight slot; the domain reports {media:?}"
    );
    assert_eq!(
        h.health().resource_domains.get(&media.id).copied(),
        Some(ResourceHealth::Throttled { cause: ThrottleCause::StuckWorker, resume: None }),
        "RFC 13.5: one stuck worker quarantines its storage domain"
    );
    let hung = release_charge(&h);
    assert!(
        hung > estimate && hung >= STUCK_THRESHOLD,
        "RFC 15.2: an operation that has not completed is charged its occupancy so far; it went from {estimate:?} to \
         {hung:?}"
    );

    h.auto_release = true;
    h.complete_releases();
    h.run_until_idle();
    assert!(h.stats().stuck_workers.is_empty(), "RFC 13.5: the returned removal is no longer stuck");
    assert_eq!(domain_stat(&h, MEDIA).stuck, 0, "RFC 13.5: the quarantine lifts when the stuck call returns");
    assert!(
        !h.stats().blocking_slots.iter().any(|slot| slot.operation == JobOperation::WatchRelease),
        "the returned removal released its slot; {:?}",
        h.stats().blocking_slots
    );
}

#[test]
fn a_watch_removal_is_admitted_with_an_empty_domain_bucket() {
    let fs = two_domain_watched_tree();
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ReadDir, Duration::from_secs(10));
    let mut h = scanned(fs.clone(), follow());
    let drained = domain_stat(&h, MEDIA);
    assert!(
        drained.level.is_zero() && drained.debt > Duration::ZERO,
        "the media bucket was never emptied, so the removal is not tested against an empty bucket; {drained:?}"
    );
    assert!(
        matches!(drained.resource, ResourceHealth::Throttled { cause: ThrottleCause::DutyBudget, .. }),
        "an ordinary read on this domain would be denied; the domain reports {:?}",
        drained.resource
    );

    let before = h.governor().watch_release_grants;
    h.command(Command::Unload(path("media")));
    assert!(
        h.governor().watch_release_grants > before,
        "RFC 15.1 item 1: a removal releases resources and is admitted with an empty domain bucket; grants stayed at \
         {before}"
    );
    assert!(
        h.stats().blocking_slots.iter().any(|slot| slot.operation == JobOperation::WatchRelease),
        "the admitted removal holds a physical slot; {:?}",
        h.stats().blocking_slots
    );
    h.complete_releases();
    assert!(!h.unwatched().is_empty(), "the removal never reached the adapter");
}

#[test]
fn a_removal_on_a_healthy_domain_never_waits_behind_a_quarantined_one() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    for dir in ["fast", "media", "media/inner"] {
        fs.mkdir(dir);
        fs.create_file(&format!("{dir}/f"), 1);
    }
    fs.set_domain("", HOME);
    fs.set_domain("media", MEDIA);
    fs.set_capabilities(MEDIA, remote_network());
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    fs.set_cost(CostScope::path("media/inner"), FakeOp::ReadDir, Duration::from_secs(36_000));
    let mut h = scanned(fs.clone(), follow());
    let held = domain_stat(&h, MEDIA);
    assert_eq!(
        h.health().resource_domains.get(&held.id).copied(),
        Some(ResourceHealth::Throttled { cause: ThrottleCause::StuckWorker, resume: None }),
        "the media domain was never quarantined, so nothing blocks the removal queued on it"
    );
    let stuck = h.pending_job_for("media/inner").expect("the hung listing is still outstanding");
    h.auto_release = false;

    h.command(Command::Unload(path("media")));
    h.command(Command::Unload(path("fast")));
    let releasing: Vec<RelativePath> = h
        .stats()
        .blocking_slots
        .into_iter()
        .filter(|slot| slot.operation == JobOperation::WatchRelease)
        .map(|slot| slot.path)
        .collect();
    assert_eq!(
        releasing,
        vec![path("fast")],
        "RFC 13.5: a quarantined domain holds back only its own removals; the tree is releasing {releasing:?}"
    );
    assert_eq!(h.pending_releases().len(), 1, "the healthy domain's removal reached the adapter alone");

    assert!(h.complete_job(stuck.id), "the hung listing never returned");
    h.run_until_idle();
    assert!(
        h.stats().blocking_slots.iter().any(|slot| slot.operation == JobOperation::WatchRelease),
        "RFC 13.5: the removals queued on the domain start once the quarantine lifts; {:?}",
        h.stats().blocking_slots
    );
    h.auto_release = true;
    h.complete_releases();
    assert!(h.pending_releases().is_empty() && !h.unwatched().is_empty(), "every queued removal reached the adapter");
}

#[test]
fn a_watch_removal_waits_for_the_in_flight_ceiling() {
    let fs = two_domain_watched_tree();
    let mut h = scanned_under(fs.clone(), one_worker(), follow());
    h.command(Command::Refresh(vec![path("fast")]));
    let listing = h.pending_job_for("fast").expect("the refresh dispatched a listing");
    assert_eq!(h.governor().in_flight, 1, "the one physical slot of the host is occupied");

    let occupied = h.governor().watch_release_grants;
    h.command(Command::Unload(path("media")));
    assert!(
        !h.stats().blocking_slots.iter().any(|slot| slot.operation == JobOperation::WatchRelease),
        "RFC 15.3: a removal never bypasses the process-wide in-flight ceiling; {:?}",
        h.stats().blocking_slots
    );
    assert_eq!(
        h.governor().watch_release_grants,
        occupied,
        "RFC 15.3: the removal waited for a free physical slot rather than taking one"
    );

    assert!(h.complete_job(listing.id), "the held listing never completed");
    assert!(
        h.governor().watch_release_grants > occupied,
        "RFC 15.3: the removal is admitted once the ceiling has a free slot"
    );
    h.complete_releases();
    assert!(!h.unwatched().is_empty(), "the removal never reached the adapter");
}

#[test]
fn shutdown_keeps_reporting_a_hung_unwatch_until_it_returns() {
    let fs = two_domain_watched_tree();
    let mut h = scanned(fs.clone(), follow());
    assert!(h.stats().paths_watched > 0, "the tree registered no watch, so no removal can be exercised");
    h.auto_release = false;

    h.command(Command::Shutdown);
    assert!(h.stopped(), "the tree accepted the shutdown");
    assert!(!h.pending_releases().is_empty(), "RFC 9: shutdown removes the watches it holds");

    h.run_jobs_until(h.now() + STUCK_THRESHOLD + Duration::from_secs(1));
    let stuck = h.stats().stuck_workers;
    assert!(
        stuck.iter().any(|slot| slot.operation == JobOperation::WatchRelease),
        "RFC 9 and 13.5: a shut-down tree keeps reporting a removal whose call has not returned; {stuck:?}"
    );

    h.auto_release = true;
    h.complete_releases();
    assert!(h.stats().stuck_workers.is_empty(), "RFC 13.5: the returned removal is no longer reported stuck");
    assert!(
        h.stats().blocking_slots.is_empty(),
        "the returned removal released its slot; {:?}",
        h.stats().blocking_slots
    );
}

#[test]
fn registration_latency_is_recorded_apart_from_the_listing_it_precedes() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    fs.mkdir("a");
    fs.create_file("a/f", 1);
    fs.set_cost(CostScope::Everything, FakeOp::Watch, Duration::from_secs(5));
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let host = HostConfig {
        background_duty: 1.0,
        background_burst: Duration::from_secs(60),
        domain_background_duty: 1.0,
        domain_background_burst: Duration::from_secs(60),
        ..Default::default()
    };
    let mut h = Harness::open_with_host(fs.clone(), Arc::new(LoadAll), host, Config::default()).expect("open");
    h.run_jobs_until(h.now() + Duration::from_secs(120));
    assert!(h.paths().contains(&"a/f".to_string()), "the scan never completed: {:?}", h.paths());
    assert!(fs.count_ops(FakeOp::Watch, "a") >= 1, "no registration ran");
    let stat = h.stats().domains.into_iter().next().expect("the tree entered no domain");
    assert_eq!(
        stat.registration_latency.minimum,
        Duration::from_secs(5),
        "RFC 16: the registration call is recorded in its own latency window; {stat:?}"
    );
    assert!(stat.registration_latency.samples >= 2, "{stat:?}");
    assert_eq!(
        stat.listing_latency.minimum,
        Duration::from_millis(10),
        "RFC 15.2 and 16: the listing latency sample covers the listing call only; {stat:?}"
    );
    assert_eq!(stat.listing_latency.tail, Duration::from_millis(10), "{stat:?}");
    assert!(
        stat.charged >= Duration::from_secs(10),
        "RFC 15.2: occupancy still covers the registration and the listing under one grant; {stat:?}"
    );
}

#[test]
fn a_listing_lost_between_leases_restarts_from_a_fresh_enumeration() {
    let fs = tree(&["wide"]);
    for i in 0..6 {
        fs.create_file(&format!("wide/f{i}"), 1);
    }
    let config =
        Config { entries_per_lease: 2, fixed_interval: Some(Duration::from_secs(86_400)), ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    fs.add_silently("wide/late", EntryKind::File);
    let t = h.command(Command::Refresh(vec![path("wide")]));
    let first = h.pending_job_for("wide").expect("the refresh listing started");
    assert!(h.complete_job(first.id), "the first lease never ran");
    let resumed = h.pending_job_for("wide").expect("the suspended session never resumed");
    let reads = fs.count_ops(FakeOp::ReadDir, "wide");
    assert!(h.lose_job(resumed.id));
    assert_eq!(h.held_listing_sessions(), 0, "RFC 10.2: a lost session leaves no handle behind");

    for _ in 0..600 {
        if h.result(t).is_some() {
            break;
        }
        h.run_jobs_until(h.now() + Duration::from_secs(1));
    }
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(
        fs.count_ops(FakeOp::ReadDir, "wide"),
        reads + 1,
        "RFC 10.2: the retry opens a fresh enumeration instead of trusting a remembered offset"
    );
    let mut children: Vec<String> = h.paths().into_iter().filter(|p| p.starts_with("wide/")).collect();
    let total = children.len();
    children.dedup();
    assert_eq!(children.len(), total, "an entry was published twice");
    assert_eq!(total, 8, "every entry of the restarted enumeration was published exactly once: {children:?}");
}

#[test]
fn a_session_suspended_between_leases_accrues_no_occupancy_while_it_waits() {
    let fs = wide(8);
    fs.set_chunk_size(1);
    fs.set_cost(CostScope::path("aaa"), FakeOp::ReadDir, Duration::from_secs(5));
    let host = HostConfig {
        maximum_in_flight: 1,
        per_domain_concurrency: 1,
        domain_background_duty: 0.001,
        background_duty: 0.001,
        ..Default::default()
    };
    let config = Config { entries_per_lease: 2, ..Default::default() };
    let mut h = Harness::open_with_host(fs.clone(), Arc::new(LoadAll), host, config).expect("open");
    assert!(h.advance_to_next_completion(), "the root listing never ran");
    let big = h.pending_job_for("aaa").expect("the wide listing started");
    assert!(h.advance_to_next_completion(), "the first lease never returned");
    assert_eq!(h.stats().suspended_sessions, 1, "the first lease did not leave the session suspended");

    for minute in 1..=10 {
        h.run_jobs_until(h.now() + Duration::from_secs(60));
        let stats = h.stats();
        assert_eq!(stats.suspended_sessions, 1, "minute {minute}: the session was resumed before its lease refilled");
        assert_eq!(
            stats.governor.running_occupancy,
            Duration::ZERO,
            "RFC 10.2 and 17.5: a session waiting for its next lease holds no worker; minute {minute} reports {:?}",
            stats.governor.running_occupancy
        );
        assert!(
            !stats.blocking_slots.iter().any(|slot| slot.job() == Some(big.id)),
            "minute {minute}: the suspended session holds a blocking slot"
        );
        assert_eq!(stats.governor.in_flight, 0, "minute {minute}: {}", stats.governor.in_flight);
    }
    assert_eq!(h.held_listing_sessions(), 1, "RFC 10.2: the session keeps its handle and buffer while it waits");
}

#[test]
fn an_effectively_infinite_directory_stops_at_the_ceiling_plus_one_chunk_without_materialising_the_rest() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("huge");
    fs.set_synthetic_children("huge", 10_000_000);
    fs.set_chunk_size(16);
    let mut session = fs.open_listing(fs.root(), &path("huge"), Ceilings::entries(100), CancellationToken::new());
    let mut total_bytes = 0;
    let mut enumerated = 0;
    let outcome = loop {
        let (continuation, cost) = session.resume(Lease { entries: 64, operations: 64 });
        total_bytes = total_bytes.max(cost.bytes);
        enumerated += cost.entries_enumerated;
        match continuation {
            Continuation::Suspended(next) => session = next,
            Continuation::Finished(outcome) => break outcome,
        }
    };
    let SessionOutcome::ResourceLimited(limited) = outcome else {
        panic!("RFC 10.2: a directory over the ceiling ends ResourceLimited, not {outcome:?}");
    };
    assert!(limited.observed <= 116, "RFC 10.2: at most the ceiling plus one chunk is observed; {limited:?}");
    assert!(enumerated <= 116, "{enumerated} entries were enumerated");
    let widest = entry_bytes(std::ffi::OsStr::new("f9999999"));
    assert!(
        total_bytes <= 116 * widest,
        "RFC 10.2 and 17.5: memory never scales with the hidden remainder; the session held {total_bytes} bytes"
    );

    let config = Config { entries_per_directory: 100, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    assert_eq!(h.paths(), [".", "huge"], "RFC 10.2 and 20: a directory over its limit publishes nothing");
    let event = h.stats().resource_limits.into_iter().find(|e| e.path == path("huge")).expect("resource-limit event");
    assert!(event.limited.observed <= 116, "{event:?}");
    assert!(h.stats().snapshot_bytes < 116 * widest, "the snapshot never grew with the hidden remainder");
}

#[test]
fn per_domain_statistics_split_listing_and_metadata_latency_and_report_rates() {
    let fs = tree(&["fast0"]);
    fs.set_domain("", HOME);
    fs.set_default_capabilities(DomainCapabilities {
        kind_source: KindSource::Sometimes,
        ..DomainCapabilities::inline()
    });
    fs.report_unknown_kind("fast0/f");
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    fs.set_cost(CostScope::Everything, FakeOp::Metadata, Duration::from_millis(5));
    let mut h = scanned(fs.clone(), Config::default());
    let t = h.command(Command::Refresh(vec![path("fast0/f")]));
    h.run_jobs_until(h.now() + Duration::from_secs(60));
    assert_eq!(h.result(t), Some(Ok(())));

    let stat = domain_stat(&h, HOME);
    assert!(stat.listing_latency.samples > 0, "listing latency is missing: {stat:?}");
    assert!(stat.metadata_latency.samples > 0, "metadata latency is missing after a metadata read: {stat:?}");
    assert_eq!(stat.listing_latency.minimum, Duration::from_millis(10), "listing latency carries listings: {stat:?}");
    assert_eq!(
        stat.metadata_latency.minimum,
        Duration::from_millis(5),
        "metadata latency carries metadata reads and nothing else: {stat:?}"
    );
    assert!(stat.entries_per_second > 0.0, "entries per second is missing: {stat:?}");
    assert!(stat.per_child_lookups > 0, "per-child lookups are missing after an unknown kind: {stat:?}");
    assert!(stat.per_child_lookups_per_second > 0.0, "per-child lookup rate is missing: {stat:?}");
}

fn smb_media() -> DomainCapabilities {
    DomainCapabilities {
        semantics: FilesystemSemantics::Smb,
        topology: AccessTopology::Remote,
        transport: TransportHint::Network,
        filesystem: FilesystemInstance::Known(tree_fucker::FilesystemInstanceKey::declared(42)),
        kind_source: KindSource::Sometimes,
        identity_source: IdentitySource::PerChildRead,
        metadata_sources: MetadataSources { size: MetadataSource::PerChildRead, ..MetadataSources::INLINE },
        ..DomainCapabilities::inline()
    }
}

#[test]
fn production_observability_locates_a_stuck_smb_domain_from_the_public_api() {
    let fs = tree(&["local", "media", "media/inner", "media/stuck"]);
    fs.create_file("local/f", 1);
    fs.create_file("media/inner/f", 1);
    fs.set_domain("", HOME);
    fs.set_domain("media", MEDIA);
    fs.set_capabilities(MEDIA, smb_media());
    fs.report_unknown_kind("media/inner/f");
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    fs.set_cost(CostScope::path("media/stuck"), FakeOp::ReadDir, Duration::from_secs(36_000));
    let mut h = scanned(fs.clone(), follow());
    h.run_jobs_until(h.now() + Duration::from_secs(600));

    let media = domain_stat(&h, MEDIA);
    assert_eq!(
        media.path,
        Some(path("media")),
        "RFC 16 and line 1027: a domain is observable at the path it was entered; the stat reports {:?}",
        media.path
    );
    assert_eq!(media.capabilities.semantics, FilesystemSemantics::Smb, "line 1027: the domain names itself SMB");
    assert!(
        matches!(media.capabilities.filesystem, FilesystemInstance::Known(_)),
        "line 1008: the filesystem instance"
    );
    assert_eq!(media.capabilities.transport, TransportHint::Network, "line 1009: the transport hint is observable");
    assert_eq!(
        media.resource,
        ResourceHealth::Throttled { cause: ThrottleCause::StuckWorker, resume: None },
        "line 1028: the domain is quarantined and its resume is a wait for state change, not a timestamp"
    );
    assert!(media.stuck >= 1 && media.in_flight >= 1, "line 1029: the stuck physical read is counted, not hidden");
    assert!(
        media.last_listing_children == Some(1),
        "line 1029: the last completed listing size is observable per domain; media reports {:?}",
        media.last_listing_children
    );
    assert!(
        media.kind_resolutions >= 1 || media.per_child_lookups >= 1,
        "line 1016: per-child type/identity lookups are observable per domain; media reports {media:?}"
    );

    let slot = h
        .stats()
        .stuck_workers
        .into_iter()
        .find(|slot| slot.path == path("media/stuck"))
        .expect("line 1028: the stuck worker is reported with its path and start time");
    let age = h.stats().observed_at.since(slot.started);
    assert!(
        age >= STUCK_THRESHOLD,
        "line 1012 and 1028: stuck-worker age is computable from the observation time and the start time; age {age:?}"
    );
    assert!(
        !matches!(domain_stat(&h, HOME).resource, ResourceHealth::Throttled { cause: ThrottleCause::StuckWorker, .. }),
        "line 1031: the local workspace domain is never quarantined by the SMB domain's stuck worker; it reports {:?}",
        domain_stat(&h, HOME).resource
    );
    assert!(
        h.paths().contains(&"local/f".to_string()),
        "line 1031: local workspace reconciliation remains active while the SMB domain is stuck"
    );
    assert!(h.stats().listing_operations > 0, "line 1015: tree-level listing operations are observable");
}

#[test]
fn a_degraded_directory_names_its_cause_through_health() {
    let fs = tree(&["denied", "denied/inner"]);
    fs.create_file("denied/inner/f", 1);
    let mut h = scanned(fs.clone(), Config::default());
    fs.fail("denied", FakeOp::ReadDir, FailureMode::Always(FsError::PermissionDenied));
    for _ in 0..6 {
        h.run_round();
        h.run_until_idle();
    }

    let causes = h.health().reconciliation.degraded_path_causes;
    assert_eq!(
        causes.get(&path("denied")),
        Some(&DegradedCause::PermissionDenied),
        "RFC 13.1 and 15.6 and line 1022: a degraded path names its cause, distinguishing lack of permission from \
         absence; the tree reports {causes:?}"
    );
    assert!(
        h.snapshot().get(&path("denied")).is_some(),
        "line 1022: a permission-denied directory is degraded, not removed as absent",
    );
}

#[test]
fn suspended_sessions_are_counted_per_domain() {
    let fs = wide(8);
    fs.set_chunk_size(1);
    fs.set_domain("", HOME);
    fs.set_domain("aaa", MEDIA);
    fs.set_cost(CostScope::path("aaa"), FakeOp::ReadDir, Duration::from_secs(5));
    let config = Config { entries_per_lease: 2, ..follow() };
    let mut h = Harness::open_with_host(fs.clone(), Arc::new(LoadAll), one_worker(), config).expect("open");
    for _ in 0..8 {
        if h.stats().suspended_sessions > 0 {
            break;
        }
        assert!(h.advance_to_next_completion(), "no completion was scheduled before a session suspended");
    }
    assert_eq!(h.stats().suspended_sessions, 1, "the wide listing never suspended, so nothing is counted");
    assert_eq!(
        domain_stat(&h, MEDIA).suspended_sessions,
        1,
        "line 1017: a suspended session is counted against the domain of its job"
    );
    assert_eq!(
        domain_stat(&h, HOME).suspended_sessions,
        0,
        "line 1017: a domain with no suspended session reports none"
    );
}
