use std::sync::Arc;
use std::time::Duration;

use tree_fucker::core::{Command, MonotonicTime, WorkOrigin};
use tree_fucker::testing::{Admission, CostScope, FakeFileSystem, FakeOp, Harness};
use tree_fucker::update::{ResourceHealth, ResourceLimit, ThrottleCause};
use tree_fucker::{
    Config, EntryKind, Error, HostGovernor, HostGovernorError, LoadAll, RelativePath, Tree, WatcherKind, entry_bytes,
};

const BACKGROUND_DUTY_GLOBAL: f64 = 0.02;
const BACKGROUND_BURST_GLOBAL: Duration = Duration::from_millis(500);
const INITIAL_COST_ESTIMATE: Duration = Duration::from_millis(20);

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

fn costed(dirs: &[&str]) -> Arc<FakeFileSystem> {
    let fs = tree(dirs);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, INITIAL_COST_ESTIMATE);
    fs
}

fn envelope(duty: f64, burst: Duration, window: Duration) -> Duration {
    Duration::from_secs_f64(window.as_secs_f64() * duty) + burst
}

fn scanned(fs: Arc<FakeFileSystem>, config: Config) -> Harness {
    let mut h = Harness::open(fs, Arc::new(LoadAll), config).expect("open");
    h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(120));
    h
}

fn foreground(config: Config) -> Config {
    Config {
        fixed_interval: Some(Duration::from_secs(86_400)),
        foreground_duty: 0.05,
        foreground_burst: Duration::from_millis(200),
        domain_foreground_duty: 0.05,
        domain_foreground_burst: Duration::from_millis(200),
        ..config
    }
}

#[test]
fn a_refresh_storm_stays_within_the_foreground_envelope_and_never_touches_the_background_bucket() {
    let fs = tree(&["a", "b", "c"]);
    let mut h = scanned(fs.clone(), foreground(Config::default()));
    let start = h.now();
    for _ in 0..200 {
        h.command(Command::Refresh(vec![path("a"), path("b"), path("c")]));
        let next = h.now() + Duration::from_secs(1);
        h.run_jobs_until(next);
    }
    let window = Duration::from_secs(300);
    let (at, worst) = h.worst_reserved_window_of(window, Some(WorkOrigin::Foreground));
    let budget = envelope(0.05, Duration::from_millis(200), window);
    assert!(
        worst > Duration::ZERO,
        "RFC 15.4: a refresh storm must draw on the foreground buckets, and this one reserved nothing"
    );
    assert!(
        worst <= budget,
        "RFC 15.1 item 4 and 15.4: the foreground allowance has hard ceilings on rate and burst; the {window:?} \
         window ending at {at:?} reserved {worst:?} against a budget of {budget:?}"
    );
    assert!(h.admissions().iter().any(|a| a.origin == WorkOrigin::Foreground), "the storm admitted foreground work");
    let background: Vec<Admission> =
        h.admissions().into_iter().filter(|a| a.at > start && a.origin == WorkOrigin::Background).collect();
    assert!(
        background.is_empty(),
        "RFC 15.1 item 4: foreground and background allowances must not transfer capacity, yet the storm admitted \
         {} background operations",
        background.len()
    );
}

#[test]
fn a_command_past_its_foreground_ceiling_fails_with_resource_limited_rather_than_admitting_more() {
    let fs = tree(&["a", "b"]);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(500));
    let config = Config {
        max_in_flight: 1,
        per_domain_concurrency: 1,
        foreground_ceiling_per_command: Duration::from_millis(300),
        foreground_duty: 1.0,
        foreground_burst: Duration::from_secs(30),
        domain_foreground_duty: 1.0,
        domain_foreground_burst: Duration::from_secs(30),
        ..foreground(Config::default())
    };
    let mut h = scanned(fs.clone(), config);
    let ticket = h.command(Command::Refresh(vec![path("a"), path("b")]));
    for _ in 0..200 {
        if h.result(ticket).is_some() {
            break;
        }
        let next = h.now() + Duration::from_secs(1);
        h.run_jobs_until(next);
    }
    let Some(Err(Error::ResourceLimited(limited))) = h.result(ticket) else {
        panic!(
            "RFC 15.4 and 13.1: a command past its worker-time ceiling fails with ResourceLimited, not {:?}",
            h.result(ticket)
        );
    };
    assert_eq!(limited.limit, ResourceLimit::CommandWorkerTime);
    assert_eq!(limited.configured, u64::try_from(Duration::from_millis(300).as_nanos()).expect("nanos"));
    assert!(
        limited.observed >= limited.configured,
        "RFC 13.1: the structured outcome names the observed value against the configured limit, {limited:?}"
    );
    let after: Vec<Admission> =
        h.admissions().into_iter().filter(|a| a.origin == WorkOrigin::Foreground && a.at > h.now()).collect();
    assert!(after.is_empty(), "RFC 15.4: no further operation for the command is admitted once its ceiling is reached");
}

#[test]
fn a_foreground_read_still_counts_in_the_shared_physical_ceilings() {
    let fs = tree(&["a", "b", "c"]);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(50));
    let config = Config {
        max_in_flight: 1,
        per_domain_concurrency: 1,
        foreground_duty: 1.0,
        foreground_burst: Duration::from_secs(30),
        domain_foreground_duty: 1.0,
        domain_foreground_burst: Duration::from_secs(30),
        ..foreground(Config::default())
    };
    let mut h = scanned(fs.clone(), config);
    h.command(Command::Refresh(vec![path("a"), path("b"), path("c")]));
    let mut peak = 0;
    for _ in 0..40 {
        peak = peak.max(h.stats().blocking_slots_held);
        assert!(
            h.stats().governor.in_flight <= 1,
            "RFC 15.4: a foreground read still needs a free slot in the global in-flight limit"
        );
        let next = h.now() + Duration::from_millis(25);
        h.run_jobs_until(next);
    }
    assert!(peak > 0, "the refresh dispatched no read");
    assert!(peak <= 1, "RFC 15.4: a foreground read still needs a free slot in its domain window, peak was {peak}");
}

#[test]
fn two_trees_under_one_host_governor_share_its_envelope_and_two_governors_do_not() {
    let window = Duration::from_secs(300);
    let budget = envelope(BACKGROUND_DUTY_GLOBAL, BACKGROUND_BURST_GLOBAL, window);
    let config = Config::default();
    let shared = HostGovernor::independent(&config);
    let mut one =
        Harness::open_under(costed(&["a", "b", "c"]), Arc::new(LoadAll), config.clone(), shared.clone()).expect("open");
    let mut two =
        Harness::open_under(costed(&["d", "e", "f"]), Arc::new(LoadAll), config.clone(), shared.clone()).expect("open");
    let mut alone_one = Harness::open(costed(&["a", "b", "c"]), Arc::new(LoadAll), config.clone()).expect("open");
    let mut alone_two = Harness::open(costed(&["d", "e", "f"]), Arc::new(LoadAll), config.clone()).expect("open");
    let horizon = MonotonicTime::ZERO + window;
    for step in 1..=60 {
        let target = MonotonicTime::ZERO + Duration::from_secs(5 * step);
        one.run_jobs_until(target);
        two.run_jobs_until(target);
        alone_one.run_jobs_until(target);
        alone_two.run_jobs_until(target);
    }
    let together =
        one.reserved_between(MonotonicTime::ZERO, horizon) + two.reserved_between(MonotonicTime::ZERO, horizon);
    let apart = alone_one.reserved_between(MonotonicTime::ZERO, horizon)
        + alone_two.reserved_between(MonotonicTime::ZERO, horizon);
    assert!(
        together <= budget,
        "RFC 15.9: every tree opened under one host governor shares one global background bucket; the pair reserved \
         {together:?} against a budget of {budget:?}"
    );
    assert!(
        apart > budget,
        "RFC 15.9: two independently governed trees are outside that bound, and these reserved {apart:?} against \
         {budget:?}"
    );
    assert!(
        together < apart,
        "RFC 15.9: a consumer cannot multiply the envelope by opening more trees; shared {together:?}, apart {apart:?}"
    );
}

#[test]
fn memory_pressure_reports_throttled_memory_with_no_resume_time() {
    let fs = tree(&["a", "b", "c"]);
    let leased = Config { entries_per_lease: 8, ..Default::default() };
    let probe = scanned(fs.clone(), leased.clone());
    let ceiling = probe.stats().snapshot_bytes + 1500;
    let mut h = scanned(fs.clone(), Config { accounted_memory_ceiling: ceiling, ..leased });
    assert!(h.paths().contains(&"a/f".to_string()), "the scan completes under the memory ceiling");
    for i in 0..100 {
        fs.add_silently(&format!("a/w{i}"), EntryKind::File);
    }
    for _ in 0..200 {
        if h.health().resource.cause() == Some(ThrottleCause::Memory) {
            break;
        }
        let next = h.now() + Duration::from_secs(1);
        h.run_jobs_until(next);
    }
    assert!(
        h.stats().governor.accounted_memory > ceiling,
        "the suspended session holds enough in-flight listing bytes to pass the ceiling, {} against {ceiling}",
        h.stats().governor.accounted_memory
    );
    assert_eq!(
        h.health().resource,
        ResourceHealth::Throttled { cause: ThrottleCause::Memory, resume: None },
        "RFC 15.6: memory is a throttle cause with no computable resume time"
    );
    let before = h.now();
    h.run_jobs_until(before + Duration::from_secs(600));
    assert_eq!(
        h.health().resource,
        ResourceHealth::Throttled { cause: ThrottleCause::Memory, resume: None },
        "RFC 15.6: a memory throttle does not resume on a timer"
    );
    assert!(
        !h.health().reconciliation.degraded_paths.contains(&path("a")),
        "RFC 15.1 item 5: the throttled path itself is never reported as reconciliation degradation"
    );
}

#[test]
fn a_listing_over_the_snapshot_byte_ceiling_is_rejected_in_full_and_reports_the_structured_event() {
    let fs = tree(&["big"]);
    let probe = scanned(fs.clone(), Config::default());
    let ceiling = probe.stats().snapshot_bytes;
    let mut h = scanned(fs.clone(), Config { snapshot_bytes: ceiling, ..Default::default() });
    let before = h.stats().version;
    let paths = h.paths();
    fs.add_silently("big/extra", EntryKind::File);
    h.run_round();
    assert_eq!(h.stats().version, before, "RFC 15.6: a listing over a byte ceiling retains the previous snapshot");
    assert_eq!(h.paths(), paths, "RFC 15.6 and 20: a rejected listing publishes nothing");
    assert!(
        h.health().reconciliation.degraded_paths.contains(&path("big")),
        "RFC 15.6: the path is reported degraded with a resource-limit cause"
    );
    let events = h.stats().resource_limits;
    let event = events
        .iter()
        .find(|e| e.limited.limit == ResourceLimit::SnapshotBytes)
        .unwrap_or_else(|| panic!("RFC 13.1 and 16: a snapshot-byte rejection records its own event, {events:?}"));
    assert_eq!(event.path, path("big"));
    assert_eq!(event.limited.configured, ceiling);
    assert!(event.limited.observed > ceiling);
    assert!(event.limited.domain.is_some(), "RFC 15.6: the event names the storage domain that hit the limit");
}

#[test]
fn a_listing_over_the_accounted_memory_ceiling_is_rejected_in_full_and_reports_the_structured_event() {
    let fs = tree(&["big"]);
    let probe = scanned(fs.clone(), Config::default());
    let ceiling = probe.stats().snapshot_bytes;
    let mut h = scanned(fs.clone(), Config { accounted_memory_ceiling: ceiling, ..Default::default() });
    let before = h.stats().version;
    fs.add_silently("big/extra", EntryKind::File);
    h.run_round();
    assert_eq!(h.stats().version, before, "RFC 15.6: a listing over the memory ceiling retains the previous snapshot");
    let events = h.stats().resource_limits;
    let event = events
        .iter()
        .find(|e| e.limited.limit == ResourceLimit::AccountedMemory)
        .unwrap_or_else(|| panic!("RFC 13.1 and 16: an accounted-memory rejection records its own event, {events:?}"));
    assert_eq!(event.limited.configured, ceiling);
    assert!(event.limited.observed > ceiling);
}

#[test]
fn a_listing_over_the_in_flight_byte_ceiling_ends_the_session_resource_limited() {
    let fs = wide(20);
    let child = entry_bytes(std::ffi::OsStr::new("f0"));
    let ceiling = child * 4;
    let h = scanned(fs.clone(), Config { in_flight_listing_bytes: ceiling, ..Default::default() });
    assert!(h.paths().contains(&"zzz/f".to_string()), "the narrow directories still list under the byte ceiling");
    assert!(
        !h.paths().contains(&"aaa/f0".to_string()),
        "RFC 10.2 and 15.6: a session over its result-size ceiling commits nothing"
    );
    let events = h.stats().resource_limits;
    let event = events
        .iter()
        .find(|e| e.limited.limit == ResourceLimit::ListingBytes)
        .unwrap_or_else(|| panic!("RFC 10.2: a session stopping at the result-size ceiling reports it, {events:?}"));
    assert_eq!(event.path, path("aaa"));
    assert_eq!(event.limited.configured, ceiling);
    assert!(event.limited.observed > ceiling);
    assert!(event.limited.domain.is_some(), "RFC 15.6: the event names the storage domain that hit the limit");
    assert!(
        h.health().reconciliation.degraded_paths.contains(&path("aaa")),
        "RFC 15.6: the path is reported degraded with a resource-limit cause"
    );
}

#[test]
fn every_unwatch_correlates_with_a_governor_grant() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    for dir in ["a", "b"] {
        fs.mkdir(dir);
        fs.create_file(&format!("{dir}/f"), 1);
    }
    let mut h = scanned(fs.clone(), Config::default());
    assert!(h.stats().paths_watched > 0, "the tree registered watches");
    h.command(Command::Unload(path("a")));
    h.run_until_idle();
    h.command(Command::Shutdown);
    h.run_until_idle();
    let released = u64::try_from(h.unwatched().len()).expect("count");
    assert!(released > 0, "the tree released its watches");
    assert!(
        released <= h.governor().watch_release_grants,
        "RFC 15.1 item 1: watch removal is admitted through the governor; {released} unwatches against {} grants",
        h.governor().watch_release_grants
    );
}

#[test]
fn a_command_blocked_by_a_ceiling_fails_with_the_same_structured_outcome_as_its_event() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("big");
    fs.create_file("big/f0", 1);
    fs.create_file("big/f1", 1);
    let mut h = scanned(fs.clone(), Config { entries_per_directory: 3, ..Default::default() });
    for i in 2..5 {
        fs.add_silently(&format!("big/f{i}"), EntryKind::File);
    }
    let ticket = h.command(Command::Refresh(vec![path("big")]));
    for _ in 0..60 {
        if h.result(ticket).is_some() {
            break;
        }
        let next = h.now() + Duration::from_secs(1);
        h.run_jobs_until(next);
    }
    let Some(Err(Error::ResourceLimited(limited))) = h.result(ticket) else {
        panic!(
            "RFC 9 and 13.1: a command whose required read hit a ceiling fails with ResourceLimited, not {:?}",
            h.result(ticket)
        );
    };
    assert_eq!(limited.limit, ResourceLimit::EntriesPerDirectory);
    assert_eq!(limited.configured, 3);
    assert_eq!(limited.observed, 5);
    let events = h.stats().resource_limits;
    let event = events
        .iter()
        .find(|e| e.path == path("big"))
        .unwrap_or_else(|| panic!("RFC 16: the rejection records an event, {events:?}"));
    assert_eq!(
        event.limited, limited,
        "RFC 13.1: one structured representation serves the command outcome, the event and the cause"
    );
}

#[test]
fn a_listing_over_the_represented_entry_ceiling_is_rejected_in_full_and_reports_the_structured_event() {
    let fs = tree(&["a", "b"]);
    let probe = scanned(fs.clone(), Config::default());
    let ceiling = probe.stats().represented_entries;
    let mut h = scanned(fs.clone(), Config { represented_entries: ceiling, ..Default::default() });
    let before = h.stats().version;
    fs.add_silently("a/extra", EntryKind::File);
    h.run_round();
    assert_eq!(
        h.stats().version,
        before,
        "RFC 20: a directory over the representation limit is degraded, not truncated"
    );
    assert!(!h.paths().contains(&"a/extra".to_string()));
    let events = h.stats().resource_limits;
    let event = events
        .iter()
        .find(|e| e.limited.limit == ResourceLimit::RepresentedEntries)
        .unwrap_or_else(|| panic!("RFC 13.1 and 16: a represented-entry rejection records its own event, {events:?}"));
    assert_eq!(event.path, path("a"));
    assert_eq!(event.limited.configured, u64::try_from(ceiling).expect("count"));
    assert!(event.limited.observed > event.limited.configured);
    assert!(event.limited.domain.is_some(), "RFC 15.6: the event names the storage domain that hit the limit");
    assert!(
        h.health().reconciliation.degraded_paths.contains(&path("a")),
        "RFC 15.6: the path is reported degraded with a resource-limit cause"
    );
}

#[test]
fn a_tree_that_raises_a_host_limit_is_rejected_before_any_tree_state_exists() {
    let host = HostGovernor::independent(&Config::default());
    let raised =
        Config { accounted_memory_ceiling: Config::default().accounted_memory_ceiling + 1, ..Default::default() };
    let opened = Harness::open_under(tree(&["a"]), Arc::new(LoadAll), raised, host.clone());
    assert!(
        matches!(opened, Err(Error::InvalidConfig(_))),
        "RFC 9.2: a tree MUST NOT raise a host limit, and opening one that does must fail with InvalidConfig"
    );
    let tighter = Config { accounted_memory_ceiling: 1024, per_domain_concurrency: 1, ..Default::default() };
    assert!(
        Harness::open_under(tree(&["a"]), Arc::new(LoadAll), tighter, host).is_ok(),
        "RFC 9.2: a tree MAY impose a subordinate limit that is tighter than the host's"
    );
}

#[test]
fn the_process_governor_is_installed_once_before_its_first_use() {
    let raised = Config {
        max_in_flight: 16,
        per_domain_concurrency: 8,
        accounted_memory_ceiling: 1024 * 1024 * 1024,
        ..Default::default()
    };
    let installed = HostGovernor::install(raised.clone()).expect("the process governor is installed before first use");
    assert!(
        installed.reject_raised_limits(&raised).is_ok(),
        "RFC 9.2: the host governor owns the physical ceilings, and an installed host may hold more than the defaults"
    );

    let runtime = Arc::new(tree_fucker::testing::DeterministicRuntime::new());
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let fs = tree(&["a"]);
    let (handle, _stream) = runtime
        .block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), raised.clone(), rt.clone()))
        .expect("RFC 9.2: a tree at the installed host limits opens");
    runtime.block_on(handle.initial_scan_complete()).expect("scan");

    let above = Config { max_in_flight: 32, ..raised.clone() };
    let opened = runtime.block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), above, rt));
    assert!(
        matches!(opened, Err(Error::InvalidConfig(_))),
        "RFC 9.2: a tree MUST NOT raise a host limit, whatever the host was installed with"
    );

    assert!(
        matches!(HostGovernor::install(Config::default()), Err(HostGovernorError::AlreadyInstalled)),
        "RFC 15.9: the host governor is one per process, so a second installation fails"
    );
    assert!(
        tree_fucker::host_governor().reject_raised_limits(&raised).is_ok(),
        "RFC 15.9: opening another tree changes no host limit, and neither does a refused installation"
    );
}
