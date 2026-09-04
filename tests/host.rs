use std::sync::Arc;
use std::time::Duration;

use tree_fucker::core::{Command, MonotonicTime, WorkOrigin};
use tree_fucker::testing::{Admission, CostScope, DomainId, FakeFileSystem, FakeOp, Harness};
use tree_fucker::update::{ResourceHealth, ResourceLimit, RoundResult, ThrottleCause};
use tree_fucker::{
    AccessTopology, Config, DomainCapabilities, EntryKind, Error, HostConfig, HostGovernor, HostGovernorError, LoadAll,
    MediaHint, RelativePath, Tree, WatcherKind, entry_bytes,
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
    scanned_under(fs, HostConfig::default(), config)
}

fn scanned_under(fs: Arc<FakeFileSystem>, host: HostConfig, config: Config) -> Harness {
    let mut h = Harness::open_with_host(fs, Arc::new(LoadAll), host, config).expect("open");
    h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(120));
    h
}

fn quiet(config: Config) -> Config {
    Config { fixed_interval: Some(Duration::from_secs(86_400)), ..config }
}

fn foreground_host() -> HostConfig {
    HostConfig {
        foreground_duty: 0.05,
        foreground_burst: Duration::from_millis(200),
        domain_foreground_duty: 0.05,
        domain_foreground_burst: Duration::from_millis(200),
        ..Default::default()
    }
}

fn wide_foreground_host() -> HostConfig {
    HostConfig {
        maximum_in_flight: 1,
        per_domain_concurrency: 1,
        foreground_duty: 1.0,
        foreground_burst: Duration::from_secs(30),
        domain_foreground_duty: 1.0,
        domain_foreground_burst: Duration::from_secs(30),
        ..Default::default()
    }
}

#[test]
fn a_refresh_storm_stays_within_the_foreground_envelope_and_never_touches_the_background_bucket() {
    let fs = tree(&["a", "b", "c"]);
    let mut h = scanned_under(fs.clone(), foreground_host(), quiet(Config::default()));
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
    let config = Config { foreground_ceiling_per_command: Duration::from_millis(300), ..quiet(Config::default()) };
    let mut h = scanned_under(fs.clone(), wide_foreground_host(), config);
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
    let mut h = scanned_under(fs.clone(), wide_foreground_host(), quiet(Config::default()));
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
    let host = HostConfig {
        domain_background_duty: BACKGROUND_DUTY_GLOBAL,
        domain_background_burst: BACKGROUND_BURST_GLOBAL,
        ..Default::default()
    };
    let shared = HostGovernor::independent(&host);
    let mut one =
        Harness::open_under(costed(&["a", "b", "c"]), Arc::new(LoadAll), config.clone(), shared.clone()).expect("open");
    let mut two =
        Harness::open_under(costed(&["d", "e", "f"]), Arc::new(LoadAll), config.clone(), shared.clone()).expect("open");
    let mut alone_one =
        Harness::open_with_host(costed(&["a", "b", "c"]), Arc::new(LoadAll), host, config.clone()).expect("open");
    let mut alone_two =
        Harness::open_with_host(costed(&["d", "e", "f"]), Arc::new(LoadAll), host, config.clone()).expect("open");
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
    let host = HostConfig { accounted_memory_ceiling: ceiling, ..Default::default() };
    let mut h = scanned_under(fs.clone(), host, leased);
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
    let host = HostConfig { accounted_memory_ceiling: ceiling, ..Default::default() };
    let mut h = scanned_under(fs.clone(), host, Config::default());
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
    let host = HostConfig { in_flight_listing_bytes: ceiling, ..Default::default() };
    let h = scanned_under(fs.clone(), host, Config::default());
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
fn a_tree_reads_the_host_ceilings_and_cannot_carry_one_of_its_own() {
    let host = HostGovernor::independent(&HostConfig {
        maximum_in_flight: 2,
        per_domain_concurrency: 1,
        accounted_memory_ceiling: 4096,
        in_flight_listing_bytes: 2048,
        ..Default::default()
    });
    let one = Harness::open_under(tree(&["a"]), Arc::new(LoadAll), Config::default(), host.clone()).expect("open");
    let two = Harness::open_under(
        tree(&["b"]),
        Arc::new(LoadAll),
        Config { batch_size: 8, entries_per_directory: 4, ..Default::default() },
        host.clone(),
    )
    .expect("open");
    for h in [&one, &two] {
        let view = h.stats().governor;
        assert_eq!(
            (view.memory_ceiling, view.in_flight_bytes_ceiling),
            (4096, 2048),
            "RFC 9.2 and 15.9: the host governor owns every physical ceiling and a tree reads them from it"
        );
    }
    assert!(
        HostGovernor::install(HostConfig { per_domain_concurrency: 9, ..Default::default() }).is_err(),
        "RFC 9.2: per_domain_concurrency above maximum_in_flight is InvalidConfig"
    );
    assert!(
        Harness::open_with_host(
            tree(&["c"]),
            Arc::new(LoadAll),
            HostConfig { accounted_memory_ceiling: 0, ..Default::default() },
            Config::default()
        )
        .is_err(),
        "RFC 9.2: `open` rejects InvalidConfig before creating tree state"
    );
}

#[test]
fn the_process_governor_is_installed_once_before_its_first_use() {
    let raised = HostConfig {
        maximum_in_flight: 16,
        per_domain_concurrency: 8,
        accounted_memory_ceiling: 1024 * 1024 * 1024,
        ..Default::default()
    };
    let installed = HostGovernor::install(raised).expect("the process governor is installed before first use");
    assert_eq!(
        *installed.limits(),
        raised,
        "RFC 9.2: the host governor owns the physical ceilings, and an installed host may hold more than the defaults"
    );

    let runtime = Arc::new(tree_fucker::testing::DeterministicRuntime::new());
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let fs = tree(&["a"]);
    let (handle, _stream) = runtime
        .block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), Config::default(), rt.clone()))
        .expect("RFC 9.2: a tree opens under the installed host limits");
    runtime.block_on(handle.initial_scan_complete()).expect("scan");
    assert_eq!(
        handle.stats().governor.memory_ceiling,
        1024 * 1024 * 1024,
        "RFC 15.9: `open` uses the process-wide governor, so the tree accounts against the installed ceiling"
    );

    assert!(
        matches!(HostGovernor::install(HostConfig::default()), Err(HostGovernorError::AlreadyInstalled)),
        "RFC 15.9: the host governor is one per process, so a second installation fails"
    );
    assert_eq!(
        *tree_fucker::host_governor().limits(),
        raised,
        "RFC 15.9: opening another tree changes no host limit, and neither does a refused installation"
    );
}

#[test]
fn the_default_configuration_equals_the_rfc_9_2_table() {
    let host = HostConfig::default();
    let rows: Vec<(&str, String, String)> = vec![
        ("maximum in-flight jobs", format!("{:?}", host.maximum_in_flight), format!("{:?}", 8usize)),
        ("per-domain concurrency ceiling", format!("{:?}", host.per_domain_concurrency), format!("{:?}", 4usize)),
        ("background duty, per domain", format!("{:?}", host.domain_background_duty), format!("{:?}", 0.01f64)),
        ("background duty, global", format!("{:?}", host.background_duty), format!("{:?}", 0.02f64)),
        (
            "background burst, per domain",
            format!("{:?}", host.domain_background_burst),
            format!("{:?}", Duration::from_millis(250)),
        ),
        (
            "background burst, global",
            format!("{:?}", host.background_burst),
            format!("{:?}", Duration::from_millis(500)),
        ),
        ("foreground duty", format!("{:?}", host.foreground_duty), format!("{:?}", 0.25f64)),
        ("foreground burst", format!("{:?}", host.foreground_burst), format!("{:?}", Duration::from_secs(2))),
        ("bootstrap allowance", format!("{:?}", host.bootstrap_allowance), format!("{:?}", Duration::from_millis(500))),
        (
            "aggregate accounted-memory ceiling",
            format!("{:?}", host.accounted_memory_ceiling),
            format!("{:?}", 512u64 * 1024 * 1024),
        ),
        (
            "in-flight listing byte ceiling",
            format!("{:?}", host.in_flight_listing_bytes),
            format!("{:?}", 32u64 * 1024 * 1024),
        ),
        (
            "initial cost estimate",
            format!("{:?}", host.initial_cost_estimate),
            format!("{:?}", Duration::from_millis(20)),
        ),
        ("stuck worker threshold", format!("{:?}", host.stuck_threshold), format!("{:?}", Duration::from_secs(30))),
    ];
    for (row, actual, expected) in rows {
        assert_eq!(actual, expected, "RFC 9.2 host governor default `{row}`");
    }

    let tree = Config::default();
    let rows: Vec<(&str, String, String)> = vec![
        ("batch size", format!("{:?}", tree.batch_size), format!("{:?}", 64usize)),
        ("pending command capacity", format!("{:?}", tree.command_capacity), format!("{:?}", 1024usize)),
        ("paths per command limit", format!("{:?}", tree.paths_per_command), format!("{:?}", 65536usize)),
        ("priority-set path limit", format!("{:?}", tree.priority_set_limit), format!("{:?}", 4096usize)),
        ("update-stream capacity", format!("{:?}", tree.update_stream_capacity), format!("{:?}", 256usize)),
        ("coalesced watcher-path limit", format!("{:?}", tree.watcher_path_limit), format!("{:?}", 16384usize)),
        ("entries per directory limit", format!("{:?}", tree.entries_per_directory), format!("{:?}", 250_000usize)),
        ("represented entry limit", format!("{:?}", tree.represented_entries), format!("{:?}", 1_000_000usize)),
        ("snapshot byte ceiling", format!("{:?}", tree.snapshot_bytes), format!("{:?}", 256u64 * 1024 * 1024)),
        (
            "foreground ceiling per command",
            format!("{:?}", tree.foreground_ceiling_per_command),
            format!("{:?}", Duration::from_secs(30)),
        ),
        ("metadata fields", format!("{:?}", tree.metadata_fields), format!("{:?}", tree_fucker::MetadataFields::NONE)),
        (
            "domain crossing",
            format!("{:?}", tree.domain_crossing),
            format!("{:?}", tree_fucker::DomainCrossing::LoadOnDemand),
        ),
        ("transient degrade threshold", format!("{:?}", tree.transient_degrade_threshold), format!("{:?}", 3u32)),
        ("retry maximum delay", format!("{:?}", tree.retry_maximum_delay), format!("{:?}", Duration::from_secs(300))),
        (
            "watch registration failure",
            format!("{:?}", tree.watch_registration_failure_mode),
            format!("{:?}", tree_fucker::WatchRegistrationFailure::ReconcileOnly),
        ),
        ("root reappearance monitoring", format!("{:?}", tree.root_reappearance_monitoring), format!("{:?}", true)),
        ("minimum_period (RFC 12)", format!("{:?}", tree.minimum_period), format!("{:?}", Duration::from_secs(1))),
        ("maximum_period (RFC 12)", format!("{:?}", tree.maximum_period), format!("{:?}", Duration::from_secs(300))),
        ("baseline_share (RFC 11.3)", format!("{:?}", tree.baseline_share), format!("{:?}", 0.5f64)),
        (
            "class weights (RFC 11.3)",
            format!("{:?}", tree.class_weights),
            format!("{:?}", tree_fucker::ClassWeights { control: 4, refresh: 4, watcher: 2, retry: 1, priority: 2 }),
        ),
    ];
    for (row, actual, expected) in rows {
        assert_eq!(actual, expected, "RFC 9.2 tree default `{row}`");
    }

    assert!(host.validate().is_ok(), "RFC 9.2: the host defaults satisfy every InvalidConfig condition");
    assert!(tree.validate().is_ok(), "RFC 9.2: the tree defaults satisfy every InvalidConfig condition");
}

#[test]
fn ten_trees_under_one_host_governor_share_one_physical_ceiling_and_one_envelope() {
    let host = HostConfig { maximum_in_flight: 2, per_domain_concurrency: 2, ..Default::default() };
    let shared = HostGovernor::independent(&host);
    let mut trees: Vec<Harness> = (0..10)
        .map(|index| {
            let fs = tree(&["a", "b", "c"]);
            let domain = DomainId::new(100 + index);
            fs.set_domain("", domain);
            fs.set_capabilities(
                domain,
                DomainCapabilities {
                    topology: AccessTopology::Local,
                    media: MediaHint::SolidState,
                    ..DomainCapabilities::inline()
                },
            );
            fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(1));
            Harness::open_under(fs, Arc::new(LoadAll), Config::default(), shared.clone()).expect("open")
        })
        .collect();
    let window = Duration::from_secs(300);
    let mut peak = 0;
    for step in 1..=300 {
        let target = MonotonicTime::ZERO + Duration::from_secs(step);
        for h in trees.iter_mut() {
            h.run_jobs_until(target);
        }
        let held: usize = trees.iter().map(|h| h.stats().blocking_slots_held).sum();
        peak = peak.max(held);
        assert!(
            held <= 2,
            "RFC 15.9: every tree in the process shares one ceiling on in-flight workers; {held} workers were running \
             across ten trees at {target:?}"
        );
        assert!(
            shared.view(target).in_flight <= 2,
            "RFC 15.3: the host governor reports {}",
            shared.view(target).in_flight
        );
    }
    assert!(peak > 0, "no tree ever ran a worker");
    let reserved: Duration =
        trees.iter().map(|h| h.reserved_between(MonotonicTime::ZERO, MonotonicTime::ZERO + window)).sum();
    let budget = envelope(BACKGROUND_DUTY_GLOBAL, BACKGROUND_BURST_GLOBAL, window);
    assert!(reserved <= budget, "RFC 15.9: ten trees reserved {reserved:?} against one global envelope of {budget:?}");
}

#[test]
fn the_host_governor_counts_in_flight_workers_across_trees_against_one_ceiling() {
    use tree_fucker::core::{GrantId, Reservation};
    use tree_fucker::{DomainKey, JobId, StorageDomainId};
    let shared = HostGovernor::independent(&HostConfig {
        maximum_in_flight: 2,
        per_domain_concurrency: 2,
        ..Default::default()
    });
    let now = MonotonicTime::ZERO;
    let capabilities = DomainCapabilities {
        topology: AccessTopology::Local,
        media: MediaHint::SolidState,
        ..DomainCapabilities::inline()
    };
    let domains: Vec<StorageDomainId> = (0..3).map(|i| StorageDomainId::of(&DomainKey::declared(200 + i))).collect();
    let grants: Vec<GrantId> = domains
        .iter()
        .map(|domain| {
            shared.register_domain(*domain, &capabilities, now);
            let id = GrantId::Job(shared.next_tree(), JobId::new(1));
            shared
                .try_admit(
                    Reservation {
                        id,
                        path: RelativePath::root(),
                        reads: 1,
                        registrations: 0,
                        lease: 0,
                        domain: Some(*domain),
                        origin: WorkOrigin::Background,
                        listing: true,
                    },
                    now,
                )
                .expect("admitted");
            id
        })
        .collect();
    assert_eq!(shared.may_start(Some(domains[0])), Ok(()));
    shared.start(grants[0], now);
    assert_eq!(shared.may_start(Some(domains[1])), Ok(()));
    shared.start(grants[1], now);
    assert_eq!(
        shared.may_start(Some(domains[2])),
        Err(ThrottleCause::Concurrency),
        "RFC 15.9: one set of physical ceilings on in-flight workers for every tree in the process; a third tree on \
         its own domain must wait behind two workers of other trees"
    );
    assert_eq!(shared.view(now).in_flight, 2);
    shared.release(grants[0], now);
    assert_eq!(shared.may_start(Some(domains[2])), Ok(()), "a released slot frees the ceiling for any tree");
}

#[test]
fn a_stuck_domain_resolution_in_one_tree_never_freezes_the_shared_bootstrap_scope() {
    let shared = HostGovernor::independent(&HostConfig::default());
    let stuck = tree(&["local", "mnt"]);
    stuck.create_file("local/f", 1);
    stuck.mkdir("mnt/inner");
    stuck.create_file("mnt/inner/deep", 1);
    stuck.set_domain("mnt", DomainId::new(2));
    stuck.report_inline_domains(false);
    stuck.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(5));
    stuck.set_cost(CostScope::Domain(DomainId::new(2)), FakeOp::ResolveDomain, Duration::from_secs(36_000));
    let follow = Config { domain_crossing: tree_fucker::DomainCrossing::Follow, ..Default::default() };
    let mut first = Harness::open_under(stuck.clone(), Arc::new(LoadAll), follow, shared.clone()).expect("open");
    first.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(120));
    assert!(
        first.stats().blocking_slots.iter().any(|slot| slot.path == path("mnt")),
        "the resolution on mnt was not held, so the scenario is untested"
    );

    let second = tree(&["a", "b", "c"]);
    for name in ["a", "b", "c"] {
        second.create_file(&format!("{name}/f"), 1);
    }
    second.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(5));
    let mut other = Harness::open_under(second.clone(), Arc::new(LoadAll), Config::default(), shared.clone())
        .expect("RFC 13.5: a stuck bootstrap-scope worker in one tree must not deny another tree's open");
    other.run_until_idle();
    assert_eq!(
        other.health().reconciliation.last_round,
        Some(RoundResult::Successful),
        "RFC 13.5: a stuck domain resolution charged to the process-wide bootstrap scope quarantines nothing, so a \
         second tree under the same host governor still completes its scan"
    );
    assert!(other.paths().contains(&"a/f".to_string()));
    assert!(
        first.paths().contains(&"mnt/inner/deep".to_string()) || !first.paths().contains(&"mnt/inner".to_string()),
        "the first tree's healthy work continued around the stuck resolution"
    );
}

#[test]
fn two_trees_reaching_one_domain_debit_one_domain_account() {
    let shared = HostGovernor::independent(&HostConfig::default());
    let make = |dirs: &[&str]| {
        let fs = tree(dirs);
        fs.set_domain("", DomainId::new(7));
        fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
        fs
    };
    let mut one =
        Harness::open_under(make(&["a", "b"]), Arc::new(LoadAll), Config::default(), shared.clone()).expect("open");
    let mut two =
        Harness::open_under(make(&["c", "d"]), Arc::new(LoadAll), Config::default(), shared.clone()).expect("open");
    let mut target = MonotonicTime::ZERO;
    for step in 1..=120 {
        target = MonotonicTime::ZERO + Duration::from_secs(step);
        one.run_jobs_until(target);
        two.run_jobs_until(target);
    }
    let first = one.stats().domains.into_iter().next().expect("the first tree entered no domain");
    let second = two.stats().domains.into_iter().next().expect("the second tree entered no domain");
    assert_eq!(
        first.id, second.id,
        "RFC 15.9: adapters report the same identity for the same mount, so both trees bind one storage domain"
    );
    assert_eq!(first.charged, second.charged, "RFC 15.9: both trees read one domain account");
    let view = shared.view(target);
    assert_eq!(view.domains.len(), 1, "RFC 15.9: one accounting of worker time per storage domain; {:?}", view.domains);
    let account = view.domains.get(&first.id).copied().expect("the shared domain account");
    assert!(
        account.charged >= one.charged_work() + two.charged_work(),
        "RFC 15.9: the one account carries both trees' work; {:?} against {:?} and {:?}",
        account.charged,
        one.charged_work(),
        two.charged_work()
    );
}

#[test]
fn each_tree_under_one_host_governor_reports_its_own_charged_worker_time() {
    let shared = HostGovernor::independent(&HostConfig::default());
    let mut one = Harness::open_under(costed(&["a", "b", "c"]), Arc::new(LoadAll), Config::default(), shared.clone())
        .expect("open");
    let mut two = Harness::open_under(costed(&["d", "e", "f"]), Arc::new(LoadAll), Config::default(), shared.clone())
        .expect("open");
    let mut target = MonotonicTime::ZERO;
    for step in 1..=60 {
        target = MonotonicTime::ZERO + Duration::from_secs(step);
        one.run_jobs_until(target);
        two.run_jobs_until(target);
    }
    let first = one.stats().charged_worker_time;
    let second = two.stats().charged_worker_time;
    assert!(
        first > Duration::ZERO && second > Duration::ZERO,
        "line 1004: each tree reports the worker time charged for its own work; {first:?} and {second:?}"
    );
    let total = shared.view(target).charged;
    assert!(
        first + second <= total,
        "line 1004 and RFC 15.9: the per-tree subtotals never exceed the process governor's charged total; \
         {first:?} + {second:?} against {total:?}"
    );
}
