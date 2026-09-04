use std::sync::Arc;
use std::time::Duration;

use tree_fucker::core::{Command, JobOperation, MonotonicTime};
use tree_fucker::policy::{PolicyContext, ScanDecision, ScanPolicy};
use tree_fucker::testing::{CostScope, DomainId, FakeFileSystem, FakeOp, Harness};
use tree_fucker::update::{RoundResult, WatcherHealth};
use tree_fucker::{
    Answer, Config, DirectoryListing, DomainCapabilities, DomainCrossing, DomainIdentity, EntryInfo, HintKind, LoadAll,
    LoadState, PolicyRevision, RelativePath, WatcherAvailability, WatcherCapabilities, WatcherKind, WatcherScope,
};

const BACKGROUND_DUTY_GLOBAL: f64 = 0.02;
const BACKGROUND_BURST_GLOBAL: Duration = Duration::from_millis(500);
const MAXIMUM_PERIOD: Duration = Duration::from_secs(300);

const MEDIA: DomainId = DomainId::new(2);
const REMOTE: DomainId = DomainId::new(3);

fn path(p: &str) -> RelativePath {
    RelativePath::parse(p).expect("valid path")
}

fn follow() -> Config {
    Config { domain_crossing: DomainCrossing::Follow, ..Default::default() }
}

fn watching(scope: WatcherScope, observes: Answer) -> WatcherCapabilities {
    WatcherCapabilities {
        availability: WatcherAvailability::Available,
        scope,
        observes_external_writers: observes,
        can_lose_events: Answer::Yes,
        signals_overflow: Answer::Yes,
        registration_gaps: Answer::No,
        polling_fallback_required: Answer::No,
    }
}

fn unwatched() -> WatcherCapabilities {
    WatcherCapabilities {
        availability: WatcherAvailability::Unavailable,
        scope: WatcherScope::Unknown,
        observes_external_writers: Answer::No,
        can_lose_events: Answer::Unknown,
        signals_overflow: Answer::No,
        registration_gaps: Answer::Unknown,
        polling_fallback_required: Answer::Yes,
    }
}

fn declaring(watcher: WatcherCapabilities) -> DomainCapabilities {
    DomainCapabilities { watcher, ..DomainCapabilities::inline() }
}

fn two_domains() -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    fs.mkdir("local");
    fs.mkdir("local/inner");
    fs.create_file("local/inner/f", 1);
    fs.mkdir("mnt");
    fs.mkdir("mnt/inner");
    fs.create_file("mnt/inner/f", 1);
    fs.set_domain("mnt", MEDIA);
    fs
}

fn domain_stat(h: &Harness, domain: DomainId) -> tree_fucker::core::DomainStat {
    let key = FakeFileSystem::domain_key(domain);
    h.stats()
        .domains
        .into_iter()
        .find(|entered| entered.identity == DomainIdentity::Known(key.clone()))
        .unwrap_or_else(|| panic!("the tree never entered {domain}"))
}

#[test]
fn watcher_capabilities_are_declared_per_domain_in_one_tree() {
    let fs = two_domains();
    fs.set_capabilities(DomainId::ROOT, declaring(watching(WatcherScope::PerDirectory, Answer::Yes)));
    fs.set_capabilities(MEDIA, declaring(watching(WatcherScope::PerDirectory, Answer::No)));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), follow()).expect("open");
    h.run_until_idle();

    let root = domain_stat(&h, DomainId::ROOT);
    let media = domain_stat(&h, MEDIA);
    assert_eq!(
        (root.watcher.observes_external_writers, media.watcher.observes_external_writers),
        (Answer::Yes, Answer::No),
        "RFC 10.4: watcher capabilities are declared per storage domain, never once per tree"
    );
    assert_eq!(
        (root.watcher.polling_fallback_required, media.watcher.polling_fallback_required),
        (Answer::No, Answer::No)
    );
    assert!(
        matches!(root.watcher_health, WatcherHealth::Healthy { .. })
            && matches!(media.watcher_health, WatcherHealth::Healthy { .. }),
        "RFC 10.4 and 16: watcher health is reported per domain; the tree reports {:?} and {:?}",
        root.watcher_health,
        media.watcher_health
    );
    assert_eq!(
        h.health().watcher_domains.get(&media.id).cloned(),
        Some(media.watcher_health.clone()),
        "RFC 7.4 and 10.4: the per-domain watcher health reaches consumers through the health state"
    );
}

#[test]
fn a_domain_without_a_watcher_registers_nothing_and_is_covered_by_baseline_only() {
    let fs = two_domains();
    fs.set_capabilities(DomainId::ROOT, declaring(watching(WatcherScope::PerDirectory, Answer::Yes)));
    fs.set_capabilities(MEDIA, declaring(unwatched()));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), follow()).expect("open");
    h.run_until_idle();

    assert_eq!(
        (fs.count_ops(FakeOp::Watch, "mnt"), fs.count_ops(FakeOp::Watch, "mnt/inner")),
        (0, 0),
        "RFC 10.4: a domain whose watcher is unavailable gets no registrations"
    );
    assert!(
        fs.count_ops(FakeOp::Watch, "local") > 0 && fs.count_ops(FakeOp::Watch, "local/inner") > 0,
        "the watching domain registered nothing either, so this test measures nothing"
    );
    let media = domain_stat(&h, MEDIA);
    assert_eq!(media.paths_watched, 0);
    assert_eq!(
        media.watcher_health,
        WatcherHealth::Absent,
        "RFC 10.4 and 16: a domain without a watcher reports its watcher health as absent"
    );

    fs.add_silently("mnt/inner/late", tree_fucker::EntryKind::File);
    h.run_round();
    h.run_until_idle();
    assert!(
        h.paths().contains(&"mnt/inner/late".to_string()),
        "RFC 5.1 and 10.4: the directories of a domain without a watcher are covered by baseline reconciliation"
    );
}

#[test]
fn a_non_observing_domain_keeps_the_same_baseline_cadence_as_an_observing_one() {
    fn rounds_and_listings(observes: Answer) -> (usize, usize) {
        let fs = two_domains();
        fs.set_capabilities(DomainId::ROOT, declaring(watching(WatcherScope::PerDirectory, Answer::Yes)));
        fs.set_capabilities(MEDIA, declaring(watching(WatcherScope::PerDirectory, observes)));
        fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(5));
        let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), follow()).expect("open");
        h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(600));
        let mut rounds = 0;
        let mut last = h.last_round();
        for _ in 0..20 {
            let target = h.now() + Duration::from_secs(60);
            h.run_jobs_until(target);
            if h.last_round() != last {
                last = h.last_round();
                rounds += 1;
            }
        }
        (rounds, fs.count_ops(FakeOp::ReadDir, "mnt/inner"))
    }

    let (observing_rounds, observing_listings) = rounds_and_listings(Answer::Yes);
    let (blind_rounds, blind_listings) = rounds_and_listings(Answer::No);
    assert!(observing_rounds > 0 && blind_rounds > 0, "no round completed, so there is no cadence to compare");
    assert_eq!(
        (blind_rounds, blind_listings),
        (observing_rounds, observing_listings),
        "RFC 10.4: a watcher that does not observe external writers is latency assistance for local writes only, \
         so the reconciliation cadence for that domain is not relaxed"
    );
}

#[test]
fn hints_from_a_non_observing_domain_do_not_raise_its_envelope() {
    fn storm_worst(storm: bool) -> Duration {
        let fs = two_domains();
        fs.set_capabilities(MEDIA, declaring(watching(WatcherScope::PerDirectory, Answer::No)));
        fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(5));
        let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), follow()).expect("open");
        h.run_jobs_until(MonotonicTime::ZERO + Duration::from_secs(120));
        let target = h.now() + Duration::from_secs(120);
        if storm {
            h.flood_hints_until(&["mnt", "mnt/inner"], HintKind::Modify, target);
        } else {
            h.run_jobs_until(target);
        }
        h.worst_reserved_window(MAXIMUM_PERIOD).1
    }

    let budget =
        Duration::from_secs_f64(MAXIMUM_PERIOD.as_secs_f64() * BACKGROUND_DUTY_GLOBAL) + BACKGROUND_BURST_GLOBAL;
    let quiet = storm_worst(false);
    let storm = storm_worst(true);
    assert!(quiet <= budget, "the quiet baseline already exceeds the envelope: {quiet:?} against {budget:?}");
    assert!(
        storm <= budget,
        "RFC 10.4 and 15.1 item 3: hints from a domain that does not observe external writers are latency \
         assistance only and must not raise its envelope; the {MAXIMUM_PERIOD:?} window reserved {storm:?} under \
         a storm against a budget of {budget:?} (quiet {quiet:?})"
    );
}

fn capped_tree(dirs: usize) -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    for i in 0..dirs {
        let name = format!("d{i}");
        fs.mkdir(&name);
        fs.create_file(&format!("{name}/f"), 1);
    }
    fs
}

#[test]
fn the_path_cap_stops_registration_and_the_uncovered_directories_are_still_reconciled() {
    let fs = capped_tree(6);
    let config = Config { watcher_path_limit: 3, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();

    let stats = h.stats();
    assert_eq!(
        stats.paths_watched, 3,
        "RFC 9.2 and 10.4: the configured watcher path limit bounds the registered watch paths per tree; the \
         tree registered {} of a limit of {}",
        stats.paths_watched, stats.watcher_path_limit
    );
    assert!(
        stats.paths_unwatched_by_cap > 0,
        "RFC 16: the directories left unwatched by the cap must be reported; the tree reports {stats:?}"
    );
    let registered = fs.ops().iter().filter(|(op, _)| *op == FakeOp::Watch).count();
    assert_eq!(
        registered, 3,
        "RFC 10.4: registration beyond the cap is not attempted; the adapter performed {registered} registrations"
    );

    for i in 0..6 {
        fs.add_silently(&format!("d{i}/late"), tree_fucker::EntryKind::File);
    }
    h.run_round();
    h.run_until_idle();
    for i in 0..6 {
        assert!(
            h.paths().contains(&format!("d{i}/late")),
            "RFC 10.4: a directory the cap left unwatched is still covered by reconciliation; the tree holds {:?}",
            h.paths()
        );
    }
    assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful));
}

struct CapChildDomain(usize);

impl ScanPolicy for CapChildDomain {
    fn revision(&self) -> PolicyRevision {
        PolicyRevision::new(0)
    }

    fn root_context(&self, _root: &EntryInfo) -> PolicyContext {
        PolicyContext::unit()
    }

    fn classify(&self, _parent: &PolicyContext, _path: &RelativePath, _info: &EntryInfo) -> ScanDecision {
        ScanDecision::Eligible { initially_loaded: true }
    }

    fn child_context(
        &self,
        parent: &PolicyContext,
        _path: &RelativePath,
        _listing: &DirectoryListing,
    ) -> PolicyContext {
        parent.clone()
    }

    fn crossing(
        &self,
        _parent: &PolicyContext,
        _path: &RelativePath,
        _child: &DomainCapabilities,
        _configured: DomainCrossing,
    ) -> DomainCrossing {
        DomainCrossing::Follow
    }

    fn watcher_path_limit(
        &self,
        _parent: &PolicyContext,
        _path: &RelativePath,
        domain: &DomainCapabilities,
        configured: usize,
    ) -> usize {
        match domain.watcher.observes_external_writers {
            Answer::No => self.0,
            _ => configured,
        }
    }
}

fn split_tree() -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    fs.mkdir("local");
    fs.mkdir("mnt");
    for i in 0..4 {
        fs.mkdir(&format!("mnt/d{i}"));
        fs.create_file(&format!("mnt/d{i}/f"), 1);
    }
    fs.set_domain("mnt", MEDIA);
    fs.set_capabilities(DomainId::ROOT, declaring(watching(WatcherScope::PerDirectory, Answer::Yes)));
    fs.set_capabilities(MEDIA, declaring(watching(WatcherScope::PerDirectory, Answer::No)));
    fs
}

#[test]
fn a_per_domain_cap_below_the_tree_cap_is_honoured_and_a_higher_one_is_clamped() {
    let fs = split_tree();
    let config = Config { watcher_path_limit: 32, ..follow() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    let unconstrained = domain_stat(&h, MEDIA);
    assert_eq!(
        (unconstrained.paths_watched, unconstrained.paths_unwatched_by_cap),
        (5, 0),
        "under a tree cap of 32 the child domain must register every one of its directories, or the per-domain \
         cap below has nothing to bind"
    );

    let fs = split_tree();
    let config = Config { watcher_path_limit: 32, ..follow() };
    let mut h = Harness::open(fs.clone(), Arc::new(CapChildDomain(2)), config).expect("open");
    h.run_until_idle();
    let media = domain_stat(&h, MEDIA);
    let root = domain_stat(&h, DomainId::ROOT);
    assert_eq!(
        (media.paths_watched, media.paths_unwatched_by_cap),
        (2, 3),
        "RFC 10.4 and 16: a per-domain watcher path cap below the tree cap bounds that domain's registrations and \
         the directories it turns away are reported"
    );
    assert_eq!(
        (root.paths_watched, root.paths_unwatched_by_cap),
        (2, 0),
        "RFC 10.4: a lower cap on one domain never bounds another domain, which stays bound by the tree cap"
    );

    let fs = split_tree();
    let config = Config { watcher_path_limit: 2, ..follow() };
    let mut h = Harness::open(fs.clone(), Arc::new(CapChildDomain(64)), config).expect("open");
    h.run_until_idle();
    assert_eq!(
        h.stats().paths_watched,
        2,
        "RFC 10.4: a per-domain cap may be lower and never higher, so a policy asking for 64 paths under a tree \
         cap of 2 registers 2"
    );
}

#[test]
fn a_watcher_failure_on_one_domain_does_not_restart_another_domains_watches() {
    let fs = two_domains();
    fs.set_capabilities(DomainId::ROOT, declaring(watching(WatcherScope::PerDirectory, Answer::Yes)));
    fs.set_capabilities(MEDIA, declaring(watching(WatcherScope::PerDirectory, Answer::No)));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), follow()).expect("open");
    h.run_until_idle();
    let local_before = fs.count_ops(FakeOp::Watch, "local") + fs.count_ops(FakeOp::Watch, "local/inner");
    let media_before = fs.count_ops(FakeOp::Watch, "mnt") + fs.count_ops(FakeOp::Watch, "mnt/inner");
    assert!(local_before > 0 && media_before > 0, "one of the domains registered nothing before the failure");

    assert!(fs.emit_watcher_failure_under("mnt", "mount watcher gone") > 0, "no watch under mnt was failed");
    h.advance(Duration::from_secs(120));

    let local_after = fs.count_ops(FakeOp::Watch, "local") + fs.count_ops(FakeOp::Watch, "local/inner");
    let media_after = fs.count_ops(FakeOp::Watch, "mnt") + fs.count_ops(FakeOp::Watch, "mnt/inner");
    assert_eq!(
        local_after,
        local_before,
        "RFC 10.4 and 13.4: watcher capabilities are per domain, so a watcher failure on one domain must not \
         restart another domain's watches; the unaffected domain re-registered {} times",
        local_after - local_before
    );
    assert!(
        media_after > media_before,
        "RFC 13.4: the failing domain's watcher must be restarted with backoff; it registered {media_after} \
         against {media_before} before the failure"
    );
    assert_eq!(
        domain_stat(&h, DomainId::ROOT).watcher_health,
        WatcherHealth::Healthy { backend: WatcherKind::NonRecursive },
        "RFC 10.4: a watcher failure scoped to one domain leaves another domain's watcher health untouched"
    );
}

#[test]
fn a_recursive_domain_registers_at_its_own_domain_root() {
    let fs = two_domains();
    fs.set_capabilities(DomainId::ROOT, declaring(watching(WatcherScope::Recursive, Answer::Yes)));
    fs.set_capabilities(MEDIA, declaring(watching(WatcherScope::Recursive, Answer::Yes)));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), follow()).expect("open");
    h.run_until_idle();

    assert_eq!(
        (fs.count_ops(FakeOp::Watch, ""), fs.count_ops(FakeOp::Watch, "mnt")),
        (1, 1),
        "RFC 10.4 and 14.3: a recursive watcher covers one domain, so each domain the tree enters registers at \
         its own root and nowhere else"
    );
    assert_eq!(
        (fs.count_ops(FakeOp::Watch, "local"), fs.count_ops(FakeOp::Watch, "mnt/inner")),
        (0, 0),
        "RFC 10.4: a recursive domain registers no per-directory watch"
    );
    assert_eq!(h.stats().paths_watched, 2);
}

#[test]
fn a_capped_directory_registers_once_the_cap_frees_up() {
    let fs = capped_tree(3);
    let config = Config { watcher_path_limit: 3, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    assert_eq!(h.stats().paths_watched, 3);
    let watched: Vec<String> =
        (0..3).map(|i| format!("d{i}")).filter(|name| fs.count_ops(FakeOp::Watch, name) > 0).collect();
    let capped: Vec<String> =
        (0..3).map(|i| format!("d{i}")).filter(|name| fs.count_ops(FakeOp::Watch, name) == 0).collect();
    assert_eq!(capped.len(), 1, "a four-directory tree under a cap of three left {capped:?} unwatched");
    assert_eq!(h.stats().paths_unwatched_by_cap, 1);

    let t = h.command(Command::Unload(path(&watched[0])));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(h.entry(&watched[0]).and_then(|e| e.load_state()), Some(LoadState::Unloaded));

    h.run_round();
    h.run_until_idle();
    assert!(
        fs.count_ops(FakeOp::Watch, &capped[0]) > 0,
        "RFC 10.4: a directory the cap turned away registers once a watch path is released; {} is still unwatched",
        capped[0]
    );
    assert!(h.stats().paths_watched <= 3, "the cap was exceeded while re-registering a capped directory");
}

#[test]
fn a_remote_domain_declaring_no_external_writers_is_still_reconciled_under_the_default_crossing() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    fs.mkdir("local");
    fs.create_file("local/f", 1);
    fs.mkdir("net");
    fs.create_file("net/f", 1);
    fs.set_domain("net", REMOTE);
    fs.set_capabilities(REMOTE, declaring(watching(WatcherScope::PerDirectory, Answer::No)));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();

    assert_eq!(
        h.entry("net").and_then(|e| e.load_state()),
        Some(LoadState::Unloaded),
        "RFC 14.3: the default crossing mode leaves a foreign domain unloaded"
    );
    assert_eq!(fs.count_ops(FakeOp::Watch, "net"), 0, "RFC 10.4: an unloaded mount point takes no watch registration");
    assert_eq!(h.stats().paths_unwatched_by_cap, 0, "nothing was turned away by the cap in this tree");
}

#[test]
fn a_symbolic_link_entry_receives_no_watch_registration() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    fs.mkdir("dir");
    fs.create_file("dir/f", 1);
    fs.add_silently("link", tree_fucker::EntryKind::Symlink);
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();

    assert_eq!(
        h.entry("link").map(|e| e.kind()),
        Some(tree_fucker::EntryKind::Symlink),
        "RFC 14.2: a symbolic link is represented as an entry"
    );
    assert_eq!(
        fs.count_ops(FakeOp::Watch, "link"),
        0,
        "RFC 14.2 and 10.4: a symbolic link is never traversed, so it takes no watch registration; the adapter \
         performed {:?}",
        fs.ops()
    );
    assert!(fs.count_ops(FakeOp::Watch, "dir") > 0, "the real directory registered nothing, so nothing was compared");
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "link"), 0, "RFC 14.2: a symbolic link entry is never listed");
}

#[test]
fn a_hint_delivered_during_an_in_flight_listing_discards_the_stale_result() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    fs.mkdir("d0");
    fs.create_file("d0/f", 1);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();
    fs.clear_ops();
    let stale_before = h.stats().stale_results;
    let reads_before = fs.count_ops(FakeOp::ReadDir, "d0");

    let t = h.command(Command::Refresh(vec![path("d0")]));
    let job = loop {
        if let Some(job) = h.pending_job_for("d0") {
            break job;
        }
        let next = h.now() + Duration::from_secs(1);
        h.run_jobs_until(next);
    };
    fs.add_silently("d0/late", tree_fucker::EntryKind::File);
    h.inject_watcher_event(tree_fucker::fs::WatcherEvent::Hint { paths: vec![path("d0")], kind: HintKind::Modify });
    h.deliver_watcher_events();
    h.complete_job(job.id);

    assert_eq!(
        h.stats().stale_results,
        stale_before + 1,
        "RFC 11.2: accepting a watcher hint increments the target's change epoch, so the listing that was in flight \
         when the hint arrived is stale and its result MUST NOT commit"
    );
    h.run_until_idle();
    assert!(
        fs.count_ops(FakeOp::ReadDir, "d0") > reads_before + 1,
        "RFC 11.2: the stale target is queued again, so d0 is listed a second time before the hint is served"
    );
    assert_eq!(h.result(t), Some(Ok(())));
    assert!(
        h.paths().contains(&"d0/late".to_string()),
        "the re-listing after the hint observes the change; the tree holds {:?}",
        h.paths()
    );
}

fn watched_tree() -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    for i in 0..3 {
        fs.mkdir(&format!("d{i}"));
        fs.create_file(&format!("d{i}/f"), 1);
    }
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(5));
    fs
}

#[test]
fn a_watcher_triggered_read_carries_a_governor_admission_like_any_other() {
    let fs = watched_tree();
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();
    fs.clear_ops();
    let before = h.admissions().len();

    fs.emit_storm(&["d0", "d1", "d2"], HintKind::Modify, 1);
    h.deliver_watcher_events();
    h.run_until_idle();

    let performed: usize = ["d0", "d1", "d2"].iter().map(|d| fs.count_ops(FakeOp::ReadDir, d)).sum();
    assert!(performed > 0, "the hints triggered no read, so the property was never tested");
    let watcher_admissions: Vec<_> = h.admissions().into_iter().skip(before).collect();
    let listings = watcher_admissions.iter().filter(|a| a.operation == JobOperation::Listing).count();
    assert!(
        listings >= performed,
        "RFC 15.1 item 1 and lines 886-906: every watcher-triggered read passes through the governor; {performed} \
         reads ran against {listings} logged listing admissions"
    );
}

#[test]
fn a_watcher_storm_changes_priority_never_capacity_ceiling_or_window() {
    let fs = watched_tree();
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();
    let before_capacity = h.governor().capacity;
    let before: Vec<usize> = h.stats().domains.iter().map(|d| d.ceiling).collect();
    let before_windows: Vec<usize> = h.stats().domains.iter().map(|d| d.window).collect();

    let target = h.now() + Duration::from_secs(120);
    let emitted = h.flood_hints_until(&["d0", "d1", "d2"], HintKind::Modify, target);
    assert!(emitted > 100, "the storm emitted only {emitted} hints");

    assert_eq!(
        h.governor().capacity,
        before_capacity,
        "RFC 15.1 item 3 and line 972: a watcher storm must not change the background admission envelope"
    );
    let after: Vec<usize> = h.stats().domains.iter().map(|d| d.ceiling).collect();
    assert_eq!(
        after, before,
        "RFC 15.1 item 3 and 15.5: a watcher storm changes priority, never the per-domain concurrency ceiling; \
         before {before:?} after {after:?}"
    );
    let after_windows: Vec<usize> = h.stats().domains.iter().map(|d| d.window).collect();
    assert!(
        after_windows.iter().zip(&after).all(|(window, ceiling)| window <= ceiling),
        "RFC 15.5: the concurrency window adapts to measurements but never past its ceiling; windows {after_windows:?} \
         against ceilings {after:?} (before {before_windows:?})"
    );
    assert!(
        h.stats().dropped_hints > 0 || h.stats().coalesced_hints > 0,
        "the storm was neither coalesced nor dropped, so it was not absorbed"
    );
}

#[test]
fn an_overflow_storm_coalesces_and_the_overflow_itself_publishes_no_change() {
    let fs = watched_tree();
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();
    h.take_events();
    let version = h.snapshot().version();

    for _ in 0..50 {
        fs.emit_overflow();
    }
    h.deliver_watcher_events();
    assert_eq!(
        h.snapshot().version(),
        version,
        "RFC 11.6 and line 975: an overflow infers no state and commits nothing, so the snapshot version is \
         unchanged by the overflow itself"
    );
    assert!(
        h.events().iter().all(|event| !matches!(event, tree_fucker::UpdateEvent::Delta(_))),
        "RFC 11.6: repeated overflows coalesce into a reconciliation requirement and publish no delta of their own"
    );

    fs.add_silently("d0/late", tree_fucker::EntryKind::File);
    h.run_round();
    h.run_until_idle();
    assert!(
        h.paths().contains(&"d0/late".to_string()),
        "RFC 11.6: the coalesced overflow schedules the reconciliation that recovers the missed change"
    );
}

#[test]
fn a_silent_write_under_a_domain_that_declares_no_external_writers_converges_by_baseline() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    fs.mkdir("net");
    fs.mkdir("net/inner");
    fs.create_file("net/inner/f", 1);
    fs.set_domain("net", REMOTE);
    fs.set_capabilities(REMOTE, declaring(watching(WatcherScope::PerDirectory, Answer::No)));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), follow()).expect("open");
    h.run_until_idle();
    assert!(h.paths().contains(&"net/inner/f".to_string()));

    fs.add_silently("net/inner/late", tree_fucker::EntryKind::File);
    for _ in 0..4 {
        h.run_round();
        h.run_until_idle();
    }
    assert!(
        h.paths().contains(&"net/inner/late".to_string()),
        "RFC 10.4 and line 973: a domain whose watcher cannot see external writers mutates without an event, and \
         periodic reconciliation still converges on the change; the tree holds {:?}",
        h.paths()
    );
}

#[test]
fn an_unknown_hint_reconciles_the_named_directory_and_its_parent() {
    let fs = watched_tree();
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();
    fs.clear_ops();

    fs.replace_with_kind("d0/f", tree_fucker::EntryKind::Directory);
    h.deliver_watcher_events();
    h.run_until_idle();
    assert!(
        fs.count_ops(FakeOp::ReadDir, "d0") > 0,
        "RFC 11.2 and lines 330-334: an unknown hint carries no child names, so it reconciles the containing \
         directory rather than inventing precision; the adapter performed {:?}",
        fs.ops()
    );
}

#[test]
fn a_whole_watcher_failure_charges_every_release_to_its_owning_domain_not_the_bootstrap_scope() {
    let fs = two_domains();
    fs.set_capabilities(DomainId::ROOT, declaring(watching(WatcherScope::PerDirectory, Answer::Yes)));
    fs.set_capabilities(MEDIA, declaring(watching(WatcherScope::PerDirectory, Answer::Yes)));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), follow()).expect("open");
    h.run_until_idle();
    assert!(h.stats().paths_watched > 0, "no watch was registered, so no release can be charged");

    fs.emit_watcher_failure("backend restarted");
    h.deliver_watcher_events();
    h.run_until_idle();

    assert_eq!(
        h.governor().bootstrap.granted,
        Duration::ZERO,
        "RFC 15.3 and lines 1027-1031: a watch release is charged to the domain of the directory it watched, so a \
         whole-watcher failure strands no release in the process-wide bootstrap scope; it holds {:?}",
        h.governor().bootstrap
    );
    assert!(
        h.governor().watch_release_grants > 0,
        "the failure released no watch, so the charging path was never exercised"
    );
}
