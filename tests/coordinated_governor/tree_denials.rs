use std::time::Instant;

use tree_fucker::core::{Command, JobResult};
use tree_fucker::testing::{CostScope, FakeFileSystem, FakeOp, Harness, Ticket};
use tree_fucker::{
    Error, PathPredicate, ResourceLimit, ScanDecision, SessionCost, SessionStep, StorageDomainId, WatcherKind,
};

use super::*;

fn setup(
    ceiling: Duration,
    listing_cost: Duration,
) -> (tempfile::TempDir, Arc<Scope>, HostGovernor, Harness, StorageDomainId) {
    let (root, _) = fixture();
    let local = HostConfig {
        maximum_in_flight: 2,
        per_domain_concurrency: 2,
        background_burst: Duration::from_secs(1),
        domain_background_burst: Duration::from_secs(1),
        // Estimator setup measures real time, including scheduler delays.
        // Its ten-second deadline can include two simultaneous physical calls.
        // Keep duty capacity separate from the small command ceiling tested.
        foreground_burst: Duration::from_secs(60),
        domain_foreground_burst: Duration::from_secs(60),
        ..host_config()
    };
    let config = Config::from_host(&local, 8, 16, 16).unwrap();
    let scope = Scope::open(root.path().join("tree-ceiling"), config).unwrap();
    let host = HostGovernor::with_coordination(&local, scope.clone()).unwrap();
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.set_default_capabilities(tree_fucker::DomainCapabilities {
        topology: tree_fucker::AccessTopology::Local,
        ..tree_fucker::DomainCapabilities::inline()
    });
    fs.mkdir("child");
    fs.create_file("child/leaf", 1);
    let domain = StorageDomainId::of(&FakeFileSystem::domain_key(fs.domain_of(&RelativePath::root())));
    let policy = Arc::new(PathPredicate::new(|path: &RelativePath, _| ScanDecision::Eligible {
        initially_loaded: path.is_root(),
    }));
    let mut harness = Harness::open_under(
        fs.clone(),
        policy,
        tree_fucker::Config {
            foreground_ceiling_per_command: ceiling,
            fixed_interval: Some(Duration::from_secs(86400)),
            ..Default::default()
        },
        host.clone(),
    )
    .unwrap();
    let initial = harness.command(Command::InitialScanComplete);
    for _ in 0..20 {
        if harness.result(initial).is_some() {
            break;
        }
        assert!(harness.complete_next_job(), "initial scan must make progress");
    }
    assert_eq!(harness.result(initial), Some(Ok(())));
    for _ in 0..20 {
        if !harness.complete_next_job() {
            break;
        }
    }
    assert!(harness.pending_jobs().is_empty());
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, listing_cost);
    (root, scope, host, harness, domain)
}

fn raise_shared_minimum(host: &HostGovernor, domain: StorageDomainId, now: MonotonicTime) {
    prime_shared_minimum(host, domain, now, Duration::from_millis(10));
}

fn prime_shared_minimum(host: &HostGovernor, domain: StorageDomainId, now: MonotonicTime, hold: Duration) {
    // Native accounting measures actual elapsed time; local accounting uses
    // the harness clock. Fill the shared estimator's history while leaving
    // the local estimate unchanged, including when a Tree lease is live.
    let deadline = Instant::now() + Duration::from_secs(10);
    for _ in 0..32 {
        assert!(Instant::now() < deadline, "shared estimator setup exceeded ten seconds");
        let mut reservation = request(host);
        reservation.domain = Some(domain);
        let id = reservation.id;
        retry_setup(deadline, || host.try_admit(reservation.clone(), now));
        retry_setup(deadline, || host.try_start(id, now));
        std::thread::sleep(hold);
        host.release(id, now);
    }
    assert!(host.cost_of(Some(domain), 1) < Duration::from_millis(5));
}

fn retry_setup<T>(deadline: Instant, mut operation: impl FnMut() -> Result<T, ThrottleCause>) -> T {
    loop {
        match operation() {
            Ok(value) => return value,
            Err(ThrottleCause::Coordination) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(cause) => panic!("shared estimator setup admission failed: {cause}"),
        }
    }
}

fn command(load: bool) -> Command {
    if load {
        Command::Load(RelativePath::parse("child").unwrap())
    } else {
        Command::Refresh(vec![RelativePath::root()])
    }
}

fn assert_limited(harness: &Harness, ticket: Ticket, domain: StorageDomainId) {
    let Some(Err(Error::ResourceLimited(limited))) = harness.result(ticket) else {
        panic!("command must finish without a timer or refill: {:?}", harness.result(ticket));
    };
    assert_eq!(limited.limit, ResourceLimit::CommandWorkerTime);
    assert_eq!(limited.configured, 5_000_000);
    assert!(limited.observed >= 10_000_000);
    assert_eq!(limited.domain, Some(domain));
}

fn complete_background(harness: &mut Harness) {
    for _ in 0..20 {
        if !harness.complete_next_job() {
            break;
        }
    }
    assert!(harness.pending_jobs().is_empty());
}

#[test]
fn tree_commands_complete_when_initial_shared_admission_exceeds_their_ceiling() {
    for load in [false, true] {
        let (_root, scope, host, mut harness, domain) = setup(Duration::from_millis(5), Duration::from_millis(10));
        raise_shared_minimum(&host, domain, harness.now());
        let foreground = scope.view().unwrap().foreground_level_ns;
        let ticket = harness.command(command(load));
        assert_limited(&harness, ticket, domain);
        assert!(
            scope.view().unwrap().foreground_level_ns >= foreground,
            "denial must not charge the shared foreground allowance"
        );
        assert_eq!(host.view(harness.now()).preparations, 0);
        complete_background(&mut harness);
        harness.command(Command::Shutdown);
        assert_eq!(scope.view().unwrap().physical, 0);
    }
}

#[test]
fn tree_commands_complete_when_resumed_shared_admission_exceeds_their_ceiling() {
    for load in [false, true] {
        let (_root, scope, host, mut harness, domain) = setup(Duration::from_millis(5), Duration::from_millis(10));
        let ticket = harness.command(command(load));
        assert!(harness.result(ticket).is_none());
        let job = harness.pending_job_for(if load { "child" } else { "" }).unwrap();
        raise_shared_minimum(&host, domain, harness.now());
        assert!(harness.complete_job_with(
            job.id,
            JobResult::Listing(SessionStep::suspended(SessionCost { listing_operations: 1, ..SessionCost::default() }))
        ));
        assert_limited(&harness, ticket, domain);
        complete_background(&mut harness);
        let shared = scope.view().unwrap();
        assert_eq!((shared.prepared, shared.physical), (0, 0));
        harness.command(Command::Shutdown);
        assert_eq!(host.view(harness.now()).preparations, 0);
    }
}

#[test]
fn a_coalesced_refresh_with_enough_budget_survives_an_older_commands_ceiling() {
    let (_root, scope, host, mut harness, domain) = setup(Duration::from_secs(1), Duration::from_millis(995));
    raise_shared_minimum(&host, domain, harness.now());
    let older = harness.command(Command::Refresh(vec![RelativePath::root()]));
    assert!(harness.pending_job_for("").is_some());
    let fresh = harness.command(Command::Refresh(vec![RelativePath::root()]));
    assert!(harness.advance_to_next_completion());
    let Some(Err(Error::ResourceLimited(limited))) = harness.result(older) else {
        panic!("older command must complete: {:?}", harness.result(older));
    };
    assert!(limited.observed > limited.configured);
    assert!(harness.result(fresh).is_none(), "fresh command still has enough budget");
    let next_job = harness.pending_job_for("").expect("remaining command must dispatch without a timer");
    assert!(harness.complete_job(next_job.id));
    assert_eq!(harness.result(fresh), Some(Ok(())));
    harness.command(Command::Shutdown);
    assert_eq!(scope.view().unwrap().prepared, 0);
}

#[test]
fn tree_ceiling_setup_tolerates_slow_native_samples() {
    for resumed in [false, true] {
        let (_root, scope, host, mut harness, domain) = setup(Duration::from_millis(5), Duration::from_millis(10));
        let pending = resumed.then(|| {
            let ticket = harness.command(command(false));
            let job = harness.pending_job_for("").unwrap();
            (ticket, job.id)
        });
        prime_shared_minimum(&host, domain, harness.now(), Duration::from_millis(50));
        let ticket = match pending {
            Some((ticket, id)) => {
                assert!(harness.complete_job_with(
                    id,
                    JobResult::Listing(SessionStep::suspended(SessionCost {
                        listing_operations: 1,
                        ..SessionCost::default()
                    }))
                ));
                ticket
            }
            None => harness.command(command(false)),
        };
        assert_limited(&harness, ticket, domain);
        complete_background(&mut harness);
        harness.command(Command::Shutdown);
        let view = scope.view().unwrap();
        assert_eq!((view.prepared, view.physical), (0, 0));
    }
}

#[cfg(target_os = "linux")]
mod quarantine {
    use std::path::Path;

    use tree_fucker::domain::{DomainProbe, LinuxProbe};
    use tree_fucker::testing::DomainId;
    use tree_fucker::{DomainCapabilities, DomainCrossing, ResourceHealth};

    use super::*;

    const MOUNT: DomainId = DomainId::new(2);
    const STUCK_AFTER: Duration = Duration::from_millis(50);

    fn path(p: &str) -> RelativePath {
        RelativePath::parse(p).unwrap()
    }

    fn open(local: HostConfig) -> (tempfile::TempDir, Arc<Scope>, HostGovernor, Harness, StorageDomainId) {
        let (root, _) = fixture();
        let mut config = Config::from_host(&local, 8, 16, 16).unwrap();
        config.stuck_after_ns = STUCK_AFTER.as_nanos() as u64;
        config.ownership.physical = 2;
        config.per_domain_physical = 2;
        let scope = Scope::open(root.path().join("tree-quarantine"), config).unwrap();
        let host = HostGovernor::with_coordination(&local, scope.clone()).unwrap();
        let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
        fs.set_default_capabilities(tree_fucker::DomainCapabilities {
            topology: tree_fucker::AccessTopology::Local,
            ..DomainCapabilities::inline()
        });
        fs.mkdir("local");
        fs.create_file("local/leaf", 1);
        fs.mkdir("mnt");
        fs.create_file("mnt/leaf", 1);
        fs.set_domain("mnt", MOUNT);
        let key = LinuxProbe::new().probe(Path::new("/dev/shm"), None).unwrap().identity.key().unwrap().clone();
        fs.report_domain_key(MOUNT, key.clone());
        let domain = StorageDomainId::of(&key);
        let policy =
            Arc::new(PathPredicate::new(|_: &RelativePath, _| ScanDecision::Eligible { initially_loaded: true }));
        let mut harness = Harness::open_under(
            fs,
            policy,
            tree_fucker::Config {
                domain_crossing: DomainCrossing::Follow,
                fixed_interval: Some(Duration::from_secs(86400)),
                ..Default::default()
            },
            host.clone(),
        )
        .unwrap();
        let initial = harness.command(Command::InitialScanComplete);
        for _ in 0..40 {
            if harness.result(initial).is_some() {
                break;
            }
            assert!(harness.complete_next_job(), "initial scan must make progress");
        }
        assert_eq!(harness.result(initial), Some(Ok(())));
        for _ in 0..40 {
            if !harness.complete_next_job() {
                break;
            }
        }
        assert!(harness.pending_jobs().is_empty());
        (root, scope, host, harness, domain)
    }

    fn stick_peer(
        local: &HostConfig,
        scope: &Arc<Scope>,
        host: &HostGovernor,
        domain: StorageDomainId,
    ) -> (HostGovernor, GrantId) {
        let peer = HostGovernor::with_coordination(local, scope.clone()).unwrap();
        peer.register_domain(domain, &DomainCapabilities::inline(), NOW);
        let mut reservation = request(&peer);
        reservation.domain = Some(domain);
        let id = reservation.id;
        peer.try_admit(reservation, NOW).unwrap();
        peer.try_start(id, NOW).unwrap();
        std::thread::sleep(STUCK_AFTER + Duration::from_millis(10));
        assert!(!host.quarantined(Some(domain)), "only the shared authority knows the peer is stuck");
        (peer, id)
    }

    fn assert_cancelled_listing_resumes(
        harness: &mut Harness,
        host: &HostGovernor,
        peer: &HostGovernor,
        id: GrantId,
        refresh: Ticket,
        domain: StorageDomainId,
    ) {
        harness.advance(Duration::ZERO);
        assert_eq!(harness.result(refresh), None, "cancellation leaves the command waiting for the domain");
        assert_eq!(
            harness.health().resource_domains.get(&domain).copied(),
            Some(ResourceHealth::Throttled { cause: ThrottleCause::StuckWorker, resume: None }),
            "the Tree must report the peer's quarantine"
        );
        let retry = host.coordination_retry_at(harness.now());
        assert_eq!(harness.timer().map(|(_, at)| at), retry, "the quarantine retry must wake the Tree");
        peer.release(id, NOW);
        assert!(harness.fire_timer());
        assert_eq!(harness.result(refresh), Some(Ok(())));
        assert_eq!(harness.now(), NOW + Duration::from_millis(10), "the read waits for the quarantine deadline");
        assert_ne!(
            harness.health().resource_domains.get(&domain).and_then(ResourceHealth::cause),
            Some(ThrottleCause::StuckWorker),
            "shared admission clears the peer's quarantine"
        );
    }

    fn assert_healthy_domain_dispatches(harness: &mut Harness, host: &HostGovernor) {
        assert_eq!(host.view(NOW).preparations, 0, "the quarantined preparation must be released");
        harness.command(Command::Refresh(vec![path("local")]));
        let job = harness.pending_job_for("local").expect("the batch must not retain quarantined work");
        assert!(harness.complete_job(job.id));
    }

    #[test]
    fn a_queued_tree_job_cancels_when_shared_quarantine_denies_its_start() {
        let local = HostConfig { maximum_in_flight: 1, per_domain_concurrency: 1, ..host_config() };
        let (_root, scope, host, mut harness, domain) = open(local);
        let held = request(&host);
        let held_id = held.id;
        host.try_admit(held, NOW).unwrap();
        host.try_start(held_id, NOW).unwrap();
        let refresh = harness.command(Command::Refresh(vec![path("mnt")]));
        assert!(harness.pending_job_for("mnt").is_none(), "host capacity must hold the listing in the queue");
        assert_eq!(host.view(NOW).preparations, 1);
        let (peer, id) = stick_peer(&local, &scope, &host, domain);
        host.release(held_id, NOW);
        harness.advance(Duration::ZERO);
        assert!(harness.pending_job_for("mnt").is_none());
        assert_healthy_domain_dispatches(&mut harness, &host);
        assert_cancelled_listing_resumes(&mut harness, &host, &peer, id, refresh, domain);
        harness.command(Command::Shutdown);
        let shared = scope.view().unwrap();
        assert_eq!((shared.prepared, shared.physical), (0, 0));
    }

    #[test]
    fn a_suspended_tree_job_cancels_when_shared_quarantine_denies_its_resumption() {
        let local = HostConfig { maximum_in_flight: 2, per_domain_concurrency: 2, ..host_config() };
        let (_root, scope, host, mut harness, domain) = open(local);
        let refresh = harness.command(Command::Refresh(vec![path("mnt")]));
        let job = harness.pending_job_for("mnt").expect("mount listing dispatched");
        let (peer, id) = stick_peer(&local, &scope, &host, domain);
        assert!(harness.complete_job_with(
            job.id,
            JobResult::Listing(SessionStep::suspended(SessionCost { listing_operations: 1, ..SessionCost::default() }))
        ));
        assert!(harness.pending_job_for("mnt").is_none());
        assert_healthy_domain_dispatches(&mut harness, &host);
        assert_cancelled_listing_resumes(&mut harness, &host, &peer, id, refresh, domain);
        harness.command(Command::Shutdown);
        let shared = scope.view().unwrap();
        assert_eq!((shared.prepared, shared.physical), (0, 0));
    }
}
