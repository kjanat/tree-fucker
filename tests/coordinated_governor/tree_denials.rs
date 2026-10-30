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

#[test]
fn tree_commands_complete_when_initial_shared_admission_exceeds_their_ceiling() {
    for load in [false, true] {
        let (_root, scope, host, mut harness, domain) = setup(Duration::from_millis(5), Duration::from_millis(10));
        raise_shared_minimum(&host, domain, harness.now());
        let charged = scope.view().unwrap().charged_ns;
        let ticket = harness.command(command(load));
        assert_limited(&harness, ticket, domain);
        assert_eq!(scope.view().unwrap().charged_ns, charged, "denial must not charge shared work");
        assert_eq!(host.view(harness.now()).preparations, 0);
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
        harness.command(Command::Shutdown);
        let view = scope.view().unwrap();
        assert_eq!((view.prepared, view.physical), (0, 0));
    }
}
