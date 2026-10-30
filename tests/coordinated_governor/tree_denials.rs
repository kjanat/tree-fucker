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
        domain_foreground_burst: Duration::from_secs(1),
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
    // Native accounting measures actual elapsed time; local accounting uses
    // the harness clock. Fill the shared estimator's history while leaving
    // the local estimate unchanged, including when a Tree lease is live.
    for _ in 0..32 {
        let mut reservation = request(host);
        reservation.domain = Some(domain);
        let id = reservation.id;
        host.try_admit(reservation, now).unwrap();
        host.try_start(id, now).unwrap();
        std::thread::sleep(Duration::from_millis(10));
        host.release(id, now);
    }
    assert!(host.cost_of(Some(domain), 1) < Duration::from_millis(5));
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
