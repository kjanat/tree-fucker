use std::num::NonZeroU32;
use std::time::Duration;

use tree_fucker::core::{GrantId, MonotonicTime, Reservation, WorkOrigin};
use tree_fucker::{DomainCapabilities, HostConfig, HostGovernor, RelativePath, StorageDomainId, ThrottleCause};

const NOW: MonotonicTime = MonotonicTime::ZERO;

fn config() -> HostConfig {
    HostConfig {
        initial_cost_estimate: Duration::from_millis(10),
        foreground_burst: Duration::from_millis(20),
        domain_foreground_burst: Duration::from_millis(20),
        bootstrap_allowance: Duration::from_millis(20),
        ..Default::default()
    }
}

fn request(governor: &HostGovernor, domain: Option<StorageDomainId>) -> Reservation {
    Reservation {
        id: GrantId::Bootstrap(governor.next_bootstrap()),
        path: RelativePath::root(),
        reads: 1,
        registrations: 0,
        operations: 0,
        ceiling: None,
        lease: 0,
        domain,
        origin: WorkOrigin::Foreground,
        listing: false,
    }
}

#[test]
fn repeated_shared_denials_do_not_charge_local_work() {
    let governor = HostGovernor::independent(&config());
    for _ in 0..100 {
        let prepared = governor.try_prepare(request(&governor, None), NOW).unwrap();
        let view = governor.view(NOW);
        assert_eq!(view.preparations, 1);
        assert_eq!(view.prepared, Duration::from_millis(10));
        assert_eq!(view.charged, Duration::ZERO);
        assert_eq!(view.in_flight, 0);
        drop(prepared); // Other authority denied; retry later.
    }
    let view = governor.view(NOW);
    assert_eq!(view.preparations, 0);
    assert_eq!(view.grants, 0);
    assert_eq!(view.charged, Duration::ZERO);
    assert_eq!(view.foreground_level, config().foreground_burst);
}

#[test]
fn other_admissions_observe_prepared_budget_and_abort_returns_it() {
    let governor = HostGovernor::independent(&config());
    let first = governor.try_prepare(request(&governor, None), NOW).unwrap();
    let second = governor.try_prepare(request(&governor, None), NOW).unwrap();
    assert_eq!(governor.try_admit(request(&governor, None), NOW), Err(ThrottleCause::ForegroundCeiling));
    assert!(governor.global_exhausted(None, WorkOrigin::Foreground));
    assert_eq!(governor.throttle(NOW), Some((ThrottleCause::ForegroundCeiling, None)));
    let changes = governor.changes();
    drop(second);
    assert_ne!(governor.changes(), changes, "abort wakes waiters whose capacity was held");
    assert_eq!(governor.throttle(NOW), None);
    governor.try_admit(request(&governor, None), NOW).unwrap();
    assert_eq!(governor.try_admit(request(&governor, None), NOW), Err(ThrottleCause::ForegroundCeiling));
    first.commit(NOW).unwrap();
    let view = governor.view(NOW);
    assert_eq!(view.prepared, Duration::ZERO);
    assert_eq!(view.charged, Duration::from_millis(20));
    assert_eq!(view.grants, 2);
    assert_eq!(view.in_flight, 0);
}

#[test]
fn abort_after_refill_does_not_mint_capacity() {
    let governor = HostGovernor::independent(&config());
    let held = governor.try_prepare(request(&governor, None), NOW).unwrap();
    let later = MonotonicTime(Duration::from_secs(100));
    governor.account(later);
    drop(held);
    let view = governor.view(later);
    assert_eq!(view.foreground_level, config().foreground_burst);
    assert_eq!(view.charged, Duration::ZERO);
    for _ in 0..2 {
        governor.try_admit(request(&governor, None), later).unwrap();
    }
    assert_eq!(governor.try_admit(request(&governor, None), later), Err(ThrottleCause::ForegroundCeiling));
}

#[test]
fn commit_revalidates_memory_and_does_not_charge_failed_preparation() {
    let governor = HostGovernor::independent(&config());
    let prepared = governor.try_prepare(request(&governor, None), NOW).unwrap();
    let owner = governor.next_tree();
    governor.report_memory(owner, governor.memory_ceiling() + 1, 0);
    assert_eq!(prepared.commit(NOW), Err(ThrottleCause::Memory));
    let view = governor.view(NOW);
    assert_eq!(view.preparations, 0);
    assert_eq!(view.charged, Duration::ZERO);
}

#[test]
fn preparation_table_is_bounded_and_duplicate_ids_do_not_replace_ownership() {
    let governor =
        HostGovernor::independent(&HostConfig { maximum_in_flight: 1, per_domain_concurrency: 1, ..config() });
    let request = request(&governor, None);
    let prepared = governor.try_prepare(request.clone(), NOW).unwrap();
    assert_eq!(governor.try_start(request.id, NOW), Err(ThrottleCause::Concurrency));
    assert!(matches!(governor.try_prepare(request.clone(), NOW), Err(ThrottleCause::Concurrency)));
    assert_eq!(governor.try_admit(request.clone(), NOW), Err(ThrottleCause::Concurrency));
    prepared.commit(NOW).unwrap();
    assert_eq!(governor.try_admit(request.clone(), NOW), Err(ThrottleCause::Concurrency));
    assert_eq!(governor.view(NOW).grants, 1);
    governor.release(request.id, NOW);
    assert_eq!(governor.try_start(request.id, NOW), Err(ThrottleCause::Concurrency));
}

#[test]
fn committed_lease_cannot_exceed_either_prepared_operation_allowance() {
    let governor = HostGovernor::independent(&HostConfig {
        foreground_burst: Duration::from_secs(1),
        domain_foreground_burst: Duration::from_secs(1),
        bootstrap_allowance: Duration::from_secs(1),
        ..config()
    });
    let mut reservation = request(&governor, None);
    reservation.reads = 0;
    reservation.operations = 64;
    let mut prepared = governor.try_prepare(reservation, NOW).unwrap();
    assert_eq!(prepared.admitted().operations, 64);
    prepared.limit_operations(NonZeroU32::new(12).unwrap());
    let admitted = prepared.commit(NOW).unwrap();
    assert_eq!(admitted.operations, 12);
    assert_eq!(admitted.cost, Duration::from_millis(120));
    assert_eq!(governor.view(NOW).charged, admitted.cost);
}

#[test]
fn per_domain_and_bootstrap_holds_do_not_multiply_allowances() {
    let governor = HostGovernor::independent(&HostConfig {
        foreground_burst: Duration::from_secs(1),
        bootstrap_allowance: Duration::from_millis(10),
        ..config()
    });
    let a = StorageDomainId::fresh();
    let b = StorageDomainId::fresh();
    for domain in [a, b] {
        governor.register_domain(domain, &DomainCapabilities::default(), NOW);
    }
    let a1 = governor.try_prepare(request(&governor, Some(a)), NOW).unwrap();
    let a2 = governor.try_prepare(request(&governor, Some(a)), NOW).unwrap();
    assert_eq!(governor.try_admit(request(&governor, Some(a)), NOW), Err(ThrottleCause::ForegroundCeiling));
    governor.try_admit(request(&governor, Some(b)), NOW).unwrap();
    let bootstrap = governor.try_prepare(request(&governor, None), NOW).unwrap();
    assert_eq!(governor.try_admit(request(&governor, None), NOW), Err(ThrottleCause::DutyBudget));
    drop((a1, a2, bootstrap));
    assert_eq!(governor.view(NOW).charged, Duration::from_millis(10));
}
