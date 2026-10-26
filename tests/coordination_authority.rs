use tree_fucker::coordination::authority::{
    Authority, Budget, Config, DomainId, Error, Origin, Request, SharedDomainKey,
};
use tree_fucker::coordination::protocol::{
    Error as ProtocolError, Generation, Limits, OperationId, Participant, Progress, VERSION, Work,
};

fn config() -> Config {
    Config {
        ownership: Limits { participants: 20, operations: 32, physical: 2 },
        domains: 8,
        background: Budget { refill_ns_per_second: 1, burst_ns: 100 },
        foreground: Budget { refill_ns_per_second: 1, burst_ns: 100 },
        domain_background: Budget { refill_ns_per_second: 1, burst_ns: 100 },
        domain_foreground: Budget { refill_ns_per_second: 1, burst_ns: 100 },
        bootstrap_ns: 100,
        per_domain_physical: 2,
        initial_estimate_ns: 10,
        stuck_after_ns: 1000,
        failure_surcharge_ns: 7,
    }
}

fn authority() -> Authority {
    Authority::new(Generation([1; 16]), config(), 0).unwrap()
}

fn domain(authority: &mut Authority, id: u8) -> DomainId {
    authority
        .register_shared_domain(SharedDomainKey { namespace: [1; 16], filesystem: [id; 16], incarnation: [1; 16] })
        .unwrap()
}

fn request(domain: Option<DomainId>) -> Request {
    Request { work: Work::LazyRead, origin: Origin::Foreground, domain, required: 1, desired: 0, ceiling_ns: u64::MAX }
}

fn prepare(authority: &mut Authority, participant: Participant, request: Request, now: u64) -> OperationId {
    let id = authority.ledger().next_operation(participant).unwrap();
    authority.prepare(id, request, now).unwrap();
    id
}

fn completed(elapsed_ns: u64) -> Progress {
    Progress { revision: 1, operations: 1, elapsed_ns, failed: false }
}

#[test]
fn many_participants_cannot_multiply_global_or_domain_allowances() {
    let mut authority = authority();
    let domain = domain(&mut authority, 1);
    let participants: Vec<_> = (0..20).map(|_| authority.join(VERSION).unwrap()).collect();
    let mut ids = Vec::new();
    for participant in &participants[..10] {
        ids.push(prepare(&mut authority, *participant, request(Some(domain)), 0));
    }
    for participant in &participants[10..] {
        let id = authority.ledger().next_operation(*participant).unwrap();
        assert_eq!(authority.prepare(id, request(Some(domain)), 0), Err(Error::Budget));
    }
    authority.authorize(ids[0], 0).unwrap();
    authority.authorize(ids[1], 0).unwrap();
    assert_eq!(authority.authorize(ids[2], 0), Err(Error::DomainPhysical));
    assert_eq!(authority.view().physical, 2);
    assert_eq!(authority.view().charged_ns, 20);
    assert!(authority.cancel(ids[0], 0).unwrap());
    assert_eq!(authority.view().physical, 2);
    authority.settle(ids[0], completed(0), 0).unwrap();
    authority.authorize(ids[2], 0).unwrap();
    assert_eq!(authority.view().physical, 2);
    assert_eq!(authority.view().charged_ns, 30);
}

#[test]
fn provisional_denials_and_aborts_neither_spend_nor_mint_budget() {
    let mut authority = authority();
    let participant = authority.join(VERSION).unwrap();
    for _ in 0..100 {
        let id = prepare(&mut authority, participant, request(None), 0);
        assert!(!authority.cancel(id, 0).unwrap());
    }
    let view = authority.view();
    assert_eq!(view.foreground_level_ns, 100);
    assert_eq!(view.charged_ns, 0);
    assert_eq!(view.bootstrap_reserved_ns, 0);
    assert_eq!(view.physical, 0);
}

#[test]
fn last_participant_exit_retains_real_bucket_debt() {
    let mut authority = authority();
    let participant = authority.join(VERSION).unwrap();
    let id = prepare(&mut authority, participant, request(None), 0);
    authority.authorize(id, 0).unwrap();
    authority.settle(id, completed(250), 250).unwrap();
    authority.leave(participant).unwrap();
    assert_eq!(authority.view().participants, 0);
    assert_eq!(authority.view().foreground_level_ns, -150);
    let replacement = authority.join(VERSION).unwrap();
    let next = authority.ledger().next_operation(replacement).unwrap();
    assert_ne!(replacement.incarnation, participant.incarnation);
    assert_eq!(authority.prepare(next, request(None), 250), Err(Error::Budget));
    assert_eq!(authority.view().foreground_level_ns, -150);
    authority.advance(160_000_000_250).unwrap();
    authority.prepare(next, request(None), 160_000_000_250).unwrap();
    assert_eq!(authority.view().foreground_level_ns, 10);
}

#[test]
fn ambiguous_owner_exit_reconciles_cost_without_resetting_the_scope() {
    let mut authority = authority();
    let participant = authority.join(VERSION).unwrap();
    let id = prepare(&mut authority, participant, request(None), 0);
    authority.authorize(id, 0).unwrap();
    authority.reclaim_after_owner_exit(id, 80).unwrap();
    assert_eq!(authority.view().foreground_level_ns, 20);
    assert_eq!(authority.view().charged_ns, 80);
    assert_eq!(authority.view().surcharged_ns, 7);
    assert_eq!(authority.view().physical, 0);
    authority.reclaim_after_owner_exit(id, 80).unwrap();
    assert_eq!(authority.view().surcharged_ns, 7);
    authority.leave(participant).unwrap();
    assert_eq!(authority.view().foreground_level_ns, 20);
}

#[test]
fn stuck_work_keeps_occupancy_and_defers_only_its_global_debt() {
    let mut cfg = config();
    cfg.stuck_after_ns = 20;
    let mut authority = Authority::new(Generation([1; 16]), cfg, 0).unwrap();
    let a = domain(&mut authority, 1);
    let b = domain(&mut authority, 2);
    let participant = authority.join(VERSION).unwrap();
    let stuck = prepare(&mut authority, participant, request(Some(a)), 0);
    authority.authorize(stuck, 0).unwrap();
    authority.advance(20).unwrap();
    assert_eq!(authority.view().foreground_level_ns, 80);
    assert_eq!(authority.view().surcharged_ns, 7);
    assert!(authority.cancel(stuck, 40).unwrap());
    assert_eq!(authority.view().physical, 1);
    assert_eq!(authority.view().foreground_level_ns, 80);
    assert_eq!(authority.view().withheld_ns, 20);
    let next = authority.ledger().next_operation(participant).unwrap();
    assert_eq!(authority.prepare(next, request(Some(a)), 40), Err(Error::Quarantined));
    let healthy = prepare(&mut authority, participant, request(Some(b)), 40);
    authority.authorize(healthy, 40).unwrap();
    assert_eq!(authority.view().physical, 2);
    authority.settle(stuck, Progress { failed: true, ..completed(40) }, 40).unwrap();
    assert_eq!(authority.view().physical, 1);
    assert_eq!(authority.view().foreground_level_ns, 50);
    assert_eq!(authority.view().withheld_ns, 0);
    assert_eq!(authority.view().surcharged_ns, 7);
}

#[test]
fn cleanup_exempts_duty_but_never_exempts_physical_capacity() {
    let mut cfg = config();
    cfg.ownership.physical = 1;
    cfg.per_domain_physical = 1;
    let mut authority = Authority::new(Generation([1; 16]), cfg, 0).unwrap();
    let participant = authority.join(VERSION).unwrap();
    let id = prepare(&mut authority, participant, request(None), 0);
    authority.authorize(id, 0).unwrap();
    authority.advance(150).unwrap();
    let cleanup_request = Request { work: Work::WatchRelease, ..request(None) };
    let cleanup = prepare(&mut authority, participant, cleanup_request, 150);
    assert_eq!(authority.authorize(cleanup, 150), Err(Error::Protocol(ProtocolError::PhysicalCapacity)));
    assert_eq!(authority.view().charged_ns, 150);
    authority.settle(id, completed(150), 150).unwrap();
    authority.authorize(cleanup, 150).unwrap();
    assert_eq!(authority.view().physical, 1);
    assert_eq!(authority.view().foreground_level_ns, -60);
}

#[test]
fn shared_identity_is_namespace_qualified_and_private_numbers_do_not_match() {
    let mut authority = authority();
    let a = authority.join(VERSION).unwrap();
    let b = authority.join(VERSION).unwrap();
    let key = SharedDomainKey { namespace: [1; 16], filesystem: [2; 16], incarnation: [3; 16] };
    let shared = authority.register_shared_domain(key).unwrap();
    assert_eq!(authority.register_shared_domain(key).unwrap(), shared);
    assert_ne!(authority.register_shared_domain(SharedDomainKey { namespace: [4; 16], ..key }).unwrap(), shared);
    assert_ne!(authority.register_shared_domain(SharedDomainKey { incarnation: [4; 16], ..key }).unwrap(), shared);
    assert_ne!(authority.register_private_domain(a, 7).unwrap(), authority.register_private_domain(b, 7).unwrap());
    assert_eq!(authority.register_private_domain(a, 7).unwrap(), authority.register_private_domain(a, 7).unwrap());
}

#[test]
fn bounded_domain_accounts_are_not_evicted_to_forgive_debt() {
    let mut cfg = config();
    cfg.domains = 1;
    let mut authority = Authority::new(Generation([1; 16]), cfg, 0).unwrap();
    let participant = authority.join(VERSION).unwrap();
    let held = domain(&mut authority, 1);
    let id = prepare(&mut authority, participant, request(Some(held)), 0);
    authority.authorize(id, 0).unwrap();
    authority.settle(id, completed(150), 150).unwrap();
    authority.leave(participant).unwrap();
    assert_eq!(
        authority.register_shared_domain(SharedDomainKey {
            namespace: [1; 16],
            filesystem: [2; 16],
            incarnation: [1; 16],
        }),
        Err(Error::DomainCapacity)
    );
    assert_eq!(domain(&mut authority, 1), held);
    assert_eq!(authority.view().domains, 1);
}

#[test]
fn sparse_snapshots_can_grow_to_domain_capacity_without_losing_live_accounting() {
    for initial_domains in [0, 1, 5] {
        let mut config = config();
        config.domains = 9;
        let mut authority = Authority::new(Generation([1; 16]), config, 0).unwrap();
        let participant = authority.join(VERSION).unwrap();
        let domains: Vec<_> = (0..initial_domains).map(|index| domain(&mut authority, index)).collect();
        let id = prepare(&mut authority, participant, request(domains.first().copied()), 0);
        authority.authorize(id, 0).unwrap();
        let progress = completed(25);
        authority.report(id, progress, 25).unwrap();
        let mut restored = Authority::decode(&authority.encode().unwrap()).unwrap();
        assert_eq!(restored, authority);
        let charged = restored.view().charged_ns;
        for index in initial_domains..config.domains as u8 {
            let added = domain(&mut restored, index);
            assert_eq!(added.slot, u32::from(index));
            assert_eq!(restored.view().physical, 1);
            assert_eq!(restored.view().charged_ns, charged);
            for (index, expected) in domains.iter().enumerate() {
                assert_eq!(domain(&mut restored, index as u8), *expected);
            }
            restored = Authority::decode(&restored.encode().unwrap()).unwrap();
        }
        assert_eq!(
            restored.register_shared_domain(SharedDomainKey {
                namespace: [1; 16],
                filesystem: [99; 16],
                incarnation: [1; 16],
            }),
            Err(Error::DomainCapacity)
        );
        restored.settle(id, progress, 25).unwrap();
        restored.settle(id, progress, 25).unwrap();
        assert_eq!(restored.view().charged_ns, charged);
        assert_eq!(restored.view().physical, 0);
    }
}

#[test]
fn retrying_reports_and_settlement_never_double_charges_or_fails_twice() {
    let mut authority = authority();
    let participant = authority.join(VERSION).unwrap();
    let id = prepare(&mut authority, participant, request(None), 0);
    authority.authorize(id, 0).unwrap();
    authority.authorize(id, 0).unwrap();
    let progress = Progress { failed: true, ..completed(30) };
    authority.report(id, progress, 30).unwrap();
    authority.report(id, progress, 30).unwrap();
    authority.settle(id, progress, 30).unwrap();
    authority.settle(id, progress, 30).unwrap();
    assert_eq!(authority.view().charged_ns, 30);
    assert_eq!(authority.view().surcharged_ns, 7);
    assert_eq!(authority.view().foreground_level_ns, 70);
}

#[test]
fn fractional_refill_is_independent_of_access_frequency() {
    let mut bulk = authority();
    let participant = bulk.join(VERSION).unwrap();
    let id = prepare(&mut bulk, participant, request(None), 0);
    bulk.authorize(id, 0).unwrap();
    bulk.settle(id, completed(0), 0).unwrap();
    let mut frequent = bulk.clone();
    bulk.advance(1_000_000_000).unwrap();
    for step in 1..=100 {
        frequent.advance(step * 10_000_000).unwrap();
    }
    assert_eq!(frequent, bulk);
    assert_eq!(bulk.view().foreground_level_ns, 91);
}

#[test]
fn narrowing_a_lease_frees_held_budget_at_the_original_unit_price() {
    let mut authority = authority();
    let participant = authority.join(VERSION).unwrap();
    let id = prepare(
        &mut authority,
        participant,
        Request { work: Work::Listing, required: 0, desired: 10, ..request(None) },
        0,
    );
    assert_eq!(authority.narrow(id, 4).unwrap().cost_ns, 40);
    let next = prepare(&mut authority, participant, Request { required: 0, desired: 6, ..request(None) }, 0);
    authority.authorize(id, 0).unwrap();
    authority.authorize(next, 0).unwrap();
    assert_eq!(authority.view().charged_ns, 100);
    assert_eq!(authority.narrow(id, 1), Err(Error::Protocol(ProtocolError::InvalidTransition)));
}

#[test]
fn a_failed_start_attempt_does_not_consume_its_prepared_budget() {
    let mut cfg = config();
    cfg.ownership.physical = 1;
    cfg.per_domain_physical = 1;
    let mut authority = Authority::new(Generation([1; 16]), cfg, 0).unwrap();
    let participant = authority.join(VERSION).unwrap();
    let first = prepare(&mut authority, participant, request(None), 0);
    let second = prepare(&mut authority, participant, request(None), 0);
    authority.authorize(first, 0).unwrap();
    for _ in 0..10 {
        assert_eq!(authority.authorize(second, 0), Err(Error::Protocol(ProtocolError::PhysicalCapacity)));
    }
    assert!(!authority.cancel(second, 0).unwrap());
    assert_eq!(authority.view().charged_ns, 10);
    assert_eq!(authority.view().foreground_level_ns, 90);
}

#[test]
fn snapshot_round_trip_retains_preparations_occupancy_debt_and_incarnations() {
    let mut authority = authority();
    let participant = authority.join(VERSION).unwrap();
    let private = authority.register_private_domain(participant, 42).unwrap();
    let prepared = prepare(&mut authority, participant, request(Some(private)), 0);
    let running = prepare(&mut authority, participant, request(None), 0);
    authority.authorize(running, 0).unwrap();
    authority.advance(1200).unwrap();
    authority.advance(1300).unwrap();
    let bytes = authority.encode().unwrap();
    let mut recovered = Authority::decode(&bytes).unwrap();
    assert_eq!(recovered, authority);
    assert_eq!(recovered.view().physical, 1);
    assert_eq!(recovered.view().withheld_ns, 100);
    assert_eq!(recovered.encode().unwrap(), bytes);
    recovered.cancel(prepared, 1300).unwrap();
    recovered.reclaim_after_owner_exit(running, 1400).unwrap();
    recovered.leave(participant).unwrap();
    let recovered = Authority::decode(&recovered.encode().unwrap()).unwrap();
    assert_eq!(recovered.view().participants, 0);
    assert_eq!(recovered.view().foreground_level_ns, -1300);
    assert_eq!(recovered.view().charged_ns, 1400);
}

#[test]
fn every_truncation_and_single_byte_corruption_is_rejected() {
    let mut authority = authority();
    let participant = authority.join(VERSION).unwrap();
    let private = authority.register_private_domain(participant, 42).unwrap();
    let id = prepare(&mut authority, participant, request(Some(private)), 0);
    authority.authorize(id, 0).unwrap();
    let bytes = authority.encode().unwrap();
    for length in 0..bytes.len() {
        assert!(Authority::decode(&bytes[..length]).is_err(), "truncation at {length}");
    }
    for index in 0..bytes.len() {
        let mut corrupted = bytes.clone();
        corrupted[index] ^= 1;
        assert!(Authority::decode(&corrupted).is_err(), "corruption at {index}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Authority::decode(&trailing).is_err());
}

#[test]
fn narrowing_to_required_work_still_round_trips() {
    let mut authority = authority();
    let participant = authority.join(VERSION).unwrap();
    let id = prepare(&mut authority, participant, Request { desired: 4, ..request(None) }, 0);
    assert_eq!(authority.narrow(id, 0).unwrap().operations, 1);
    assert_eq!(Authority::decode(&authority.encode().unwrap()).unwrap(), authority);
}
