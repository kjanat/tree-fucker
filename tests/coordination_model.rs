//! Deterministic ownership histories; OS storage and lifetime evidence are
//! separate acceptance layers.

use tree_fucker::coordination::protocol::{
    Effect, Error, Generation, Ledger, Limits, OperationId, Phase, Progress, Reservation, VERSION, Work,
};

fn ledger(physical: u32) -> Ledger {
    Ledger::new(Generation([1; 16]), Limits { participants: 2, operations: 4, physical }).unwrap()
}

fn request(work: Work) -> Reservation {
    Reservation { work, operations: 4, estimated_ns: 10 }
}

fn prepared(ledger: &mut Ledger) -> OperationId {
    let participant = ledger.join(VERSION).unwrap();
    let id = ledger.next_operation(participant).unwrap();
    ledger.prepare(id, request(Work::Listing)).unwrap();
    id
}

#[test]
fn authorization_occupies_capacity_before_running_acknowledgment() {
    let mut ledger = ledger(1);
    let first = prepared(&mut ledger);
    let second = prepared(&mut ledger);
    assert_eq!(ledger.authorize(first, 10).unwrap().charged_ns, 10);
    assert_eq!(ledger.physical(), 1);
    assert_eq!(ledger.authorize(second, 10), Err(Error::PhysicalCapacity));

    let before = ledger.clone();
    assert!(ledger.cancel(first).unwrap().detached);
    assert_eq!(ledger, before, "cancelled interest cannot release potentially running work");
    assert_eq!(ledger.authorize(first, 999).unwrap(), Effect::default());
    assert_eq!(ledger.record(first).unwrap().authorized_at, Some(10));
    assert_eq!(ledger.physical(), 1);

    ledger.running(first).unwrap();
    ledger.settle(first, Progress { revision: 1, operations: 4, elapsed_ns: 20, failed: false }).unwrap();
    assert_eq!(ledger.physical(), 0);
    ledger.authorize(second, 30).unwrap();
    assert_eq!(ledger.physical(), 1);
}

#[test]
fn abort_is_reversible_and_terminal_ids_cannot_be_prepared_again() {
    let mut ledger = ledger(1);
    let id = prepared(&mut ledger);
    assert_eq!(ledger.cancel(id).unwrap(), Effect { aborted_ns: 10, ..Effect::default() });
    assert_eq!(ledger.cancel(id).unwrap(), Effect::default());
    assert_eq!(ledger.prepare(id, request(Work::Listing)), Err(Error::RetiredOperation));
    assert_eq!(ledger.authorize(id, 10), Err(Error::RetiredOperation));
    assert_eq!(ledger.physical(), 0);
    let next = ledger.next_operation(id.participant).unwrap();
    assert_eq!(next.sequence, id.sequence + 1);
    ledger.prepare(next, request(Work::LazyRead)).unwrap();
}

#[test]
fn reused_participant_slot_does_not_accept_previous_incarnation() {
    let mut ledger = ledger(1);
    let old = prepared(&mut ledger);
    assert_eq!(ledger.leave(old.participant), Err(Error::ParticipantBusy));
    ledger.cancel(old).unwrap();
    ledger.leave(old.participant).unwrap();
    let new = prepared(&mut ledger);
    assert_eq!(old.participant.slot, new.participant.slot);
    assert_ne!(old.participant.incarnation, new.participant.incarnation);
    assert_eq!(ledger.authorize(old, 0), Err(Error::StaleParticipant));
    assert_eq!(ledger.settle(old, Progress::default()), Err(Error::StaleParticipant));
    ledger.authorize(new, 0).unwrap();
    assert_eq!(ledger.physical(), 1);
}

#[test]
fn retries_have_no_duplicate_accounting_effects() {
    let mut ledger = ledger(1);
    let id = prepared(&mut ledger);
    ledger.prepare(id, request(Work::Listing)).unwrap();
    assert_eq!(ledger.prepare(id, request(Work::LazyRead)), Err(Error::ConflictingRetry));
    let mut charge = ledger.authorize(id, 0).unwrap().charged_ns;
    charge += ledger.authorize(id, 1).unwrap().charged_ns;
    let progress = Progress { revision: 1, operations: 2, elapsed_ns: 30, failed: true };
    let first = ledger.report(id, progress).unwrap();
    assert!(first.failed);
    charge += first.charged_ns;
    assert_eq!(ledger.report(id, progress).unwrap(), Effect::default());
    let final_progress = Progress { revision: 2, operations: 4, elapsed_ns: 40, failed: true };
    let final_effect = ledger.settle(id, final_progress).unwrap();
    assert!(!final_effect.failed);
    charge += final_effect.charged_ns;
    assert_eq!(ledger.settle(id, final_progress).unwrap(), Effect::default());
    assert_eq!(charge, 40);
    assert_eq!(ledger.physical(), 0);
}

#[test]
fn negotiating_a_smaller_lease_returns_only_the_uncommitted_difference() {
    let mut ledger = ledger(1);
    let id = prepared(&mut ledger);
    assert_eq!(ledger.narrow(id, 2, 5).unwrap(), Effect { aborted_ns: 5, ..Effect::default() });
    assert_eq!(ledger.narrow(id, 2, 5).unwrap(), Effect::default());
    assert_eq!(ledger.narrow(id, 3, 5), Err(Error::InvalidReservation));
    assert_eq!(ledger.narrow(id, 2, 6), Err(Error::InvalidReservation));
    assert_eq!(ledger.authorize(id, 0).unwrap().charged_ns, 5);
    assert_eq!(ledger.narrow(id, 1, 1), Err(Error::InvalidTransition));
    assert_eq!(
        ledger.settle(id, Progress { revision: 1, operations: 3, elapsed_ns: 5, failed: false }),
        Err(Error::InvalidProgress)
    );
    ledger.settle(id, Progress { revision: 1, operations: 2, elapsed_ns: 5, failed: false }).unwrap();
}

#[test]
fn progress_must_be_monotonic_and_cannot_exceed_granted_operations() {
    let mut ledger = ledger(1);
    let id = prepared(&mut ledger);
    assert_eq!(ledger.report(id, Progress::default()), Err(Error::InvalidTransition));
    ledger.authorize(id, 0).unwrap();
    ledger.report(id, Progress { revision: 2, operations: 2, elapsed_ns: 20, failed: true }).unwrap();
    for progress in [
        Progress { revision: 1, operations: 2, elapsed_ns: 20, failed: true },
        Progress { revision: 2, operations: 3, elapsed_ns: 20, failed: true },
        Progress { revision: 3, operations: 1, elapsed_ns: 20, failed: true },
        Progress { revision: 3, operations: 5, elapsed_ns: 20, failed: true },
        Progress { revision: 3, operations: 2, elapsed_ns: 19, failed: true },
        Progress { revision: 3, operations: 2, elapsed_ns: 20, failed: false },
    ] {
        let before = ledger.clone();
        assert_eq!(ledger.settle(id, progress), Err(Error::InvalidProgress));
        assert_eq!(ledger, before);
    }
}

#[test]
fn malformed_identities_and_capacity_exhaustion_fail_without_mutation() {
    let mut ledger = ledger(1);
    let id = prepared(&mut ledger);
    let before = ledger.clone();
    assert_eq!(ledger.join(VERSION + 1), Err(Error::IncompatibleVersion));
    assert_eq!(ledger, before);
    let mut wrong = id;
    wrong.participant.generation = Generation([2; 16]);
    assert_eq!(ledger.authorize(wrong, 0), Err(Error::WrongGeneration));
    wrong = id;
    wrong.participant.slot = u32::MAX;
    assert_eq!(ledger.authorize(wrong, 0), Err(Error::StaleParticipant));
    wrong = id;
    wrong.sequence = u64::MAX;
    assert_eq!(ledger.authorize(wrong, 0), Err(Error::InvalidSequence));
    assert_eq!(ledger, before);

    ledger.join(VERSION).unwrap();
    let before = ledger.clone();
    assert_eq!(ledger.join(VERSION), Err(Error::ParticipantCapacity));
    assert_eq!(ledger, before);
    for _ in 1..4 {
        let next = ledger.next_operation(id.participant).unwrap();
        ledger.prepare(next, request(Work::Listing)).unwrap();
    }
    let next = ledger.next_operation(id.participant).unwrap();
    let before = ledger.clone();
    assert_eq!(ledger.prepare(next, request(Work::Listing)), Err(Error::OperationCapacity));
    assert_eq!(ledger, before);
}

#[test]
fn backwards_clock_cannot_authorize_or_reclaim_work() {
    let mut ledger = ledger(2);
    let a = prepared(&mut ledger);
    let b = prepared(&mut ledger);
    ledger.authorize(a, 100).unwrap();
    let before = ledger.clone();
    assert_eq!(ledger.authorize(b, 99), Err(Error::ClockRegression));
    assert_eq!(ledger.reclaim_after_owner_exit(a, 99), Err(Error::ClockRegression));
    assert_eq!(ledger, before);
}

#[test]
fn owner_exit_reclaims_ambiguous_dispatch_conservatively() {
    for running in [false, true] {
        let mut ledger = ledger(1);
        let id = prepared(&mut ledger);
        let minimum = ledger.authorize(id, 10).unwrap().charged_ns;
        if running {
            ledger.running(id).unwrap();
        }
        let effect = ledger.reclaim_after_owner_exit(id, 110).unwrap();
        assert_eq!(minimum + effect.charged_ns, 100);
        assert!(effect.failed);
        assert_eq!(ledger.physical(), 0);
        assert_eq!(ledger.reclaim_after_owner_exit(id, 200).unwrap(), Effect::default());
        ledger.leave(id.participant).unwrap();
    }

    let mut ledger = ledger(1);
    let id = prepared(&mut ledger);
    assert_eq!(ledger.reclaim_after_owner_exit(id, 100).unwrap(), Effect { aborted_ns: 10, ..Effect::default() });
    assert_eq!(ledger.physical(), 0);
}

#[test]
fn delayed_and_out_of_order_completions_cannot_release_new_work() {
    let mut ledger = ledger(1);
    let old = prepared(&mut ledger);
    ledger.authorize(old, 0).unwrap();
    ledger.settle(old, Progress::default()).unwrap();
    let new = ledger.next_operation(old.participant).unwrap();
    ledger.prepare(new, request(Work::Listing)).unwrap();
    ledger.authorize(new, 1).unwrap();
    assert_eq!(ledger.settle(old, Progress::default()).unwrap(), Effect::default());
    assert_eq!(ledger.cancel(old).unwrap(), Effect::default());
    assert_eq!(ledger.physical(), 1);
    assert_eq!(ledger.record(new).unwrap().phase, Phase::StartAuthorized);
}

#[test]
fn every_work_source_has_the_same_physical_ownership_rules() {
    for work in [
        Work::Bootstrap,
        Work::DomainDiscovery,
        Work::Listing,
        Work::Enrichment,
        Work::LazyRead,
        Work::WatchRegistration,
        Work::WatchRelease,
    ] {
        let mut ledger = ledger(1);
        let participant = ledger.join(VERSION).unwrap();
        let id = ledger.next_operation(participant).unwrap();
        ledger.prepare(id, request(work)).unwrap();
        ledger.authorize(id, 0).unwrap();
        assert!(ledger.cancel(id).unwrap().detached);
        assert_eq!(ledger.physical(), 1);
        ledger.settle(id, Progress::default()).unwrap();
        assert_eq!(ledger.physical(), 0);
    }
}

/// Models an atomic store transaction that includes both the ownership
/// change and its accounting effects. Storage adapters must establish this
/// atomicity themselves; these tests do not claim to test torn OS writes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Store {
    ledger: Ledger,
    charge: u128,
    failures: u64,
}

impl Store {
    fn transaction(
        &mut self,
        operation: impl FnOnce(&mut Ledger) -> Result<Effect, Error>,
        interrupt_before_commit: bool,
    ) -> Result<(), Error> {
        let mut staged = self.clone();
        let effect = operation(&mut staged.ledger)?;
        staged.charge += u128::from(effect.charged_ns);
        staged.failures += u64::from(effect.failed);
        if !interrupt_before_commit {
            *self = staged;
        }
        Ok(())
    }
}

#[test]
fn interruption_and_retry_at_each_accounting_boundary_preserve_exact_effects() {
    // Exhaustively interrupt before or after the commit of authorization,
    // progress, settlement, and retry each operation after reconnect.
    for interruptions in 0..8 {
        let mut ledger = ledger(1);
        let id = prepared(&mut ledger);
        let mut store = Store { ledger, charge: 0, failures: 0 };
        for (step, progress) in [
            (0, Progress::default()),
            (1, Progress { revision: 1, operations: 2, elapsed_ns: 30, failed: true }),
            (2, Progress { revision: 2, operations: 4, elapsed_ns: 50, failed: true }),
        ] {
            let operation = |ledger: &mut Ledger| match step {
                0 => ledger.authorize(id, 0),
                1 => ledger.report(id, progress),
                _ => ledger.settle(id, progress),
            };
            store.transaction(operation, interruptions & (1 << step) != 0).unwrap();
            store.transaction(operation, false).unwrap();
        }
        assert_eq!(store.charge, 50, "interruption pattern {interruptions}");
        assert_eq!(store.failures, 1);
        assert_eq!(store.ledger.physical(), 0);
        store.ledger.leave(id.participant).unwrap();
        let restarted = prepared(&mut store.ledger);
        assert_ne!(restarted.participant, id.participant);
        assert_eq!(store.charge, 50, "last-participant exit cannot reset committed accounting");
    }
}

fn explore(ledger: Ledger, ids: [OperationId; 2], depth: usize) {
    assert!(ledger.physical() <= ledger.limits().physical);
    assert_eq!(ledger.physical() as usize, ledger.records().filter(|record| record.phase != Phase::Prepared).count());
    if depth == 0 {
        return;
    }
    for id in ids {
        for action in 0..5 {
            let mut next = ledger.clone();
            let result = match action {
                0 => next.authorize(id, 0),
                1 => next.running(id).map(|()| Effect::default()),
                2 => next.cancel(id),
                3 => next.settle(id, Progress::default()),
                _ => next.reclaim_after_owner_exit(id, 0),
            };
            if result.is_err() {
                assert_eq!(next, ledger, "a failed transition must not partially mutate ownership");
            } else {
                explore(next, ids, depth - 1);
            }
        }
    }
}

#[test]
fn exhaustively_interleave_two_participants_under_one_physical_permit() {
    let mut ledger = ledger(1);
    let ids = [prepared(&mut ledger), prepared(&mut ledger)];
    explore(ledger, ids, 6);
}
