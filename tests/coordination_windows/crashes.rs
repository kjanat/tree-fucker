use super::*;

const RECOVER_AT: u64 = 1_000_000;

fn retire(state: &mut Authority) -> Result<(), tree_fucker::coordination::authority::Error> {
    let participants: Vec<_> = state.ledger().participants().collect();
    for participant in participants {
        let operations: Vec<_> = state
            .ledger()
            .records()
            .filter(|record| record.id.participant == participant)
            .map(|record| record.id)
            .collect();
        for operation in operations {
            state.reclaim_after_owner_exit(operation, RECOVER_AT)?;
        }
        state.leave(participant)?;
    }
    Ok(())
}

pub(super) fn fixture(root: &Path, mode: &str) {
    let (boundary, cut) = mode.split_once('-').unwrap();
    let anchor = open_bookkeeping(&root.join("anchor"), false).unwrap();
    let _lock = Bookkeeping::try_lock(&anchor).unwrap();
    // The exclusive owner handle spans every publication write. Terminating
    // this writer releases both bookkeeping and this registration/recovery pin.
    let owner = open_owner(&root.join("owner"), false).unwrap();
    let owner_id = identity(&owner).unwrap();
    let mut journal = Journal::open(Interrupted {
        file: open_bookkeeping(&root.join("journal"), false).unwrap(),
        root: root.to_owned(),
        cut: cut.parse().unwrap(),
        writes: 0,
    })
    .unwrap();
    journal
        .transaction(|state| {
            if boundary == "registration" {
                state.join_owned(VERSION, 0, owner_id.file)?;
                Ok(())
            } else {
                retire(state)
            }
        })
        .unwrap();
    drop(owner);
    panic!("writer did not stop at its publication boundary");
}

fn history(registration: bool) {
    for cut in 1..=4 {
        let root = tempfile::tempdir().unwrap();
        let owner = open_owner(&root.path().join("owner"), true).unwrap();
        let owner_id = identity(&owner).unwrap();
        let mut before = authority();
        if !registration {
            let participant = before.join_owned(VERSION, 0, owner_id.file).unwrap();
            let id = OperationId { participant, sequence: 1 };
            before
                .prepare(
                    id,
                    Request {
                        work: Work::LazyRead,
                        origin: Origin::Foreground,
                        domain: None,
                        required: 1,
                        desired: 0,
                        ceiling_ns: u64::MAX,
                    },
                    0,
                )
                .unwrap();
            before.authorize(id, 0).unwrap();
        }
        let mut after = before.clone();
        if registration {
            after.join_owned(VERSION, 0, owner_id.file).unwrap();
        } else {
            retire(&mut after).unwrap();
        }
        let anchor = open_bookkeeping(&root.path().join("anchor"), true).unwrap();
        let lock = Bookkeeping::try_lock(&anchor).unwrap();
        Journal::create(open_bookkeeping(&root.path().join("journal"), true).unwrap(), &before).unwrap();
        lock.unlock().unwrap();
        drop(owner);
        let boundary = if registration { "registration" } else { "recovery" };
        let mut writer = Fixture::spawn(root.path(), &format!("{boundary}-{cut}"), Stdio::null());
        writer.ready("writer-paused");
        assert!(matches!(Bookkeeping::try_lock(&anchor), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        assert!(recover_owner(&root.path().join("owner"), owner_id).unwrap().is_none());
        writer.kill();
        let mut recovered_lock = None;
        wait_until(|| match Bookkeeping::try_lock(&anchor) {
            Ok(lock) => {
                recovered_lock = Some(lock);
                true
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => false,
            Err(error) => panic!("bookkeeping recovery failed: {error}"),
        });
        let recovered = recover_owner(&root.path().join("owner"), owner_id).unwrap().expect("final owner closed");
        let mut journal = Journal::open(open_bookkeeping(&root.path().join("journal"), false).unwrap()).unwrap();
        let state = journal.load().unwrap();
        let expected = if cut >= 3 { &after } else { &before };
        assert_eq!(state.encode().unwrap(), expected.encode().unwrap(), "{boundary}, cut {cut}");
        // Both recoverers make the same final-owner observation. Replaying a
        // published retirement must preserve the complete accounting exactly.
        let mut finished = expected.clone();
        retire(&mut finished).unwrap();
        for _ in 0..2 {
            journal.transaction(retire).unwrap();
            assert_eq!(journal.load().unwrap().encode().unwrap(), finished.encode().unwrap());
        }
        if !registration {
            assert!(finished.view().charged_ns >= before.view().charged_ns);
            assert_eq!(finished.view().surcharged_ns, u128::from(finished.config().failure_surcharge_ns));
        }
        let replacement = journal.transaction(|state| state.join_owned(VERSION, 0, owner_id.file)).unwrap();
        assert_eq!(replacement.slot, 0);
        if let Some(previous) =
            expected.ledger().participants().next().or_else(|| before.ledger().participants().next())
        {
            assert!(replacement.incarnation > previous.incarnation);
        }
        let retained = journal.load().unwrap().encode().unwrap();
        drop((journal, recovered));
        recovered_lock.take().unwrap().unlock().unwrap();
        drop(recovered_lock);
        drop(anchor);
        assert_eq!(
            Journal::open(open_bookkeeping(&root.path().join("journal"), false).unwrap())
                .unwrap()
                .load()
                .unwrap()
                .encode()
                .unwrap(),
            retained
        );
    }
}

#[test]
fn killed_registration_writers_release_only_unowned_incarnations() {
    history(true);
}

#[test]
fn killed_recovery_writers_preserve_exactly_one_retirement() {
    history(false);
}
