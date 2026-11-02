//! Kill a real tmpfs journal writer at publication boundaries. The operation
//! owner is a different process, so lock-owner death cannot stand in for it.

use std::io;

use tree_fucker::coordination::authority::Authority;
use tree_fucker::coordination::journal::Journal;
use tree_fucker::coordination::protocol::{OperationId, Progress};

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transition {
    Prepare,
    Abort,
    Authorize,
    Report,
    Settle,
    Recover,
}

impl Transition {
    const ALL: [Self; 6] = [Self::Prepare, Self::Abort, Self::Authorize, Self::Report, Self::Settle, Self::Recover];

    fn apply(self, authority: &mut Authority, id: OperationId, at: u64) -> Result<(), authority::Error> {
        let progress = Progress { revision: 1, operations: 1, elapsed_ns: 0, failed: true };
        match self {
            Self::Prepare => authority.prepare(id, request(Work::LazyRead), at).map(|_| ()),
            Self::Abort => authority.cancel(id, at).map(|detached| assert!(!detached)),
            Self::Authorize => authority.authorize(id, at),
            Self::Report => authority.report(id, progress, at),
            Self::Settle => authority.settle(id, progress, at),
            Self::Recover => authority.reclaim_after_owner_exit(id, at),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Prefix {
    Bytes(usize),
    Half,
    AllButLast,
    All,
}

// The production publication sequence writes the invalidation marker, slot
// header, payload, and final commit decision. Partial writes reach the actual
// file before the writer blocks and the controller kills it.
const CUTS: [(usize, Prefix); 10] = [
    (1, Prefix::Bytes(0)),
    (1, Prefix::All),
    (2, Prefix::Bytes(1)),
    (2, Prefix::Half),
    (2, Prefix::All),
    (3, Prefix::Bytes(1)),
    (3, Prefix::Half),
    (3, Prefix::AllButLast),
    (3, Prefix::All),
    (4, Prefix::All),
];

struct InterruptedFile<'a> {
    file: File,
    writes: usize,
    cut: (usize, Prefix),
    root: &'a Path,
    gate: File,
}

impl Read for InterruptedFile<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}

impl Seek for InterruptedFile<'_> {
    fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
        self.file.seek(at)
    }
}

impl Write for InterruptedFile<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.writes == self.cut.0 {
            let prefix = match self.cut.1 {
                Prefix::Bytes(count) => count,
                Prefix::Half => bytes.len() / 2,
                Prefix::AllButLast => bytes.len() - 1,
                Prefix::All => bytes.len(),
            };
            self.file.write_all(&bytes[..prefix])?;
            fs::write(self.root.join("paused"), [])?;
            self.gate.read_exact(&mut [0])?;
            panic!("crash fixture resumed instead of being killed");
        }
        self.file.write_all(bytes)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn monotonic_ns() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(now.tv_sec).unwrap() * 1_000_000_000 + now.tv_nsec as u64
}

fn state_file(root: &Path) -> File {
    OpenOptions::new().read(true).write(true).open(root.join("scope/authority.state")).unwrap()
}

fn lock(file: &File) {
    retry(|| match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(Error::Busy),
        Err(error) => Err(error.into()),
    });
}

struct BookkeepingLock(File);

impl Drop for BookkeepingLock {
    fn drop(&mut self) {
        // Match the backend's explicit bookkeeping unlock. Lifetime evidence
        // remains close-only, including descriptors inherited during exec.
        flock(&self.0, FlockOperation::Unlock).unwrap();
    }
}

fn anchor(root: &Path) -> BookkeepingLock {
    let file = OpenOptions::new().read(true).write(true).open(root.join("scope.authority.lock")).unwrap();
    lock(&file);
    BookkeepingLock(file)
}

fn operation(state: &Authority, transition: Transition) -> OperationId {
    match transition {
        Transition::Prepare => state.ledger().next_operation(state.ledger().participants().next().unwrap()).unwrap(),
        _ => state.ledger().records().next().unwrap().id,
    }
}

fn owner_exit_proof(root: &Path, state: &Authority, id: OperationId) -> File {
    use std::os::unix::fs::MetadataExt;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join(format!("scope/owner-{}", id.participant.slot)))
        .unwrap();
    let metadata = file.metadata().unwrap();
    let mut identity = [0; 16];
    identity[..8].copy_from_slice(&metadata.dev().to_le_bytes());
    identity[8..].copy_from_slice(&metadata.ino().to_le_bytes());
    assert_eq!(state.ledger().owner(id.participant).unwrap(), Some(identity));
    lock(&file);
    file
}

#[test]
#[ignore = "native interrupted-journal writer launched by crash acceptance tests"]
fn interrupted_journal_writer() {
    let root = std::env::var_os("TF_COORDINATION_FIXTURE").unwrap();
    let root = Path::new(&root);
    let index: usize = std::env::var("TF_COORDINATION_INDEX").unwrap().parse().unwrap();
    let transition = Transition::ALL[index / CUTS.len()];
    let cut = CUTS[index % CUTS.len()];
    let _anchor = anchor(root);
    let mut journal = Journal::open(state_file(root)).unwrap();
    let before = journal.load().unwrap();
    let id = operation(&before, transition);
    // Reclamation uses the same inode-qualified kernel lifetime evidence as
    // the backend, obtained while holding its bookkeeping lock.
    let _owner = (transition == Transition::Recover).then(|| owner_exit_proof(root, &before, id));
    let at = monotonic_ns();
    let mut after = before.clone();
    transition.apply(&mut after, id, at).unwrap();
    fs::write(root.join("before.bin"), before.encode().unwrap()).unwrap();
    fs::write(root.join("after.bin"), after.encode().unwrap()).unwrap();
    fs::write(root.join("transition-time"), at.to_string()).unwrap();
    let file = InterruptedFile {
        file: journal.into_inner(),
        writes: 0,
        cut,
        root,
        gate: File::open(root.join("gate-0")).unwrap(),
    };
    Journal::open(file).unwrap().transaction(|state| transition.apply(state, id, at)).unwrap();
    panic!("journal publication did not reach {cut:?}");
}

#[test]
#[ignore = "completed physical owner exits before settlement publication"]
fn completed_operation_owner() {
    let root = std::env::var_os("TF_COORDINATION_FIXTURE").unwrap();
    let root = Path::new(&root);
    let scope = retry(|| Scope::open(root.join("scope"), config()));
    let client = retry(|| scope.join());
    let mut prepared = retry(|| client.prepare(request(Work::LazyRead)));
    prepared
        .try_run::<()>(|_| {
            fs::write(root.join("completed-work"), b"completed").unwrap();
            assert_eq!(fs::read(root.join("completed-work")).unwrap(), b"completed");
            // The physical call returned, but the owner process exits before
            // publishing completion or running any ownership destructors.
            std::process::exit(0);
        })
        .unwrap();
    unreachable!();
}

fn crash_at_each_publication_boundary(transition: Transition) {
    for cut in 0..CUTS.len() {
        let (root, scope) = fixture();
        let owner = if transition == Transition::Recover {
            let mut children = Children(vec![spawn_fixture(root.path(), 0, "crashes::completed_operation_owner")]);
            assert!(children.0[0].wait().unwrap().success());
            assert_eq!(fs::read(root.path().join("completed-work")).unwrap(), b"completed");
            None
        } else {
            let client = scope.join().unwrap();
            let prepared =
                (transition != Transition::Prepare).then(|| client.prepare(request(Work::LazyRead)).unwrap());
            if matches!(transition, Transition::Report | Transition::Settle) {
                let _anchor = anchor(root.path());
                let mut journal = Journal::open(state_file(root.path())).unwrap();
                let id = operation(&journal.load().unwrap(), transition);
                journal.transaction(|state| state.authorize(id, monotonic_ns())).unwrap();
                // Actual filesystem work completes while the committed physical
                // permission remains owned, before any completion publication.
                fs::write(root.path().join("completed-work"), b"completed").unwrap();
                assert_eq!(fs::read(root.path().join("completed-work")).unwrap(), b"completed");
            }
            Some((client, prepared))
        };
        let _gate = fifo(root.path(), 0);
        let index = Transition::ALL.iter().position(|candidate| *candidate == transition).unwrap() * CUTS.len() + cut;
        let mut children = Children(vec![spawn_fixture(root.path(), index, "crashes::interrupted_journal_writer")]);
        let deadline = Instant::now() + Duration::from_secs(15);
        while !root.path().join("paused").exists() {
            assert!(children.0[0].try_wait().unwrap().is_none(), "{transition:?} {cut}: writer exited before barrier");
            assert!(Instant::now() < deadline, "{transition:?} {cut}: writer did not reach barrier");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(matches!(scope.view(), Err(Error::Busy)), "writer must retain the bookkeeping lock");
        children.0[0].kill().unwrap();
        assert!(!children.0[0].wait().unwrap().success());

        let before = Authority::decode(&fs::read(root.path().join("before.bin")).unwrap()).unwrap();
        let after = Authority::decode(&fs::read(root.path().join("after.bin")).unwrap()).unwrap();
        let at: u64 = fs::read_to_string(root.path().join("transition-time")).unwrap().parse().unwrap();
        // Reopen through the actual backend, including native lock acquisition,
        // pinned identities, and adoption of a complete preparing snapshot.
        let reopened = retry(|| Scope::open(root.path().join("scope"), config()));
        {
            let _anchor = anchor(root.path());
            let mut journal = Journal::open(state_file(root.path())).unwrap();
            let recovered = journal.load().unwrap();
            assert!(recovered == before || recovered == after, "{transition:?} {cut}: torn accounting/ownership");
            if cut == 0 {
                assert_eq!(recovered, before);
            }
            if cut >= 8 {
                assert_eq!(recovered, after, "a complete payload must retain its accounting decision");
            }
            let id = operation(&before, transition);
            let _owner = (transition == Transition::Recover).then(|| owner_exit_proof(root.path(), &recovered, id));
            for _ in 0..2 {
                journal.transaction(|state| transition.apply(state, id, at)).unwrap();
                assert_eq!(journal.load().unwrap(), after, "{transition:?} {cut}: duplicate replay changed state");
            }
        }
        let view = retry(|| reopened.view());
        assert_eq!(view.physical, after.view().physical, "bookkeeping-owner death cannot reclaim a live owner's work");
        drop(owner);
        let deadline = Instant::now() + Duration::from_secs(15);
        let final_view = loop {
            let view = retry(|| reopened.view());
            if view.participants == 0 {
                break view;
            }
            // Deferred cancellation and descriptors inherited by concurrent
            // spawn/exec may temporarily retain the owner's lifetime lock.
            assert!(Instant::now() < deadline, "{transition:?} {cut}: ownership did not retire");
            std::thread::sleep(Duration::from_millis(2));
        };
        assert_eq!((final_view.participants, final_view.prepared, final_view.physical), (0, 0, 0));
        assert!(final_view.charged_ns >= after.view().charged_ns);
        assert!(final_view.surcharged_ns >= after.view().surcharged_ns);
        assert_eq!(reopened.diagnostics().unwrap().generation, after.ledger().generation());
    }
}

#[test]
fn killed_writer_preserves_atomic_preparation() {
    crash_at_each_publication_boundary(Transition::Prepare);
}

#[test]
fn killed_writer_preserves_atomic_preparation_abort() {
    crash_at_each_publication_boundary(Transition::Abort);
}

#[test]
fn killed_writer_preserves_atomic_authorization_without_reclaiming_live_owner() {
    crash_at_each_publication_boundary(Transition::Authorize);
}

#[test]
fn killed_writer_preserves_atomic_progress_and_failure_charge() {
    crash_at_each_publication_boundary(Transition::Report);
}

#[test]
fn killed_writer_preserves_atomic_completion_before_acknowledgment() {
    crash_at_each_publication_boundary(Transition::Settle);
}

#[test]
fn killed_recovery_writer_preserves_accounting_after_operation_owner_exit() {
    crash_at_each_publication_boundary(Transition::Recover);
}
