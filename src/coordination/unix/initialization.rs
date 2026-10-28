//! Process interruption during the first anchor and journal publication.

#[path = "../../../tests/coordination_support/fifo.rs"]
mod native_fifo;

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::*;
use crate::HostConfig;
use crate::coordination::authority::{Origin, Request};
use crate::coordination::protocol::Work;

// Header prefixes and the final READY decision use the production initializer.
// A full header before READY already pins both the generation and state inode.
const CUTS: [(usize, usize); 7] = [(1, 0), (1, 1), (1, 64), (1, 127), (1, 128), (2, 0), (2, 1)];

// Journal::create writes its header, extends the file, and then publishes the
// first slot with invalidation, header, payload, and commit writes.
const JOURNAL_CUTS: [(usize, usize); 14] = [
    (1, 0),
    (1, 1),
    (1, 32),
    (1, 63),
    (1, 64),
    (2, 0),
    (2, 1),
    (3, 1),
    (4, 1),
    (4, 31),
    (5, 1),
    (5, usize::MAX),
    (6, 0),
    (6, 1),
];

struct InterruptedStorage {
    file: File,
    writes: usize,
    cut: (usize, usize),
    fixture: PathBuf,
    gate: File,
}

impl Read for InterruptedStorage {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}

impl Seek for InterruptedStorage {
    fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
        self.file.seek(at)
    }
}

impl Write for InterruptedStorage {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.writes == self.cut.0 {
            self.file.write_all(&bytes[..self.cut.1.min(bytes.len())])?;
            fs::write(self.fixture.join("paused"), [])?;
            self.gate.read_exact(&mut [0])?;
            panic!("initializer resumed instead of being killed");
        }
        self.file.write_all(bytes)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn config() -> Config {
    Config::from_host(&HostConfig::default(), 4, 8, 8).unwrap()
}

#[test]
#[ignore = "initializer process killed by the anchor publication test"]
fn interrupted_initializer() {
    let fixture = PathBuf::from(std::env::var_os("TF_INITIALIZATION_FIXTURE").unwrap());
    let index: usize = std::env::var("TF_INITIALIZATION_CUT").unwrap().parse().unwrap();
    let journal = std::env::var("TF_INITIALIZATION_JOURNAL").unwrap() == "1";
    let context = Context::current().unwrap();
    if !journal {
        fs::DirBuilder::new().mode(0o700).create(fixture.join("scope")).unwrap();
    }
    let root = File::open(fixture.join("scope")).unwrap();
    let parent = File::open(&fixture).unwrap();
    let mut file = open_file(&parent, OsStr::new("scope.authority.lock"), true, context.uid).unwrap();
    exclusive(&file).unwrap();
    let gate = File::open(fixture.join("gate")).unwrap();
    if journal {
        let mut header = [0; HEADER_SIZE];
        file.read_exact(&mut header).unwrap();
        assert_eq!(header[12], PREPARING);
        let generation = Generation(header[16..32].try_into().unwrap());
        let state = open_file(&root, OsStr::new(STATE), false, context.uid).unwrap();
        assert_eq!(state.metadata().unwrap().len(), 0);
        let storage = InterruptedStorage { file: state, writes: 0, cut: JOURNAL_CUTS[index], fixture, gate };
        Journal::create(storage, &Authority::new(generation, config(), now().unwrap()).unwrap()).unwrap();
        // Retain the anchor's bookkeeping lock through the interrupted write.
        drop(file);
    } else {
        let mut anchor = InterruptedStorage { file, writes: 0, cut: CUTS[index], fixture, gate };
        initialize_storage(&root, &mut anchor, 0, context, config()).unwrap();
    }
    panic!("initializer did not reach cut {index}");
}

struct Writer(Child);

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn killed_initializers_recover_pinned_authority_or_reject_partial_anchor() {
    crash_initialization(false);
}

#[test]
fn killed_initial_journal_writers_recover_the_pinned_generation() {
    crash_initialization(true);
}

fn kill_writer(root: &Path, index: usize, journal: bool) {
    let mut writer = Writer(
        Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "coordination::unix::initialization::interrupted_initializer"])
            .env("TF_INITIALIZATION_FIXTURE", root)
            .env("TF_INITIALIZATION_CUT", index.to_string())
            .env("TF_INITIALIZATION_JOURNAL", if journal { "1" } else { "0" })
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !root.join("paused").exists() {
        assert!(writer.0.try_wait().unwrap().is_none(), "cut {index}, journal {journal}: writer exited before barrier");
        assert!(Instant::now() < deadline, "cut {index}, journal {journal}: writer did not reach barrier");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(matches!(Scope::open(root.join("scope"), config()), Err(Error::Busy)));
    writer.0.kill().unwrap();
    assert!(!writer.0.wait().unwrap().success());
    fs::remove_file(root.join("paused")).unwrap();
}

fn crash_initialization(journal: bool) {
    let cuts = if journal { JOURNAL_CUTS.len() } else { CUTS.len() };
    for index in 0..cuts {
        let fixture =
            tempfile::Builder::new().prefix("tree-fucker-initialization-").tempdir_in(platform::RENDEZVOUS).unwrap();
        let root = fixture.path();
        native_fifo::create(&root.join("gate")).unwrap();
        let _gate = OpenOptions::new().read(true).write(true).open(root.join("gate")).unwrap();
        if journal {
            // Stop after publishing the complete PREPARING anchor, before the
            // journal exists. The second writer uses that pinned empty inode.
            kill_writer(root, 4, false);
        }
        kill_writer(root, index, journal);
        let anchor_path = root.join("scope.authority.lock");
        let state_path = root.join("scope/authority.state");
        let before = fs::read(&anchor_path).unwrap();
        let state_identity = identity(&fs::metadata(&state_path).unwrap());
        if !before.is_empty() && before.len() < HEADER_SIZE {
            for _ in 0..2 {
                let result = Scope::open(root.join("scope"), config());
                assert!(
                    matches!(result, Err(Error::Replaced)),
                    "cut {index}, journal {journal}, {} anchor bytes: {:?}",
                    before.len(),
                    result.err()
                );
                assert_eq!(fs::read(&anchor_path).unwrap(), before);
                assert_eq!(fs::metadata(&state_path).unwrap().len(), 0);
            }
            continue;
        }

        let scope = Scope::open(root.join("scope"), config()).unwrap();
        assert_eq!(identity(&fs::metadata(&state_path).unwrap()), state_identity);
        if before.len() == HEADER_SIZE {
            assert_eq!(scope.generation.0, before[16..32]);
        }
        let generation = scope.generation;
        let client = scope.join().unwrap();
        client
            .prepare(Request {
                work: Work::LazyRead,
                origin: Origin::Foreground,
                domain: None,
                required: 1,
                desired: 0,
                ceiling_ns: u64::MAX,
            })
            .unwrap()
            .try_run(|_| {
                fs::write(root.join("work"), b"completed").unwrap();
                assert_eq!(fs::read(root.join("work")).unwrap(), b"completed");
                Completion { value: (), operations: 1, failed: false }
            })
            .unwrap();
        let charged = scope.view().unwrap().charged_ns;
        assert!(charged > 0);
        let reopened = Scope::open(root.join("scope"), config()).unwrap();
        assert_eq!(reopened.generation, generation);
        assert_eq!(reopened.view().unwrap().charged_ns, charged);
        drop(reopened);
        drop(client);
        drop(scope);
        let retained = Scope::open(root.join("scope"), config()).unwrap();
        assert_eq!(retained.generation, generation);
        assert_eq!(retained.view().unwrap().charged_ns, charged);
        assert_eq!(identity(&fs::metadata(&state_path).unwrap()), state_identity);
    }
}
