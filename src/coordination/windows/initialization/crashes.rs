//! Kill native writers while the production initializer retains bookkeeping.

use std::fs;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::*;
use crate::HostConfig;
use crate::coordination::authority::{Origin, Request};
use crate::coordination::protocol::Work;

const ANCHOR_CUTS: [(usize, usize); 7] = [(1, 0), (1, 1), (1, 128), (1, 255), (1, usize::MAX), (2, 0), (2, 1)];
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

fn config() -> Config {
    Config::from_host(&HostConfig::default(), 4, 8, 8).unwrap()
}

struct Interrupted {
    file: File,
    writes: usize,
    cut: (usize, usize),
    root: PathBuf,
}

impl Read for Interrupted {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}

impl Seek for Interrupted {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

impl Write for Interrupted {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.writes == self.cut.0 {
            self.file.write_all(&bytes[..bytes.len().min(self.cut.1)])?;
            fs::write(self.root.join("paused"), [])?;
            std::io::stdin().read_exact(&mut [0])?;
            panic!("initializer resumed instead of being killed");
        }
        self.file.write_all(bytes)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[test]
#[ignore = "subprocess killed at an initialization publication boundary"]
fn interrupted_initializer() {
    let root = PathBuf::from(std::env::var_os("TF_WINDOWS_INITIALIZER_ROOT").unwrap());
    let index: usize = std::env::var("TF_WINDOWS_INITIALIZER_CUT").unwrap().parse().unwrap();
    let journal = std::env::var("TF_WINDOWS_INITIALIZER_JOURNAL").unwrap() == "1";
    let principal = Principal::current().unwrap();
    let parent = relative::Directory::open(&root).unwrap();
    let anchor =
        principal.open_at(parent.handle(), OsStr::new("coordination.authority.lock"), true, SHARED, false).unwrap();
    let _lock = Bookkeeping::try_lock(&anchor).unwrap();
    let mut clock = Clock::current().unwrap();
    if journal {
        let bytes = fs::read(root.join("coordination.authority.lock")).unwrap();
        assert_eq!(bytes[12], PREPARING);
        let generation = Generation(bytes[16..32].try_into().unwrap());
        let directory = principal.open_at(parent.handle(), OsStr::new("coordination"), false, SHARED, true).unwrap();
        let state = principal.open_at(&directory, OsStr::new(STATE), false, SHARED, false).unwrap();
        assert_eq!(state.metadata().unwrap().len(), 0);
        let storage = Interrupted { file: state, writes: 0, cut: JOURNAL_CUTS[index], root };
        let mut authority = Authority::new(generation, config(), clock.now().unwrap()).unwrap();
        authority.bind_clock(clock.binding());
        Journal::create(storage, &authority).unwrap();
    } else {
        let storage = Interrupted { file: anchor.try_clone().unwrap(), writes: 0, cut: ANCHOR_CUTS[index], root };
        initialize_storage(&parent, OsStr::new("coordination"), storage, 0, &principal, &mut clock, config()).unwrap();
    }
    panic!("initializer did not stop at the requested boundary");
}

struct Writer(Child);

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn reopen(path: &Path) -> Arc<Scope> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match Scope::open(path, config()) {
            Ok(scope) => return scope,
            Err(Error::Busy) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
            Err(error) => panic!("reopen failed: {error}"),
        }
    }
}

fn history(journal: bool) {
    let cuts = if journal { JOURNAL_CUTS.len() } else { ANCHOR_CUTS.len() };
    for index in 0..cuts {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("coordination");
        if journal {
            drop(Scope::open(&path, config()).unwrap());
            super::tests::mark_preparing(root.path());
            File::options().write(true).open(path.join(STATE)).unwrap().set_len(0).unwrap();
        }
        let mut writer = Writer(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "coordination::windows::initialization::crashes::interrupted_initializer",
                ])
                .env("TF_WINDOWS_INITIALIZER_ROOT", root.path())
                .env("TF_WINDOWS_INITIALIZER_CUT", index.to_string())
                .env("TF_WINDOWS_INITIALIZER_JOURNAL", if journal { "1" } else { "0" })
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while !root.path().join("paused").exists() {
            assert!(writer.0.try_wait().unwrap().is_none(), "initializer exited before cut {index}, journal={journal}");
            assert!(Instant::now() < deadline, "initializer never reached cut {index}, journal={journal}");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(matches!(Scope::open(&path, config()), Err(Error::Busy)));
        let anchor_path = root.path().join("coordination.authority.lock");
        let before = fs::read(&anchor_path).unwrap();
        let state_id = identity(&File::open(path.join(STATE)).unwrap()).unwrap();
        writer.0.kill().unwrap();
        assert!(!writer.0.wait().unwrap().success());
        // Process termination may be observed before Windows releases its
        // byte-range locks. Wait for that kernel lifetime evidence explicitly.
        let anchor = File::options().read(true).write(true).open(&anchor_path).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match Bookkeeping::try_lock(&anchor) {
                Ok(lock) => {
                    lock.unlock().unwrap();
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("dead initializer retained bookkeeping: {error}"),
            }
        }
        drop(anchor);
        if !before.is_empty() && before.len() != HEADER {
            let retained = fs::read(path.join(STATE)).unwrap();
            for _ in 0..2 {
                assert!(matches!(Scope::open(&path, config()), Err(Error::Replaced)));
                assert_eq!(fs::read(&anchor_path).unwrap(), before);
                assert_eq!(fs::read(path.join(STATE)).unwrap(), retained);
            }
            continue;
        }
        let scope = reopen(&path);
        let generation = scope.diagnostics().unwrap().generation;
        if before.len() == HEADER {
            assert_eq!(generation.0, before[16..32]);
        }
        assert_eq!(identity(&File::open(path.join(STATE)).unwrap()).unwrap(), state_id);
        let view = scope.view().unwrap();
        assert_eq!((view.participants, view.prepared, view.physical, view.charged_ns), (0, 0, 0, 0));
        assert_eq!(fs::read(&anchor_path).unwrap()[12], READY);
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
            .try_run(|_| Completion { value: (), operations: 1, failed: false })
            .unwrap();
        let charged = scope.view().unwrap().charged_ns;
        assert!(charged > 0);
        drop((client, scope));
        let fresh = reopen(&path);
        assert_eq!(fresh.diagnostics().unwrap().generation, generation);
        assert_eq!(fresh.view().unwrap().charged_ns, charged);
    }
}

#[test]
fn killed_windows_initializers_preserve_or_reject_the_pinned_authority() {
    history(false);
}

#[test]
fn killed_windows_initial_journal_writers_retain_the_pinned_generation() {
    history(true);
}
