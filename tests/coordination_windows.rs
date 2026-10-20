//! Windows authority primitives, exercised through independent processes.
#![cfg(windows)]

#[path = "../src/coordination/windows/handles.rs"]
mod handles;
#[path = "../src/coordination/windows/clock.rs"]
mod native_clock;
#[path = "../src/coordination/windows/relative.rs"]
mod relative;
#[path = "../src/coordination/windows/security.rs"]
mod security;
#[path = "../src/coordination/windows/storage.rs"]
mod storage;

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use handles::{Bookkeeping, Identity, identity, recover_at};
use security::Principal;
use tree_fucker::HostConfig;
use tree_fucker::coordination::authority::{Authority, Config, Origin, Request};
use tree_fucker::coordination::journal::Journal;
use tree_fucker::coordination::protocol::{Generation, OperationId, VERSION, Work};
use tree_fucker::coordination::windows::{Completion, Scope};

#[test]
fn native_scope_retains_generation_and_debt_after_every_handle_closes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("scope");
    let config = authority().config();
    let scope = Scope::open(&path, config).unwrap();
    let generation = scope.diagnostics().unwrap().generation;
    let client = scope.join().unwrap();
    let mut prepared = client
        .prepare(Request {
            work: Work::LazyRead,
            origin: Origin::Foreground,
            domain: None,
            required: 1,
            desired: 0,
            ceiling_ns: u64::MAX,
        })
        .unwrap();
    prepared
        .try_run(|_| {
            assert_eq!(scope.view().unwrap().physical, 1);
            Completion { value: (), operations: 1, failed: false }
        })
        .unwrap();
    let charged = scope.view().unwrap().charged_ns;
    assert!(charged > 0);
    drop((prepared, client, scope));
    let reopened = Scope::open(&path, config).unwrap();
    assert_eq!(reopened.diagnostics().unwrap().generation, generation);
    let view = reopened.view().unwrap();
    assert_eq!(view.charged_ns, charged);
    assert_eq!((view.participants, view.physical, view.prepared), (0, 0, 0));
}

#[test]
fn native_scope_reuses_final_closed_owner_without_releasing_recovery_exclusion() {
    let root = tempfile::tempdir().unwrap();
    let mut config = authority().config();
    config.ownership.participants = 1;
    let scope = Scope::open(root.path().join("scope"), config).unwrap();
    let client = scope.join().unwrap();
    let first = client.participant();
    drop(client);
    let second = scope.join().unwrap();
    assert_eq!(second.participant().slot, first.slot);
    assert_eq!(second.participant().generation, first.generation);
    assert!(second.participant().incarnation > first.incarnation);
}

#[test]
fn native_scope_rejects_replacement_and_configuration_disagreement() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("scope");
    let config = authority().config();
    let scope = Scope::open(&path, config).unwrap();
    let generation = scope.diagnostics().unwrap().generation;
    let state = path.join("authority.state");
    let retained = path.join("retained-state");
    assert!(fs::rename(&state, &retained).is_err());
    assert!(fs::rename(&path, root.path().join("renamed")).is_err());
    let mut incompatible = config;
    incompatible.initial_estimate_ns += 1;
    assert!(matches!(Scope::open(&path, incompatible), Err(tree_fucker::coordination::windows::Error::Incompatible)));
    drop(scope);
    fs::rename(&state, &retained).unwrap();
    drop(open_bookkeeping(&state, true).unwrap());
    assert!(matches!(Scope::open(&path, config), Err(tree_fucker::coordination::windows::Error::Incompatible)));
    fs::remove_file(&state).unwrap();
    fs::rename(&retained, &state).unwrap();
    assert_eq!(Scope::open(&path, config).unwrap().diagnostics().unwrap().generation, generation);
}

#[test]
fn native_governor_scan_and_lazy_reads_use_the_shared_authority() {
    use std::sync::Arc;

    use tree_fucker::{DomainCrossing, HostGovernor, LoadAll, Scan, ScanEvent, ScanOptions, SystemClock};

    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("leaf"), b"content").unwrap();
    let config = HostConfig {
        foreground_burst: Duration::from_secs(1),
        bootstrap_allowance: Duration::from_secs(1),
        ..Default::default()
    };
    let limits = Config::from_host(&config, 4, 16, 16).unwrap();
    let scope = Scope::open(root.path().join("scope"), limits).unwrap();
    let host = HostGovernor::with_coordination(&config, scope.clone()).unwrap();
    let mut scan = Scan::open_outside_host_governor(
        Arc::new(tree_fucker::std_fs::StdFileSystem::new()),
        input,
        Arc::new(LoadAll),
        ScanOptions { crossing: DomainCrossing::Follow, ceiling: Duration::MAX, ..Default::default() },
        host.clone(),
        Arc::new(SystemClock),
    )
    .unwrap();
    let mut entries = 0;
    while let Some(event) = scan.next() {
        match event.unwrap() {
            ScanEvent::Entry(entry) => {
                entries += 1;
                scan.read(&entry, |_| {
                    assert_eq!(scope.view().unwrap().physical, 1);
                    Ok(())
                })
                .unwrap();
            }
            ScanEvent::Unlisted { failure, .. } => panic!("unlisted: {failure:?}"),
            _ => {}
        }
    }
    assert_eq!(entries, 2);
    assert!(host.coordination_error().is_none());
    let view = scope.view().unwrap();
    assert_eq!((view.physical, view.prepared), (0, 0));
    assert!(view.charged_ns > 0);
}
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready() {
        assert!(Instant::now() < deadline, "Windows fixture did not reach its expected transition");
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn owner_recovery_requires_final_close_and_keeps_the_slot_pinned() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("owner");
    let owner = open_owner(&path, true).unwrap();
    let expected = identity(&owner).unwrap();
    for _ in 0..100 {
        assert!(recover_owner(&path, expected).unwrap().is_none());
    }
    let duplicate = owner.try_clone().unwrap();
    drop(owner);
    assert!(recover_owner(&path, expected).unwrap().is_none());
    assert!(fs::remove_file(&path).is_err(), "a live owner must pin its pathname");
    assert!(fs::rename(&path, root.path().join("removed")).is_err());
    drop(duplicate);
    let recovered = recover_owner(&path, expected).unwrap().expect("final reference closed");
    assert_eq!(identity(&recovered).unwrap(), expected);
    assert!(recover_owner(&path, expected).unwrap().is_none(), "recovery holds the slot through commit");
    drop(recovered);
    assert!(recover_owner(&path, expected).unwrap().is_some());
}

#[test]
fn missing_replaced_and_hardlinked_owner_files_never_prove_exit() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("owner");
    let old = open_owner(&path, true).unwrap();
    let expected = identity(&old).unwrap();
    drop(old);
    fs::rename(&path, root.path().join("retained-old-owner")).unwrap();
    assert!(recover_owner(&path, expected).is_err());
    let replacement = open_owner(&path, true).unwrap();
    assert_ne!(identity(&replacement).unwrap(), expected);
    assert!(recover_owner(&path, expected).is_err(), "even a currently live replacement is incompatible");
    drop(replacement);
    assert!(recover_owner(&path, expected).is_err());
    fs::remove_file(&path).unwrap();
    fs::hard_link(root.path().join("retained-old-owner"), &path).unwrap();
    assert!(recover_owner(&path, expected).is_err());
    fs::remove_file(&path).unwrap();
    fs::rename(root.path().join("retained-old-owner"), &path).unwrap();
    let original_permissions = fs::metadata(&path).unwrap().permissions();
    let mut readonly = original_permissions.clone();
    readonly.set_readonly(true);
    fs::set_permissions(&path, readonly).unwrap();
    let denied = recover_owner(&path, expected);
    fs::set_permissions(&path, original_permissions).unwrap();
    assert!(
        matches!(denied, Err(error) if error.kind() == io::ErrorKind::PermissionDenied),
        "an inaccessible data handle is not proof of final close"
    );
}

#[test]
fn bookkeeping_is_nonblocking_across_independent_opens_and_unrelated_closes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("anchor");
    let first = open_bookkeeping(&path, true).unwrap();
    let second = open_bookkeeping(&path, false).unwrap();
    let lock = Bookkeeping::try_lock(&first).unwrap();
    for _ in 0..100 {
        drop(open_bookkeeping(&path, false).unwrap());
        assert!(matches!(Bookkeeping::try_lock(&second), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    }
    lock.unlock().unwrap();
    Bookkeeping::try_lock(&second).unwrap().unlock().unwrap();
    assert!(fs::rename(&path, root.path().join("replacement")).is_err(), "open anchors prevent replacement");
}

struct Fixture {
    child: Child,
    root: PathBuf,
}

impl Fixture {
    fn spawn(root: &Path, mode: &str, stdin: Stdio) -> Self {
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows_fixture", "--ignored", "--nocapture"])
            .env("TREE_FUCKER_WINDOWS_FIXTURE", mode)
            .env("TREE_FUCKER_WINDOWS_ROOT", root)
            .stdin(stdin)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        Self { child, root: root.to_owned() }
    }

    fn ready(&mut self, name: &str) {
        wait_until(|| {
            assert!(self.child.try_wait().unwrap().is_none(), "fixture exited before {name}");
            self.root.join(name).exists()
        });
    }

    fn kill(&mut self) {
        self.child.kill().unwrap();
        assert!(!self.child.wait().unwrap().success());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::write(self.root.join("release"), []);
    }
}

#[test]
fn inherited_owner_survives_original_process_death() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("owner");
    let initial = open_owner(&path, true).unwrap();
    let expected = identity(&initial).unwrap();
    drop(initial);
    let mut fixture = Fixture::spawn(root.path(), "owner-parent", Stdio::null());
    fixture.ready("descendant-ready");
    fixture.kill();
    for _ in 0..100 {
        assert!(recover_owner(&path, expected).unwrap().is_none(), "descendant still owns the slot");
    }
    fs::write(root.path().join("release"), []).unwrap();
    wait_until(|| recover_owner(&path, expected).unwrap().is_some());
    assert_eq!(identity(&open_owner(&path, false).unwrap()).unwrap(), expected);
}

fn authority() -> Authority {
    Authority::new(Generation([1; 16]), Config::from_host(&HostConfig::default(), 4, 8, 4).unwrap(), 0).unwrap()
}

/// Actual writer termination at each production journal publication write.
/// A different live process owns the operation file throughout recovery.
#[test]
fn writer_death_recovers_the_journal_without_releasing_live_operation_ownership() {
    for cut in 1..=4 {
        let root = tempfile::tempdir().unwrap();
        let anchor = open_bookkeeping(&root.path().join("anchor"), true).unwrap();
        let operation_owner = open_owner(&root.path().join("owner"), true).unwrap();
        let expected = identity(&operation_owner).unwrap();
        let initial = authority();
        let lock = Bookkeeping::try_lock(&anchor).unwrap();
        Journal::create(open_bookkeeping(&root.path().join("journal"), true).unwrap(), &initial).unwrap();
        lock.unlock().unwrap();
        let mut fixture = Fixture::spawn(root.path(), &format!("writer-{cut}"), Stdio::null());
        fixture.ready("writer-paused");
        assert!(matches!(Bookkeeping::try_lock(&anchor), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        fixture.kill();
        // Windows may release a killed process's locks asynchronously.
        let mut recovered_lock = None;
        wait_until(|| match Bookkeeping::try_lock(&anchor) {
            Ok(lock) => {
                recovered_lock = Some(lock);
                true
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => false,
            Err(error) => panic!("bookkeeping recovery failed: {error}"),
        });
        let mut journal = Journal::open(open_bookkeeping(&root.path().join("journal"), false).unwrap()).unwrap();
        let state = journal.load().unwrap();
        // A complete prepared payload is conservatively committed during
        // recovery, even when its writer never acknowledged authorization.
        assert_eq!(state.view().physical, u32::from(cut >= 3), "recoverable decision at cut {cut}");
        assert_eq!(state.view().charged_ns > 0, cut >= 3);
        assert!(recover_owner(&root.path().join("owner"), expected).unwrap().is_none());
        drop(journal);
        recovered_lock.take().unwrap().unlock().unwrap();
        drop(recovered_lock);
        drop(operation_owner);
        assert!(recover_owner(&root.path().join("owner"), expected).unwrap().is_some());
        // Closing every journal/anchor handle must preserve the same decision.
        drop(anchor);
        let reopened = open_bookkeeping(&root.path().join("anchor"), false).unwrap();
        let lock = Bookkeeping::try_lock(&reopened).unwrap();
        let retained =
            Journal::open(open_bookkeeping(&root.path().join("journal"), false).unwrap()).unwrap().load().unwrap();
        assert_eq!(retained.encode().unwrap(), state.encode().unwrap());
        lock.unlock().unwrap();
    }
}

struct Interrupted {
    file: File,
    root: PathBuf,
    cut: usize,
    writes: usize,
}

impl Read for Interrupted {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}

impl Seek for Interrupted {
    fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
        self.file.seek(at)
    }
}

impl Write for Interrupted {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        self.file.write_all(bytes)?;
        if self.writes == self.cut {
            fs::write(self.root.join("writer-paused"), [])?;
            wait_until(|| self.root.join("release").exists());
            panic!("writer was released instead of killed");
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[test]
#[ignore = "independent process entry point"]
fn windows_fixture() {
    let root = PathBuf::from(std::env::var_os("TREE_FUCKER_WINDOWS_ROOT").unwrap());
    let mode = std::env::var("TREE_FUCKER_WINDOWS_FIXTURE").unwrap();
    if mode == "owner-parent" {
        let owner = open_owner(&root.join("owner"), false).unwrap();
        let mut child = Fixture::spawn(&root, "owner-descendant", Stdio::from(owner.try_clone().unwrap()));
        child.ready("descendant-ready");
        wait_until(|| root.join("release").exists());
        assert!(child.child.wait().unwrap().success());
    } else if mode == "owner-descendant" {
        // The standard-input handle is an inherited reference to the owner's
        // exclusive file, not a newly opened file with different sharing.
        let input = std::io::stdin();
        use std::os::windows::io::AsHandle;
        let retained = File::from(input.as_handle().try_clone_to_owned().unwrap());
        let expected = identity(&retained).unwrap();
        assert!(recover_owner(&root.join("owner"), expected).unwrap().is_none());
        fs::write(root.join("descendant-ready"), []).unwrap();
        wait_until(|| root.join("release").exists());
    } else if let Some(cut) = mode.strip_prefix("writer-") {
        let anchor = open_bookkeeping(&root.join("anchor"), false).unwrap();
        let _lock = Bookkeeping::try_lock(&anchor).unwrap();
        let mut journal = Journal::open(Interrupted {
            file: open_bookkeeping(&root.join("journal"), false).unwrap(),
            root,
            cut: cut.parse().unwrap(),
            writes: 0,
        })
        .unwrap();
        journal
            .transaction(|state| {
                let participant = state.join(VERSION)?;
                let id = OperationId { participant, sequence: 1 };
                state.prepare(
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
                )?;
                state.authorize(id, 0)
            })
            .unwrap();
        panic!("writer did not stop at the requested publication boundary");
    } else {
        panic!("unknown Windows fixture");
    }
}

fn open(path: &Path, create: bool, share: u32) -> io::Result<File> {
    let file = Principal::current()?.open_file(path, create, share)?;
    identity(&file)?;
    Ok(file)
}

pub(crate) fn open_bookkeeping(path: &Path, create: bool) -> io::Result<File> {
    open(path, create, FILE_SHARE_READ | FILE_SHARE_WRITE)
}

/// No sharing of data or delete access. Duplicates and inherited handles retain
/// this exclusion; only closing the final reference relinquishes ownership.
pub(crate) fn open_owner(path: &Path, create: bool) -> io::Result<File> {
    open(path, create, 0)
}

/// `None` proves only that conflicting data access is still held. Every other
/// failure is an error, never evidence of owner exit. Attribute access pins the
/// expected file while the conflicting open probes its lifetime.
pub(crate) fn recover_owner(path: &Path, expected: Identity) -> io::Result<Option<File>> {
    let principal = Principal::current()?;
    let parent =
        path.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "owner file has no parent"))?;
    let name = path.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "owner file has no name"))?;
    let parent = relative::Directory::open(parent)?;
    recover_at(parent.handle(), name, expected, &principal)
}
