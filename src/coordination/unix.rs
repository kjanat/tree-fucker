//! This module provides the retained tmpfs authority with open-description
//! lifetime locks.
//!
//! The backend retains authority files and never replaces them automatically.
//! All lock acquisition for admission is nonblocking. The backend stores no
//! target paths.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError};

use rustix::fs::{FlockOperation, Mode, OFlags, flock, openat};

use super::authority::{self, Authority, Config, View};
pub(crate) use super::client::Physical;
use super::client::{Cleanup, Pending};
pub use super::client::{Client, Completion, Prepared};
#[cfg(target_os = "freebsd")]
use super::freebsd as platform;
#[cfg(target_os = "illumos")]
use super::illumos as platform;
use super::journal::{self, Journal};
#[cfg(target_os = "linux")]
use super::linux as platform;
#[cfg(target_os = "macos")]
use super::macos as platform;
use super::protocol::{self, Generation, VERSION};
use super::wire::checksum;

#[cfg(test)]
#[path = "unix/initialization.rs"]
mod initialization;

const STATE: &str = "authority.state";
const HEADER_SIZE: usize = 128;
const PREPARING: u8 = 0x5a;
const READY: u8 = 0xa5;
const RECOVERY_BATCH: usize = 8;

pub use super::native_error::Error;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Context {
    pid: u32,
    uid: u32,
    namespaces: [[u8; 16]; 3],
}

impl Context {
    fn current() -> Result<Self, Error> {
        Ok(Self {
            pid: rustix::process::getpid().as_raw_nonzero().get() as u32,
            uid: rustix::process::geteuid().as_raw(),
            namespaces: platform::namespaces()?,
        })
    }

    fn check(self) -> Result<(), Error> {
        // Do not touch inherited mutexes before checking the PID.
        if rustix::process::getpid().as_raw_nonzero().get() as u32 != self.pid {
            return Err(Error::Forked);
        }
        if Self::current()? != self {
            return Err(Error::Incompatible);
        }
        Ok(())
    }
}

pub(super) fn identity(metadata: &fs::Metadata) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&metadata.dev().to_le_bytes());
    bytes[8..].copy_from_slice(&metadata.ino().to_le_bytes());
    bytes
}

fn is_tmpfs(file: &File) -> Result<bool, Error> {
    platform::is_tmpfs(file)
}

fn now() -> Result<u64, Error> {
    let time = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let seconds = u64::try_from(time.tv_sec).map_err(|_| Error::InvalidScope)?;
    seconds.checked_mul(1_000_000_000).and_then(|ns| ns.checked_add(time.tv_nsec as u64)).ok_or(Error::InvalidScope)
}

fn exclusive(file: &File) -> Result<(), Error> {
    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(Error::Busy),
        Err(error) => Err(error.into()),
    }
}

struct Unlock<'a>(Option<&'a File>);

impl Unlock<'_> {
    fn release(mut self) -> Result<(), Error> {
        flock(self.0.expect("held bookkeeping lock"), FlockOperation::Unlock)?;
        self.0 = None;
        Ok(())
    }
}

impl Drop for Unlock<'_> {
    fn drop(&mut self) {
        if let Some(file) = self.0 {
            let _ = flock(file, FlockOperation::Unlock);
        }
    }
}

fn bookkeeping<T>(anchor: &File, operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    exclusive(anchor)?;
    // A concurrent fork can retain this open description after this process
    // closes it.
    // Bookkeeping exclusion ends here even when initialization fails or
    // unwinds.
    let unlock = Unlock(Some(anchor));
    let result = operation();
    unlock.release()?;
    result
}

fn open_file(root: &File, name: &OsStr, create: bool, uid: u32) -> Result<File, Error> {
    let flags =
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | if create { OFlags::CREATE } else { OFlags::empty() };
    let file = File::from(openat(root, name, flags, Mode::RUSR | Mode::WUSR)?);
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o7777 != 0o600 || meta.nlink() != 1 {
        return Err(Error::InvalidScope);
    }
    Ok(file)
}

fn matches_file(root: &File, name: &OsStr, file: &File, uid: u32) -> Result<(), Error> {
    let current = open_file(root, name, false, uid).map_err(|_| Error::Replaced)?;
    if identity(&current.metadata()?) != identity(&file.metadata()?) {
        return Err(Error::Replaced);
    }
    Ok(())
}

struct Store {
    journal: Journal<File>,
    recovery_slot: u32,
}

/// `Scope` is one independently opened connection to a retained tmpfs
/// authority.
///
/// Clone the returned `Arc` within a process. Independently opened connections
/// use distinct open file descriptions and coordinate through the kernel.
pub struct Scope {
    path: PathBuf,
    root: File,
    anchor_root: File,
    anchor_name: std::ffi::OsString,
    anchor: File,
    context: Context,
    store: Mutex<Store>,
    failed: AtomicBool,
    queue: Cleanup,
    config: Config,
    generation: Generation,
    attempts: AtomicU64,
    acquired: AtomicU64,
    busy: AtomicU64,
}

/// `AccessCounters` counts this connection's bookkeeping lock activity.
///
/// The counters include deferred settlement and cover this connection only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccessCounters {
    /// `attempts` counts the accesses that tried to take the bookkeeping locks.
    pub attempts: u64,
    /// `acquired` counts the accesses that acquired the interprocess lock.
    pub acquired: u64,
    /// `busy` counts the accesses that found the connection mutex or the
    /// interprocess lock busy.
    pub busy: u64,
}

/// `Diagnostics` describes one connection without taking the shared lock.
///
/// [`Scope::view`] reports the shared budget totals.
#[derive(Clone, Debug)]
pub struct Diagnostics {
    /// `path` names the directory where the connection opened the scope.
    pub path: PathBuf,
    /// `generation` identifies the retained authority.
    pub generation: Generation,
    /// `config` holds the configuration that the authority enforces.
    pub config: Config,
    /// `namespaces` holds the three identities that qualify the scope on this
    /// platform.
    ///
    /// [`ScopeIdentity`](super::ScopeIdentity) names each component per
    /// platform.
    pub namespaces: [[u8; 16]; 3],
    /// `pending_settlements` counts the settlements and cancellations that wait
    /// for the bookkeeping lock.
    pub pending_settlements: usize,
    /// `bookkeeping_active` is `true` while a bookkeeping thread drains
    /// deferred settlements.
    pub bookkeeping_active: bool,
    /// `failed` is `true` after an uncertain failure fenced the connection.
    pub failed: bool,
    /// `access` reports the connection's lock activity.
    pub access: AccessCounters,
}

impl Diagnostics {
    pub(crate) fn identity(&self) -> super::ScopeIdentity {
        let [first, _second, third] = self.namespaces;
        #[cfg(target_os = "linux")]
        {
            super::ScopeIdentity::Linux { user: first, ipc: _second, time: third }
        }
        #[cfg(target_os = "freebsd")]
        {
            super::ScopeIdentity::FreeBsd { root: first, clock: third }
        }
        #[cfg(target_os = "macos")]
        {
            super::ScopeIdentity::MacOs { root: first, clock: third }
        }
        #[cfg(target_os = "illumos")]
        {
            super::ScopeIdentity::Illumos { root: first, zone: _second, clock: third }
        }
    }
}

impl Scope {
    pub(crate) fn fail(&self) {
        self.failed.store(true, Ordering::Release);
    }
    pub(crate) fn now(&self) -> Result<u64, Error> {
        now()
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn generation(&self) -> Generation {
        self.generation
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn mount_namespace(&self) -> [u8; 16] {
        self.context.namespaces[0]
    }

    pub(crate) fn check_context(&self) -> Result<(), Error> {
        self.context.check()?;
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::Failed);
        }
        Ok(())
    }

    /// `discover` opens the private scope for the effective user and namespace
    /// on the platform's retained tmpfs rendezvous.
    ///
    /// The backend creates nothing in a home directory or on a network
    /// filesystem.
    pub fn discover(config: Config) -> Result<Arc<Self>, Error> {
        let context = Context::current()?;
        let mut name = format!("tree-fucker-{}", context.uid);
        for namespace in context.namespaces {
            for byte in namespace {
                use std::fmt::Write as _;
                write!(name, "{byte:02x}").expect("write to string");
            }
        }
        Self::open(Path::new(platform::RENDEZVOUS).join(name), config)
    }

    /// `open` opens an explicit private scope at the absolute tmpfs path
    /// `path`.
    ///
    /// Isolated applications and acceptance tests use it. All cooperating
    /// participants must use the same path.
    pub fn open(path: impl AsRef<Path>, config: Config) -> Result<Arc<Self>, Error> {
        // Validate before creating retained storage.
        config.validate()?;
        let context = Context::current()?;
        let path = path.as_ref().to_path_buf();
        if !path.is_absolute() {
            return Err(Error::InvalidScope);
        }
        // Keep the persistent rendezvous outside the replaceable state
        // directory. Its header pins that directory's inode, so recreating
        // the directory cannot create another budget while old work runs.
        let parent = path.parent().ok_or(Error::InvalidScope)?;
        let anchor_root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(parent)?;
        let parent_meta = anchor_root.metadata()?;
        if !is_tmpfs(&anchor_root)?
            || ![0, context.uid].contains(&parent_meta.uid())
            || (parent_meta.mode() & 0o022 != 0 && parent_meta.mode() & 0o1000 == 0)
        {
            return Err(Error::InvalidScope);
        }
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&path)?;
        let meta = root.metadata()?;
        if meta.uid() != context.uid || meta.mode() & 0o7777 != 0o700 || !is_tmpfs(&root)? {
            return Err(Error::InvalidScope);
        }
        let mut anchor_name = path.file_name().ok_or(Error::InvalidScope)?.to_os_string();
        anchor_name.push(".authority.lock");
        let anchor = open_file(&anchor_root, &anchor_name, true, context.uid)?;
        let (journal, generation) = bookkeeping(&anchor, || {
            let mut journal = initialize(&root, &anchor, context, config)?;
            let generation = journal.load()?.ledger().generation();
            Ok((journal, generation))
        })?;
        let scope = Arc::new(Self {
            path,
            root,
            anchor_root,
            anchor_name,
            anchor,
            context,
            store: Mutex::new(Store { journal, recovery_slot: 0 }),
            failed: AtomicBool::new(false),
            queue: Cleanup::new(),
            config,
            generation,
            attempts: AtomicU64::new(0),
            acquired: AtomicU64::new(0),
            busy: AtomicU64::new(0),
        });
        scope.check_files()?;
        Ok(scope)
    }

    fn check_files(&self) -> Result<(), Error> {
        let current = fs::symlink_metadata(&self.path).map_err(|_| Error::Replaced)?;
        if !current.is_dir()
            || current.uid() != self.context.uid
            || current.mode() & 0o7777 != 0o700
            || identity(&current) != identity(&self.root.metadata()?)
        {
            return Err(Error::Replaced);
        }
        matches_file(&self.anchor_root, &self.anchor_name, &self.anchor, self.context.uid)
    }

    fn access<T>(&self, operation: impl FnOnce(&mut Store) -> Result<T, Error>) -> Result<T, Error> {
        self.context.check()?;
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::Failed);
        }
        self.attempts.fetch_add(1, Ordering::Relaxed);
        let mut store = match self.store.try_lock() {
            Ok(store) => store,
            Err(TryLockError::WouldBlock) => {
                self.busy.fetch_add(1, Ordering::Relaxed);
                return Err(Error::Busy);
            }
            Err(TryLockError::Poisoned(_)) => return Err(Error::Failed),
        };
        if let Err(error) = exclusive(&self.anchor) {
            if matches!(error, Error::Busy) {
                self.busy.fetch_add(1, Ordering::Relaxed);
            }
            return Err(error);
        }
        self.acquired.fetch_add(1, Ordering::Relaxed);
        let _unlock = Unlock(Some(&self.anchor));
        let result = (|| {
            self.check_files()?;
            matches_file(&self.root, OsStr::new(STATE), store.journal.storage(), self.context.uid)?;
            operation(&mut store)
        })();
        if matches!(result, Err(Error::Io(_) | Error::Journal(_) | Error::Replaced | Error::Failed)) {
            self.failed.store(true, Ordering::Release);
        }
        result
    }

    pub(crate) fn transaction<T>(
        &self,
        operation: impl FnOnce(&mut Authority, u64) -> Result<T, authority::Error>,
    ) -> Result<T, Error> {
        self.access(|store| {
            let Store { journal, recovery_slot } = store;
            journal
                .transaction_with(|state| {
                    self.recover(state, recovery_slot)?;
                    // Commit accrued accounting even when policy denies this
                    // request, without decoding the same snapshot a second
                    // time.
                    Ok::<_, Error>(operation(state, now()?))
                })?
                .map_err(Error::Authority)
        })
    }

    fn recover(&self, state: &mut Authority, recovery_slot: &mut u32) -> Result<(), Error> {
        let mut expired = Vec::new();
        let count = self.config.ownership.participants;
        for _ in 0..RECOVERY_BATCH.min(count as usize) {
            let slot = *recovery_slot;
            *recovery_slot = (slot + 1) % count;
            let Some(participant) = state.ledger().participants().find(|participant| participant.slot == slot) else {
                continue;
            };
            let expected =
                state.ledger().owner(participant).map_err(authority::Error::from)?.ok_or(Error::Incompatible)?;
            let owner = open_file(&self.root, OsStr::new(&format!("owner-{slot}")), false, self.context.uid)
                .map_err(|_| Error::Replaced)?;
            if identity(&owner.metadata()?) != expected {
                return Err(Error::Replaced);
            }
            match exclusive(&owner) {
                // The authority lock excludes concurrent joins through commit.
                // Acquiring this lifetime lock is permanent proof that the
                // original incarnation no longer has any execution handles.
                Ok(()) => expired.push((participant, owner)),
                Err(Error::Busy) => {}
                Err(error) => return Err(error),
            }
        }
        if !expired.is_empty() {
            let at = now()?;
            let mut remaining = RECOVERY_BATCH;
            for (participant, _) in &expired {
                let operations: Vec<_> = state
                    .ledger()
                    .records()
                    .filter(|record| record.id.participant == *participant)
                    .map(|record| record.id)
                    .take(remaining)
                    .collect();
                remaining -= operations.len();
                for id in operations {
                    state.reclaim_after_owner_exit(id, at)?;
                }
                if !state.ledger().records().any(|record| record.id.participant == *participant) {
                    state.leave(*participant)?;
                }
            }
        }
        Ok(())
    }

    /// `join` registers a new participant and returns its [`Client`].
    ///
    /// The participant holds an exclusive lifetime lock on a persistent owner
    /// slot file. Joining first recovers the operations of owners that
    /// exited, in bounded batches, and visits the whole participant table
    /// before it reports participant capacity exhaustion.
    pub fn join(self: &Arc<Self>) -> Result<Client, Error> {
        // Visit the whole table before reporting exhaustion, committing each
        // bounded recovery batch and releasing the authority lock between them.
        for _ in (0..self.config.ownership.participants).step_by(RECOVERY_BATCH) {
            let client = self.access(|store| {
                let Store { journal, recovery_slot } = store;
                journal.transaction_with(|state| {
                    self.recover(state, recovery_slot)?;
                    if state.ledger().participant_count() == self.config.ownership.participants as usize {
                        return Ok(None);
                    }
                    for slot in 0..self.config.ownership.participants {
                        if state.ledger().participants().any(|participant| participant.slot == slot) {
                            continue;
                        }
                        let owner =
                            open_file(&self.root, OsStr::new(&format!("owner-{slot}")), true, self.context.uid)?;
                        match exclusive(&owner) {
                            Ok(()) => {}
                            Err(Error::Busy) => continue,
                            Err(error) => return Err(error),
                        }
                        let identity = identity(&owner.metadata()?);
                        let participant = state.join_owned(VERSION, slot, identity)?;
                        return Ok(Some(Client::new(self.clone(), participant, owner)));
                    }
                    // Retain successful recovery even if no participant slot is
                    // available yet. A retry must not repeat discarded
                    // recovery.
                    Ok::<_, Error>(None)
                })
            })?;
            if let Some(client) = client {
                return Ok(client);
            }
        }
        Err(Error::Authority(protocol::Error::ParticipantCapacity.into()))
    }

    /// `view` returns the shared accounting at the current authority time.
    ///
    /// The caller must not add this view to process accounting.
    pub fn view(&self) -> Result<View, Error> {
        self.transaction(|state, at| {
            state.advance(at)?;
            Ok(state.view())
        })
    }

    /// `diagnostics` reads connection state without acquiring the shared lock.
    pub fn diagnostics(&self) -> Result<Diagnostics, Error> {
        self.context.check()?;
        let (pending_settlements, bookkeeping_active) = self.queue.status();
        Ok(Diagnostics {
            path: self.path.clone(),
            generation: self.generation,
            config: self.config,
            namespaces: self.context.namespaces,
            pending_settlements,
            bookkeeping_active,
            failed: self.failed.load(Ordering::Acquire),
            access: AccessCounters {
                attempts: self.attempts.load(Ordering::Relaxed),
                acquired: self.acquired.load(Ordering::Relaxed),
                busy: self.busy.load(Ordering::Relaxed),
            },
        })
    }

    pub(crate) fn enqueue(self: &Arc<Self>, pending: Pending) -> Result<(), Error> {
        self.queue.enqueue(self, pending, self.config.ownership.operations as usize)
    }
    pub(crate) fn cleanup(&self) -> &Cleanup {
        &self.queue
    }
}

fn initialize(root: &File, mut anchor: &File, context: Context, config: Config) -> Result<Journal<File>, Error> {
    let length = anchor.metadata()?.len();
    initialize_storage(root, &mut anchor, length, context, config)
}

fn initialize_storage(
    root: &File,
    anchor: &mut (impl Read + Write + Seek),
    anchor_length: u64,
    context: Context,
    config: Config,
) -> Result<Journal<File>, Error> {
    let mut bytes = [0; HEADER_SIZE];
    let mut state;
    if anchor_length == 0 {
        state = open_file(root, OsStr::new(STATE), true, context.uid)?;
        // An empty anchor never grants permission to overwrite existing debt.
        if state.metadata()?.len() != 0 {
            return Err(Error::Replaced);
        }
        bytes[..8].copy_from_slice(platform::MAGIC);
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[12] = PREPARING;
        getrandom::fill(&mut bytes[16..32]).map_err(io::Error::from)?;
        bytes[32..40].copy_from_slice(&u64::from(context.uid).to_le_bytes());
        for (target, namespace) in bytes[40..88].as_chunks_mut::<16>().0.iter_mut().zip(context.namespaces) {
            target.copy_from_slice(&namespace);
        }
        bytes[88..104].copy_from_slice(&identity(&root.metadata()?));
        bytes[104..120].copy_from_slice(&identity(&state.metadata()?));
        let hash = anchor_checksum(&bytes);
        bytes[120..].copy_from_slice(&hash.to_le_bytes());
        anchor.write_all(&bytes)?;
        anchor.flush()?;
    } else {
        if anchor_length != HEADER_SIZE as u64 {
            return Err(Error::Replaced);
        }
        anchor.read_exact(&mut bytes)?;
        if &bytes[..8] != platform::MAGIC
            || bytes[8..12] != 1u32.to_le_bytes()
            || bytes[13..16] != [0; 3]
            || ![PREPARING, READY].contains(&bytes[12])
            || bytes[120..] != anchor_checksum(&bytes).to_le_bytes()
        {
            return Err(Error::Incompatible);
        }
        state = open_file(root, OsStr::new(STATE), false, context.uid).map_err(|_| Error::Replaced)?;
    }
    if bytes[32..40] != u64::from(context.uid).to_le_bytes()
        || !bytes[40..88].as_chunks::<16>().0.iter().zip(context.namespaces).all(|(a, b)| *a == b)
        || bytes[88..104] != identity(&root.metadata()?)
        || bytes[104..120] != identity(&state.metadata()?)
    {
        return Err(Error::Incompatible);
    }
    let generation = Generation(bytes[16..32].try_into().expect("generation"));
    if bytes[12] == PREPARING {
        // Reuse a fully published journal even if the anchor's final READY
        // byte was not written. Never reset known accounting only because
        // the anchor is preparing.
        let recovered = if state.metadata()?.len() > journal::HEADER {
            let mut journal = Journal::open(state.try_clone()?)?;
            match journal.load() {
                Ok(authority) => {
                    if authority.config() != config || authority.ledger().generation() != generation {
                        return Err(Error::Incompatible);
                    }
                    Some(journal)
                }
                Err(journal::Error::Uninitialized) => None,
                Err(error) => return Err(error.into()),
            }
        } else {
            None
        };
        let journal = match recovered {
            Some(journal) => journal,
            None => {
                // No initial snapshot was published. Retain the pinned inode.
                state.set_len(0)?;
                state.seek(SeekFrom::Start(0))?;
                Journal::create(state, &Authority::new(generation, config, now()?)?)?
            }
        };
        anchor.seek(SeekFrom::Start(12))?;
        anchor.write_all(&[READY])?;
        anchor.flush()?;
        Ok(journal)
    } else {
        let mut journal = Journal::open(state)?;
        let authority = journal.load()?;
        if authority.config() != config || authority.ledger().generation() != generation {
            return Err(Error::Incompatible);
        }
        Ok(journal)
    }
}

fn anchor_checksum(bytes: &[u8; HEADER_SIZE]) -> u64 {
    let mut header = *bytes;
    header[12] = 0; // Initialization decision is the last single-byte write.
    checksum(&header[..120])
}
