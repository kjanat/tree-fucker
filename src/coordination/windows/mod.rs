//! This module provides the retained Windows authority, and exclusive file
//! handles establish operation ownership.

mod clock;
mod handles;
mod initialization;
mod relative;
mod security;
mod storage;

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError};

use clock::Clock;
use handles::{Bookkeeping, Identity, directory_identity, identity};
use security::Principal;
use windows_sys::Win32::Foundation::{ERROR_NO_TOKEN, ERROR_SHARING_VIOLATION};
use windows_sys::Win32::Security::{TOKEN_IMPERSONATE, TOKEN_QUERY};
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken, SetThreadToken};

use super::authority::{self, Authority, Config, View};
pub(crate) use super::client::Physical;
use super::client::{Cleanup, Pending};
pub use super::client::{Client, Completion, Prepared};
use super::clock_binding::ClockBinding;
use super::journal::Journal;
pub use super::native_error::Error;
use super::protocol::{self, Generation, VERSION};

const STATE: &str = "authority.state";
const SHARED: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
const RECOVERY_BATCH: usize = 8;

struct Store {
    journal: Journal<File>,
    recovery_slot: u32,
}

/// `Scope` is one independently opened connection to retained per-user
/// accounting.
///
/// Clone the returned `Arc` within a process. The scope lives on verified
/// local NTFS or ReFS storage under a protected owner-only DACL.
pub struct Scope {
    path: PathBuf,
    parent: relative::Directory,
    root_name: OsString,
    root: File,
    root_id: Identity,
    anchor_name: OsString,
    anchor: File,
    principal: Principal,
    clock: Clock,
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
    /// `acquired` counts the accesses that acquired the anchor's byte-range
    /// lock.
    pub acquired: u64,
    /// `busy` counts the accesses that found the connection mutex or the
    /// byte-range lock busy.
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
    /// `user` holds the effective user's SID.
    pub user: String,
    /// `clock` encodes the boot-entry GUID, kernel boot sequence, and
    /// performance-counter frequency of the current boot.
    pub clock: [u8; 32],
    /// `clock_offset_ns` holds the signed offset that the connection adds to
    /// the raw counter time to obtain authority time.
    ///
    /// The journal retains the offset, and a reboot rebases it at the last
    /// committed authority time (coordination-platforms.md, "Windows").
    pub clock_offset_ns: i64,
    /// `volume` holds the volume serial number of the scope directory.
    pub volume: u64,
    /// `root` holds the 128-bit file ID of the scope directory.
    pub root: [u8; 16],
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
        super::ScopeIdentity::Windows {
            user: self.user.clone(),
            clock: self.clock,
            volume: self.volume,
            root: self.root,
        }
    }
}

impl Scope {
    pub(crate) fn fail(&self) {
        self.failed.store(true, Ordering::Release);
    }
    pub(crate) fn now(&self) -> Result<u64, Error> {
        Ok(self.clock.now()?)
    }

    fn now_at(&self, state: &Authority) -> Result<u64, Error> {
        // Cross-thread QPC readings can differ by a tick. Clamp this reading
        // so every connection stays on the same persisted counter mapping.
        Ok(self.clock.now()?.max(state.now()))
    }

    pub(crate) fn check_context(&self) -> Result<(), Error> {
        self.principal.check().map_err(|_| Error::Incompatible)?;
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::Failed);
        }
        Ok(())
    }

    /// `discover` opens the scope in the effective user's local application
    /// data folder.
    ///
    /// The shell's known-folder lookup with the effective token resolves the
    /// folder. Environment variables and logon or session IDs never select an
    /// authority.
    pub fn discover(config: Config) -> Result<Arc<Self>, Error> {
        config.validate()?;
        let principal = Principal::current()?;
        let path = principal.local_data_directory()?.join("tree-fucker-coordination");
        Self::open_for(path, config, principal)
    }

    /// `open` opens a private retained scope at `path` on verified local NTFS
    /// or ReFS storage.
    ///
    /// All cooperating participants must use the same path.
    pub fn open(path: impl AsRef<Path>, config: Config) -> Result<Arc<Self>, Error> {
        config.validate()?;
        let principal = Principal::current()?;
        Self::open_for(path.as_ref().to_path_buf(), config, principal)
    }

    fn open_for(path: PathBuf, config: Config, principal: Principal) -> Result<Arc<Self>, Error> {
        principal.check().map_err(|_| Error::Incompatible)?;
        let mut clock = Clock::current()?;
        let root_name = path.file_name().ok_or(Error::InvalidScope)?.to_os_string();
        let parent = relative::Directory::open(path.parent().ok_or(Error::InvalidScope)?)?;
        let mut anchor_name = root_name.clone();
        anchor_name.push(".authority.lock");
        let anchor = principal.open_at(parent.handle(), &anchor_name, true, SHARED, false)?;
        let lock = Bookkeeping::try_lock(&anchor).map_err(lock_error)?;
        let (root, mut journal) = initialization::open(&parent, &root_name, &anchor, &principal, &mut clock, config)?;
        let root_id = directory_identity(&root)?;
        let generation = journal.load()?.ledger().generation();
        lock.unlock()?;
        let scope = Arc::new(Self {
            path,
            parent,
            root_name,
            root,
            root_id,
            anchor_name,
            anchor,
            principal,
            clock,
            store: Mutex::new(Store { journal, recovery_slot: 0 }),
            failed: AtomicBool::new(false),
            queue: Cleanup::new(),
            config,
            generation,
            attempts: AtomicU64::new(0),
            acquired: AtomicU64::new(0),
            busy: AtomicU64::new(0),
        });
        scope.access(|_| Ok(()))?;
        Ok(scope)
    }

    fn matches(&self, parent: &File, name: &OsStr, pinned: &File, directory: bool) -> Result<(), Error> {
        let current = self.principal.open_at(parent, name, false, SHARED, directory)?;
        let identify = if directory { directory_identity } else { identity };
        if identify(&current)? != identify(pinned)? {
            return Err(Error::Replaced);
        }
        Ok(())
    }

    fn access<T>(&self, operation: impl FnOnce(&mut Store) -> Result<T, Error>) -> Result<T, Error> {
        self.check_context()?;
        self.attempts.fetch_add(1, Ordering::Relaxed);
        let mut store = match self.store.try_lock() {
            Ok(store) => store,
            Err(TryLockError::WouldBlock) => {
                self.busy.fetch_add(1, Ordering::Relaxed);
                return Err(Error::Busy);
            }
            Err(TryLockError::Poisoned(_)) => {
                self.fail();
                return Err(Error::Failed);
            }
        };
        let lock = match Bookkeeping::try_lock(&self.anchor) {
            Ok(lock) => lock,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.busy.fetch_add(1, Ordering::Relaxed);
                return Err(Error::Busy);
            }
            Err(error) => {
                self.fail();
                return Err(error.into());
            }
        };
        self.acquired.fetch_add(1, Ordering::Relaxed);
        let result = (|| {
            self.matches(self.parent.handle(), &self.root_name, &self.root, true)?;
            self.matches(self.parent.handle(), &self.anchor_name, &self.anchor, false)?;
            self.matches(&self.root, OsStr::new(STATE), store.journal.storage(), false)?;
            operation(&mut store)
        })();
        if let Err(error) = lock.unlock() {
            self.fail();
            return Err(error.into());
        }
        if matches!(
            result,
            Err(Error::Io(_) | Error::Journal(_) | Error::Replaced | Error::Failed | Error::Incompatible)
        ) {
            self.fail();
        }
        result
    }

    pub(crate) fn transaction<T>(
        &self,
        operation: impl FnOnce(&mut Authority, u64) -> Result<T, authority::Error>,
    ) -> Result<T, Error> {
        self.access(|store| {
            let Store { journal, recovery_slot } = store;
            // `recovered` holds the final-close evidence exclusively until
            // publication.
            let mut recovered = Vec::new();
            journal
                .transaction_with(|state| {
                    self.recover(state, recovery_slot, &mut recovered)?;
                    let now = self.now_at(state)?;
                    Ok::<_, Error>(operation(state, now))
                })?
                .map_err(Error::Authority)
        })
    }

    fn recover(&self, state: &mut Authority, cursor: &mut u32, pins: &mut Vec<(u32, File)>) -> Result<(), Error> {
        if state.clock_binding() != Some(self.clock.binding()) {
            return Err(Error::Incompatible);
        }
        let count = self.config.ownership.participants;
        let mut remaining = RECOVERY_BATCH;
        for _ in 0..RECOVERY_BATCH.min(count as usize) {
            let slot = *cursor;
            *cursor = (slot + 1) % count;
            let participant = state.ledger().participants().find(|participant| participant.slot == slot);
            let Some(participant) = participant else {
                continue;
            };
            let file = state.ledger().owner(participant).map_err(authority::Error::from)?.ok_or(Error::Incompatible)?;
            let expected = Identity { volume: self.root_id.volume, file };
            let name = format!("owner-{slot}");
            let Some(owner) = handles::recover_at(&self.root, OsStr::new(&name), expected, &self.principal)? else {
                continue;
            };
            pins.push((slot, owner));
            let ids: Vec<_> = state
                .ledger()
                .records()
                .filter(|record| record.id.participant == participant)
                .map(|record| record.id)
                .take(remaining)
                .collect();
            remaining -= ids.len();
            let at = self.now_at(state)?;
            for id in ids {
                state.reclaim_after_owner_exit(id, at)?;
            }
            if !state.ledger().records().any(|record| record.id.participant == participant) {
                state.leave(participant)?;
            }
        }
        Ok(())
    }

    /// `join` registers a new participant and returns its [`Client`].
    ///
    /// The participant holds an exclusive handle on a persistent owner slot
    /// file. Joining first recovers the operations of owners whose handles
    /// all closed, in bounded batches, and visits the whole participant table
    /// before it reports participant capacity exhaustion.
    pub fn join(self: &Arc<Self>) -> Result<Client, Error> {
        // Fresh connections must reach every slot without extending a single
        // authority-lock hold beyond the bounded recovery batch.
        for _ in (0..self.config.ownership.participants).step_by(RECOVERY_BATCH) {
            let client = self.access(|store| {
                let Store { journal, recovery_slot } = store;
                let mut recovered = Vec::new();
                journal.transaction_with(|state| {
                    self.recover(state, recovery_slot, &mut recovered)?;
                    if state.ledger().participant_count() == self.config.ownership.participants as usize {
                        return Ok(None);
                    }
                    for slot in 0..self.config.ownership.participants {
                        if state.ledger().participants().any(|participant| participant.slot == slot) {
                            continue;
                        }
                        let owner = if let Some(index) =
                            recovered.iter().position(|(recovered_slot, _)| *recovered_slot == slot)
                        {
                            recovered.swap_remove(index).1
                        } else {
                            match self.principal.open_at(
                                &self.root,
                                OsStr::new(&format!("owner-{slot}")),
                                true,
                                0,
                                false,
                            ) {
                                Ok(owner) => owner,
                                Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => continue,
                                Err(error) => return Err(error.into()),
                            }
                        };
                        let id = identity(&owner)?;
                        if id.volume != self.root_id.volume {
                            return Err(Error::Replaced);
                        }
                        let participant = state.join_owned(VERSION, slot, id.file)?;
                        return Ok(Some(Client::new(self.clone(), participant, owner)));
                    }
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
        self.principal.check().map_err(|_| Error::Incompatible)?;
        let (pending_settlements, bookkeeping_active) = self.queue.status();
        Ok(Diagnostics {
            path: self.path.clone(),
            generation: self.generation,
            config: self.config,
            user: self.principal.sid.clone(),
            clock: self.clock.epoch.encode(),
            clock_offset_ns: self.clock.binding().offset_ns,
            volume: self.root_id.volume,
            root: self.root_id.file,
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
}

fn lock_error(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::WouldBlock { Error::Busy } else { error.into() }
}

pub(crate) struct Caller(Option<OwnedHandle>);

impl Caller {
    pub(crate) fn current() -> io::Result<Self> {
        let mut token = null_mut();
        // SAFETY: the pseudo-handle refers to this thread; success transfers
        // a real token handle to OwnedHandle.
        unsafe {
            if OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE | TOKEN_QUERY, 1, &mut token) == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_NO_TOKEN as i32) {
                    return Ok(Self(None));
                }
                return Err(error);
            }
            Ok(Self(Some(OwnedHandle::from_raw_handle(token))))
        }
    }

    pub(crate) fn enter(&self) -> io::Result<()> {
        let Some(token) = &self.0 else {
            return Ok(());
        };
        // SetThreadToken assigns the token object itself and keeps its TokenId.
        // SAFETY: null selects the current thread; the token handle is live.
        if unsafe { SetThreadToken(null(), token.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Scope {
    pub(crate) fn enqueue(self: &Arc<Self>, pending: Pending) -> Result<(), Error> {
        self.queue.enqueue(self, pending, self.config.ownership.operations as usize)
    }
    pub(crate) fn cleanup(&self) -> &Cleanup {
        &self.queue
    }
}
