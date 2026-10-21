//! Retained Windows authority with exclusive file-handle operation ownership.

mod clock;
mod handles;
mod initialization;
mod relative;
mod security;
mod storage;

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError};

use clock::Clock;
use handles::{Bookkeeping, Identity, directory_identity, identity};
use security::Principal;
use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

use super::authority::{self, Authority, Config, View};
pub(crate) use super::client::Physical;
use super::client::{Cleanup, Pending};
pub use super::client::{Client, Completion, Prepared};
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

/// One independently opened connection to retained per-user accounting.
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccessCounters {
    pub attempts: u64,
    pub acquired: u64,
    pub busy: u64,
}

#[derive(Clone, Debug)]
pub struct Diagnostics {
    pub path: PathBuf,
    pub generation: Generation,
    pub config: Config,
    pub user: String,
    pub clock: [u8; 32],
    pub volume: u64,
    pub root: [u8; 16],
    pub pending_settlements: usize,
    pub bookkeeping_active: bool,
    pub failed: bool,
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
        Ok(self.clock.now()?.max(state.now()))
    }

    pub(crate) fn check_context(&self) -> Result<(), Error> {
        self.principal.check().map_err(|_| Error::Incompatible)?;
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::Failed);
        }
        Ok(())
    }

    /// Resolve the effective user's OS-configured local application-data path.
    /// Environment variables and logon/session IDs do not select an authority.
    pub fn discover(config: Config) -> Result<Arc<Self>, Error> {
        config.validate()?;
        let principal = Principal::current()?;
        let path = principal.local_data_directory()?.join("tree-fucker-coordination");
        Self::open_for(path, config, principal)
    }

    /// Open a private retained scope on verified local NTFS or ReFS storage.
    pub fn open(path: impl AsRef<Path>, config: Config) -> Result<Arc<Self>, Error> {
        config.validate()?;
        let principal = Principal::current()?;
        Self::open_for(path.as_ref().to_path_buf(), config, principal)
    }

    fn open_for(path: PathBuf, config: Config, principal: Principal) -> Result<Arc<Self>, Error> {
        principal.check().map_err(|_| Error::Incompatible)?;
        let clock = Clock::current()?;
        let root_name = path.file_name().ok_or(Error::InvalidScope)?.to_os_string();
        let parent = relative::Directory::open(path.parent().ok_or(Error::InvalidScope)?)?;
        let mut anchor_name = root_name.clone();
        anchor_name.push(".authority.lock");
        let anchor = principal.open_at(parent.handle(), &anchor_name, true, SHARED, false)?;
        let lock = Bookkeeping::try_lock(&anchor).map_err(lock_error)?;
        let (root, mut journal) = initialization::open(&parent, &root_name, &anchor, &principal, &clock, config)?;
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
            // Final-close evidence stays exclusively held through publication.
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

    pub fn join(self: &Arc<Self>) -> Result<Client, Error> {
        self.access(|store| {
            let Store { journal, recovery_slot } = store;
            let mut recovered = Vec::new();
            journal.transaction_with(|state| {
                self.recover(state, recovery_slot, &mut recovered)?;
                for slot in 0..self.config.ownership.participants {
                    if state.ledger().participants().any(|participant| participant.slot == slot) {
                        continue;
                    }
                    let owner = if let Some(index) =
                        recovered.iter().position(|(recovered_slot, _)| *recovered_slot == slot)
                    {
                        recovered.swap_remove(index).1
                    } else {
                        match self.principal.open_at(&self.root, OsStr::new(&format!("owner-{slot}")), true, 0, false) {
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
                    return Ok(Ok(Client::new(self.clone(), participant, owner)));
                }
                Ok::<_, Error>(Err(Error::Authority(protocol::Error::ParticipantCapacity.into())))
            })?
        })
    }

    pub fn view(&self) -> Result<View, Error> {
        self.transaction(|state, at| {
            state.advance(at)?;
            Ok(state.view())
        })
    }

    pub fn diagnostics(&self) -> Result<Diagnostics, Error> {
        self.principal.check().map_err(|_| Error::Incompatible)?;
        let (pending_settlements, bookkeeping_active) = self.queue.status();
        Ok(Diagnostics {
            path: self.path.clone(),
            generation: self.generation,
            config: self.config,
            user: self.principal.sid.clone(),
            clock: self.clock.epoch.encode(),
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

impl Scope {
    pub(crate) fn enqueue(self: &Arc<Self>, pending: Pending) -> Result<(), Error> {
        self.queue.enqueue(self, pending, self.config.ownership.operations as usize)
    }
    pub(crate) fn cleanup(&self) -> &Cleanup {
        &self.queue
    }
}
