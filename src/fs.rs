use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::domain::{ProbeError, ProbeResult};
use crate::entry::{EntryKind, FileIdentity, Metadata, MetadataFields};
use crate::ids::WatchId;
use crate::path::{CaseSensitivity, RelativePath};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FsError {
    NotFound,
    NotDirectory,
    PermissionDenied,
    Transient(String),
    Unsupported(String),
    Fatal(String),
}

impl FsError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, FsError::PermissionDenied | FsError::Transient(_) | FsError::Unsupported(_))
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsError::NotFound => f.write_str("not found"),
            FsError::NotDirectory => f.write_str("not a directory"),
            FsError::PermissionDenied => f.write_str("permission denied"),
            FsError::Transient(m) => write!(f, "transient failure: {m}"),
            FsError::Unsupported(m) => write!(f, "unsupported: {m}"),
            FsError::Fatal(m) => write!(f, "fatal: {m}"),
        }
    }
}

impl std::error::Error for FsError {}

impl From<std::io::Error> for FsError {
    fn from(err: std::io::Error) -> Self {
        use std::io::ErrorKind;
        match err.kind() {
            ErrorKind::NotFound => FsError::NotFound,
            ErrorKind::NotADirectory => FsError::NotDirectory,
            ErrorKind::PermissionDenied => FsError::PermissionDenied,
            ErrorKind::Unsupported => FsError::Unsupported(err.to_string()),
            _ => FsError::Transient(err.to_string()),
        }
    }
}

impl From<ProbeError> for FsError {
    fn from(err: ProbeError) -> Self {
        match err {
            ProbeError::NotFound => FsError::NotFound,
            ProbeError::NotDirectory => FsError::NotDirectory,
            ProbeError::PermissionDenied => FsError::PermissionDenied,
            ProbeError::Transient(m) => FsError::Transient(m),
            ProbeError::Unsupported(m) => FsError::Unsupported(m),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryInfo {
    pub kind: EntryKind,
    pub metadata: Metadata,
    pub identity: Option<FileIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObservedKind {
    Resolved(EntryKind),
    Unresolved,
}

impl ObservedKind {
    pub fn resolved(self) -> Option<EntryKind> {
        match self {
            ObservedKind::Resolved(kind) => Some(kind),
            ObservedKind::Unresolved => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub kind: ObservedKind,
    pub metadata: Metadata,
    pub identity: Option<FileIdentity>,
}

impl Observation {
    pub fn resolved(info: EntryInfo) -> Observation {
        Observation { kind: ObservedKind::Resolved(info.kind), metadata: info.metadata, identity: info.identity }
    }

    pub fn info(self) -> Option<EntryInfo> {
        Some(EntryInfo { kind: self.kind.resolved()?, metadata: self.metadata, identity: self.identity })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: OsString,
    pub info: Observation,
    pub domain: Option<Box<ProbeResult>>,
}

impl DirEntry {
    pub fn new(name: OsString, info: Observation) -> DirEntry {
        DirEntry { name, info, domain: None }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryListing {
    pub directory: EntryInfo,
    pub entries: Vec<DirEntry>,
    pub supplied_fields: MetadataFields,
    pub domain: Box<ProbeResult>,
}

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn new() -> CancellationToken {
        CancellationToken(Arc::new(AtomicBool::new(false)))
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl PartialEq for CancellationToken {
    fn eq(&self, other: &CancellationToken) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for CancellationToken {}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CancellationToken({})", self.is_cancelled())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Lease {
    pub entries: usize,
    pub operations: usize,
}

impl Lease {
    pub const UNBOUNDED: Lease = Lease { entries: usize::MAX, operations: usize::MAX };
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionCost {
    pub blocking: Option<Duration>,
    pub listing_operations: u32,
    pub metadata_operations: u32,
    pub kind_resolutions: u32,
    pub identity_reads: u32,
    pub entries_enumerated: u64,
    pub bytes: u64,
}

impl SessionCost {
    pub fn per_child_operations(&self) -> u32 {
        self.metadata_operations.saturating_add(self.identity_reads)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionOutcome {
    Complete(DirectoryListing),
    Cancelled,
    ResourceLimited { seen: usize },
    Failed(FsError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    Suspended,
    Finished(SessionOutcome),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStep {
    pub cost: SessionCost,
    pub state: SessionState,
}

impl SessionStep {
    pub fn suspended(cost: SessionCost) -> SessionStep {
        SessionStep { cost, state: SessionState::Suspended }
    }

    pub fn finished(cost: SessionCost, outcome: SessionOutcome) -> SessionStep {
        SessionStep { cost, state: SessionState::Finished(outcome) }
    }

    pub fn complete(listing: DirectoryListing) -> SessionStep {
        SessionStep::finished(SessionCost::default(), SessionOutcome::Complete(listing))
    }

    pub fn cancelled() -> SessionStep {
        SessionStep::finished(SessionCost::default(), SessionOutcome::Cancelled)
    }

    pub fn failed(error: FsError) -> SessionStep {
        SessionStep::finished(SessionCost::default(), SessionOutcome::Failed(error))
    }
}

pub enum Continuation {
    Suspended(Box<dyn ListingSession>),
    Finished(SessionOutcome),
}

pub trait ListingSession: Send {
    fn resume(self: Box<Self>, lease: Lease) -> (Continuation, SessionCost);
}

pub fn list_directory(filesystem: &dyn FileSystem, root: &Path, path: &RelativePath, ceiling: usize) -> SessionOutcome {
    let mut session = filesystem.open_listing(root, path, ceiling, CancellationToken::new());
    loop {
        match session.resume(Lease::UNBOUNDED).0 {
            Continuation::Suspended(next) => session = next,
            Continuation::Finished(outcome) => return outcome,
        }
    }
}

pub fn entry_bytes(name: &std::ffi::OsStr) -> u64 {
    u64::try_from(std::mem::size_of::<DirEntry>() + name.len()).unwrap_or(u64::MAX)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrichment {
    pub directory: Option<Metadata>,
    pub children: Vec<(OsString, Metadata)>,
    pub supplied_fields: MetadataFields,
    pub metadata_operations: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WatcherKind {
    None,
    Recursive,
    NonRecursive,
    Polling,
}

impl WatcherKind {
    pub fn is_present(self) -> bool {
        !matches!(self, WatcherKind::None)
    }

    pub fn is_per_directory(self) -> bool {
        matches!(self, WatcherKind::NonRecursive)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsCapabilities {
    pub case: CaseSensitivity,
    pub watcher: WatcherKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HintKind {
    Create,
    Remove,
    Rename,
    Modify,
    Metadata,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatcherEvent {
    Hint { paths: Vec<RelativePath>, kind: HintKind },
    Overflow,
    Failed { message: String, path: Option<RelativePath> },
    Dropped { count: u64 },
}

pub trait WatcherSink: Send + Sync {
    fn deliver(&self, event: WatcherEvent);
}

impl<F: Fn(WatcherEvent) + Send + Sync> WatcherSink for F {
    fn deliver(&self, event: WatcherEvent) {
        self(event)
    }
}

pub trait FileSystem: Send + Sync {
    fn capabilities(&self) -> FsCapabilities;
    fn canonicalize(&self, root: &Path) -> Result<PathBuf, FsError>;
    fn resolve_domain(
        &self,
        root: &Path,
        path: &RelativePath,
        parent: Option<&ProbeResult>,
    ) -> Result<ProbeResult, FsError>;
    fn metadata(&self, root: &Path, path: &RelativePath) -> Result<EntryInfo, FsError>;
    fn open_listing(
        &self,
        root: &Path,
        path: &RelativePath,
        ceiling: usize,
        cancel: CancellationToken,
    ) -> Box<dyn ListingSession>;
    fn enrich(&self, root: &Path, path: &RelativePath, fields: MetadataFields) -> Result<Enrichment, FsError>;
    fn watch(
        &self,
        root: &Path,
        path: &RelativePath,
        recursive: bool,
        sink: Arc<dyn WatcherSink>,
    ) -> Result<WatchId, FsError>;
    fn unwatch(&self, watch: WatchId);
}
