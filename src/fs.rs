//! The core performs every filesystem operation through this boundary.
//!
//! A [`FileSystem`] adapter supplies root canonicalization, metadata reads,
//! listing sessions, enrichment, storage-domain resolution, and watcher
//! registration (RFC §10). The core admits every call through the resource
//! governor (RFC §15) and validates every result before the result commits.

use std::any::Any;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::domain::{ProbeError, ProbeResult};
use crate::entry::{EntryKind, FileIdentity, Metadata, MetadataFields};
use crate::ids::WatchId;
use crate::path::{CaseSensitivity, RelativePath};
use crate::update::{ResourceLimit, ResourceLimited};

/// `FsError` classifies a failed filesystem operation (RFC §13.1).
///
/// A path-scoped failure takes any variant except [`FsError::Fatal`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FsError {
    /// The path names no entry.
    NotFound,
    /// The path names a non-directory or a symbolic link to a directory.
    NotDirectory,
    /// The process lacks permission for the operation.
    PermissionDenied,
    /// The operation failed and may succeed on retry.
    Transient(String),
    /// The adapter or platform cannot perform the operation.
    Unsupported(String),
    /// Continued operation is unsafe, and the tree terminates.
    Fatal(String),
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

/// `EntryInfo` carries the kind, metadata and identity of one entry whose kind
/// is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryInfo {
    /// `kind` holds the entry's kind, and a symbolic link reports
    /// [`EntryKind::Symlink`].
    pub kind: EntryKind,
    /// The read obtained the fields in `metadata`, and every other field
    /// stays `None`.
    pub metadata: Metadata,
    /// `identity` holds the entry's identity when its storage domain supplies
    /// one.
    pub identity: Option<FileIdentity>,
}

/// `ObservedKind` records the kind of a listed child.
///
/// Enumeration may leave that kind unresolved (RFC §10.1). The core commits,
/// removes, or traverses an unresolved child only after it learns the child's
/// kind. If a listing holds an unresolved child, the listing proves no name
/// absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObservedKind {
    /// The adapter established the child's kind.
    Resolved(EntryKind),
    /// Kind resolution failed for this child.
    Unresolved,
}

impl ObservedKind {
    /// `resolved` returns the kind when the adapter resolved it.
    pub fn resolved(self) -> Option<EntryKind> {
        match self {
            ObservedKind::Resolved(kind) => Some(kind),
            ObservedKind::Unresolved => None,
        }
    }
}

/// `Observation` records what a listing observed about one child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    /// `kind` holds the child's kind, and it may be unresolved.
    pub kind: ObservedKind,
    /// Enumeration supplies the fields in `metadata` inline.
    pub metadata: Metadata,
    /// `identity` holds the child's identity when its storage domain supplies
    /// one.
    pub identity: Option<FileIdentity>,
}

impl Observation {
    /// `resolved` builds an observation of an entry whose kind is known.
    pub fn resolved(info: EntryInfo) -> Observation {
        Observation { kind: ObservedKind::Resolved(info.kind), metadata: info.metadata, identity: info.identity }
    }

    /// `info` converts the observation to [`EntryInfo`] when its kind is
    /// resolved.
    pub fn info(self) -> Option<EntryInfo> {
        Some(EntryInfo { kind: self.kind.resolved()?, metadata: self.metadata, identity: self.identity })
    }
}

/// `DirEntry` describes one child in a [`DirectoryListing`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// `name` holds the child's file name exactly as the platform reports it.
    pub name: OsString,
    /// `info` holds the enumeration's observation of the child.
    pub info: Observation,
    /// `domain` holds the child's storage domain when enumeration reports it
    /// inline (RFC §10.3).
    pub domain: Option<Box<ProbeResult>>,
}

impl DirEntry {
    /// `new` creates an entry without an inline storage domain.
    pub fn new(name: OsString, info: Observation) -> DirEntry {
        DirEntry { name, info, domain: None }
    }
}

/// `Anchor` holds an opaque, adapter-owned handle to a listed directory (RFC
/// §9.3).
///
/// An adapter wraps its own handle with [`Anchor::new`] and recovers it with
/// [`Anchor::get`]. Clones share one handle, and equality compares that
/// handle. Every entry of an anchored listing shares its anchor. The anchor
/// lives until every holder releases it.
#[derive(Clone)]
pub struct Anchor(Arc<Anchored>);

struct Anchored {
    value: Box<dyn Any + Send + Sync>,
    slot: OnceLock<Arc<AnchorSlot>>,
}

/// `AnchorSlot` represents one reserved anchor slot, and its cursor and
/// observations share it.
pub(crate) struct AnchorSlot(Arc<AtomicUsize>);

impl AnchorSlot {
    pub(crate) fn reserve(live: &Arc<AtomicUsize>) -> (Arc<Self>, usize) {
        let count = live.fetch_add(1, Ordering::SeqCst) + 1;
        (Arc::new(Self(live.clone())), count)
    }
}

impl Drop for AnchorSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Anchor {
    /// `new` wraps an adapter value as an anchor.
    pub fn new<T: Any + Send + Sync>(value: T) -> Anchor {
        Anchor(Arc::new(Anchored { value: Box::new(value), slot: OnceLock::new() }))
    }

    /// `get` returns the wrapped value when it has type `T`.
    pub fn get<T: Any>(&self) -> Option<&T> {
        self.0.value.downcast_ref::<T>()
    }

    pub(crate) fn retain_slot(&self, slot: &Arc<AnchorSlot>) {
        let _ = self.0.slot.set(slot.clone());
    }
}

impl PartialEq for Anchor {
    fn eq(&self, other: &Anchor) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Anchor {}

impl fmt::Debug for Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Anchor")
    }
}

/// `ListingAt` holds the anchor options for [`FileSystem::open_listing_at`]
/// (RFC §10.2).
///
/// With the default value, the adapter reaches the directory by path and
/// returns no anchor.
#[derive(Clone, Copy, Debug, Default)]
pub struct ListingAt<'a> {
    /// `beneath` names the parent directory's anchor, and the adapter opens the
    /// listing through it.
    pub beneath: Option<&'a Anchor>,
    /// `anchored` asks the adapter to include an anchor of the listed directory
    /// in a Complete outcome.
    pub anchored: bool,
}

/// `DirectoryListing` holds the complete result of a listing session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryListing {
    /// `directory` describes the listed directory itself.
    pub directory: EntryInfo,
    /// `entries` holds every observed child in enumeration order.
    pub entries: Vec<DirEntry>,
    /// Each entry carries the metadata fields in `supplied_fields` inline.
    pub supplied_fields: MetadataFields,
    /// `domain` identifies the storage domain of the listed directory.
    pub domain: Box<ProbeResult>,
    /// `anchor` holds the directory's anchor when the caller requested one and
    /// the adapter supports anchors.
    pub anchor: Option<Anchor>,
}

/// The core sets a `CancellationToken` to cancel listing sessions.
///
/// A session polls the token between chunks (RFC §10.2). A call already
/// inside the kernel runs to completion. Clones share one flag, and equality
/// compares that flag.
#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// `new` creates an unset token.
    pub fn new() -> CancellationToken {
        CancellationToken(Arc::new(AtomicBool::new(false)))
    }

    /// `cancel` sets the token for every clone.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// `is_cancelled` reports whether any clone has set the token.
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

/// A `Lease` bounds the work of one [`ListingSession::resume`] call (RFC
/// §10.2).
///
/// The governor grants a lease before each resume. The session yields when
/// either bound runs out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Lease {
    /// `entries` caps how many entries the session enumerates under this lease.
    pub entries: usize,
    /// `operations` caps per-child operations, and
    /// [`SessionCost::per_child_operations`] counts them.
    pub operations: usize,
}

impl Lease {
    /// `UNBOUNDED` sets both bounds to their maximum value.
    ///
    /// The session runs without an entry bound or an operation bound.
    pub const UNBOUNDED: Lease = Lease { entries: usize::MAX, operations: usize::MAX };
}

/// `Ceilings` limits one directory listing across all of its leases (RFC
/// §15.6).
///
/// A session that exceeds either ceiling ends with
/// [`SessionOutcome::ResourceLimited`]. The session holds at most the entry
/// ceiling plus one chunk before it stops (RFC §10.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ceilings {
    /// `entries` caps the number of entries in the directory.
    pub entries: usize,
    /// `bytes` caps the accounted bytes of the listing, and [`entry_bytes`]
    /// computes each entry's share.
    pub bytes: u64,
}

impl Ceilings {
    /// `UNBOUNDED` sets both ceilings to their maximum value.
    pub const UNBOUNDED: Ceilings = Ceilings { entries: usize::MAX, bytes: u64::MAX };

    /// `entries` caps the entry count and leaves bytes unbounded.
    pub fn entries(entries: usize) -> Ceilings {
        Ceilings { entries, bytes: u64::MAX }
    }

    /// `exceeded_by` checks `entries` against the entry ceiling and then
    /// `bytes` against the byte ceiling.
    ///
    /// It returns the first violation as a [`ResourceLimited`] without a
    /// storage domain.
    pub fn exceeded_by(&self, entries: usize, bytes: u64) -> Option<ResourceLimited> {
        if entries > self.entries {
            return Some(ResourceLimited {
                limit: ResourceLimit::EntriesPerDirectory,
                configured: u64::try_from(self.entries).unwrap_or(u64::MAX),
                observed: u64::try_from(entries).unwrap_or(u64::MAX),
                domain: None,
            });
        }
        if bytes > self.bytes {
            return Some(ResourceLimited {
                limit: ResourceLimit::ListingBytes,
                configured: self.bytes,
                observed: bytes,
                domain: None,
            });
        }
        None
    }
}

/// A listing session reports a `SessionCost` for each resume (RFC §15.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionCost {
    /// `blocking` records how long the resume occupied a worker, and the
    /// governor charges occupancy when it is absent.
    pub blocking: Option<Duration>,
    /// `listing_operations` counts directory open and read operations.
    pub listing_operations: u32,
    /// `metadata_operations` counts per-child metadata reads, including kind
    /// resolutions.
    pub metadata_operations: u32,
    /// `kind_resolutions` counts reads that resolved an unknown kind.
    pub kind_resolutions: u32,
    /// `identity_reads` counts per-child reads that obtained an identity.
    pub identity_reads: u32,
    /// `entries_enumerated` counts enumerated entries, including skipped
    /// entries.
    pub entries_enumerated: u64,
    /// `bytes` measures the session's current buffer, including the returned
    /// final listing.
    ///
    /// The value reports the buffer's size across leases. A chunk leaves the
    /// count once `take_chunk` removes it.
    pub bytes: u64,
}

impl SessionCost {
    /// `per_child_operations` sums metadata operations and identity reads.
    ///
    /// This sum counts against [`Lease::operations`].
    pub fn per_child_operations(&self) -> u32 {
        self.metadata_operations.saturating_add(self.identity_reads)
    }
}

/// `SessionOutcome` reports how a listing session ended (RFC §10.2).
///
/// Only [`SessionOutcome::Complete`] carries children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionOutcome {
    /// The session enumerated every child.
    Complete(DirectoryListing),
    /// The session saw its cancellation token set.
    Cancelled,
    /// The listing exceeded its entry or byte ceiling.
    ResourceLimited(ResourceLimited),
    /// The listing failed with a classified error.
    Failed(FsError),
}

/// `SessionState` describes a listing session after one resume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// The session yielded and waits for another lease.
    Suspended,
    /// The session ended with this outcome.
    Finished(SessionOutcome),
}

/// The core records each resume as a `SessionStep` with its cost and resulting
/// state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStep {
    /// `cost` holds the cost of this resume.
    pub cost: SessionCost,
    /// `state` holds the session state after this resume.
    pub state: SessionState,
}

impl SessionStep {
    /// `suspended` builds a step that left the session suspended.
    pub fn suspended(cost: SessionCost) -> SessionStep {
        SessionStep { cost, state: SessionState::Suspended }
    }

    /// `finished` builds a step that ended the session with `outcome`.
    pub fn finished(cost: SessionCost, outcome: SessionOutcome) -> SessionStep {
        SessionStep { cost, state: SessionState::Finished(outcome) }
    }

    /// `complete` builds a zero-cost step that completed with `listing`.
    pub fn complete(listing: DirectoryListing) -> SessionStep {
        SessionStep::finished(SessionCost::default(), SessionOutcome::Complete(listing))
    }

    /// `cancelled` builds a zero-cost cancelled step.
    pub fn cancelled() -> SessionStep {
        SessionStep::finished(SessionCost::default(), SessionOutcome::Cancelled)
    }

    /// `failed` builds a zero-cost step that failed with `error`.
    pub fn failed(error: FsError) -> SessionStep {
        SessionStep::finished(SessionCost::default(), SessionOutcome::Failed(error))
    }
}

/// [`ListingSession::resume`] returns a `Continuation` after one lease.
pub enum Continuation {
    /// The session yielded, and the caller resumes it under a new lease.
    Suspended(Box<dyn ListingSession>),
    /// The session ended.
    Finished(SessionOutcome),
}

/// A `ListingSession` enumerates one directory in bounded, leased chunks (RFC
/// §10.2).
///
/// Between chunks the session checks its [`CancellationToken`] and its
/// [`Ceilings`]. A suspended session keeps its open handle and partial
/// buffer and occupies no worker.
pub trait ListingSession: Send {
    /// `resume` performs work under `lease` and reports its cost.
    ///
    /// The session must hold remaining lease before each chunk and before
    /// each kind or identity read. When the lease runs out, it returns
    /// [`Continuation::Suspended`] with itself. Otherwise it returns
    /// [`Continuation::Finished`] with exactly one outcome.
    fn resume(self: Box<Self>, lease: Lease) -> (Continuation, SessionCost);

    /// `take_chunk` hands a suspended lease's buffered entries to a one-shot
    /// consumer.
    ///
    /// The default keeps the complete-listing contract. Implementations that
    /// support draining must preserve their total entry ceiling and return the
    /// same anchor across chunks. A returned chunk drains the buffered
    /// entries. Later values of `SessionCost::bytes` must exclude their bytes.
    /// This method must perform no filesystem work.
    fn take_chunk(&mut self) -> Option<DirectoryListing> {
        None
    }

    /// `supports_chunks` reports whether [`ListingSession::take_chunk`] drains
    /// buffered entries.
    fn supports_chunks(&self) -> bool {
        false
    }
}

/// `list_directory` lists one directory to completion under unbounded leases.
///
/// The listing runs on the calling thread outside the resource governor.
pub fn list_directory(
    filesystem: &dyn FileSystem,
    root: &Path,
    path: &RelativePath,
    ceilings: Ceilings,
) -> SessionOutcome {
    let mut session = filesystem.open_listing(root, path, ceilings, CancellationToken::new());
    loop {
        match session.resume(Lease::UNBOUNDED).0 {
            Continuation::Suspended(next) => session = next,
            Continuation::Finished(outcome) => return outcome,
        }
    }
}

/// `entry_bytes` computes the accounted bytes of one listed child named `name`.
///
/// Adapters sum it into [`SessionCost::bytes`] and check the sum against
/// [`Ceilings::bytes`].
pub fn entry_bytes(name: &std::ffi::OsStr) -> u64 {
    u64::try_from(std::mem::size_of::<DirEntry>() + name.len()).unwrap_or(u64::MAX)
}

/// An `EnrichmentBatch` requests configured metadata fields for a directory and
/// its children (RFC §10.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrichmentBatch {
    /// `fields` names the fields to read.
    pub fields: MetadataFields,
    /// `directory` asks for the directory's own metadata.
    pub directory: bool,
    /// `children` names the children to read.
    pub children: Vec<OsString>,
}

/// [`FileSystem::enrich`] returns an `Enrichment`.
///
/// A child absent from both lists keeps its previous metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrichment {
    /// `directory` holds the directory's own metadata when the batch requested
    /// it.
    pub directory: Option<Metadata>,
    /// `children` pairs each read child with its metadata, and the adapter
    /// projects that metadata onto the requested fields.
    pub children: Vec<(OsString, Metadata)>,
    /// `failed` pairs each child whose read failed with its classified error.
    pub failed: Vec<(OsString, FsError)>,
    /// The read supplied the fields in `supplied_fields`.
    pub supplied_fields: MetadataFields,
    /// `metadata_operations` counts the adapter's metadata reads.
    pub metadata_operations: u32,
}

/// An adapter declares its watcher backend as a `WatcherKind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WatcherKind {
    /// The adapter offers no watcher.
    None,
    /// One registration covers a directory and its descendants.
    Recursive,
    /// Each registration covers one directory.
    NonRecursive,
    /// The adapter detects changes by polling and delivers them as hints.
    /// The core registers it like [`WatcherKind::Recursive`].
    Polling,
}

impl WatcherKind {
    /// `is_present` reports whether the adapter offers any watcher.
    pub fn is_present(self) -> bool {
        !matches!(self, WatcherKind::None)
    }

    /// `is_per_directory` reports whether each registration covers a single
    /// directory.
    pub fn is_per_directory(self) -> bool {
        matches!(self, WatcherKind::NonRecursive)
    }
}

/// An adapter declares its tree-wide capabilities in `FsCapabilities`.
///
/// Per-domain declarations in [`ProbeResult`] refine these values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsCapabilities {
    /// `case` sets the default case sensitivity of paths in the tree.
    pub case: CaseSensitivity,
    /// `watcher` names the adapter's watcher backend.
    pub watcher: WatcherKind,
}

/// `HintKind` classifies the change behind a watcher hint (RFC §11.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HintKind {
    /// An entry was created.
    Create,
    /// An entry was removed.
    Remove,
    /// An entry was renamed, and the hint carries every path from the backend's
    /// report.
    Rename,
    /// An entry's contents changed.
    Modify,
    /// An entry's metadata changed.
    Metadata,
    /// The backend reported a change without classifying it.
    Unknown,
}

/// A watcher adapter delivers each normalized `WatcherEvent` to a
/// [`WatcherSink`].
///
/// Events schedule reads. Reconciliation stays responsible for correctness
/// (RFC §5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatcherEvent {
    /// The backend reported a change at these paths.
    Hint {
        /// `paths` lists the backend's root-relative paths.
        paths: Vec<RelativePath>,
        /// `kind` classifies the change.
        kind: HintKind,
    },
    /// The backend lost events (RFC §11.6).
    ///
    /// The core invalidates reconciliation coverage for every loaded directory.
    Overflow,
    /// The backend requires recursive reconciliation below this path.
    ///
    /// The core invalidates coverage for every loaded directory.
    /// A normal path hint refreshes only its target and is insufficient here.
    Rescan {
        /// `path` holds the backend's root-relative path.
        path: RelativePath,
    },
    /// The watcher backend or one of its registrations failed (RFC §13.4).
    Failed {
        /// `message` describes the failure.
        message: String,
        /// `path` names the scope of the failed registration, and `None` means
        /// the whole backend failed.
        path: Option<RelativePath>,
    },
    /// A watcher queue dropped hints before the core accepted them.
    Dropped {
        /// `count` counts the dropped hints.
        count: u64,
    },
}

/// A `WatcherSink` receives normalized watcher events.
pub trait WatcherSink: Send + Sync {
    /// `deliver` accepts one event, and adapters call it from any thread.
    fn deliver(&self, event: WatcherEvent);
}

impl<F: Fn(WatcherEvent) + Send + Sync> WatcherSink for F {
    fn deliver(&self, event: WatcherEvent) {
        self(event)
    }
}

/// An adapter implements `FileSystem` to supply filesystem operations and
/// capability declarations.
///
/// Protocol clients implement this same contract. Domain evidence belongs in
/// [`ProbeResult`], and unavailable metadata remains `None`. Network calls are
/// blocking work, and the same admission, lease, and cancellation rules apply
/// to them. Native access-control payloads remain adapter-owned.
/// [`Metadata::permissions`] carries permission bits and holds no portable
/// ACL and no authorization decision.
pub trait FileSystem: Send + Sync {
    /// `capabilities` declares tree-wide capabilities, and the core reads them
    /// once at open.
    fn capabilities(&self) -> FsCapabilities;

    /// `canonicalize` canonicalizes the configured root path.
    ///
    /// The core charges this read to the bootstrap scope (RFC §10.3).
    fn canonicalize(&self, root: &Path) -> Result<PathBuf, FsError>;

    /// `resolve_domain` identifies the storage domain of the directory at
    /// `path` (RFC §10.3).
    ///
    /// The core calls it before it first lists a directory. `parent` carries
    /// the parent directory's probe result when the core knows it.
    fn resolve_domain(
        &self,
        root: &Path,
        path: &RelativePath,
        parent: Option<&ProbeResult>,
    ) -> Result<ProbeResult, FsError>;

    /// `metadata` reads the entry at `path` without following a symbolic link.
    fn metadata(&self, root: &Path, path: &RelativePath) -> Result<EntryInfo, FsError>;

    /// `open_listing` opens a listing session for the directory at `path`.
    ///
    /// The session reports the cost of opening the directory in its first
    /// resume. If `path` names a symbolic link, the session ends with
    /// [`FsError::NotDirectory`] (RFC §14.2).
    fn open_listing(
        &self,
        root: &Path,
        path: &RelativePath,
        ceilings: Ceilings,
        cancel: CancellationToken,
    ) -> Box<dyn ListingSession>;

    /// `open_listing_at` opens a listing session with the anchor options in
    /// `at` (RFC §10.2).
    ///
    /// An implementation must ignore `at.beneath` when it names a directory
    /// other than the parent of `path`. The default ignores `at` and calls
    /// [`FileSystem::open_listing`].
    fn open_listing_at(
        &self,
        root: &Path,
        path: &RelativePath,
        _at: ListingAt<'_>,
        ceilings: Ceilings,
        cancel: CancellationToken,
    ) -> Box<dyn ListingSession> {
        self.open_listing(root, path, ceilings, cancel)
    }

    /// `resolve_domain_beneath` identifies the storage domain of `path` through
    /// the parent anchor `beneath`.
    ///
    /// An implementation must ignore `beneath` when it names a directory
    /// other than the parent of `path` (RFC §10.2). The default ignores
    /// `beneath` and calls [`FileSystem::resolve_domain`].
    fn resolve_domain_beneath(
        &self,
        root: &Path,
        path: &RelativePath,
        _beneath: Option<&Anchor>,
        parent: Option<&ProbeResult>,
    ) -> Result<ProbeResult, FsError> {
        self.resolve_domain(root, path, parent)
    }

    /// `enrich` reads the fields of `batch` for the directory at `path` and its
    /// named children.
    ///
    /// A per-child failure belongs in [`Enrichment::failed`]. An `Err` fails
    /// the whole batch (RFC §10.1).
    fn enrich(&self, root: &Path, path: &RelativePath, batch: &EnrichmentBatch) -> Result<Enrichment, FsError>;

    /// `watch` registers a watcher on `path` and delivers its events to `sink`.
    ///
    /// `recursive` requests coverage of descendants. An adapter without a
    /// watcher returns [`FsError::Unsupported`].
    fn watch(
        &self,
        root: &Path,
        path: &RelativePath,
        recursive: bool,
        sink: Arc<dyn WatcherSink>,
    ) -> Result<WatchId, FsError>;

    /// `unwatch` releases the registration with the ID `watch`.
    fn unwatch(&self, watch: WatchId);
}
