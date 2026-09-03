use std::collections::BTreeSet;
use std::fmt;

use crate::core::MonotonicTime;
use crate::entry::{EntryKind, LoadState, Metadata};
use crate::fs::{FsError, WatcherKind};
use crate::ids::{EntryId, RootIncarnation, SnapshotVersion};
use crate::path::RelativePath;
use crate::snapshot::Snapshot;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathChange {
    Added { id: EntryId, path: RelativePath, kind: EntryKind },
    Removed { id: EntryId, path: RelativePath, kind: EntryKind },
    Renamed { id: EntryId, old_path: RelativePath, new_path: RelativePath },
    KindChanged { id: EntryId, path: RelativePath, old: EntryKind, new: EntryKind },
    LoadStateChanged { id: EntryId, path: RelativePath, old: LoadState, new: LoadState },
    MetadataChanged { id: EntryId, path: RelativePath, old: Metadata, new: Metadata },
}

impl PathChange {
    pub fn id(&self) -> EntryId {
        match self {
            PathChange::Added { id, .. }
            | PathChange::Removed { id, .. }
            | PathChange::Renamed { id, .. }
            | PathChange::KindChanged { id, .. }
            | PathChange::LoadStateChanged { id, .. }
            | PathChange::MetadataChanged { id, .. } => *id,
        }
    }

    pub fn path(&self) -> &RelativePath {
        match self {
            PathChange::Added { path, .. }
            | PathChange::Removed { path, .. }
            | PathChange::KindChanged { path, .. }
            | PathChange::LoadStateChanged { path, .. }
            | PathChange::MetadataChanged { path, .. } => path,
            PathChange::Renamed { new_path, .. } => new_path,
        }
    }

    pub fn phase(&self) -> u8 {
        match self {
            PathChange::Removed { .. } => 0,
            PathChange::Renamed { .. } => 1,
            PathChange::KindChanged { .. } => 2,
            PathChange::LoadStateChanged { .. } => 3,
            PathChange::Added { .. } => 4,
            PathChange::MetadataChanged { .. } => 5,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitialScanState {
    Running { incarnation: RootIncarnation },
    Degraded { incarnation: RootIncarnation, failed: BTreeSet<RelativePath> },
    Complete { incarnation: RootIncarnation },
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootAvailability {
    Available { incarnation: RootIncarnation },
    Unavailable { last: RootIncarnation },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatcherHealth {
    Absent,
    Healthy { backend: WatcherKind },
    Degraded { backend: WatcherKind, reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoundResult {
    Successful,
    Degraded { unsatisfied: BTreeSet<RelativePath> },
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ReconciliationHealth {
    pub last_round: Option<RoundResult>,
    pub degraded_paths: BTreeSet<RelativePath>,
    pub metadata_degraded_paths: BTreeSet<RelativePath>,
    pub coverage_pending: bool,
}

impl ReconciliationHealth {
    pub fn is_degraded(&self) -> bool {
        matches!(self.last_round, Some(RoundResult::Degraded { .. })) || !self.degraded_paths.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThrottleCause {
    DutyBudget,
    Concurrency,
}

impl fmt::Display for ThrottleCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThrottleCause::DutyBudget => f.write_str("duty budget"),
            ThrottleCause::Concurrency => f.write_str("concurrency window"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceHealth {
    Nominal,
    Throttled { cause: ThrottleCause, resume: Option<MonotonicTime> },
}

impl ResourceHealth {
    pub fn is_throttled(&self) -> bool {
        matches!(self, ResourceHealth::Throttled { .. })
    }

    pub fn cause(&self) -> Option<ThrottleCause> {
        match self {
            ResourceHealth::Nominal => None,
            ResourceHealth::Throttled { cause, .. } => Some(*cause),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceLimit {
    EntriesPerDirectory,
    RepresentedEntries,
}

impl fmt::Display for ResourceLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceLimit::EntriesPerDirectory => f.write_str("entries per directory"),
            ResourceLimit::RepresentedEntries => f.write_str("represented entries"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceLimitEvent {
    pub path: RelativePath,
    pub resource: ResourceLimit,
    pub seen: u64,
    pub limit: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShutdownState {
    Running,
    ShuttingDown,
    Stopped,
    Terminated { error: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    pub initial_scan: InitialScanState,
    pub root: RootAvailability,
    pub watcher: WatcherHealth,
    pub reconciliation: ReconciliationHealth,
    pub resource: ResourceHealth,
    pub shutdown: ShutdownState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Operation {
    Listing,
    Metadata,
    DomainResolution,
    WatchRegistration,
    RootProbe,
    Watcher,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorCause {
    Fs(FsError),
    LimitExceeded,
    InvalidName(std::ffi::OsString),
    DuplicateName(std::ffi::OsString),
    UnresolvedKind(std::ffi::OsString),
    WatcherLost(String),
    WorkerLost,
    WorkerStuck,
    ResultMismatch,
    SnapshotRejected(crate::snapshot::BuildError),
}

impl fmt::Display for ErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCause::Fs(e) => write!(f, "{e}"),
            ErrorCause::LimitExceeded => f.write_str("configured entry limit exceeded"),
            ErrorCause::InvalidName(n) => write!(f, "unrepresentable name {n:?}"),
            ErrorCause::DuplicateName(n) => write!(f, "duplicate name {n:?}"),
            ErrorCause::UnresolvedKind(n) => write!(f, "unresolved kind for {n:?}"),
            ErrorCause::WatcherLost(m) => write!(f, "watcher lost: {m}"),
            ErrorCause::WorkerLost => f.write_str("filesystem worker lost"),
            ErrorCause::WorkerStuck => f.write_str("filesystem worker stuck"),
            ErrorCause::ResultMismatch => f.write_str("filesystem result does not match its job"),
            ErrorCause::SnapshotRejected(e) => write!(f, "snapshot rejected the entry: {e:?}"),
        }
    }
}

impl From<FsError> for ErrorCause {
    fn from(err: FsError) -> Self {
        ErrorCause::Fs(err)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoverableError {
    pub path: RelativePath,
    pub operation: Operation,
    pub error: ErrorCause,
}

impl fmt::Display for RecoverableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} on {}: {}", self.operation, self.path, self.error)
    }
}

#[derive(Clone, Debug)]
pub struct Update {
    pub previous_version: SnapshotVersion,
    pub new_version: SnapshotVersion,
    pub snapshot: Snapshot,
    pub changes: Vec<PathChange>,
    pub crossings: Vec<crate::core::CrossingEvent>,
    pub health: Health,
    pub errors: Vec<RecoverableError>,
}

#[derive(Clone, Debug)]
pub enum UpdateEvent {
    Delta(Update),
    Reset { snapshot: Snapshot, health: Health, errors: Vec<RecoverableError>, truncated_errors: usize },
    Health { version: SnapshotVersion, health: Health, errors: Vec<RecoverableError> },
    Terminal { health: Health },
}

impl UpdateEvent {
    pub fn version(&self) -> Option<SnapshotVersion> {
        match self {
            UpdateEvent::Delta(update) => Some(update.new_version),
            UpdateEvent::Reset { snapshot, .. } => Some(snapshot.version()),
            UpdateEvent::Health { version, .. } => Some(*version),
            UpdateEvent::Terminal { .. } => None,
        }
    }

    pub fn health(&self) -> &Health {
        match self {
            UpdateEvent::Delta(update) => &update.health,
            UpdateEvent::Reset { health, .. }
            | UpdateEvent::Health { health, .. }
            | UpdateEvent::Terminal { health } => health,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamError {
    Lagged { missed: usize },
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamError::Lagged { missed } => {
                write!(f, "update stream lagged, {} events missed", missed)
            }
        }
    }
}

impl std::error::Error for StreamError {}
