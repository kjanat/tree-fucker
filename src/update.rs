use std::collections::BTreeSet;
use std::fmt;

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
    pub coverage_pending: bool,
}

impl ReconciliationHealth {
    pub fn is_degraded(&self) -> bool {
        matches!(self.last_round, Some(RoundResult::Degraded { .. })) || !self.degraded_paths.is_empty()
    }
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
    pub shutdown: ShutdownState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Operation {
    Listing,
    Metadata,
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
    WatcherLost(String),
}

impl fmt::Display for ErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCause::Fs(e) => write!(f, "{e}"),
            ErrorCause::LimitExceeded => f.write_str("configured entry limit exceeded"),
            ErrorCause::InvalidName(n) => write!(f, "unrepresentable name {n:?}"),
            ErrorCause::DuplicateName(n) => write!(f, "duplicate name {n:?}"),
            ErrorCause::WatcherLost(m) => write!(f, "watcher lost: {m}"),
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
