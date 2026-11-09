//! This module defines the events and health values of the update stream.
//!
//! A [`crate::tree::UpdateStream`] yields [`UpdateEvent`] values. Every event
//! carries a [`Health`] value, and each health field reports one independent
//! condition (RFC §7.4). The tree attaches each [`RecoverableError`] to
//! exactly one published event.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::core::MonotonicTime;
use crate::entry::{EntryKind, LoadState, Metadata};
use crate::fs::{FsError, WatcherKind};
use crate::ids::{EntryId, RootIncarnation, SnapshotVersion};
use crate::path::RelativePath;
use crate::snapshot::Snapshot;

/// `PathChange` describes one entry-level difference between two snapshots.
///
/// An [`Update`] lists its changes as one indivisible transaction. The
/// changes follow the canonical order of RFC §7.4. Removals come first,
/// then renames, kind changes, load-state changes, additions, and metadata
/// changes. [`PathChange::phase`] returns the position of a change in that
/// order. A consumer must accept a rename as a removal plus an addition
/// with a new [`EntryId`] (RFC §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathChange {
    /// `Added` reports a new entry in the new snapshot.
    Added {
        /// `id` identifies the new entry.
        id: EntryId,
        /// `path` locates the new entry.
        path: RelativePath,
        /// `kind` gives the kind of the new entry.
        kind: EntryKind,
    },
    /// `Removed` reports the removal of an entry from the snapshot.
    Removed {
        /// `id` identifies the removed entry.
        id: EntryId,
        /// `path` locates the entry in the previous snapshot.
        path: RelativePath,
        /// `kind` gives the kind of the removed entry.
        kind: EntryKind,
    },
    /// `Renamed` reports a move under stable identity (RFC §7.4).
    Renamed {
        /// `id` identifies the moved entry before and after the move.
        id: EntryId,
        /// `old_path` locates the entry in the previous snapshot.
        old_path: RelativePath,
        /// `new_path` locates the entry in the new snapshot.
        new_path: RelativePath,
    },
    /// `KindChanged` reports a new kind at an unchanged path.
    KindChanged {
        /// `id` identifies the entry.
        id: EntryId,
        /// `path` locates the entry.
        path: RelativePath,
        /// `old` gives the kind in the previous snapshot.
        old: EntryKind,
        /// `new` gives the kind in the new snapshot.
        new: EntryKind,
    },
    /// `LoadStateChanged` reports a new load state of a directory (RFC §7.2).
    LoadStateChanged {
        /// `id` identifies the directory.
        id: EntryId,
        /// `path` locates the directory.
        path: RelativePath,
        /// `old` gives the load state in the previous snapshot.
        old: LoadState,
        /// `new` gives the load state in the new snapshot.
        new: LoadState,
    },
    /// `MetadataChanged` reports new configured metadata of an entry.
    MetadataChanged {
        /// `id` identifies the entry.
        id: EntryId,
        /// `path` locates the entry.
        path: RelativePath,
        /// `old` holds the metadata in the previous snapshot.
        old: Metadata,
        /// `new` holds the metadata in the new snapshot.
        new: Metadata,
    },
}

impl PathChange {
    /// `id` returns the entry identifier of this change.
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

    /// `path` returns the entry path in the new snapshot.
    ///
    /// A [`PathChange::Renamed`] yields its `new_path`. A
    /// [`PathChange::Removed`] yields its path in the previous snapshot.
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

    /// `phase` returns the position of this change kind in the canonical order.
    ///
    /// Removals have phase 0, renames 1, kind changes 2, load-state changes
    /// 3, additions 4, and metadata changes 5 (RFC §7.4).
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

/// `InitialScanState` reports the initial scan of the current root incarnation.
///
/// The state can move from `Degraded` back through `Running` to `Complete`
/// while background retries accept the failed listings (RFC §11.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitialScanState {
    /// `Running` means initial work remains and no initial listing failed.
    ///
    /// Initial work is traversal or a pending initial listing.
    Running {
        /// `incarnation` names the root incarnation of this scan.
        incarnation: RootIncarnation,
    },
    /// `Degraded` means traversal finished with an unsatisfied listing.
    Degraded {
        /// `incarnation` names the root incarnation of this scan.
        incarnation: RootIncarnation,
        /// `failed` lists the directories with an unsatisfied initial listing.
        failed: BTreeSet<RelativePath>,
    },
    /// `Complete` means the tree accepted or removed every initial directory.
    Complete {
        /// `incarnation` names the root incarnation of this scan.
        incarnation: RootIncarnation,
    },
    /// `Unavailable` means the root is unavailable and no initial scan runs.
    Unavailable,
}

/// `RootAvailability` reports whether the root exists as a directory.
///
/// RFC §13.2 defines the root lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootAvailability {
    /// `Available` means the root exists as a directory.
    Available {
        /// `incarnation` names the current root incarnation.
        incarnation: RootIncarnation,
    },
    /// `Unavailable` means the root vanished or became a non-directory.
    ///
    /// The snapshot is empty in this state.
    Unavailable {
        /// `last` names the incarnation before the root became unavailable.
        last: RootIncarnation,
    },
}

/// `WatcherHealth` reports a watcher backend for the tree or for one domain.
///
/// Watcher health only affects latency. Reconciliation continues in every
/// state (RFC §5.3, §13.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatcherHealth {
    /// `Absent` means the filesystem offers no watcher for this scope.
    Absent,
    /// `Healthy` means the watcher registered and reports hints.
    Healthy {
        /// `backend` names the backend kind.
        backend: WatcherKind,
    },
    /// `Degraded` means registration failed or the backend reported a failure.
    Degraded {
        /// `backend` names the backend kind.
        backend: WatcherKind,
        /// `reason` carries the failure message of the registration or backend.
        reason: String,
    },
}

/// `RoundResult` reports the outcome of the latest completed round (RFC §5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoundResult {
    /// `Successful` means every remaining obligation had an accepted listing.
    Successful,
    /// `Degraded` means at least one obligation ended Unsatisfied.
    Degraded {
        /// `unsatisfied` lists the directories with an Unsatisfied obligation.
        unsatisfied: BTreeSet<RelativePath>,
    },
}

/// `ReconciliationHealth` holds the reconciliation fields of [`Health`].
///
/// Throttling never appears here. [`ResourceHealth`] reports it separately
/// (RFC §15.1).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ReconciliationHealth {
    /// `last_round` holds the latest round result.
    ///
    /// It holds `None` before the first round ends.
    pub last_round: Option<RoundResult>,
    /// `degraded_paths` lists the paths with currently failing reads.
    pub degraded_paths: BTreeSet<RelativePath>,
    /// `degraded_path_causes` maps each degraded path to its failure class.
    pub degraded_path_causes: BTreeMap<RelativePath, crate::core::DegradedCause>,
    /// `metadata_degraded_paths` lists the paths with failed enrichment.
    ///
    /// Membership of these paths stays current.
    pub metadata_degraded_paths: BTreeSet<RelativePath>,
    /// `coverage_pending` reports a coverage gap after event loss or a rescan.
    ///
    /// Newer accepted listings close the gap. The watcher backend can stay
    /// healthy during the gap (RFC §11.6).
    pub coverage_pending: bool,
}

impl ReconciliationHealth {
    /// `is_degraded` reports a degraded latest round or any degraded path.
    pub fn is_degraded(&self) -> bool {
        matches!(self.last_round, Some(RoundResult::Degraded { .. })) || !self.degraded_paths.is_empty()
    }
}

/// `ThrottleCause` names the reason for a governor denial (RFC §15.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThrottleCause {
    /// `DutyBudget` means a domain or global background bucket is exhausted.
    DutyBudget,
    /// `Concurrency` means the domain window or the in-flight limit is full.
    Concurrency,
    /// `Memory` means accounted memory is at the configured ceiling.
    Memory,
    /// `ForegroundCeiling` means the foreground allowance is exhausted.
    ForegroundCeiling,
    /// The minimum lease exceeds the command allowance even after refill.
    CommandCeiling {
        /// `required` gives the worker time of the smallest admissible lease.
        required: std::time::Duration,
    },
    /// `StuckWorker` means a stuck worker quarantines the domain.
    ///
    /// The domain admits nothing new until the stuck worker returns.
    StuckWorker,
    /// `Coordination` means the shared cross-process authority denied the work.
    Coordination,
    /// `CoordinationFailed` means the shared authority failed after joining.
    CoordinationFailed,
}

impl fmt::Display for ThrottleCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThrottleCause::DutyBudget => f.write_str("duty budget"),
            ThrottleCause::Concurrency => f.write_str("concurrency window"),
            ThrottleCause::Memory => f.write_str("accounted memory"),
            ThrottleCause::ForegroundCeiling => f.write_str("foreground allowance"),
            ThrottleCause::CommandCeiling { required } => write!(f, "command allowance below required {required:?}"),
            ThrottleCause::StuckWorker => f.write_str("stuck worker"),
            ThrottleCause::Coordination => f.write_str("shared admission"),
            ThrottleCause::CoordinationFailed => f.write_str("shared authority unavailable after joining"),
        }
    }
}

/// `ResourceHealth` reports the admission state of the governor (RFC §15.6).
///
/// Throttling delays work and never counts as degradation (RFC §15.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceHealth {
    /// `Nominal` means the governor admits ready work.
    Nominal,
    /// `Throttled` means the governor denies ready work for `cause`.
    Throttled {
        /// `cause` names the reason for the denial.
        cause: ThrottleCause,
        /// `resume` gives the earliest computable time for renewed admission.
        ///
        /// `None` means a state change resumes admission. A returning worker
        /// or released memory is such a change (RFC §12).
        resume: Option<MonotonicTime>,
    },
}

impl ResourceHealth {
    /// `is_throttled` reports whether the governor denies ready work.
    pub fn is_throttled(&self) -> bool {
        matches!(self, ResourceHealth::Throttled { .. })
    }

    /// `cause` returns the throttle cause, or `None` during nominal admission.
    pub fn cause(&self) -> Option<ThrottleCause> {
        match self {
            ResourceHealth::Nominal => None,
            ResourceHealth::Throttled { cause, .. } => Some(*cause),
        }
    }
}

/// `ResourceLimit` names a configured hard limit (RFC §13.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceLimit {
    /// `Anchors` means a one-shot scan reached its anchor limit.
    Anchors,
    /// `EntriesPerDirectory` means a listing reached the entry ceiling.
    EntriesPerDirectory,
    /// `RepresentedEntries` means a commit would exceed the entry limit.
    RepresentedEntries,
    /// `ListingBytes` means a listing reached its result-size ceiling.
    ListingBytes,
    /// `InFlightBytes` means listing buffers reached the in-flight ceiling.
    InFlightBytes,
    /// `SnapshotBytes` means a commit would exceed the snapshot byte ceiling.
    SnapshotBytes,
    /// `AccountedMemory` means accounted memory reached the host ceiling.
    AccountedMemory,
    /// `CommandWorkerTime` means a command reached its worker-time ceiling.
    CommandWorkerTime,
}

impl fmt::Display for ResourceLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceLimit::Anchors => f.write_str("retained observation anchors"),
            ResourceLimit::EntriesPerDirectory => f.write_str("entries per directory"),
            ResourceLimit::RepresentedEntries => f.write_str("represented entries"),
            ResourceLimit::ListingBytes => f.write_str("listing bytes"),
            ResourceLimit::InFlightBytes => f.write_str("in-flight listing bytes"),
            ResourceLimit::SnapshotBytes => f.write_str("snapshot bytes"),
            ResourceLimit::AccountedMemory => f.write_str("accounted memory"),
            ResourceLimit::CommandWorkerTime => f.write_str("command worker time"),
        }
    }
}

/// `ResourceLimited` describes a ResourceLimited outcome (RFC §13.1).
///
/// The previous snapshot stays intact. A limited listing publishes nothing
/// and never truncates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimited {
    /// `limit` names the reached limit.
    pub limit: ResourceLimit,
    /// `configured` holds the configured value, in nanoseconds for worker time.
    pub configured: u64,
    /// `observed` holds the reached or required value in the same unit.
    pub observed: u64,
    /// `domain` names the storage domain of the operation, or holds `None`.
    pub domain: Option<crate::domain::StorageDomainId>,
}

impl fmt::Display for ResourceLimited {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} limit {} reached with {} observed", self.limit, self.configured, self.observed)?;
        match self.domain {
            Some(domain) => write!(f, " on domain {domain}"),
            None => Ok(()),
        }
    }
}

/// `ResourceLimitEvent` records one path at a resource limit.
///
/// [`crate::core::Stats`] lists these records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceLimitEvent {
    /// `path` locates the limited read or commit.
    pub path: RelativePath,
    /// `limited` names the limit with its configured and observed values.
    pub limited: ResourceLimited,
}

/// `ShutdownState` reports the lifecycle stage of the tree (RFC §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShutdownState {
    /// `Running` means the tree accepts commands.
    Running,
    /// `ShuttingDown` means the tree accepted a shutdown and is tearing down.
    ShuttingDown,
    /// `Stopped` means an orderly shutdown finished, and the stream ends.
    Stopped,
    /// `Terminated` means a Fatal failure ended the tree (RFC §13.1).
    Terminated {
        /// `error` carries the message of the Fatal error.
        error: String,
    },
}

/// `Health` reports the state of a tree as independent fields (RFC §7.4, §16).
///
/// Each field reports one condition, and no field implies another. A
/// degraded watcher leaves the root available. A degraded round leaves the
/// snapshot readable. Throttling implies neither degradation nor root loss.
///
/// Every [`UpdateEvent`] carries the current health at its publication.
/// [`crate::tree::TreeHandle::health`] returns the latest published value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    /// `initial_scan` reports the initial scan of the current root incarnation.
    pub initial_scan: InitialScanState,
    /// `root` reports whether the root exists as a directory.
    pub root: RootAvailability,
    /// `watcher` reports the tree-wide watcher state.
    ///
    /// Root registration and backend failures set this field.
    pub watcher: WatcherHealth,
    /// `watcher_domains` reports the watcher state of each entered domain.
    pub watcher_domains: BTreeMap<crate::domain::StorageDomainId, WatcherHealth>,
    /// `reconciliation` reports round results, degraded paths, and coverage.
    pub reconciliation: ReconciliationHealth,
    /// `resource` reports the throttle state of the host governor.
    ///
    /// Without a host-wide throttle, it reports the first throttled domain.
    pub resource: ResourceHealth,
    /// `resource_domains` reports the admission state of each entered domain.
    pub resource_domains: BTreeMap<crate::domain::StorageDomainId, ResourceHealth>,
    /// `shutdown` reports the lifecycle stage of the tree.
    pub shutdown: ShutdownState,
}

/// `Operation` names the filesystem operation of a [`RecoverableError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Operation {
    /// `Listing` names a directory listing session.
    Listing,
    /// `Metadata` names a metadata read or a metadata enrichment batch.
    Metadata,
    /// `DomainResolution` names a storage-domain resolution.
    DomainResolution,
    /// `WatchRegistration` names a watcher registration.
    WatchRegistration,
    /// `RootProbe` names a probe for an unavailable root (RFC §13.2).
    RootProbe,
    /// `Watcher` names a failure report from the watcher backend.
    Watcher,
}

/// `ErrorCause` names the cause of a [`RecoverableError`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorCause {
    /// `Fs` carries a classified error from the adapter (RFC §13.1).
    Fs(FsError),
    /// `ResourceLimited` means the operation reached a configured limit.
    ResourceLimited(ResourceLimited),
    /// `InvalidName` carries an unrepresentable child name (RFC §14.1).
    InvalidName(std::ffi::OsString),
    /// `DuplicateName` carries a child name with a duplicate comparison key.
    DuplicateName(std::ffi::OsString),
    /// `UnresolvedKind` carries a child name with an unknown kind (RFC §10.1).
    UnresolvedKind(std::ffi::OsString),
    /// `WatcherLost` carries the failure message of the watcher backend.
    WatcherLost(String),
    /// `WorkerLost` means a worker panicked or dropped its result (RFC §13.5).
    WorkerLost,
    /// `WorkerStuck` means a worker passed the stuck threshold (RFC §13.5).
    WorkerStuck,
    /// `ResultMismatch` means a worker returned the wrong result kind.
    ResultMismatch,
    /// `SnapshotRejected` means the snapshot builder rejected a listed entry.
    SnapshotRejected(crate::snapshot::BuildError),
}

impl fmt::Display for ErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCause::Fs(e) => write!(f, "{e}"),
            ErrorCause::ResourceLimited(limited) => write!(f, "{limited}"),
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

/// `RecoverableError` describes one failure without fatal effect.
///
/// The tree recovers from it by retrying or by degrading a path. The tree
/// attaches each error to exactly one published event. An error without a
/// snapshot or health change arrives on an [`UpdateEvent::Health`] (RFC §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoverableError {
    /// `path` locates the target of the failed operation.
    pub path: RelativePath,
    /// `operation` names the failed operation.
    pub operation: Operation,
    /// `error` names the cause of the failure.
    pub error: ErrorCause,
}

impl fmt::Display for RecoverableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} on {}: {}", self.operation, self.path, self.error)
    }
}

/// `Update` describes one committed snapshot transition (RFC §7.4).
///
/// Applying `changes` in order to the snapshot at `previous_version` yields
/// `snapshot` at `new_version`. The changes form one transaction. A consumer
/// must expose neither an intermediate state nor a partial directory
/// (RFC §7.3).
#[derive(Clone, Debug)]
pub struct Update {
    /// `previous_version` names the input snapshot version.
    pub previous_version: SnapshotVersion,
    /// `new_version` names the output snapshot version.
    pub new_version: SnapshotVersion,
    /// `snapshot` holds the complete snapshot at `new_version`.
    pub snapshot: Snapshot,
    /// `changes` lists the path changes in canonical order.
    ///
    /// [`PathChange::phase`] gives the order.
    pub changes: Vec<PathChange>,
    /// `crossings` lists the domain crossings of this transaction (RFC §14.3).
    pub crossings: Vec<crate::core::CrossingEvent>,
    /// `health` holds the health at publication.
    pub health: Health,
    /// `errors` lists the recoverable errors of this publication.
    pub errors: Vec<RecoverableError>,
}

/// `UpdateEvent` is one item of the update stream (RFC §9).
///
/// Events arrive in snapshot version order. A consumer can apply every
/// [`UpdateEvent::Delta`] in order. It can also apply the latest
/// [`UpdateEvent::Reset`] and every later Delta. Both paths reach the
/// snapshot version of the last applied event. [`UpdateEvent::Terminal`]
/// precedes the end of the stream.
#[derive(Clone, Debug)]
pub enum UpdateEvent {
    /// `Delta` carries one snapshot transition with its path changes.
    Delta(Update),
    /// `Reset` replaces the queued events of a lagging consumer.
    ///
    /// The consumer discards its own state and adopts `snapshot`. The stream
    /// emits a Reset under [`crate::config::LagMode::Reset`].
    Reset {
        /// `snapshot` holds the latest complete snapshot.
        snapshot: Snapshot,
        /// `health` holds the latest health.
        health: Health,
        /// `errors` lists the recoverable errors of the replaced events.
        ///
        /// The list stops at a cap.
        errors: Vec<RecoverableError>,
        /// `truncated_errors` counts the errors beyond the cap.
        truncated_errors: usize,
    },
    /// `Health` carries a health change or recoverable errors.
    ///
    /// The snapshot stays unchanged.
    Health {
        /// `version` names the current snapshot version.
        version: SnapshotVersion,
        /// `health` holds the current health.
        health: Health,
        /// `errors` lists the recoverable errors outside any Delta or Reset.
        errors: Vec<RecoverableError>,
    },
    /// `Terminal` carries the final health after shutdown or fatal termination.
    Terminal {
        /// `health` holds the final health.
        ///
        /// Its [`Health::shutdown`] field is Stopped or Terminated.
        health: Health,
    },
}

impl UpdateEvent {
    /// `version` returns the snapshot version of this event.
    ///
    /// It returns `None` for Terminal.
    pub fn version(&self) -> Option<SnapshotVersion> {
        match self {
            UpdateEvent::Delta(update) => Some(update.new_version),
            UpdateEvent::Reset { snapshot, .. } => Some(snapshot.version()),
            UpdateEvent::Health { version, .. } => Some(*version),
            UpdateEvent::Terminal { .. } => None,
        }
    }

    /// `health` returns the health of this event.
    pub fn health(&self) -> &Health {
        match self {
            UpdateEvent::Delta(update) => &update.health,
            UpdateEvent::Reset { health, .. }
            | UpdateEvent::Health { health, .. }
            | UpdateEvent::Terminal { health } => health,
        }
    }
}

/// `StreamError` is the error item of the update stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// `Lagged` means a consumer fell behind and lost its connection.
    ///
    /// The stream emits it under [`crate::config::LagMode::Disconnect`] and
    /// ends after this item (RFC §9).
    Lagged {
        /// `missed` counts the discarded undelivered events.
        missed: usize,
    },
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
