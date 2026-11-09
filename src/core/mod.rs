//! `core` holds the deterministic coordinator of a [`Tree`](crate::Tree).
//!
//! [`Coordinator`] owns all mutable synchronization state of one tree (RFC §6).
//! A driver feeds it [`Input`] values with the current [`MonotonicTime`]. The
//! driver then executes the [`Output`] values from the coordinator. The
//! coordinator performs no I/O and reads no clock. Admission goes through the
//! shared [`HostGovernor`].

mod apply;
mod commands;
mod governor;
mod jobs;
mod scheduler;
mod types;
mod watcher;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

pub(crate) use apply::requires_crossing_decision;
pub(crate) use governor::ChangeWaker;
pub use governor::{
    AdmissionDecision, Admitted, DomainAccount, DomainView, GovernorView, Grant, GrantId, HostGovernor,
    HostGovernorError, LatencySummary, PreparedAdmission, Reported, Reservation, TreeNumber, host_governor,
};
use types::*;
pub use types::{Class, DegradedCause, MonotonicTime, WorkOrigin};

use crate::config::Config;
use crate::domain::{
    DomainCapabilities, DomainCrossing, DomainIdentity, ProbeResult, StorageDomainId, WatcherAvailability,
    WatcherCapabilities, WatcherScope,
};
use crate::entry::{LoadState, MetadataFields, Shape};
use crate::error::Error;
use crate::fs::{
    CancellationToken, Ceilings, Enrichment, EnrichmentBatch, EntryInfo, FsCapabilities, FsError, Lease, SessionCost,
    SessionStep, WatcherEvent, WatcherKind,
};
use crate::ids::*;
use crate::path::RelativePath;
use crate::policy::{PolicyContext, ScanPolicy};
use crate::snapshot::{Snapshot, new_entry};
use crate::update::{
    ErrorCause, Health, InitialScanState, Operation, ReconciliationHealth, RecoverableError, ResourceHealth,
    ResourceLimit, ResourceLimitEvent, ResourceLimited, RootAvailability, ShutdownState, ThrottleCause, Update,
    UpdateEvent, WatcherHealth,
};

const RESOURCE_LIMIT_HISTORY: usize = 64;
const CROSSING_HISTORY: usize = 64;
const LARGEST_DIRECTORIES: usize = 16;

/// `ObligationCounts` describes the obligations of one reconciliation round
/// (RFC §16).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObligationCounts {
    /// The round froze this many loaded directories.
    pub total: usize,
    /// An accepted listing satisfied this many obligations.
    pub accepted: usize,
    /// This many obligations ended unsatisfied.
    ///
    /// Their designated jobs failed, went stale or got stuck.
    pub unsatisfied: usize,
    /// This many obligations ended removed.
    ///
    /// Their directories were removed, unloaded or excluded.
    pub removed: usize,
}

/// `DirectorySize` gives the child count of one large directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectorySize {
    /// `path` holds the root-relative path of the directory.
    pub path: RelativePath,
    /// The latest complete or resource-limited listing counted this many
    /// children.
    pub children: usize,
}

/// `CrossingEvent` describes one domain-crossing decision during traversal (RFC
/// §14.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossingEvent {
    /// `path` holds the root-relative path of the directory in the child
    /// domain.
    pub path: RelativePath,
    /// `parent` holds the domain of the parent directory, when the tree knows
    /// it.
    pub parent: Option<StorageDomainId>,
    /// `child` holds the domain of the directory itself.
    pub child: StorageDomainId,
    /// Scan policy returned this decision for the crossing.
    pub mode: DomainCrossing,
}

/// `DomainStat` describes one storage domain of a tree (RFC §16).
///
/// The governor fields repeat the [`DomainView`] of the same domain.
#[derive(Clone, Debug, PartialEq)]
pub struct DomainStat {
    /// `id` identifies the domain.
    pub id: StorageDomainId,
    /// The adapter reported this identity for the domain.
    pub identity: DomainIdentity,
    /// The adapter declared these capabilities and their sources.
    pub capabilities: DomainCapabilities,
    /// The tree resolves Unknown entries of these watcher capabilities against
    /// the backend.
    pub watcher: WatcherCapabilities,
    /// `watcher_health` holds the watcher health on the domain.
    pub watcher_health: WatcherHealth,
    /// This many paths on the domain hold a pending or registered watch.
    pub paths_watched: usize,
    /// The watcher path limit left this many directories on the domain
    /// unwatched.
    pub paths_unwatched_by_cap: usize,
    /// The governor reserved this worker time on the domain at admission.
    pub granted: Duration,
    /// The governor charged this worker time on the domain.
    ///
    /// The total includes overshoot and surcharges.
    pub charged: Duration,
    /// `capacity` holds the capacity of the domain background bucket.
    pub capacity: Duration,
    /// `level` holds the current background bucket level.
    ///
    /// The level reads zero while the bucket is in debt.
    pub level: Duration,
    /// The background bucket is this far below zero.
    pub debt: Duration,
    /// `window` holds the current concurrency window (RFC §15.5).
    pub window: usize,
    /// The window may grow to at most this size.
    pub ceiling: usize,
    /// This many started grants run on the domain.
    pub in_flight: usize,
    /// This many grants on the domain are stuck.
    ///
    /// One stuck grant quarantines the domain.
    pub stuck: usize,
    /// The governor estimates this worker time per filesystem operation.
    pub estimate: Duration,
    /// `foreground_capacity` holds the capacity of the domain foreground
    /// bucket.
    pub foreground_capacity: Duration,
    /// `foreground_level` holds the current foreground bucket level.
    ///
    /// The level reads zero while the bucket is in debt.
    pub foreground_level: Duration,
    /// The foreground bucket is this far below zero.
    pub foreground_debt: Duration,
    /// `bytes_estimate` holds the moving mean of listing result bytes on the
    /// domain.
    pub bytes_estimate: u64,
    /// `latency` covers every operation kind.
    pub latency: LatencySummary,
    /// `listing_latency` covers listing operations.
    pub listing_latency: LatencySummary,
    /// `metadata_latency` covers every operation other than listings.
    pub metadata_latency: LatencySummary,
    /// `registration_latency` covers watch registrations.
    pub registration_latency: LatencySummary,
    /// The governor denied this many admissions on the domain.
    pub throttled_jobs: u64,
    /// The domain spent this long with a denial outstanding.
    pub throttled_duration: Duration,
    /// `effective_duty` holds charged worker time per elapsed second.
    ///
    /// `effective_duty` counts from the registration of the domain.
    pub effective_duty: f64,
    /// `resource` holds the resource health of the domain (RFC §15.6).
    pub resource: ResourceHealth,
    /// This tree performed this many listing operations on the domain.
    pub listings: u64,
    /// This tree performed this many metadata operations on the domain.
    pub metadata_operations: u64,
    /// This tree enumerated this many directory entries on the domain.
    pub entries_enumerated: u64,
    /// This tree performed this many per-child operations on the domain.
    pub per_child_lookups: u64,
    /// This tree performed this many kind resolutions on the domain.
    pub kind_resolutions: u64,
    /// This tree performed this many identity reads on the domain.
    pub identity_reads: u64,
    /// This tree enumerated this many entries per second on the domain.
    ///
    /// `entries_per_second` counts from the registration of the domain.
    pub entries_per_second: f64,
    /// This tree performed this many per-child operations per second.
    ///
    /// `per_child_lookups_per_second` counts from the registration of the
    /// domain.
    pub per_child_lookups_per_second: f64,
    /// The tree first bound a directory to the domain at this path.
    pub entry_path: Option<RelativePath>,
    /// The latest complete listing on the domain counted this many children.
    pub last_listing_children: Option<usize>,
    /// `last_limited_listing` holds the latest resource-limited listing on the
    /// domain.
    pub last_limited_listing: Option<ResourceLimited>,
    /// This many listing sessions on the domain wait for their next lease.
    pub suspended_sessions: usize,
}

/// `DomainOps` records the operations of one tree on one storage domain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DomainOps {
    /// The tree performed this many listing operations.
    pub listings: u64,
    /// The tree performed this many metadata operations.
    pub metadata_operations: u64,
    /// The tree enumerated this many directory entries.
    pub entries_enumerated: u64,
    /// The tree performed this many per-child operations.
    pub per_child_lookups: u64,
    /// The tree performed this many kind resolutions.
    pub kind_resolutions: u64,
    /// The tree performed this many identity reads.
    pub identity_reads: u64,
    /// The latest complete listing counted this many children.
    pub last_listing_children: Option<usize>,
    /// `last_limited_listing` holds the latest resource-limited listing.
    pub last_limited_listing: Option<ResourceLimited>,
}

fn to_f64(count: u64) -> f64 {
    let high = u32::try_from(count >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(count & u64::from(u32::MAX)).unwrap_or(u32::MAX);
    f64::from(high) * 4_294_967_296.0 + f64::from(low)
}

fn rate(count: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 { 0.0 } else { to_f64(count) / seconds }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DomainRecord {
    identity: DomainIdentity,
    capabilities: DomainCapabilities,
    watcher: WatcherCapabilities,
}

fn resolve_watcher(declared: WatcherCapabilities, root: WatcherKind) -> WatcherCapabilities {
    let availability = match declared.availability {
        WatcherAvailability::Unknown if root.is_present() => WatcherAvailability::Available,
        WatcherAvailability::Unknown => WatcherAvailability::Unavailable,
        declared => declared,
    };
    let scope = match declared.scope {
        WatcherScope::Unknown if root.is_per_directory() => WatcherScope::PerDirectory,
        WatcherScope::Unknown => WatcherScope::Recursive,
        declared => declared,
    };
    WatcherCapabilities { availability, scope, ..declared }
}

fn watcher_backend(capabilities: WatcherCapabilities) -> WatcherKind {
    match (capabilities.availability, capabilities.scope) {
        (WatcherAvailability::Available, WatcherScope::PerDirectory) => WatcherKind::NonRecursive,
        (WatcherAvailability::Available, _) => WatcherKind::Recursive,
        _ => WatcherKind::None,
    }
}

fn names_the_same_mount(held: &ProbeResult, probe: &ProbeResult) -> bool {
    match (held.identity.weak(), probe.identity.weak()) {
        (Some(held), Some(observed)) => held == observed,
        (None, None) => !held.identity.is_known() && held.capabilities == probe.capabilities,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

#[derive(Clone, Copy)]
pub(super) enum DomainSite<'a> {
    Represented(EntryId),
    Child { domain: StorageDomainId, probe: &'a ProbeResult },
    Detached,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WatchScope {
    Recursive,
    PerDirectory,
}

impl WatchScope {
    pub(super) fn is_recursive(self) -> bool {
        self == WatchScope::Recursive
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WatchDecision {
    NotNeeded,
    Register(WatchScope),
    Capped,
}

/// `Command` carries one consumer request to the coordinator.
///
/// Each variant matches one [`TreeHandle`](crate::TreeHandle) method. RFC §9
/// and §9.1 specify the completion and target resolution of each command.
#[derive(Clone, Debug)]
pub enum Command {
    /// The consumer asks the tree to read each path again after the barrier.
    Refresh(Vec<RelativePath>),
    /// The consumer asks the tree to load a represented directory.
    Load(RelativePath),
    /// The consumer asks the tree to unload a directory and its descendants.
    Unload(RelativePath),
    /// The consumer asks the tree to reevaluate policy beneath each root.
    InvalidatePolicy(Vec<RelativePath>),
    /// The consumer replaces the priority set.
    SetPriority(Vec<RelativePath>),
    /// The consumer waits for the initial scan of the current root incarnation.
    InitialScanComplete,
    /// The consumer stops the tree.
    Shutdown,
}

/// `JobOperation` names the filesystem operation in a worker slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobOperation {
    /// The worker runs a listing session step.
    Listing,
    /// The worker reads metadata.
    Metadata,
    /// The worker resolves a storage domain (RFC §10.3).
    DomainResolution,
    /// The worker reads configured metadata of children (RFC §10.1).
    Enrichment {
        /// The enrichment reads these fields.
        fields: MetadataFields,
    },
    /// The worker registers a watch.
    WatchRegistration,
    /// The worker releases a watch.
    WatchRelease,
}

/// `ListingWork` bounds one listing session step (RFC §10.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListingWork {
    /// The step may perform the entries and per-child operations of this lease.
    pub lease: Lease,
    /// `ceilings` bounds the entries and bytes of the whole listing.
    pub ceilings: Ceilings,
    /// The session polls this token between chunks.
    pub cancel: CancellationToken,
    /// `resume` tells the worker to continue the suspended session of the job.
    ///
    /// A `false` value opens a new session.
    pub resume: bool,
}

/// `Work` describes the filesystem work of one [`JobSpec`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Work {
    /// The worker runs one listing session step.
    Listing(ListingWork),
    /// The worker reads the metadata of the target.
    Metadata,
    /// The worker resolves the storage domain of the target.
    ResolveDomain {
        /// `parent` holds the domain probe of the parent, when the tree knows
        /// it.
        parent: Option<Box<ProbeResult>>,
    },
    /// The worker reads configured metadata of the target's children.
    Enrichment {
        /// `batch` names the children and fields to read.
        ///
        /// The grant bounds `batch`.
        batch: EnrichmentBatch,
    },
}

/// The driver runs this job on a blocking worker.
///
/// The driver answers with [`Input::JobCompleted`] or [`Input::WorkerLost`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobSpec {
    /// `id` identifies the job.
    pub id: JobId,
    /// `path` holds the root-relative path of the target.
    pub path: RelativePath,
    /// `work` describes the work to perform.
    pub work: Work,
}

impl JobSpec {
    /// `operation` returns the operation kind of the work.
    pub fn operation(&self) -> JobOperation {
        match &self.work {
            Work::Listing(_) => JobOperation::Listing,
            Work::Metadata => JobOperation::Metadata,
            Work::ResolveDomain { .. } => JobOperation::DomainResolution,
            Work::Enrichment { batch } => JobOperation::Enrichment { fields: batch.fields },
        }
    }
}

/// `JobResult` carries the result of one [`Work`] item.
///
/// Each variant matches the variant of its work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobResult {
    /// The listing session step ended suspended or finished.
    Listing(SessionStep),
    /// The metadata read returned this result.
    Metadata(Result<EntryInfo, FsError>),
    /// The domain resolution returned this result.
    Domain(Result<ProbeResult, FsError>),
    /// The enrichment read returned this result.
    Enrichment(Result<Enrichment, FsError>),
}

/// A worker ended without a result for this work (RFC §13.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WorkerLoss {
    /// The worker for this job panicked or lost its channel.
    Job(JobId),
    /// The worker for this watch registration panicked or lost its channel.
    WatchRegistration(WatchRequestId),
    /// The worker for this watch release panicked or lost its channel.
    WatchRelease(WatchReleaseId),
}

/// `Input` reports one event to [`Coordinator::handle`].
///
/// The driver delivers each input.
#[derive(Clone, Debug)]
pub enum Input {
    /// The consumer issued a command.
    ///
    /// The `id` must be unique per tree.
    Command {
        /// [`Output::CommandFinished`] echoes this identity.
        id: CommandId,
        /// `command` holds the command.
        command: Command,
    },
    /// The watcher backend reported an event.
    Watcher(WatcherEvent),
    /// A worker finished a job from [`Output::StartJob`].
    JobCompleted {
        /// `job` identifies the job.
        job: JobId,
        /// `result` holds the result of the job.
        result: JobResult,
    },
    /// A watch registration from [`Output::RegisterWatch`] returned.
    WatchRegistered {
        /// `request` identifies the registration request.
        request: WatchRequestId,
        /// `result` holds the new watch or the failure.
        result: Result<WatchId, FsError>,
    },
    /// A watch release from [`Output::Unwatch`] returned.
    WatchReleased {
        /// `release` identifies the release request.
        release: WatchReleaseId,
    },
    /// A worker ended without delivering its result.
    WorkerLost(WorkerLoss),
    /// The timer from [`Output::SetTimer`] with this id fired.
    Timer(TimerId),
}

/// `TerminalOutcome` tells how the coordinator stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalOutcome {
    /// A `shutdown` command completed.
    ShutDown,
    /// A Fatal filesystem failure terminated the tree (RFC §13.1).
    Terminated,
}

/// `Output` names one effect for the driver.
///
/// The driver performs the outputs in the returned order.
#[derive(Clone, Debug)]
pub enum Output {
    /// The driver runs the job on a blocking worker.
    ///
    /// The coordinator has already started the grant of the job.
    StartJob(JobSpec),
    /// The driver discards the eventual result of the job.
    ///
    /// The coordinator has already set the cancellation token of the job.
    CancelJob(JobId),
    /// The driver registers a watch and answers with
    /// [`Input::WatchRegistered`].
    RegisterWatch {
        /// `request` identifies the registration.
        request: WatchRequestId,
        /// `path` holds the root-relative path to watch.
        path: RelativePath,
        /// `recursive` asks for a watch on the whole subtree.
        ///
        /// A `false` value watches the directory alone.
        recursive: bool,
    },
    /// The driver releases a watch and answers with [`Input::WatchReleased`].
    Unwatch {
        /// `release` identifies the release.
        release: WatchReleaseId,
        /// `watch` names the watch to release.
        watch: WatchId,
    },
    /// The driver delivers the event to the update stream.
    Publish(Box<UpdateEvent>),
    /// The driver completes the command with this result.
    CommandFinished {
        /// `id` echoes the identity from [`Input::Command`].
        id: CommandId,
        /// `result` holds the outcome of the command.
        result: Result<(), Error>,
    },
    /// The driver replaces any armed timer with one for `at`.
    ///
    /// The new timer delivers [`Input::Timer`].
    SetTimer {
        /// The timer input must carry this identity.
        id: TimerId,
        /// The timer fires at this monotonic time.
        at: MonotonicTime,
    },
    /// The coordinator accepts no further commands.
    Stopped(TerminalOutcome),
}

/// `SlotOwner` names the work in a physical worker slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SlotOwner {
    /// A job holds the slot, its watch registration included.
    Job(JobId),
    /// A watch registration outside any job holds the slot.
    WatchRegistration(WatchRequestId),
    /// A watch release holds the slot.
    WatchRelease(WatchReleaseId),
}

impl SlotOwner {
    /// `job` returns the job of a [`SlotOwner::Job`].
    pub fn job(self) -> Option<JobId> {
        match self {
            SlotOwner::Job(id) => Some(id),
            SlotOwner::WatchRegistration(_) | SlotOwner::WatchRelease(_) => None,
        }
    }

    /// `release` returns the release of a [`SlotOwner::WatchRelease`].
    pub fn release(self) -> Option<WatchReleaseId> {
        match self {
            SlotOwner::WatchRelease(id) => Some(id),
            SlotOwner::Job(_) | SlotOwner::WatchRegistration(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingRelease {
    watch: WatchId,
    path: RelativePath,
    domain: Option<StorageDomainId>,
}

/// `BlockingSlot` describes a physical worker slot of a tree (RFC §13.5).
///
/// The tree holds the slot until the call returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockingSlot {
    /// `owner` names the work in the slot.
    pub owner: SlotOwner,
    /// `path` holds the root-relative path of the target.
    pub path: RelativePath,
    /// `operation` names the operation in progress.
    pub operation: JobOperation,
    /// The tree took the slot at this time.
    pub started: MonotonicTime,
}

impl BlockingSlot {
    /// `job` returns the job in the slot, if any.
    pub fn job(&self) -> Option<JobId> {
        self.owner.job()
    }
}

/// `BatchView` describes the open closed batch of a dispatch cycle (RFC §11.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchView {
    /// `periodic` is set when the periodic timer started this cycle.
    pub periodic: bool,
    /// `members` holds the admitted jobs without a terminal outcome.
    pub members: BTreeSet<JobId>,
}

/// `Stats` describes one tree at one instant (RFC §16).
///
/// The governor fields cover every tree on the governor. The other fields cover
/// this tree.
#[derive(Clone, Debug, PartialEq)]
pub struct Stats {
    /// The coordinator took the observation at this time.
    pub observed_at: MonotonicTime,
    /// The governor charged this worker time to the grants of this tree after
    /// open.
    pub charged_worker_time_after_open: Duration,
    /// `version` holds the current snapshot version.
    pub version: SnapshotVersion,
    /// `initial_scan` holds the initial scan state.
    pub initial_scan: InitialScanState,
    /// `reconciliation_generation` holds the generation of the active round or
    /// of the latest round.
    pub reconciliation_generation: ReconciliationGeneration,
    /// Every loaded directory needs coverage at this generation or later.
    ///
    /// Overflow and watcher restart raise the minimum (RFC §11.6).
    pub minimum_coverage_generation: ReconciliationGeneration,
    /// The latest completed round started at this time and took this long.
    pub last_round: Option<(MonotonicTime, Duration)>,
    /// The latest successful round started at this time and took this long.
    pub last_successful_round: Option<(MonotonicTime, Duration)>,
    /// `baseline_cursor` holds the baseline cursor position and the obligation
    /// count.
    ///
    /// Both values refer to the active round.
    pub baseline_cursor: (usize, usize),
    /// `obligations` counts the obligations of the active round or the latest
    /// completed round.
    pub obligations: ObligationCounts,
    /// `priority_cursor` holds the priority cursor position and the priority
    /// set size.
    pub priority_cursor: (usize, usize),
    /// This many directories are in Loaded state.
    pub loaded_directories: usize,
    /// The snapshot represents this many entries.
    pub represented_entries: usize,
    /// The snapshot accounts this many bytes.
    pub snapshot_bytes: u64,
    /// All trees on the governor together account this many bytes.
    pub accounted_memory: u64,
    /// This many admitted jobs wait for a worker or for their next lease.
    pub queued_jobs: usize,
    /// This many jobs have a started worker.
    pub in_flight_jobs: usize,
    /// This tree holds this many physical worker slots.
    pub blocking_slots_held: usize,
    /// `blocking_slots` holds every physical worker slot of this tree.
    pub blocking_slots: Vec<BlockingSlot>,
    /// `stuck_workers` holds the slots of this tree with a stuck worker.
    pub stuck_workers: Vec<BlockingSlot>,
    /// `governor` shows the governor state at `observed_at`.
    pub governor: GovernorView,
    /// `grants` holds every live grant of the governor.
    pub grants: Vec<Grant>,
    /// `resource` holds the resource health of the tree (RFC §15.6).
    pub resource: ResourceHealth,
    /// This many reads wait for admission.
    ///
    /// A pending root probe counts as one read.
    pub pending_requests: usize,
    /// `watcher` names the watcher backend of the filesystem.
    pub watcher: WatcherKind,
    /// `watcher_path_limit` repeats [`Config::watcher_path_limit`].
    pub watcher_path_limit: usize,
    /// Snapshot commits computed this many case-folded path keys.
    pub path_folds: u64,
    /// This many paths hold a pending or registered watch.
    pub paths_watched: usize,
    /// The watcher path limit left this many directories unwatched.
    pub paths_unwatched_by_cap: usize,
    /// The tree dropped this many watcher hints at the watcher path limit.
    pub dropped_hints: u64,
    /// The tree merged this many watcher hints into an already pending read.
    pub coalesced_hints: u64,
    /// The tree received this many complete listings.
    pub listings: u64,
    /// This many listings failed or reached a resource limit, or the tree
    /// rejected them at commit.
    pub listing_failures: u64,
    /// The tree discarded this many results for a stale publication guard.
    pub stale_results: u64,
    /// The driver reported this many workers lost after start.
    pub lost_workers: u64,
    /// The latest listing result arrived this long after its job started.
    pub last_listing_duration: Option<Duration>,
    /// The latest complete listing counted this many children.
    pub last_listing_children: Option<usize>,
    /// `last_limited_listing` holds the latest resource-limited listing.
    pub last_limited_listing: Option<ResourceLimited>,
    /// `largest_directories` holds up to 16 of the largest directories, largest
    /// first.
    pub largest_directories: Vec<DirectorySize>,
    /// `degraded_paths` holds every path with an active degradation cause.
    pub degraded_paths: BTreeSet<RelativePath>,
    /// `degraded_path_causes` gives the cause of each degraded path.
    pub degraded_path_causes: BTreeMap<RelativePath, DegradedCause>,
    /// Metadata enrichment failed for these paths.
    pub metadata_degraded_paths: BTreeSet<RelativePath>,
    /// Sessions and enrichment reported this many metadata operations.
    pub metadata_operations: u64,
    /// Sessions reported this many listing operations.
    pub listing_operations: u64,
    /// Sessions enumerated this many directory entries.
    ///
    /// The count includes filtered entries.
    pub entries_enumerated: u64,
    /// Finished listing results held this many bytes in total.
    pub listing_bytes: u64,
    /// Open listing sessions of this tree hold this many bytes.
    pub in_flight_listing_bytes: u64,
    /// Adapters reported this much blocking time to the governor.
    pub reported_blocking: Duration,
    /// Sessions reported this many kind resolutions.
    pub kind_resolutions: u64,
    /// Sessions reported this many identity reads.
    pub identity_reads: u64,
    /// This many listings contained a child of unresolved kind.
    pub unresolved_listings: u64,
    /// This many listing sessions wait for their next lease.
    pub suspended_sessions: usize,
    /// The governor granted this many leases after the first lease of a job.
    pub lease_grants: u64,
    /// This many listing sessions ended Cancelled.
    pub cancelled_sessions: u64,
    /// `resource_limits` holds the latest 64 resource-limit events.
    pub resource_limits: Vec<ResourceLimitEvent>,
    /// The tree applied this many enrichment results.
    pub enrichments: u64,
    /// This many enrichment jobs failed in whole or in part.
    pub enrichment_failures: u64,
    /// This many directories wait for enrichment.
    pub pending_enrichments: usize,
    /// `domains` holds statistics for every storage domain of the tree.
    pub domains: Vec<DomainStat>,
    /// `crossings` holds the latest 64 domain-crossing decisions.
    pub crossings: Vec<CrossingEvent>,
    /// The tree applied this many domain resolution results.
    pub domain_resolutions: u64,
    /// This many directories wait for domain resolution.
    pub pending_domain_resolutions: usize,
}

/// `Coordinator` runs the synchronization state machine of one tree.
///
/// The coordinator is the only writer of its snapshot (RFC §6). The same inputs
/// at the same times give the same outputs. A driver such as
/// [`Tree`](crate::Tree) runs the coordinator on one task. The driver executes
/// every [`Output`] and feeds back the matching [`Input`]. Dropping the
/// coordinator releases all of its grants.
pub struct Coordinator {
    config: Config,
    governor: HostGovernor,
    tree: TreeNumber,
    memory_ceiling: u64,
    maximum_in_flight: usize,
    in_flight_bytes_ceiling: u64,
    policy: Arc<dyn ScanPolicy>,
    caps: FsCapabilities,
    now: MonotonicTime,
    seq: Sequence,
    recon_seq: ReconciliationGeneration,
    min_recon: ReconciliationGeneration,
    next_entry_id: EntryId,
    next_job_id: JobId,
    next_watch_request: WatchRequestId,
    next_watch_release: WatchReleaseId,
    snapshot: Snapshot,
    parent_cache: std::cell::RefCell<(SnapshotVersion, IdMap<EntryId, Option<EntryId>>)>,
    published_version: SnapshotVersion,
    root: RootState,
    root_seed: Option<PolicyContext>,
    initial_scan: InitialScan,
    entries: EntryStates,
    pending: IdMap<EntryId, PendingRequest>,
    pending_enrichment: IdMap<EntryId, EnrichmentRequest>,
    pending_domain: IdMap<EntryId, DomainRequest>,
    domain_records: BTreeMap<StorageDomainId, DomainRecord>,
    crossing_events: VecDeque<CrossingEvent>,
    domain_ops: BTreeMap<StorageDomainId, DomainOps>,
    domain_entry_paths: BTreeMap<StorageDomainId, RelativePath>,
    domain_resolutions: u64,
    root_probe: Option<RootProbe>,
    probe_attempts: u32,
    jobs: IdMap<JobId, ActiveJob>,
    blocking_slots: BTreeMap<SlotOwner, Occupancy>,
    active_by_entry: IdMap<EntryId, JobId>,
    probe_job: Option<JobId>,
    registrations: IdMap<WatchRequestId, Registration>,
    queue_order: VecDeque<JobId>,
    batch: Option<Batch>,
    round: Option<Round>,
    last_round: Option<(MonotonicTime, Duration)>,
    last_successful_round: Option<(MonotonicTime, Duration)>,
    last_round_result: Option<crate::update::RoundResult>,
    last_obligations: ObligationCounts,
    commands: IdMap<CommandId, PendingCommand>,
    priority: PrioritySet,
    policy_fence: PolicyFence,
    class_rotation: usize,
    dispatch_rotation: usize,
    watcher_health: WatcherHealth,
    watcher_degraded: BTreeMap<StorageDomainId, String>,
    watcher_restart_due: Option<MonotonicTime>,
    watcher_restart_attempts: u32,
    watches: IdMap<WatchId, RelativePath>,
    pending_releases: VecDeque<PendingRelease>,
    open_gate: OpenGate,
    outputs: Vec<Output>,
    baseline_due: bool,
    periodic_due: MonotonicTime,
    timer_wake: Option<MonotonicTime>,
    timer_id: TimerId,
    shutdown: ShutdownState,
    last_published_health: Option<Health>,
    errors: Vec<RecoverableError>,
    rng: u64,
    dropped_hints: u64,
    coalesced_hints: u64,
    listings: u64,
    listing_failures: u64,
    stale_results: u64,
    lost_workers: u64,
    metadata_operations: u64,
    listing_operations: u64,
    entries_enumerated: u64,
    listing_bytes: u64,
    in_flight_listing_bytes: u64,
    reported_memory: (u64, u64),
    session_bytes: IdMap<JobId, u64>,
    kind_resolutions: u64,
    identity_reads: u64,
    unresolved_listings: u64,
    path_folds: u64,
    cancelled_sessions: u64,
    resource_limits: VecDeque<ResourceLimitEvent>,
    enrichments: u64,
    enrichment_failures: u64,
    last_listing_duration: Option<Duration>,
    last_listing_children: Option<usize>,
    last_limited_listing: Option<ResourceLimited>,
    largest_directories: Vec<DirectorySize>,
}

impl Drop for Coordinator {
    fn drop(&mut self) {
        let now = self.now;
        for id in self.jobs.keys() {
            self.governor.release(self.job_grant(*id), now);
        }
        for id in self.blocking_slots.keys().filter_map(|owner| owner.job()) {
            self.governor.release(self.job_grant(id), now);
        }
        for (request, held) in self.registrations.iter() {
            self.governor.release(self.registration_grant(*request), now);
            if let Some(job) = held.target.job() {
                self.governor.release(self.job_grant(job), now);
            }
        }
        for release in self.blocking_slots.keys().filter_map(|owner| owner.release()) {
            self.governor.release(self.release_grant(release), now);
        }
        self.governor.forget_tree(self.tree);
    }
}

impl Coordinator {
    /// `new` creates the coordinator and schedules the first root listing.
    ///
    /// The caller obtains `root_info` under bootstrap grants.
    /// [`Coordinator::take_outputs`] returns the initial outputs.
    ///
    /// # Errors
    ///
    /// `new` returns [`Error::InvalidConfig`] when `config` or the governor
    /// limits fail validation. It returns [`Error::NotDirectory`] when the root
    /// is a non-directory.
    pub fn new(
        config: Config,
        policy: Arc<dyn ScanPolicy>,
        caps: FsCapabilities,
        root_info: EntryInfo,
        now: MonotonicTime,
        governor: HostGovernor,
    ) -> Result<Coordinator, Error> {
        config.validate().map_err(Error::InvalidConfig)?;
        governor.limits().validate().map_err(Error::InvalidConfig)?;
        if root_info.kind != crate::entry::EntryKind::Directory {
            return Err(Error::NotDirectory);
        }
        let seed = config.jitter_seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let snapshot = Snapshot::empty(SnapshotVersion::new(0), caps.case);
        let tree = governor.next_tree();
        let memory_ceiling = governor.memory_ceiling();
        let maximum_in_flight = governor.limits().maximum_in_flight;
        let in_flight_bytes_ceiling = governor.limits().in_flight_listing_bytes;
        let mut coordinator = Coordinator {
            config,
            governor,
            tree,
            memory_ceiling,
            maximum_in_flight,
            in_flight_bytes_ceiling,
            policy,
            caps,
            now,
            seq: Sequence::new(0),
            recon_seq: ReconciliationGeneration::new(0),
            min_recon: ReconciliationGeneration::new(0),
            next_entry_id: EntryId::new(1),
            next_job_id: JobId::new(1),
            next_watch_request: WatchRequestId::new(1),
            next_watch_release: WatchReleaseId::new(1),
            snapshot,
            parent_cache: std::cell::RefCell::new((SnapshotVersion::new(0), IdMap::default())),
            published_version: SnapshotVersion::new(0),
            root: RootState::Unavailable { last: RootIncarnation::new(0) },
            root_seed: None,
            initial_scan: InitialScan::new(),
            entries: EntryStates::default(),
            pending: IdMap::default(),
            pending_enrichment: IdMap::default(),
            pending_domain: IdMap::default(),
            domain_records: BTreeMap::new(),
            crossing_events: VecDeque::new(),
            domain_ops: BTreeMap::new(),
            domain_entry_paths: BTreeMap::new(),
            domain_resolutions: 0,
            root_probe: None,
            probe_attempts: 0,
            jobs: IdMap::default(),
            blocking_slots: BTreeMap::new(),
            active_by_entry: IdMap::default(),
            probe_job: None,
            registrations: IdMap::default(),
            queue_order: VecDeque::new(),
            batch: None,
            round: None,
            last_round: None,
            last_successful_round: None,
            last_round_result: None,
            last_obligations: ObligationCounts::default(),
            commands: IdMap::default(),
            priority: PrioritySet::default(),
            policy_fence: PolicyFence::new(0),
            class_rotation: 0,
            dispatch_rotation: 0,
            watcher_health: if caps.watcher.is_present() {
                WatcherHealth::Healthy { backend: caps.watcher }
            } else {
                WatcherHealth::Absent
            },
            watcher_degraded: BTreeMap::new(),
            watcher_restart_due: None,
            watcher_restart_attempts: 0,
            watches: IdMap::default(),
            pending_releases: VecDeque::new(),
            open_gate: OpenGate::Pending,
            outputs: Vec::new(),
            baseline_due: false,
            periodic_due: now,
            timer_wake: None,
            timer_id: TimerId::new(0),
            shutdown: ShutdownState::Running,
            last_published_health: None,
            errors: Vec::new(),
            rng: seed,
            dropped_hints: 0,
            coalesced_hints: 0,
            listings: 0,
            listing_failures: 0,
            stale_results: 0,
            lost_workers: 0,
            metadata_operations: 0,
            listing_operations: 0,
            entries_enumerated: 0,
            listing_bytes: 0,
            in_flight_listing_bytes: 0,
            reported_memory: (0, 0),
            session_bytes: IdMap::default(),
            kind_resolutions: 0,
            identity_reads: 0,
            unresolved_listings: 0,
            path_folds: 0,
            cancelled_sessions: 0,
            resource_limits: VecDeque::new(),
            enrichments: 0,
            enrichment_failures: 0,
            last_listing_duration: None,
            last_listing_children: None,
            last_limited_listing: None,
            largest_directories: Vec::new(),
        };
        coordinator.install_root(root_info);
        if !coordinator.caps.watcher.is_present() {
            coordinator.open_gate = OpenGate::Ready;
        }
        coordinator.after_input();
        Ok(coordinator)
    }

    /// `open_gate` reports whether the tree may publish its handle.
    ///
    /// `None` means the initial root watch registration is still pending (RFC
    /// §11.1). An error means that open must fail with it.
    pub fn open_gate(&self) -> Option<Result<(), Error>> {
        match &self.open_gate {
            OpenGate::Pending => None,
            OpenGate::Ready => Some(Ok(())),
            OpenGate::Failed(err) => Some(Err(err.clone())),
        }
    }

    /// `take_outputs` drains the queued outputs.
    pub fn take_outputs(&mut self) -> Vec<Output> {
        std::mem::take(&mut self.outputs)
    }

    /// `snapshot` returns the current snapshot.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// `health` returns the current health.
    pub fn health(&self) -> Health {
        self.compute_health()
    }

    /// `config` returns the tree configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// `job_class` returns the admission class of an active job.
    pub fn job_class(&self, id: JobId) -> Option<Class> {
        self.jobs.get(&id).map(|job| job.reasons.class())
    }

    /// `job_operation` returns the operation of an active job.
    pub fn job_operation(&self, id: JobId) -> Option<JobOperation> {
        self.jobs.get(&id).map(|job| Coordinator::operation_for(job.need))
    }

    pub(super) fn record_session_cost(&mut self, job: JobId, cost: &SessionCost) {
        self.listing_operations += u64::from(cost.listing_operations);
        self.metadata_operations += u64::from(cost.metadata_operations);
        self.kind_resolutions += u64::from(cost.kind_resolutions);
        self.identity_reads += u64::from(cost.identity_reads);
        self.entries_enumerated += cost.entries_enumerated;
        let previous = self.session_bytes.insert(job, cost.bytes).unwrap_or(0);
        self.in_flight_listing_bytes = self.in_flight_listing_bytes.saturating_sub(previous).saturating_add(cost.bytes);
        let domain = self.jobs.get(&job).and_then(|job| job.domain);
        if let Some(domain) = domain {
            let ops = self.domain_ops.entry(domain).or_default();
            ops.listings += u64::from(cost.listing_operations);
            ops.metadata_operations += u64::from(cost.metadata_operations);
            ops.entries_enumerated += cost.entries_enumerated;
            ops.per_child_lookups += u64::from(cost.per_child_operations());
            ops.kind_resolutions += u64::from(cost.kind_resolutions);
            ops.identity_reads += u64::from(cost.identity_reads);
        }
    }

    pub(super) fn record_domain_metadata(&mut self, entry: EntryId, operations: u32) {
        let Some(domain) = self.domain_of(entry) else {
            return;
        };
        self.domain_ops.entry(domain).or_default().metadata_operations += u64::from(operations);
    }

    pub(super) fn release_session_bytes(&mut self, job: JobId) {
        let domain = self.jobs.get(&job).and_then(|job| job.domain);
        if let Some(bytes) = self.session_bytes.remove(&job) {
            self.listing_bytes += bytes;
            self.in_flight_listing_bytes = self.in_flight_listing_bytes.saturating_sub(bytes);
            let now = self.now;
            self.governor.record_bytes(domain, bytes, now);
        }
    }

    pub(super) fn memory_ceiling(&self) -> u64 {
        self.memory_ceiling
    }

    pub(super) fn projected_memory(&self, snapshot_bytes: u64) -> u64 {
        self.governor
            .accounted_memory_excluding(self.tree)
            .saturating_add(snapshot_bytes)
            .saturating_add(self.in_flight_listing_bytes)
    }

    fn report_memory(&mut self) {
        let reported = (self.snapshot.bytes(), self.in_flight_listing_bytes);
        if self.reported_memory == reported {
            return;
        }
        self.reported_memory = reported;
        self.governor.report_memory(self.tree, reported.0, reported.1);
    }

    pub(super) fn record_resource_limit(&mut self, event: ResourceLimitEvent) {
        if self.resource_limits.len() >= RESOURCE_LIMIT_HISTORY {
            self.resource_limits.pop_front();
        }
        self.resource_limits.push_back(event);
    }

    pub(super) fn operation_for(need: ReadNeed) -> JobOperation {
        match need {
            ReadNeed::Listing => JobOperation::Listing,
            ReadNeed::Metadata => JobOperation::Metadata,
            ReadNeed::Domain => JobOperation::DomainResolution,
            ReadNeed::Enrichment(fields) => JobOperation::Enrichment { fields },
        }
    }

    pub(super) fn job_grant(&self, id: JobId) -> GrantId {
        GrantId::Job(self.tree, id)
    }

    pub(super) fn registration_grant(&self, request: WatchRequestId) -> GrantId {
        GrantId::WatchRegistration(self.tree, request)
    }

    pub(super) fn release_grant(&self, release: WatchReleaseId) -> GrantId {
        GrantId::WatchRelease(self.tree, release)
    }

    /// `grants` returns every live grant of the shared governor.
    pub fn grants(&self) -> Vec<Grant> {
        self.governor.grants()
    }

    /// `new_grants_into` appends every unseen live grant to `into`.
    ///
    /// The `seen` callback receives the id and lease of each grant. It returns
    /// `true` for a known grant.
    pub fn new_grants_into(&self, into: &mut Vec<Grant>, seen: &dyn Fn(GrantId, u32) -> bool) {
        self.governor.new_grants_into(into, seen)
    }

    pub(super) fn record_complete_listing(&mut self, path: &RelativePath, children: usize) {
        self.last_listing_children = Some(children);
        if let Some(domain) = self.listed_domain(path) {
            self.domain_ops.entry(domain).or_default().last_listing_children = Some(children);
        }
        self.record_directory_size(path, children);
    }

    pub(super) fn record_limited_listing(&mut self, path: &RelativePath, limited: ResourceLimited) {
        self.last_limited_listing = Some(limited);
        if let Some(domain) = self.listed_domain(path) {
            self.domain_ops.entry(domain).or_default().last_limited_listing = Some(limited);
        }
        if limited.limit == ResourceLimit::EntriesPerDirectory {
            self.record_directory_size(path, usize::try_from(limited.observed).unwrap_or(usize::MAX));
        }
    }

    fn listed_domain(&self, path: &RelativePath) -> Option<StorageDomainId> {
        self.snapshot.get(path).map(|e| e.id).and_then(|id| self.domain_of(id))
    }

    fn record_directory_size(&mut self, path: &RelativePath, children: usize) {
        match self.largest_directories.iter().position(|entry| entry.path == *path) {
            Some(at) if self.largest_directories[at].children == children => return,
            Some(at) => self.largest_directories[at].children = children,
            None if self.largest_directories.len() >= LARGEST_DIRECTORIES
                && self.largest_directories.last().is_some_and(|last| last.children >= children) =>
            {
                return;
            }
            None => self.largest_directories.push(DirectorySize { path: path.clone(), children }),
        }
        self.largest_directories.sort_by(|a, b| b.children.cmp(&a.children).then_with(|| a.path.cmp(&b.path)));
        self.largest_directories.truncate(LARGEST_DIRECTORIES);
    }

    pub(super) fn ceilings(&self) -> Ceilings {
        Ceilings { entries: self.config.entries_per_directory, bytes: self.in_flight_bytes_ceiling }
    }

    pub(super) fn limited(
        &self,
        limit: ResourceLimit,
        configured: u64,
        observed: u64,
        entry: EntryId,
    ) -> ResourceLimited {
        ResourceLimited { limit, configured, observed, domain: self.domain_of(entry) }
    }

    /// `governor` returns the governor state at the coordinator's current time.
    pub fn governor(&self) -> GovernorView {
        self.governor.view(self.now)
    }

    /// `last_round` returns the start and duration of the latest completed
    /// round.
    pub fn last_round(&self) -> Option<(MonotonicTime, Duration)> {
        self.last_round
    }

    /// `open_batch` returns the open closed batch.
    ///
    /// `open_batch` returns `None` between dispatch cycles.
    pub fn open_batch(&self) -> Option<BatchView> {
        self.batch
            .as_ref()
            .map(|batch| BatchView { periodic: batch.periodic, members: batch.members.iter().copied().collect() })
    }

    /// `is_stopped` reports whether the tree shut down or was terminated.
    pub fn is_stopped(&self) -> bool {
        matches!(self.shutdown, ShutdownState::Stopped | ShutdownState::Terminated { .. })
    }

    pub(crate) fn has_pending_releases(&self) -> bool {
        !self.pending_releases.is_empty()
    }

    /// `observe` advances the clock to `now` and runs scheduling.
    ///
    /// `observe` returns the resulting outputs. The coordinator ignores a `now`
    /// before its current time.
    pub fn observe(&mut self, now: MonotonicTime) -> Vec<Output> {
        self.now = self.now.max(now);
        self.after_input();
        self.take_outputs()
    }

    /// `handle` applies one input at `now`.
    ///
    /// The driver executes the returned outputs in order. The coordinator
    /// ignores a `now` before its current time. After the coordinator stops,
    /// commands fail with [`Error::Shutdown`] or [`Error::TreeTerminated`].
    /// A late result then only releases its grant.
    pub fn handle(&mut self, input: Input, now: MonotonicTime) -> Vec<Output> {
        self.now = self.now.max(now);
        self.finish_stuck_jobs();
        // The coordinator keeps the completion record until it classifies the
        // result. Validation failures and lost workers must also settle with
        // the shared authority.
        let completed = match &input {
            Input::JobCompleted { job, .. } | Input::WorkerLost(WorkerLoss::Job(job)) => Some(self.job_grant(*job)),
            _ => None,
        };
        match &input {
            Input::WorkerLost(WorkerLoss::Job(job)) => self.governor.note_grant_failure(self.job_grant(*job)),
            Input::WatchRegistered { request, result: Err(_) }
            | Input::WorkerLost(WorkerLoss::WatchRegistration(request)) => {
                let grant = match self.registrations.get(request).map(|registration| registration.target) {
                    Some(RegistrationTarget::Job(job) | RegistrationTarget::AbandonedJob(job)) => self.job_grant(job),
                    _ => self.registration_grant(*request),
                };
                self.governor.note_grant_failure(grant);
            }
            Input::WorkerLost(WorkerLoss::WatchRelease(release)) => {
                self.governor.note_grant_failure(self.release_grant(*release))
            }
            Input::JobCompleted { job, result: JobResult::Enrichment(Ok(read)) } if !read.failed.is_empty() => {
                self.governor.note_grant_failure(self.job_grant(*job));
            }
            _ => {}
        }
        match &input {
            Input::JobCompleted { job, result } => {
                self.blocking_slots.remove(&SlotOwner::Job(*job));
                let now = self.now;
                if let Some(probe) = reported_domain(result) {
                    let site = match self.jobs.get(job).and_then(|job| job.entry()) {
                        Some(entry) => DomainSite::Represented(entry),
                        None => DomainSite::Detached,
                    };
                    let binding = self.bind_domain(site, &probe);
                    self.governor.attribute(self.job_grant(*job), binding.id, now);
                }
                match result {
                    JobResult::Listing(step) => {
                        let operations = step.cost.listing_operations.saturating_add(step.cost.per_child_operations());
                        let reported = Reported { blocking: step.cost.blocking, operations };
                        self.governor.report(self.job_grant(*job), reported, now);
                    }
                    JobResult::Enrichment(Ok(read)) => {
                        let reported = Reported { blocking: None, operations: read.metadata_operations };
                        self.governor.report(self.job_grant(*job), reported, now);
                    }
                    JobResult::Metadata(_) | JobResult::Domain(_) | JobResult::Enrichment(Err(_)) => {}
                }
                let barriers = self.jobs.get(job).map(|job| job.barriers.clone()).unwrap_or_default();
                if !barriers.is_empty() {
                    let overshoot = self.governor.overshoot_of(self.job_grant(*job));
                    self.charge_commands(&barriers, overshoot);
                }
                if self.governor.grant_is_stuck(self.job_grant(*job)) {
                    self.finish_job(*job, JobOutcome::Stuck);
                }
            }
            Input::WorkerLost(WorkerLoss::Job(job)) => {
                self.blocking_slots.remove(&SlotOwner::Job(*job));
                if self.governor.grant_is_stuck(self.job_grant(*job)) {
                    self.finish_job(*job, JobOutcome::Stuck);
                }
            }
            Input::WatchRegistered { request, .. } | Input::WorkerLost(WorkerLoss::WatchRegistration(request)) => {
                let now = self.now;
                self.governor.release(self.registration_grant(*request), now);
                match self.registrations.get(request).map(|held| held.target) {
                    Some(RegistrationTarget::AbandonedJob(job)) => {
                        self.blocking_slots.remove(&SlotOwner::Job(job));
                        self.governor.release(self.job_grant(job), now);
                    }
                    Some(RegistrationTarget::AbandonedStandalone | RegistrationTarget::Standalone(_)) => {
                        self.blocking_slots.remove(&SlotOwner::WatchRegistration(*request));
                    }
                    Some(RegistrationTarget::Job(_)) | None => {}
                }
            }
            Input::WatchReleased { release } | Input::WorkerLost(WorkerLoss::WatchRelease(release)) => {
                let now = self.now;
                self.blocking_slots.remove(&SlotOwner::WatchRelease(*release));
                self.governor.release(self.release_grant(*release), now);
            }
            Input::Command { .. } | Input::Watcher(_) | Input::Timer(_) => {}
        }
        if self.is_stopped() {
            match input {
                Input::Command { id, .. } => {
                    let err = match &self.shutdown {
                        ShutdownState::Terminated { .. } => Error::TreeTerminated,
                        _ => Error::Shutdown,
                    };
                    self.outputs.push(Output::CommandFinished { id, result: Err(err) });
                }
                Input::WatchRegistered { request, result } => {
                    if let Some(held) = self.registrations.remove(&request) {
                        self.release_watch(result.map_err(ErrorCause::Fs), held.path);
                    }
                }
                Input::Watcher(_)
                | Input::JobCompleted { .. }
                | Input::WatchReleased { .. }
                | Input::WorkerLost(_)
                | Input::Timer(_) => {}
            }
            if let Some(grant) = completed {
                self.governor.release(grant, self.now);
            }
            self.after_input();
            return self.take_outputs();
        }
        match input {
            Input::Command { id, command } => self.on_command(id, command),
            Input::Watcher(event) => self.on_watcher(event),
            Input::JobCompleted { job, result } => self.on_job_completed(job, result),
            Input::WatchRegistered { request, result } => {
                self.on_watch_registered(request, result.map_err(ErrorCause::Fs))
            }
            Input::WatchReleased { .. } => {}
            Input::WorkerLost(loss) => self.on_worker_lost(loss),
            Input::Timer(id) => self.on_timer(id),
        }
        if let Some(grant) = completed {
            self.governor.release(grant, self.now);
        }
        self.after_input();
        self.take_outputs()
    }

    /// `stats` returns the statistics at the coordinator's current time.
    pub fn stats(&self) -> Stats {
        let queued = self.jobs.values().filter(|j| matches!(j.phase, JobPhase::Queued | JobPhase::Suspended)).count();
        let in_flight = self.jobs.values().filter(|j| j.phase.started().is_some()).count();
        let blocking_slots: Vec<BlockingSlot> = self
            .blocking_slots
            .iter()
            .map(|(owner, held)| BlockingSlot {
                owner: *owner,
                path: held.path.clone(),
                operation: held.operation,
                started: held.started,
            })
            .collect();
        let loaded = self.entries.loaded_directories();
        let priority_len = self.priority.paths.len();
        let watches = self.entries.watch_accounts();
        let view = self.governor.view(self.now);
        let resource = self.domain_resource_health();
        let domains = self.domain_stats(&view.domains, &resource);
        Stats {
            observed_at: self.now,
            charged_worker_time_after_open: self.governor.charged_by_tree(self.tree),
            version: self.snapshot.version(),
            initial_scan: self.initial_scan_state(),
            reconciliation_generation: self.round.as_ref().map(|r| r.generation).unwrap_or(self.recon_seq),
            minimum_coverage_generation: self.min_recon,
            last_round: self.last_round,
            last_successful_round: self.last_successful_round,
            baseline_cursor: self.round.as_ref().map(|r| (r.cursor, r.obligations.len())).unwrap_or((0, 0)),
            obligations: match self.round.as_ref() {
                Some(round) => obligation_counts(round),
                None => self.last_obligations,
            },
            priority_cursor: (self.priority.cursor, priority_len),
            loaded_directories: loaded,
            represented_entries: self.snapshot.len(),
            snapshot_bytes: self.snapshot.bytes(),
            accounted_memory: view.accounted_memory,
            queued_jobs: queued,
            in_flight_jobs: in_flight,
            stuck_workers: self
                .governor
                .stuck_grants()
                .into_iter()
                .filter_map(|grant| {
                    let owner = match grant.id {
                        GrantId::Job(_, job) => SlotOwner::Job(job),
                        GrantId::WatchRegistration(_, request) => SlotOwner::WatchRegistration(request),
                        GrantId::WatchRelease(_, release) => SlotOwner::WatchRelease(release),
                        GrantId::Bootstrap(_) => return None,
                    };
                    let held = self.blocking_slots.get(&owner)?;
                    Some(BlockingSlot {
                        owner,
                        path: held.path.clone(),
                        operation: held.operation,
                        started: held.started,
                    })
                })
                .collect(),
            grants: self.governor.grants(),
            resource: self.resource_health(&resource),
            reported_blocking: view.reported_blocking,
            lease_grants: view.lease_grants,
            governor: view,
            blocking_slots_held: blocking_slots.len(),
            blocking_slots,
            pending_requests: self.pending.len() + usize::from(self.root_probe.is_some()),
            watcher: self.caps.watcher,
            watcher_path_limit: self.config.watcher_path_limit,
            path_folds: self.path_folds,
            paths_watched: watches.values().map(|account| account.watched).sum(),
            paths_unwatched_by_cap: watches.values().map(|account| account.unwatched_by_cap).sum(),
            dropped_hints: self.dropped_hints,
            coalesced_hints: self.coalesced_hints,
            listings: self.listings,
            listing_failures: self.listing_failures,
            stale_results: self.stale_results,
            lost_workers: self.lost_workers,
            last_listing_duration: self.last_listing_duration,
            last_listing_children: self.last_listing_children,
            last_limited_listing: self.last_limited_listing,
            largest_directories: self.largest_directories.clone(),
            degraded_paths: self.degraded_paths(),
            degraded_path_causes: self.degraded_path_causes(),
            metadata_degraded_paths: self.metadata_degraded_paths(),
            metadata_operations: self.metadata_operations,
            listing_operations: self.listing_operations,
            entries_enumerated: self.entries_enumerated,
            listing_bytes: self.listing_bytes,
            in_flight_listing_bytes: self.in_flight_listing_bytes,
            kind_resolutions: self.kind_resolutions,
            identity_reads: self.identity_reads,
            unresolved_listings: self.unresolved_listings,
            suspended_sessions: self.jobs.values().filter(|j| j.phase == JobPhase::Suspended).count(),
            cancelled_sessions: self.cancelled_sessions,
            resource_limits: self.resource_limits.iter().cloned().collect(),
            enrichments: self.enrichments,
            enrichment_failures: self.enrichment_failures,
            pending_enrichments: self.pending_enrichment.len(),
            domains,
            crossings: self.crossing_events.iter().cloned().collect(),
            domain_resolutions: self.domain_resolutions,
            pending_domain_resolutions: self.pending_domain.len(),
        }
    }

    fn domain_stats(
        &self,
        accounts: &BTreeMap<StorageDomainId, DomainView>,
        resource: &BTreeMap<StorageDomainId, ResourceHealth>,
    ) -> Vec<DomainStat> {
        let watches = self.entries.watch_accounts();
        let mut suspended: BTreeMap<StorageDomainId, usize> = BTreeMap::new();
        for job in self.jobs.values().filter(|job| job.phase == JobPhase::Suspended) {
            if let Some(domain) = job.domain {
                *suspended.entry(domain).or_insert(0) += 1;
            }
        }
        self.domain_records
            .iter()
            .map(|(id, record)| {
                let watch = watches.get(&Some(*id)).copied().unwrap_or_default();
                let ops = self.domain_ops.get(id).copied().unwrap_or_default();
                let account = accounts.get(id);
                let elapsed = account.map(|view| view.elapsed).unwrap_or_default();
                DomainStat {
                    id: *id,
                    identity: record.identity.clone(),
                    capabilities: record.capabilities.clone(),
                    watcher: record.watcher,
                    watcher_health: self.domain_watcher_health(*id, record.watcher),
                    paths_watched: watch.watched,
                    paths_unwatched_by_cap: watch.unwatched_by_cap,
                    granted: account.map(|view| view.granted).unwrap_or_default(),
                    charged: account.map(|view| view.charged).unwrap_or_default(),
                    capacity: account.map(|view| view.capacity).unwrap_or_default(),
                    level: account.map(|view| view.level).unwrap_or_default(),
                    debt: account.map(|view| view.debt).unwrap_or_default(),
                    window: account.map(|view| view.window).unwrap_or_default(),
                    ceiling: account.map(|view| view.ceiling).unwrap_or_default(),
                    in_flight: account.map(|view| view.in_flight).unwrap_or_default(),
                    stuck: account.map(|view| view.stuck).unwrap_or_default(),
                    estimate: account.map(|view| view.estimate).unwrap_or_default(),
                    foreground_capacity: account.map(|view| view.foreground_capacity).unwrap_or_default(),
                    foreground_level: account.map(|view| view.foreground_level).unwrap_or_default(),
                    foreground_debt: account.map(|view| view.foreground_debt).unwrap_or_default(),
                    bytes_estimate: account.map(|view| view.bytes_estimate).unwrap_or_default(),
                    latency: account.map(|view| view.latency).unwrap_or_default(),
                    listing_latency: account.map(|view| view.listing_latency).unwrap_or_default(),
                    metadata_latency: account.map(|view| view.metadata_latency).unwrap_or_default(),
                    registration_latency: account.map(|view| view.registration_latency).unwrap_or_default(),
                    throttled_jobs: account.map(|view| view.throttled_jobs).unwrap_or_default(),
                    throttled_duration: account.map(|view| view.throttled_duration).unwrap_or_default(),
                    effective_duty: account.map(|view| view.effective_duty()).unwrap_or_default(),
                    resource: resource.get(id).copied().unwrap_or(ResourceHealth::Nominal),
                    listings: ops.listings,
                    metadata_operations: ops.metadata_operations,
                    entries_enumerated: ops.entries_enumerated,
                    per_child_lookups: ops.per_child_lookups,
                    kind_resolutions: ops.kind_resolutions,
                    identity_reads: ops.identity_reads,
                    entries_per_second: rate(ops.entries_enumerated, elapsed),
                    per_child_lookups_per_second: rate(ops.per_child_lookups, elapsed),
                    entry_path: self.domain_entry_paths.get(id).cloned(),
                    last_listing_children: ops.last_listing_children,
                    last_limited_listing: ops.last_limited_listing,
                    suspended_sessions: suspended.get(id).copied().unwrap_or(0),
                }
            })
            .collect()
    }

    pub(super) fn bind_domain(&mut self, site: DomainSite<'_>, probe: &ProbeResult) -> DomainBinding {
        let id = match probe.identity.key() {
            Some(key) => StorageDomainId::of(key),
            None => self.unresolved_domain(site, probe),
        };
        let identity = probe.identity.clone();
        let capabilities = probe.capabilities.clone();
        let watcher = resolve_watcher(capabilities.watcher, self.caps.watcher);
        let now = self.now;
        let known = self.domain_records.get(&id).is_some_and(|held| {
            held.identity == identity && held.capabilities == capabilities && held.watcher == watcher
        });
        if !known {
            self.governor.register_domain(id, &capabilities, now);
            self.domain_records.insert(id, DomainRecord { identity, capabilities, watcher });
        }
        DomainBinding { id, probe: probe.clone() }
    }

    fn unresolved_domain(&self, site: DomainSite<'_>, probe: &ProbeResult) -> StorageDomainId {
        let held = match site {
            DomainSite::Represented(entry) => self.dir_state(entry).and_then(|dir| dir.domain.as_ref()),
            DomainSite::Child { .. } | DomainSite::Detached => None,
        };
        if let Some(binding) = held
            && names_the_same_mount(&binding.probe, probe)
        {
            return binding.id;
        }
        let parent = match site {
            DomainSite::Represented(entry) => self
                .parent_of(entry)
                .and_then(|parent| self.dir_state(parent))
                .and_then(|dir| dir.domain.as_ref())
                .map(|binding| (binding.id, &binding.probe)),
            DomainSite::Child { domain, probe } => Some((domain, probe)),
            DomainSite::Detached => None,
        };
        if let Some((domain, parent)) = parent
            && !apply::requires_crossing_decision(Some(parent), probe)
        {
            return domain;
        }
        StorageDomainId::fresh()
    }

    pub(super) fn domain_of(&self, entry: EntryId) -> Option<StorageDomainId> {
        if let Some(binding) = self.dir_state(entry).and_then(|d| d.domain.as_ref()) {
            return Some(binding.id);
        }
        let parent = self.parent_of(entry)?;
        self.dir_state(parent).and_then(|d| d.domain.as_ref()).map(|binding| binding.id)
    }

    pub(super) fn parent_domain_probe(&self, entry: EntryId) -> Option<ProbeResult> {
        let parent = self.parent_of(entry)?;
        self.dir_state(parent).and_then(|d| d.domain.as_ref()).map(|binding| binding.probe.clone())
    }

    pub(super) fn domain_probe(&self, entry: EntryId) -> Option<ProbeResult> {
        match self.dir_state(entry).and_then(|d| d.domain.as_ref()) {
            Some(binding) => Some(binding.probe.clone()),
            None => self.parent_domain_probe(entry),
        }
    }

    pub(super) fn watcher_of(&self, entry: EntryId) -> WatcherCapabilities {
        let declared = self.domain_probe(entry).map(|probe| probe.capabilities.watcher).unwrap_or_default();
        resolve_watcher(declared, self.caps.watcher)
    }

    fn is_watch_anchor(&self, entry: EntryId) -> bool {
        let Some(represented) = self.snapshot.get_by_id(entry) else {
            return false;
        };
        if represented.path.is_root() {
            return true;
        }
        let Some(own) = self.dir_state(entry).and_then(|d| d.domain.as_ref()).map(|binding| binding.id) else {
            return false;
        };
        let parent = self
            .parent_of(entry)
            .and_then(|parent| self.dir_state(parent))
            .and_then(|d| d.domain.as_ref())
            .map(|binding| binding.id);
        parent != Some(own)
    }

    pub(super) fn watcher_path_limit_of(&self, entry: EntryId) -> usize {
        let configured = self.config.watcher_path_limit;
        let Some(probe) = self.domain_probe(entry) else {
            return configured;
        };
        let Some(path) = self.snapshot.get_by_id(entry).map(|e| e.path.clone()) else {
            return configured;
        };
        let context = self.parent_context(entry).unwrap_or_else(PolicyContext::unit);
        self.policy.watcher_path_limit(&context, &path, &probe.capabilities, configured).min(configured)
    }

    pub(super) fn tree_watch_capacity(&self) -> bool {
        self.watched_paths() < self.config.watcher_path_limit
    }

    fn watched_paths(&self) -> usize {
        self.entries.watch_accounts().values().map(|account| account.watched).sum()
    }

    fn watch_slot_available(&self, entry: EntryId) -> bool {
        if !self.tree_watch_capacity() {
            return false;
        }
        let domain = self.domain_of(entry);
        let held = self.entries.watch_accounts().get(&domain).map(|account| account.watched).unwrap_or(0);
        held < self.watcher_path_limit_of(entry)
    }

    pub(super) fn hold_watch_path(&mut self, entry: EntryId) {
        let domain = self.domain_of(entry);
        self.entries.set_watch(entry, WatchState::Pending, domain);
    }

    fn watch_target(&self, entry: EntryId) -> Option<WatchScope> {
        let capabilities = self.watcher_of(entry);
        if capabilities.availability != WatcherAvailability::Available {
            return None;
        }
        let scope = match capabilities.scope {
            WatcherScope::PerDirectory => WatchScope::PerDirectory,
            WatcherScope::Recursive | WatcherScope::Unknown => WatchScope::Recursive,
        };
        if scope.is_recursive() && !self.is_watch_anchor(entry) {
            return None;
        }
        let wanted = match self.dir_state(entry).map(|d| d.watch()) {
            Some(WatchState::NotRegistered | WatchState::Capped) => true,
            Some(WatchState::Failed) => {
                self.config.watch_registration_failure_mode == crate::config::WatchRegistrationFailure::RequireWatcher
            }
            Some(WatchState::Pending | WatchState::Registered(_)) | None => false,
        };
        wanted.then_some(scope)
    }

    pub(super) fn watch_decision(&self, entry: EntryId) -> WatchDecision {
        match self.watch_target(entry) {
            None => WatchDecision::NotNeeded,
            Some(scope) if self.watch_slot_available(entry) => WatchDecision::Register(scope),
            Some(_) => WatchDecision::Capped,
        }
    }

    pub(super) fn degrade_domain_watcher(&mut self, entry: EntryId, reason: String) {
        if let Some(domain) = self.domain_of(entry) {
            self.watcher_degraded.insert(domain, reason);
        }
    }

    pub(super) fn recover_domain_watcher(&mut self, entry: EntryId) {
        if let Some(domain) = self.domain_of(entry) {
            self.watcher_degraded.remove(&domain);
        }
    }

    fn domain_watcher_health(&self, domain: StorageDomainId, capabilities: WatcherCapabilities) -> WatcherHealth {
        let backend = watcher_backend(capabilities);
        if !backend.is_present() {
            return WatcherHealth::Absent;
        }
        match self.watcher_degraded.get(&domain) {
            Some(reason) => WatcherHealth::Degraded { backend, reason: reason.clone() },
            None => WatcherHealth::Healthy { backend },
        }
    }

    fn watcher_domain_health(&self) -> BTreeMap<StorageDomainId, WatcherHealth> {
        self.domain_records.iter().map(|(id, record)| (*id, self.domain_watcher_health(*id, record.watcher))).collect()
    }

    pub(super) fn crossing_mode(
        &self,
        entry: EntryId,
        path: &RelativePath,
        child: &DomainCapabilities,
    ) -> DomainCrossing {
        let context = self.parent_context(entry).unwrap_or_else(PolicyContext::unit);
        self.policy.crossing(&context, path, child, self.config.domain_crossing)
    }

    pub(super) fn record_crossing(&mut self, event: CrossingEvent) {
        if self.crossing_events.len() >= CROSSING_HISTORY {
            self.crossing_events.pop_front();
        }
        self.crossing_events.push_back(event);
    }

    fn after_input(&mut self) {
        let now = self.now;
        self.governor.account(now);
        self.declare_stuck_workers();
        self.start_releases();
        if self.is_stopped() {
            let mut wake = None;
            if !self.pending_releases.is_empty() && self.governor.coordination_error().is_none() {
                wake = Some(self.governor.coordination_retry_at(now).unwrap_or(now + self.config.minimum_period));
            }
            if !self.blocking_slots.is_empty()
                && let Some(deadline) = self.governor.next_stuck_deadline()
            {
                wake = Some(wake.map_or(deadline, |at| at.min(deadline)));
            }
            if let Some(at) = wake
                && self.timer_wake != Some(at)
            {
                self.timer_wake = Some(at);
                self.timer_id = self.timer_id.next();
                self.outputs.push(Output::SetTimer { id: self.timer_id, at });
            }
            return;
        }
        self.report_memory();
        self.enforce_command_ceilings();
        self.check_round_end();
        self.check_initial_scan();
        self.maybe_dispatch();
        self.resume_sessions();
        self.start_queued();
        if let Some(error) = self.governor.coordination_error() {
            if self.open_gate == OpenGate::Pending {
                self.open_gate = OpenGate::Failed(Error::Coordination(error.clone()));
            }
            let commands: Vec<_> = self.commands.keys().copied().collect();
            for id in commands {
                self.finish_command(id, Err(Error::Coordination(error.clone())));
            }
            for id in std::mem::take(&mut self.initial_scan.waiters) {
                self.outputs.push(Output::CommandFinished { id, result: Err(Error::Coordination(error.clone())) });
            }
            let queued: Vec<_> = self
                .jobs
                .iter()
                .filter(|(_, job)| matches!(job.phase, JobPhase::Queued | JobPhase::Suspended))
                .map(|(id, _)| *id)
                .collect();
            for id in queued {
                self.cancel_job(id);
            }
        }
        self.publish();
        self.arm_timer();
    }

    fn declare_stuck_workers(&mut self) {
        let now = self.now;
        for grant in self.governor.newly_stuck(now) {
            self.governor.mark_stuck(grant, now);
        }
        self.finish_stuck_jobs();
    }

    fn finish_stuck_jobs(&mut self) {
        // Another scan or tree may have marked our physical call already.
        // Match the complete owner identity before ending a logical job.
        for grant in self.governor.stuck_grants() {
            if grant.id.tree() == Some(self.tree)
                && let Some(job) = grant.id.job()
                && self.jobs.contains_key(&job)
            {
                self.finish_job(job, JobOutcome::Stuck);
            }
            self.release_quarantined(grant.domain);
        }
    }

    pub(super) fn origin_of(&self, entry: Option<EntryId>, barriers: &[CommandId]) -> WorkOrigin {
        let foreground = |id: &CommandId| self.commands.get(id).is_some_and(|cmd| cmd.draws_on_foreground());
        if barriers.iter().any(foreground) {
            return WorkOrigin::Foreground;
        }
        let retained = entry.and_then(|entry| self.entries.retry(entry)).map(|record| record.barriers.clone());
        match retained.iter().flatten().any(foreground) {
            true => WorkOrigin::Foreground,
            false => WorkOrigin::Background,
        }
    }

    pub(super) fn charge_commands(&mut self, barriers: &[CommandId], cost: Duration) {
        if cost.is_zero() {
            return;
        }
        for id in barriers {
            if let Some(command) = self.commands.get_mut(id)
                && command.draws_on_foreground()
            {
                command.admitted += cost;
            }
        }
    }

    fn enforce_command_ceilings(&mut self) {
        let ceiling = self.config.foreground_ceiling_per_command;
        let exhausted: Vec<(CommandId, Duration)> = self
            .commands
            .values()
            .filter_map(|command| {
                if !command.draws_on_foreground() || command.admitted < ceiling {
                    return None;
                }
                // Preparations reduce the available ceiling for other work.
                // Only committed charges can exhaust the command.
                let prepared: Duration = self
                    .jobs
                    .values()
                    .filter(|job| job.phase == JobPhase::Queued && job.barriers.contains(&command.id))
                    .map(|job| self.governor.prepared_cost_of(self.job_grant(job.id)))
                    .sum();
                let admitted = command.admitted.saturating_sub(prepared);
                (admitted >= ceiling).then_some((command.id, admitted))
            })
            .collect();
        for (id, admitted) in exhausted {
            let limited = ResourceLimited {
                limit: ResourceLimit::CommandWorkerTime,
                configured: u64::try_from(ceiling.as_nanos()).unwrap_or(u64::MAX),
                observed: u64::try_from(admitted.as_nanos()).unwrap_or(u64::MAX),
                domain: None,
            };
            self.finish_command(id, Err(Error::ResourceLimited(limited)));
        }
    }

    fn release_quarantined(&mut self, domain: Option<StorageDomainId>) {
        if !self.governor.quarantined(domain) {
            return;
        }
        let waiting: Vec<JobId> = self
            .jobs
            .iter()
            .filter(|(_, job)| job.phase.started().is_none())
            .filter(|(_, job)| job.domain == domain)
            .map(|(id, _)| *id)
            .collect();
        for id in waiting {
            self.cancel_job(id);
        }
    }

    fn host_full_with_queue(&self) -> bool {
        self.governor.in_flight() >= self.maximum_in_flight && !self.queue_order.is_empty()
    }

    /// `throttled` reports whether admission is throttled.
    ///
    /// Host throttling, a full host with queued work and a throttled domain of
    /// this tree all count.
    pub fn throttled(&self) -> bool {
        if self.governor.throttle(self.now).is_some() {
            return true;
        }
        if self.host_full_with_queue() {
            return true;
        }
        self.domain_resource_health().values().any(ResourceHealth::is_throttled)
    }

    fn resource_health(&self, domains: &BTreeMap<StorageDomainId, ResourceHealth>) -> ResourceHealth {
        if let Some((cause, resume)) = self.governor.throttle(self.now) {
            return ResourceHealth::Throttled { cause, resume };
        }
        if self.host_full_with_queue() {
            return ResourceHealth::Throttled { cause: ThrottleCause::Concurrency, resume: None };
        }
        domains.values().copied().find(|health| health.is_throttled()).unwrap_or(ResourceHealth::Nominal)
    }

    fn queued_domains(&self) -> BTreeSet<StorageDomainId> {
        self.queue_order.iter().filter_map(|id| self.jobs.get(id)).filter_map(|job| job.domain).collect()
    }

    fn domain_resource_health(&self) -> BTreeMap<StorageDomainId, ResourceHealth> {
        let mut health: BTreeMap<StorageDomainId, ResourceHealth> =
            self.domain_records.keys().map(|id| (*id, ResourceHealth::Nominal)).collect();
        if health.is_empty() {
            return health;
        }
        let queued = self.queued_domains();
        self.governor.domain_health_map(self.now, &queued, &mut health);
        health
    }

    pub(super) fn next_admissible(&self, resume: Option<MonotonicTime>) -> Option<MonotonicTime> {
        let Some(round) = self.round.as_ref() else {
            return resume;
        };
        let mut seen: Vec<Option<StorageDomainId>> = Vec::new();
        let mut earliest: Option<MonotonicTime> = None;
        for obligation in round.obligations.iter() {
            if obligation.state != ObligationState::Pending {
                continue;
            }
            let domain = self.domain_of(obligation.entry);
            if seen.contains(&domain) {
                continue;
            }
            seen.push(domain);
            let at = self.governor.admissible_at(domain, self.now)?;
            earliest = Some(match earliest {
                Some(previous) => previous.min(at),
                None => at,
            });
        }
        match earliest {
            Some(at) => Some(at),
            None => resume,
        }
    }

    fn next_seq(&mut self) -> Sequence {
        self.seq = self.seq.next();
        self.seq
    }

    fn next_entry_id(&mut self) -> EntryId {
        let id = self.next_entry_id;
        self.next_entry_id = id.next();
        id
    }

    fn next_watch_request(&mut self) -> WatchRequestId {
        let id = self.next_watch_request;
        self.next_watch_request = id.next();
        id
    }

    fn random(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    fn backoff(&mut self, attempts: u32) -> Duration {
        let base = self.config.minimum_period;
        let max = self.config.retry_maximum_delay;
        let exp = attempts.min(20);
        let scaled = base.checked_mul(1u32 << exp).unwrap_or(max).min(max);
        let jitter_max = scaled / 4;
        let ceiling = u64::try_from(jitter_max.as_nanos()).unwrap_or(u64::MAX);
        let jitter_nanos = if jitter_max.is_zero() { 0 } else { self.random() % ceiling.saturating_add(1) };
        (scaled + Duration::from_nanos(jitter_nanos)).min(max)
    }

    fn install_root(&mut self, info: EntryInfo) {
        let incarnation = self.root.incarnation().next();
        let id = self.next_entry_id();
        self.root = RootState::Available { incarnation, id };
        self.initial_scan = InitialScan::new();
        self.root_seed = Some(self.policy.root_context(&info));
        let mut root = new_entry(id, RelativePath::root(), Shape::Directory(LoadState::Loading));
        root.metadata = info.metadata.project(self.config.metadata_fields);
        root.identity = info.identity;
        let mut builder = self.snapshot.builder();
        if let Err(err) = builder.insert(root) {
            self.errors.push(RecoverableError {
                path: RelativePath::root(),
                operation: Operation::Listing,
                error: ErrorCause::SnapshotRejected(err),
            });
        }
        let (snapshot, _) = builder.finish(self.snapshot.version().next());
        self.snapshot = snapshot;
        self.entries.insert(id, EntryState::directory());
        self.initial_scan.record_pending(id, LoadGeneration::new(0));
        let mut reasons = Reasons::control();
        reasons.initial_scan = true;
        self.request(id, RelativePath::root(), ReadNeed::Listing, reasons, Vec::new());
    }

    fn entry_state_mut(&mut self, id: EntryId) -> &mut EntryState {
        self.entries.entry_mut(id)
    }

    fn dir_state(&self, id: EntryId) -> Option<&DirState> {
        self.entries.get(id).and_then(|e| e.dir())
    }

    fn dir_state_mut(&mut self, id: EntryId) -> Option<&mut DirState> {
        self.entries.get_mut(id).and_then(|e| e.dir_mut())
    }

    fn parent_of(&self, id: EntryId) -> Option<EntryId> {
        let version = self.snapshot.version();
        let mut cache = self.parent_cache.borrow_mut();
        if cache.0 != version {
            cache.0 = version;
            cache.1.clear();
        }
        if let Some(parent) = cache.1.get(&id) {
            return *parent;
        }
        let parent = self.snapshot.parent_id(id);
        cache.1.insert(id, parent);
        parent
    }

    fn context_for_children(&self, dir: EntryId) -> Option<PolicyContext> {
        self.dir_state(dir).and_then(|d| d.context.clone())
    }

    fn parent_context(&self, id: EntryId) -> Option<PolicyContext> {
        match self.parent_of(id) {
            Some(parent) => self.context_for_children(parent),
            None => self.root_seed.clone(),
        }
    }

    fn request(&mut self, id: EntryId, path: RelativePath, need: ReadNeed, reasons: Reasons, barriers: Vec<CommandId>) {
        let request = PendingRequest { path, need, reasons, barriers, designate_for_round: None };
        self.request_with(id, request);
    }

    fn request_with(&mut self, id: EntryId, request: PendingRequest) {
        match self.pending.get_mut(&id) {
            Some(existing) => {
                if request.reasons.watcher {
                    self.coalesced_hints += 1;
                }
                existing.merge(request);
            }
            None => {
                self.pending.insert(id, request);
            }
        }
    }

    fn bump_epoch(&mut self, id: EntryId) {
        let state = self.entry_state_mut(id);
        state.change_epoch = state.change_epoch.next();
    }

    fn push_error(&mut self, path: RelativePath, operation: Operation, error: impl Into<ErrorCause>) {
        self.errors.push(RecoverableError { path, operation, error: error.into() });
    }

    fn degraded_paths(&self) -> BTreeSet<RelativePath> {
        self.entries.degraded_ids().filter_map(|id| self.snapshot.get_by_id(id).map(|e| e.path.clone())).collect()
    }

    pub(super) fn degraded_path_causes(&self) -> BTreeMap<RelativePath, DegradedCause> {
        self.entries
            .degraded_causes()
            .filter_map(|(id, cause)| self.snapshot.get_by_id(id).map(|e| (e.path.clone(), cause)))
            .collect()
    }

    fn metadata_degraded_paths(&self) -> BTreeSet<RelativePath> {
        self.entries
            .metadata_degraded_ids()
            .filter_map(|id| self.snapshot.get_by_id(id).map(|e| e.path.clone()))
            .collect()
    }

    fn initial_scan_state(&self) -> InitialScanState {
        match self.root {
            RootState::Unavailable { .. } => InitialScanState::Unavailable,
            RootState::Available { incarnation, .. } => {
                let scan = &self.initial_scan;
                if scan.any_unsatisfied() {
                    InitialScanState::Degraded { incarnation, failed: scan.failed_paths() }
                } else if scan.foreground_done && !scan.any_pending() && !self.traversal_in_progress() {
                    InitialScanState::Complete { incarnation }
                } else {
                    InitialScanState::Running { incarnation }
                }
            }
        }
    }

    fn traversal_in_progress(&self) -> bool {
        self.pending.values().any(|p| p.reasons.initial_scan) || self.jobs.values().any(|j| j.reasons.initial_scan)
    }

    fn compute_health(&self) -> Health {
        let resource_domains = self.domain_resource_health();
        let root = match self.root {
            RootState::Available { incarnation, .. } => RootAvailability::Available { incarnation },
            RootState::Unavailable { last } => RootAvailability::Unavailable { last },
        };
        let coverage_pending =
            self.min_recon > ReconciliationGeneration::new(0) && self.entries.coverage_pending(self.min_recon);
        Health {
            initial_scan: self.initial_scan_state(),
            root,
            watcher: self.watcher_health.clone(),
            watcher_domains: self.watcher_domain_health(),
            reconciliation: ReconciliationHealth {
                last_round: self.last_round_result.clone(),
                degraded_paths: self.degraded_paths(),
                degraded_path_causes: self.degraded_path_causes(),
                metadata_degraded_paths: self.metadata_degraded_paths(),
                coverage_pending,
            },
            resource: self.resource_health(&resource_domains),
            resource_domains,
            shutdown: self.shutdown.clone(),
        }
    }

    fn publish(&mut self) {
        let version = self.snapshot.version();
        if version != self.published_version {
            return;
        }
        let health = self.compute_health();
        let health_changed = self.last_published_health.as_ref() != Some(&health);
        if health_changed || !self.errors.is_empty() {
            let errors = std::mem::take(&mut self.errors);
            self.last_published_health = Some(health.clone());
            self.outputs.push(Output::Publish(Box::new(UpdateEvent::Health { version, health, errors })));
        }
    }

    fn publish_delta(
        &mut self,
        previous: SnapshotVersion,
        changes: Vec<crate::update::PathChange>,
        crossings: Vec<CrossingEvent>,
    ) {
        let health = self.compute_health();
        let errors = std::mem::take(&mut self.errors);
        self.last_published_health = Some(health.clone());
        self.published_version = self.snapshot.version();
        self.outputs.push(Output::Publish(Box::new(UpdateEvent::Delta(Update {
            previous_version: previous,
            new_version: self.snapshot.version(),
            snapshot: self.snapshot.clone(),
            changes,
            crossings,
            health,
            errors,
        }))));
    }

    fn terminate(&mut self, error: FsError) {
        let message = error.to_string();
        self.shutdown = ShutdownState::Terminated { error: message };
        let ids: Vec<CommandId> = self.commands.keys().copied().collect();
        for id in ids {
            self.finish_command(id, Err(Error::TreeTerminated));
        }
        let waiters = std::mem::take(&mut self.initial_scan.waiters);
        for id in waiters {
            self.outputs.push(Output::CommandFinished { id, result: Err(Error::TreeTerminated) });
        }
        self.cancel_all_jobs();
        self.unwatch_all();
        let health = self.compute_health();
        self.outputs.push(Output::Publish(Box::new(UpdateEvent::Terminal { health })));
        self.outputs.push(Output::Stopped(TerminalOutcome::Terminated));
    }

    fn cancel_all_jobs(&mut self) {
        let ids: Vec<JobId> = self.jobs.keys().copied().collect();
        for id in ids {
            if let Some(job) = self.jobs.remove(&id) {
                job.cancel.cancel();
                if job.phase.started().is_some() || job.session_open {
                    self.outputs.push(Output::CancelJob(id));
                }
                if job.phase.started().is_none() {
                    self.governor.release(self.job_grant(id), self.now);
                }
                if let Some(entry) = job.entry() {
                    self.active_by_entry.remove(&entry);
                }
            }
        }
        self.probe_job = None;
        self.queue_order.clear();
        self.batch = None;
        for held in self.registrations.values_mut() {
            held.abandon();
        }
    }

    pub(super) fn emit_unwatch(&mut self, watch: WatchId, path: RelativePath, domain: Option<StorageDomainId>) {
        self.pending_releases.push_back(PendingRelease { watch, path, domain });
    }

    pub(super) fn release_registered(&mut self, watch: WatchId, domain: Option<StorageDomainId>) {
        if let Some(path) = self.watches.remove(&watch) {
            self.emit_unwatch(watch, path, domain);
        }
    }

    fn start_releases(&mut self) {
        let queued: Vec<PendingRelease> = self.pending_releases.drain(..).collect();
        let mut deferred: VecDeque<PendingRelease> = VecDeque::new();
        for pending in queued {
            let blocked = deferred.iter().any(|held| held.domain == pending.domain);
            if blocked || !self.start_release(&pending) {
                deferred.push_back(pending);
            }
        }
        self.pending_releases = deferred;
        if self.is_stopped() && self.governor.coordination_error().is_some() {
            // A release attempt may discover a permanent authority failure.
            // That failure forbids the dispatch of any I/O, cleanup included.
            // Undispatched watch IDs would retain the terminal actor, and this
            // branch drops them. Dispatched workers keep their grants and
            // drain before the actor exits.
            self.pending_releases.clear();
        }
    }

    fn start_release(&mut self, pending: &PendingRelease) -> bool {
        let domain = pending.domain;
        if self.governor.may_start(domain).is_err() {
            return false;
        }
        let release = self.next_watch_release;
        let now = self.now;
        let reservation = Reservation {
            id: self.release_grant(release),
            path: pending.path.clone(),
            reads: 1,
            registrations: 0,
            operations: 0,
            ceiling: None,
            lease: 0,
            domain,
            origin: WorkOrigin::Background,
            listing: false,
        };
        if self.governor.try_admit(reservation, now).is_err() {
            return false;
        }
        if self.governor.try_start(self.release_grant(release), now).is_err() {
            self.governor.release(self.release_grant(release), now);
            return false;
        }
        self.next_watch_release = release.next();
        self.blocking_slots.insert(
            SlotOwner::WatchRelease(release),
            Occupancy { path: pending.path.clone(), operation: JobOperation::WatchRelease, started: now },
        );
        self.outputs.push(Output::Unwatch { release, watch: pending.watch });
        true
    }

    fn unwatch_all(&mut self) {
        let watched: Vec<crate::ids::EntryId> = self.entries.watched_ids().collect();
        for id in watched {
            if let Some(WatchState::Registered(watch)) = self.dir_state(id).map(|d| d.watch()) {
                let domain = self.domain_of(id);
                self.release_registered(watch, domain);
            }
        }
        for (watch, path) in std::mem::take(&mut self.watches) {
            self.emit_unwatch(watch, path, None);
        }
        self.entries.reset_watches();
    }

    fn arm_timer(&mut self) {
        let mut wake: Option<MonotonicTime> = None;
        let mut consider = |t: MonotonicTime| {
            wake = Some(match wake {
                Some(w) => w.min(t),
                None => t,
            });
        };
        let (resume, background_resume, stuck_deadline) = self.governor.timer_hints(self.now);
        let waiting_for_work = self.baseline_due
            || !self.pending.is_empty()
            || !self.pending_enrichment.is_empty()
            || !self.pending_domain.is_empty()
            || !self.pending_releases.is_empty()
            || self.jobs.values().any(|job| matches!(job.phase, JobPhase::Queued | JobPhase::Suspended));
        if waiting_for_work && let Some(at) = self.governor.coordination_retry_at(self.now) {
            consider(at);
        }
        if !self.baseline_due && self.batch.is_none() {
            let due = match self.next_admissible(background_resume) {
                Some(at) => self.periodic_due.max(at),
                None => self.periodic_due.min(self.now + self.config.maximum_period),
            };
            consider(due);
        }
        if self.batch.is_none()
            && let Some(at) = resume
        {
            consider(at);
        }
        if self.jobs.values().any(|j| j.phase == JobPhase::Suspended)
            && let Some(at) = resume
        {
            consider(at);
        }
        if let Some(at) = stuck_deadline {
            consider(at);
        }
        if let Some(probe) = &self.root_probe
            && let Some(t) = probe.not_before
        {
            consider(t);
        }
        if let Some(t) = self.entries.earliest_retry() {
            consider(t);
        }
        if let Some(t) = self.pending_enrichment.values().filter_map(|r| r.due).min() {
            consider(t);
        }
        if let Some(t) = self.pending_domain.values().filter_map(|r| r.due).min() {
            consider(t);
        }
        if let Some(t) = self.watcher_restart_due {
            consider(t);
        }
        if !self.pending_releases.is_empty() {
            consider(self.now + self.config.minimum_period);
        }
        if wake != self.timer_wake {
            self.timer_wake = wake;
            if let Some(at) = wake {
                self.timer_id = self.timer_id.next();
                self.outputs.push(Output::SetTimer { id: self.timer_id, at });
            }
        }
    }

    fn on_timer(&mut self, id: TimerId) {
        if id != self.timer_id {
            return;
        }
        self.timer_wake = None;
        if self.now >= self.periodic_due {
            self.baseline_due = true;
        }
        if let Some(due) = self.watcher_restart_due
            && self.now >= due
        {
            self.watcher_restart_due = None;
            self.restart_watcher();
        }
    }
}

fn reported_domain(result: &JobResult) -> Option<ProbeResult> {
    match result {
        JobResult::Listing(SessionStep {
            state: crate::fs::SessionState::Finished(crate::fs::SessionOutcome::Complete(listing)),
            ..
        }) => Some((*listing.domain).clone()),
        JobResult::Domain(Ok(probe)) => Some(probe.clone()),
        JobResult::Domain(Err(_)) | JobResult::Listing(_) | JobResult::Metadata(_) | JobResult::Enrichment(_) => None,
    }
}

fn obligation_counts(round: &Round) -> ObligationCounts {
    let mut counts = ObligationCounts { total: round.obligations.len(), ..ObligationCounts::default() };
    for obligation in &round.obligations {
        match obligation.state {
            ObligationState::Accepted => counts.accepted += 1,
            ObligationState::Unsatisfied => counts.unsatisfied += 1,
            ObligationState::Removed => counts.removed += 1,
            ObligationState::Pending | ObligationState::Designated(_) => {}
        }
    }
    counts
}
