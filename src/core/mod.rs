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

pub use governor::{
    AdmissionDecision, DomainAccount, DomainView, GovernorView, Grant, GrantId, HostGovernor, HostGovernorError,
    LatencySummary, Reservation, host_governor,
};
use types::*;
pub use types::{Class, MonotonicTime, WorkOrigin};

use crate::config::Config;
use crate::domain::{
    DomainCapabilities, DomainCrossing, DomainIdentity, ProbeResult, StorageDomainId, WatcherAvailability,
    WatcherCapabilities, WatcherScope,
};
use crate::entry::{LoadState, MetadataFields, Shape};
use crate::error::Error;
use crate::fs::{
    CancellationToken, Ceilings, Enrichment, EntryInfo, FsCapabilities, FsError, Lease, SessionCost, SessionStep,
    WatcherEvent, WatcherKind,
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObligationCounts {
    pub total: usize,
    pub accepted: usize,
    pub unsatisfied: usize,
    pub removed: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectorySize {
    pub path: RelativePath,
    pub children: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossingEvent {
    pub path: RelativePath,
    pub parent: Option<StorageDomainId>,
    pub child: StorageDomainId,
    pub mode: DomainCrossing,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DomainStat {
    pub id: StorageDomainId,
    pub identity: DomainIdentity,
    pub capabilities: DomainCapabilities,
    pub watcher: WatcherCapabilities,
    pub watcher_health: WatcherHealth,
    pub paths_watched: usize,
    pub paths_unwatched_by_cap: usize,
    pub granted: Duration,
    pub charged: Duration,
    pub capacity: Duration,
    pub level: Duration,
    pub debt: Duration,
    pub window: usize,
    pub ceiling: usize,
    pub in_flight: usize,
    pub stuck: usize,
    pub estimate: Duration,
    pub foreground_capacity: Duration,
    pub foreground_level: Duration,
    pub foreground_debt: Duration,
    pub bytes_estimate: u64,
    pub latency: LatencySummary,
    pub throttled_jobs: u64,
    pub throttled_duration: Duration,
    pub effective_duty: f64,
    pub resource: ResourceHealth,
    pub listings: u64,
    pub metadata_operations: u64,
    pub entries_enumerated: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DomainOps {
    pub listings: u64,
    pub metadata_operations: u64,
    pub entries_enumerated: u64,
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

#[derive(Clone, Debug)]
pub enum Command {
    Refresh(Vec<RelativePath>),
    Load(RelativePath),
    Unload(RelativePath),
    InvalidatePolicy(Vec<RelativePath>),
    SetPriority(Vec<RelativePath>),
    InitialScanComplete,
    Shutdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobOperation {
    Listing,
    Metadata,
    DomainResolution,
    Enrichment { fields: MetadataFields },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListingWork {
    pub lease: Lease,
    pub ceilings: Ceilings,
    pub cancel: CancellationToken,
    pub resume: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Work {
    Listing(ListingWork),
    Metadata,
    ResolveDomain { parent: Option<Box<ProbeResult>> },
    Enrichment { fields: MetadataFields },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobSpec {
    pub id: JobId,
    pub path: RelativePath,
    pub work: Work,
}

impl JobSpec {
    pub fn operation(&self) -> JobOperation {
        match &self.work {
            Work::Listing(_) => JobOperation::Listing,
            Work::Metadata => JobOperation::Metadata,
            Work::ResolveDomain { .. } => JobOperation::DomainResolution,
            Work::Enrichment { fields } => JobOperation::Enrichment { fields: *fields },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobResult {
    Listing(SessionStep),
    Metadata(Result<EntryInfo, FsError>),
    Domain(Result<ProbeResult, FsError>),
    Enrichment(Result<Enrichment, FsError>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WorkerLoss {
    Job(JobId),
    WatchRegistration(WatchRequestId),
}

#[derive(Clone, Debug)]
pub enum Input {
    Command { id: CommandId, command: Command },
    Watcher(WatcherEvent),
    JobCompleted { job: JobId, result: JobResult },
    WatchRegistered { request: WatchRequestId, result: Result<WatchId, FsError> },
    WorkerLost(WorkerLoss),
    Timer(TimerId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalOutcome {
    ShutDown,
    Terminated,
}

#[derive(Clone, Debug)]
pub enum Output {
    StartJob(JobSpec),
    CancelJob(JobId),
    RegisterWatch { request: WatchRequestId, path: RelativePath, recursive: bool },
    Unwatch(WatchId),
    Publish(Box<UpdateEvent>),
    CommandFinished { id: CommandId, result: Result<(), Error> },
    SetTimer { id: TimerId, at: MonotonicTime },
    Stopped(TerminalOutcome),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockingSlot {
    pub job: JobId,
    pub path: RelativePath,
    pub operation: JobOperation,
    pub started: MonotonicTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchView {
    pub periodic: bool,
    pub members: BTreeSet<JobId>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Stats {
    pub version: SnapshotVersion,
    pub initial_scan: InitialScanState,
    pub reconciliation_generation: ReconciliationGeneration,
    pub minimum_coverage_generation: ReconciliationGeneration,
    pub last_round: Option<(MonotonicTime, Duration)>,
    pub last_successful_round: Option<(MonotonicTime, Duration)>,
    pub baseline_cursor: (usize, usize),
    pub obligations: ObligationCounts,
    pub priority_cursor: (usize, usize),
    pub loaded_directories: usize,
    pub represented_entries: usize,
    pub snapshot_bytes: u64,
    pub accounted_memory: u64,
    pub queued_jobs: usize,
    pub in_flight_jobs: usize,
    pub blocking_slots_held: usize,
    pub blocking_slots: Vec<BlockingSlot>,
    pub stuck_workers: Vec<BlockingSlot>,
    pub governor: GovernorView,
    pub grants: Vec<Grant>,
    pub resource: ResourceHealth,
    pub pending_requests: usize,
    pub watcher: WatcherKind,
    pub watcher_path_limit: usize,
    pub path_folds: u64,
    pub paths_watched: usize,
    pub paths_unwatched_by_cap: usize,
    pub dropped_hints: u64,
    pub coalesced_hints: u64,
    pub listings: u64,
    pub listing_failures: u64,
    pub stale_results: u64,
    pub lost_workers: u64,
    pub last_listing_duration: Option<Duration>,
    pub last_listing_children: Option<usize>,
    pub largest_directories: Vec<DirectorySize>,
    pub degraded_paths: BTreeSet<RelativePath>,
    pub metadata_degraded_paths: BTreeSet<RelativePath>,
    pub metadata_operations: u64,
    pub listing_operations: u64,
    pub entries_enumerated: u64,
    pub listing_bytes: u64,
    pub in_flight_listing_bytes: u64,
    pub reported_blocking: Duration,
    pub kind_resolutions: u64,
    pub identity_reads: u64,
    pub unresolved_listings: u64,
    pub suspended_sessions: usize,
    pub lease_grants: u64,
    pub cancelled_sessions: u64,
    pub resource_limits: Vec<ResourceLimitEvent>,
    pub enrichments: u64,
    pub enrichment_failures: u64,
    pub pending_enrichments: usize,
    pub domains: Vec<DomainStat>,
    pub crossings: Vec<CrossingEvent>,
    pub domain_resolutions: u64,
    pub pending_domain_resolutions: usize,
}

pub struct Coordinator {
    config: Config,
    governor: HostGovernor,
    tree: u64,
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
    unknown_domain: Option<StorageDomainId>,
    crossing_events: VecDeque<CrossingEvent>,
    domain_ops: BTreeMap<StorageDomainId, DomainOps>,
    domain_resolutions: u64,
    root_probe: Option<RootProbe>,
    probe_attempts: u32,
    jobs: IdMap<JobId, ActiveJob>,
    blocking_slots: BTreeMap<JobId, Occupancy>,
    active_by_entry: IdMap<EntryId, JobId>,
    probe_job: Option<JobId>,
    registrations: IdMap<WatchRequestId, RegistrationTarget>,
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
    watches: Vec<WatchId>,
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
    largest_directories: Vec<DirectorySize>,
}

impl Drop for Coordinator {
    fn drop(&mut self) {
        let now = self.now;
        for id in self.jobs.keys() {
            self.governor.release(GrantId::Job(*id), now);
        }
        for request in self.registrations.keys() {
            self.governor.release(GrantId::WatchRegistration(*request), now);
        }
        self.governor.forget_tree(self.tree);
    }
}

impl Coordinator {
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
            unknown_domain: None,
            crossing_events: VecDeque::new(),
            domain_ops: BTreeMap::new(),
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
            watches: Vec::new(),
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
            largest_directories: Vec::new(),
        };
        coordinator.install_root(root_info);
        if !coordinator.caps.watcher.is_present() {
            coordinator.open_gate = OpenGate::Ready;
        }
        coordinator.after_input();
        Ok(coordinator)
    }

    pub fn open_gate(&self) -> Option<Result<(), Error>> {
        match &self.open_gate {
            OpenGate::Pending => None,
            OpenGate::Ready => Some(Ok(())),
            OpenGate::Failed(err) => Some(Err(err.clone())),
        }
    }

    pub fn take_outputs(&mut self) -> Vec<Output> {
        std::mem::take(&mut self.outputs)
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub fn health(&self) -> Health {
        self.compute_health()
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn job_class(&self, id: JobId) -> Option<Class> {
        self.jobs.get(&id).map(|job| job.reasons.class())
    }

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

    pub fn grants(&self) -> Vec<Grant> {
        self.governor.grants()
    }

    pub fn new_grants_into(&self, into: &mut Vec<Grant>, seen: &dyn Fn(GrantId, u32) -> bool) {
        self.governor.new_grants_into(into, seen)
    }

    pub(super) fn record_directory_size(&mut self, path: &RelativePath, children: usize) {
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

    pub fn governor(&self) -> GovernorView {
        self.governor.view(self.now)
    }

    pub fn last_round(&self) -> Option<(MonotonicTime, Duration)> {
        self.last_round
    }

    pub fn open_batch(&self) -> Option<BatchView> {
        self.batch
            .as_ref()
            .map(|batch| BatchView { periodic: batch.periodic, members: batch.members.iter().copied().collect() })
    }

    pub fn is_stopped(&self) -> bool {
        matches!(self.shutdown, ShutdownState::Stopped | ShutdownState::Terminated { .. })
    }

    pub fn observe(&mut self, now: MonotonicTime) -> Vec<Output> {
        self.now = self.now.max(now);
        if self.is_stopped() {
            return self.take_outputs();
        }
        self.after_input();
        self.take_outputs()
    }

    pub fn handle(&mut self, input: Input, now: MonotonicTime) -> Vec<Output> {
        self.now = self.now.max(now);
        match &input {
            Input::JobCompleted { job, result } => {
                self.blocking_slots.remove(job);
                let now = self.now;
                if let Some(probe) = reported_domain(result) {
                    let binding = self.bind_domain(&probe);
                    self.governor.attribute(GrantId::Job(*job), binding.id, now);
                }
                if let JobResult::Listing(step) = result
                    && let Some(blocking) = step.cost.blocking
                {
                    self.governor.report(GrantId::Job(*job), blocking, now);
                }
                let barriers = self.jobs.get(job).map(|job| job.barriers.clone()).unwrap_or_default();
                if !barriers.is_empty() {
                    let overshoot = self.governor.overshoot_of(GrantId::Job(*job));
                    self.charge_commands(&barriers, overshoot);
                }
                self.governor.release(GrantId::Job(*job), now);
            }
            Input::WorkerLost(WorkerLoss::Job(job)) => {
                self.blocking_slots.remove(job);
                let now = self.now;
                self.governor.release(GrantId::Job(*job), now);
            }
            Input::WatchRegistered { request, .. } | Input::WorkerLost(WorkerLoss::WatchRegistration(request)) => {
                let now = self.now;
                self.governor.release(GrantId::WatchRegistration(*request), now);
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
                Input::WatchRegistered { result, .. } => self.release_watch(result.map_err(ErrorCause::Fs)),
                Input::Watcher(_) | Input::JobCompleted { .. } | Input::WorkerLost(_) | Input::Timer(_) => {}
            }
            return self.take_outputs();
        }
        match input {
            Input::Command { id, command } => self.on_command(id, command),
            Input::Watcher(event) => self.on_watcher(event),
            Input::JobCompleted { job, result } => self.on_job_completed(job, result),
            Input::WatchRegistered { request, result } => {
                self.on_watch_registered(request, result.map_err(ErrorCause::Fs))
            }
            Input::WorkerLost(loss) => self.on_worker_lost(loss),
            Input::Timer(id) => self.on_timer(id),
        }
        self.after_input();
        self.take_outputs()
    }

    pub fn stats(&self) -> Stats {
        let queued = self
            .jobs
            .values()
            .filter(|j| matches!(j.phase, JobPhase::Queued | JobPhase::Registering(_) | JobPhase::Suspended))
            .count();
        let in_flight = self.jobs.values().filter(|j| j.phase.started().is_some()).count();
        let blocking_slots: Vec<BlockingSlot> = self
            .blocking_slots
            .iter()
            .map(|(job, held)| BlockingSlot {
                job: *job,
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
                    let job = grant.id.job()?;
                    let held = self.blocking_slots.get(&job)?;
                    Some(BlockingSlot {
                        job,
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
            largest_directories: self.largest_directories.clone(),
            degraded_paths: self.degraded_paths(),
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
        self.domain_records
            .iter()
            .map(|(id, record)| {
                let watch = watches.get(&Some(*id)).copied().unwrap_or_default();
                let ops = self.domain_ops.get(id).copied().unwrap_or_default();
                let account = accounts.get(id);
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
                    throttled_jobs: account.map(|view| view.throttled_jobs).unwrap_or_default(),
                    throttled_duration: account.map(|view| view.throttled_duration).unwrap_or_default(),
                    effective_duty: account.map(|view| view.effective_duty()).unwrap_or_default(),
                    resource: resource.get(id).copied().unwrap_or(ResourceHealth::Nominal),
                    listings: ops.listings,
                    metadata_operations: ops.metadata_operations,
                    entries_enumerated: ops.entries_enumerated,
                }
            })
            .collect()
    }

    pub(super) fn bind_domain(&mut self, probe: &ProbeResult) -> DomainBinding {
        let (id, identity, capabilities) = match probe.identity.key() {
            Some(key) => (StorageDomainId::of(key), probe.identity.clone(), probe.capabilities.clone()),
            None => {
                let id = match self.unknown_domain {
                    Some(id) => id,
                    None => {
                        let id = StorageDomainId::fresh();
                        self.unknown_domain = Some(id);
                        id
                    }
                };
                (id, DomainIdentity::Unknown, DomainCapabilities::default())
            }
        };
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
        if self.is_stopped() {
            return;
        }
        let now = self.now;
        self.report_memory();
        self.governor.account(now);
        self.declare_stuck_workers();
        self.enforce_command_ceilings();
        self.check_round_end();
        self.check_initial_scan();
        self.maybe_dispatch();
        self.resume_sessions();
        self.start_queued();
        self.publish();
        self.arm_timer();
    }

    fn declare_stuck_workers(&mut self) {
        let now = self.now;
        for grant in self.governor.newly_stuck(now) {
            self.governor.mark_stuck(grant, now);
            let Some(job) = grant.job() else {
                continue;
            };
            let domain = self.jobs.get(&job).and_then(|job| job.domain);
            if self.jobs.contains_key(&job) {
                self.finish_job(job, JobOutcome::Stuck);
            }
            self.release_quarantined(domain);
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
            .filter(|command| command.draws_on_foreground() && command.admitted >= ceiling)
            .map(|command| (command.id, command.admitted))
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

    pub fn throttled(&self) -> bool {
        if self.governor.throttle(self.now).is_some() {
            return true;
        }
        if self.blocking_slots.len() >= self.maximum_in_flight && !self.queue_order.is_empty() {
            return true;
        }
        self.domain_resource_health().values().any(ResourceHealth::is_throttled)
    }

    fn resource_health(&self, domains: &BTreeMap<StorageDomainId, ResourceHealth>) -> ResourceHealth {
        if let Some((cause, resume)) = self.governor.throttle(self.now) {
            return ResourceHealth::Throttled { cause, resume };
        }
        if self.blocking_slots.len() >= self.maximum_in_flight && !self.queue_order.is_empty() {
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
                if let Some(entry) = job.entry() {
                    self.active_by_entry.remove(&entry);
                }
            }
        }
        self.probe_job = None;
        self.queue_order.clear();
        self.batch = None;
        for target in self.registrations.values_mut() {
            *target = RegistrationTarget::Abandoned;
        }
    }

    pub(super) fn emit_unwatch(&mut self, watch: WatchId, domain: Option<StorageDomainId>) {
        let now = self.now;
        self.governor.charge_release(domain, now);
        self.outputs.push(Output::Unwatch(watch));
    }

    fn unwatch_all(&mut self) {
        for id in std::mem::take(&mut self.watches) {
            self.emit_unwatch(id, None);
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
        let (resume, stuck_deadline) = self.governor.timer_hints(self.now);
        if !self.baseline_due && self.batch.is_none() {
            let due = match self.next_admissible(resume) {
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
