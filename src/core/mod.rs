mod apply;
mod commands;
mod governor;
mod jobs;
mod scheduler;
mod types;
mod watcher;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use governor::Governor;
pub use governor::{AdmissionDecision, DomainAccount, GovernorView, Grant, GrantId};
use types::*;
pub use types::{Class, MonotonicTime};

use crate::config::Config;
use crate::domain::{DomainCapabilities, DomainCrossing, DomainIdentity, ProbeResult, StorageDomainId};
use crate::entry::{LoadState, MetadataFields, Shape};
use crate::error::Error;
use crate::fs::{
    CancellationToken, Enrichment, EntryInfo, FsCapabilities, FsError, Lease, SessionCost, SessionStep, WatcherEvent,
    WatcherKind,
};
use crate::ids::*;
use crate::path::RelativePath;
use crate::policy::{PolicyContext, ScanPolicy};
use crate::snapshot::{Snapshot, new_entry};
use crate::update::{
    ErrorCause, Health, InitialScanState, Operation, ReconciliationHealth, RecoverableError, ResourceHealth,
    ResourceLimitEvent, RootAvailability, ShutdownState, ThrottleCause, Update, UpdateEvent, WatcherHealth,
};

const RESOURCE_LIMIT_HISTORY: usize = 64;
const CROSSING_HISTORY: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossingEvent {
    pub path: RelativePath,
    pub parent: Option<StorageDomainId>,
    pub child: StorageDomainId,
    pub mode: DomainCrossing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainStat {
    pub id: StorageDomainId,
    pub identity: DomainIdentity,
    pub capabilities: DomainCapabilities,
    pub granted: Duration,
    pub charged: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DomainRecord {
    identity: DomainIdentity,
    capabilities: DomainCapabilities,
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
    pub ceiling: usize,
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
    pub baseline_cursor: (usize, usize),
    pub priority_cursor: (usize, usize),
    pub loaded_directories: usize,
    pub represented_entries: usize,
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
    pub dropped_hints: u64,
    pub coalesced_hints: u64,
    pub listings: u64,
    pub listing_failures: u64,
    pub stale_results: u64,
    pub lost_workers: u64,
    pub last_listing_duration: Option<Duration>,
    pub last_listing_children: Option<usize>,
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
    governor: Governor,
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
    published_version: SnapshotVersion,
    root: RootState,
    root_seed: Option<PolicyContext>,
    initial_scan: InitialScan,
    entries: EntryStates,
    pending: HashMap<EntryId, PendingRequest>,
    pending_enrichment: HashMap<EntryId, EnrichmentRequest>,
    pending_domain: HashMap<EntryId, DomainRequest>,
    domain_records: BTreeMap<StorageDomainId, DomainRecord>,
    unknown_domain: Option<StorageDomainId>,
    crossing_events: VecDeque<CrossingEvent>,
    domain_resolutions: u64,
    root_probe: Option<RootProbe>,
    probe_attempts: u32,
    jobs: HashMap<JobId, ActiveJob>,
    blocking_slots: BTreeMap<JobId, Occupancy>,
    active_by_entry: HashMap<EntryId, JobId>,
    probe_job: Option<JobId>,
    registrations: HashMap<WatchRequestId, RegistrationTarget>,
    queue_order: VecDeque<JobId>,
    batch: Option<Batch>,
    round: Option<Round>,
    last_round: Option<(MonotonicTime, Duration)>,
    last_round_result: Option<crate::update::RoundResult>,
    commands: HashMap<CommandId, PendingCommand>,
    priority: PrioritySet,
    policy_fence: PolicyFence,
    class_rotation: usize,
    dispatch_rotation: usize,
    watcher_health: WatcherHealth,
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
    session_bytes: HashMap<JobId, u64>,
    kind_resolutions: u64,
    identity_reads: u64,
    unresolved_listings: u64,
    cancelled_sessions: u64,
    resource_limits: VecDeque<ResourceLimitEvent>,
    enrichments: u64,
    enrichment_failures: u64,
    last_listing_duration: Option<Duration>,
    last_listing_children: Option<usize>,
}

impl Coordinator {
    pub fn new(
        config: Config,
        policy: Arc<dyn ScanPolicy>,
        caps: FsCapabilities,
        root_info: EntryInfo,
        now: MonotonicTime,
    ) -> Result<Coordinator, Error> {
        config.validate().map_err(Error::InvalidConfig)?;
        if root_info.kind != crate::entry::EntryKind::Directory {
            return Err(Error::NotDirectory);
        }
        let seed = config.jitter_seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let snapshot = Snapshot::empty(SnapshotVersion::new(0), caps.case);
        let governor = Governor::new(&config, now);
        let mut coordinator = Coordinator {
            config,
            governor,
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
            published_version: SnapshotVersion::new(0),
            root: RootState::Unavailable { last: RootIncarnation::new(0) },
            root_seed: None,
            initial_scan: InitialScan::new(),
            entries: EntryStates::default(),
            pending: HashMap::new(),
            pending_enrichment: HashMap::new(),
            pending_domain: HashMap::new(),
            domain_records: BTreeMap::new(),
            unknown_domain: None,
            crossing_events: VecDeque::new(),
            domain_resolutions: 0,
            root_probe: None,
            probe_attempts: 0,
            jobs: HashMap::new(),
            blocking_slots: BTreeMap::new(),
            active_by_entry: HashMap::new(),
            probe_job: None,
            registrations: HashMap::new(),
            queue_order: VecDeque::new(),
            batch: None,
            round: None,
            last_round: None,
            last_round_result: None,
            commands: HashMap::new(),
            priority: PrioritySet::default(),
            policy_fence: PolicyFence::new(0),
            class_rotation: 0,
            dispatch_rotation: 0,
            watcher_health: if caps.watcher.is_present() {
                WatcherHealth::Healthy { backend: caps.watcher }
            } else {
                WatcherHealth::Absent
            },
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
            session_bytes: HashMap::new(),
            kind_resolutions: 0,
            identity_reads: 0,
            unresolved_listings: 0,
            cancelled_sessions: 0,
            resource_limits: VecDeque::new(),
            enrichments: 0,
            enrichment_failures: 0,
            last_listing_duration: None,
            last_listing_children: None,
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
        self.session_bytes.insert(job, cost.bytes);
    }

    pub(super) fn release_session_bytes(&mut self, job: JobId) {
        if let Some(bytes) = self.session_bytes.remove(&job) {
            self.listing_bytes += bytes;
        }
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
        self.governor.grants().cloned().collect()
    }

    pub fn governor(&self) -> GovernorView {
        self.governor.view(self.now)
    }

    pub fn open_batch(&self) -> Option<BatchView> {
        self.batch
            .as_ref()
            .map(|batch| BatchView { periodic: batch.periodic, members: batch.members.iter().copied().collect() })
    }

    pub fn is_stopped(&self) -> bool {
        matches!(self.shutdown, ShutdownState::Stopped | ShutdownState::Terminated { .. })
    }

    pub fn next_wake(&self) -> Option<MonotonicTime> {
        self.timer_wake
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
                    self.governor.attribute(GrantId::Job(*job), binding.id);
                }
                if let JobResult::Listing(step) = result
                    && let Some(blocking) = step.cost.blocking
                {
                    self.governor.report(GrantId::Job(*job), blocking, now);
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
        let loaded = self.snapshot.loaded_directories().count();
        let priority_len = self.priority.keys.len();
        Stats {
            version: self.snapshot.version(),
            initial_scan: self.initial_scan_state(),
            reconciliation_generation: self.round.as_ref().map(|r| r.generation).unwrap_or(self.recon_seq),
            minimum_coverage_generation: self.min_recon,
            last_round: self.last_round,
            baseline_cursor: self.round.as_ref().map(|r| (r.cursor, r.obligations.len())).unwrap_or((0, 0)),
            priority_cursor: (self.priority.cursor, priority_len),
            loaded_directories: loaded,
            represented_entries: self.snapshot.len(),
            queued_jobs: queued,
            in_flight_jobs: in_flight,
            stuck_workers: self
                .governor
                .stuck_grants()
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
            governor: self.governor.view(self.now),
            grants: self.governor.grants().cloned().collect(),
            resource: self.resource_health(),
            blocking_slots_held: blocking_slots.len(),
            blocking_slots,
            pending_requests: self.pending.len() + usize::from(self.root_probe.is_some()),
            watcher: self.caps.watcher,
            dropped_hints: self.dropped_hints,
            coalesced_hints: self.coalesced_hints,
            listings: self.listings,
            listing_failures: self.listing_failures,
            stale_results: self.stale_results,
            lost_workers: self.lost_workers,
            last_listing_duration: self.last_listing_duration,
            last_listing_children: self.last_listing_children,
            degraded_paths: self.degraded_paths(),
            metadata_degraded_paths: self.metadata_degraded_paths(),
            metadata_operations: self.metadata_operations,
            listing_operations: self.listing_operations,
            entries_enumerated: self.entries_enumerated,
            listing_bytes: self.listing_bytes,
            in_flight_listing_bytes: self.session_bytes.values().sum(),
            reported_blocking: self.governor.view(self.now).reported_blocking,
            kind_resolutions: self.kind_resolutions,
            identity_reads: self.identity_reads,
            unresolved_listings: self.unresolved_listings,
            suspended_sessions: self.jobs.values().filter(|j| j.phase == JobPhase::Suspended).count(),
            lease_grants: self.governor.view(self.now).lease_grants,
            cancelled_sessions: self.cancelled_sessions,
            resource_limits: self.resource_limits.iter().cloned().collect(),
            enrichments: self.enrichments,
            enrichment_failures: self.enrichment_failures,
            pending_enrichments: self.pending_enrichment.len(),
            domains: self.domain_stats(),
            crossings: self.crossing_events.iter().cloned().collect(),
            domain_resolutions: self.domain_resolutions,
            pending_domain_resolutions: self.pending_domain.len(),
        }
    }

    fn domain_stats(&self) -> Vec<DomainStat> {
        let accounts = self.governor.view(self.now).domains;
        self.domain_records
            .iter()
            .map(|(id, record)| {
                let account = accounts.get(id).copied().unwrap_or_default();
                DomainStat {
                    id: *id,
                    identity: record.identity.clone(),
                    capabilities: record.capabilities.clone(),
                    granted: account.granted,
                    charged: account.charged,
                }
            })
            .collect()
    }

    pub(super) fn bind_domain(&mut self, probe: &ProbeResult) -> DomainBinding {
        let (id, record) = match probe.identity.key() {
            Some(key) => (
                StorageDomainId::of(key),
                DomainRecord { identity: probe.identity.clone(), capabilities: probe.capabilities.clone() },
            ),
            None => {
                let id = match self.unknown_domain {
                    Some(id) => id,
                    None => {
                        let id = StorageDomainId::fresh();
                        self.unknown_domain = Some(id);
                        id
                    }
                };
                (id, DomainRecord { identity: DomainIdentity::Unknown, capabilities: DomainCapabilities::default() })
            }
        };
        self.domain_records.insert(id, record);
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
        self.governor.account(now);
        self.declare_stuck_workers();
        self.check_round_end();
        self.check_initial_scan();
        self.maybe_dispatch();
        self.resume_sessions();
        self.start_queued();
        self.publish();
        self.arm_timer();
    }

    fn declare_stuck_workers(&mut self) {
        for grant in self.governor.newly_stuck(self.now) {
            self.governor.mark_stuck(grant);
            let Some(job) = grant.job() else {
                continue;
            };
            if self.jobs.contains_key(&job) {
                self.finish_job(job, JobOutcome::Stuck);
            }
        }
    }

    fn resource_health(&self) -> ResourceHealth {
        if let Some(resume) = self.governor.resume_at(self.now) {
            return ResourceHealth::Throttled { cause: ThrottleCause::DutyBudget, resume: Some(resume) };
        }
        if self.blocking_slots.len() >= self.config.max_in_flight && !self.queue_order.is_empty() {
            return ResourceHealth::Throttled { cause: ThrottleCause::Concurrency, resume: None };
        }
        ResourceHealth::Nominal
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
        let entry = self.snapshot.get_by_id(id)?;
        let parent_path = entry.path.parent()?;
        self.snapshot.get(&parent_path).map(|p| p.id)
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
            reconciliation: ReconciliationHealth {
                last_round: self.last_round_result.clone(),
                degraded_paths: self.degraded_paths(),
                metadata_degraded_paths: self.metadata_degraded_paths(),
                coverage_pending,
            },
            resource: self.resource_health(),
            shutdown: self.shutdown.clone(),
        }
    }

    fn publish(&mut self) {
        let health = self.compute_health();
        let version = self.snapshot.version();
        if version != self.published_version {
            return;
        }
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

    fn unwatch_all(&mut self) {
        for id in std::mem::take(&mut self.watches) {
            self.outputs.push(Output::Unwatch(id));
        }
        for state in self.entries.values_mut() {
            if let Some(dir) = state.dir_mut() {
                dir.watch = WatchState::NotRegistered;
            }
        }
    }

    fn arm_timer(&mut self) {
        let mut wake: Option<MonotonicTime> = None;
        let mut consider = |t: MonotonicTime| {
            wake = Some(match wake {
                Some(w) => w.min(t),
                None => t,
            });
        };
        if !self.baseline_due && self.batch.is_none() {
            let due = match self.governor.resume_at(self.now) {
                Some(at) => self.periodic_due.max(at),
                None => self.periodic_due.min(self.now + self.config.maximum_period),
            };
            consider(due);
        }
        if self.batch.is_none()
            && let Some(at) = self.governor.resume_at(self.now)
        {
            consider(at);
        }
        if self.jobs.values().any(|j| j.phase == JobPhase::Suspended)
            && let Some(at) = self.governor.resume_at(self.now)
        {
            consider(at);
        }
        if let Some(at) = self.governor.next_stuck_deadline() {
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
