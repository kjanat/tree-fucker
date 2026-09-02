mod apply;
mod commands;
mod jobs;
mod scheduler;
mod types;
mod watcher;

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::entry::{LoadState, Shape};
use crate::error::Error;
use crate::fs::{DirectoryListing, EntryInfo, FsCapabilities, FsError, WatcherEvent, WatcherKind};
use crate::ids::*;
use crate::path::RelativePath;
use crate::policy::{PolicyContext, ScanPolicy};
use crate::snapshot::{Snapshot, new_entry};
use crate::update::{
    ErrorCause, Health, InitialScanState, Operation, ReconciliationHealth, RecoverableError, RootAvailability,
    ShutdownState, Update, UpdateEvent, WatcherHealth,
};

pub use types::MonotonicTime;
use types::*;

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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobSpec {
    pub id: JobId,
    pub path: RelativePath,
    pub operation: JobOperation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobResult {
    Listing(Result<DirectoryListing, FsError>),
    Metadata(Result<EntryInfo, FsError>),
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

#[derive(Clone, Debug)]
pub enum Output {
    StartJob(JobSpec),
    CancelJob(JobId),
    RegisterWatch { request: WatchRequestId, path: RelativePath, recursive: bool },
    Unwatch(WatchId),
    Publish(UpdateEvent),
    CommandFinished { id: CommandId, result: Result<(), Error> },
    SetTimer { id: TimerId, at: MonotonicTime },
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
}

pub struct Coordinator {
    config: Config,
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
    entries: HashMap<EntryId, EntryState>,
    pending: HashMap<EntryId, PendingRequest>,
    root_probe: Option<PendingRequest>,
    probe_attempts: u32,
    jobs: HashMap<JobId, ActiveJob>,
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
        let mut coordinator = Coordinator {
            config,
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
            entries: HashMap::new(),
            pending: HashMap::new(),
            root_probe: None,
            probe_attempts: 0,
            jobs: HashMap::new(),
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

    pub fn is_stopped(&self) -> bool {
        matches!(self.shutdown, ShutdownState::Stopped | ShutdownState::Terminated { .. })
    }

    pub fn next_wake(&self) -> Option<MonotonicTime> {
        self.timer_wake
    }

    pub fn handle(&mut self, input: Input, now: MonotonicTime) -> Vec<Output> {
        self.now = self.now.max(now);
        if self.is_stopped() {
            if let Input::Command { id, .. } = input {
                let err = match &self.shutdown {
                    ShutdownState::Terminated { .. } => Error::TreeTerminated,
                    _ => Error::Shutdown,
                };
                self.outputs.push(Output::CommandFinished { id, result: Err(err) });
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
        let queued =
            self.jobs.values().filter(|j| matches!(j.phase, JobPhase::Queued | JobPhase::Registering(_))).count();
        let in_flight =
            self.jobs.values().filter(|j| matches!(j.phase, JobPhase::Running | JobPhase::Confirming)).count();
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
        }
    }

    fn after_input(&mut self) {
        if self.is_stopped() {
            return;
        }
        self.check_round_end();
        self.check_initial_scan();
        self.maybe_dispatch();
        self.start_queued();
        self.publish();
        self.arm_timer();
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

    fn next_job_id(&mut self) -> JobId {
        let id = self.next_job_id;
        self.next_job_id = id.next();
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
        let jitter_nanos = if jitter_max.is_zero() { 0 } else { self.random() % (jitter_max.as_nanos() as u64 + 1) };
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
                error: ErrorCause::Fs(FsError::Fatal(format!("root install failed: {err:?}"))),
            });
        }
        let (snapshot, _) = builder.finish(self.snapshot.version().next());
        self.snapshot = snapshot;
        self.entries.insert(id, EntryState::directory());
        self.initial_scan.obligations.insert(id, (LoadGeneration::new(0), ScanObligation::Pending));
        let mut reasons = Reasons::control();
        reasons.initial_scan = true;
        self.request(id, RelativePath::root(), ReadNeed::Listing, reasons, Vec::new());
    }

    pub(crate) fn entry_state(&self, id: EntryId) -> Option<&EntryState> {
        self.entries.get(&id)
    }

    fn entry_state_mut(&mut self, id: EntryId) -> &mut EntryState {
        self.entries.entry(id).or_default()
    }

    fn dir_state(&self, id: EntryId) -> Option<&DirState> {
        self.entries.get(&id).and_then(|e| e.dir.as_ref())
    }

    fn dir_state_mut(&mut self, id: EntryId) -> Option<&mut DirState> {
        self.entries.get_mut(&id).and_then(|e| e.dir.as_mut())
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
        let request = PendingRequest { path, need, reasons, barriers, designate_for_round: None, not_before: None };
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
        let mut paths = BTreeSet::new();
        for (id, state) in &self.entries {
            if state.degraded.is_some()
                && let Some(entry) = self.snapshot.get_by_id(*id)
            {
                paths.insert(entry.path.clone());
            }
        }
        paths
    }

    fn initial_scan_state(&self) -> InitialScanState {
        match self.root {
            RootState::Unavailable { .. } => InitialScanState::Unavailable,
            RootState::Available { incarnation, .. } => {
                let scan = &self.initial_scan;
                if scan.any_unsatisfied() {
                    InitialScanState::Degraded { incarnation, failed: scan.failed.clone() }
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
        let coverage_pending = self.snapshot.loaded_directories().any(|dir| {
            self.dir_state(dir.id).map(|d| d.last_covered.map(|g| g < self.min_recon).unwrap_or(true)).unwrap_or(true)
        }) && self.min_recon > ReconciliationGeneration::new(0);
        Health {
            initial_scan: self.initial_scan_state(),
            root,
            watcher: self.watcher_health.clone(),
            reconciliation: ReconciliationHealth {
                last_round: self.last_round_result.clone(),
                degraded_paths: self.degraded_paths(),
                coverage_pending,
            },
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
            self.outputs.push(Output::Publish(UpdateEvent::Health { version, health, errors }));
        }
    }

    fn publish_delta(&mut self, previous: SnapshotVersion, changes: Vec<crate::update::PathChange>) {
        let health = self.compute_health();
        let errors = std::mem::take(&mut self.errors);
        self.last_published_health = Some(health.clone());
        self.published_version = self.snapshot.version();
        self.outputs.push(Output::Publish(UpdateEvent::Delta(Update {
            previous_version: previous,
            new_version: self.snapshot.version(),
            snapshot: self.snapshot.clone(),
            changes,
            health,
            errors,
        })));
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
        self.outputs.push(Output::Publish(UpdateEvent::Terminal { health }));
        self.outputs.push(Output::Stopped);
    }

    fn cancel_all_jobs(&mut self) {
        let ids: Vec<JobId> = self.jobs.keys().copied().collect();
        for id in ids {
            if let Some(job) = self.jobs.remove(&id) {
                if matches!(job.phase, JobPhase::Running | JobPhase::Confirming) {
                    self.outputs.push(Output::CancelJob(id));
                }
                if let Some(entry) = job.entry {
                    self.active_by_entry.remove(&entry);
                }
            }
        }
        self.probe_job = None;
        self.queue_order.clear();
        self.batch = None;
        self.registrations.clear();
    }

    fn unwatch_all(&mut self) {
        for id in std::mem::take(&mut self.watches) {
            self.outputs.push(Output::Unwatch(id));
        }
        for state in self.entries.values_mut() {
            if let Some(dir) = state.dir.as_mut() {
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
            consider(self.periodic_due);
        }
        for request in self.pending.values() {
            if let Some(t) = request.not_before {
                consider(t);
            }
        }
        if let Some(probe) = &self.root_probe
            && let Some(t) = probe.not_before
        {
            consider(t);
        }
        for state in self.entries.values() {
            if let Some(retry) = &state.retry
                && let Some(t) = retry.due
            {
                consider(t);
            }
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
