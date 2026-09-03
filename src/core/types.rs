use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Add;
use std::time::Duration;

use crate::fs::FsError;
use crate::ids::*;
use crate::path::{PathKey, RelativePath};
use crate::policy::PolicyContext;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MonotonicTime(pub Duration);

impl MonotonicTime {
    pub const ZERO: MonotonicTime = MonotonicTime(Duration::ZERO);

    pub fn saturating_sub(self, other: MonotonicTime) -> Duration {
        self.0.saturating_sub(other.0)
    }

    pub fn since(self, earlier: MonotonicTime) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
}

impl Add<Duration> for MonotonicTime {
    type Output = MonotonicTime;

    fn add(self, rhs: Duration) -> MonotonicTime {
        MonotonicTime(self.0.saturating_add(rhs))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Class {
    Baseline,
    Control,
    Refresh,
    Watcher,
    Retry,
    Priority,
}

pub const EXPEDITED_CLASSES: [Class; 5] =
    [Class::Control, Class::Refresh, Class::Watcher, Class::Retry, Class::Priority];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reasons {
    pub baseline: bool,
    pub control: bool,
    pub refresh: bool,
    pub watcher: bool,
    pub retry: bool,
    pub priority: bool,
    pub initial_scan: bool,
}

impl Reasons {
    pub fn control() -> Reasons {
        Reasons { control: true, ..Default::default() }
    }

    pub fn refresh() -> Reasons {
        Reasons { refresh: true, ..Default::default() }
    }

    pub fn watcher() -> Reasons {
        Reasons { watcher: true, ..Default::default() }
    }

    pub fn priority() -> Reasons {
        Reasons { priority: true, ..Default::default() }
    }

    pub fn merge(&mut self, other: Reasons) {
        self.baseline |= other.baseline;
        self.control |= other.control;
        self.refresh |= other.refresh;
        self.watcher |= other.watcher;
        self.retry |= other.retry;
        self.priority |= other.priority;
        self.initial_scan |= other.initial_scan;
    }

    pub fn class(&self) -> Class {
        if self.baseline {
            Class::Baseline
        } else if self.control {
            Class::Control
        } else if self.refresh {
            Class::Refresh
        } else if self.watcher {
            Class::Watcher
        } else if self.retry {
            Class::Retry
        } else if self.priority {
            Class::Priority
        } else {
            Class::Control
        }
    }

    pub fn expedited_class(&self) -> Class {
        let mut without = *self;
        without.baseline = false;
        without.class()
    }

    pub fn for_retry(self) -> Reasons {
        Reasons {
            baseline: false,
            control: false,
            refresh: false,
            watcher: false,
            retry: true,
            priority: false,
            ..self
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReadNeed {
    Metadata,
    Listing,
}

#[derive(Clone, Debug)]
pub struct PendingRequest {
    pub path: RelativePath,
    pub need: ReadNeed,
    pub reasons: Reasons,
    pub barriers: Vec<CommandId>,
    pub designate_for_round: Option<ReconciliationGeneration>,
}

impl PendingRequest {
    pub fn merge(&mut self, other: PendingRequest) {
        self.path = other.path;
        if other.need > self.need {
            self.need = other.need;
        }
        self.reasons.merge(other.reasons);
        for b in other.barriers {
            if !self.barriers.contains(&b) {
                self.barriers.push(b);
            }
        }
        if other.designate_for_round.is_some() {
            self.designate_for_round = other.designate_for_round;
        }
    }
}

#[derive(Clone, Debug)]
pub struct RootProbe {
    pub request: PendingRequest,
    pub not_before: Option<MonotonicTime>,
}

impl RootProbe {
    pub fn ready(&self, now: MonotonicTime) -> bool {
        self.not_before.map(|t| t <= now).unwrap_or(true)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guards {
    pub incarnation: RootIncarnation,
    pub entry_generation: EntryGeneration,
    pub load_generation: Option<LoadGeneration>,
    pub policy_revision: PolicyRevision,
    pub policy_fence: PolicyFence,
    pub parent_context: Option<ContextGeneration>,
    pub child_state: Option<ChildStateGeneration>,
    pub parent_child_state: Option<ChildStateGeneration>,
    pub entry_state: StateGeneration,
    pub change_epoch: ChangeEpoch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobPhase {
    Registering(WatchRequestId),
    Queued,
    Running(MonotonicTime),
    Confirming(MonotonicTime),
}

impl JobPhase {
    pub fn started(self) -> Option<MonotonicTime> {
        match self {
            JobPhase::Running(at) | JobPhase::Confirming(at) => Some(at),
            JobPhase::Registering(_) | JobPhase::Queued => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Occupancy {
    pub path: RelativePath,
    pub operation: super::JobOperation,
    pub started: MonotonicTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobTarget {
    Entry { id: EntryId, guards: Guards },
    RootProbe { expected_unavailable: RootIncarnation },
}

impl JobTarget {
    pub fn entry(self) -> Option<EntryId> {
        match self {
            JobTarget::Entry { id, .. } => Some(id),
            JobTarget::RootProbe { .. } => None,
        }
    }

    pub fn load_generation(self) -> Option<LoadGeneration> {
        match self {
            JobTarget::Entry { guards, .. } => guards.load_generation,
            JobTarget::RootProbe { .. } => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ActiveJob {
    pub id: JobId,
    pub target: JobTarget,
    pub path: RelativePath,
    pub need: ReadNeed,
    pub phase: JobPhase,
    pub dispatch: Sequence,
    pub recon: Option<ReconciliationGeneration>,
    pub reasons: Reasons,
    pub barriers: Vec<CommandId>,
    pub designated: bool,
}

impl ActiveJob {
    pub fn entry(&self) -> Option<EntryId> {
        self.target.entry()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RetryPhase {
    Metadata,
    Listing,
    WatchRegistrationThenListing,
}

impl RetryPhase {
    pub fn required_need(self) -> ReadNeed {
        match self {
            RetryPhase::Metadata => ReadNeed::Metadata,
            RetryPhase::Listing | RetryPhase::WatchRegistrationThenListing => ReadNeed::Listing,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryTiming {
    Backoff,
    Untimed,
}

#[derive(Clone, Debug)]
pub struct RetryRecord {
    pub phase: RetryPhase,
    pub attempts: u32,
    pub due: Option<MonotonicTime>,
    pub reasons: Reasons,
    pub barriers: Vec<CommandId>,
}

impl RetryRecord {
    pub fn admission_reasons(&self) -> Reasons {
        let mut reasons = self.reasons;
        reasons.retry = true;
        if self.phase == RetryPhase::WatchRegistrationThenListing {
            reasons.control = true;
        }
        reasons
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DegradedCause {
    Transient,
    PermissionDenied,
    Unsupported,
    LimitExceeded,
    WatcherRegistration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchState {
    NotRegistered,
    Registered(WatchId),
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    Unloaded,
    Uncovered,
    Covered(ReconciliationGeneration),
}

#[derive(Clone, Debug)]
pub struct DirState {
    pub load_generation: LoadGeneration,
    pub child_state: ChildStateGeneration,
    pub context: Option<PolicyContext>,
    pub context_generation: ContextGeneration,
    pub override_load: Option<bool>,
    coverage: Coverage,
    pub watch: WatchState,
}

impl Default for DirState {
    fn default() -> Self {
        DirState {
            load_generation: LoadGeneration::new(0),
            child_state: ChildStateGeneration::new(0),
            context: None,
            context_generation: ContextGeneration::new(0),
            override_load: None,
            coverage: Coverage::Unloaded,
            watch: WatchState::NotRegistered,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct EntryState {
    pub change_epoch: ChangeEpoch,
    pub state_generation: StateGeneration,
    pub latest_dispatch: Option<Sequence>,
    pub transient_failures: u32,
    retry: Option<RetryRecord>,
    degraded: Option<DegradedCause>,
    dir: Option<DirState>,
}

impl EntryState {
    pub fn directory() -> EntryState {
        EntryState { dir: Some(DirState::default()), ..Default::default() }
    }

    pub fn retry(&self) -> Option<&RetryRecord> {
        self.retry.as_ref()
    }

    pub fn dir(&self) -> Option<&DirState> {
        self.dir.as_ref()
    }

    pub fn dir_mut(&mut self) -> Option<&mut DirState> {
        self.dir.as_mut()
    }

    fn coverage(&self) -> Coverage {
        self.dir.as_ref().map(|d| d.coverage).unwrap_or(Coverage::Unloaded)
    }
}

#[derive(Debug, Default)]
pub struct EntryStates {
    states: HashMap<EntryId, EntryState>,
    due: BTreeMap<MonotonicTime, BTreeSet<EntryId>>,
    degraded: BTreeSet<EntryId>,
    uncovered: usize,
    covered: BTreeMap<ReconciliationGeneration, usize>,
}

impl EntryStates {
    pub fn get(&self, id: EntryId) -> Option<&EntryState> {
        self.states.get(&id)
    }

    pub fn get_mut(&mut self, id: EntryId) -> Option<&mut EntryState> {
        self.states.get_mut(&id)
    }

    pub fn entry_mut(&mut self, id: EntryId) -> &mut EntryState {
        self.states.entry(id).or_default()
    }

    pub fn contains(&self, id: EntryId) -> bool {
        self.states.contains_key(&id)
    }

    pub fn insert(&mut self, id: EntryId, state: EntryState) {
        let coverage = state.coverage();
        let due = state.retry.as_ref().and_then(|r| r.due);
        let degraded = state.degraded.is_some();
        if let Some(previous) = self.states.insert(id, state) {
            Self::unindex(&mut self.due, previous.retry.as_ref().and_then(|r| r.due), id);
            self.release_coverage(previous.coverage());
        }
        if degraded {
            self.degraded.insert(id);
        } else {
            self.degraded.remove(&id);
        }
        self.acquire_coverage(coverage);
        Self::index(&mut self.due, due, id);
    }

    pub fn remove(&mut self, id: EntryId) -> Option<EntryState> {
        let previous = self.states.remove(&id)?;
        Self::unindex(&mut self.due, previous.retry.as_ref().and_then(|r| r.due), id);
        self.degraded.remove(&id);
        self.release_coverage(previous.coverage());
        Some(previous)
    }

    pub fn clear(&mut self) {
        self.states.clear();
        self.due.clear();
        self.degraded.clear();
        self.uncovered = 0;
        self.covered.clear();
    }

    pub fn set_degraded(&mut self, id: EntryId, cause: Option<DegradedCause>) {
        let Some(state) = self.states.get_mut(&id) else {
            return;
        };
        state.degraded = cause;
        match cause {
            Some(_) => {
                self.degraded.insert(id);
            }
            None => {
                self.degraded.remove(&id);
            }
        }
    }

    pub fn degraded_ids(&self) -> impl Iterator<Item = EntryId> {
        self.degraded.iter().copied()
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut EntryState> {
        self.states.values_mut()
    }

    pub fn set_directory(&mut self, id: EntryId, directory: bool) {
        let state = self.states.entry(id).or_default();
        let previous = state.coverage();
        match (directory, state.dir.is_some()) {
            (true, false) => state.dir = Some(DirState::default()),
            (false, true) => state.dir = None,
            _ => return,
        }
        self.release_coverage(previous);
    }

    pub fn mark_loaded(&mut self, id: EntryId) {
        self.set_coverage(id, Coverage::Uncovered);
    }

    pub fn mark_unloaded(&mut self, id: EntryId) {
        self.set_coverage(id, Coverage::Unloaded);
    }

    pub fn mark_covered(&mut self, id: EntryId, generation: ReconciliationGeneration) {
        let coverage = match self.states.get(&id).map(|s| s.coverage()) {
            Some(Coverage::Uncovered) => generation,
            Some(Coverage::Covered(previous)) => previous.max(generation),
            _ => return,
        };
        self.set_coverage(id, Coverage::Covered(coverage));
    }

    #[cfg(test)]
    pub fn covered_through(&self, id: EntryId) -> Option<ReconciliationGeneration> {
        match self.states.get(&id).map(|s| s.coverage()) {
            Some(Coverage::Covered(generation)) => Some(generation),
            _ => None,
        }
    }

    pub fn coverage_pending(&self, minimum: ReconciliationGeneration) -> bool {
        self.uncovered > 0 || self.covered.range(..minimum).next().is_some()
    }

    fn set_coverage(&mut self, id: EntryId, coverage: Coverage) {
        let Some(dir) = self.states.get_mut(&id).and_then(|s| s.dir.as_mut()) else {
            return;
        };
        let previous = std::mem::replace(&mut dir.coverage, coverage);
        self.release_coverage(previous);
        self.acquire_coverage(coverage);
    }

    fn acquire_coverage(&mut self, coverage: Coverage) {
        match coverage {
            Coverage::Unloaded => {}
            Coverage::Uncovered => self.uncovered += 1,
            Coverage::Covered(generation) => *self.covered.entry(generation).or_insert(0) += 1,
        }
    }

    fn release_coverage(&mut self, coverage: Coverage) {
        match coverage {
            Coverage::Unloaded => {}
            Coverage::Uncovered => self.uncovered -= 1,
            Coverage::Covered(generation) => {
                if let Some(count) = self.covered.get_mut(&generation) {
                    *count -= 1;
                    if *count == 0 {
                        self.covered.remove(&generation);
                    }
                }
            }
        }
    }

    pub fn retry(&self, id: EntryId) -> Option<&RetryRecord> {
        self.states.get(&id).and_then(|s| s.retry.as_ref())
    }

    pub fn set_retry(&mut self, id: EntryId, record: RetryRecord) {
        let due = record.due;
        let previous = self.states.entry(id).or_default().retry.replace(record);
        Self::unindex(&mut self.due, previous.and_then(|r| r.due), id);
        Self::index(&mut self.due, due, id);
    }

    pub fn advance_watch_phase(&mut self, id: EntryId) {
        let Some(record) = self.states.get_mut(&id).and_then(|s| s.retry.as_mut()) else {
            return;
        };
        if record.phase == RetryPhase::WatchRegistrationThenListing {
            record.phase = RetryPhase::Listing;
        }
    }

    pub fn take_retry(&mut self, id: EntryId) -> Option<RetryRecord> {
        let previous = self.states.get_mut(&id)?.retry.take()?;
        Self::unindex(&mut self.due, previous.due, id);
        Some(previous)
    }

    pub fn clear_retry(&mut self, id: EntryId) {
        self.take_retry(id);
    }

    pub fn disarm_retry(&mut self, id: EntryId) {
        let Some(state) = self.states.get_mut(&id) else {
            return;
        };
        let Some(record) = state.retry.as_mut() else {
            return;
        };
        let due = record.due.take();
        Self::unindex(&mut self.due, due, id);
    }

    pub fn earliest_retry(&self) -> Option<MonotonicTime> {
        self.due.keys().next().copied()
    }

    pub fn retries_due(&self, now: MonotonicTime) -> Vec<EntryId> {
        self.due.range(..=now).flat_map(|(_, ids)| ids.iter().copied()).collect()
    }

    fn index(due: &mut BTreeMap<MonotonicTime, BTreeSet<EntryId>>, at: Option<MonotonicTime>, id: EntryId) {
        if let Some(at) = at {
            due.entry(at).or_default().insert(id);
        }
    }

    fn unindex(due: &mut BTreeMap<MonotonicTime, BTreeSet<EntryId>>, at: Option<MonotonicTime>, id: EntryId) {
        let Some(at) = at else {
            return;
        };
        let Some(slot) = due.get_mut(&at) else {
            return;
        };
        slot.remove(&id);
        if slot.is_empty() {
            due.remove(&at);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObligationState {
    Pending,
    Designated(JobId),
    Accepted,
    Unsatisfied,
    Removed,
}

impl ObligationState {
    pub fn is_terminal(self) -> bool {
        matches!(self, ObligationState::Accepted | ObligationState::Unsatisfied | ObligationState::Removed)
    }
}

#[derive(Clone, Debug)]
pub struct Obligation {
    pub entry: EntryId,
    pub load_generation: LoadGeneration,
    pub path: RelativePath,
    pub state: ObligationState,
}

#[derive(Clone, Debug)]
pub struct Round {
    pub generation: ReconciliationGeneration,
    pub barrier: Sequence,
    pub obligations: Vec<Obligation>,
    pub index: HashMap<EntryId, usize>,
    pub cursor: usize,
    pub started: MonotonicTime,
}

impl Round {
    pub fn all_terminal(&self) -> bool {
        self.obligations.iter().all(|o| o.state.is_terminal())
    }

    pub fn wrapped(&self) -> bool {
        self.cursor >= self.obligations.len()
    }

    pub fn obligation_mut(&mut self, entry: EntryId) -> Option<&mut Obligation> {
        let index = *self.index.get(&entry)?;
        self.obligations.get_mut(index)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ScanState {
    Pending,
    Unsatisfied(RelativePath),
}

#[derive(Clone, Debug)]
struct ScanObligation {
    generation: LoadGeneration,
    state: ScanState,
}

#[derive(Clone, Debug)]
pub struct InitialScan {
    obligations: HashMap<EntryId, ScanObligation>,
    pending: usize,
    failed: BTreeMap<RelativePath, usize>,
    pub foreground_done: bool,
    pub waiters: Vec<CommandId>,
}

impl InitialScan {
    pub fn new() -> InitialScan {
        InitialScan {
            obligations: HashMap::new(),
            pending: 0,
            failed: BTreeMap::new(),
            foreground_done: false,
            waiters: Vec::new(),
        }
    }

    pub fn any_unsatisfied(&self) -> bool {
        !self.failed.is_empty()
    }

    pub fn any_pending(&self) -> bool {
        self.pending > 0
    }

    pub fn failed_paths(&self) -> BTreeSet<RelativePath> {
        self.failed.keys().cloned().collect()
    }

    #[cfg(test)]
    pub fn open_obligations(&self) -> usize {
        self.obligations.len()
    }

    pub fn record_pending(&mut self, entry: EntryId, generation: LoadGeneration) {
        self.install(entry, generation, ScanState::Pending);
    }

    pub fn resolve_accepted(&mut self, entry: EntryId, generation: LoadGeneration) {
        let Some(obligation) = self.obligations.get(&entry) else {
            return;
        };
        if obligation.generation == generation {
            self.take(entry);
        }
    }

    pub fn resolve_removed(&mut self, entry: EntryId) {
        self.take(entry);
    }

    pub fn resolve_unsatisfied(&mut self, entry: EntryId, path: RelativePath) {
        let Some(obligation) = self.obligations.get(&entry) else {
            return;
        };
        if obligation.state != ScanState::Pending {
            return;
        }
        let generation = obligation.generation;
        self.install(entry, generation, ScanState::Unsatisfied(path));
    }

    pub fn revive(&mut self, entry: EntryId) {
        let Some(obligation) = self.obligations.get(&entry) else {
            return;
        };
        let generation = obligation.generation;
        self.install(entry, generation, ScanState::Pending);
    }

    fn install(&mut self, entry: EntryId, generation: LoadGeneration, state: ScanState) {
        self.acquire(&state);
        if let Some(previous) = self.obligations.insert(entry, ScanObligation { generation, state }) {
            self.release(previous.state);
        }
    }

    fn take(&mut self, entry: EntryId) {
        if let Some(previous) = self.obligations.remove(&entry) {
            self.release(previous.state);
        }
    }

    fn acquire(&mut self, state: &ScanState) {
        match state {
            ScanState::Pending => self.pending += 1,
            ScanState::Unsatisfied(path) => *self.failed.entry(path.clone()).or_insert(0) += 1,
        }
    }

    fn release(&mut self, state: ScanState) {
        match state {
            ScanState::Pending => self.pending -= 1,
            ScanState::Unsatisfied(path) => {
                if let Some(count) = self.failed.get_mut(&path) {
                    *count -= 1;
                    if *count == 0 {
                        self.failed.remove(&path);
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum RefreshTarget {
    Read { entry: EntryId },
    Walk { ancestor: EntryId, target: RelativePath },
    RootRecovery,
}

#[derive(Clone, Debug)]
pub enum CommandState {
    Refresh { remaining: Vec<RefreshTarget> },
    Load { entry: EntryId },
    InvalidatePolicy { remaining: HashMap<EntryId, LoadGeneration> },
}

#[derive(Clone, Debug)]
pub struct PendingCommand {
    pub id: CommandId,
    pub barrier: Sequence,
    pub state: CommandState,
}

#[derive(Clone, Debug)]
pub struct Batch {
    pub members: HashSet<JobId>,
    pub periodic: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PrioritySet {
    pub keys: BTreeSet<PathKey>,
    pub cursor: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootState {
    Available { incarnation: RootIncarnation, id: EntryId },
    Unavailable { last: RootIncarnation },
}

impl RootState {
    pub fn incarnation(&self) -> RootIncarnation {
        match self {
            RootState::Available { incarnation, .. } => *incarnation,
            RootState::Unavailable { last } => *last,
        }
    }

    pub fn id(&self) -> Option<EntryId> {
        match self {
            RootState::Available { id, .. } => Some(*id),
            RootState::Unavailable { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListingRejection {
    MalformedNames,
    LimitExceeded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobOutcome {
    Accepted,
    Removed,
    Failed(FsError),
    LimitExceeded,
    WatcherRegistrationFailed,
    Stale,
    Cancelled,
    WorkerLost,
    Stuck,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenGate {
    Pending,
    Ready,
    Failed(crate::error::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationTarget {
    Job(JobId),
    Standalone(EntryId),
    Abandoned,
}
