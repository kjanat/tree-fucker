use std::collections::{BTreeSet, HashMap, HashSet};
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
    pub not_before: Option<MonotonicTime>,
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
        self.not_before = match (self.not_before, other.not_before) {
            (Some(a), Some(b)) => Some(a.min(b)),
            _ => None,
        };
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guards {
    pub incarnation: RootIncarnation,
    pub entry_generation: EntryGeneration,
    pub load_generation: Option<LoadGeneration>,
    pub policy_fence: PolicyRevision,
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
    Running,
    Confirming,
}

#[derive(Clone, Debug)]
pub struct ActiveJob {
    pub id: JobId,
    pub entry: Option<EntryId>,
    pub path: RelativePath,
    pub need: ReadNeed,
    pub phase: JobPhase,
    pub guards: Guards,
    pub dispatch: Sequence,
    pub recon: Option<ReconciliationGeneration>,
    pub reasons: Reasons,
    pub barriers: Vec<CommandId>,
    pub designated: bool,
    pub started: Option<MonotonicTime>,
    pub expected_unavailable: Option<RootIncarnation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryPhase {
    Metadata,
    Listing,
    WatchRegistrationThenListing,
}

#[derive(Clone, Debug)]
pub struct RetryRecord {
    pub phase: RetryPhase,
    pub attempts: u32,
    pub due: Option<MonotonicTime>,
    pub reasons: Reasons,
    pub barriers: Vec<CommandId>,
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

#[derive(Clone, Debug)]
pub struct DirState {
    pub load_generation: LoadGeneration,
    pub child_state: ChildStateGeneration,
    pub context: Option<PolicyContext>,
    pub context_generation: ContextGeneration,
    pub override_load: Option<bool>,
    pub last_covered: Option<ReconciliationGeneration>,
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
            last_covered: None,
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
    pub degraded: Option<DegradedCause>,
    pub retry: Option<RetryRecord>,
    pub dir: Option<DirState>,
}

impl EntryState {
    pub fn directory() -> EntryState {
        EntryState { dir: Some(DirState::default()), ..Default::default() }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanObligation {
    Pending,
    Accepted,
    Unsatisfied,
    Removed,
}

#[derive(Clone, Debug)]
pub struct InitialScan {
    pub obligations: HashMap<EntryId, (LoadGeneration, ScanObligation)>,
    pub failed: BTreeSet<RelativePath>,
    pub foreground_done: bool,
    pub waiters: Vec<CommandId>,
}

impl InitialScan {
    pub fn new() -> InitialScan {
        InitialScan {
            obligations: HashMap::new(),
            failed: BTreeSet::new(),
            foreground_done: false,
            waiters: Vec::new(),
        }
    }

    pub fn any_unsatisfied(&self) -> bool {
        self.obligations.values().any(|(_, s)| *s == ScanObligation::Unsatisfied)
    }

    pub fn any_pending(&self) -> bool {
        self.obligations.values().any(|(_, s)| *s == ScanObligation::Pending)
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
    pub started: MonotonicTime,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobOutcome {
    Accepted,
    Removed,
    Failed(FsError),
    LimitExceeded,
    WatcherRegistrationFailed,
    Stale,
    Cancelled,
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
}
