use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::Add;
use std::time::Duration;

use crate::domain::{DomainCrossing, ProbeResult, StorageDomainId};
use crate::entry::{Entry, LoadState, MetadataFields, Shape};
use crate::fs::FsError;
use crate::ids::*;
use crate::path::RelativePath;
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
pub enum WorkOrigin {
    Background,
    Foreground,
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
pub enum ReadKind {
    Metadata,
    Listing,
}

impl ReadKind {
    pub fn need(self) -> ReadNeed {
        match self {
            ReadKind::Metadata => ReadNeed::Metadata,
            ReadKind::Listing => ReadNeed::Listing,
        }
    }

    pub fn operation(self) -> super::Operation {
        match self {
            ReadKind::Metadata => super::Operation::Metadata,
            ReadKind::Listing => super::Operation::Listing,
        }
    }

    pub fn still_required(self, current: &Entry) -> bool {
        match self {
            ReadKind::Listing => matches!(current.shape, Shape::Directory(LoadState::Loaded | LoadState::Loading)),
            ReadKind::Metadata => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReadNeed {
    Domain,
    Metadata,
    Listing,
    Enrichment(MetadataFields),
}

impl ReadNeed {
    pub fn observes_children(self) -> bool {
        matches!(self, ReadNeed::Listing | ReadNeed::Enrichment(_))
    }

    pub fn kind(self) -> Option<ReadKind> {
        match self {
            ReadNeed::Metadata => Some(ReadKind::Metadata),
            ReadNeed::Listing => Some(ReadKind::Listing),
            ReadNeed::Domain | ReadNeed::Enrichment(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainBinding {
    pub id: StorageDomainId,
    pub probe: ProbeResult,
}

#[derive(Clone, Debug)]
pub struct DomainRequest {
    pub path: RelativePath,
    pub reasons: Reasons,
    pub attempts: u32,
    pub due: Option<MonotonicTime>,
}

impl DomainRequest {
    pub fn ready(&self, now: MonotonicTime) -> bool {
        self.due.map(|at| at <= now).unwrap_or(true)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum EnrichmentScope {
    #[default]
    Directory,
    Children(Vec<std::ffi::OsString>),
}

impl EnrichmentScope {
    pub fn widen(self, other: EnrichmentScope) -> EnrichmentScope {
        match (self, other) {
            (EnrichmentScope::Directory, _) | (_, EnrichmentScope::Directory) => EnrichmentScope::Directory,
            (EnrichmentScope::Children(mut held), EnrichmentScope::Children(more)) => {
                for name in more {
                    if !held.contains(&name) {
                        held.push(name);
                    }
                }
                EnrichmentScope::Children(held)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct EnrichmentRequest {
    pub path: RelativePath,
    pub fields: MetadataFields,
    pub scope: EnrichmentScope,
    pub reasons: Reasons,
    pub attempts: u32,
    pub due: Option<MonotonicTime>,
}

impl EnrichmentRequest {
    pub fn ready(&self, now: MonotonicTime) -> bool {
        self.due.map(|at| at <= now).unwrap_or(true)
    }
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
    Registering(WatchRequestId, MonotonicTime),
    Queued,
    Suspended,
    Running(MonotonicTime),
    Confirming(MonotonicTime),
}

impl JobPhase {
    pub fn started(self) -> Option<MonotonicTime> {
        match self {
            JobPhase::Running(at) | JobPhase::Confirming(at) | JobPhase::Registering(_, at) => Some(at),
            JobPhase::Queued | JobPhase::Suspended => None,
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

#[derive(Clone, Debug, Default)]
pub struct EnrichmentProgress {
    pub scope: EnrichmentScope,
    pub cursor: usize,
    pub dispatched: usize,
    pub directory: Option<crate::entry::Metadata>,
    pub children: Vec<(std::ffi::OsString, crate::entry::Metadata)>,
    pub failed: Vec<(std::ffi::OsString, FsError)>,
    pub metadata_operations: u32,
}

#[derive(Clone, Debug)]
pub struct ActiveJob {
    pub id: JobId,
    pub target: JobTarget,
    pub path: RelativePath,
    pub domain: Option<StorageDomainId>,
    pub origin: WorkOrigin,
    pub need: ReadNeed,
    pub phase: JobPhase,
    pub dispatch: Sequence,
    pub recon: Option<ReconciliationGeneration>,
    pub reasons: Reasons,
    pub barriers: Vec<CommandId>,
    pub designated: bool,
    pub cancel: crate::fs::CancellationToken,
    pub leases: u32,
    pub permitted: u32,
    pub starved: bool,
    pub session_open: bool,
    pub registration: Option<super::WatchScope>,
    pub enrichment: Option<EnrichmentProgress>,
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
    pub fn required_kind(self) -> ReadKind {
        match self {
            RetryPhase::Metadata => ReadKind::Metadata,
            RetryPhase::Listing | RetryPhase::WatchRegistrationThenListing => ReadKind::Listing,
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
    ResourceLimited,
    WatcherRegistration,
    Enrichment,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WatchAccount {
    pub watched: usize,
    pub unwatched_by_cap: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchState {
    NotRegistered,
    Pending,
    Registered(WatchId),
    Failed,
    Capped,
}

impl WatchState {
    pub fn holds_a_path(self) -> bool {
        matches!(self, WatchState::Pending | WatchState::Registered(_))
    }
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
    pub domain: Option<DomainBinding>,
    watch_domain: Option<StorageDomainId>,
    pub crossing: Option<DomainCrossing>,
    coverage: Coverage,
    watch: WatchState,
}

impl DirState {
    pub fn watch(&self) -> WatchState {
        self.watch
    }
}

impl Default for DirState {
    fn default() -> Self {
        DirState {
            load_generation: LoadGeneration::new(0),
            child_state: ChildStateGeneration::new(0),
            context: None,
            context_generation: ContextGeneration::new(0),
            override_load: None,
            domain: None,
            crossing: None,
            coverage: Coverage::Unloaded,
            watch: WatchState::NotRegistered,
            watch_domain: None,
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
    metadata_degraded: Option<DegradedCause>,
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
    states: IdMap<EntryId, EntryState>,
    due: BTreeMap<MonotonicTime, BTreeSet<EntryId>>,
    degraded: BTreeSet<EntryId>,
    metadata_degraded: BTreeSet<EntryId>,
    watched: BTreeSet<EntryId>,
    capped: BTreeSet<EntryId>,
    watch_accounts: BTreeMap<Option<StorageDomainId>, WatchAccount>,
    uncovered: usize,
    covered: BTreeMap<ReconciliationGeneration, usize>,
}

impl EntryStates {
    pub fn get(&self, id: EntryId) -> Option<&EntryState> {
        self.states.get(&id)
    }

    pub fn set_watch(&mut self, id: EntryId, watch: WatchState, domain: Option<StorageDomainId>) {
        let Some(dir) = self.states.get_mut(&id).and_then(|state| state.dir.as_mut()) else {
            return;
        };
        let previous = (dir.watch, dir.watch_domain);
        dir.watch = watch;
        dir.watch_domain = domain;
        Self::release_watch(&mut self.watch_accounts, previous.0, previous.1);
        Self::acquire_watch(&mut self.watch_accounts, watch, domain);
        if watch.holds_a_path() {
            self.watched.insert(id);
        } else {
            self.watched.remove(&id);
        }
        if watch == WatchState::Capped {
            self.capped.insert(id);
        } else {
            self.capped.remove(&id);
        }
    }

    pub fn rebind_watch_domain(&mut self, id: EntryId, domain: Option<StorageDomainId>) {
        let Some(dir) = self.states.get_mut(&id).and_then(|state| state.dir.as_mut()) else {
            return;
        };
        if dir.watch_domain == domain {
            return;
        }
        let watch = dir.watch;
        let previous = dir.watch_domain;
        dir.watch_domain = domain;
        Self::release_watch(&mut self.watch_accounts, watch, previous);
        Self::acquire_watch(&mut self.watch_accounts, watch, domain);
    }

    pub fn watch_accounts(&self) -> &BTreeMap<Option<StorageDomainId>, WatchAccount> {
        &self.watch_accounts
    }

    fn acquire_watch(
        accounts: &mut BTreeMap<Option<StorageDomainId>, WatchAccount>,
        watch: WatchState,
        domain: Option<StorageDomainId>,
    ) {
        match watch {
            WatchState::Pending | WatchState::Registered(_) => accounts.entry(domain).or_default().watched += 1,
            WatchState::Capped => accounts.entry(domain).or_default().unwatched_by_cap += 1,
            WatchState::NotRegistered | WatchState::Failed => {}
        }
    }

    fn release_watch(
        accounts: &mut BTreeMap<Option<StorageDomainId>, WatchAccount>,
        watch: WatchState,
        domain: Option<StorageDomainId>,
    ) {
        let Some(account) = accounts.get_mut(&domain) else {
            return;
        };
        match watch {
            WatchState::Pending | WatchState::Registered(_) => account.watched -= 1,
            WatchState::Capped => account.unwatched_by_cap -= 1,
            WatchState::NotRegistered | WatchState::Failed => return,
        }
        if *account == WatchAccount::default() {
            accounts.remove(&domain);
        }
    }

    pub fn watched_ids(&self) -> impl Iterator<Item = EntryId> {
        self.watched.iter().copied()
    }

    pub fn capped_ids(&self) -> impl Iterator<Item = EntryId> {
        self.capped.iter().copied()
    }

    pub fn any_capped(&self) -> bool {
        !self.capped.is_empty()
    }

    pub fn reset_watches(&mut self) {
        let mut pending: BTreeSet<EntryId> = BTreeSet::new();
        let mut accounts: BTreeMap<Option<StorageDomainId>, WatchAccount> = BTreeMap::new();
        for (id, state) in self.states.iter_mut() {
            let Some(dir) = state.dir.as_mut() else {
                continue;
            };
            match dir.watch {
                WatchState::Pending => {
                    pending.insert(*id);
                    Self::acquire_watch(&mut accounts, WatchState::Pending, dir.watch_domain);
                }
                WatchState::NotRegistered | WatchState::Registered(_) | WatchState::Failed | WatchState::Capped => {
                    dir.watch = WatchState::NotRegistered;
                    dir.watch_domain = None;
                }
            }
        }
        self.watched = pending;
        self.capped.clear();
        self.watch_accounts = accounts;
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
        let watched = state.dir.as_ref().map(|d| d.watch.holds_a_path()).unwrap_or(false);
        let capped = state.dir.as_ref().map(|d| d.watch == WatchState::Capped).unwrap_or(false);
        let acquired = state.dir.as_ref().map(|dir| (dir.watch, dir.watch_domain));
        if let Some(previous) = self.states.insert(id, state) {
            Self::unindex(&mut self.due, previous.retry.as_ref().and_then(|r| r.due), id);
            if let Some(dir) = previous.dir() {
                Self::release_watch(&mut self.watch_accounts, dir.watch, dir.watch_domain);
            }
            self.release_coverage(previous.coverage());
        }
        if let Some(acquired) = acquired {
            Self::acquire_watch(&mut self.watch_accounts, acquired.0, acquired.1);
        }
        if degraded {
            self.degraded.insert(id);
        } else {
            self.degraded.remove(&id);
        }
        if watched {
            self.watched.insert(id);
        } else {
            self.watched.remove(&id);
        }
        if capped {
            self.capped.insert(id);
        } else {
            self.capped.remove(&id);
        }
        self.metadata_degraded.remove(&id);
        self.acquire_coverage(coverage);
        Self::index(&mut self.due, due, id);
    }

    pub fn remove(&mut self, id: EntryId) -> Option<EntryState> {
        let previous = self.states.remove(&id)?;
        Self::unindex(&mut self.due, previous.retry.as_ref().and_then(|r| r.due), id);
        self.degraded.remove(&id);
        self.metadata_degraded.remove(&id);
        self.watched.remove(&id);
        self.capped.remove(&id);
        if let Some(dir) = previous.dir() {
            Self::release_watch(&mut self.watch_accounts, dir.watch, dir.watch_domain);
        }
        self.release_coverage(previous.coverage());
        Some(previous)
    }

    pub fn clear(&mut self) {
        self.states.clear();
        self.due.clear();
        self.degraded.clear();
        self.metadata_degraded.clear();
        self.watched.clear();
        self.capped.clear();
        self.watch_accounts.clear();
        self.uncovered = 0;
        self.covered.clear();
    }

    pub fn set_metadata_degraded(&mut self, id: EntryId, cause: Option<DegradedCause>) {
        let Some(state) = self.states.get_mut(&id) else {
            return;
        };
        state.metadata_degraded = cause;
        match cause {
            Some(_) => {
                self.metadata_degraded.insert(id);
            }
            None => {
                self.metadata_degraded.remove(&id);
            }
        }
    }

    pub fn metadata_degraded_ids(&self) -> impl Iterator<Item = EntryId> {
        self.metadata_degraded.iter().copied()
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

    pub fn degraded_causes(&self) -> impl Iterator<Item = (EntryId, DegradedCause)> + '_ {
        self.degraded.iter().filter_map(|id| self.states.get(id).and_then(|s| s.degraded).map(|cause| (*id, cause)))
    }

    pub fn set_directory(&mut self, id: EntryId, directory: bool) {
        let state = self.states.entry(id).or_default();
        let previous = state.coverage();
        let released = state.dir.as_ref().map(|dir| (dir.watch, dir.watch_domain));
        match (directory, state.dir.is_some()) {
            (true, false) => state.dir = Some(DirState::default()),
            (false, true) => state.dir = None,
            _ => return,
        }
        if !directory {
            self.watched.remove(&id);
            self.capped.remove(&id);
            if let Some(released) = released {
                Self::release_watch(&mut self.watch_accounts, released.0, released.1);
            }
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

    pub fn loaded_directories(&self) -> usize {
        self.uncovered + self.covered.values().sum::<usize>()
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
    pub index: IdMap<EntryId, usize>,
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
    obligations: IdMap<EntryId, ScanObligation>,
    pending: usize,
    failed: BTreeMap<RelativePath, usize>,
    pub foreground_done: bool,
    pub waiters: Vec<CommandId>,
}

impl InitialScan {
    pub fn new() -> InitialScan {
        InitialScan {
            obligations: IdMap::default(),
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
    InvalidatePolicy { remaining: IdMap<EntryId, LoadGeneration> },
}

#[derive(Clone, Debug)]
pub struct PendingCommand {
    pub id: CommandId,
    pub barrier: Sequence,
    pub state: CommandState,
    pub admitted: Duration,
}

impl PendingCommand {
    pub fn draws_on_foreground(&self) -> bool {
        matches!(self.state, CommandState::Refresh { .. } | CommandState::Load { .. })
    }
}

#[derive(Clone, Debug)]
pub struct Batch {
    pub members: HashSet<JobId>,
    pub periodic: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PrioritySet {
    pub paths: BTreeSet<RelativePath>,
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
    UnresolvedChild,
    ResourceLimited(crate::update::ResourceLimited),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobOutcome {
    Accepted,
    Removed,
    Failed(FsError),
    Rejected(ListingRejection),
    AncestorNotDirectory,
    ResultMismatch,
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
    AbandonedJob(JobId),
    AbandonedStandalone,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub path: RelativePath,
    pub target: RegistrationTarget,
}

impl Registration {
    pub fn abandon(&mut self) {
        self.target = self.target.abandon();
    }
}

impl RegistrationTarget {
    pub fn abandon(self) -> RegistrationTarget {
        match self {
            RegistrationTarget::Job(id) | RegistrationTarget::AbandonedJob(id) => RegistrationTarget::AbandonedJob(id),
            RegistrationTarget::Standalone(_) | RegistrationTarget::AbandonedStandalone => {
                RegistrationTarget::AbandonedStandalone
            }
        }
    }

    pub fn job(self) -> Option<JobId> {
        match self {
            RegistrationTarget::Job(id) | RegistrationTarget::AbandonedJob(id) => Some(id),
            RegistrationTarget::Standalone(_) | RegistrationTarget::AbandonedStandalone => None,
        }
    }
}
