use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::fake_fs::{DomainId, FakeFileSystem, FakeOp};
use crate::config::{Config, HostConfig};
use crate::core::{
    Class, Command, Coordinator, HostGovernor, Input, JobOperation, JobResult, JobSpec, MonotonicTime, Output, Stats,
    Work, WorkOrigin, WorkerLoss,
};
use crate::domain::StorageDomainId;
use crate::error::Error;
use crate::fs::{Continuation, FileSystem, HintKind, ListingSession, SessionStep, WatcherEvent};
use crate::ids::{CommandId, IdMap, JobId, TimerId, WatchId, WatchReleaseId, WatchRequestId};
use crate::path::RelativePath;
use crate::policy::ScanPolicy;
use crate::snapshot::Snapshot;
use crate::update::{Health, UpdateEvent};

const MAXIMUM_STEPS: usize = 1_000_000;
const SETTLE_HORIZON: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ticket(pub CommandId);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    pub at: MonotonicTime,
    pub job: JobId,
    pub class: Class,
    pub operation: JobOperation,
    pub entry: RelativePath,
    pub batch: usize,
    pub reserved: Duration,
    pub lease: u32,
    pub operations: u32,
    pub domain: Option<StorageDomainId>,
    pub origin: WorkOrigin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dispatched {
    Listing { job: JobId, path: RelativePath, operations: usize },
    Enrichment { job: JobId, path: RelativePath, children: usize },
    Metadata { job: JobId, path: RelativePath },
    Domain { job: JobId, path: RelativePath },
}

impl Dispatched {
    pub fn path(&self) -> &RelativePath {
        match self {
            Dispatched::Listing { path, .. }
            | Dispatched::Enrichment { path, .. }
            | Dispatched::Metadata { path, .. }
            | Dispatched::Domain { path, .. } => path,
        }
    }

    pub fn job(&self) -> JobId {
        match self {
            Dispatched::Listing { job, .. }
            | Dispatched::Enrichment { job, .. }
            | Dispatched::Metadata { job, .. }
            | Dispatched::Domain { job, .. } => *job,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Charge {
    pub at: MonotonicTime,
    pub job: JobId,
    pub domain: DomainId,
    pub cost: Duration,
}

struct Running {
    started: MonotonicTime,
    due: MonotonicTime,
    domain: DomainId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Scheduled {
    Job(JobId),
    Registration(WatchRequestId),
}

struct Sink {
    queue: Mutex<VecDeque<WatcherEvent>>,
}

impl crate::fs::WatcherSink for Sink {
    fn deliver(&self, event: WatcherEvent) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.push_back(event);
        }
    }
}

enum SessionSlot {
    Open(Box<dyn ListingSession>),
    Cancelled,
}

pub struct Harness {
    pub fs: Arc<FakeFileSystem>,
    pub coordinator: Coordinator,
    now: MonotonicTime,
    injected: Duration,
    opened_at: std::time::Instant,
    jobs: VecDeque<JobSpec>,
    registrations: VecDeque<(WatchRequestId, RelativePath, bool)>,
    events: Vec<UpdateEvent>,
    results: IdMap<CommandId, Result<(), Error>>,
    next_command: u64,
    timer: Option<(TimerId, MonotonicTime)>,
    sink: Arc<Sink>,
    cancelled: Vec<JobId>,
    outstanding: VecDeque<JobSpec>,
    unwatched: Vec<WatchId>,
    releases: VecDeque<(WatchReleaseId, WatchId)>,
    stopped: bool,
    schedule: BTreeSet<(MonotonicTime, Scheduled)>,
    registration_due: IdMap<WatchRequestId, MonotonicTime>,
    running: IdMap<JobId, Running>,
    job_domain: IdMap<JobId, DomainId>,
    charges: Vec<Charge>,
    dispatches: Vec<Dispatched>,
    admissions: Vec<Admission>,
    admitted: HashSet<(JobId, u32), crate::ids::IdHashing>,
    grant_buffer: Vec<crate::core::Grant>,
    sessions: IdMap<JobId, SessionSlot>,
    entries_seen: IdMap<JobId, usize>,
    batch_index: usize,
    batch_members: BTreeSet<JobId>,
    waited_at: Option<MonotonicTime>,
    pub auto_register: bool,
    pub auto_release: bool,
}

impl Harness {
    pub fn open(fs: Arc<FakeFileSystem>, policy: Arc<dyn ScanPolicy>, config: Config) -> Result<Harness, Error> {
        Harness::open_with_host(fs, policy, HostConfig::default(), config)
    }

    pub fn open_with_host(
        fs: Arc<FakeFileSystem>,
        policy: Arc<dyn ScanPolicy>,
        host: HostConfig,
        config: Config,
    ) -> Result<Harness, Error> {
        host.validate().map_err(Error::InvalidConfig)?;
        Harness::open_under(fs, policy, config, HostGovernor::independent(&host))
    }

    pub fn open_under(
        fs: Arc<FakeFileSystem>,
        policy: Arc<dyn ScanPolicy>,
        config: Config,
        governor: HostGovernor,
    ) -> Result<Harness, Error> {
        config.validate().map_err(Error::InvalidConfig)?;
        let root_info = fs.metadata(fs.root(), &RelativePath::root())?;
        let now = MonotonicTime::ZERO;
        let mut coordinator = Coordinator::new(config, policy, fs.capabilities(), root_info, now, governor)?;
        let outputs = coordinator.take_outputs();
        let mut harness = Harness {
            fs,
            coordinator,
            now,
            injected: Duration::ZERO,
            opened_at: std::time::Instant::now(),
            jobs: VecDeque::new(),
            registrations: VecDeque::new(),
            events: Vec::new(),
            results: IdMap::default(),
            next_command: 1,
            timer: None,
            sink: Arc::new(Sink { queue: Mutex::new(VecDeque::new()) }),
            cancelled: Vec::new(),
            outstanding: VecDeque::new(),
            unwatched: Vec::new(),
            releases: VecDeque::new(),
            stopped: false,
            schedule: BTreeSet::new(),
            registration_due: IdMap::default(),
            running: IdMap::default(),
            job_domain: IdMap::default(),
            charges: Vec::new(),
            dispatches: Vec::new(),
            admissions: Vec::new(),
            admitted: HashSet::default(),
            grant_buffer: Vec::new(),
            sessions: IdMap::default(),
            entries_seen: IdMap::default(),
            batch_index: 0,
            batch_members: BTreeSet::new(),
            waited_at: None,
            auto_register: true,
            auto_release: true,
        };
        harness.record_grants();
        harness.process(outputs);
        if harness.auto_register {
            harness.complete_registrations();
        }
        if let Some(Err(err)) = harness.coordinator.open_gate() {
            return Err(err);
        }
        Ok(harness)
    }

    pub fn open_default(fs: Arc<FakeFileSystem>, policy: Arc<dyn ScanPolicy>) -> Harness {
        Harness::open(fs, policy, Config::default()).expect("open")
    }

    fn advance_injected(&mut self, at: MonotonicTime) {
        let next = self.now.max(at);
        self.injected += next.since(self.now);
        self.now = next;
    }

    pub fn injected(&self) -> Duration {
        self.injected
    }

    pub fn real_elapsed(&self) -> Duration {
        self.opened_at.elapsed()
    }

    pub fn now(&self) -> MonotonicTime {
        self.now
    }

    fn process(&mut self, outputs: Vec<Output>) {
        for output in outputs {
            match output {
                Output::StartJob(spec) => {
                    self.begin_work(&spec);
                    self.jobs.push_back(spec);
                }
                Output::CancelJob(id) => {
                    self.cancelled.push(id);
                    match self.jobs.iter().position(|j| j.id == id) {
                        Some(index) => {
                            if let Some(spec) = self.jobs.remove(index) {
                                self.outstanding.push_back(spec);
                            }
                            if self.sessions.remove(&id).is_none() {
                                self.sessions.insert(id, SessionSlot::Cancelled);
                            }
                        }
                        None => self.drop_session(id),
                    }
                }
                Output::RegisterWatch { request, path, recursive } => {
                    let cost = self.fs.cost_of(FakeOp::Watch, &path);
                    if !cost.is_zero() {
                        let due = self.now + cost;
                        self.registration_due.insert(request, due);
                        self.schedule.insert((due, Scheduled::Registration(request)));
                    }
                    self.registrations.push_back((request, path, recursive))
                }
                Output::Unwatch { release, watch } => {
                    self.unwatched.push(watch);
                    self.releases.push_back((release, watch));
                }
                Output::Publish(event) => self.events.push(*event),
                Output::CommandFinished { id, result } => {
                    self.results.insert(id, result);
                }
                Output::SetTimer { id, at } => self.timer = Some((id, at)),
                Output::Stopped(_) => self.stopped = true,
            }
        }
    }

    fn feed(&mut self, input: Input) {
        let now = self.now;
        let outputs = self.coordinator.handle(input, now);
        self.record_grants();
        self.process(outputs);
    }

    fn observe(&mut self) {
        let now = self.now;
        let outputs = self.coordinator.observe(now);
        self.record_grants();
        self.process(outputs);
    }

    fn record_grants(&mut self) {
        let mut fresh = std::mem::take(&mut self.grant_buffer);
        fresh.clear();
        let admitted = &self.admitted;
        self.coordinator.new_grants_into(&mut fresh, &|id, lease| match id.job() {
            Some(job) => admitted.contains(&(job, lease)),
            None => true,
        });
        for grant in &fresh {
            let Some(job) = grant.id.job() else {
                continue;
            };
            let Some(class) = self.coordinator.job_class(job) else {
                continue;
            };
            let Some(operation) = self.coordinator.job_operation(job) else {
                continue;
            };
            self.admitted.insert((job, grant.lease));
            let batch = self.batch_of(job);
            self.admissions.push(Admission {
                at: grant.admitted,
                job,
                class,
                operation,
                entry: grant.path.clone(),
                batch,
                reserved: grant.reserved,
                lease: grant.lease,
                operations: grant.operations,
                domain: grant.domain,
                origin: grant.origin,
            });
        }
        self.grant_buffer = fresh;
    }

    fn batch_of(&mut self, job: JobId) -> usize {
        if self.batch_members.contains(&job) {
            return self.batch_index;
        }
        self.batch_index += 1;
        self.batch_members = self.coordinator.open_batch().map(|view| view.members).unwrap_or_default();
        self.batch_members.insert(job);
        self.batch_index
    }

    fn begin_work(&mut self, spec: &JobSpec) {
        self.settle_work(spec.id);
        let job = spec.id;
        let path = spec.path.clone();
        self.dispatches.push(match &spec.work {
            Work::Listing(listing) => Dispatched::Listing { job, path, operations: listing.lease.operations },
            Work::Enrichment { batch } => Dispatched::Enrichment { job, path, children: batch.children.len() },
            Work::Metadata => Dispatched::Metadata { job, path },
            Work::ResolveDomain { .. } => Dispatched::Domain { job, path },
        });
        let cost = match &spec.work {
            Work::Listing(listing) => {
                let skip = self.entries_seen.get(&spec.id).copied().unwrap_or(0);
                self.fs.lease_cost(&spec.path, !listing.resume, skip, listing.lease.entries, listing.lease.operations)
            }
            Work::Metadata => self.fs.cost_of(FakeOp::Metadata, &spec.path),
            Work::ResolveDomain { .. } => self.fs.domain_resolution_cost(&spec.path),
            Work::Enrichment { batch } => self.fs.enrichment_cost(&spec.path, batch),
        };
        let domain = self.fs.domain_of(&spec.path);
        let due = self.now + cost;
        self.job_domain.insert(spec.id, domain);
        self.running.insert(spec.id, Running { started: self.now, due, domain });
        self.schedule.insert((due, Scheduled::Job(spec.id)));
    }

    fn forget_registration(&mut self, request: WatchRequestId) {
        if let Some(due) = self.registration_due.remove(&request) {
            self.schedule.remove(&(due, Scheduled::Registration(request)));
        }
    }

    fn registration_ready(&self, request: WatchRequestId) -> bool {
        self.registration_due.get(&request).is_none_or(|due| *due <= self.now)
    }

    fn drop_session(&mut self, job: JobId) {
        self.sessions.remove(&job);
        self.entries_seen.remove(&job);
    }

    pub fn held_listing_sessions(&self) -> usize {
        self.sessions.values().filter(|slot| matches!(slot, SessionSlot::Open(_))).count()
    }

    fn settle_work(&mut self, job: JobId) {
        let Some(run) = self.running.remove(&job) else {
            return;
        };
        self.schedule.remove(&(run.due, Scheduled::Job(job)));
        let cost = self.now.since(run.started);
        if !cost.is_zero() {
            self.charges.push(Charge { at: self.now, job, domain: run.domain, cost });
        }
    }

    pub fn admissions(&self) -> Vec<Admission> {
        self.admissions.clone()
    }

    pub fn dispatches(&self) -> Vec<Dispatched> {
        self.dispatches.clone()
    }

    pub fn charges(&self) -> Vec<Charge> {
        self.charges.clone()
    }

    pub fn charged_work(&self) -> Duration {
        self.charges.iter().map(|c| c.cost).sum()
    }

    pub fn reserved_between(&self, from: MonotonicTime, to: MonotonicTime) -> Duration {
        self.admissions.iter().filter(|a| a.at > from && a.at <= to).map(|a| a.reserved).sum()
    }

    pub fn worst_reserved_window(&self, window: Duration) -> (MonotonicTime, Duration) {
        self.worst_reserved_window_of(window, None)
    }

    pub fn worst_reserved_window_of(&self, window: Duration, origin: Option<WorkOrigin>) -> (MonotonicTime, Duration) {
        let admissions: Vec<&Admission> =
            self.admissions.iter().filter(|a| origin.is_none_or(|origin| a.origin == origin)).collect();
        let mut worst = (MonotonicTime::ZERO, Duration::ZERO);
        let mut oldest = 0;
        let mut total = Duration::ZERO;
        for index in 0..admissions.len() {
            let end = admissions[index].at;
            total += admissions[index].reserved;
            while admissions[oldest].at.0 + window <= end.0 {
                total -= admissions[oldest].reserved;
                oldest += 1;
            }
            if total > worst.1 {
                worst = (end, total);
            }
        }
        worst
    }

    pub fn governor(&self) -> crate::core::GovernorView {
        self.coordinator.governor()
    }

    pub fn charged_work_by_domain(&self) -> BTreeMap<DomainId, Duration> {
        let mut totals: BTreeMap<DomainId, Duration> = BTreeMap::new();
        for charge in &self.charges {
            *totals.entry(charge.domain).or_default() += charge.cost;
        }
        totals
    }

    pub fn domain_of(&self, job: JobId) -> Option<DomainId> {
        self.job_domain.get(&job).copied()
    }

    pub fn command(&mut self, command: Command) -> Ticket {
        let id = CommandId::new(self.next_command);
        self.next_command += 1;
        self.feed(Input::Command { id, command });
        Ticket(id)
    }

    pub fn result(&self, ticket: Ticket) -> Option<Result<(), Error>> {
        self.results.get(&ticket.0).cloned()
    }

    pub fn pending_jobs(&self) -> Vec<JobSpec> {
        self.jobs.iter().cloned().collect()
    }

    pub fn pending_job_for(&self, p: &str) -> Option<JobSpec> {
        let path = FakeFileSystem::path(p);
        self.jobs.iter().find(|j| j.path == path).cloned()
    }

    pub fn complete_job(&mut self, id: JobId) -> bool {
        let Some(index) = self.jobs.iter().position(|j| j.id == id) else {
            return false;
        };
        let Some(spec) = self.jobs.remove(index) else {
            return false;
        };
        let result = self.perform(&spec);
        self.settle_work(spec.id);
        self.feed(Input::JobCompleted { job: spec.id, result });
        true
    }

    fn perform(&mut self, spec: &JobSpec) -> JobResult {
        match &spec.work {
            Work::Listing(listing) => {
                let fs = self.fs.clone();
                let existing = match self.sessions.remove(&spec.id) {
                    Some(SessionSlot::Open(session)) => Some(session),
                    Some(SessionSlot::Cancelled) | None => None,
                };
                let session = existing.unwrap_or_else(|| {
                    fs.open_listing(fs.root(), &spec.path, listing.ceilings, listing.cancel.clone())
                });
                let (continuation, cost) = session.resume(listing.lease);
                *self.entries_seen.entry(spec.id).or_default() +=
                    usize::try_from(cost.entries_enumerated).unwrap_or(usize::MAX);
                let step = match continuation {
                    Continuation::Suspended(session) => {
                        let cancelled = matches!(self.sessions.get(&spec.id), Some(SessionSlot::Cancelled));
                        if cancelled || listing.cancel.is_cancelled() {
                            drop(session);
                        } else {
                            self.sessions.insert(spec.id, SessionSlot::Open(session));
                        }
                        SessionStep::suspended(cost)
                    }
                    Continuation::Finished(outcome) => {
                        self.entries_seen.remove(&spec.id);
                        SessionStep::finished(cost, outcome)
                    }
                };
                JobResult::Listing(step)
            }
            Work::Metadata => JobResult::Metadata(self.fs.metadata(self.fs.root(), &spec.path)),
            Work::ResolveDomain { parent } => {
                JobResult::Domain(self.fs.resolve_domain(self.fs.root(), &spec.path, parent.as_deref()))
            }
            Work::Enrichment { batch } => JobResult::Enrichment(self.fs.enrich(self.fs.root(), &spec.path, batch)),
        }
    }

    pub fn complete_job_with(&mut self, id: JobId, result: JobResult) -> bool {
        let Some(index) = self.jobs.iter().position(|j| j.id == id) else {
            return false;
        };
        self.jobs.remove(index);
        self.drop_session(id);
        self.settle_work(id);
        self.feed(Input::JobCompleted { job: id, result });
        true
    }

    pub fn lose_job(&mut self, id: JobId) -> bool {
        let Some(index) = self.jobs.iter().position(|j| j.id == id) else {
            return false;
        };
        self.jobs.remove(index);
        self.drop_session(id);
        self.settle_work(id);
        self.feed(Input::WorkerLost(WorkerLoss::Job(id)));
        true
    }

    pub fn outstanding_jobs(&self) -> Vec<JobSpec> {
        self.outstanding.iter().cloned().collect()
    }

    pub fn complete_outstanding_job(&mut self, id: JobId) -> bool {
        let Some(index) = self.outstanding.iter().position(|j| j.id == id) else {
            return false;
        };
        let Some(spec) = self.outstanding.remove(index) else {
            return false;
        };
        let result = self.perform(&spec);
        self.settle_work(spec.id);
        self.feed(Input::JobCompleted { job: spec.id, result });
        true
    }

    pub fn lose_outstanding_job(&mut self, id: JobId) -> bool {
        let Some(index) = self.outstanding.iter().position(|j| j.id == id) else {
            return false;
        };
        self.outstanding.remove(index);
        self.drop_session(id);
        self.settle_work(id);
        self.feed(Input::WorkerLost(WorkerLoss::Job(id)));
        true
    }

    fn release_outstanding(&mut self) -> usize {
        let mut count = 0;
        while let Some(id) = self.outstanding.front().map(|j| j.id) {
            if !self.lose_outstanding_job(id) {
                break;
            }
            count += 1;
        }
        count
    }

    pub fn lose_registration(&mut self, request: WatchRequestId) -> bool {
        let Some(index) = self.registrations.iter().position(|(r, _, _)| *r == request) else {
            return false;
        };
        self.registrations.remove(index);
        self.forget_registration(request);
        self.feed(Input::WorkerLost(WorkerLoss::WatchRegistration(request)));
        true
    }

    pub fn complete_next_job(&mut self) -> bool {
        match self.jobs.front().map(|j| j.id) {
            Some(id) => self.complete_job(id),
            None => false,
        }
    }

    pub fn complete_all_jobs(&mut self) -> usize {
        let mut count = 0;
        while self.complete_next_job() {
            count += 1;
        }
        count
    }

    pub fn pending_registrations(&self) -> Vec<(WatchRequestId, RelativePath, bool)> {
        self.registrations.iter().cloned().collect()
    }

    pub fn take_registration(&mut self, p: &str) -> Option<(WatchRequestId, RelativePath, bool)> {
        let path = FakeFileSystem::path(p);
        let index = self.registrations.iter().position(|(_, q, _)| *q == path)?;
        let taken = self.registrations.remove(index)?;
        self.forget_registration(taken.0);
        Some(taken)
    }

    pub fn complete_registration(&mut self, request: WatchRequestId, path: &RelativePath, recursive: bool) {
        self.forget_registration(request);
        let result = self.fs.watch(self.fs.root(), path, recursive, self.sink.clone());
        self.feed(Input::WatchRegistered { request, result });
    }

    pub fn pending_releases(&self) -> Vec<(WatchReleaseId, WatchId)> {
        self.releases.iter().copied().collect()
    }

    pub fn complete_release(&mut self, release: WatchReleaseId) -> bool {
        let Some(index) = self.releases.iter().position(|(held, _)| *held == release) else {
            return false;
        };
        let Some((release, watch)) = self.releases.remove(index) else {
            return false;
        };
        self.fs.unwatch(watch);
        self.feed(Input::WatchReleased { release });
        true
    }

    pub fn complete_releases(&mut self) -> usize {
        let mut count = 0;
        while let Some((release, _)) = self.releases.front().copied() {
            if !self.complete_release(release) {
                break;
            }
            count += 1;
        }
        count
    }

    pub fn complete_registrations(&mut self) -> usize {
        let mut count = 0;
        loop {
            let next = self
                .registrations
                .iter()
                .position(|(request, _, _)| self.registration_ready(*request))
                .and_then(|index| self.registrations.remove(index));
            let Some((request, path, recursive)) = next else {
                break;
            };
            self.complete_registration(request, &path, recursive);
            count += 1;
        }
        count
    }

    pub fn deliver_watcher_events(&mut self) -> usize {
        let mut count = 0;
        loop {
            let next = self.sink.queue.lock().ok().and_then(|mut q| q.pop_front());
            let Some(event) = next else { break };
            self.feed(Input::Watcher(event));
            count += 1;
        }
        count
    }

    pub fn deliver_watcher_events_capped(&mut self, limit: usize) -> usize {
        let mut count = 0;
        while count < limit {
            let next = self.sink.queue.lock().ok().and_then(|mut q| q.pop_front());
            let Some(event) = next else { break };
            self.feed(Input::Watcher(event));
            count += 1;
        }
        count
    }

    pub fn inject_watcher_event(&mut self, event: WatcherEvent) {
        self.feed(Input::Watcher(event));
    }

    pub fn advance_to_next_completion(&mut self) -> bool {
        let Some((due, scheduled)) = self.schedule.iter().next().copied() else {
            return false;
        };
        self.advance_injected(due);
        match scheduled {
            Scheduled::Job(id) => {
                if self.complete_job(id) || self.complete_outstanding_job(id) {
                    return true;
                }
                self.settle_work(id);
            }
            Scheduled::Registration(request) => {
                let pending = self
                    .registrations
                    .iter()
                    .position(|(held, _, _)| *held == request)
                    .and_then(|index| self.registrations.remove(index));
                match pending {
                    Some((request, path, recursive)) => self.complete_registration(request, &path, recursive),
                    None => self.forget_registration(request),
                }
            }
        }
        true
    }

    fn step(&mut self, target: MonotonicTime, fired: &mut Option<MonotonicTime>) -> bool {
        if self.auto_register {
            self.complete_registrations();
        }
        if self.auto_release {
            self.complete_releases();
        }
        self.deliver_watcher_events();
        let job = self.schedule.iter().next().map(|(due, _)| *due).filter(|due| *due <= target);
        let timer = self.timer.map(|(_, at)| at).filter(|at| *at <= target && Some(*at) != *fired);
        match (job, timer) {
            (Some(j), Some(t)) if t < j => {
                *fired = Some(t);
                self.fire_timer_only()
            }
            (Some(_), _) => {
                *fired = None;
                self.advance_to_next_completion()
            }
            (None, Some(t)) => {
                *fired = Some(t);
                self.fire_timer_only()
            }
            (None, None) => false,
        }
    }

    fn drive(&mut self, target: MonotonicTime, mut before_step: impl FnMut(&mut Harness)) {
        let mut fired = None;
        for _ in 0..MAXIMUM_STEPS {
            before_step(self);
            if !self.step(target, &mut fired) {
                self.advance_injected(target);
                self.observe();
                if self.auto_register {
                    self.complete_registrations();
                }
                if self.auto_release {
                    self.complete_releases();
                }
                self.deliver_watcher_events();
                return;
            }
        }
        panic!("the harness took {MAXIMUM_STEPS} steps without reaching {target:?}");
    }

    pub fn run_jobs_until(&mut self, target: MonotonicTime) {
        self.drive(target, |_| {});
    }

    pub fn flood_hints_until(&mut self, paths: &[&str], kind: HintKind, target: MonotonicTime) -> usize {
        let owned: Vec<String> = paths.iter().map(|p| (*p).to_string()).collect();
        let mut emitted = 0;
        self.drive(target, |harness| {
            let borrowed: Vec<&str> = owned.iter().map(|p| p.as_str()).collect();
            emitted += harness.fs.emit_storm(&borrowed, kind, 1);
        });
        emitted
    }

    pub fn run_until_idle(&mut self) {
        let horizon = self.now + SETTLE_HORIZON;
        self.settle(horizon);
    }

    pub fn settle(&mut self, horizon: MonotonicTime) {
        for _ in 0..MAXIMUM_STEPS {
            let mut progress = 0;
            if self.auto_register {
                progress += self.complete_registrations();
            }
            if self.auto_release {
                progress += self.complete_releases();
            }
            progress += self.complete_all_jobs();
            progress += self.release_outstanding();
            progress += self.deliver_watcher_events();
            if progress > 0 {
                continue;
            }
            if !self.wait_for_capacity(horizon) {
                return;
            }
        }
        panic!("the harness took {MAXIMUM_STEPS} steps without settling");
    }

    fn wait_for_capacity(&mut self, horizon: MonotonicTime) -> bool {
        if !self.coordinator.throttled() {
            return false;
        }
        let Some((id, at)) = self.timer else {
            return false;
        };
        if at > horizon {
            return false;
        }
        if at <= self.now && self.waited_at == Some(self.now) {
            return false;
        }
        self.waited_at = Some(self.now.max(at));
        self.advance_injected(at);
        self.timer = None;
        self.feed(Input::Timer(id));
        true
    }

    pub fn advance(&mut self, duration: Duration) {
        let target = self.now + duration;
        loop {
            match self.timer {
                Some((id, at)) if at <= target => {
                    self.advance_injected(at);
                    self.timer = None;
                    self.feed(Input::Timer(id));
                    self.settle(target);
                }
                _ => break,
            }
        }
        self.advance_injected(target);
        self.observe();
        self.settle(target);
    }

    pub fn fire_timer_only(&mut self) -> bool {
        match self.timer {
            Some((id, at)) => {
                self.advance_injected(at);
                self.timer = None;
                self.feed(Input::Timer(id));
                true
            }
            None => false,
        }
    }

    pub fn fire_timer(&mut self) -> bool {
        match self.timer {
            Some((id, at)) => {
                self.advance_injected(at);
                self.timer = None;
                self.feed(Input::Timer(id));
                self.run_until_idle();
                true
            }
            None => false,
        }
    }

    pub fn run_round(&mut self) {
        let before = self.last_round();
        for _ in 0..10_000 {
            if !self.fire_timer() {
                break;
            }
            if self.last_round() != before {
                return;
            }
        }
        panic!("no reconciliation round completed");
    }

    pub fn timer(&self) -> Option<(TimerId, MonotonicTime)> {
        self.timer
    }

    pub fn snapshot(&self) -> Snapshot {
        self.coordinator.snapshot().clone()
    }

    pub fn health(&self) -> Health {
        self.coordinator.health()
    }

    pub fn last_round(&self) -> Option<(MonotonicTime, Duration)> {
        self.coordinator.last_round()
    }

    pub fn stats(&self) -> Stats {
        self.coordinator.stats()
    }

    pub fn events(&self) -> &[UpdateEvent] {
        &self.events
    }

    pub fn take_events(&mut self) -> Vec<UpdateEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn cancelled(&self) -> &[JobId] {
        &self.cancelled
    }

    pub fn unwatched(&self) -> &[WatchId] {
        &self.unwatched
    }

    pub fn stopped(&self) -> bool {
        self.stopped
    }

    pub fn paths(&self) -> Vec<String> {
        self.snapshot().entries().map(|e| e.path.to_string()).collect()
    }

    pub fn entry(&self, p: &str) -> Option<crate::entry::Entry> {
        self.snapshot().get(&FakeFileSystem::path(p)).cloned()
    }
}
