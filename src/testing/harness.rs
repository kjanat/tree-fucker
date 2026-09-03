use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::fake_fs::{DomainId, FakeFileSystem, FakeOp};
use crate::config::Config;
use crate::core::{
    Class, Command, Coordinator, Input, JobOperation, JobResult, JobSpec, MonotonicTime, Output, Stats, Work,
    WorkerLoss,
};
use crate::domain::StorageDomainId;
use crate::error::Error;
use crate::fs::{Continuation, FileSystem, HintKind, ListingSession, SessionStep, WatcherEvent};
use crate::ids::{CommandId, JobId, TimerId, WatchId, WatchRequestId};
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
    pub domain: Option<StorageDomainId>,
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
    jobs: VecDeque<JobSpec>,
    registrations: VecDeque<(WatchRequestId, RelativePath, bool)>,
    events: Vec<UpdateEvent>,
    results: HashMap<CommandId, Result<(), Error>>,
    next_command: u64,
    timer: Option<(TimerId, MonotonicTime)>,
    sink: Arc<Sink>,
    cancelled: Vec<JobId>,
    outstanding: VecDeque<JobSpec>,
    unwatched: Vec<WatchId>,
    stopped: bool,
    schedule: BTreeSet<(MonotonicTime, JobId)>,
    running: HashMap<JobId, Running>,
    job_domain: HashMap<JobId, DomainId>,
    charges: Vec<Charge>,
    admissions: Vec<Admission>,
    admitted: HashSet<(JobId, u32)>,
    sessions: HashMap<JobId, SessionSlot>,
    entries_seen: HashMap<JobId, usize>,
    batch_index: usize,
    batch_members: BTreeSet<JobId>,
    waited_at: Option<MonotonicTime>,
    pub auto_register: bool,
}

impl Harness {
    pub fn open(fs: Arc<FakeFileSystem>, policy: Arc<dyn ScanPolicy>, config: Config) -> Result<Harness, Error> {
        config.validate().map_err(Error::InvalidConfig)?;
        let root_info = fs.metadata(fs.root(), &RelativePath::root())?;
        let now = MonotonicTime::ZERO;
        let mut coordinator = Coordinator::new(config, policy, fs.capabilities(), root_info, now)?;
        let outputs = coordinator.take_outputs();
        let mut harness = Harness {
            fs,
            coordinator,
            now,
            jobs: VecDeque::new(),
            registrations: VecDeque::new(),
            events: Vec::new(),
            results: HashMap::new(),
            next_command: 1,
            timer: None,
            sink: Arc::new(Sink { queue: Mutex::new(VecDeque::new()) }),
            cancelled: Vec::new(),
            outstanding: VecDeque::new(),
            unwatched: Vec::new(),
            stopped: false,
            schedule: BTreeSet::new(),
            running: HashMap::new(),
            job_domain: HashMap::new(),
            charges: Vec::new(),
            admissions: Vec::new(),
            admitted: HashSet::new(),
            sessions: HashMap::new(),
            entries_seen: HashMap::new(),
            batch_index: 0,
            batch_members: BTreeSet::new(),
            waited_at: None,
            auto_register: true,
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
                    self.registrations.push_back((request, path, recursive))
                }
                Output::Unwatch(id) => {
                    self.unwatched.push(id);
                    self.fs.unwatch(id);
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
        for grant in self.coordinator.grants() {
            let Some(job) = grant.id.job() else {
                continue;
            };
            if self.admitted.contains(&(job, grant.lease)) {
                continue;
            }
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
                domain: grant.domain,
            });
        }
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
        let cost = match &spec.work {
            Work::Listing(listing) => {
                let skip = self.entries_seen.get(&spec.id).copied().unwrap_or(0);
                self.fs.lease_cost(&spec.path, !listing.resume, skip, listing.lease.entries)
            }
            Work::Metadata => self.fs.cost_of(FakeOp::Metadata, &spec.path),
            Work::ResolveDomain { .. } => self.fs.domain_resolution_cost(&spec.path),
            Work::Enrichment { .. } => self.fs.enrichment_cost(&spec.path),
        };
        let domain = self.fs.domain_of(&spec.path);
        let due = self.now + cost;
        self.job_domain.insert(spec.id, domain);
        self.running.insert(spec.id, Running { started: self.now, due, domain });
        self.schedule.insert((due, spec.id));
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
        self.schedule.remove(&(run.due, job));
        let cost = self.now.since(run.started);
        if !cost.is_zero() {
            self.charges.push(Charge { at: self.now, job, domain: run.domain, cost });
        }
    }

    pub fn admissions(&self) -> Vec<Admission> {
        self.admissions.clone()
    }

    pub fn charges(&self) -> Vec<Charge> {
        self.charges.clone()
    }

    pub fn charged_work(&self) -> Duration {
        self.charges.iter().map(|c| c.cost).sum()
    }

    pub fn charged_work_between(&self, from: MonotonicTime, to: MonotonicTime) -> Duration {
        self.charges.iter().filter(|c| c.at > from && c.at <= to).map(|c| c.cost).sum()
    }

    pub fn reserved_between(&self, from: MonotonicTime, to: MonotonicTime) -> Duration {
        self.admissions.iter().filter(|a| a.at > from && a.at <= to).map(|a| a.reserved).sum()
    }

    pub fn worst_reserved_window(&self, window: Duration) -> (MonotonicTime, Duration) {
        let mut worst = (MonotonicTime::ZERO, Duration::ZERO);
        let mut oldest = 0;
        let mut total = Duration::ZERO;
        for index in 0..self.admissions.len() {
            let end = self.admissions[index].at;
            total += self.admissions[index].reserved;
            while self.admissions[oldest].at.0 + window <= end.0 {
                total -= self.admissions[oldest].reserved;
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
                let session = existing
                    .unwrap_or_else(|| fs.open_listing(fs.root(), &spec.path, listing.ceiling, listing.cancel.clone()));
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
            Work::Enrichment { fields } => JobResult::Enrichment(self.fs.enrich(self.fs.root(), &spec.path, *fields)),
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
        self.registrations.remove(index)
    }

    pub fn complete_registration(&mut self, request: WatchRequestId, path: &RelativePath, recursive: bool) {
        let result = self.fs.watch(self.fs.root(), path, recursive, self.sink.clone());
        self.feed(Input::WatchRegistered { request, result });
    }

    pub fn complete_registrations(&mut self) -> usize {
        let mut count = 0;
        while let Some((request, path, recursive)) = self.registrations.pop_front() {
            let result = self.fs.watch(self.fs.root(), &path, recursive, self.sink.clone());
            self.feed(Input::WatchRegistered { request, result });
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
        let Some((due, id)) = self.schedule.iter().next().copied() else {
            return false;
        };
        self.now = self.now.max(due);
        if self.complete_job(id) || self.complete_outstanding_job(id) {
            return true;
        }
        self.settle_work(id);
        true
    }

    fn step(&mut self, target: MonotonicTime, fired: &mut Option<MonotonicTime>) -> bool {
        if self.auto_register {
            self.complete_registrations();
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
                self.now = self.now.max(target);
                self.observe();
                if self.auto_register {
                    self.complete_registrations();
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
        if !self.stats().resource.is_throttled() {
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
        self.now = self.now.max(at);
        self.timer = None;
        self.feed(Input::Timer(id));
        true
    }

    pub fn advance(&mut self, duration: Duration) {
        let target = self.now + duration;
        loop {
            match self.timer {
                Some((id, at)) if at <= target => {
                    self.now = self.now.max(at);
                    self.timer = None;
                    self.feed(Input::Timer(id));
                    self.settle(target);
                }
                _ => break,
            }
        }
        self.now = target;
        self.observe();
        self.settle(target);
    }

    pub fn fire_timer_only(&mut self) -> bool {
        match self.timer {
            Some((id, at)) => {
                self.now = self.now.max(at);
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
                self.now = self.now.max(at);
                self.timer = None;
                self.feed(Input::Timer(id));
                self.run_until_idle();
                true
            }
            None => false,
        }
    }

    pub fn run_round(&mut self) {
        let before = self.stats().last_round;
        for _ in 0..10_000 {
            if !self.fire_timer() {
                break;
            }
            if self.stats().last_round != before {
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
