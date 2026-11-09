//! This module drives the coordinator step by step for tests.
//!
//! [`Harness`] feeds commands, job results, watcher events, and timers to a
//! [`Coordinator`] on injected time, with no runtime or threads. Tests
//! decide when each job completes. They inspect every admission, dispatch,
//! and charge of the coordinator (RFC §17.1, §17.5).

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

/// `Ticket` identifies a command from [`Harness::command`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ticket(pub CommandId);

/// `Admission` records one governor grant for a job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    /// `at` holds the injected time of the grant.
    pub at: MonotonicTime,
    /// `job` identifies the admitted job.
    pub job: JobId,
    /// `class` names the scheduling class of the job.
    pub class: Class,
    /// `operation` names the operation of the job.
    pub operation: JobOperation,
    /// `entry` holds the path of the grant.
    pub entry: RelativePath,
    /// `batch` numbers the closed batch of the job, counted from 1.
    pub batch: usize,
    /// `reserved` holds the reserved worker time of the grant.
    pub reserved: Duration,
    /// `lease` numbers the lease within the job.
    pub lease: u32,
    /// `operations` counts the permitted per-child operations.
    pub operations: u32,
    /// `domain` names the charged storage domain, or holds `None`.
    pub domain: Option<StorageDomainId>,
    /// `origin` gives the background or foreground origin of the grant.
    pub origin: WorkOrigin,
}

/// `Dispatched` records one job start of the coordinator.
///
/// The harness keeps these records in start order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dispatched {
    /// `Listing` records a listing lease.
    Listing {
        /// `job` identifies the job of the lease.
        job: JobId,
        /// `path` locates the listed directory.
        path: RelativePath,
        /// `operations` counts the permitted per-child operations.
        operations: usize,
    },
    /// `Enrichment` records a metadata enrichment batch.
    Enrichment {
        /// `job` identifies the job of the batch.
        job: JobId,
        /// `path` locates the parent directory of the enriched children.
        path: RelativePath,
        /// `children` counts the children in the batch.
        children: usize,
    },
    /// `Metadata` records a metadata read.
    Metadata {
        /// `job` identifies the job of the read.
        job: JobId,
        /// `path` locates the read target.
        path: RelativePath,
    },
    /// `Domain` records a storage-domain resolution.
    Domain {
        /// `job` identifies the job of the resolution.
        job: JobId,
        /// `path` locates the resolved directory.
        path: RelativePath,
    },
}

impl Dispatched {
    /// `path` returns the target path of the job.
    pub fn path(&self) -> &RelativePath {
        match self {
            Dispatched::Listing { path, .. }
            | Dispatched::Enrichment { path, .. }
            | Dispatched::Metadata { path, .. }
            | Dispatched::Domain { path, .. } => path,
        }
    }

    /// `job` returns the job identifier.
    pub fn job(&self) -> JobId {
        match self {
            Dispatched::Listing { job, .. }
            | Dispatched::Enrichment { job, .. }
            | Dispatched::Metadata { job, .. }
            | Dispatched::Domain { job, .. } => *job,
        }
    }
}

/// `Charge` records the simulated worker time of one job lease.
///
/// The harness records it when the lease ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Charge {
    /// `at` holds the injected end time of the lease.
    pub at: MonotonicTime,
    /// `job` identifies the job of the lease.
    pub job: JobId,
    /// `domain` names the fake domain of the job path.
    pub domain: DomainId,
    /// `cost` holds the injected time from the start to the end of the lease.
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

/// `Harness` drives one [`Coordinator`] over a [`FakeFileSystem`].
///
/// The harness keeps its own injected clock, and the clock starts at zero.
/// A started job becomes due after its simulated cost elapses. Tests
/// complete jobs by hand, or the drive methods complete them in due order.
/// Nothing sleeps, and jobs run on the calling thread.
///
/// Drive methods complete ready watch registrations and releases while
/// [`Harness::auto_register`] and [`Harness::auto_release`] are true.
/// Several methods panic after one million steps without settling.
pub struct Harness {
    /// `fs` holds the fake filesystem of the jobs.
    pub fs: Arc<FakeFileSystem>,
    /// `coordinator` holds the coordinator under test.
    pub coordinator: Coordinator,
    host: HostGovernor,
    governor_seen: u64,
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
    /// `auto_register` lets drive methods complete ready registrations.
    ///
    /// It defaults to true.
    pub auto_register: bool,
    /// `auto_release` lets drive methods complete pending watch releases.
    ///
    /// It defaults to true.
    pub auto_release: bool,
}

impl Harness {
    /// `open` opens a harness under an independent default governor.
    ///
    /// It fails with [`Error::InvalidConfig`] for an invalid `config`. It
    /// also fails with the root metadata error or the coordinator's open
    /// failure.
    pub fn open(fs: Arc<FakeFileSystem>, policy: Arc<dyn ScanPolicy>, config: Config) -> Result<Harness, Error> {
        Harness::open_with_host(fs, policy, HostConfig::default(), config)
    }

    /// `open_with_host` opens a harness under an independent governor.
    ///
    /// The governor uses the `host` limits.
    pub fn open_with_host(
        fs: Arc<FakeFileSystem>,
        policy: Arc<dyn ScanPolicy>,
        host: HostConfig,
        config: Config,
    ) -> Result<Harness, Error> {
        host.validate().map_err(Error::InvalidConfig)?;
        Harness::open_under(fs, policy, config, HostGovernor::independent(&host))
    }

    /// `open_under` opens a harness under `governor`.
    ///
    /// Other harnesses may share the governor. The harness reads the root
    /// metadata directly and completes the root watch registration before it
    /// returns.
    pub fn open_under(
        fs: Arc<FakeFileSystem>,
        policy: Arc<dyn ScanPolicy>,
        config: Config,
        governor: HostGovernor,
    ) -> Result<Harness, Error> {
        config.validate().map_err(Error::InvalidConfig)?;
        let root_info = fs.metadata(fs.root(), &RelativePath::root())?;
        let now = MonotonicTime::ZERO;
        let host = governor.clone();
        let governor_seen = host.changes();
        let mut coordinator = Coordinator::new(config, policy, fs.capabilities(), root_info, now, governor)?;
        let outputs = coordinator.take_outputs();
        let mut harness = Harness {
            fs,
            coordinator,
            host,
            governor_seen,
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

    /// `open_default` opens a harness with the default [`Config`].
    ///
    /// # Panics
    ///
    /// `open_default` panics when opening fails.
    pub fn open_default(fs: Arc<FakeFileSystem>, policy: Arc<dyn ScanPolicy>) -> Harness {
        Harness::open(fs, policy, Config::default()).expect("open")
    }

    fn advance_injected(&mut self, at: MonotonicTime) {
        let next = self.now.max(at);
        self.injected += next.since(self.now);
        self.now = next;
    }

    /// `injected` returns the injected time since opening.
    pub fn injected(&self) -> Duration {
        self.injected
    }

    /// `real_elapsed` returns the wall-clock time since opening.
    pub fn real_elapsed(&self) -> Duration {
        self.opened_at.elapsed()
    }

    /// `now` returns the current injected time.
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
        self.follow_governor();
        let now = self.now;
        let outputs = self.coordinator.handle(input, now);
        self.record_grants();
        self.process(outputs);
        self.follow_governor();
    }

    fn follow_governor(&mut self) {
        for _ in 0..MAXIMUM_STEPS {
            let generation = self.host.changes();
            if generation == self.governor_seen {
                return;
            }
            self.governor_seen = generation;
            let now = self.now;
            let outputs = self.coordinator.observe(now);
            self.record_grants();
            self.process(outputs);
        }
        panic!("the governor changed {MAXIMUM_STEPS} times without settling");
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

    /// `held_listing_sessions` counts the suspended listing sessions.
    ///
    /// A session suspends between leases.
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

    /// `admissions` returns every job grant since opening, in grant order.
    pub fn admissions(&self) -> Vec<Admission> {
        self.admissions.clone()
    }

    /// `dispatches` returns every job start since opening, in start order.
    pub fn dispatches(&self) -> Vec<Dispatched> {
        self.dispatches.clone()
    }

    /// `charges` returns every nonzero worker-time charge.
    ///
    /// The charges appear in the order of their lease ends.
    pub fn charges(&self) -> Vec<Charge> {
        self.charges.clone()
    }

    /// `charged_work` returns the sum of every charge.
    pub fn charged_work(&self) -> Duration {
        self.charges.iter().map(|c| c.cost).sum()
    }

    /// `reserved_between` sums the reserved worker time between two times.
    ///
    /// It counts the grants after `from` and up to `to`.
    pub fn reserved_between(&self, from: MonotonicTime, to: MonotonicTime) -> Duration {
        self.admissions.iter().filter(|a| a.at > from && a.at <= to).map(|a| a.reserved).sum()
    }

    /// `worst_reserved_window` finds the busiest sliding `window`.
    ///
    /// The busiest window holds the most reserved worker time. The method
    /// returns the end of that window and its total. Tests compare the total
    /// against rate times window plus burst (RFC §15.3).
    pub fn worst_reserved_window(&self, window: Duration) -> (MonotonicTime, Duration) {
        self.worst_reserved_window_of(window, None)
    }

    /// `worst_reserved_window_of` finds the busiest `window` for one `origin`.
    ///
    /// `None` considers every grant.
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

    /// `governor` returns the governor view of the coordinator.
    pub fn governor(&self) -> crate::core::GovernorView {
        self.coordinator.governor()
    }

    /// `charged_work_by_domain` sums the charges for each fake domain.
    pub fn charged_work_by_domain(&self) -> BTreeMap<DomainId, Duration> {
        let mut totals: BTreeMap<DomainId, Duration> = BTreeMap::new();
        for charge in &self.charges {
            *totals.entry(charge.domain).or_default() += charge.cost;
        }
        totals
    }

    /// `domain_of` returns the fake domain of the start path of `job`.
    pub fn domain_of(&self, job: JobId) -> Option<DomainId> {
        self.job_domain.get(&job).copied()
    }

    /// `command` sends `command` to the coordinator at the current time.
    pub fn command(&mut self, command: Command) -> Ticket {
        let id = CommandId::new(self.next_command);
        self.next_command += 1;
        self.feed(Input::Command { id, command });
        Ticket(id)
    }

    /// `result` returns the result of a command.
    ///
    /// It returns `None` while the command is unfinished.
    pub fn result(&self, ticket: Ticket) -> Option<Result<(), Error>> {
        self.results.get(&ticket.0).cloned()
    }

    /// `pending_jobs` returns the started and unfinished jobs in start order.
    pub fn pending_jobs(&self) -> Vec<JobSpec> {
        self.jobs.iter().cloned().collect()
    }

    /// `pending_job_for` returns the first pending job for the path `p`.
    pub fn pending_job_for(&self, p: &str) -> Option<JobSpec> {
        let path = FakeFileSystem::path(p);
        self.jobs.iter().find(|j| j.path == path).cloned()
    }

    /// `complete_job` runs pending job `id` against the fake now.
    ///
    /// It feeds the result to the coordinator. It returns false when `id` is
    /// not pending.
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

    /// `complete_job_with` feeds `result` for pending job `id`.
    ///
    /// The fake stays untouched. The method returns false when `id` is not
    /// pending.
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

    /// `lose_job` reports pending job `id` as a lost worker (RFC §13.5).
    ///
    /// It returns false when `id` is not pending.
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

    /// `outstanding_jobs` returns the jobs of pending cancellations.
    ///
    /// The coordinator cancelled these jobs while they were pending. Their
    /// workers still hold slots until a test completes or loses them.
    pub fn outstanding_jobs(&self) -> Vec<JobSpec> {
        self.outstanding.iter().cloned().collect()
    }

    /// `complete_outstanding_job` runs outstanding job `id` against the fake.
    ///
    /// It feeds the late result to the coordinator. It returns false when `id`
    /// is not outstanding.
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

    /// `lose_outstanding_job` reports outstanding job `id` as a lost worker.
    ///
    /// It returns false when `id` is not outstanding.
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

    /// `lose_registration` reports registration `request` as a lost worker.
    ///
    /// It returns false when `request` is not pending.
    pub fn lose_registration(&mut self, request: WatchRequestId) -> bool {
        let Some(index) = self.registrations.iter().position(|(r, _, _)| *r == request) else {
            return false;
        };
        self.registrations.remove(index);
        self.forget_registration(request);
        self.feed(Input::WorkerLost(WorkerLoss::WatchRegistration(request)));
        true
    }

    /// `complete_next_job` completes the oldest pending job.
    ///
    /// It returns false without a pending job.
    pub fn complete_next_job(&mut self) -> bool {
        match self.jobs.front().map(|j| j.id) {
            Some(id) => self.complete_job(id),
            None => false,
        }
    }

    /// `complete_all_jobs` completes pending jobs until none remain.
    ///
    /// The loop also completes newly started jobs. Injected time stays still.
    /// The method returns the number of completed jobs.
    pub fn complete_all_jobs(&mut self) -> usize {
        let mut count = 0;
        while self.complete_next_job() {
            count += 1;
        }
        count
    }

    /// `pending_registrations` returns the pending registrations.
    ///
    /// Each item holds the request, the path, and the recursive flag.
    pub fn pending_registrations(&self) -> Vec<(WatchRequestId, RelativePath, bool)> {
        self.registrations.iter().cloned().collect()
    }

    /// `take_registration` removes the pending registration for `p`.
    ///
    /// It leaves the registration incomplete. The test completes it later with
    /// [`Harness::complete_registration`].
    pub fn take_registration(&mut self, p: &str) -> Option<(WatchRequestId, RelativePath, bool)> {
        let path = FakeFileSystem::path(p);
        let index = self.registrations.iter().position(|(_, q, _)| *q == path)?;
        let taken = self.registrations.remove(index)?;
        self.forget_registration(taken.0);
        Some(taken)
    }

    /// `complete_registration` registers the watch on the fake.
    ///
    /// It feeds the result for `request` to the coordinator.
    pub fn complete_registration(&mut self, request: WatchRequestId, path: &RelativePath, recursive: bool) {
        self.forget_registration(request);
        let result = self.fs.watch(self.fs.root(), path, recursive, self.sink.clone());
        self.feed(Input::WatchRegistered { request, result });
    }

    /// `pending_releases` returns the pending watch releases.
    ///
    /// Each item pairs a release with its watch.
    pub fn pending_releases(&self) -> Vec<(WatchReleaseId, WatchId)> {
        self.releases.iter().copied().collect()
    }

    /// `complete_release` completes the pending release `release`.
    ///
    /// It removes the watch from the fake and feeds the release. It returns
    /// false when `release` is not pending.
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

    /// `complete_releases` completes every pending release.
    ///
    /// It returns the number of completed releases.
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

    /// `complete_registrations` completes every due registration.
    ///
    /// A registration becomes due after its Watch cost elapses. The method
    /// returns the number of completed registrations.
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

    /// `deliver_watcher_events` feeds every queued watcher event.
    ///
    /// It returns the number of fed events.
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

    /// `deliver_watcher_events_capped` feeds at most `limit` queued events.
    ///
    /// It returns the number of fed events.
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

    /// `inject_watcher_event` feeds `event` to the coordinator directly.
    ///
    /// The event bypasses the watches of the fake.
    pub fn inject_watcher_event(&mut self, event: WatcherEvent) {
        self.feed(Input::Watcher(event));
    }

    /// `advance_to_next_completion` completes the earliest due work.
    ///
    /// It advances to the earliest due job or registration and completes it.
    /// It returns false when nothing is scheduled.
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
                self.follow_governor();
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

    /// `run_jobs_until` completes jobs and fires timers up to `target`.
    ///
    /// It works in time order, and injected time ends at `target`.
    pub fn run_jobs_until(&mut self, target: MonotonicTime) {
        self.drive(target, |_| {});
    }

    /// `flood_hints_until` drives the harness and sends watcher hints at every
    /// step.
    ///
    /// It drives like [`Harness::run_jobs_until`]. Before each step it sends
    /// one hint of `kind` for all of `paths`. It returns the number of sent
    /// hints.
    pub fn flood_hints_until(&mut self, paths: &[&str], kind: HintKind, target: MonotonicTime) -> usize {
        let owned: Vec<String> = paths.iter().map(|p| (*p).to_string()).collect();
        let mut emitted = 0;
        self.drive(target, |harness| {
            let borrowed: Vec<&str> = owned.iter().map(|p| p.as_str()).collect();
            emitted += harness.fs.emit_storm(&borrowed, kind, 1);
        });
        emitted
    }

    /// `run_until_idle` settles with a horizon one hour ahead.
    pub fn run_until_idle(&mut self) {
        let horizon = self.now + SETTLE_HORIZON;
        self.settle(horizon);
    }

    /// `settle` completes all ready work and fires throttle timers.
    ///
    /// Jobs complete at the current time regardless of their cost, and the
    /// harness reports outstanding jobs as lost. Time advances only to fire a
    /// timer while the coordinator is throttled, and never past `horizon`.
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

    /// `advance` moves injected time forward by `duration`.
    ///
    /// It fires due timers and settles after each one.
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
        self.follow_governor();
        self.settle(target);
    }

    /// `fire_timer_only` advances to the pending timer and fires it.
    ///
    /// It skips settling. It returns false when no timer is pending.
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

    /// `fire_timer` fires the pending timer and runs until idle.
    ///
    /// It returns false when no timer is pending.
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

    /// `run_round` fires timers until a reconciliation round completes.
    ///
    /// # Panics
    ///
    /// `run_round` panics when timers run out. It also panics after 10000
    /// timers without a completed round.
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

    /// `timer` returns the pending timer and its due time.
    pub fn timer(&self) -> Option<(TimerId, MonotonicTime)> {
        self.timer
    }

    /// `snapshot` returns the current snapshot of the coordinator.
    pub fn snapshot(&self) -> Snapshot {
        self.coordinator.snapshot().clone()
    }

    /// `health` returns the current health of the coordinator.
    pub fn health(&self) -> Health {
        self.coordinator.health()
    }

    /// `last_round` returns the start and duration of the latest round.
    pub fn last_round(&self) -> Option<(MonotonicTime, Duration)> {
        self.coordinator.last_round()
    }

    /// `stats` returns the coordinator statistics.
    pub fn stats(&self) -> Stats {
        self.coordinator.stats()
    }

    /// `events` returns the published events since opening or the last take.
    pub fn events(&self) -> &[UpdateEvent] {
        &self.events
    }

    /// `take_events` removes and returns the published events.
    pub fn take_events(&mut self) -> Vec<UpdateEvent> {
        std::mem::take(&mut self.events)
    }

    /// `cancelled` returns every cancelled job in cancellation order.
    pub fn cancelled(&self) -> &[JobId] {
        &self.cancelled
    }

    /// `unwatched` returns every watch with a release request.
    pub fn unwatched(&self) -> &[WatchId] {
        &self.unwatched
    }

    /// `stopped` reports whether the coordinator stopped.
    pub fn stopped(&self) -> bool {
        self.stopped
    }

    /// `paths` returns every snapshot path in snapshot order.
    ///
    /// The root appears as `.`.
    pub fn paths(&self) -> Vec<String> {
        self.snapshot().entries().map(|e| e.path.to_string()).collect()
    }

    /// `entry` returns the snapshot entry at `p`.
    pub fn entry(&self, p: &str) -> Option<crate::entry::Entry> {
        self.snapshot().get(&FakeFileSystem::path(p)).cloned()
    }
}
