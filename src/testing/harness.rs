use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::Config;
use crate::core::{Command, Coordinator, Input, JobOperation, JobResult, JobSpec, MonotonicTime, Output, Stats};
use crate::error::Error;
use crate::fs::{FileSystem, WatcherEvent};
use crate::ids::{CommandId, JobId, TimerId, WatchId, WatchRequestId};
use crate::path::RelativePath;
use crate::policy::ScanPolicy;
use crate::snapshot::Snapshot;
use crate::update::{Health, UpdateEvent};

use super::fake_fs::FakeFileSystem;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ticket(pub CommandId);

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
    unwatched: Vec<WatchId>,
    stopped: bool,
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
            unwatched: Vec::new(),
            stopped: false,
            auto_register: true,
        };
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
                Output::StartJob(spec) => self.jobs.push_back(spec),
                Output::CancelJob(id) => {
                    self.cancelled.push(id);
                    self.jobs.retain(|j| j.id != id);
                }
                Output::RegisterWatch { request, path, recursive } => {
                    self.registrations.push_back((request, path, recursive))
                }
                Output::Unwatch(id) => {
                    self.unwatched.push(id);
                    self.fs.unwatch(id);
                }
                Output::Publish(event) => self.events.push(event),
                Output::CommandFinished { id, result } => {
                    self.results.insert(id, result);
                }
                Output::SetTimer { id, at } => self.timer = Some((id, at)),
                Output::Stopped => self.stopped = true,
            }
        }
    }

    fn feed(&mut self, input: Input) {
        let now = self.now;
        let outputs = self.coordinator.handle(input, now);
        self.process(outputs);
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
        let result = match spec.operation {
            JobOperation::Listing => JobResult::Listing(self.fs.read_dir(self.fs.root(), &spec.path)),
            JobOperation::Metadata => JobResult::Metadata(self.fs.metadata(self.fs.root(), &spec.path)),
        };
        self.feed(Input::JobCompleted { job: spec.id, result });
        true
    }

    pub fn complete_job_with(&mut self, id: JobId, result: JobResult) -> bool {
        let Some(index) = self.jobs.iter().position(|j| j.id == id) else {
            return false;
        };
        self.jobs.remove(index);
        self.feed(Input::JobCompleted { job: id, result });
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

    pub fn inject_watcher_event(&mut self, event: WatcherEvent) {
        self.feed(Input::Watcher(event));
    }

    pub fn run_until_idle(&mut self) {
        loop {
            let mut progress = 0;
            if self.auto_register {
                progress += self.complete_registrations();
            }
            progress += self.complete_all_jobs();
            progress += self.deliver_watcher_events();
            if progress == 0 {
                break;
            }
        }
    }

    pub fn advance(&mut self, duration: Duration) {
        let target = self.now + duration;
        loop {
            match self.timer {
                Some((id, at)) if at <= target => {
                    self.now = self.now.max(at);
                    self.timer = None;
                    self.feed(Input::Timer(id));
                    self.run_until_idle();
                }
                _ => break,
            }
        }
        self.now = target;
        self.run_until_idle();
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
