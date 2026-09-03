use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use futures_channel::{mpsc, oneshot};
use futures_core::Stream;
use futures_util::StreamExt;

use crate::config::{Config, LagMode};
use crate::core::{
    Command, Coordinator, Input, JobResult, MonotonicTime, Output, Stats, TerminalOutcome, Work, WorkerLoss,
};
use crate::error::{Error, Result};
use crate::fs::{Continuation, FileSystem, FsError, ListingSession, SessionStep, WatcherEvent, WatcherSink};
use crate::ids::{CommandId, JobId, WatchId, WatchRequestId};
use crate::path::RelativePath;
use crate::policy::ScanPolicy;
use crate::runtime::{BoxTaskHandle, Runtime};
use crate::snapshot::Snapshot;
use crate::update::{Health, RecoverableError, StreamError, UpdateEvent};

enum Message {
    Input(Input),
    WatcherReady,
}

enum RunPhase {
    Serving,
    ReleasingRegistrations,
}

#[derive(Clone, Copy)]
enum Lifecycle {
    Running,
    Stopped(TerminalOutcome),
}

struct StreamInner {
    queue: VecDeque<std::result::Result<UpdateEvent, StreamError>>,
    closed: bool,
    waker: Option<Waker>,
    capacity: usize,
    lag_mode: LagMode,
}

impl StreamInner {
    fn push(&mut self, event: UpdateEvent, latest: &Snapshot) {
        if self.closed {
            return;
        }
        if self.queue.len() >= self.capacity {
            self.lag(event, latest);
        } else {
            self.queue.push_back(Ok(event));
        }
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    fn lag(&mut self, event: UpdateEvent, latest: &Snapshot) {
        match self.lag_mode {
            LagMode::Disconnect => {
                let missed = self.queue.len() + 1;
                self.queue.clear();
                self.queue.push_back(Err(StreamError::Lagged { missed }));
                self.closed = true;
            }
            LagMode::Reset => {
                let mut errors: Vec<RecoverableError> = Vec::new();
                let mut terminal: Option<UpdateEvent> = None;
                for queued in self.queue.drain(..) {
                    match queued {
                        Ok(UpdateEvent::Delta(update)) => errors.extend(update.errors),
                        Ok(UpdateEvent::Health { errors: e, .. }) | Ok(UpdateEvent::Reset { errors: e, .. }) => {
                            errors.extend(e)
                        }
                        Ok(t @ UpdateEvent::Terminal { .. }) => terminal = Some(t),
                        Err(_) => {}
                    }
                }
                let (snapshot, health) = match &event {
                    UpdateEvent::Delta(update) => (update.snapshot.clone(), update.health.clone()),
                    UpdateEvent::Reset { snapshot, health, .. } => (snapshot.clone(), health.clone()),
                    UpdateEvent::Health { health, .. } => (latest.clone(), health.clone()),
                    UpdateEvent::Terminal { health } => (latest.clone(), health.clone()),
                };
                match event {
                    UpdateEvent::Delta(update) => errors.extend(update.errors),
                    UpdateEvent::Health { errors: e, .. } | UpdateEvent::Reset { errors: e, .. } => errors.extend(e),
                    t @ UpdateEvent::Terminal { .. } => terminal = Some(t),
                }
                let limit = self.capacity.max(1) * 16;
                let truncated_errors = errors.len().saturating_sub(limit);
                errors.truncate(limit);
                self.queue.push_back(Ok(UpdateEvent::Reset { snapshot, health, errors, truncated_errors }));
                if let Some(t) = terminal {
                    self.queue.push_back(Ok(t));
                }
            }
        }
    }

    fn close(&mut self) {
        self.closed = true;
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

pub struct UpdateStream {
    inner: Arc<Mutex<StreamInner>>,
}

impl UpdateStream {
    pub async fn next(&mut self) -> Option<std::result::Result<UpdateEvent, StreamError>> {
        StreamExt::next(self).await
    }
}

impl Stream for UpdateStream {
    type Item = std::result::Result<UpdateEvent, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut inner = lock(&self.inner);
        if let Some(item) = inner.queue.pop_front() {
            return Poll::Ready(Some(item));
        }
        if inner.closed {
            return Poll::Ready(None);
        }
        inner.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct Shared {
    snapshot: Mutex<Snapshot>,
    health: Mutex<Health>,
    stats: Mutex<Stats>,
    replies: Mutex<HashMap<CommandId, oneshot::Sender<Result<()>>>>,
    lifecycle: Mutex<Lifecycle>,
    next_command: AtomicU64,
    held_sessions: AtomicU64,
    tx: mpsc::UnboundedSender<Message>,
    stream: Arc<Mutex<StreamInner>>,
}

impl Shared {
    fn terminal_error(&self) -> Error {
        match *lock(&self.lifecycle) {
            Lifecycle::Stopped(TerminalOutcome::Terminated) => Error::TreeTerminated,
            Lifecycle::Stopped(TerminalOutcome::ShutDown) | Lifecycle::Running => Error::Shutdown,
        }
    }
}

struct Sink {
    queue: Mutex<VecDeque<WatcherEvent>>,
    dropped: AtomicU64,
    signalled: AtomicBool,
    capacity: usize,
    tx: mpsc::UnboundedSender<Message>,
}

impl WatcherSink for Sink {
    fn deliver(&self, event: WatcherEvent) {
        {
            let mut queue = lock(&self.queue);
            if queue.len() >= self.capacity {
                self.dropped.fetch_add(1, Ordering::SeqCst);
            } else {
                queue.push_back(event);
            }
        }
        if !self.signalled.swap(true, Ordering::SeqCst) {
            let _ = self.tx.unbounded_send(Message::WatcherReady);
        }
    }
}

struct WorkerGuard {
    loss: WorkerLoss,
    tx: Option<mpsc::UnboundedSender<Message>>,
}

impl WorkerGuard {
    fn new(loss: WorkerLoss, tx: mpsc::UnboundedSender<Message>) -> WorkerGuard {
        WorkerGuard { loss, tx: Some(tx) }
    }

    fn finish(mut self, input: Input) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.unbounded_send(Message::Input(input));
        }
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.unbounded_send(Message::Input(Input::WorkerLost(self.loss)));
        }
    }
}

struct Actor {
    coordinator: Coordinator,
    rx: mpsc::UnboundedReceiver<Message>,
    shared: Arc<Shared>,
    sink: Arc<Sink>,
    fs: Arc<dyn FileSystem>,
    runtime: Arc<dyn Runtime>,
    root: Arc<PathBuf>,
    base: Instant,
    workers: HashMap<JobId, BoxTaskHandle>,
    registrations: HashSet<WatchRequestId>,
    sessions: Arc<Mutex<HashMap<JobId, SessionSlot>>>,
}

enum SessionSlot {
    Open(Box<dyn ListingSession>),
    Cancelled,
}

impl Actor {
    fn now(&self) -> MonotonicTime {
        MonotonicTime(self.runtime.now().saturating_duration_since(self.base))
    }

    fn handle(&mut self, input: Input) -> Option<TerminalOutcome> {
        match &input {
            Input::JobCompleted { job, .. } => {
                self.workers.remove(job);
                Actor::forget_cancelled(&self.sessions, *job);
            }
            Input::WorkerLost(WorkerLoss::Job(job)) => {
                self.workers.remove(job);
                lock(&self.sessions).remove(job);
            }
            Input::WatchRegistered { request, .. } | Input::WorkerLost(WorkerLoss::WatchRegistration(request)) => {
                self.registrations.remove(request);
            }
            Input::Command { .. } | Input::Watcher(_) | Input::Timer(_) => {}
        }
        let now = self.now();
        let outputs = self.coordinator.handle(input, now);
        self.execute(outputs)
    }

    fn drain_watcher(&mut self) -> Option<TerminalOutcome> {
        self.sink.signalled.store(false, Ordering::SeqCst);
        loop {
            let next = lock(&self.sink.queue).pop_front();
            let Some(event) = next else { break };
            if let Some(outcome) = self.handle(Input::Watcher(event)) {
                return Some(outcome);
            }
        }
        let dropped = self.sink.dropped.swap(0, Ordering::SeqCst);
        if dropped > 0 {
            return self.handle(Input::Watcher(WatcherEvent::Dropped { count: dropped }));
        }
        None
    }

    fn execute(&mut self, outputs: Vec<Output>) -> Option<TerminalOutcome> {
        let mut stopped = None;
        for output in outputs {
            match output {
                Output::StartJob(spec) => {
                    let fs = self.fs.clone();
                    let root = self.root.clone();
                    let job = spec.id;
                    let sessions = self.sessions.clone();
                    let guard = WorkerGuard::new(WorkerLoss::Job(job), self.shared.tx.clone());
                    let handle = self.runtime.spawn_blocking(Box::new(move || {
                        let result = match spec.work {
                            Work::Listing(listing) => {
                                let existing = match lock(&sessions).remove(&job) {
                                    Some(SessionSlot::Open(session)) => Some(session),
                                    Some(SessionSlot::Cancelled) | None => None,
                                };
                                let cancel = listing.cancel.clone();
                                let session = existing.unwrap_or_else(|| {
                                    fs.open_listing(&root, &spec.path, listing.ceiling, listing.cancel)
                                });
                                let (continuation, cost) = session.resume(listing.lease);
                                let step = match continuation {
                                    Continuation::Suspended(session) => {
                                        let mut held = lock(&sessions);
                                        match held.get(&job) {
                                            Some(SessionSlot::Cancelled) => drop(session),
                                            _ if cancel.is_cancelled() => drop(session),
                                            _ => {
                                                held.insert(job, SessionSlot::Open(session));
                                            }
                                        }
                                        SessionStep::suspended(cost)
                                    }
                                    Continuation::Finished(outcome) => SessionStep::finished(cost, outcome),
                                };
                                JobResult::Listing(step)
                            }
                            Work::Metadata => JobResult::Metadata(fs.metadata(&root, &spec.path)),
                            Work::Enrichment { fields } => JobResult::Enrichment(fs.enrich(&root, &spec.path, fields)),
                        };
                        guard.finish(Input::JobCompleted { job, result });
                    }));
                    self.workers.insert(job, handle);
                }
                Output::CancelJob(id) => {
                    let mut sessions = lock(&self.sessions);
                    if sessions.remove(&id).is_none() && self.workers.contains_key(&id) {
                        sessions.insert(id, SessionSlot::Cancelled);
                    }
                    drop(sessions);
                    if let Some(handle) = self.workers.get(&id) {
                        handle.cancel();
                    }
                }
                Output::RegisterWatch { request, path, recursive } => {
                    let fs = self.fs.clone();
                    let root = self.root.clone();
                    let sink: Arc<dyn WatcherSink> = self.sink.clone();
                    let guard = WorkerGuard::new(WorkerLoss::WatchRegistration(request), self.shared.tx.clone());
                    self.registrations.insert(request);
                    self.runtime
                        .spawn_blocking(Box::new(move || {
                            let result = fs.watch(&root, &path, recursive, sink);
                            guard.finish(Input::WatchRegistered { request, result });
                        }))
                        .detach();
                }
                Output::Unwatch(id) => self.unwatch(id),
                Output::Publish(event) => {
                    let event = *event;
                    match &event {
                        UpdateEvent::Delta(update) => *lock(&self.shared.snapshot) = update.snapshot.clone(),
                        UpdateEvent::Reset { snapshot, .. } => *lock(&self.shared.snapshot) = snapshot.clone(),
                        _ => {}
                    }
                    *lock(&self.shared.health) = event.health().clone();
                    self.publish_stats();
                    let latest = lock(&self.shared.snapshot).clone();
                    lock(&self.shared.stream).push(event, &latest);
                }
                Output::CommandFinished { id, result } => {
                    if let Some(reply) = lock(&self.shared.replies).remove(&id) {
                        let _ = reply.send(result);
                    }
                }
                Output::SetTimer { id, at } => {
                    let tx = self.shared.tx.clone();
                    let delay = at.0.saturating_sub(self.now().0);
                    let sleep = self.runtime.sleep(delay);
                    self.runtime.spawn(Box::pin(async move {
                        sleep.await;
                        let _ = tx.unbounded_send(Message::Input(Input::Timer(id)));
                    }));
                }
                Output::Stopped(outcome) => {
                    *lock(&self.shared.lifecycle) = Lifecycle::Stopped(outcome);
                    stopped = Some(outcome);
                }
            }
        }
        self.publish_stats();
        stopped
    }

    fn publish_stats(&self) {
        let held = u64::try_from(lock(&self.sessions).len()).unwrap_or(u64::MAX);
        self.shared.held_sessions.store(held, Ordering::SeqCst);
        *lock(&self.shared.stats) = self.coordinator.stats();
    }

    fn forget_cancelled(sessions: &Mutex<HashMap<JobId, SessionSlot>>, job: JobId) {
        let mut held = lock(sessions);
        if matches!(held.get(&job), Some(SessionSlot::Cancelled)) {
            held.remove(&job);
        }
    }

    fn unwatch(&self, id: WatchId) {
        let fs = self.fs.clone();
        self.runtime.spawn_blocking(Box::new(move || fs.unwatch(id))).detach();
    }

    fn close_stream_and_fail_pending(&self) {
        lock(&self.shared.stream).close();
        let pending: Vec<oneshot::Sender<Result<()>>> = lock(&self.shared.replies).drain().map(|(_, tx)| tx).collect();
        let error = self.shared.terminal_error();
        for reply in pending {
            let _ = reply.send(Err(error.clone()));
        }
    }

    fn dispatch(&mut self, message: Message) -> Option<TerminalOutcome> {
        match message {
            Message::Input(input) => self.handle(input),
            Message::WatcherReady => self.drain_watcher(),
        }
    }

    async fn run(mut self) {
        let mut phase = RunPhase::Serving;
        while let Some(message) = self.rx.next().await {
            if self.dispatch(message).is_some() {
                phase = RunPhase::ReleasingRegistrations;
                self.close_stream_and_fail_pending();
            }
            if matches!(phase, RunPhase::ReleasingRegistrations) && self.registrations.is_empty() {
                break;
            }
        }
        self.rx.close();
        while let Ok(message) = self.rx.try_recv() {
            let _ = self.dispatch(message);
        }
        self.close_stream_and_fail_pending();
    }
}

pub struct Tree;

impl Tree {
    pub async fn open(
        filesystem: Arc<dyn FileSystem>,
        root: PathBuf,
        policy: Arc<dyn ScanPolicy>,
        config: Config,
        runtime: Arc<dyn Runtime>,
    ) -> Result<(TreeHandle, UpdateStream)> {
        config.validate().map_err(Error::InvalidConfig)?;
        let caps = filesystem.capabilities();
        let root = {
            let fs = filesystem.clone();
            blocking(&runtime, move || fs.canonicalize(&root)).await?
        };
        let root = Arc::new(root);
        let root_info = {
            let fs = filesystem.clone();
            let root = root.clone();
            blocking(&runtime, move || fs.metadata(&root, &RelativePath::root())).await?
        };
        let base = runtime.now();
        let mut coordinator = Coordinator::new(config.clone(), policy, caps, root_info, MonotonicTime::ZERO)?;
        let (tx, rx) = mpsc::unbounded();
        let stream = Arc::new(Mutex::new(StreamInner {
            queue: VecDeque::new(),
            closed: false,
            waker: None,
            capacity: config.update_stream_capacity,
            lag_mode: config.lag_mode,
        }));
        let shared = Arc::new(Shared {
            snapshot: Mutex::new(coordinator.snapshot().clone()),
            health: Mutex::new(coordinator.health()),
            stats: Mutex::new(coordinator.stats()),
            replies: Mutex::new(HashMap::new()),
            lifecycle: Mutex::new(Lifecycle::Running),
            next_command: AtomicU64::new(1),
            held_sessions: AtomicU64::new(0),
            tx: tx.clone(),
            stream: stream.clone(),
        });
        let sink = Arc::new(Sink {
            queue: Mutex::new(VecDeque::new()),
            dropped: AtomicU64::new(0),
            signalled: AtomicBool::new(false),
            capacity: config.watcher_path_limit,
            tx: tx.clone(),
        });
        let initial = coordinator.take_outputs();
        let mut actor = Actor {
            coordinator,
            rx,
            shared: shared.clone(),
            sink,
            fs: filesystem,
            runtime: runtime.clone(),
            root,
            base,
            workers: HashMap::new(),
            registrations: HashSet::new(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        };
        let _ = actor.execute(initial);
        while actor.coordinator.open_gate().is_none() {
            let Some(message) = actor.rx.next().await else {
                return Err(Error::Shutdown);
            };
            match message {
                Message::Input(input) => {
                    let _ = actor.handle(input);
                }
                Message::WatcherReady => {
                    let _ = actor.drain_watcher();
                }
            }
        }
        if let Some(Err(err)) = actor.coordinator.open_gate() {
            return Err(err);
        }
        runtime.spawn(Box::pin(actor.run()));
        Ok((TreeHandle { shared }, UpdateStream { inner: stream }))
    }
}

async fn blocking<T: Send + 'static>(
    runtime: &Arc<dyn Runtime>,
    work: impl FnOnce() -> std::result::Result<T, FsError> + Send + 'static,
) -> Result<T> {
    let (tx, rx) = oneshot::channel();
    runtime
        .spawn_blocking(Box::new(move || {
            let _ = tx.send(work());
        }))
        .detach();
    match rx.await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(Error::from(err)),
        Err(_) => Err(Error::WorkerLost),
    }
}

#[derive(Clone)]
pub struct TreeHandle {
    shared: Arc<Shared>,
}

impl TreeHandle {
    pub fn snapshot(&self) -> Snapshot {
        lock(&self.shared.snapshot).clone()
    }

    pub fn health(&self) -> Health {
        lock(&self.shared.health).clone()
    }

    pub fn stats(&self) -> Stats {
        lock(&self.shared.stats).clone()
    }

    pub fn held_listing_sessions(&self) -> u64 {
        self.shared.held_sessions.load(Ordering::SeqCst)
    }

    async fn command(&self, command: Command) -> Result<()> {
        let id = CommandId::new(self.shared.next_command.fetch_add(1, Ordering::SeqCst));
        let (tx, rx) = oneshot::channel();
        lock(&self.shared.replies).insert(id, tx);
        if self.shared.tx.unbounded_send(Message::Input(Input::Command { id, command })).is_err() {
            lock(&self.shared.replies).remove(&id);
            return Err(self.shared.terminal_error());
        }
        match rx.await {
            Ok(result) => result,
            Err(_) => Err(self.shared.terminal_error()),
        }
    }

    pub async fn initial_scan_complete(&self) -> Result<()> {
        self.command(Command::InitialScanComplete).await
    }

    pub async fn refresh(&self, paths: Vec<RelativePath>) -> Result<()> {
        self.command(Command::Refresh(paths)).await
    }

    pub async fn load(&self, path: RelativePath) -> Result<()> {
        self.command(Command::Load(path)).await
    }

    pub async fn unload(&self, path: RelativePath) -> Result<()> {
        self.command(Command::Unload(path)).await
    }

    pub async fn invalidate_policy(&self, roots: Vec<RelativePath>) -> Result<()> {
        self.command(Command::InvalidatePolicy(roots)).await
    }

    pub async fn set_priority(&self, paths: impl IntoIterator<Item = RelativePath>) -> Result<()> {
        self.command(Command::SetPriority(paths.into_iter().collect())).await
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.command(Command::Shutdown).await
    }
}
