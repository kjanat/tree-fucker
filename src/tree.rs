//! This module provides the live reconciled tree and its update stream.
//!
//! [`Tree::open`] validates a root, starts a coordinator task on the
//! supplied [`Runtime`], and returns a [`TreeHandle`] and an
//! [`UpdateStream`]. The coordinator keeps the [`Snapshot`] in agreement
//! with the filesystem through the initial scan, watcher hints, and
//! periodic reconciliation rounds (RFC §5, §11). The handle reads the
//! current state and sends commands. The stream delivers every committed
//! transition and health change until [`TreeHandle::shutdown`] or a fatal
//! failure ends the tree.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use futures_channel::{mpsc, oneshot};
use futures_core::Stream;
use futures_util::StreamExt;

use crate::config::{Config, LagMode};
use crate::core::{
    ChangeWaker, Command, Coordinator, GrantId, HostGovernor, Input, JobResult, MonotonicTime, Output, Reservation,
    Stats, TerminalOutcome, Work, WorkOrigin, WorkerLoss, host_governor,
};
use crate::error::{Error, Result};
use crate::fs::{Continuation, FileSystem, FsError, ListingSession, SessionStep, WatcherEvent, WatcherSink};
use crate::ids::{CommandId, JobId, WatchId, WatchReleaseId, WatchRequestId};
use crate::path::RelativePath;
use crate::policy::ScanPolicy;
use crate::runtime::{BoxTaskHandle, Runtime};
use crate::snapshot::Snapshot;
use crate::update::{Health, RecoverableError, StreamError, UpdateEvent};

enum Message {
    Input(Box<Input>),
    WatcherReady,
    GovernorChanged,
}

enum RunPhase {
    Serving,
    ReleasingWorkers,
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

/// `UpdateStream` delivers the [`UpdateEvent`] items of one tree (RFC §9).
///
/// [`Tree::open`] returns the only stream of a tree. Events arrive in
/// snapshot version order. The stream holds at most
/// [`Config::update_stream_capacity`] undelivered events. When a consumer
/// falls behind under [`LagMode::Reset`], it receives one
/// [`UpdateEvent::Reset`]. Under [`LagMode::Disconnect`], it receives a
/// [`StreamError::Lagged`], and then the stream ends. After shutdown or
/// fatal termination the stream yields [`UpdateEvent::Terminal`] and ends.
///
/// `UpdateStream` implements [`Stream`] for use with stream combinators.
pub struct UpdateStream {
    inner: Arc<Mutex<StreamInner>>,
}

impl UpdateStream {
    /// `next` waits for the next event, or returns `None` after the end.
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

struct GovernorWake {
    signalled: AtomicBool,
    tx: mpsc::UnboundedSender<Message>,
}

impl ChangeWaker for GovernorWake {
    fn wake(&self) {
        if !self.signalled.swap(true, Ordering::SeqCst) {
            let _ = self.tx.unbounded_send(Message::GovernorChanged);
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
            let _ = tx.unbounded_send(Message::Input(Box::new(input)));
        }
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.unbounded_send(Message::Input(Box::new(Input::WorkerLost(self.loss))));
        }
    }
}

struct Actor {
    coordinator: Coordinator,
    rx: mpsc::UnboundedReceiver<Message>,
    shared: Arc<Shared>,
    sink: Arc<Sink>,
    governor_wake: Arc<GovernorWake>,
    fs: Arc<dyn FileSystem>,
    runtime: Arc<dyn Runtime>,
    root: Arc<PathBuf>,
    base: Instant,
    workers: HashMap<JobId, BoxTaskHandle>,
    registrations: HashSet<WatchRequestId>,
    releases: HashSet<WatchReleaseId>,
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
            Input::WatchReleased { release } | Input::WorkerLost(WorkerLoss::WatchRelease(release)) => {
                self.releases.remove(release);
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

    fn governor_changed(&mut self) -> Option<TerminalOutcome> {
        self.governor_wake.signalled.store(false, Ordering::SeqCst);
        let outputs = self.coordinator.observe(self.now());
        self.execute(outputs)
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
                                    fs.open_listing(&root, &spec.path, listing.ceilings, listing.cancel)
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
                            Work::ResolveDomain { parent } => {
                                JobResult::Domain(fs.resolve_domain(&root, &spec.path, parent.as_deref()))
                            }
                            Work::Enrichment { batch } => JobResult::Enrichment(fs.enrich(&root, &spec.path, &batch)),
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
                Output::Unwatch { release, watch } => self.unwatch(release, watch),
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
                        let _ = tx.unbounded_send(Message::Input(Box::new(Input::Timer(id))));
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

    fn unwatch(&mut self, release: WatchReleaseId, watch: WatchId) {
        let fs = self.fs.clone();
        let guard = WorkerGuard::new(WorkerLoss::WatchRelease(release), self.shared.tx.clone());
        self.releases.insert(release);
        self.runtime
            .spawn_blocking(Box::new(move || {
                fs.unwatch(watch);
                guard.finish(Input::WatchReleased { release });
            }))
            .detach();
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
            Message::Input(input) => self.handle(*input),
            Message::WatcherReady => self.drain_watcher(),
            Message::GovernorChanged => self.governor_changed(),
        }
    }

    async fn run(mut self) {
        let mut phase = RunPhase::Serving;
        while let Some(message) = self.rx.next().await {
            if self.dispatch(message).is_some() {
                phase = RunPhase::ReleasingWorkers;
                self.close_stream_and_fail_pending();
            }
            if matches!(phase, RunPhase::ReleasingWorkers)
                && self.registrations.is_empty()
                && self.releases.is_empty()
                && self.workers.is_empty()
                && !self.coordinator.has_pending_releases()
            {
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

/// `Tree` opens a live, reconciled view of one directory tree.
///
/// A tree runs through four stages.
///
/// 1. [`Tree::open`] validates the configuration, canonicalizes the root,
///    confirms the root is a directory, completes the root watch registration
///    attempt, and spawns the coordinator on the runtime. It returns a
///    [`TreeHandle`] and an [`UpdateStream`].
/// 2. The initial scan runs as governed background work (RFC §11.1).
///    [`TreeHandle::initial_scan_complete`] waits for it.
/// 3. The consumer reads [`UpdateStream`] events and calls
///    [`TreeHandle::snapshot`] whenever it needs the current state. Watcher
///    hints and reconciliation rounds keep the snapshot current.
/// 4. [`TreeHandle::shutdown`] stops the tree. The stream then yields
///    [`UpdateEvent::Terminal`] and ends.
///
/// The tree keeps running after the caller drops every handle. The caller
/// must call [`TreeHandle::shutdown`] to stop it.
pub struct Tree;

impl Tree {
    /// `open` opens a tree at `root` under the process-wide host governor.
    ///
    /// Every tree and scan in one process shares that governor (RFC §9,
    /// §15.9).
    ///
    /// `filesystem` performs every read. `policy` decides which directories
    /// load. `config` sets per-tree limits. `runtime` supplies task
    /// spawning, blocking workers, timers, and the monotonic clock. The
    /// caller must poll the returned future on that runtime.
    ///
    /// `open` returns after the root watch registration attempt finishes.
    /// The initial scan continues in the background.
    ///
    /// # Errors
    ///
    /// - `open` returns [`Error::InvalidConfig`] for an invalid `config` or
    ///   invalid host limits.
    /// - It returns [`Error::NotFound`] or [`Error::NotDirectory`] for an
    ///   absent or non-directory root (RFC §13.2).
    /// - It returns [`Error::WatcherRegistrationFailed`] when root registration
    ///   fails under
    ///   [`crate::config::WatchRegistrationFailure::RequireWatcher`].
    /// - It returns [`Error::Io`] when the adapter fails a root read.
    /// - It returns [`Error::Coordination`] when the shared authority fails.
    /// - It returns [`Error::WorkerLost`] when a bootstrap worker ends without
    ///   a result.
    pub async fn open(
        filesystem: Arc<dyn FileSystem>,
        root: PathBuf,
        policy: Arc<dyn ScanPolicy>,
        config: Config,
        runtime: Arc<dyn Runtime>,
    ) -> Result<(TreeHandle, UpdateStream)> {
        Tree::open_under(filesystem, root, policy, config, runtime, host_governor()).await
    }

    /// `open_outside_host_governor` opens a tree under the given `governor`.
    ///
    /// This function is the named opt-out of RFC §15.9. The process-wide
    /// governor states a bound for the process, and work of this tree falls
    /// outside it. Tests call it with [`HostGovernor::independent`]. Its
    /// arguments and errors match [`Tree::open`].
    pub async fn open_outside_host_governor(
        filesystem: Arc<dyn FileSystem>,
        root: PathBuf,
        policy: Arc<dyn ScanPolicy>,
        config: Config,
        runtime: Arc<dyn Runtime>,
        governor: HostGovernor,
    ) -> Result<(TreeHandle, UpdateStream)> {
        Tree::open_under(filesystem, root, policy, config, runtime, governor).await
    }

    async fn open_under(
        filesystem: Arc<dyn FileSystem>,
        root: PathBuf,
        policy: Arc<dyn ScanPolicy>,
        config: Config,
        runtime: Arc<dyn Runtime>,
        governor: HostGovernor,
    ) -> Result<(TreeHandle, UpdateStream)> {
        config.validate().map_err(Error::InvalidConfig)?;
        governor.limits().validate().map_err(Error::InvalidConfig)?;
        let caps = filesystem.capabilities();
        let base = governor.base(runtime.now());
        let root = {
            let fs = filesystem.clone();
            bootstrap(&runtime, &governor, base, &config, move || fs.canonicalize(&root)).await?
        };
        let root = Arc::new(root);
        let root_info = {
            let fs = filesystem.clone();
            let root = root.clone();
            bootstrap(&runtime, &governor, base, &config, move || fs.metadata(&root, &RelativePath::root())).await?
        };
        let now = MonotonicTime(runtime.now().saturating_duration_since(base));
        let (tx, rx) = mpsc::unbounded();
        let governor_wake = Arc::new(GovernorWake { signalled: AtomicBool::new(false), tx: tx.clone() });
        governor.on_change(Arc::<GovernorWake>::downgrade(&governor_wake));
        let mut coordinator = Coordinator::new(config.clone(), policy, caps, root_info, now, governor)?;
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
            governor_wake,
            fs: filesystem,
            runtime: runtime.clone(),
            root,
            base,
            workers: HashMap::new(),
            registrations: HashSet::new(),
            releases: HashSet::new(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        };
        let _ = actor.execute(initial);
        while actor.coordinator.open_gate().is_none() {
            let Some(message) = actor.rx.next().await else {
                return Err(Error::Shutdown);
            };
            let _ = actor.dispatch(message);
        }
        if let Some(Err(err)) = actor.coordinator.open_gate() {
            return Err(err);
        }
        runtime.spawn(Box::pin(actor.run()));
        Ok((TreeHandle { shared }, UpdateStream { inner: stream }))
    }
}

struct BootstrapGrant {
    id: GrantId,
    governor: HostGovernor,
    runtime: Arc<dyn Runtime>,
    base: Instant,
}

impl Drop for BootstrapGrant {
    fn drop(&mut self) {
        let now = MonotonicTime(self.runtime.now().saturating_duration_since(self.base));
        if std::thread::panicking() {
            self.governor.record_grant_failure(self.id, now);
        }
        self.governor.release(self.id, now);
    }
}

async fn bootstrap<T: Send + 'static>(
    runtime: &Arc<dyn Runtime>,
    governor: &HostGovernor,
    base: Instant,
    config: &Config,
    work: impl FnOnce() -> std::result::Result<T, FsError> + Send + 'static,
) -> Result<T> {
    let id = GrantId::Bootstrap(governor.next_bootstrap());
    let grant = loop {
        if let Some(error) = governor.coordination_error() {
            return Err(Error::Coordination(error));
        }
        let now = MonotonicTime(runtime.now().saturating_duration_since(base));
        let reservation = Reservation {
            id,
            path: RelativePath::root(),
            reads: 1,
            registrations: 0,
            operations: 0,
            ceiling: None,
            lease: 0,
            domain: None,
            origin: WorkOrigin::Background,
            listing: false,
        };
        if governor.try_admit(reservation, now).is_ok() {
            break BootstrapGrant { id, governor: governor.clone(), runtime: runtime.clone(), base };
        }
        runtime.sleep(bootstrap_delay(governor, config, now)).await;
    };
    loop {
        let now = MonotonicTime(runtime.now().saturating_duration_since(base));
        if let Some(error) = governor.coordination_error() {
            return Err(Error::Coordination(error));
        }
        if governor.try_start(id, now).is_ok() {
            break;
        }
        runtime.sleep(bootstrap_delay(governor, config, now)).await;
    }
    blocking(runtime, work, grant).await
}

fn bootstrap_delay(governor: &HostGovernor, config: &Config, now: MonotonicTime) -> Duration {
    match governor.resume_at(now) {
        Some(at) => at.0.saturating_sub(now.0).max(config.minimum_period),
        None => config.minimum_period,
    }
}

async fn blocking<T: Send + 'static>(
    runtime: &Arc<dyn Runtime>,
    work: impl FnOnce() -> std::result::Result<T, FsError> + Send + 'static,
    grant: BootstrapGrant,
) -> Result<T> {
    let (tx, rx) = oneshot::channel();
    runtime
        .spawn_blocking(Box::new(move || {
            let outcome = work();
            if outcome.is_err() {
                let now = MonotonicTime(grant.runtime.now().saturating_duration_since(grant.base));
                grant.governor.record_grant_failure(grant.id, now);
            }
            drop(grant);
            let _ = tx.send(outcome);
        }))
        .detach();
    match rx.await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(Error::from(err)),
        Err(_) => Err(Error::WorkerLost),
    }
}

/// `TreeHandle` reads and commands one open tree (RFC §9).
///
/// Clones address the same tree. Reads return the latest published state
/// and never wait for filesystem I/O. Commands go to the coordinator and
/// complete when the coordinator finishes them.
///
/// The coordinator accepts a command when it assigns the command a causal
/// barrier. A read satisfies the command only when the coordinator
/// dispatched it after that barrier. Dropping a command future leaves an
/// accepted command running. No command has a wall-clock bound, and
/// throttling delays commands without failing them (RFC §15.4).
///
/// Every command can fail with [`Error::Shutdown`] after shutdown began,
/// [`Error::TreeTerminated`] after a fatal failure, [`Error::Capacity`]
/// when the pending command capacity is full, and [`Error::Coordination`]
/// when the shared admission authority failed. While the root is
/// unavailable, a refresh of the root starts recovery and every other
/// root-dependent command fails with [`Error::RootUnavailable`] (RFC §9.1).
#[derive(Clone)]
pub struct TreeHandle {
    shared: Arc<Shared>,
}

impl TreeHandle {
    /// `snapshot` returns the latest published snapshot.
    pub fn snapshot(&self) -> Snapshot {
        lock(&self.shared.snapshot).clone()
    }

    /// `health` returns the latest published health.
    pub fn health(&self) -> Health {
        lock(&self.shared.health).clone()
    }

    /// `stats` returns the coordinator statistics of RFC §16.
    pub fn stats(&self) -> Stats {
        lock(&self.shared.stats).clone()
    }

    /// `held_listing_sessions` counts the suspended listing sessions.
    ///
    /// A session suspends between leases. It then holds its buffer and
    /// handle and no worker slot (RFC §10.2).
    pub fn held_listing_sessions(&self) -> u64 {
        self.shared.held_sessions.load(Ordering::SeqCst)
    }

    async fn command(&self, command: Command) -> Result<()> {
        let id = CommandId::new(self.shared.next_command.fetch_add(1, Ordering::SeqCst));
        let (tx, rx) = oneshot::channel();
        lock(&self.shared.replies).insert(id, tx);
        if self.shared.tx.unbounded_send(Message::Input(Box::new(Input::Command { id, command }))).is_err() {
            lock(&self.shared.replies).remove(&id);
            return Err(self.shared.terminal_error());
        }
        match rx.await {
            Ok(result) => result,
            Err(_) => Err(self.shared.terminal_error()),
        }
    }

    /// `initial_scan_complete` waits for the initial scan of the current root.
    ///
    /// The call succeeds when traversal is exhausted and the tree accepted
    /// or removed every initial directory. It fails with
    /// [`Error::InitialScanDegraded`], and the error lists the unsatisfied
    /// paths. Background retries continue after that failure, and
    /// [`Health::initial_scan`] reports their progress. The call fails with
    /// [`Error::RootUnavailable`] when the root vanishes. The caller can call
    /// it again after the root recovers, and the new call waits for the new
    /// incarnation (RFC §9, §11.1).
    pub async fn initial_scan_complete(&self) -> Result<()> {
        self.command(Command::InitialScanComplete).await
    }

    /// `refresh` rereads `paths` and waits for an accepted fresh read of each.
    ///
    /// The coordinator counts a read as fresh after it dispatches the read
    /// past the command barrier (RFC §9, §9.1).
    ///
    /// A Loaded or Loading directory gets a listing. An Unloaded or Excluded
    /// directory and a non-directory get a metadata read. For an
    /// unrepresented target, the coordinator lists its deepest Loaded or
    /// Loading ancestor and walks down one component at a time. The walk
    /// fails with [`Error::NotLoaded`], [`Error::PolicyDenied`], or
    /// [`Error::NotDirectory`] at an Unloaded, Excluded, or non-directory
    /// component. When a listing proves the target absent, the command
    /// succeeds. Refresh draws on the foreground allowance (RFC §15.4).
    ///
    /// A failed required read fails the command with [`Error::Io`],
    /// [`Error::ResourceLimited`], [`Error::Stuck`], [`Error::InvalidListing`],
    /// [`Error::UnresolvedKind`], [`Error::AncestorNotDirectory`], or
    /// [`Error::WatcherRegistrationFailed`]. A command over the configured
    /// path limit fails with [`Error::PathLimit`] before acceptance.
    pub async fn refresh(&self, paths: Vec<RelativePath>) -> Result<()> {
        self.command(Command::Refresh(paths)).await
    }

    /// `load` loads the represented directory at `path` (RFC §9.1).
    ///
    /// An Unloaded target becomes Loading. The command succeeds after an
    /// accepted post-barrier listing makes the target Loaded. A Loading or
    /// Loaded target also waits for such a listing. Policy selects further
    /// descendants, and they load as ordinary background work.
    ///
    /// The command fails with [`Error::PolicyDenied`] for an Excluded target
    /// and with [`Error::NotDirectory`] for a non-directory. It fails with
    /// [`Error::NotFound`] for an unrepresented target and for a target
    /// removed during loading. Required reads fail it as they fail
    /// [`TreeHandle::refresh`].
    pub async fn load(&self, path: RelativePath) -> Result<()> {
        self.command(Command::Load(path)).await
    }

    /// `unload` unloads the directory at `path` without filesystem I/O.
    ///
    /// The command follows RFC §9.1.
    ///
    /// A Loaded or Loading target becomes Unloaded. Its represented
    /// descendants leave the snapshot, and the coordinator cancels its pending
    /// work. An
    /// Unloaded, Excluded, or unrepresented target succeeds unchanged. A
    /// non-directory fails with [`Error::NotDirectory`].
    pub async fn unload(&self, path: RelativePath) -> Result<()> {
        self.command(Command::Unload(path)).await
    }

    /// `invalidate_policy` reevaluates policy below `roots`.
    ///
    /// The reevaluation covers each root and its represented descendants.
    ///
    /// The caller invokes it after the policy changes its decisions for
    /// those subtrees. Results from before the call cannot commit within
    /// them. The command succeeds after the reevaluation commits its loads,
    /// unloads, and exclusions. Every newly Loading directory must also have
    /// an accepted listing. An unrepresented root succeeds unchanged.
    /// Required reads fail the command as they fail [`TreeHandle::refresh`]
    /// (RFC §8, §9).
    pub async fn invalidate_policy(&self, roots: Vec<RelativePath>) -> Result<()> {
        self.command(Command::InvalidatePolicy(roots)).await
    }

    /// `set_priority` replaces the priority set with `paths` (RFC §9.1, §11.3).
    ///
    /// Loaded directories in the set get lower-latency reconciliation.
    /// Other paths have no effect until they match a Loaded directory. The
    /// command succeeds after the coordinator replaces the set. A set over
    /// the priority-set limit fails with [`Error::PathLimit`], and the
    /// existing set stays.
    pub async fn set_priority(&self, paths: impl IntoIterator<Item = RelativePath>) -> Result<()> {
        self.command(Command::SetPriority(paths.into_iter().collect())).await
    }

    /// `shutdown` stops the tree (RFC §9).
    ///
    /// Shutdown stops command acceptance, fails every unfinished command
    /// with [`Error::Shutdown`], cancels queued and in-flight work, releases
    /// watches, publishes [`UpdateEvent::Terminal`], and closes the stream.
    /// Blocked filesystem calls keep their worker slots until they return.
    /// A second call fails with [`Error::Shutdown`].
    pub async fn shutdown(&self) -> Result<()> {
        self.command(Command::Shutdown).await
    }
}
