use std::sync::Arc;
use std::time::Duration;

use tree_fucker::core::JobOperation;
use tree_fucker::policy::{PathPredicate, ScanDecision};
use tree_fucker::testing::{BlockingMode, DeterministicRuntime, FailureMode, FakeFileSystem, FakeOp};
use tree_fucker::update::{ErrorCause, InitialScanState, Operation, RecoverableError, RoundResult, UpdateEvent};
use tree_fucker::{Config, EntryKind, Error, FsError, LagMode, LoadAll, LoadState, RelativePath, Tree, WatcherKind};

fn path(p: &str) -> RelativePath {
    RelativePath::parse(p).expect("valid path")
}

#[test]
fn open_scan_refresh_and_shutdown_over_the_async_layer() {
    let runtime = Arc::new(DeterministicRuntime::new());
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::Recursive));
    fs.mkdir("a");
    fs.create_file("a/x", 3);
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let (handle, mut stream) = runtime
        .block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), Config::default(), rt))
        .expect("open");
    runtime.block_on(handle.initial_scan_complete()).expect("scan");
    assert!(matches!(handle.health().initial_scan, InitialScanState::Complete { .. }));
    let paths: Vec<String> = handle.snapshot().entries().map(|e| e.path.to_string()).collect();
    assert_eq!(paths, [".", "a", "a/x"]);
    let first = runtime.block_on(stream.next()).expect("event").expect("ok");
    assert!(matches!(first, UpdateEvent::Delta(_)));
    fs.create_file("a/y", 1);
    runtime.run_until_stalled();
    runtime.block_on(handle.refresh(vec![path("a")])).expect("refresh");
    assert!(handle.snapshot().get(&path("a/y")).is_some());
    fs.add_silently("late", EntryKind::File);
    runtime.advance(Duration::from_secs(2));
    runtime.advance(Duration::from_secs(2));
    assert!(handle.snapshot().get(&path("late")).is_some());
    runtime.block_on(handle.shutdown()).expect("shutdown");
    let mut saw_terminal = false;
    loop {
        match runtime.block_on(stream.next()) {
            Some(Ok(UpdateEvent::Terminal { .. })) => saw_terminal = true,
            Some(Ok(_)) => {}
            Some(Err(e)) => panic!("unexpected stream error {e}"),
            None => break,
        }
    }
    assert!(saw_terminal);
    assert_eq!(runtime.block_on(handle.refresh(vec![path("a")])), Err(Error::Shutdown));
}

#[test]
fn slow_consumer_receives_reset_or_lagged() {
    for mode in [LagMode::Reset, LagMode::Disconnect] {
        let runtime = Arc::new(DeterministicRuntime::new());
        let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
        fs.mkdir("a");
        let config = Config { update_stream_capacity: 2, lag_mode: mode, ..Default::default() };
        let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
        let (handle, mut stream) = runtime
            .block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), config, rt))
            .expect("open");
        runtime.block_on(handle.initial_scan_complete()).expect("scan");
        for i in 0..5 {
            fs.add_silently(&format!("a/f{i}"), EntryKind::File);
            runtime.block_on(handle.refresh(vec![path("a")])).expect("refresh");
        }
        let mut events = Vec::new();
        while let Some(event) = {
            runtime.run_until_stalled();

            runtime.block_on(async {
                futures_util::future::poll_fn(|cx| {
                    use futures_core::Stream;
                    match std::pin::Pin::new(&mut stream).poll_next(cx) {
                        std::task::Poll::Ready(item) => std::task::Poll::Ready(item),
                        std::task::Poll::Pending => std::task::Poll::Ready(None),
                    }
                })
                .await
            })
        } {
            events.push(event);
        }
        match mode {
            LagMode::Reset => {
                assert!(events.iter().any(|e| matches!(e, Ok(UpdateEvent::Reset { .. }))));
                let last_version = events.iter().rev().find_map(|e| e.as_ref().ok().and_then(|e| e.version()));
                assert_eq!(last_version, Some(handle.snapshot().version()));
            }
            LagMode::Disconnect => {
                assert!(events.iter().any(|e| matches!(e, Err(tree_fucker::StreamError::Lagged { .. }))));
            }
        }
    }
}

#[test]
fn open_rejects_missing_or_non_directory_root() {
    let runtime = Arc::new(DeterministicRuntime::new());
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.set_root_kind(EntryKind::File);
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let result =
        runtime.block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), Config::default(), rt));
    assert!(matches!(result, Err(Error::NotDirectory)));
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.remove_root();
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let result =
        runtime.block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), Config::default(), rt));
    assert!(matches!(result, Err(Error::NotFound)));
}

fn poll_once<T>(future: std::pin::Pin<&mut impl std::future::Future<Output = T>>) -> std::task::Poll<T> {
    let waker = futures_util::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    future.poll(&mut cx)
}

fn drain(runtime: &DeterministicRuntime, stream: &mut tree_fucker::UpdateStream) -> Vec<UpdateEvent> {
    let mut events = Vec::new();
    loop {
        runtime.run_until_stalled();
        let next = runtime.block_on(futures_util::future::poll_fn(|cx| {
            use futures_core::Stream;
            match std::pin::Pin::new(&mut *stream).poll_next(cx) {
                std::task::Poll::Ready(item) => std::task::Poll::Ready(item),
                std::task::Poll::Pending => std::task::Poll::Ready(None),
            }
        }));
        match next {
            Some(Ok(event)) => events.push(event),
            Some(Err(e)) => panic!("unexpected stream error {e}"),
            None => return events,
        }
    }
}

fn lost_worker_errors(events: &[UpdateEvent]) -> Vec<RecoverableError> {
    events
        .iter()
        .flat_map(|event| match event {
            UpdateEvent::Delta(update) => update.errors.clone(),
            UpdateEvent::Health { errors, .. } | UpdateEvent::Reset { errors, .. } => errors.clone(),
            UpdateEvent::Terminal { .. } => Vec::new(),
        })
        .filter(|e| e.error == ErrorCause::WorkerLost)
        .collect()
}

#[test]
fn unload_cancels_the_running_worker_and_its_result_never_lands() {
    let runtime = Arc::new(DeterministicRuntime::new());
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("a");
    fs.create_file("a/x", 3);
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let (handle, _stream) = runtime
        .block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), Config::default(), rt))
        .expect("open");
    runtime.block_on(handle.initial_scan_complete()).expect("scan");
    let listings_before = fs.count_ops(FakeOp::ReadDir, "a");
    fs.add_silently("a/late", EntryKind::File);
    let mut refresh = Box::pin(handle.refresh(vec![path("a")]));
    assert!(poll_once(refresh.as_mut()).is_pending());
    let mut unload = Box::pin(handle.unload(path("a")));
    assert!(poll_once(unload.as_mut()).is_pending());
    runtime.run_until_stalled();
    assert_eq!(runtime.cancel_requests(), 1);
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a"), listings_before);
    assert!(handle.snapshot().get(&path("a/late")).is_none());
    assert_eq!(handle.snapshot().get(&path("a")).and_then(|e| e.load_state()), Some(LoadState::Unloaded));
    assert_eq!(runtime.block_on(unload), Ok(()));
    assert_eq!(runtime.block_on(refresh), Ok(()));
    assert!(handle.snapshot().get(&path("a/late")).is_none());
    assert_eq!(handle.stats().lost_workers, 0);
}

#[test]
fn unload_discards_the_result_of_a_worker_that_cancellation_cannot_interrupt() {
    let runtime = Arc::new(DeterministicRuntime::new());
    runtime.set_blocking_mode(BlockingMode::Uninterruptible);
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("a");
    fs.create_file("a/x", 3);
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let (handle, _stream) = runtime
        .block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), Config::default(), rt))
        .expect("open");
    runtime.block_on(handle.initial_scan_complete()).expect("scan");
    let listings_before = fs.count_ops(FakeOp::ReadDir, "a");
    fs.add_silently("a/late", EntryKind::File);
    let mut refresh = Box::pin(handle.refresh(vec![path("a")]));
    assert!(poll_once(refresh.as_mut()).is_pending());
    let mut unload = Box::pin(handle.unload(path("a")));
    assert!(poll_once(unload.as_mut()).is_pending());
    runtime.run_until_stalled();
    assert_eq!(runtime.cancel_requests(), 1);
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a"), listings_before + 1);
    assert!(handle.snapshot().get(&path("a/late")).is_none());
    assert_eq!(handle.snapshot().get(&path("a")).and_then(|e| e.load_state()), Some(LoadState::Unloaded));
    assert_eq!(runtime.block_on(unload), Ok(()));
    assert_eq!(runtime.block_on(refresh), Ok(()));
    assert!(handle.snapshot().get(&path("a/late")).is_none());
    assert_eq!(handle.stats().lost_workers, 0);
}

#[test]
fn panicking_worker_is_reported_and_the_directory_is_listed_again() {
    let runtime = Arc::new(DeterministicRuntime::new());
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("a");
    fs.create_file("a/x", 3);
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let (handle, mut stream) = runtime
        .block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), Config::default(), rt))
        .expect("open");
    runtime.block_on(handle.initial_scan_complete()).expect("scan");
    drain(&runtime, &mut stream);
    let listings_before = fs.count_ops(FakeOp::ReadDir, "a");
    fs.panic_once("a", FakeOp::ReadDir);
    fs.add_silently("a/late", EntryKind::File);
    assert_eq!(runtime.block_on(handle.refresh(vec![path("a")])), Ok(()));
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a"), listings_before + 2);
    assert!(handle.snapshot().get(&path("a/x")).is_some());
    assert!(handle.snapshot().get(&path("a/late")).is_some());
    assert_eq!(handle.stats().lost_workers, 1);
    let events = drain(&runtime, &mut stream);
    let lost = lost_worker_errors(&events);
    assert_eq!(lost.len(), 1);
    assert_eq!(lost[0].path, path("a"));
    assert_eq!(lost[0].operation, Operation::Listing);
    assert!(events.iter().any(|e| matches!(e, UpdateEvent::Health { errors, .. } if !errors.is_empty())));
    for _ in 0..20 {
        runtime.advance(Duration::from_secs(1));
        if handle.health().reconciliation.last_round == Some(RoundResult::Successful) {
            break;
        }
    }
    assert_eq!(handle.health().reconciliation.last_round, Some(RoundResult::Successful));
    assert!(handle.health().reconciliation.degraded_paths.is_empty());
}

struct CancelOnDropHandle {
    inner: Option<tree_fucker::runtime::BoxTaskHandle>,
}

impl tree_fucker::runtime::TaskHandle for CancelOnDropHandle {
    fn cancel(&self) {
        if let Some(inner) = &self.inner {
            inner.cancel();
        }
    }

    fn detach(mut self: Box<Self>) {
        if let Some(inner) = self.inner.take() {
            inner.detach();
        }
    }
}

impl Drop for CancelOnDropHandle {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner.cancel();
        }
    }
}

struct CancelOnDropRuntime {
    inner: Arc<DeterministicRuntime>,
}

impl tree_fucker::runtime::Runtime for CancelOnDropRuntime {
    fn now(&self) -> std::time::Instant {
        self.inner.now()
    }

    fn spawn(&self, future: tree_fucker::runtime::BoxFuture<'static, ()>) {
        self.inner.spawn(future);
    }

    fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send + 'static>) -> tree_fucker::runtime::BoxTaskHandle {
        Box::new(CancelOnDropHandle { inner: Some(self.inner.spawn_blocking(work)) })
    }

    fn sleep(&self, duration: Duration) -> tree_fucker::runtime::BoxFuture<'static, ()> {
        self.inner.sleep(duration)
    }
}

#[test]
fn a_runtime_whose_handles_cancel_on_drop_still_opens_and_watches() {
    let inner = Arc::new(DeterministicRuntime::new());
    let runtime = Arc::new(CancelOnDropRuntime { inner: inner.clone() });
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::Recursive));
    fs.mkdir("a");
    fs.create_file("a/x", 3);
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let (handle, _stream) = inner
        .block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), Config::default(), rt))
        .expect("open");
    inner.block_on(handle.initial_scan_complete()).expect("scan");
    assert_eq!(fs.watch_count(), 1);
    let paths: Vec<String> = handle.snapshot().entries().map(|e| e.path.to_string()).collect();
    assert_eq!(paths, [".", "a", "a/x"]);
}

#[test]
fn open_fails_when_the_runtime_drops_initial_blocking_work() {
    let runtime = Arc::new(DeterministicRuntime::new());
    runtime.set_blocking_mode(BlockingMode::Discarded);
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("a");
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let result =
        runtime.block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), Config::default(), rt));
    assert!(matches!(result, Err(Error::WorkerLost)));
    assert_eq!(fs.count_ops(FakeOp::ReadDir, ""), 0);
}

#[test]
fn a_registration_dispatched_before_shutdown_releases_its_watch() {
    let runtime = Arc::new(DeterministicRuntime::new());
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    fs.mkdir("c");
    fs.create_file("c/x", 1);
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let (handle, _stream) = runtime
        .block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), Config::default(), rt))
        .expect("open");
    runtime.block_on(handle.initial_scan_complete()).expect("scan");
    assert_eq!(fs.watch_count(), 2);
    assert_eq!(runtime.block_on(handle.unload(path("c"))), Ok(()));
    assert_eq!(fs.watch_count(), 1);
    let mut load = Box::pin(handle.load(path("c")));
    assert!(poll_once(load.as_mut()).is_pending());
    let mut shut = Box::pin(handle.shutdown());
    assert!(poll_once(shut.as_mut()).is_pending());
    runtime.run_until_stalled();
    assert_eq!(fs.watch_count(), 0);
}

struct InertHandle {
    cancels: Arc<std::sync::atomic::AtomicUsize>,
    drops: Arc<std::sync::atomic::AtomicUsize>,
}

impl tree_fucker::runtime::TaskHandle for InertHandle {
    fn cancel(&self) {
        self.cancels.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn detach(self: Box<Self>) {}
}

impl Drop for InertHandle {
    fn drop(&mut self) {
        self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

struct HoldingRuntime {
    inner: Arc<DeterministicRuntime>,
    hold: std::sync::atomic::AtomicBool,
    budget: std::sync::atomic::AtomicUsize,
    held: std::sync::Mutex<Vec<Box<dyn FnOnce() + Send + 'static>>>,
    cancels: Arc<std::sync::atomic::AtomicUsize>,
    drops: Arc<std::sync::atomic::AtomicUsize>,
}

impl HoldingRuntime {
    fn new(inner: Arc<DeterministicRuntime>) -> HoldingRuntime {
        HoldingRuntime {
            inner,
            hold: std::sync::atomic::AtomicBool::new(false),
            budget: std::sync::atomic::AtomicUsize::new(0),
            held: std::sync::Mutex::new(Vec::new()),
            cancels: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            drops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    fn cancels(&self) -> usize {
        self.cancels.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn dropped_handles(&self) -> usize {
        self.drops.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn hold(&self) {
        self.hold.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn hold_next(&self, count: usize) {
        self.budget.store(count, std::sync::atomic::Ordering::SeqCst);
    }

    fn take_budget(&self) -> bool {
        let mut left = self.budget.load(std::sync::atomic::Ordering::SeqCst);
        loop {
            let Some(next) = left.checked_sub(1) else {
                return false;
            };
            match self.budget.compare_exchange(
                left,
                next,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(current) => left = current,
            }
        }
    }

    fn held(&self) -> usize {
        self.held.lock().expect("held lock").len()
    }

    fn release(&self) {
        let work: Vec<Box<dyn FnOnce() + Send + 'static>> = self.held.lock().expect("held lock").drain(..).collect();
        for item in work {
            item();
        }
    }
}

impl tree_fucker::runtime::Runtime for HoldingRuntime {
    fn now(&self) -> std::time::Instant {
        self.inner.now()
    }

    fn spawn(&self, future: tree_fucker::runtime::BoxFuture<'static, ()>) {
        self.inner.spawn(future);
    }

    fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send + 'static>) -> tree_fucker::runtime::BoxTaskHandle {
        if self.hold.load(std::sync::atomic::Ordering::SeqCst) || self.take_budget() {
            self.held.lock().expect("held lock").push(work);
            return Box::new(InertHandle { cancels: self.cancels.clone(), drops: self.drops.clone() });
        }
        self.inner.spawn_blocking(work)
    }

    fn sleep(&self, duration: Duration) -> tree_fucker::runtime::BoxFuture<'static, ()> {
        self.inner.sleep(duration)
    }
}

fn poll_stream(
    stream: &mut tree_fucker::UpdateStream,
) -> std::task::Poll<Option<std::result::Result<UpdateEvent, tree_fucker::StreamError>>> {
    use futures_core::Stream;
    let waker = futures_util::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    std::pin::Pin::new(stream).poll_next(&mut cx)
}

#[test]
fn a_cancelled_worker_that_cannot_be_interrupted_holds_its_slot_and_its_handle_until_it_returns() {
    let inner = Arc::new(DeterministicRuntime::new());
    inner.set_blocking_mode(BlockingMode::Uninterruptible);
    let runtime = Arc::new(HoldingRuntime::new(inner.clone()));
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("a");
    fs.create_file("a/x", 3);
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let (handle, _stream) = inner
        .block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), Config::default(), rt))
        .expect("open");
    inner.block_on(handle.initial_scan_complete()).expect("scan");
    let listings_before = fs.count_ops(FakeOp::ReadDir, "a");
    fs.add_silently("a/late", EntryKind::File);
    runtime.hold_next(1);
    let mut refresh = Box::pin(handle.refresh(vec![path("a")]));
    assert!(poll_once(refresh.as_mut()).is_pending());
    inner.run_until_stalled();
    assert_eq!(runtime.held(), 1);
    let started = handle.stats().blocking_slots;
    assert_eq!(started.len(), 1);
    assert_eq!(started[0].path, path("a"));
    assert_eq!(started[0].operation, JobOperation::Listing);
    let mut unload = Box::pin(handle.unload(path("a")));
    assert!(poll_once(unload.as_mut()).is_pending());
    inner.run_until_stalled();
    assert_eq!(runtime.cancels(), 1);
    assert_eq!(runtime.dropped_handles(), 0, "the worker handle was dropped before its result arrived");
    assert_eq!(handle.stats().blocking_slots, started, "the slot was released before the worker returned");
    assert_eq!(handle.stats().in_flight_jobs, 0);
    assert_eq!(handle.snapshot().get(&path("a")).and_then(|e| e.load_state()), Some(LoadState::Unloaded));
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a"), listings_before);
    runtime.release();
    inner.run_until_stalled();
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a"), listings_before + 1);
    assert_eq!(runtime.dropped_handles(), 1);
    assert_eq!(handle.stats().blocking_slots_held, 0);
    assert!(handle.snapshot().get(&path("a/late")).is_none());
    assert_eq!(inner.block_on(unload), Ok(()));
    assert_eq!(inner.block_on(refresh), Ok(()));
    assert_eq!(handle.stats().lost_workers, 0);
}

#[test]
fn shutdown_closes_the_stream_while_a_registration_worker_never_runs() {
    let inner = Arc::new(DeterministicRuntime::new());
    let runtime = Arc::new(HoldingRuntime::new(inner.clone()));
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    fs.mkdir("c");
    fs.create_file("c/x", 1);
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let (handle, mut stream) = inner
        .block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), Config::default(), rt))
        .expect("open");
    inner.block_on(handle.initial_scan_complete()).expect("scan");
    assert_eq!(fs.watch_count(), 2);
    assert_eq!(inner.block_on(handle.unload(path("c"))), Ok(()));
    assert_eq!(fs.watch_count(), 1);
    runtime.hold();
    let mut load = Box::pin(handle.load(path("c")));
    assert!(poll_once(load.as_mut()).is_pending());
    let mut shut = Box::pin(handle.shutdown());
    assert!(poll_once(shut.as_mut()).is_pending());
    inner.run_until_stalled();
    assert_eq!(poll_once(shut.as_mut()), std::task::Poll::Ready(Ok(())));
    assert_eq!(poll_once(load.as_mut()), std::task::Poll::Ready(Err(Error::Shutdown)));
    assert_eq!(runtime.held(), 2);
    let mut terminal = false;
    let mut closed = false;
    loop {
        inner.run_until_stalled();
        match poll_stream(&mut stream) {
            std::task::Poll::Ready(Some(Ok(UpdateEvent::Terminal { .. }))) => terminal = true,
            std::task::Poll::Ready(Some(Ok(_))) => assert!(!terminal, "event published after Terminal"),
            std::task::Poll::Ready(Some(Err(e))) => panic!("unexpected stream error {e}"),
            std::task::Poll::Ready(None) => {
                closed = true;
                break;
            }
            std::task::Poll::Pending => break,
        }
    }
    assert!(terminal, "terminal event never published");
    assert!(closed, "update stream never closed after shutdown");
    assert_eq!(inner.block_on(handle.refresh(vec![path("c")])), Err(Error::Shutdown));
}

#[test]
fn a_command_after_fatal_termination_reports_the_termination() {
    let runtime = Arc::new(DeterministicRuntime::new());
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("c");
    fs.create_file("c/x", 1);
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let (handle, mut stream) = runtime
        .block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), Config::default(), rt))
        .expect("open");
    runtime.block_on(handle.initial_scan_complete()).expect("scan");
    fs.fail("c", FakeOp::ReadDir, FailureMode::Always(FsError::Fatal("gone".into())));
    assert_eq!(runtime.block_on(handle.refresh(vec![path("c")])), Err(Error::TreeTerminated));
    runtime.run_until_stalled();
    assert_eq!(runtime.block_on(handle.refresh(vec![path("c")])), Err(Error::TreeTerminated));
    assert_eq!(runtime.block_on(handle.load(path("c"))), Err(Error::TreeTerminated));
    assert_eq!(runtime.block_on(handle.shutdown()), Err(Error::TreeTerminated));
    let mut terminal = false;
    loop {
        runtime.run_until_stalled();
        match poll_stream(&mut stream) {
            std::task::Poll::Ready(Some(Ok(UpdateEvent::Terminal { .. }))) => terminal = true,
            std::task::Poll::Ready(Some(Ok(_))) => {}
            std::task::Poll::Ready(Some(Err(e))) => panic!("unexpected stream error {e}"),
            std::task::Poll::Ready(None) => break,
            std::task::Poll::Pending => panic!("update stream never closed after termination"),
        }
    }
    assert!(terminal, "terminal event never published");
}

#[test]
fn fatal_termination_with_a_registration_outstanding_reports_the_same_error_before_and_after_the_actor_exits() {
    let inner = Arc::new(DeterministicRuntime::new());
    let runtime = Arc::new(HoldingRuntime::new(inner.clone()));
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    fs.mkdir("c");
    fs.create_file("c/x", 1);
    fs.mkdir("d");
    fs.create_file("d/y", 1);
    let switch = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let flag = switch.clone();
    let policy = Arc::new(PathPredicate::new(move |p: &RelativePath, _k| {
        let selected = flag.load(std::sync::atomic::Ordering::SeqCst) == 1 || p.is_root();
        ScanDecision::Eligible { initially_loaded: selected }
    }));
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let (handle, _stream) = inner
        .block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), policy.clone(), Config::default(), rt))
        .expect("open");
    inner.block_on(handle.initial_scan_complete()).expect("scan");
    assert_eq!(fs.watch_count(), 1);
    fs.fail("d", FakeOp::ReadDir, FailureMode::Always(FsError::Fatal("gone".into())));
    switch.store(1, std::sync::atomic::Ordering::SeqCst);
    policy.bump_revision();
    runtime.hold_next(1);
    let mut invalidate = Box::pin(handle.invalidate_policy(vec![path("")]));
    assert!(poll_once(invalidate.as_mut()).is_pending());
    inner.run_until_stalled();
    assert_eq!(runtime.held(), 1);
    assert_eq!(poll_once(invalidate.as_mut()), std::task::Poll::Ready(Err(Error::TreeTerminated)));
    assert_eq!(inner.block_on(handle.refresh(vec![path("c")])), Err(Error::TreeTerminated));
    runtime.release();
    inner.run_until_stalled();
    assert_eq!(inner.block_on(handle.refresh(vec![path("c")])), Err(Error::TreeTerminated));
}
