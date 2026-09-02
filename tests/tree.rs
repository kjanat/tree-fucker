use std::sync::Arc;
use std::time::Duration;

use tree_fucker::testing::{DeterministicRuntime, FakeFileSystem, FakeOp};
use tree_fucker::update::{ErrorCause, InitialScanState, Operation, RecoverableError, RoundResult, UpdateEvent};
use tree_fucker::{Config, EntryKind, Error, LagMode, LoadAll, LoadState, RelativePath, Tree, WatcherKind};

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

#[test]
fn open_fails_when_the_runtime_drops_initial_blocking_work() {
    let runtime = Arc::new(DeterministicRuntime::new());
    runtime.discard_blocking(true);
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("a");
    let rt: Arc<dyn tree_fucker::runtime::Runtime> = runtime.clone();
    let result =
        runtime.block_on(Tree::open(fs.clone(), fs.root().to_path_buf(), Arc::new(LoadAll), Config::default(), rt));
    assert!(matches!(result, Err(Error::WorkerLost)));
    assert_eq!(fs.count_ops(FakeOp::ReadDir, ""), 0);
}
