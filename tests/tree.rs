use std::sync::Arc;
use std::time::Duration;

use tree_fucker::testing::{DeterministicRuntime, FakeFileSystem};
use tree_fucker::update::{InitialScanState, UpdateEvent};
use tree_fucker::{Config, EntryKind, Error, LagMode, LoadAll, RelativePath, Tree, WatcherKind};

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
