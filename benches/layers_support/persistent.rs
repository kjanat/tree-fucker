use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tree_fucker::{BoxFuture, BoxTaskHandle, Runtime, TaskHandle};

struct BenchRuntime(tokio::runtime::Handle);
struct Task(tokio::task::JoinHandle<()>);
impl TaskHandle for Task {
    fn cancel(&self) {
        self.0.abort();
    }
    fn detach(self: Box<Self>) {}
}
impl Runtime for BenchRuntime {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn spawn(&self, future: BoxFuture<'static, ()>) {
        self.0.spawn(future);
    }
    fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send + 'static>) -> BoxTaskHandle {
        Box::new(Task(self.0.spawn_blocking(work)))
    }
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

pub fn scan(root: &Path, visit: &mut dyn FnMut(&Path), verify: bool) -> (usize, Option<Duration>) {
    let start = Instant::now();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_time().max_blocking_threads(8).build().unwrap();
    let (tree, _updates) = runtime
        .block_on(tree_fucker::Tree::open(
            super::raw::filesystem(),
            root.to_path_buf(),
            Arc::new(tree_fucker::LoadAll),
            tree_fucker::Config {
                domain_crossing: tree_fucker::DomainCrossing::Follow,
                foreground_ceiling_per_command: Duration::MAX,
                ..Default::default()
            },
            Arc::new(BenchRuntime(runtime.handle().clone())),
        ))
        .unwrap();
    runtime.block_on(tree.initial_scan_complete()).unwrap();
    // This control deliberately measures the consumer that waits for the
    // complete initial snapshot. Incremental update-stream latency is distinct.
    let snapshot = tree.snapshot();
    let count = snapshot.len().saturating_sub(1);
    let first = (count > 0).then(|| start.elapsed());
    if verify {
        for entry in snapshot.entries().filter(|entry| !entry.path.is_root()) {
            visit(&entry.path.under(root));
        }
    }
    std::hint::black_box(&snapshot);
    runtime.block_on(tree.shutdown()).unwrap();
    (count, first)
}
