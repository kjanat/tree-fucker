use std::collections::VecDeque;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_channel::oneshot;
use futures_util::task::{ArcWake, waker_ref};

use crate::runtime::{BoxFuture, BoxTaskHandle, Runtime, TaskHandle};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockingMode {
    Queued,
    Discarded,
    Uninterruptible,
}

struct BlockingWork {
    work: Box<dyn FnOnce() + Send + 'static>,
    cancelled: Arc<AtomicBool>,
}

struct BlockingHandle {
    cancelled: Arc<AtomicBool>,
    requests: Arc<AtomicU64>,
}

impl TaskHandle for BlockingHandle {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.requests.fetch_add(1, Ordering::SeqCst);
    }

    fn detach(self: Box<Self>) {}
}

struct UninterruptibleHandle {
    requests: Arc<AtomicU64>,
}

impl TaskHandle for UninterruptibleHandle {
    fn cancel(&self) {
        self.requests.fetch_add(1, Ordering::SeqCst);
    }

    fn detach(self: Box<Self>) {}
}

struct DiscardedHandle;

impl TaskHandle for DiscardedHandle {
    fn cancel(&self) {}

    fn detach(self: Box<Self>) {}
}

struct Inner {
    base: Instant,
    offset: Duration,
    tasks: VecDeque<BoxFuture<'static, ()>>,
    blocking: VecDeque<BlockingWork>,
    timers: Vec<(Duration, oneshot::Sender<()>)>,
    blocking_mode: BlockingMode,
}

pub struct DeterministicRuntime {
    inner: Mutex<Inner>,
    woken: Arc<Flag>,
    cancel_requests: Arc<AtomicU64>,
    caught_panics: AtomicU64,
}

struct Flag(AtomicBool);

impl ArcWake for Flag {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.store(true, Ordering::SeqCst);
    }
}

fn lock(inner: &Mutex<Inner>) -> std::sync::MutexGuard<'_, Inner> {
    match inner.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl Default for DeterministicRuntime {
    fn default() -> Self {
        DeterministicRuntime::new()
    }
}

impl DeterministicRuntime {
    pub fn new() -> DeterministicRuntime {
        DeterministicRuntime {
            inner: Mutex::new(Inner {
                base: Instant::now(),
                offset: Duration::ZERO,
                tasks: VecDeque::new(),
                blocking: VecDeque::new(),
                timers: Vec::new(),
                blocking_mode: BlockingMode::Queued,
            }),
            woken: Arc::new(Flag(AtomicBool::new(false))),
            cancel_requests: Arc::new(AtomicU64::new(0)),
            caught_panics: AtomicU64::new(0),
        }
    }

    pub fn elapsed(&self) -> Duration {
        lock(&self.inner).offset
    }

    pub fn set_blocking_mode(&self, mode: BlockingMode) {
        lock(&self.inner).blocking_mode = mode;
    }

    pub fn cancel_requests(&self) -> u64 {
        self.cancel_requests.load(Ordering::SeqCst)
    }

    pub fn caught_panics(&self) -> u64 {
        self.caught_panics.load(Ordering::SeqCst)
    }

    pub fn run_until_stalled(&self) {
        loop {
            let blocking: Vec<BlockingWork> = lock(&self.inner).blocking.drain(..).collect();
            let ran_blocking = !blocking.is_empty();
            for BlockingWork { work, cancelled } in blocking {
                if cancelled.load(Ordering::SeqCst) {
                    continue;
                }
                if catch_unwind(AssertUnwindSafe(work)).is_err() {
                    self.caught_panics.fetch_add(1, Ordering::SeqCst);
                }
            }
            self.woken.0.store(false, Ordering::SeqCst);
            let tasks: Vec<BoxFuture<'static, ()>> = lock(&self.inner).tasks.drain(..).collect();
            let waker = waker_ref(&self.woken);
            let mut cx = Context::from_waker(&waker);
            let mut still_pending = Vec::new();
            for mut task in tasks {
                match task.as_mut().poll(&mut cx) {
                    Poll::Ready(()) => {}
                    Poll::Pending => still_pending.push(task),
                }
            }
            {
                let mut inner = lock(&self.inner);
                let newly_spawned: Vec<BoxFuture<'static, ()>> = inner.tasks.drain(..).collect();
                inner.tasks.extend(still_pending);
                inner.tasks.extend(newly_spawned);
            }
            let has_blocking = !lock(&self.inner).blocking.is_empty();
            let woken = self.woken.0.load(Ordering::SeqCst);
            if !ran_blocking && !has_blocking && !woken {
                break;
            }
        }
    }

    pub fn advance(&self, duration: Duration) {
        {
            let mut inner = lock(&self.inner);
            inner.offset += duration;
            let now = inner.offset;
            let mut due = Vec::new();
            let mut rest = Vec::new();
            for (at, tx) in inner.timers.drain(..) {
                if at <= now {
                    due.push(tx);
                } else {
                    rest.push((at, tx));
                }
            }
            inner.timers = rest;
            for tx in due {
                let _ = tx.send(());
            }
        }
        self.run_until_stalled();
    }

    pub fn next_timer(&self) -> Option<Duration> {
        let inner = lock(&self.inner);
        inner.timers.iter().map(|(at, _)| *at).min().map(|at| at.saturating_sub(inner.offset))
    }

    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        let mut future = Box::pin(future);
        let main = Arc::new(Flag(AtomicBool::new(false)));
        loop {
            self.run_until_stalled();
            main.0.store(false, Ordering::SeqCst);
            let waker = waker_ref(&main);
            let mut cx = Context::from_waker(&waker);
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }
            self.run_until_stalled();
            if main.0.load(Ordering::SeqCst) {
                continue;
            }
            match self.next_timer() {
                Some(delay) => self.advance(delay),
                None => panic!("deterministic runtime deadlocked: future pending with no timers or tasks"),
            }
        }
    }
}

struct InertHandle {
    cancels: Arc<AtomicU64>,
    drops: Arc<AtomicU64>,
}

impl TaskHandle for InertHandle {
    fn cancel(&self) {
        self.cancels.fetch_add(1, Ordering::SeqCst);
    }

    fn detach(self: Box<Self>) {}
}

impl Drop for InertHandle {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

pub struct HoldingRuntime {
    inner: Arc<DeterministicRuntime>,
    hold: AtomicBool,
    budget: AtomicU64,
    held: Mutex<Vec<Box<dyn FnOnce() + Send + 'static>>>,
    cancels: Arc<AtomicU64>,
    drops: Arc<AtomicU64>,
}

impl HoldingRuntime {
    pub fn new(inner: Arc<DeterministicRuntime>) -> HoldingRuntime {
        HoldingRuntime {
            inner,
            hold: AtomicBool::new(false),
            budget: AtomicU64::new(0),
            held: Mutex::new(Vec::new()),
            cancels: Arc::new(AtomicU64::new(0)),
            drops: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn hold(&self) {
        self.hold.store(true, Ordering::SeqCst);
    }

    pub fn hold_next(&self, count: usize) {
        self.budget.store(count as u64, Ordering::SeqCst);
    }

    pub fn held(&self) -> usize {
        self.held.lock().map(|held| held.len()).unwrap_or(0)
    }

    pub fn cancels(&self) -> usize {
        self.cancels.load(Ordering::SeqCst) as usize
    }

    pub fn dropped_handles(&self) -> usize {
        self.drops.load(Ordering::SeqCst) as usize
    }

    pub fn release(&self) {
        let work: Vec<Box<dyn FnOnce() + Send + 'static>> = match self.held.lock() {
            Ok(mut held) => held.drain(..).collect(),
            Err(poisoned) => poisoned.into_inner().drain(..).collect(),
        };
        for item in work {
            item();
        }
    }

    fn take_budget(&self) -> bool {
        let mut left = self.budget.load(Ordering::SeqCst);
        loop {
            let Some(next) = left.checked_sub(1) else {
                return false;
            };
            match self.budget.compare_exchange(left, next, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return true,
                Err(current) => left = current,
            }
        }
    }
}

impl Runtime for HoldingRuntime {
    fn now(&self) -> Instant {
        self.inner.now()
    }

    fn spawn(&self, future: BoxFuture<'static, ()>) {
        self.inner.spawn(future);
    }

    fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send + 'static>) -> BoxTaskHandle {
        if self.hold.load(Ordering::SeqCst) || self.take_budget() {
            match self.held.lock() {
                Ok(mut held) => held.push(work),
                Err(poisoned) => poisoned.into_inner().push(work),
            }
            return Box::new(InertHandle { cancels: self.cancels.clone(), drops: self.drops.clone() });
        }
        self.inner.spawn_blocking(work)
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        self.inner.sleep(duration)
    }
}

impl Runtime for DeterministicRuntime {
    fn now(&self) -> Instant {
        let inner = lock(&self.inner);
        inner.base + inner.offset
    }

    fn spawn(&self, future: BoxFuture<'static, ()>) {
        lock(&self.inner).tasks.push_back(future);
        self.woken.0.store(true, Ordering::SeqCst);
    }

    fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send + 'static>) -> BoxTaskHandle {
        let mut inner = lock(&self.inner);
        match inner.blocking_mode {
            BlockingMode::Discarded => {
                drop(work);
                Box::new(DiscardedHandle)
            }
            BlockingMode::Queued => {
                let cancelled = Arc::new(AtomicBool::new(false));
                inner.blocking.push_back(BlockingWork { work, cancelled: cancelled.clone() });
                self.woken.0.store(true, Ordering::SeqCst);
                Box::new(BlockingHandle { cancelled, requests: self.cancel_requests.clone() })
            }
            BlockingMode::Uninterruptible => {
                inner.blocking.push_back(BlockingWork { work, cancelled: Arc::new(AtomicBool::new(false)) });
                self.woken.0.store(true, Ordering::SeqCst);
                Box::new(UninterruptibleHandle { requests: self.cancel_requests.clone() })
            }
        }
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        let (tx, rx) = oneshot::channel();
        {
            let mut inner = lock(&self.inner);
            let at = inner.offset + duration;
            inner.timers.push((at, tx));
        }
        Box::pin(async move {
            let _ = rx.await;
        })
    }
}
