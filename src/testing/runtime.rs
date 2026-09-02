use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_channel::oneshot;
use futures_util::task::{ArcWake, waker_ref};

use crate::runtime::{BoxFuture, Runtime};

struct Inner {
    base: Instant,
    offset: Duration,
    tasks: VecDeque<BoxFuture<'static, ()>>,
    blocking: VecDeque<Box<dyn FnOnce() + Send + 'static>>,
    timers: Vec<(Duration, oneshot::Sender<()>)>,
}

pub struct DeterministicRuntime {
    inner: Mutex<Inner>,
    woken: Arc<Flag>,
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
            }),
            woken: Arc::new(Flag(AtomicBool::new(false))),
        }
    }

    pub fn elapsed(&self) -> Duration {
        lock(&self.inner).offset
    }

    pub fn run_until_stalled(&self) {
        loop {
            let blocking: Vec<Box<dyn FnOnce() + Send + 'static>> = lock(&self.inner).blocking.drain(..).collect();
            let ran_blocking = !blocking.is_empty();
            for work in blocking {
                work();
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

impl Runtime for DeterministicRuntime {
    fn now(&self) -> Instant {
        let inner = lock(&self.inner);
        inner.base + inner.offset
    }

    fn spawn(&self, future: BoxFuture<'static, ()>) {
        lock(&self.inner).tasks.push_back(future);
        self.woken.0.store(true, Ordering::SeqCst);
    }

    fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send + 'static>) {
        lock(&self.inner).blocking.push_back(work);
        self.woken.0.store(true, Ordering::SeqCst);
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
