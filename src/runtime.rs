//! The core reaches its async runtime through this abstraction.
//!
//! The core is runtime-neutral (RFC §9). A [`Runtime`] adapter supplies task
//! spawning, a blocking-work pool, timers, and a monotonic clock.
#![cfg_attr(feature = "tokio", doc = " The `tokio` feature adds [`TokioRuntime`].")]
#![cfg_attr(not(feature = "tokio"), doc = " The `tokio` feature adds `TokioRuntime`.")]

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

/// `BoxFuture` is a boxed future, and a [`Runtime`] can move it between
/// threads.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// [`Runtime::spawn_blocking`] starts work and returns a `TaskHandle` for it.
///
/// An implementation must offer no operation that waits for a running
/// blocking call to stop (RFC §9).
pub trait TaskHandle: Send + Sync + 'static {
    /// `cancel` prevents queued work from starting, on a best-effort basis.
    ///
    /// Work that has started runs to completion, and the core discards its
    /// result.
    fn cancel(&self);

    /// `detach` releases the handle and lets the work run to completion.
    fn detach(self: Box<Self>);
}

/// `BoxTaskHandle` is a boxed [`TaskHandle`].
pub type BoxTaskHandle = Box<dyn TaskHandle>;

/// A `Runtime` adapter drives a [`crate::tree::Tree`].
pub trait Runtime: Send + Sync + 'static {
    /// `now` reads the monotonic clock.
    fn now(&self) -> Instant;

    /// `spawn` runs `future` to completion on the runtime.
    fn spawn(&self, future: BoxFuture<'static, ()>);

    /// `spawn_blocking` runs `work` on the blocking-work pool.
    fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send + 'static>) -> BoxTaskHandle;

    /// `sleep` returns a future that completes after `duration`.
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()>;
}

/// `TokioRuntime` implements [`Runtime`] on a Tokio runtime handle.
#[cfg(feature = "tokio")]
pub struct TokioRuntime {
    handle: tokio::runtime::Handle,
}

#[cfg(feature = "tokio")]
impl TokioRuntime {
    /// `new` builds a runtime that spawns every task on `handle`.
    pub fn new(handle: tokio::runtime::Handle) -> TokioRuntime {
        TokioRuntime { handle }
    }

    /// `current` builds a runtime on the Tokio runtime of the calling context.
    ///
    /// # Panics
    ///
    /// `current` panics when the caller runs outside a Tokio runtime context.
    pub fn current() -> TokioRuntime {
        TokioRuntime { handle: tokio::runtime::Handle::current() }
    }
}

#[cfg(feature = "tokio")]
struct TokioTask(tokio::task::JoinHandle<()>);

#[cfg(feature = "tokio")]
impl TaskHandle for TokioTask {
    fn cancel(&self) {
        self.0.abort();
    }

    fn detach(self: Box<Self>) {}
}

#[cfg(feature = "tokio")]
impl Runtime for TokioRuntime {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn spawn(&self, future: BoxFuture<'static, ()>) {
        self.handle.spawn(future);
    }

    fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send + 'static>) -> BoxTaskHandle {
        Box::new(TokioTask(self.handle.spawn_blocking(work)))
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}
