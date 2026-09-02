use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Runtime: Send + Sync + 'static {
    fn now(&self) -> Instant;
    fn spawn(&self, future: BoxFuture<'static, ()>);
    fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send + 'static>);
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()>;
}

#[cfg(feature = "tokio")]
pub struct TokioRuntime {
    handle: tokio::runtime::Handle,
}

#[cfg(feature = "tokio")]
impl TokioRuntime {
    pub fn new(handle: tokio::runtime::Handle) -> TokioRuntime {
        TokioRuntime { handle }
    }

    pub fn current() -> TokioRuntime {
        TokioRuntime { handle: tokio::runtime::Handle::current() }
    }
}

#[cfg(feature = "tokio")]
impl Runtime for TokioRuntime {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn spawn(&self, future: BoxFuture<'static, ()>) {
        self.handle.spawn(future);
    }

    fn spawn_blocking(&self, work: Box<dyn FnOnce() + Send + 'static>) {
        self.handle.spawn_blocking(work);
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}
