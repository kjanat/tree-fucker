use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

use crate::{CancellationToken, Error, FsError, Result};

type Job = Box<dyn FnOnce() + Send>;
pub(super) const CHECK_INTERVAL: Duration = Duration::from_millis(50);

/// A reusable, bounded set of workers for one-shot listing leases.
///
/// Clone this executor to share its worker bound across scans. Workers are
/// created lazily and reused. A blocked call retains its worker; cancellation
/// never starts a replacement beyond the configured bound.
#[derive(Clone)]
pub struct ListingExecutor(Arc<Pool>);

struct Pool {
    capacity: usize,
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Default)]
struct State {
    workers: usize,
    idle: Vec<mpsc::Sender<Job>>,
}

pub(super) struct Worker {
    pool: Arc<Pool>,
    sender: Option<mpsc::Sender<Job>>,
}

impl ListingExecutor {
    pub fn new(maximum_workers: usize) -> Result<Self> {
        if maximum_workers == 0 {
            return Err(Error::InvalidConfig("listing executor requires at least one worker".into()));
        }
        Ok(Self(Arc::new(Pool {
            capacity: maximum_workers,
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
        })))
    }

    pub fn capacity(&self) -> usize {
        self.0.capacity
    }

    pub(super) fn acquire(&self, cancel: &CancellationToken, mut check: impl FnMut() -> Result<()>) -> Result<Worker> {
        let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            check()?;
            if let Some(sender) = state.idle.pop() {
                return Ok(Worker { pool: self.0.clone(), sender: Some(sender) });
            }
            if state.workers < self.0.capacity {
                let (sender, receiver) = mpsc::channel::<Job>();
                std::thread::Builder::new()
                    .name("tree-listing".into())
                    .spawn(move || {
                        while let Ok(job) = receiver.recv() {
                            // A failed adapter must not permanently consume a
                            // pool slot.
                            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                        }
                    })
                    .map_err(|e| Error::Io(FsError::Fatal(format!("cannot start listing worker: {e}"))))?;
                state.workers += 1;
                return Ok(Worker { pool: self.0.clone(), sender: Some(sender) });
            }
            state = self.0.changed.wait_timeout(state, CHECK_INTERVAL).unwrap_or_else(|e| e.into_inner()).0;
        }
    }
}

impl Worker {
    pub(super) fn run(self, work: impl FnOnce() + Send + 'static) -> Result<()> {
        let sender = self.sender.as_ref().expect("worker sender").clone();
        sender
            .send(Box::new(move || {
                let _worker = self;
                work();
            }))
            .map_err(|_| Error::WorkerLost)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            self.pool.state.lock().unwrap_or_else(|e| e.into_inner()).idle.push(sender);
            self.pool.changed.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shared_pool_never_replaces_a_held_worker_and_reuses_it_after_completion() {
        let pool = ListingExecutor::new(1).unwrap();
        let cancel = CancellationToken::new();
        let worker = pool.acquire(&cancel, || Ok(())).unwrap();
        let (started, start) = mpsc::channel();
        let (release, released) = mpsc::channel();
        worker
            .run(move || {
                started.send(()).unwrap();
                released.recv().unwrap();
            })
            .unwrap();
        start.recv_timeout(Duration::from_secs(5)).unwrap();
        let waiting_cancel = CancellationToken::new();
        let waiter = {
            let pool = pool.clone();
            let cancel = waiting_cancel.clone();
            std::thread::spawn(move || pool.acquire(&cancel, || Ok(())))
        };
        waiting_cancel.cancel();
        assert!(matches!(waiter.join().unwrap(), Err(Error::Cancelled)));
        assert_eq!(pool.0.state.lock().unwrap().workers, 1);
        assert!(pool.0.state.lock().unwrap().idle.is_empty());
        release.send(()).unwrap();
        let worker = pool.acquire(&cancel, || Ok(())).unwrap();
        assert_eq!(pool.0.state.lock().unwrap().workers, 1);
        drop(worker);
        assert_eq!(pool.0.state.lock().unwrap().idle.len(), 1);
    }

    #[test]
    fn a_panicking_job_returns_its_worker_to_the_pool() {
        let pool = ListingExecutor::new(1).unwrap();
        let cancel = CancellationToken::new();
        pool.acquire(&cancel, || Ok(())).unwrap().run(|| panic!("adapter failure")).unwrap();
        let worker = pool.acquire(&cancel, || Ok(())).unwrap();
        assert_eq!(pool.0.state.lock().unwrap().workers, 1);
        drop(worker);
        assert!(ListingExecutor::new(0).is_err());
    }
}
