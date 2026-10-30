//! Shared operation lifecycle and deferred completion ownership for native
//! backends.

use std::collections::VecDeque;
use std::fs::File;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::authority::{Admission, DomainId, Request, SharedDomainKey};
use super::native::{Error, Scope};
use super::protocol::{self, OperationId, Participant, Progress};

struct Member {
    scope: Arc<Scope>,
    participant: Participant,
    // Close only: explicit LOCK_UN would also release inherited descriptions.
    _owner: File,
}

/// Participant ownership is retained by all its outstanding operations.
#[derive(Clone)]
pub struct Client(Arc<Member>);

impl Client {
    pub(crate) fn new(scope: Arc<Scope>, participant: Participant, owner: File) -> Self {
        Self(Arc::new(Member { scope, participant, _owner: owner }))
    }

    pub fn participant(&self) -> Participant {
        self.0.participant
    }

    pub fn register_shared_domain(&self, key: SharedDomainKey) -> Result<DomainId, Error> {
        self.0.scope.transaction(|state, _| state.register_shared_domain(key))
    }

    pub fn register_private_domain(&self, local: u64) -> Result<DomainId, Error> {
        self.0.scope.transaction(|state, _| state.register_private_domain(self.0.participant, local))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn register_mount_domain(&self, mount: u64) -> Result<DomainId, Error> {
        // STATX_MNT_ID_UNIQUE is never recycled during the boot. The tmpfs
        // authority generation bounds that lifetime; user namespace evidence
        // qualifies the identity independently of process-local interning.
        let mut filesystem = [0; 16];
        filesystem[..8].copy_from_slice(b"linuxmnt");
        filesystem[8..].copy_from_slice(&mount.to_le_bytes());
        self.register_shared_domain(SharedDomainKey {
            namespace: self.0.scope.mount_namespace(),
            filesystem,
            incarnation: self.0.scope.generation().0,
        })
    }

    pub fn prepare(&self, request: Request) -> Result<Prepared, Error> {
        let (id, admission) = self.0.scope.transaction(|state, at| {
            let id = state.ledger().next_operation(self.0.participant)?;
            Ok((id, state.prepare(id, request, at)?))
        })?;
        Ok(Prepared { member: self.0.clone(), id, admission, consumed: false })
    }
}

/// Reversible budget ownership. Dropping this without running aborts the hold.
pub struct Prepared {
    member: Arc<Member>,
    id: OperationId,
    admission: Admission,
    consumed: bool,
}

/// Actual completed work reported by a synchronous physical callback.
pub struct Completion<T> {
    pub value: T,
    pub operations: u32,
    pub failed: bool,
}

impl Prepared {
    pub fn admission(&self) -> Admission {
        self.admission
    }

    pub fn narrow(&mut self, optional_operations: u32) -> Result<Admission, Error> {
        if self.consumed {
            return Err(Error::Authority(protocol::Error::InvalidTransition.into()));
        }
        self.admission = self.member.scope.transaction(|state, _| state.narrow(self.id, optional_operations))?;
        Ok(self.admission)
    }

    /// Execute only after shared start permission commits. A denied start
    /// retains this preparation for retry or drop. The callback must retain
    /// physical ownership until its filesystem work actually returns.
    pub fn try_run<T>(&mut self, work: impl FnOnce(Admission) -> Completion<T>) -> Result<T, Error> {
        let physical = self.authorize()?;
        let result = work(self.admission);
        physical.finish(result.operations, result.failed)?;
        Ok(result.value)
    }

    pub(crate) fn authorize(&mut self) -> Result<Physical, Error> {
        if self.consumed {
            return Err(Error::Authority(protocol::Error::InvalidTransition.into()));
        }
        let started = self.member.scope.transaction(|state, at| {
            state.authorize(self.id, at)?;
            Ok(at)
        })?;
        self.consumed = true;
        Ok(Physical { pending: Some(Pending { member: self.member.clone(), id: self.id, progress: None }), started })
    }
}

/// Internal completion ownership, retained by the governor's physical grant.
/// Dropping it is only legal after physical execution has ended.
pub(crate) struct Physical {
    pending: Option<Pending>,
    started: u64,
}

impl Physical {
    pub(crate) fn finish(mut self, operations: u32, failed: bool) -> Result<(), Error> {
        let elapsed_ns = self
            .pending
            .as_ref()
            .expect("physical completion ownership")
            .member
            .scope
            .now()?
            .saturating_sub(self.started);
        let mut pending = self.pending.take().expect("physical completion ownership");
        pending.progress = Some(Progress { revision: 1, operations, elapsed_ns, failed });
        pending.submit()
    }
}

impl Drop for Physical {
    fn drop(&mut self) {
        if let Some(mut pending) = self.pending.take() {
            pending.progress = Some(Progress { revision: 1, failed: true, ..Progress::default() });
            let _ = pending.submit();
        }
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        if !self.consumed {
            let _ = Pending { member: self.member.clone(), id: self.id, progress: None }.submit();
        }
    }
}

pub(crate) struct Pending {
    member: Arc<Member>,
    id: OperationId,
    progress: Option<Progress>,
}

impl Pending {
    pub(crate) fn attempt(&self) -> Result<(), Error> {
        self.member.scope.transaction(|state, at| match self.progress {
            Some(progress) => state.settle(self.id, progress, at),
            None => state.cancel(self.id, at).map(|_| ()),
        })
    }

    fn submit(self) -> Result<(), Error> {
        match self.attempt() {
            Ok(()) => Ok(()),
            Err(Error::Busy) => {
                let scope = self.member.scope.clone();
                scope.enqueue(self)
            }
            Err(error) => {
                self.member.scope.fail();
                Err(error)
            }
        }
    }
}

struct Queue {
    tasks: VecDeque<Pending>,
    running: bool,
    in_progress: bool,
}

pub(crate) struct Cleanup {
    state: Mutex<Queue>,
}

impl Cleanup {
    pub(crate) fn new() -> Self {
        Self { state: Mutex::new(Queue { tasks: VecDeque::new(), running: false, in_progress: false }) }
    }
    pub(crate) fn status(&self) -> (usize, bool) {
        let queue = self.state.lock().unwrap_or_else(|error| error.into_inner());
        (queue.tasks.len() + usize::from(queue.in_progress), queue.running)
    }
    pub(crate) fn enqueue(&self, scope: &Arc<Scope>, pending: Pending, limit: usize) -> Result<(), Error> {
        scope.check_context()?;
        let mut queue = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if queue.tasks.len() + usize::from(queue.in_progress) >= limit {
            scope.fail();
            queue.tasks.clear();
            return Err(Error::Failed);
        }
        queue.tasks.push_back(pending);
        if queue.running {
            return Ok(());
        }
        queue.running = true;
        let worker_scope = scope.clone();
        if std::thread::Builder::new()
            .name("tree-fucker-coordination".into())
            .spawn(move || Self::flush(worker_scope))
            .is_err()
        {
            scope.fail();
            queue.tasks.clear();
            queue.running = false;
            return Err(Error::Failed);
        }
        Ok(())
    }

    fn flush(scope: Arc<Scope>) {
        loop {
            let pending = {
                let mut queue = scope.cleanup().state.lock().unwrap_or_else(|error| error.into_inner());
                queue.in_progress = false;
                match queue.tasks.pop_front() {
                    Some(pending) => {
                        queue.in_progress = true;
                        pending
                    }
                    None => {
                        queue.running = false;
                        return;
                    }
                }
            };
            match pending.attempt() {
                Ok(()) => {}
                Err(Error::Busy) => {
                    let mut queue = scope.cleanup().state.lock().unwrap_or_else(|error| error.into_inner());
                    queue.in_progress = false;
                    queue.tasks.push_back(pending);
                    drop(queue);
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => {
                    scope.fail();
                    let mut queue = scope.cleanup().state.lock().unwrap_or_else(|error| error.into_inner());
                    queue.tasks.clear();
                    queue.running = false;
                    queue.in_progress = false;
                    return;
                }
            }
        }
    }
}
