use std::sync::TryLockError;

use super::*;
use crate::coordination::authority::{self, DomainId, Origin, Request};
use crate::coordination::native::{self, Client, Physical, Prepared, Scope};
use crate::coordination::protocol::{self, Work};

const FIRST_RETRY: Duration = Duration::from_millis(3);
const MAX_RETRY: Duration = Duration::from_millis(10);

#[derive(Clone, Copy)]
struct Retry {
    at: MonotonicTime,
    delay: Duration,
}

enum Ownership {
    Prepared(Prepared),
    Physical(Physical),
}

#[derive(Default)]
struct State {
    entries: BTreeMap<GrantId, Ownership>,
    domains: BTreeMap<StorageDomainId, DomainId>,
    failure: Option<String>,
    retry: Option<Retry>,
}

pub(super) struct Binding {
    scope: Arc<Scope>,
    client: Client,
    info: crate::coordination::ScopeInfo,
    state: Mutex<State>,
}

impl State {
    fn deny(&mut self, error: native::Error, now: MonotonicTime) -> ThrottleCause {
        match error {
            native::Error::Busy
            | native::Error::Authority(
                authority::Error::DomainPhysical | authority::Error::Protocol(protocol::Error::PhysicalCapacity),
            ) => {
                // Short lock/occupancy conflicts can resolve within one lease.
                // Back off only after actual denials, never when reading a
                // hint.
                let delay = self.retry.map_or(FIRST_RETRY, |retry| retry.delay.saturating_mul(2).min(MAX_RETRY));
                self.retry = Some(Retry { at: now + delay, delay });
                ThrottleCause::Coordination
            }
            native::Error::Authority(authority::Error::Quarantined) => {
                self.retry = None;
                ThrottleCause::StuckWorker
            }
            native::Error::Authority(authority::Error::Ceiling { minimum_ns }) => {
                self.retry = None;
                ThrottleCause::CommandCeiling { required: Duration::from_nanos(minimum_ns) }
            }
            native::Error::Authority(authority::Error::Budget | authority::Error::Bootstrap) => {
                // Debt needs longer than a bookkeeping lock.
                self.retry = Some(Retry { at: now + MAX_RETRY, delay: MAX_RETRY });
                ThrottleCause::Coordination
            }
            error => {
                self.failure.get_or_insert_with(|| error.to_string());
                ThrottleCause::CoordinationFailed
            }
        }
    }
}

impl Binding {
    pub(super) fn status(&self) -> crate::coordination::State {
        let diagnostics = self.scope.diagnostics();
        let failure = self.failure().or_else(|| diagnostics.as_ref().err().map(ToString::to_string));
        crate::coordination::State::Shared {
            scope: Box::new(self.info.clone()),
            failure,
            pending_settlements: diagnostics.as_ref().ok().map(|diagnostics| diagnostics.pending_settlements),
            bookkeeping_active: diagnostics.as_ref().ok().map(|diagnostics| diagnostics.bookkeeping_active),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, ThrottleCause> {
        // Check process identity before touching a possibly inherited mutex.
        self.scope.check_context().map_err(|_| ThrottleCause::CoordinationFailed)?;
        match self.state.try_lock() {
            Ok(state) => Ok(state),
            Err(TryLockError::WouldBlock) => Err(ThrottleCause::Coordination),
            Err(TryLockError::Poisoned(_)) => Err(ThrottleCause::CoordinationFailed),
        }
    }

    pub(super) fn admit(
        &self,
        host: &HostGovernor,
        reservation: Reservation,
        work: Work,
        now: MonotonicTime,
    ) -> Result<Admitted, ThrottleCause> {
        let mut state = self.lock()?;
        if state.failure.is_some() {
            return Err(ThrottleCause::CoordinationFailed);
        }
        let id = reservation.id;
        let local = guard(&host.inner).try_prepare(reservation.clone(), now)?;
        // Local budget stays provisional throughout the native transaction.
        // No local governor mutex is held while acquiring the shared lock.
        let result = (|| {
            let domain = match reservation.domain {
                None => None,
                Some(id) => {
                    let domain = match state.domains.get(&id) {
                        Some(domain) => *domain,
                        None => {
                            #[cfg(target_os = "linux")]
                            let domain = match id.unique_mount() {
                                Some(mount) => self.client.register_mount_domain(mount)?,
                                None => self.client.register_private_domain(id.get())?,
                            };
                            #[cfg(any(target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
                            let domain = self.client.register_private_domain(id.get())?;
                            state.domains.insert(id, domain);
                            domain
                        }
                    };
                    Some(domain)
                }
            };
            self.client.prepare(Request {
                work,
                origin: match reservation.origin {
                    WorkOrigin::Background => Origin::Background,
                    WorkOrigin::Foreground => Origin::Foreground,
                },
                domain,
                required: reservation
                    .reads
                    .checked_add(reservation.registrations)
                    .ok_or(authority::Error::InvalidConfig)?,
                desired: local.operations,
                ceiling_ns: reservation
                    .ceiling
                    .map_or(u64::MAX, |duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)),
            })
        })();
        match result {
            Ok(prepared) => {
                let mut governor = guard(&host.inner);
                let local = governor.prepared.get_mut(&id).expect("local preparation");
                let operations = prepared.admission().optional_operations;
                local.reservation.operations = operations;
                local.admitted.operations = operations;
                local.admitted.cost = local.admitted.cost.min(
                    local
                        .estimate
                        .saturating_mul(local.reservation.reads + local.reservation.registrations + operations),
                );
                let admitted = local.admitted;
                state.entries.insert(id, Ownership::Prepared(prepared));
                state.retry = None;
                Ok(admitted)
            }
            Err(error) => {
                guard(&host.inner).prepared.remove(&id);
                host.changed();
                Err(state.deny(error, now))
            }
        }
    }

    pub(super) fn start(&self, host: &HostGovernor, id: GrantId, now: MonotonicTime) -> Result<(), ThrottleCause> {
        let mut state = self.lock()?;
        if state.failure.is_some() {
            return Err(ThrottleCause::CoordinationFailed);
        }
        let Some(ownership) = state.entries.get_mut(&id) else {
            return Err(ThrottleCause::Concurrency);
        };
        let Ownership::Prepared(prepared) = ownership else {
            return Ok(());
        };
        {
            let mut governor = guard(&host.inner);
            governor.account(now);
            let local = governor.prepared.get(&id).expect("local preparation");
            let domain = local.reservation.domain;
            if governor.quarantined(domain) {
                return Err(ThrottleCause::StuckWorker);
            }
            let bytes = if local.reservation.listing { governor.bytes_estimate(domain) } else { 0 };
            if id.release().is_none()
                && (governor.memory_exceeded(bytes)
                    || (local.reservation.listing && governor.in_flight_bytes_exceeded(bytes)))
            {
                return Err(ThrottleCause::Memory);
            }
            // Running work can consume the remaining duty budget while
            // this preparation waits for shared capacity. Its own hold is
            // already reserved, but other preparations must remain charged.
            if id.release().is_none()
                && nanos(local.admitted.cost)
                    > governor.affordable(domain, local.reservation.origin, local.reservation.ceiling, Some(id))
            {
                let cause = match local.reservation.origin {
                    WorkOrigin::Background => ThrottleCause::DutyBudget,
                    WorkOrigin::Foreground => ThrottleCause::ForegroundCeiling,
                };
                let cost = local.admitted.cost;
                governor.deny(cause, domain, cost, now);
                return Err(cause);
            }
            governor.may_start(domain)?;
            governor.prepared.get_mut(&id).expect("local preparation").physical = true;
            *governor.running.entry(domain).or_insert(0) += 1;
            governor.running_total += 1;
        }
        let result = prepared.authorize();
        let mut governor = guard(&host.inner);
        let local = governor.prepared.get_mut(&id).expect("local preparation");
        local.physical = false;
        let domain = local.reservation.domain;
        Governor::decrement(&mut governor.running, domain);
        governor.running_total -= 1;
        match result {
            Ok(physical) => {
                let local = governor.prepared.remove(&id).expect("local preparation");
                governor.record_admission(local.reservation, local.admitted, now);
                governor.start(id, now);
                *ownership = Ownership::Physical(physical);
                state.retry = None;
                Ok(())
            }
            Err(error) => Err(state.deny(error, now)),
        }
    }

    pub(super) fn release(&self, host: &HostGovernor, id: GrantId, now: MonotonicTime) -> bool {
        // Failed authority state still permits releasing completed local
        // ownership. check_context checks process/security identity before
        // returning Failed, so inherited or incompatible contexts stay fenced.
        if !matches!(self.scope.check_context(), Ok(()) | Err(native::Error::Failed)) {
            return false;
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let ownership = state.entries.remove(&id);
        let mut governor = guard(&host.inner);
        let stuck = governor.grants.get(&id).is_some_and(|grant| grant.stuck);
        let failed = stuck || governor.grants.get(&id).is_some_and(|grant| grant.failed);
        let operations = governor.grants.get(&id).map_or(0, |grant| grant.performed.unwrap_or(grant.required));
        governor.prepared.remove(&id);
        governor.release(id, now);
        drop(governor);
        drop(state);
        match ownership {
            Some(Ownership::Physical(physical)) => {
                if let Err(error) = physical.finish(operations, failed) {
                    self.state.lock().unwrap_or_else(|error| error.into_inner()).deny(error, now);
                }
            }
            other => drop(other),
        }
        host.changed();
        stuck
    }

    pub(super) fn failure(&self) -> Option<String> {
        if let Err(error) = self.scope.check_context() {
            return Some(error.to_string());
        }
        match self.state.lock() {
            Ok(state) => state.failure.clone(),
            Err(_) => Some("shared governor mutex is poisoned".into()),
        }
    }

    pub(super) fn retry_at(&self, now: MonotonicTime) -> Option<MonotonicTime> {
        match self.lock() {
            Ok(state)
                if state.failure.is_none()
                    && (state.retry.is_some()
                        || state.entries.values().any(|entry| matches!(entry, Ownership::Prepared(_)))) =>
            {
                // If local constraints prevented a retry at the old deadline,
                // retain the backoff instead of scheduling an expired hint in
                // a tight loop. Reading a future deadline never postpones it.
                Some(state.retry.map_or(
                    now + FIRST_RETRY,
                    |retry| {
                        if retry.at > now { retry.at } else { now + retry.delay }
                    },
                ))
            }
            Err(ThrottleCause::Coordination) => Some(now + FIRST_RETRY),
            _ => None,
        }
    }
}

impl HostGovernor {
    /// Compose process-local constraints with an explicitly selected native
    /// scope.
    pub fn with_coordination(config: &HostConfig, scope: Arc<Scope>) -> Result<Self, native::Error> {
        config.validate().map_err(|_| authority::Error::InvalidConfig)?;
        let diagnostics = scope.diagnostics()?;
        let client = scope.join()?;
        let info = crate::coordination::ScopeInfo {
            directory: diagnostics.path.clone(),
            generation: diagnostics.generation,
            participant: client.participant(),
            limits: diagnostics.config,
            identity: diagnostics.identity(),
        };
        let mut host = Self::independent(config);
        host.coordination = Some(Arc::new(crate::coordination::Selection {
            mode: crate::coordination::Mode::Required(crate::coordination::Options {
                scope: crate::coordination::Rendezvous::Directory(diagnostics.path),
                limits: diagnostics.config,
            }),
            fallback: None,
        }));
        host.shared = Some(Arc::new(Binding { scope, client, info, state: Mutex::new(State::default()) }));
        Ok(host)
    }
}
