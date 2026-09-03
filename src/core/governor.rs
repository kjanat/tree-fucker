use std::collections::BTreeMap;
use std::time::Duration;

use super::types::MonotonicTime;
use crate::config::Config;
use crate::domain::StorageDomainId;
use crate::ids::{JobId, WatchRequestId};
use crate::path::RelativePath;
use crate::update::ThrottleCause;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GrantId {
    Job(JobId),
    WatchRegistration(WatchRequestId),
}

impl GrantId {
    pub fn job(self) -> Option<JobId> {
        match self {
            GrantId::Job(id) => Some(id),
            GrantId::WatchRegistration(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionDecision {
    Granted,
    Denied(ThrottleCause),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub id: GrantId,
    pub path: RelativePath,
    pub lease: u32,
    pub domain: Option<StorageDomainId>,
    pub reserved: Duration,
    pub charged: Duration,
    pub admitted: MonotonicTime,
    pub started: Option<MonotonicTime>,
    pub stuck: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DomainAccount {
    pub granted: Duration,
    pub charged: Duration,
    pub grants: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub id: GrantId,
    pub path: RelativePath,
    pub reads: u32,
    pub registrations: u32,
    pub lease: u32,
    pub domain: Option<StorageDomainId>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Account {
    granted: i128,
    charged: i128,
    grants: u64,
}

impl Account {
    fn view(self) -> DomainAccount {
        DomainAccount { granted: duration(self.granted), charged: duration(self.charged), grants: self.grants }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernorView {
    pub capacity: Duration,
    pub level: Duration,
    pub debt: Duration,
    pub reserved: Duration,
    pub charged: Duration,
    pub reported_blocking: Duration,
    pub running_occupancy: Duration,
    pub in_flight: usize,
    pub grants: u64,
    pub lease_grants: u64,
    pub watch_registration_grants: u64,
    pub denials: u64,
    pub throttled_duration: Duration,
    pub next_admissible: Option<MonotonicTime>,
    pub last_decision: Option<AdmissionDecision>,
    pub bootstrap: DomainAccount,
    pub domains: BTreeMap<StorageDomainId, DomainAccount>,
}

pub struct Governor {
    rate: u128,
    capacity: i128,
    level: i128,
    updated: MonotonicTime,
    estimate: Duration,
    stuck_threshold: Duration,
    grants: BTreeMap<GrantId, Grant>,
    reserved_total: i128,
    charged_total: i128,
    reported_total: i128,
    granted: u64,
    lease_granted: u64,
    watch_registration_grants: u64,
    denials: u64,
    throttled_since: Option<MonotonicTime>,
    throttled_total: Duration,
    denied_cost: Option<Duration>,
    last_decision: Option<AdmissionDecision>,
    bootstrap: Account,
    accounts: BTreeMap<StorageDomainId, Account>,
}

const NANOS_PER_SECOND: u128 = 1_000_000_000;

fn nanos(value: Duration) -> i128 {
    i128::try_from(value.as_nanos()).unwrap_or(i128::MAX)
}

fn duration(value: i128) -> Duration {
    match u64::try_from(value.max(0)) {
        Ok(value) => Duration::from_nanos(value),
        Err(_) => Duration::MAX,
    }
}

impl Governor {
    pub fn new(config: &Config, now: MonotonicTime) -> Governor {
        let capacity = nanos(config.background_burst);
        Governor {
            rate: Duration::try_from_secs_f64(config.background_duty).unwrap_or(Duration::ZERO).as_nanos(),
            capacity,
            level: capacity,
            updated: now,
            estimate: config.initial_cost_estimate,
            stuck_threshold: config.stuck_threshold,
            grants: BTreeMap::new(),
            reserved_total: 0,
            charged_total: 0,
            reported_total: 0,
            granted: 0,
            lease_granted: 0,
            watch_registration_grants: 0,
            denials: 0,
            throttled_since: None,
            throttled_total: Duration::ZERO,
            denied_cost: None,
            last_decision: None,
            bootstrap: Account::default(),
            accounts: BTreeMap::new(),
        }
    }

    fn account_mut(&mut self, domain: Option<StorageDomainId>) -> &mut Account {
        match domain {
            Some(domain) => self.accounts.entry(domain).or_default(),
            None => &mut self.bootstrap,
        }
    }

    pub fn attribute(&mut self, id: GrantId, domain: StorageDomainId) {
        let Some(grant) = self.grants.get_mut(&id) else {
            return;
        };
        if grant.domain == Some(domain) {
            return;
        }
        let previous = grant.domain;
        grant.domain = Some(domain);
        let granted = nanos(grant.reserved);
        let charged = nanos(grant.charged);
        let from = self.account_mut(previous);
        from.granted -= granted;
        from.charged -= charged;
        from.grants -= 1;
        let to = self.account_mut(Some(domain));
        to.granted += granted;
        to.charged += charged;
        to.grants += 1;
    }

    pub fn cost_of(&self, operations: u32) -> Duration {
        self.estimate.saturating_mul(operations)
    }

    fn refill(&mut self, now: MonotonicTime) {
        let elapsed = now.since(self.updated);
        if elapsed.is_zero() {
            return;
        }
        if self.level >= self.capacity {
            self.updated = now;
            return;
        }
        let refill =
            i128::try_from(elapsed.as_nanos().saturating_mul(self.rate) / NANOS_PER_SECOND).unwrap_or(i128::MAX);
        if refill <= 0 {
            return;
        }
        self.level = (self.level + refill).min(self.capacity);
        self.updated = now;
    }

    pub fn account(&mut self, now: MonotonicTime) {
        self.refill(now);
        let mut extra: i128 = 0;
        let mut per_domain: Vec<(Option<StorageDomainId>, i128)> = Vec::new();
        for grant in self.grants.values_mut() {
            let Some(started) = grant.started else {
                continue;
            };
            let occupancy = now.since(started);
            if occupancy > grant.charged {
                let delta = nanos(occupancy - grant.charged);
                extra += delta;
                per_domain.push((grant.domain, delta));
                grant.charged = occupancy;
            }
        }
        for (domain, delta) in per_domain {
            self.account_mut(domain).charged += delta;
        }
        if extra > 0 {
            self.level -= extra;
            self.charged_total += extra;
        }
    }

    pub fn try_admit(&mut self, reservation: Reservation, now: MonotonicTime) -> Result<Duration, ThrottleCause> {
        let Reservation { id, path, reads, registrations, lease, domain } = reservation;
        self.account(now);
        let cost = self.cost_of(reads + registrations);
        if self.level < nanos(cost) {
            self.denials += 1;
            self.denied_cost = Some(match self.denied_cost {
                Some(previous) => previous.max(cost),
                None => cost,
            });
            self.last_decision = Some(AdmissionDecision::Denied(ThrottleCause::DutyBudget));
            if self.throttled_since.is_none() {
                self.throttled_since = Some(now);
            }
            return Err(ThrottleCause::DutyBudget);
        }
        self.level -= nanos(cost);
        self.reserved_total += nanos(cost);
        self.charged_total += nanos(cost);
        self.granted += 1;
        if lease > 0 {
            self.lease_granted += 1;
        }
        self.denied_cost = None;
        self.watch_registration_grants += u64::from(registrations);
        self.last_decision = Some(AdmissionDecision::Granted);
        if let Some(since) = self.throttled_since.take() {
            self.throttled_total += now.since(since);
        }
        let account = self.account_mut(domain);
        account.granted += nanos(cost);
        account.charged += nanos(cost);
        account.grants += 1;
        self.grants.insert(
            id,
            Grant {
                id,
                path,
                lease,
                domain,
                reserved: cost,
                charged: cost,
                admitted: now,
                started: None,
                stuck: false,
            },
        );
        Ok(cost)
    }

    pub fn report(&mut self, id: GrantId, blocking: Duration, now: MonotonicTime) {
        self.account(now);
        let Some(grant) = self.grants.get_mut(&id) else {
            return;
        };
        self.reported_total += nanos(blocking);
        let Some(started) = grant.started else {
            return;
        };
        let occupancy = now.since(started);
        let charge = blocking.min(occupancy).max(grant.reserved);
        if charge > grant.charged {
            let extra = nanos(charge - grant.charged);
            let domain = grant.domain;
            grant.charged = charge;
            self.level -= extra;
            self.charged_total += extra;
            self.account_mut(domain).charged += extra;
        }
    }

    pub fn start(&mut self, id: GrantId, at: MonotonicTime) {
        if let Some(grant) = self.grants.get_mut(&id)
            && grant.started.is_none()
        {
            grant.started = Some(at);
        }
    }

    pub fn release(&mut self, id: GrantId, now: MonotonicTime) {
        if !self.grants.contains_key(&id) {
            return;
        }
        self.account(now);
        self.grants.remove(&id);
    }

    pub fn in_flight(&self) -> usize {
        self.grants.values().filter(|g| g.started.is_some()).count()
    }

    pub fn running_occupancy(&self, now: MonotonicTime) -> Duration {
        self.grants.values().filter_map(|g| g.started.map(|at| now.since(at))).sum()
    }

    pub fn newly_stuck(&self, now: MonotonicTime) -> Vec<GrantId> {
        self.grants
            .values()
            .filter(|g| !g.stuck && g.started.is_some_and(|at| now.since(at) >= self.stuck_threshold))
            .map(|g| g.id)
            .collect()
    }

    pub fn mark_stuck(&mut self, id: GrantId) {
        if let Some(grant) = self.grants.get_mut(&id) {
            grant.stuck = true;
        }
    }

    pub fn stuck_grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.values().filter(|g| g.stuck)
    }

    pub fn next_stuck_deadline(&self) -> Option<MonotonicTime> {
        self.grants.values().filter(|g| !g.stuck).filter_map(|g| g.started.map(|at| at + self.stuck_threshold)).min()
    }

    pub fn next_admissible(&self, now: MonotonicTime, operations: u32) -> Option<MonotonicTime> {
        self.affordable_at(now, nanos(self.cost_of(operations)))
    }

    pub fn resume_at(&self, now: MonotonicTime) -> Option<MonotonicTime> {
        self.affordable_at(now, nanos(self.denied_cost?))
    }

    fn affordable_at(&self, now: MonotonicTime, cost: i128) -> Option<MonotonicTime> {
        if self.level >= cost {
            return None;
        }
        let rate = i128::try_from(self.rate).unwrap_or(i128::MAX);
        if rate <= 0 {
            return Some(now + Duration::MAX);
        }
        let per_second = i128::try_from(NANOS_PER_SECOND).unwrap_or(i128::MAX);
        let deficit = (cost - self.level).saturating_mul(per_second);
        let wait = Duration::from_nanos(1).max(duration(deficit / rate));
        Some(now + wait)
    }

    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.values()
    }

    pub fn view(&self, now: MonotonicTime) -> GovernorView {
        GovernorView {
            capacity: duration(self.capacity),
            level: duration(self.level),
            debt: duration(-self.level),
            reserved: duration(self.reserved_total),
            charged: duration(self.charged_total),
            reported_blocking: duration(self.reported_total),
            running_occupancy: self.running_occupancy(now),
            in_flight: self.in_flight(),
            grants: self.granted,
            lease_grants: self.lease_granted,
            watch_registration_grants: self.watch_registration_grants,
            denials: self.denials,
            throttled_duration: match self.throttled_since {
                Some(since) => self.throttled_total + now.since(since),
                None => self.throttled_total,
            },
            next_admissible: self.next_admissible(now, 1),
            last_decision: self.last_decision,
            bootstrap: self.bootstrap.view(),
            domains: self.accounts.iter().map(|(id, account)| (*id, account.view())).collect(),
        }
    }
}
