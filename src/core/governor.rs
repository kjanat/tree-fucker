use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use super::types::MonotonicTime;
use crate::config::Config;
use crate::domain::{AccessTopology, DomainCapabilities, MediaHint, StorageDomainId};
use crate::ids::{JobId, WatchRequestId};
use crate::path::RelativePath;
use crate::update::ThrottleCause;

const LATENCY_HISTORY: usize = 32;
const QUEUE_HISTORY: usize = 8;
const TARGET_FACTOR: u32 = 2;
const LOCAL_START_WINDOW: usize = 2;
const CONSERVATIVE_START_WINDOW: usize = 1;
const CONSERVATIVE_TOPOLOGY_CEILING: usize = 2;

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LatencySummary {
    pub samples: usize,
    pub minimum: Duration,
    pub median: Duration,
    pub mean: Duration,
    pub tail: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainView {
    pub granted: Duration,
    pub charged: Duration,
    pub grants: u64,
    pub capacity: Duration,
    pub level: Duration,
    pub debt: Duration,
    pub window: usize,
    pub ceiling: usize,
    pub in_flight: usize,
    pub stuck: usize,
    pub estimate: Duration,
    pub latency: LatencySummary,
    pub queue_delay: Duration,
    pub throttled_jobs: u64,
    pub throttled_duration: Duration,
    pub elapsed: Duration,
}

impl DomainView {
    pub fn effective_duty(&self) -> f64 {
        let elapsed = self.elapsed.as_secs_f64();
        if elapsed <= 0.0 { 0.0 } else { self.charged.as_secs_f64() / elapsed }
    }
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
    pub surcharged: Duration,
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
    pub domains: BTreeMap<StorageDomainId, DomainView>,
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

fn start_window(capabilities: &DomainCapabilities) -> usize {
    match capabilities.topology {
        AccessTopology::Local if capabilities.media != MediaHint::Removable => LOCAL_START_WINDOW,
        _ => CONSERVATIVE_START_WINDOW,
    }
}

fn topology_ceiling(capabilities: &DomainCapabilities, configured: usize) -> usize {
    let declared_conservative =
        matches!(capabilities.topology, AccessTopology::Remote | AccessTopology::Userspace | AccessTopology::Virtual)
            || capabilities.media == MediaHint::Removable;
    match declared_conservative {
        true => CONSERVATIVE_TOPOLOGY_CEILING.min(configured),
        false => configured,
    }
}

#[derive(Clone, Debug)]
struct Bucket {
    rate: u128,
    capacity: i128,
    level: i128,
    updated: MonotonicTime,
}

impl Bucket {
    fn new(duty: f64, burst: Duration, now: MonotonicTime) -> Bucket {
        let capacity = nanos(burst);
        Bucket {
            rate: Duration::try_from_secs_f64(duty).unwrap_or(Duration::ZERO).as_nanos(),
            capacity,
            level: capacity,
            updated: now,
        }
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

    fn affordable(&self, cost: i128) -> bool {
        self.level >= cost
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
}

#[derive(Clone, Debug)]
struct DomainState {
    bucket: Bucket,
    account: Account,
    window: usize,
    ceiling: usize,
    estimate: Duration,
    latency: VecDeque<Duration>,
    errors: VecDeque<bool>,
    completions: usize,
    queue: VecDeque<Duration>,
    summary: LatencySummary,
    standing_queue_delay: Duration,
    throttled_jobs: u64,
    throttled_since: Option<MonotonicTime>,
    throttled_total: Duration,
    since: MonotonicTime,
}

impl DomainState {
    fn new(config: &Config, capabilities: &DomainCapabilities, now: MonotonicTime) -> DomainState {
        let ceiling = config
            .per_domain_concurrency
            .min(config.max_in_flight)
            .min(topology_ceiling(capabilities, config.per_domain_concurrency))
            .max(1);
        DomainState {
            bucket: Bucket::new(config.domain_background_duty, config.domain_background_burst, now),
            account: Account::default(),
            window: start_window(capabilities).clamp(1, ceiling),
            ceiling,
            estimate: config.initial_cost_estimate,
            latency: VecDeque::new(),
            errors: VecDeque::new(),
            completions: 0,
            queue: VecDeque::new(),
            summary: LatencySummary::default(),
            standing_queue_delay: Duration::ZERO,
            throttled_jobs: 0,
            throttled_since: None,
            throttled_total: Duration::ZERO,
            since: now,
        }
    }

    fn summary(&self) -> LatencySummary {
        self.summary
    }

    fn recompute_summary(&mut self) {
        let samples = self.latency.len();
        if samples == 0 {
            self.summary = LatencySummary::default();
            return;
        }
        let mut sorted: Vec<Duration> = self.latency.iter().copied().collect();
        sorted.sort_unstable();
        let total: Duration = sorted.iter().copied().sum();
        let tail = (samples * 9 / 10).min(samples - 1);
        self.summary = LatencySummary {
            samples,
            minimum: sorted[0],
            median: sorted[samples / 2],
            mean: total / u32::try_from(samples).unwrap_or(u32::MAX),
            tail: sorted[tail],
        };
    }

    fn record_latency(&mut self, latency: Duration) {
        if self.latency.len() >= LATENCY_HISTORY {
            self.latency.pop_front();
        }
        self.latency.push_back(latency);
        self.completions += 1;
        self.recompute_summary();
        let ceiling = duration(self.bucket.capacity);
        self.estimate = self.summary.median.max(self.summary.minimum).min(ceiling).max(Duration::from_nanos(1));
    }

    fn record_queue_delay(&mut self, delay: Duration) {
        if self.queue.len() >= QUEUE_HISTORY {
            self.queue.pop_front();
        }
        self.queue.push_back(delay);
        self.standing_queue_delay = self.queue.iter().copied().min().unwrap_or(Duration::ZERO);
    }

    fn standing_queue_delay(&self) -> Duration {
        self.standing_queue_delay
    }

    fn record_error(&mut self, error: bool) {
        if self.errors.len() >= LATENCY_HISTORY {
            self.errors.pop_front();
        }
        self.errors.push_back(error);
    }

    fn adapt(&mut self, stuck: bool) {
        let summary = self.summary();
        if summary.samples == 0 && !stuck {
            return;
        }
        let target = summary.minimum.saturating_mul(TARGET_FACTOR);
        let queue_budget = summary.mean.saturating_mul(u32::try_from(self.window).unwrap_or(u32::MAX));
        let contended = stuck
            || self.errors.iter().any(|error| *error)
            || summary.tail > target
            || (!queue_budget.is_zero() && self.standing_queue_delay() > queue_budget);
        if contended {
            self.window = (self.window / 2).max(1);
            self.completions = 0;
            return;
        }
        if summary.samples >= 2 && self.completions >= self.window && self.window < self.ceiling {
            self.window += 1;
            self.completions = 0;
        }
    }
}

pub struct Governor {
    config: Config,
    global: Bucket,
    estimate: Duration,
    stuck_threshold: Duration,
    surcharge: Duration,
    grants: BTreeMap<GrantId, Grant>,
    reserved_total: i128,
    charged_total: i128,
    surcharged_total: i128,
    reported_total: i128,
    granted: u64,
    lease_granted: u64,
    watch_registration_grants: u64,
    denials: u64,
    throttled_since: Option<MonotonicTime>,
    throttled_total: Duration,
    denied: Option<(Option<StorageDomainId>, Duration)>,
    last_decision: Option<AdmissionDecision>,
    bootstrap: Account,
    domains: BTreeMap<StorageDomainId, DomainState>,
}

impl Governor {
    pub fn new(config: &Config, now: MonotonicTime) -> Governor {
        Governor {
            config: config.clone(),
            global: Bucket::new(config.background_duty, config.background_burst, now),
            estimate: config.initial_cost_estimate,
            stuck_threshold: config.stuck_threshold,
            surcharge: config.failure_surcharge,
            grants: BTreeMap::new(),
            reserved_total: 0,
            charged_total: 0,
            surcharged_total: 0,
            reported_total: 0,
            granted: 0,
            lease_granted: 0,
            watch_registration_grants: 0,
            denials: 0,
            throttled_since: None,
            throttled_total: Duration::ZERO,
            denied: None,
            last_decision: None,
            bootstrap: Account::default(),
            domains: BTreeMap::new(),
        }
    }

    pub fn register_domain(&mut self, id: StorageDomainId, capabilities: &DomainCapabilities, now: MonotonicTime) {
        if self.domains.contains_key(&id) {
            return;
        }
        let state = DomainState::new(&self.config, capabilities, now);
        self.domains.insert(id, state);
    }

    fn domain_mut(&mut self, id: StorageDomainId, now: MonotonicTime) -> &mut DomainState {
        let config = &self.config;
        self.domains.entry(id).or_insert_with(|| DomainState::new(config, &DomainCapabilities::default(), now))
    }

    fn credit(
        &mut self,
        domain: Option<StorageDomainId>,
        granted: i128,
        charged: i128,
        grants: i8,
        now: MonotonicTime,
    ) {
        match domain {
            Some(id) => {
                let state = self.domain_mut(id, now);
                state.account.granted += granted;
                state.account.charged += charged;
                state.bucket.level -= charged;
                match grants {
                    delta if delta > 0 => state.account.grants += 1,
                    delta if delta < 0 => state.account.grants = state.account.grants.saturating_sub(1),
                    _ => {}
                }
            }
            None => {
                self.bootstrap.granted += granted;
                self.bootstrap.charged += charged;
                match grants {
                    delta if delta > 0 => self.bootstrap.grants += 1,
                    delta if delta < 0 => self.bootstrap.grants = self.bootstrap.grants.saturating_sub(1),
                    _ => {}
                }
            }
        }
    }

    pub fn attribute(&mut self, id: GrantId, domain: StorageDomainId, now: MonotonicTime) {
        let Some(grant) = self.grants.get(&id) else {
            return;
        };
        if grant.domain == Some(domain) {
            return;
        }
        let previous = grant.domain;
        let granted = nanos(grant.reserved);
        let charged = nanos(grant.charged);
        if let Some(grant) = self.grants.get_mut(&id) {
            grant.domain = Some(domain);
        }
        self.credit(previous, -granted, -charged, -1, now);
        self.credit(Some(domain), granted, charged, 1, now);
    }

    pub fn estimate_of(&self, domain: Option<StorageDomainId>) -> Duration {
        match domain.and_then(|id| self.domains.get(&id)) {
            Some(state) => state.estimate,
            None => self.estimate,
        }
    }

    pub fn cost_of(&self, domain: Option<StorageDomainId>, operations: u32) -> Duration {
        self.estimate_of(domain).saturating_mul(operations)
    }

    pub fn account(&mut self, now: MonotonicTime) {
        self.global.refill(now);
        for state in self.domains.values_mut() {
            state.bucket.refill(now);
        }
        let mut deltas: Vec<(Option<StorageDomainId>, i128, bool)> = Vec::new();
        for grant in self.grants.values_mut() {
            let Some(started) = grant.started else {
                continue;
            };
            let occupancy = now.since(started);
            if occupancy > grant.charged {
                deltas.push((grant.domain, nanos(occupancy - grant.charged), grant.stuck));
                grant.charged = occupancy;
            }
        }
        for (domain, delta, stuck) in deltas {
            self.charged_total += delta;
            if !stuck {
                self.global.level -= delta;
            }
            self.credit(domain, 0, delta, 0, now);
        }
    }

    pub fn quarantined(&self, domain: Option<StorageDomainId>) -> bool {
        self.grants.values().any(|grant| grant.stuck && grant.domain == domain)
    }

    pub fn in_flight_on(&self, domain: Option<StorageDomainId>) -> usize {
        self.grants.values().filter(|grant| grant.started.is_some() && grant.domain == domain).count()
    }

    pub fn window_of(&self, domain: Option<StorageDomainId>) -> usize {
        match domain.and_then(|id| self.domains.get(&id)) {
            Some(state) => state.window,
            None => 1,
        }
    }

    pub fn global_exhausted(&self, domain: Option<StorageDomainId>) -> bool {
        !self.global.affordable(nanos(self.cost_of(domain, 1)))
    }

    pub fn may_start(&self, domain: Option<StorageDomainId>, in_flight: usize) -> Result<(), ThrottleCause> {
        if in_flight >= self.config.max_in_flight {
            return Err(ThrottleCause::Concurrency);
        }
        if self.in_flight_on(domain) >= self.window_of(domain) {
            return Err(ThrottleCause::Concurrency);
        }
        Ok(())
    }

    fn deny(&mut self, cause: ThrottleCause, domain: Option<StorageDomainId>, cost: Duration, now: MonotonicTime) {
        self.denials += 1;
        self.last_decision = Some(AdmissionDecision::Denied(cause));
        if cause == ThrottleCause::DutyBudget {
            self.denied = Some(match self.denied {
                Some((previous, held)) if held >= cost => (previous, held),
                _ => (domain, cost),
            });
        }
        if self.throttled_since.is_none() {
            self.throttled_since = Some(now);
        }
        if let Some(id) = domain
            && let Some(state) = self.domains.get_mut(&id)
        {
            state.throttled_jobs += 1;
            if state.throttled_since.is_none() {
                state.throttled_since = Some(now);
            }
        }
    }

    pub fn try_admit(&mut self, reservation: Reservation, now: MonotonicTime) -> Result<Duration, ThrottleCause> {
        let Reservation { id, path, reads, registrations, lease, domain } = reservation;
        self.account(now);
        if self.quarantined(domain) {
            self.deny(ThrottleCause::StuckWorker, domain, Duration::ZERO, now);
            return Err(ThrottleCause::StuckWorker);
        }
        let cost = self.cost_of(domain, reads + registrations);
        let local = domain
            .and_then(|id| self.domains.get(&id))
            .map(|state| state.bucket.affordable(nanos(cost)))
            .unwrap_or(true);
        if !self.global.affordable(nanos(cost)) || !local {
            self.deny(ThrottleCause::DutyBudget, domain, cost, now);
            return Err(ThrottleCause::DutyBudget);
        }
        self.global.level -= nanos(cost);
        self.reserved_total += nanos(cost);
        self.charged_total += nanos(cost);
        self.granted += 1;
        if lease > 0 {
            self.lease_granted += 1;
        }
        self.denied = None;
        self.watch_registration_grants += u64::from(registrations);
        self.last_decision = Some(AdmissionDecision::Granted);
        if let Some(since) = self.throttled_since.take() {
            self.throttled_total += now.since(since);
        }
        if let Some(id) = domain
            && let Some(state) = self.domains.get_mut(&id)
            && let Some(since) = state.throttled_since.take()
        {
            state.throttled_total += now.since(since);
        }
        self.credit(domain, nanos(cost), nanos(cost), 1, now);
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
        if charge <= grant.charged {
            return;
        }
        let extra = nanos(charge - grant.charged);
        let domain = grant.domain;
        let stuck = grant.stuck;
        grant.charged = charge;
        self.charged_total += extra;
        if !stuck {
            self.global.level -= extra;
        }
        self.credit(domain, 0, extra, 0, now);
    }

    pub fn charge_surcharge(&mut self, domain: Option<StorageDomainId>, now: MonotonicTime) {
        if self.surcharge.is_zero() {
            return;
        }
        self.account(now);
        let amount = nanos(self.surcharge);
        self.surcharged_total += amount;
        self.credit(domain, 0, amount, 0, now);
    }

    pub fn start(&mut self, id: GrantId, at: MonotonicTime) {
        let Some(grant) = self.grants.get_mut(&id) else {
            return;
        };
        if grant.started.is_some() {
            return;
        }
        grant.started = Some(at);
        let delay = at.since(grant.admitted);
        let domain = grant.domain;
        if let Some(id) = domain
            && let Some(state) = self.domains.get_mut(&id)
        {
            state.record_queue_delay(delay);
        }
    }

    pub fn release(&mut self, id: GrantId, now: MonotonicTime) {
        if !self.grants.contains_key(&id) {
            return;
        }
        self.account(now);
        let Some(grant) = self.grants.remove(&id) else {
            return;
        };
        let (Some(started), Some(domain)) = (grant.started, grant.domain) else {
            return;
        };
        let latency = now.since(started);
        let state = self.domain_mut(domain, now);
        state.record_latency(latency);
        state.adapt(false);
    }

    pub fn record_outcome(&mut self, domain: Option<StorageDomainId>, error: bool, now: MonotonicTime) {
        let Some(id) = domain else {
            return;
        };
        let state = self.domain_mut(id, now);
        state.record_error(error);
        if error {
            state.adapt(false);
        }
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

    pub fn mark_stuck(&mut self, id: GrantId, now: MonotonicTime) {
        let Some(grant) = self.grants.get_mut(&id) else {
            return;
        };
        if grant.stuck {
            return;
        }
        grant.stuck = true;
        let refund = nanos(grant.charged.saturating_sub(grant.reserved));
        let domain = grant.domain;
        self.global.level += refund;
        if let Some(id) = domain {
            self.domain_mut(id, now).adapt(true);
        }
    }

    pub fn stuck_grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.values().filter(|g| g.stuck)
    }

    pub fn next_stuck_deadline(&self) -> Option<MonotonicTime> {
        self.grants.values().filter(|g| !g.stuck).filter_map(|g| g.started.map(|at| at + self.stuck_threshold)).min()
    }

    pub fn admissible_at(&self, domain: Option<StorageDomainId>, now: MonotonicTime) -> Option<MonotonicTime> {
        if self.quarantined(domain) {
            return None;
        }
        self.affordable_at(domain, self.cost_of(domain, 1), now)
    }

    fn affordable_at(
        &self,
        domain: Option<StorageDomainId>,
        cost: Duration,
        now: MonotonicTime,
    ) -> Option<MonotonicTime> {
        let cost = nanos(cost);
        let global = self.global.affordable_at(now, cost);
        let local = domain.and_then(|id| self.domains.get(&id)).and_then(|state| state.bucket.affordable_at(now, cost));
        match (global, local) {
            (None, None) => None,
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
        }
    }

    pub fn throttle(&self, now: MonotonicTime) -> Option<(ThrottleCause, Option<MonotonicTime>)> {
        if let Some((domain, cost)) = self.denied
            && let Some(at) = self.affordable_at(domain, cost, now)
        {
            return Some((ThrottleCause::DutyBudget, Some(at)));
        }
        match self.grants.values().any(|grant| grant.stuck) {
            true => Some((ThrottleCause::StuckWorker, None)),
            false => None,
        }
    }

    pub fn resume_at(&self, now: MonotonicTime) -> Option<MonotonicTime> {
        self.throttle(now).and_then(|(_, resume)| resume)
    }

    pub fn domain_health(
        &self,
        domain: StorageDomainId,
        now: MonotonicTime,
        queued: bool,
    ) -> Option<(ThrottleCause, Option<MonotonicTime>)> {
        if self.quarantined(Some(domain)) {
            return Some((ThrottleCause::StuckWorker, None));
        }
        if let Some(at) = self.affordable_at(Some(domain), self.cost_of(Some(domain), 1), now) {
            return Some((ThrottleCause::DutyBudget, Some(at)));
        }
        match queued && self.in_flight_on(Some(domain)) >= self.window_of(Some(domain)) {
            true => Some((ThrottleCause::Concurrency, None)),
            false => None,
        }
    }

    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.values()
    }

    fn occupancy(&self) -> BTreeMap<Option<StorageDomainId>, (usize, usize)> {
        let mut counts: BTreeMap<Option<StorageDomainId>, (usize, usize)> = BTreeMap::new();
        for grant in self.grants.values() {
            let entry = counts.entry(grant.domain).or_default();
            if grant.started.is_some() {
                entry.0 += 1;
            }
            if grant.stuck {
                entry.1 += 1;
            }
        }
        counts
    }

    fn domain_view(&self, state: &DomainState, occupancy: (usize, usize), now: MonotonicTime) -> DomainView {
        DomainView {
            granted: duration(state.account.granted),
            charged: duration(state.account.charged),
            grants: state.account.grants,
            capacity: duration(state.bucket.capacity),
            level: duration(state.bucket.level),
            debt: duration(-state.bucket.level),
            window: state.window,
            ceiling: state.ceiling,
            in_flight: occupancy.0,
            stuck: occupancy.1,
            estimate: state.estimate,
            latency: state.summary(),
            queue_delay: state.standing_queue_delay(),
            throttled_jobs: state.throttled_jobs,
            throttled_duration: match state.throttled_since {
                Some(since) => state.throttled_total + now.since(since),
                None => state.throttled_total,
            },
            elapsed: now.since(state.since),
        }
    }

    pub fn view(&self, now: MonotonicTime) -> GovernorView {
        GovernorView {
            capacity: duration(self.global.capacity),
            level: duration(self.global.level),
            debt: duration(-self.global.level),
            reserved: duration(self.reserved_total),
            charged: duration(self.charged_total),
            surcharged: duration(self.surcharged_total),
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
            next_admissible: self
                .domains
                .keys()
                .map(|id| Some(*id))
                .chain(std::iter::once(None))
                .map(|domain| self.admissible_at(domain, now))
                .min()
                .flatten(),
            last_decision: self.last_decision,
            bootstrap: self.bootstrap.view(),
            domains: {
                let occupancy = self.occupancy();
                self.domains
                    .iter()
                    .map(|(id, state)| {
                        (*id, self.domain_view(state, occupancy.get(&Some(*id)).copied().unwrap_or_default(), now))
                    })
                    .collect()
            },
        }
    }
}
