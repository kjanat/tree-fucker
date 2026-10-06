use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use std::time::Instant;

use super::types::{MonotonicTime, WorkOrigin};
use crate::config::HostConfig;
use crate::domain::{AccessTopology, DomainCapabilities, MediaHint, StorageDomainId};
use crate::ids::{JobId, WatchReleaseId, WatchRequestId};
use crate::path::RelativePath;
use crate::update::ThrottleCause;

const LATENCY_HISTORY: usize = 32;
const QUEUE_HISTORY: usize = 8;
const TARGET_FACTOR: u32 = 2;
const LOCAL_START_WINDOW: usize = 2;
const CONSERVATIVE_START_WINDOW: usize = 1;
const CONSERVATIVE_TOPOLOGY_CEILING: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TreeNumber(u64);

impl TreeNumber {
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GrantId {
    Job(TreeNumber, JobId),
    WatchRegistration(TreeNumber, WatchRequestId),
    WatchRelease(TreeNumber, WatchReleaseId),
    Bootstrap(u64),
}

impl GrantId {
    pub fn job(self) -> Option<JobId> {
        match self {
            GrantId::Job(_, id) => Some(id),
            GrantId::WatchRegistration(_, _) | GrantId::WatchRelease(_, _) | GrantId::Bootstrap(_) => None,
        }
    }

    pub fn release(self) -> Option<WatchReleaseId> {
        match self {
            GrantId::WatchRelease(_, id) => Some(id),
            GrantId::Job(_, _) | GrantId::WatchRegistration(_, _) | GrantId::Bootstrap(_) => None,
        }
    }

    pub fn tree(self) -> Option<TreeNumber> {
        match self {
            GrantId::Job(tree, _) | GrantId::WatchRegistration(tree, _) | GrantId::WatchRelease(tree, _) => Some(tree),
            GrantId::Bootstrap(_) => None,
        }
    }
}

struct OccupancyDelta {
    domain: Option<StorageDomainId>,
    origin: WorkOrigin,
    delta: i128,
    stuck: bool,
    tree: Option<TreeNumber>,
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
    pub required: u32,
    pub operations: u32,
    pub performed: Option<u32>,
    pub domain: Option<StorageDomainId>,
    pub origin: WorkOrigin,
    pub reserved: Duration,
    pub charged: Duration,
    pub admitted: MonotonicTime,
    pub started: Option<MonotonicTime>,
    pub dispatched: Option<MonotonicTime>,
    pub stuck: bool,
    pub listing: bool,
    pub registration: bool,
    pub registration_took: Option<Duration>,
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
    pub foreground_capacity: Duration,
    pub foreground_level: Duration,
    pub foreground_debt: Duration,
    pub bytes_estimate: u64,
    pub window: usize,
    pub ceiling: usize,
    pub in_flight: usize,
    pub stuck: usize,
    pub estimate: Duration,
    pub latency: LatencySummary,
    pub listing_latency: LatencySummary,
    pub metadata_latency: LatencySummary,
    pub registration_latency: LatencySummary,
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
    pub operations: u32,
    pub ceiling: Option<Duration>,
    pub lease: u32,
    pub domain: Option<StorageDomainId>,
    pub origin: WorkOrigin,
    pub listing: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub cost: Duration,
    pub operations: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reported {
    pub blocking: Option<Duration>,
    pub operations: u32,
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
    pub foreground_capacity: Duration,
    pub foreground_level: Duration,
    pub foreground_debt: Duration,
    pub bootstrap_capacity: Duration,
    pub bootstrap_outstanding: Duration,
    pub accounted_memory: u64,
    pub memory_ceiling: u64,
    pub in_flight_bytes: u64,
    pub in_flight_bytes_ceiling: u64,
    pub reserved: Duration,
    pub charged: Duration,
    pub surcharged: Duration,
    pub reported_blocking: Duration,
    pub running_occupancy: Duration,
    pub in_flight: usize,
    pub grants: u64,
    pub lease_grants: u64,
    pub watch_registration_grants: u64,
    pub watch_release_grants: u64,
    pub denials: u64,
    pub throttled_duration: Duration,
    pub next_admissible: Option<MonotonicTime>,
    pub last_decision: Option<AdmissionDecision>,
    pub bootstrap: DomainAccount,
    pub bootstrap_estimate: Duration,
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
struct LatencyWindow {
    history: VecDeque<Duration>,
    sorted: Vec<Duration>,
    total: Duration,
    summary: LatencySummary,
}

impl LatencyWindow {
    fn new() -> LatencyWindow {
        LatencyWindow {
            history: VecDeque::new(),
            sorted: Vec::with_capacity(LATENCY_HISTORY),
            total: Duration::ZERO,
            summary: LatencySummary::default(),
        }
    }

    fn record(&mut self, latency: Duration) {
        if self.history.len() >= LATENCY_HISTORY
            && let Some(oldest) = self.history.pop_front()
        {
            if let Ok(at) = self.sorted.binary_search(&oldest) {
                self.sorted.remove(at);
            }
            self.total = self.total.saturating_sub(oldest);
        }
        self.history.push_back(latency);
        let at = self.sorted.partition_point(|held| *held < latency);
        self.sorted.insert(at, latency);
        self.total += latency;
        self.recompute();
    }

    fn recompute(&mut self) {
        let samples = self.sorted.len();
        if samples == 0 {
            self.summary = LatencySummary::default();
            return;
        }
        let tail = (samples * 9 / 10).min(samples - 1);
        self.summary = LatencySummary {
            samples,
            minimum: self.sorted[0],
            median: self.sorted[samples / 2],
            mean: self.total / u32::try_from(samples).unwrap_or(u32::MAX),
            tail: self.sorted[tail],
        };
    }
}

#[derive(Clone, Debug)]
struct DomainState {
    bucket: Bucket,
    foreground: Bucket,
    account: Account,
    window: usize,
    ceiling: usize,
    estimate: Duration,
    latency: LatencyWindow,
    listing_latency: LatencyWindow,
    metadata_latency: LatencyWindow,
    registration_latency: LatencyWindow,
    bytes: VecDeque<u64>,
    bytes_total: u64,
    bytes_estimate: u64,
    errors: VecDeque<bool>,
    completions: usize,
    queue: VecDeque<Duration>,
    standing_queue_delay: Duration,
    throttled_jobs: u64,
    throttled_since: Option<MonotonicTime>,
    throttled_total: Duration,
    since: MonotonicTime,
}

impl DomainState {
    fn new(config: &HostConfig, capabilities: &DomainCapabilities, now: MonotonicTime) -> DomainState {
        let ceiling = config
            .per_domain_concurrency
            .min(config.maximum_in_flight)
            .min(topology_ceiling(capabilities, config.per_domain_concurrency))
            .max(1);
        DomainState {
            bucket: Bucket::new(config.domain_background_duty, config.domain_background_burst, now),
            foreground: Bucket::new(config.domain_foreground_duty, config.domain_foreground_burst, now),
            account: Account::default(),
            window: start_window(capabilities).clamp(1, ceiling),
            ceiling,
            estimate: config.initial_cost_estimate,
            latency: LatencyWindow::new(),
            listing_latency: LatencyWindow::new(),
            metadata_latency: LatencyWindow::new(),
            registration_latency: LatencyWindow::new(),
            bytes: VecDeque::new(),
            bytes_total: 0,
            bytes_estimate: 0,
            errors: VecDeque::new(),
            completions: 0,
            queue: VecDeque::new(),
            standing_queue_delay: Duration::ZERO,
            throttled_jobs: 0,
            throttled_since: None,
            throttled_total: Duration::ZERO,
            since: now,
        }
    }

    fn summary(&self) -> LatencySummary {
        self.latency.summary
    }

    fn record_latency(&mut self, latency: Duration, listing: bool) {
        self.latency.record(latency);
        match listing {
            true => self.listing_latency.record(latency),
            false => self.metadata_latency.record(latency),
        }
        self.completions += 1;
        let ceiling = duration(self.bucket.capacity);
        let summary = self.latency.summary;
        self.estimate = summary.median.max(summary.minimum).min(ceiling).max(Duration::from_nanos(1));
    }

    fn record_bytes(&mut self, bytes: u64) {
        if self.bytes.len() >= LATENCY_HISTORY
            && let Some(oldest) = self.bytes.pop_front()
        {
            self.bytes_total = self.bytes_total.saturating_sub(oldest);
        }
        self.bytes.push_back(bytes);
        self.bytes_total = self.bytes_total.saturating_add(bytes);
        self.bytes_estimate = self.bytes_total / u64::try_from(self.bytes.len()).unwrap_or(1).max(1);
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
    config: HostConfig,
    global: Bucket,
    foreground: Bucket,
    bootstrap_capacity: i128,
    bootstrap_outstanding: i128,
    memory: BTreeMap<TreeNumber, (u64, u64)>,
    memory_total: u64,
    in_flight_total: u64,
    next_tree: u64,
    next_bootstrap: u64,
    estimate: Duration,
    stuck_threshold: Duration,
    surcharge: Duration,
    grants: BTreeMap<GrantId, Grant>,
    running: BTreeMap<Option<StorageDomainId>, usize>,
    stuck: BTreeMap<Option<StorageDomainId>, usize>,
    running_total: usize,
    accounted_at: Option<MonotonicTime>,
    reserved_total: i128,
    charged_total: i128,
    charged_by_tree: BTreeMap<TreeNumber, i128>,
    surcharged_total: i128,
    reported_total: i128,
    granted: u64,
    lease_granted: u64,
    watch_registration_grants: u64,
    watch_release_grants: u64,
    denials: u64,
    throttled_since: Option<MonotonicTime>,
    throttled_total: Duration,
    denied: Option<(Option<StorageDomainId>, Duration)>,
    denied_foreground: Option<(Option<StorageDomainId>, Duration)>,
    last_decision: Option<AdmissionDecision>,
    bootstrap: Account,
    bootstrap_latency: LatencyWindow,
    domains: BTreeMap<StorageDomainId, DomainState>,
}

impl Governor {
    pub fn new(config: &HostConfig, now: MonotonicTime) -> Governor {
        Governor {
            config: *config,
            global: Bucket::new(config.background_duty, config.background_burst, now),
            foreground: Bucket::new(config.foreground_duty, config.foreground_burst, now),
            bootstrap_capacity: nanos(config.bootstrap_allowance),
            bootstrap_outstanding: 0,
            memory: BTreeMap::new(),
            memory_total: 0,
            in_flight_total: 0,
            next_tree: 0,
            next_bootstrap: 0,
            estimate: config.initial_cost_estimate,
            stuck_threshold: config.stuck_threshold,
            surcharge: config.failure_surcharge,
            grants: BTreeMap::new(),
            running: BTreeMap::new(),
            stuck: BTreeMap::new(),
            running_total: 0,
            accounted_at: None,
            reserved_total: 0,
            charged_total: 0,
            charged_by_tree: BTreeMap::new(),
            surcharged_total: 0,
            reported_total: 0,
            granted: 0,
            lease_granted: 0,
            watch_registration_grants: 0,
            watch_release_grants: 0,
            denials: 0,
            throttled_since: None,
            throttled_total: Duration::ZERO,
            denied: None,
            denied_foreground: None,
            last_decision: None,
            bootstrap: Account::default(),
            bootstrap_latency: LatencyWindow::new(),
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

    pub fn next_tree(&mut self) -> TreeNumber {
        self.next_tree += 1;
        TreeNumber(self.next_tree)
    }

    pub fn next_bootstrap(&mut self) -> u64 {
        self.next_bootstrap += 1;
        self.next_bootstrap
    }

    pub fn report_memory(&mut self, tree: TreeNumber, snapshot_bytes: u64, in_flight_bytes: u64) {
        let entry = self.memory.entry(tree).or_default();
        let previous = *entry;
        *entry = (snapshot_bytes, in_flight_bytes);
        self.memory_total = self
            .memory_total
            .saturating_sub(previous.0.saturating_add(previous.1))
            .saturating_add(snapshot_bytes.saturating_add(in_flight_bytes));
        self.in_flight_total = self.in_flight_total.saturating_sub(previous.1).saturating_add(in_flight_bytes);
    }

    pub fn forget_tree(&mut self, tree: TreeNumber) {
        self.charged_by_tree.remove(&tree);
        if let Some(previous) = self.memory.remove(&tree) {
            self.memory_total = self.memory_total.saturating_sub(previous.0.saturating_add(previous.1));
            self.in_flight_total = self.in_flight_total.saturating_sub(previous.1);
        }
    }

    pub fn accounted_memory_excluding(&self, tree: TreeNumber) -> u64 {
        let own = self.memory.get(&tree).copied().unwrap_or((0, 0));
        self.memory_total.saturating_sub(own.0.saturating_add(own.1))
    }

    pub fn memory_ceiling(&self) -> u64 {
        self.config.accounted_memory_ceiling
    }

    pub fn bytes_estimate(&self, domain: Option<StorageDomainId>) -> u64 {
        domain.and_then(|id| self.domains.get(&id)).map(|state| state.bytes_estimate).unwrap_or(0)
    }

    pub fn record_bytes(&mut self, domain: Option<StorageDomainId>, bytes: u64, now: MonotonicTime) {
        let Some(id) = domain else {
            return;
        };
        self.domain_mut(id, now).record_bytes(bytes);
    }

    fn memory_exceeded(&self, extra: u64) -> bool {
        self.memory_total.saturating_add(extra) > self.config.accounted_memory_ceiling
    }

    fn in_flight_bytes_exceeded(&self, extra: u64) -> bool {
        self.in_flight_total.saturating_add(extra) > self.config.in_flight_listing_bytes
    }

    fn domain_mut(&mut self, id: StorageDomainId, now: MonotonicTime) -> &mut DomainState {
        let config = &self.config;
        self.domains.entry(id).or_insert_with(|| DomainState::new(config, &DomainCapabilities::default(), now))
    }

    fn credit(
        &mut self,
        domain: Option<StorageDomainId>,
        origin: WorkOrigin,
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
                match origin {
                    WorkOrigin::Background => state.bucket.level -= charged,
                    WorkOrigin::Foreground => state.foreground.level -= charged,
                }
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
        let origin = grant.origin;
        let granted = nanos(grant.reserved);
        let charged = nanos(grant.charged);
        let moved = grant.clone();
        self.move_counts(&moved, previous, Some(domain));
        if let Some(grant) = self.grants.get_mut(&id) {
            grant.domain = Some(domain);
        }
        if previous.is_none()
            && let Some(took) = moved.registration_took
        {
            self.domain_mut(domain, now).registration_latency.record(took);
        }
        if previous.is_none() {
            self.bootstrap_outstanding = (self.bootstrap_outstanding - granted).max(0);
        }
        self.credit(previous, origin, -granted, -charged, -1, now);
        self.credit(Some(domain), origin, granted, charged, 1, now);
    }

    fn capacity_for(&self, domain: Option<StorageDomainId>, origin: WorkOrigin) -> Duration {
        let global = match origin {
            WorkOrigin::Background => self.global.capacity,
            WorkOrigin::Foreground => self.foreground.capacity,
        };
        let local = domain
            .and_then(|id| self.domains.get(&id))
            .map(|state| match origin {
                WorkOrigin::Background => state.bucket.capacity,
                WorkOrigin::Foreground => state.foreground.capacity,
            })
            .unwrap_or_else(|| match origin {
                WorkOrigin::Background => nanos(self.config.domain_background_burst),
                WorkOrigin::Foreground => nanos(self.config.domain_foreground_burst),
            });
        duration(global.min(local))
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
        if self.accounted_at == Some(now) {
            return;
        }
        self.accounted_at = Some(now);
        self.global.refill(now);
        self.foreground.refill(now);
        for state in self.domains.values_mut() {
            state.bucket.refill(now);
            state.foreground.refill(now);
        }
        let mut deltas: Vec<OccupancyDelta> = Vec::new();
        for grant in self.grants.values_mut() {
            let Some(started) = grant.started else {
                continue;
            };
            let occupancy = now.since(started);
            if occupancy > grant.charged {
                deltas.push(OccupancyDelta {
                    domain: grant.domain,
                    origin: grant.origin,
                    delta: nanos(occupancy - grant.charged),
                    stuck: grant.stuck,
                    tree: grant.id.tree(),
                });
                grant.charged = occupancy;
            }
        }
        for OccupancyDelta { domain, origin, delta, stuck, tree } in deltas {
            self.charged_total += delta;
            self.charge_tree(tree, delta);
            if !stuck {
                self.global_bucket(origin).level -= delta;
            }
            self.credit(domain, origin, 0, delta, 0, now);
        }
    }

    fn global_bucket(&mut self, origin: WorkOrigin) -> &mut Bucket {
        match origin {
            WorkOrigin::Background => &mut self.global,
            WorkOrigin::Foreground => &mut self.foreground,
        }
    }

    pub fn quarantined(&self, domain: Option<StorageDomainId>) -> bool {
        domain.is_some() && self.stuck.get(&domain).copied().unwrap_or(0) > 0
    }

    pub fn in_flight_on(&self, domain: Option<StorageDomainId>) -> usize {
        self.running.get(&domain).copied().unwrap_or(0)
    }

    fn move_counts(&mut self, grant: &Grant, from: Option<StorageDomainId>, to: Option<StorageDomainId>) {
        if grant.started.is_some() {
            Governor::decrement(&mut self.running, from);
            *self.running.entry(to).or_insert(0) += 1;
        }
        if grant.stuck {
            Governor::decrement(&mut self.stuck, from);
            *self.stuck.entry(to).or_insert(0) += 1;
        }
    }

    fn decrement(counts: &mut BTreeMap<Option<StorageDomainId>, usize>, domain: Option<StorageDomainId>) {
        let Some(count) = counts.get_mut(&domain) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&domain);
        }
    }

    pub fn window_of(&self, domain: Option<StorageDomainId>) -> usize {
        match domain {
            Some(id) => self.domains.get(&id).map(|state| state.window).unwrap_or(1),
            None => self.config.maximum_in_flight,
        }
    }

    pub fn global_exhausted(&self, domain: Option<StorageDomainId>, origin: WorkOrigin) -> bool {
        let cost = nanos(self.cost_of(domain, 1));
        match origin {
            WorkOrigin::Background => !self.global.affordable(cost),
            WorkOrigin::Foreground => !self.foreground.affordable(cost),
        }
    }

    pub fn may_start(&self, domain: Option<StorageDomainId>) -> Result<(), ThrottleCause> {
        if self.running_total >= self.config.maximum_in_flight {
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
        if cause == ThrottleCause::ForegroundCeiling {
            self.denied_foreground = Some(match self.denied_foreground {
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

    fn affordable(&self, domain: Option<StorageDomainId>, origin: WorkOrigin, ceiling: Option<Duration>) -> i128 {
        let global = match origin {
            WorkOrigin::Background => self.global.level,
            WorkOrigin::Foreground => self.foreground.level,
        };
        let local = domain
            .and_then(|id| self.domains.get(&id))
            .map(|state| match origin {
                WorkOrigin::Background => state.bucket.level,
                WorkOrigin::Foreground => state.foreground.level,
            })
            .unwrap_or(global);
        let mut level = global.min(local).min(nanos(self.capacity_for(domain, origin)));
        if let Some(ceiling) = ceiling {
            level = level.min(nanos(ceiling));
        }
        level.max(0)
    }

    fn permitted_operations(&self, estimate: Duration, required: u32, requested: u32, affordable: i128) -> u32 {
        if requested == 0 {
            return 0;
        }
        let unit = nanos(estimate).max(1);
        let spare = affordable - unit.saturating_mul(i128::from(required));
        let room = u32::try_from((spare / unit).max(0)).unwrap_or(u32::MAX);
        requested.min(room).max(1)
    }

    pub fn try_admit(&mut self, reservation: Reservation, now: MonotonicTime) -> Result<Admitted, ThrottleCause> {
        let Reservation { id, path, reads, registrations, operations, ceiling, lease, domain, origin, listing } =
            reservation;
        self.account(now);
        if self.quarantined(domain) {
            self.deny(ThrottleCause::StuckWorker, domain, Duration::ZERO, now);
            return Err(ThrottleCause::StuckWorker);
        }
        let cleanup = id.release().is_some();
        let result_bytes = match listing {
            true => self.bytes_estimate(domain),
            false => 0,
        };
        if !cleanup && (self.memory_exceeded(result_bytes) || (listing && self.in_flight_bytes_exceeded(result_bytes)))
        {
            self.deny(ThrottleCause::Memory, domain, Duration::ZERO, now);
            return Err(ThrottleCause::Memory);
        }
        let estimate = self.estimate_of(domain);
        let capacity = self.capacity_for(domain, origin);
        let required = reads + registrations;
        let affordable = self.affordable(domain, origin, ceiling);
        let minimum = required + operations.min(1);
        let floor_cost = estimate.saturating_mul(minimum).min(capacity);
        if !cleanup && nanos(floor_cost) > affordable {
            let cause = match origin {
                WorkOrigin::Background => ThrottleCause::DutyBudget,
                WorkOrigin::Foreground => ThrottleCause::ForegroundCeiling,
            };
            self.deny(cause, domain, floor_cost, now);
            return Err(cause);
        }
        let permitted = self.permitted_operations(estimate, required, operations, affordable);
        let cost = estimate.saturating_mul(required + permitted).min(capacity);
        if !cleanup && domain.is_none() && self.bootstrap_outstanding + nanos(cost) > self.bootstrap_capacity {
            self.deny(ThrottleCause::DutyBudget, domain, cost, now);
            return Err(ThrottleCause::DutyBudget);
        }
        if domain.is_none() {
            self.bootstrap_outstanding += nanos(cost);
        }
        self.global_bucket(origin).level -= nanos(cost);
        self.reserved_total += nanos(cost);
        self.charged_total += nanos(cost);
        self.charge_tree(id.tree(), nanos(cost));
        self.granted += 1;
        if lease > 0 {
            self.lease_granted += 1;
        }
        match origin {
            WorkOrigin::Background => self.denied = None,
            WorkOrigin::Foreground => self.denied_foreground = None,
        }
        self.watch_registration_grants += u64::from(registrations);
        if cleanup {
            self.watch_release_grants += 1;
        }
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
        self.credit(domain, origin, nanos(cost), nanos(cost), 1, now);
        self.grants.insert(
            id,
            Grant {
                id,
                path,
                lease,
                required,
                operations: permitted,
                performed: None,
                domain,
                origin,
                reserved: cost,
                charged: cost,
                admitted: now,
                started: None,
                dispatched: None,
                stuck: false,
                listing,
                registration: registrations > 0,
                registration_took: None,
            },
        );
        Ok(Admitted { cost, operations: permitted })
    }

    pub fn report(&mut self, id: GrantId, reported: Reported, now: MonotonicTime) {
        self.account(now);
        let Some(grant) = self.grants.get_mut(&id) else {
            return;
        };
        grant.performed = Some(grant.performed.unwrap_or(0).saturating_add(reported.operations));
        let Some(blocking) = reported.blocking else {
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
        let origin = grant.origin;
        let stuck = grant.stuck;
        let tree = grant.id.tree();
        grant.charged = charge;
        self.charged_total += extra;
        self.charge_tree(tree, extra);
        if !stuck {
            self.global_bucket(origin).level -= extra;
        }
        self.credit(domain, origin, 0, extra, 0, now);
    }

    pub fn overshoot_of(&self, id: GrantId) -> Duration {
        self.grants.get(&id).map(|grant| grant.charged.saturating_sub(grant.reserved)).unwrap_or_default()
    }

    pub fn charge_surcharge(&mut self, domain: Option<StorageDomainId>, origin: WorkOrigin, now: MonotonicTime) {
        if self.surcharge.is_zero() {
            return;
        }
        self.account(now);
        let amount = nanos(self.surcharge);
        self.surcharged_total += amount;
        self.credit(domain, origin, 0, amount, 0, now);
    }

    fn charge_tree(&mut self, tree: Option<TreeNumber>, delta: i128) {
        if let Some(tree) = tree {
            *self.charged_by_tree.entry(tree).or_insert(0) += delta;
        }
    }

    pub fn charged_by_tree(&self, tree: TreeNumber) -> Duration {
        duration(self.charged_by_tree.get(&tree).copied().unwrap_or(0))
    }

    pub fn try_start(&mut self, id: GrantId, at: MonotonicTime) -> Result<(), ThrottleCause> {
        let Some(grant) = self.grants.get(&id) else {
            return Ok(());
        };
        let domain = grant.domain;
        self.may_start(domain)?;
        self.start(id, at);
        Ok(())
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
        *self.running.entry(domain).or_insert(0) += 1;
        self.running_total += 1;
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
        if grant.domain.is_none() {
            self.bootstrap_outstanding = (self.bootstrap_outstanding - nanos(grant.reserved)).max(0);
        }
        if grant.started.is_some() {
            Governor::decrement(&mut self.running, grant.domain);
            self.running_total = self.running_total.saturating_sub(1);
        }
        if grant.stuck {
            Governor::decrement(&mut self.stuck, grant.domain);
            let withheld = nanos(grant.charged.saturating_sub(grant.reserved));
            self.global_bucket(grant.origin).level -= withheld;
        }
        let Some(started) = grant.started else {
            return;
        };
        if grant.id.release().is_some() {
            return;
        }
        let performed = grant.performed.unwrap_or(grant.required).max(1);
        let Some(domain) = grant.domain else {
            self.bootstrap_latency.record(now.since(started) / performed);
            let summary = self.bootstrap_latency.summary;
            let ceiling = duration(self.bootstrap_capacity);
            self.estimate = summary.median.max(summary.minimum).min(ceiling).max(Duration::from_nanos(1));
            return;
        };
        let state = self.domain_mut(domain, now);
        match (grant.dispatched, grant.registration) {
            (Some(dispatched), _) => state.record_latency(now.since(dispatched) / performed, grant.listing),
            (None, true) => state.registration_latency.record(now.since(started) / performed),
            (None, false) => state.record_latency(now.since(started) / performed, grant.listing),
        }
        state.adapt(false);
    }

    pub fn dispatch(&mut self, id: GrantId, at: MonotonicTime) {
        let Some(grant) = self.grants.get_mut(&id) else {
            return;
        };
        if grant.dispatched.is_some() {
            return;
        }
        grant.dispatched = Some(at);
        let (Some(started), true) = (grant.started, grant.registration) else {
            return;
        };
        let took = at.since(started);
        grant.registration_took = Some(took);
        if let Some(domain) = grant.domain {
            self.domain_mut(domain, at).registration_latency.record(took);
        }
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
        self.running_total
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
        let counted = grant.domain;
        *self.stuck.entry(counted).or_insert(0) += 1;
        let refund = nanos(grant.charged.saturating_sub(grant.reserved));
        let domain = grant.domain;
        let origin = grant.origin;
        self.global_bucket(origin).level += refund;
        if let Some(id) = domain {
            self.domain_mut(id, now).adapt(true);
        }
    }

    pub fn domain_of_grant(&self, id: GrantId) -> Option<StorageDomainId> {
        self.grants.get(&id).and_then(|grant| grant.domain)
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
        if self.memory_exceeded(0) {
            return Some((ThrottleCause::Memory, None));
        }
        if let Some((domain, cost)) = self.denied
            && let Some(at) = self.affordable_at(domain, cost, now)
        {
            return Some((ThrottleCause::DutyBudget, Some(at)));
        }
        if let Some((domain, cost)) = self.denied_foreground
            && let Some(at) = self.foreground_affordable_at(domain, cost, now)
        {
            return Some((ThrottleCause::ForegroundCeiling, Some(at)));
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
        if self.memory_exceeded(0) {
            return Some((ThrottleCause::Memory, None));
        }
        if let Some(at) = self.affordable_at(Some(domain), self.cost_of(Some(domain), 1), now) {
            return Some((ThrottleCause::DutyBudget, Some(at)));
        }
        if let Some(at) = self.foreground_affordable_at(Some(domain), self.cost_of(Some(domain), 1), now)
            && self.denied_foreground.is_some()
        {
            return Some((ThrottleCause::ForegroundCeiling, Some(at)));
        }
        match queued && self.in_flight_on(Some(domain)) >= self.window_of(Some(domain)) {
            true => Some((ThrottleCause::Concurrency, None)),
            false => None,
        }
    }

    fn foreground_affordable_at(
        &self,
        domain: Option<StorageDomainId>,
        cost: Duration,
        now: MonotonicTime,
    ) -> Option<MonotonicTime> {
        let cost = nanos(cost);
        let global = self.foreground.affordable_at(now, cost);
        let local =
            domain.and_then(|id| self.domains.get(&id)).and_then(|state| state.foreground.affordable_at(now, cost));
        match (global, local) {
            (None, None) => None,
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
        }
    }

    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.values()
    }

    fn occupancy(&self) -> BTreeMap<Option<StorageDomainId>, (usize, usize)> {
        let mut counts: BTreeMap<Option<StorageDomainId>, (usize, usize)> = BTreeMap::new();
        for (domain, running) in &self.running {
            counts.entry(*domain).or_default().0 = *running;
        }
        for (domain, stuck) in &self.stuck {
            counts.entry(*domain).or_default().1 = *stuck;
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
            foreground_capacity: duration(state.foreground.capacity),
            foreground_level: duration(state.foreground.level),
            foreground_debt: duration(-state.foreground.level),
            bytes_estimate: state.bytes_estimate,
            window: state.window,
            ceiling: state.ceiling,
            in_flight: occupancy.0,
            stuck: occupancy.1,
            estimate: state.estimate,
            latency: state.summary(),
            listing_latency: state.listing_latency.summary,
            metadata_latency: state.metadata_latency.summary,
            registration_latency: state.registration_latency.summary,
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
            foreground_capacity: duration(self.foreground.capacity),
            foreground_level: duration(self.foreground.level),
            foreground_debt: duration(-self.foreground.level),
            bootstrap_capacity: duration(self.bootstrap_capacity),
            bootstrap_outstanding: duration(self.bootstrap_outstanding),
            accounted_memory: self.memory_total,
            memory_ceiling: self.config.accounted_memory_ceiling,
            in_flight_bytes: self.in_flight_total,
            in_flight_bytes_ceiling: self.config.in_flight_listing_bytes,
            reserved: duration(self.reserved_total),
            charged: duration(self.charged_total),
            surcharged: duration(self.surcharged_total),
            reported_blocking: duration(self.reported_total),
            running_occupancy: self.running_occupancy(now),
            in_flight: self.in_flight(),
            grants: self.granted,
            lease_grants: self.lease_granted,
            watch_registration_grants: self.watch_registration_grants,
            watch_release_grants: self.watch_release_grants,
            denials: self.denials,
            throttled_duration: match self.throttled_since {
                Some(since) => self.throttled_total + now.since(since),
                None => self.throttled_total,
            },
            next_admissible: match self.domains.is_empty() {
                true => self.admissible_at(None, now),
                false => self.domains.keys().map(|id| self.admissible_at(Some(*id), now)).min().flatten(),
            },
            last_decision: self.last_decision,
            bootstrap: self.bootstrap.view(),
            bootstrap_estimate: self.estimate,
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

#[derive(Clone)]
pub struct HostGovernor {
    inner: Arc<Mutex<Governor>>,
    base: Arc<Mutex<Option<Instant>>>,
    changes: Arc<(Mutex<Changes>, Condvar)>,
    limits: Arc<HostConfig>,
}

#[derive(Default)]
struct Changes {
    generation: u64,
    waiters: usize,
}

static PROCESS_GOVERNOR: OnceLock<HostGovernor> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostGovernorError {
    AlreadyInstalled,
    InvalidConfig(String),
}

impl std::fmt::Display for HostGovernorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostGovernorError::AlreadyInstalled => f.write_str("the process governor is already in use"),
            HostGovernorError::InvalidConfig(message) => write!(f, "invalid host configuration: {message}"),
        }
    }
}

impl std::error::Error for HostGovernorError {}

pub fn host_governor() -> HostGovernor {
    PROCESS_GOVERNOR.get_or_init(|| HostGovernor::independent(&HostConfig::default())).clone()
}

fn guard(inner: &Mutex<Governor>) -> MutexGuard<'_, Governor> {
    match inner.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn guard_changes(changes: &Mutex<Changes>) -> MutexGuard<'_, Changes> {
    match changes.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl HostGovernor {
    pub fn install(config: HostConfig) -> Result<HostGovernor, HostGovernorError> {
        config.validate().map_err(HostGovernorError::InvalidConfig)?;
        let installed = HostGovernor::independent(&config);
        match PROCESS_GOVERNOR.set(installed.clone()) {
            Ok(()) => Ok(installed),
            Err(_) => Err(HostGovernorError::AlreadyInstalled),
        }
    }

    pub fn independent(config: &HostConfig) -> HostGovernor {
        HostGovernor {
            inner: Arc::new(Mutex::new(Governor::new(config, MonotonicTime::ZERO))),
            base: Arc::new(Mutex::new(None)),
            changes: Arc::new((Mutex::new(Changes::default()), Condvar::new())),
            limits: Arc::new(*config),
        }
    }

    pub fn changes(&self) -> u64 {
        guard_changes(&self.changes.0).generation
    }

    pub fn wait_for_change(&self, seen: u64, timeout: Duration) -> u64 {
        let (lock, signal) = &*self.changes;
        let mut held = guard_changes(lock);
        held.waiters += 1;
        let mut held = match signal.wait_timeout_while(held, timeout, |current| current.generation == seen) {
            Ok((held, _)) => held,
            Err(poisoned) => poisoned.into_inner().0,
        };
        held.waiters -= 1;
        held.generation
    }

    fn changed(&self) {
        let (lock, signal) = &*self.changes;
        let mut held = guard_changes(lock);
        held.generation = held.generation.wrapping_add(1);
        if held.waiters > 0 {
            signal.notify_all();
        }
    }

    pub fn limits(&self) -> &HostConfig {
        &self.limits
    }

    pub fn base(&self, now: Instant) -> Instant {
        let mut base = match self.base.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *base.get_or_insert(now)
    }

    pub fn register_domain(&self, id: StorageDomainId, capabilities: &DomainCapabilities, now: MonotonicTime) {
        guard(&self.inner).register_domain(id, capabilities, now)
    }

    pub fn next_tree(&self) -> TreeNumber {
        guard(&self.inner).next_tree()
    }

    pub fn next_bootstrap(&self) -> u64 {
        guard(&self.inner).next_bootstrap()
    }

    pub fn report_memory(&self, tree: TreeNumber, snapshot_bytes: u64, in_flight_bytes: u64) {
        guard(&self.inner).report_memory(tree, snapshot_bytes, in_flight_bytes);
        self.changed();
    }

    pub fn forget_tree(&self, tree: TreeNumber) {
        guard(&self.inner).forget_tree(tree);
        self.changed();
    }

    pub fn accounted_memory_excluding(&self, tree: TreeNumber) -> u64 {
        guard(&self.inner).accounted_memory_excluding(tree)
    }

    pub fn memory_ceiling(&self) -> u64 {
        guard(&self.inner).memory_ceiling()
    }

    pub fn bytes_estimate(&self, domain: Option<StorageDomainId>) -> u64 {
        guard(&self.inner).bytes_estimate(domain)
    }

    pub fn record_bytes(&self, domain: Option<StorageDomainId>, bytes: u64, now: MonotonicTime) {
        guard(&self.inner).record_bytes(domain, bytes, now)
    }

    pub fn attribute(&self, id: GrantId, domain: StorageDomainId, now: MonotonicTime) {
        guard(&self.inner).attribute(id, domain, now)
    }

    pub fn estimate_of(&self, domain: Option<StorageDomainId>) -> Duration {
        guard(&self.inner).estimate_of(domain)
    }

    pub fn cost_of(&self, domain: Option<StorageDomainId>, operations: u32) -> Duration {
        guard(&self.inner).cost_of(domain, operations)
    }

    pub fn account(&self, now: MonotonicTime) {
        guard(&self.inner).account(now)
    }

    pub fn quarantined(&self, domain: Option<StorageDomainId>) -> bool {
        guard(&self.inner).quarantined(domain)
    }

    pub fn window_of(&self, domain: Option<StorageDomainId>) -> usize {
        guard(&self.inner).window_of(domain)
    }

    pub fn global_exhausted(&self, domain: Option<StorageDomainId>, origin: WorkOrigin) -> bool {
        guard(&self.inner).global_exhausted(domain, origin)
    }

    pub fn may_start(&self, domain: Option<StorageDomainId>) -> Result<(), ThrottleCause> {
        guard(&self.inner).may_start(domain)
    }

    pub fn in_flight(&self) -> usize {
        guard(&self.inner).in_flight()
    }

    pub fn try_admit(&self, reservation: Reservation, now: MonotonicTime) -> Result<Admitted, ThrottleCause> {
        guard(&self.inner).try_admit(reservation, now)
    }

    pub fn report(&self, id: GrantId, reported: Reported, now: MonotonicTime) {
        guard(&self.inner).report(id, reported, now)
    }

    pub fn overshoot_of(&self, id: GrantId) -> Duration {
        guard(&self.inner).overshoot_of(id)
    }

    pub fn charge_surcharge(&self, domain: Option<StorageDomainId>, origin: WorkOrigin, now: MonotonicTime) {
        guard(&self.inner).charge_surcharge(domain, origin, now)
    }

    pub fn charged_by_tree(&self, tree: TreeNumber) -> Duration {
        guard(&self.inner).charged_by_tree(tree)
    }

    pub fn try_start(&self, id: GrantId, at: MonotonicTime) -> Result<(), ThrottleCause> {
        guard(&self.inner).try_start(id, at)
    }

    pub fn start(&self, id: GrantId, at: MonotonicTime) {
        guard(&self.inner).start(id, at)
    }

    pub fn dispatch(&self, id: GrantId, at: MonotonicTime) {
        guard(&self.inner).dispatch(id, at)
    }

    pub fn release(&self, id: GrantId, now: MonotonicTime) {
        guard(&self.inner).release(id, now);
        self.changed();
    }

    pub fn record_outcome(&self, domain: Option<StorageDomainId>, error: bool, now: MonotonicTime) {
        guard(&self.inner).record_outcome(domain, error, now)
    }

    pub fn newly_stuck(&self, now: MonotonicTime) -> Vec<GrantId> {
        guard(&self.inner).newly_stuck(now)
    }

    pub fn mark_stuck(&self, id: GrantId, now: MonotonicTime) {
        guard(&self.inner).mark_stuck(id, now)
    }

    pub fn domain_of_grant(&self, id: GrantId) -> Option<StorageDomainId> {
        guard(&self.inner).domain_of_grant(id)
    }

    pub fn stuck_grants(&self) -> Vec<Grant> {
        guard(&self.inner).stuck_grants().cloned().collect()
    }

    pub fn next_stuck_deadline(&self) -> Option<MonotonicTime> {
        guard(&self.inner).next_stuck_deadline()
    }

    pub fn admissible_at(&self, domain: Option<StorageDomainId>, now: MonotonicTime) -> Option<MonotonicTime> {
        guard(&self.inner).admissible_at(domain, now)
    }

    pub fn throttle(&self, now: MonotonicTime) -> Option<(ThrottleCause, Option<MonotonicTime>)> {
        guard(&self.inner).throttle(now)
    }

    pub fn resume_at(&self, now: MonotonicTime) -> Option<MonotonicTime> {
        guard(&self.inner).resume_at(now)
    }

    pub fn timer_hints(&self, now: MonotonicTime) -> (Option<MonotonicTime>, Option<MonotonicTime>) {
        let governor = guard(&self.inner);
        (governor.resume_at(now), governor.next_stuck_deadline())
    }

    pub fn domain_health_map(
        &self,
        now: MonotonicTime,
        queued: &std::collections::BTreeSet<StorageDomainId>,
        into: &mut BTreeMap<StorageDomainId, crate::update::ResourceHealth>,
    ) {
        let governor = guard(&self.inner);
        for (id, slot) in into.iter_mut() {
            *slot = match governor.domain_health(*id, now, queued.contains(id)) {
                Some((cause, resume)) => crate::update::ResourceHealth::Throttled { cause, resume },
                None => crate::update::ResourceHealth::Nominal,
            };
        }
    }

    pub fn grants(&self) -> Vec<Grant> {
        guard(&self.inner).grants().cloned().collect()
    }

    pub fn new_grants_into(&self, into: &mut Vec<Grant>, seen: &dyn Fn(GrantId, u32) -> bool) {
        into.extend(guard(&self.inner).grants().filter(|grant| !seen(grant.id, grant.lease)).cloned());
    }

    pub fn view(&self, now: MonotonicTime) -> GovernorView {
        guard(&self.inner).view(now)
    }
}
