//! `governor` admits filesystem work for the whole host process.
//!
//! [`HostGovernor`] decides whether a filesystem operation may run. It keeps
//! worker-time token buckets per storage domain and globally. It also keeps
//! per-domain concurrency windows, the bootstrap allowance and the
//! accounted-memory ceilings of RFC §15. Every tree and scan in one process
//! shares the governor from [`host_governor`] (RFC §15.9). An opt-in shared
//! authority extends admission across processes (`rfc/coordination.md`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};
use std::time::Duration;
use std::time::Instant;

use super::types::{MonotonicTime, WorkOrigin};
use crate::config::HostConfig;
use crate::domain::{AccessTopology, DomainCapabilities, MediaHint, StorageDomainId};
use crate::ids::{JobId, WatchReleaseId, WatchRequestId};
use crate::path::RelativePath;
use crate::update::{ResourceLimit, ResourceLimited, ThrottleCause};

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
mod shared;

const LATENCY_HISTORY: usize = 32;
const QUEUE_HISTORY: usize = 8;
const TARGET_FACTOR: u32 = 2;
const LOCAL_START_WINDOW: usize = 2;
const CONSERVATIVE_START_WINDOW: usize = 1;
const CONSERVATIVE_TOPOLOGY_CEILING: usize = 2;

/// `TreeNumber` identifies one tree or scan in the accounting of a governor.
///
/// [`HostGovernor::next_tree`] allocates each number once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TreeNumber(u64);

impl TreeNumber {
    /// `get` returns the raw number.
    pub fn get(self) -> u64 {
        self.0
    }
}

/// `GrantId` names one grant.
///
/// A grant admits one physical filesystem step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GrantId {
    /// The grant belongs to a job of the given tree.
    ///
    /// The watch registration of the job shares the grant.
    Job(TreeNumber, JobId),
    /// The grant covers a watch registration outside any job.
    WatchRegistration(TreeNumber, WatchRequestId),
    /// The grant covers a watch release.
    ///
    /// Watch releases bypass the duty budgets and the memory ceilings.
    WatchRelease(TreeNumber, WatchReleaseId),
    /// The grant covers work before its storage domain is known (RFC §10.3).
    ///
    /// [`HostGovernor::next_bootstrap`] allocates the number.
    Bootstrap(u64),
}

impl GrantId {
    /// `job` returns the job of a [`GrantId::Job`].
    pub fn job(self) -> Option<JobId> {
        match self {
            GrantId::Job(_, id) => Some(id),
            GrantId::WatchRegistration(_, _) | GrantId::WatchRelease(_, _) | GrantId::Bootstrap(_) => None,
        }
    }

    /// `release` returns the release of a [`GrantId::WatchRelease`].
    pub fn release(self) -> Option<WatchReleaseId> {
        match self {
            GrantId::WatchRelease(_, id) => Some(id),
            GrantId::Job(_, _) | GrantId::WatchRegistration(_, _) | GrantId::Bootstrap(_) => None,
        }
    }

    /// `tree` returns the owning tree.
    ///
    /// A [`GrantId::Bootstrap`] has no tree and returns `None`.
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

/// `AdmissionDecision` records the outcome of one admission attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// The governor admitted the reservation.
    Granted,
    /// The governor refused the reservation for the given cause.
    Denied(ThrottleCause),
}

/// `Grant` records one live admission.
///
/// The governor holds each grant until [`HostGovernor::release`]. RFC §16
/// requires the permitted and performed operations of each grant to be
/// observable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// `id` identifies the grant.
    pub id: GrantId,
    /// `path` holds the root-relative path of the target.
    pub path: RelativePath,
    /// `lease` holds the ordinal of the lease within its job.
    ///
    /// The first lease has ordinal 0.
    pub lease: u32,
    /// The grant must perform this many reads and watch registrations.
    pub required: u32,
    /// The grant permits this many per-child operations.
    pub operations: u32,
    /// The adapter reported this many performed operations.
    ///
    /// `performed` stays `None` until the first report.
    pub performed: Option<u32>,
    /// The governor charges this storage domain.
    ///
    /// `None` means the bootstrap scope.
    pub domain: Option<StorageDomainId>,
    /// The grant draws on the allowance of this origin.
    pub origin: WorkOrigin,
    /// The governor reserved this worker time at admission.
    pub reserved: Duration,
    /// The governor has charged this worker time so far.
    ///
    /// The charge is at least the reservation.
    pub charged: Duration,
    /// The governor admitted the grant at this time.
    pub admitted: MonotonicTime,
    /// Physical occupancy began at this time.
    ///
    /// `started` stays `None` while the grant waits for a worker.
    pub started: Option<MonotonicTime>,
    /// The filesystem work began at this time.
    ///
    /// Any watch registration precedes this point.
    pub dispatched: Option<MonotonicTime>,
    /// `stuck` is set once the worker exceeds [`HostConfig::stuck_threshold`].
    pub stuck: bool,
    /// `failed` is set when this physical lease observes a failure.
    ///
    /// A rejected result also counts as a failure.
    pub failed: bool,
    /// `listing` is set when the grant covers a listing lease.
    pub listing: bool,
    /// `registration` is set when the grant includes a watch registration.
    pub registration: bool,
    /// The watch registration took this long.
    ///
    /// `registration_took` stays `None` until the duration is known.
    pub registration_took: Option<Duration>,
}

/// `DomainAccount` sums worker time for one storage domain or the bootstrap
/// scope.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DomainAccount {
    /// The governor reserved this worker time at admission.
    pub granted: Duration,
    /// The governor charged this worker time.
    ///
    /// Overshoot and surcharges are included.
    pub charged: Duration,
    /// The governor admitted this many grants against the account.
    pub grants: u64,
}

/// `LatencySummary` describes recent worker time per filesystem operation.
///
/// The window holds the latest 32 samples (RFC §15.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LatencySummary {
    /// The window holds this many samples.
    pub samples: usize,
    /// `minimum` holds the smallest sample.
    ///
    /// The minimum is the standing-delay signal.
    pub minimum: Duration,
    /// `median` holds the median sample.
    pub median: Duration,
    /// `mean` holds the mean sample.
    pub mean: Duration,
    /// `tail` holds the 90th-percentile sample.
    pub tail: Duration,
}

/// `DomainView` shows the governor state of one storage domain at one instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainView {
    /// The governor reserved this worker time on the domain at admission.
    pub granted: Duration,
    /// The governor charged this worker time on the domain.
    ///
    /// Overshoot and surcharges are included.
    pub charged: Duration,
    /// The governor admitted this many grants on the domain.
    pub grants: u64,
    /// `capacity` holds the capacity of the domain background bucket.
    pub capacity: Duration,
    /// `level` holds the current background bucket level.
    ///
    /// The level reads zero while the bucket is in debt.
    pub level: Duration,
    /// The background bucket is this far below zero.
    pub debt: Duration,
    /// `foreground_capacity` holds the capacity of the domain foreground
    /// bucket.
    pub foreground_capacity: Duration,
    /// `foreground_level` holds the current foreground bucket level.
    ///
    /// The level reads zero while the bucket is in debt.
    pub foreground_level: Duration,
    /// The foreground bucket is this far below zero.
    pub foreground_debt: Duration,
    /// `bytes_estimate` holds the moving mean of listing result bytes on the
    /// domain.
    pub bytes_estimate: u64,
    /// `window` holds the current concurrency window (RFC §15.5).
    pub window: usize,
    /// The window may grow to at most this size.
    pub ceiling: usize,
    /// This many started grants run on the domain.
    pub in_flight: usize,
    /// This many grants on the domain are stuck.
    ///
    /// One stuck grant quarantines the domain.
    pub stuck: usize,
    /// The governor estimates this worker time per filesystem operation.
    pub estimate: Duration,
    /// `latency` covers every operation kind.
    pub latency: LatencySummary,
    /// `listing_latency` covers listing operations.
    pub listing_latency: LatencySummary,
    /// `metadata_latency` covers every operation other than listings.
    pub metadata_latency: LatencySummary,
    /// `registration_latency` covers watch registrations.
    pub registration_latency: LatencySummary,
    /// `queue_delay` holds the smallest recent delay from admission to start.
    pub queue_delay: Duration,
    /// The governor denied this many admissions on the domain.
    pub throttled_jobs: u64,
    /// The domain spent this long with a denial outstanding.
    pub throttled_duration: Duration,
    /// This much time passed since the governor registered the domain.
    pub elapsed: Duration,
}

impl DomainView {
    /// `effective_duty` returns charged worker time per elapsed second.
    ///
    /// `effective_duty` counts from the registration of the domain.
    pub fn effective_duty(&self) -> f64 {
        let elapsed = self.elapsed.as_secs_f64();
        if elapsed <= 0.0 { 0.0 } else { self.charged.as_secs_f64() / elapsed }
    }
}

/// `Reservation` requests admission of one physical filesystem step.
///
/// The governor reserves the estimated cost of every required and permitted
/// operation (RFC §15.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    /// `id` identifies the resulting grant.
    ///
    /// The id must not name a live grant.
    pub id: GrantId,
    /// `path` holds the root-relative path of the target.
    pub path: RelativePath,
    /// The step must perform this many reads.
    pub reads: u32,
    /// The step must perform this many watch registrations before its read.
    pub registrations: u32,
    /// The step requests this many per-child operations.
    ///
    /// The governor permits as many as the budget affords, and at least one
    /// when the step requests any.
    pub operations: u32,
    /// The reserved worker time may reach at most this value.
    ///
    /// The remaining foreground ceiling of a command sets it.
    pub ceiling: Option<Duration>,
    /// `lease` holds the ordinal of the lease within its job.
    ///
    /// The first lease has ordinal 0.
    pub lease: u32,
    /// The governor charges this storage domain.
    ///
    /// `None` charges the bootstrap scope.
    pub domain: Option<StorageDomainId>,
    /// The step draws on the allowance of this origin.
    pub origin: WorkOrigin,
    /// `listing` is set when the step is a listing lease.
    ///
    /// The estimated result size of a listing counts against
    /// [`HostConfig::in_flight_listing_bytes`].
    pub listing: bool,
}

impl Reservation {
    fn work(&self) -> crate::coordination::protocol::Work {
        match self.id {
            GrantId::Bootstrap(_) => crate::coordination::protocol::Work::Bootstrap,
            GrantId::WatchRegistration(..) => crate::coordination::protocol::Work::WatchRegistration,
            GrantId::WatchRelease(..) => crate::coordination::protocol::Work::WatchRelease,
            _ if self.listing => crate::coordination::protocol::Work::Listing,
            _ => crate::coordination::protocol::Work::Enrichment,
        }
    }
}

/// `Admitted` records the terms of a successful admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The governor reserved this worker time for the grant.
    pub cost: Duration,
    /// The grant permits this many per-child operations.
    ///
    /// The work must perform no more.
    pub operations: u32,
}

struct Preparation {
    reservation: Reservation,
    admitted: Admitted,
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
    estimate: Duration,
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
    physical: bool,
}

/// `PreparedAdmission` holds a provisional local budget reservation.
///
/// Callers use it to compose admission authorities. Dropping
/// `PreparedAdmission` aborts the preparation without charging work.
/// `PreparedAdmission` owns no physical capacity. A commit revalidates current
/// policy and resource limits. Only the admission from the commit may request a
/// physical start.
#[must_use = "dropping a preparation aborts its provisional reservation"]
pub struct PreparedAdmission {
    governor: HostGovernor,
    id: GrantId,
    admitted: Admitted,
    armed: bool,
}

impl PreparedAdmission {
    /// `admitted` returns the provisional terms of the preparation.
    pub fn admitted(&self) -> Admitted {
        self.admitted
    }

    /// `limit_operations` caps the lease operations at the allowance of the
    /// other authority.
    ///
    /// `limit_operations` never increases a grant and keeps the held budget
    /// until commit. Commit computes the final charge from the reduced
    /// operation count.
    pub fn limit_operations(&mut self, maximum: std::num::NonZeroU32) {
        let mut governor = guard(&self.governor.inner);
        let prepared = governor.prepared.get_mut(&self.id).expect("preparation owns its reservation");
        prepared.reservation.operations = prepared.reservation.operations.min(maximum.get());
        self.admitted.operations = self.admitted.operations.min(maximum.get());
    }

    /// `commit` commits the preparation once.
    ///
    /// `commit` aborts when current limits no longer permit the work. The final
    /// operation count can be smaller than the prepared count when estimates
    /// change. A caller with composed authorities must reconcile that count
    /// before either authority permits physical dispatch.
    ///
    /// # Errors
    ///
    /// `commit` returns the denial causes of [`HostGovernor::try_admit`].
    pub fn commit(mut self, now: MonotonicTime) -> Result<Admitted, ThrottleCause> {
        let mut governor = guard(&self.governor.inner);
        let mut prepared = governor.prepared.remove(&self.id).expect("preparation owns its reservation");
        self.armed = false;
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
        if let Some(shared) = &self.governor.shared {
            drop(governor);
            let work = prepared.reservation.work();
            return shared.admit(&self.governor, prepared.reservation, work, Some(prepared.admitted.cost), now);
        }
        prepared.reservation.ceiling =
            Some(prepared.reservation.ceiling.unwrap_or(Duration::MAX).min(prepared.admitted.cost));
        governor.try_admit(prepared.reservation, now)
    }
}

impl Drop for PreparedAdmission {
    fn drop(&mut self) {
        if self.armed {
            guard(&self.governor.inner).prepared.remove(&self.id);
        }
        self.governor.changed();
    }
}

/// `Reported` reports the cost of one completed step of a grant (RFC §15.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reported {
    /// The step blocked a worker for this long.
    ///
    /// `None` makes the governor charge measured occupancy.
    pub blocking: Option<Duration>,
    /// The step performed this many operations.
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

/// `GovernorView` shows the process-local governor state at one instant (RFC
/// §16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernorView {
    /// `capacity` holds the capacity of the global background bucket.
    pub capacity: Duration,
    /// `level` holds the current global background level.
    ///
    /// The level reads zero while the bucket is in debt.
    pub level: Duration,
    /// The global background bucket is this far below zero.
    pub debt: Duration,
    /// `foreground_capacity` holds the capacity of the global foreground
    /// bucket.
    pub foreground_capacity: Duration,
    /// `foreground_level` holds the current global foreground level.
    ///
    /// The level reads zero while the bucket is in debt.
    pub foreground_level: Duration,
    /// The global foreground bucket is this far below zero.
    pub foreground_debt: Duration,
    /// `bootstrap_capacity` holds the configured bootstrap allowance.
    pub bootstrap_capacity: Duration,
    /// Grants without a storage domain hold this much reserved worker time.
    pub bootstrap_outstanding: Duration,
    /// All trees together account this many bytes.
    ///
    /// Snapshot bytes and in-flight listing bytes count toward the total.
    pub accounted_memory: u64,
    /// `memory_ceiling` holds the configured accounted-memory ceiling in bytes.
    pub memory_ceiling: u64,
    /// Open listing sessions of all trees hold this many result bytes.
    pub in_flight_bytes: u64,
    /// `in_flight_bytes_ceiling` holds the configured in-flight listing byte
    /// ceiling.
    pub in_flight_bytes_ceiling: u64,
    /// The governor reserved this much worker time at admission in total.
    pub reserved: Duration,
    /// Open preparations hold this much budget.
    ///
    /// The governor can reverse these holds and keeps them apart from admitted
    /// work.
    pub prepared: Duration,
    /// This many [`PreparedAdmission`] values are open.
    pub preparations: usize,
    /// The governor charged this much worker time in total.
    ///
    /// Overshoot is included.
    pub charged: Duration,
    /// The governor charged this much in failure surcharges.
    pub surcharged: Duration,
    /// Adapters reported this much blocking time in total.
    pub reported_blocking: Duration,
    /// The started grants have occupied workers this long in total.
    pub running_occupancy: Duration,
    /// This many started grants await release.
    pub in_flight: usize,
    /// The governor granted this many admissions.
    pub grants: u64,
    /// The governor granted this many leases after the first lease of a job.
    pub lease_grants: u64,
    /// The governor admitted this many watch registrations.
    pub watch_registration_grants: u64,
    /// The governor admitted this many watch releases.
    pub watch_release_grants: u64,
    /// The governor denied this many admissions.
    pub denials: u64,
    /// The governor spent this long with a denial outstanding.
    pub throttled_duration: Duration,
    /// One background operation becomes affordable at this time (RFC §12).
    ///
    /// `None` means one is affordable now or no refill time is computable.
    pub next_admissible: Option<MonotonicTime>,
    /// `last_decision` records the outcome of the latest admission attempt.
    pub last_decision: Option<AdmissionDecision>,
    /// `bootstrap` sums work without a storage domain.
    pub bootstrap: DomainAccount,
    /// The governor estimates this worker time per bootstrap operation.
    pub bootstrap_estimate: Duration,
    /// `domains` holds the state of every registered storage domain.
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
    prepared: BTreeMap<GrantId, Preparation>,
    failed_grants: BTreeSet<GrantId>,
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
            prepared: BTreeMap::new(),
            failed_grants: BTreeSet::new(),
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
        let cost = nanos(self.cost_of(domain, 1)) + self.prepared_costs(domain, origin).0;
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

    fn affordable(
        &self,
        domain: Option<StorageDomainId>,
        origin: WorkOrigin,
        ceiling: Option<Duration>,
        excluding: Option<GrantId>,
    ) -> i128 {
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
        let (global_held, domain_held) = self.prepared_costs_excluding(domain, origin, excluding);
        let mut level = (global - global_held).min(local - domain_held).min(nanos(self.capacity_for(domain, origin)));
        if let Some(ceiling) = ceiling {
            level = level.min(nanos(ceiling));
        }
        level.max(0)
    }

    fn prepared_costs(&self, domain: Option<StorageDomainId>, origin: WorkOrigin) -> (i128, i128) {
        self.prepared_costs_excluding(domain, origin, None)
    }

    fn prepared_costs_excluding(
        &self,
        domain: Option<StorageDomainId>,
        origin: WorkOrigin,
        excluding: Option<GrantId>,
    ) -> (i128, i128) {
        let held = self
            .prepared
            .values()
            .filter(|prepared| prepared.reservation.origin == origin && Some(prepared.reservation.id) != excluding);
        let global = held.clone().map(|prepared| nanos(prepared.admitted.cost)).sum();
        let local = held.filter(|prepared| prepared.reservation.domain == domain).map(|p| nanos(p.admitted.cost)).sum();
        (global, local)
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

    fn evaluate(&mut self, reservation: &Reservation, now: MonotonicTime) -> Result<Admitted, ThrottleCause> {
        let Reservation { id, reads, registrations, operations, ceiling, domain, origin, listing, .. } = *reservation;
        self.account(now);
        if self.grants.contains_key(&id) || self.prepared.contains_key(&id) {
            self.deny(ThrottleCause::Concurrency, domain, Duration::ZERO, now);
            return Err(ThrottleCause::Concurrency);
        }
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
        let affordable = self.affordable(domain, origin, ceiling, None);
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
        let bootstrap_prepared: i128 = self
            .prepared
            .values()
            .filter(|prepared| prepared.reservation.domain.is_none())
            .map(|prepared| nanos(prepared.admitted.cost))
            .sum();
        if !cleanup
            && domain.is_none()
            && self.bootstrap_outstanding + bootstrap_prepared + nanos(cost) > self.bootstrap_capacity
        {
            self.deny(ThrottleCause::DutyBudget, domain, cost, now);
            return Err(ThrottleCause::DutyBudget);
        }
        Ok(Admitted { cost, operations: permitted })
    }

    fn try_prepare(&mut self, mut reservation: Reservation, now: MonotonicTime) -> Result<Admitted, ThrottleCause> {
        // A preparation is short-lived and may not occupy a worker. Bound
        // the bookkeeping independently of callers holding onto the guards.
        if self.prepared.len() >= self.config.maximum_in_flight {
            self.deny(ThrottleCause::Concurrency, reservation.domain, Duration::ZERO, now);
            return Err(ThrottleCause::Concurrency);
        }
        let admitted = self.evaluate(&reservation, now)?;
        reservation.operations = admitted.operations;
        self.prepared.insert(
            reservation.id,
            Preparation {
                #[cfg(any(
                    target_os = "linux",
                    target_os = "freebsd",
                    target_os = "illumos",
                    target_os = "macos",
                    windows
                ))]
                estimate: self.estimate_of(reservation.domain),
                #[cfg(any(
                    target_os = "linux",
                    target_os = "freebsd",
                    target_os = "illumos",
                    target_os = "macos",
                    windows
                ))]
                physical: false,
                reservation,
                admitted,
            },
        );
        Ok(admitted)
    }

    pub fn try_admit(&mut self, reservation: Reservation, now: MonotonicTime) -> Result<Admitted, ThrottleCause> {
        let admitted = self.evaluate(&reservation, now)?;
        Ok(self.record_admission(reservation, admitted, now))
    }

    fn record_admission(&mut self, reservation: Reservation, admitted: Admitted, now: MonotonicTime) -> Admitted {
        let Admitted { cost, operations: permitted } = admitted;
        let Reservation { id, path, reads, registrations, lease, domain, origin, listing, .. } = reservation;
        let required = reads + registrations;
        let cleanup = id.release().is_some();
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
                failed: false,
                listing,
                registration: registrations > 0,
                registration_took: None,
            },
        );
        Admitted { cost, operations: permitted }
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
            return Err(ThrottleCause::Concurrency);
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
        self.failed_grants.remove(&id);
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

    pub(crate) fn record_grant_failure(&mut self, id: GrantId, now: MonotonicTime) {
        let Some(grant) = self.grants.get_mut(&id) else { return };
        if grant.started.is_none() {
            return;
        }
        grant.failed = true;
        if !self.failed_grants.insert(id) {
            return;
        }
        let (domain, origin) = (grant.domain, grant.origin);
        self.charge_surcharge(domain, origin, now);
        self.record_outcome(domain, true, now);
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
        self.record_grant_failure(id, now);
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
        self.budget_wait(domain, WorkOrigin::Background, cost, now).flatten()
    }

    // None means affordable; Some(None) waits for ownership to change rather
    // than refill. A full bucket cannot refill past a provisional hold.
    fn budget_wait(
        &self,
        domain: Option<StorageDomainId>,
        origin: WorkOrigin,
        cost: Duration,
        now: MonotonicTime,
    ) -> Option<Option<MonotonicTime>> {
        let (global_held, local_held) = self.prepared_costs(domain, origin);
        let global_bucket = match origin {
            WorkOrigin::Background => &self.global,
            WorkOrigin::Foreground => &self.foreground,
        };
        let local_bucket = domain.and_then(|id| self.domains.get(&id)).map(|state| match origin {
            WorkOrigin::Background => &state.bucket,
            WorkOrigin::Foreground => &state.foreground,
        });
        let cost = nanos(cost);
        if (global_held > 0 && cost + global_held > global_bucket.capacity)
            || local_bucket.is_some_and(|bucket| local_held > 0 && cost + local_held > bucket.capacity)
        {
            return Some(None);
        }
        let global = global_bucket.affordable_at(now, cost + global_held);
        let local = local_bucket.and_then(|bucket| bucket.affordable_at(now, cost + local_held));
        match (global, local) {
            (None, None) => None,
            (Some(a), Some(b)) => Some(Some(a.max(b))),
            (Some(a), None) => Some(Some(a)),
            (None, Some(b)) => Some(Some(b)),
        }
    }

    pub fn throttle(&self, now: MonotonicTime) -> Option<(ThrottleCause, Option<MonotonicTime>)> {
        if self.memory_exceeded(0) {
            return Some((ThrottleCause::Memory, None));
        }
        if let Some((domain, cost)) = self.denied
            && let Some(at) = self.budget_wait(domain, WorkOrigin::Background, cost, now)
        {
            return Some((ThrottleCause::DutyBudget, at));
        }
        if let Some((domain, cost)) = self.denied_foreground
            && let Some(at) = self.budget_wait(domain, WorkOrigin::Foreground, cost, now)
        {
            return Some((ThrottleCause::ForegroundCeiling, at));
        }
        match self.grants.values().any(|grant| grant.stuck) {
            true => Some((ThrottleCause::StuckWorker, None)),
            false => None,
        }
    }

    pub fn resume_at(&self, now: MonotonicTime) -> Option<MonotonicTime> {
        match self.throttle(now)? {
            (ThrottleCause::DutyBudget | ThrottleCause::ForegroundCeiling, _) => {
                let foreground = self
                    .denied_foreground
                    .and_then(|(domain, cost)| self.budget_wait(domain, WorkOrigin::Foreground, cost, now).flatten());
                self.background_resume_at(now).into_iter().chain(foreground).min()
            }
            (_, resume) => resume,
        }
    }

    pub fn background_resume_at(&self, now: MonotonicTime) -> Option<MonotonicTime> {
        match self.throttle(now)? {
            (ThrottleCause::DutyBudget, resume) => resume,
            _ => None,
        }
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
        if let Some(at) = self.budget_wait(Some(domain), WorkOrigin::Background, self.cost_of(Some(domain), 1), now) {
            return Some((ThrottleCause::DutyBudget, at));
        }
        if let Some(at) = self.budget_wait(Some(domain), WorkOrigin::Foreground, self.cost_of(Some(domain), 1), now)
            && self.denied_foreground.is_some()
        {
            return Some((ThrottleCause::ForegroundCeiling, at));
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
            prepared: self.prepared.values().map(|prepared| prepared.admitted.cost).sum(),
            preparations: self.prepared.len(),
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

/// `HostGovernor` admits filesystem work for one process.
///
/// Clones share one governor. Every operation of a tree or scan goes through
/// admission, start, report and release (RFC §15.1). A governor from neither
/// [`host_governor`] nor [`HostGovernor::install`] opts out of the process-wide
/// bound of RFC §15.9.
///
/// One grant moves through [`HostGovernor::try_admit`],
/// [`HostGovernor::try_start`], one [`HostGovernor::report`] per completed
/// step, and [`HostGovernor::release`]. Every method takes the caller's
/// [`MonotonicTime`]. The governor clamps a time before an earlier call.
#[derive(Clone)]
pub struct HostGovernor {
    inner: Arc<Mutex<Governor>>,
    base: Arc<Mutex<Option<Instant>>>,
    changes: Arc<(Mutex<Changes>, Condvar)>,
    limits: Arc<HostConfig>,
    coordination: Option<Arc<crate::coordination::Selection>>,
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
    shared: Option<Arc<shared::Binding>>,
}

#[derive(Default)]
struct Changes {
    generation: u64,
    waiters: usize,
    wakers: Vec<Weak<dyn ChangeWaker>>,
}

pub(crate) trait ChangeWaker: Send + Sync {
    fn wake(&self);
}

static PROCESS_GOVERNOR: OnceLock<HostGovernor> = OnceLock::new();

/// `HostGovernorError` reports a failure to construct or install a
/// [`HostGovernor`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostGovernorError {
    /// The process-wide governor is already in use.
    ///
    /// [`host_governor`] or an earlier installation created it.
    AlreadyInstalled,
    /// [`HostConfig::validate`] rejected the configuration with this message.
    InvalidConfig(String),
    /// The coordination scope failed to open or join, or its options were
    /// invalid.
    Coordination(crate::coordination::Error),
}

impl std::fmt::Display for HostGovernorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostGovernorError::AlreadyInstalled => f.write_str("the process governor is already in use"),
            HostGovernorError::InvalidConfig(message) => write!(f, "invalid host configuration: {message}"),
            HostGovernorError::Coordination(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for HostGovernorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Coordination(error) => Some(error),
            _ => None,
        }
    }
}

/// `host_governor` returns the process-wide governor.
///
/// The first call creates it with [`HostConfig::default`] unless
/// [`HostGovernor::install`] ran earlier. [`Tree::open`](crate::Tree::open) and
/// [`Scan::open`](crate::Scan::open) use it (RFC §15.9).
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
    /// `install` installs a process-only governor as the process-wide one.
    ///
    /// # Errors
    ///
    /// `install` returns [`HostGovernorError::AlreadyInstalled`] after any
    /// earlier use of the process-wide governor. It returns
    /// [`HostGovernorError::InvalidConfig`] when `config` fails validation.
    pub fn install(config: HostConfig) -> Result<HostGovernor, HostGovernorError> {
        Self::install_with_coordination(config, crate::coordination::Mode::ProcessOnly)
    }

    /// `install_with_coordination` installs a coordination policy as the
    /// process-wide governor.
    ///
    /// `install_with_coordination` must run before the first use of the
    /// process-wide governor.
    ///
    /// # Errors
    ///
    /// `install_with_coordination` returns
    /// [`HostGovernorError::AlreadyInstalled`] after any earlier use of the
    /// process-wide governor. It otherwise returns the errors of
    /// [`HostGovernor::configured`].
    pub fn install_with_coordination(
        config: HostConfig,
        mode: crate::coordination::Mode,
    ) -> Result<Self, HostGovernorError> {
        if PROCESS_GOVERNOR.get().is_some() {
            return Err(HostGovernorError::AlreadyInstalled);
        }
        let installed = Self::configured(&config, mode)?;
        match PROCESS_GOVERNOR.set(installed.clone()) {
            Ok(()) => Ok(installed),
            Err(_) => Err(HostGovernorError::AlreadyInstalled),
        }
    }

    /// `configured` builds a governor with an observable coordination policy.
    ///
    /// `Auto` falls back to process-only admission when the platform lacks a
    /// native backend. It also falls back when the rendezvous is unavailable
    /// before join. [`HostGovernor::coordination_status`] reports the fallback
    /// reason.
    ///
    /// # Errors
    ///
    /// `configured` returns [`HostGovernorError::InvalidConfig`] for an invalid
    /// `config`. It returns [`HostGovernorError::Coordination`] for invalid
    /// shared options and for any other open or join failure.
    pub fn configured(config: &HostConfig, mode: crate::coordination::Mode) -> Result<Self, HostGovernorError> {
        use crate::coordination::{self, Mode};
        config.validate().map_err(HostGovernorError::InvalidConfig)?;
        let options = match &mode {
            Mode::ProcessOnly => return Ok(Self::independent(config)),
            Mode::Auto(options) | Mode::Required(options) => options,
        };
        options
            .limits
            .validate()
            .map_err(|error| HostGovernorError::Coordination(coordination::Error::InvalidConfig(error.to_string())))?;
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
        let connected = (|| {
            let scope = match &options.scope {
                coordination::Rendezvous::Discover => coordination::native::Scope::discover(options.limits),
                coordination::Rendezvous::Directory(path) => coordination::native::Scope::open(path, options.limits),
            }
            .map_err(|error| (coordination::Error::from(error), true))?;
            Self::with_coordination(config, scope).map_err(|error| (coordination::Error::from(error), false))
        })();
        #[cfg(not(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "illumos",
            target_os = "macos",
            windows
        )))]
        let connected: Result<Self, (coordination::Error, bool)> =
            Err((coordination::Error::UnsupportedPlatform, true));
        let mut governor = match connected {
            Ok(governor) => governor,
            Err((error, true)) if matches!(mode, Mode::Auto(_)) && error.permits_fallback() => {
                let mut governor = Self::independent(config);
                governor.coordination = Some(Arc::new(coordination::Selection { mode, fallback: Some(error) }));
                return Ok(governor);
            }
            Err((error, _)) => return Err(HostGovernorError::Coordination(error)),
        };
        governor.coordination = Some(Arc::new(coordination::Selection { mode, fallback: None }));
        Ok(governor)
    }

    /// `coordination_status` reports the effective coordination policy and
    /// connection health.
    ///
    /// `coordination_status` keeps its report separate from local accounting.
    pub fn coordination_status(&self) -> crate::coordination::Status {
        use crate::coordination::{Mode, State, Status};
        let requested = self.coordination.as_ref().map_or(Mode::ProcessOnly, |selection| selection.mode.clone());
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
        if let Some(binding) = &self.shared {
            return Status { requested, state: binding.status() };
        }
        let state = match self.coordination.as_ref().and_then(|selection| selection.fallback.clone()) {
            Some(reason) => State::Fallback { reason },
            None => State::ProcessOnly,
        };
        Status { requested, state }
    }

    /// `independent` builds a process-only governor outside the process-wide
    /// bound.
    ///
    /// Trees and scans under it are outside the bound of RFC §15.9. The caller
    /// must validate `config` first.
    /// [`Tree::open_outside_host_governor`](crate::Tree::open_outside_host_governor)
    /// rejects an invalid one.
    pub fn independent(config: &HostConfig) -> HostGovernor {
        HostGovernor {
            inner: Arc::new(Mutex::new(Governor::new(config, MonotonicTime::ZERO))),
            base: Arc::new(Mutex::new(None)),
            changes: Arc::new((Mutex::new(Changes::default()), Condvar::new())),
            limits: Arc::new(*config),
            coordination: None,
            #[cfg(any(
                target_os = "linux",
                target_os = "freebsd",
                target_os = "illumos",
                target_os = "macos",
                windows
            ))]
            shared: None,
        }
    }

    /// `changes` returns the change generation.
    ///
    /// The generation advances whenever released capacity, memory or a dropped
    /// preparation can let waiting work proceed.
    pub fn changes(&self) -> u64 {
        guard_changes(&self.changes.0).generation
    }

    /// `wait_for_change` blocks the calling thread until the generation leaves
    /// `seen`.
    ///
    /// `wait_for_change` returns the current generation, also after `timeout`
    /// elapses.
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

    pub(crate) fn on_change(&self, waker: Weak<dyn ChangeWaker>) {
        guard_changes(&self.changes.0).wakers.push(waker);
    }

    fn changed(&self) {
        let (lock, signal) = &*self.changes;
        let mut held = guard_changes(lock);
        held.generation = held.generation.wrapping_add(1);
        if held.waiters > 0 {
            signal.notify_all();
        }
        held.wakers.retain(|waker| waker.strong_count() > 0);
        let wakers: Vec<_> = held.wakers.iter().filter_map(Weak::upgrade).collect();
        drop(held);
        for waker in wakers {
            waker.wake();
        }
    }

    /// `limits` returns the host configuration.
    pub fn limits(&self) -> &HostConfig {
        &self.limits
    }

    /// `base` returns the base instant of the governor's clock.
    ///
    /// Every [`MonotonicTime`] under this governor counts from this instant.
    /// The first call fixes the base at `now`, and later calls return it
    /// unchanged.
    pub fn base(&self, now: Instant) -> Instant {
        let mut base = match self.base.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *base.get_or_insert(now)
    }

    /// `register_domain` creates the account of a storage domain.
    ///
    /// The declared topology sizes the account. Remote, userspace, virtual and
    /// removable domains start with a window of one and a ceiling of at most
    /// two (RFC §15.5). `register_domain` leaves a known domain unchanged.
    pub fn register_domain(&self, id: StorageDomainId, capabilities: &DomainCapabilities, now: MonotonicTime) {
        guard(&self.inner).register_domain(id, capabilities, now)
    }

    /// `next_tree` allocates a new [`TreeNumber`].
    pub fn next_tree(&self) -> TreeNumber {
        guard(&self.inner).next_tree()
    }

    /// `next_bootstrap` allocates a number for a new [`GrantId::Bootstrap`].
    pub fn next_bootstrap(&self) -> u64 {
        guard(&self.inner).next_bootstrap()
    }

    /// `report_memory` replaces the snapshot and in-flight listing bytes of
    /// `tree`.
    pub fn report_memory(&self, tree: TreeNumber, snapshot_bytes: u64, in_flight_bytes: u64) {
        guard(&self.inner).report_memory(tree, snapshot_bytes, in_flight_bytes);
        self.changed();
    }

    pub(crate) fn try_reserve_scan_memory(
        &self,
        source: TreeNumber,
        tree: TreeNumber,
        bytes: u64,
    ) -> Result<(), ResourceLimited> {
        let mut governor = guard(&self.inner);
        let (snapshot, previous) = governor.memory.get(&source).copied().unwrap_or((0, 0));
        for (limit, configured, observed) in [
            (
                ResourceLimit::AccountedMemory,
                governor.memory_ceiling(),
                governor.memory_total.saturating_sub(previous).saturating_add(bytes),
            ),
            (
                ResourceLimit::InFlightBytes,
                governor.config.in_flight_listing_bytes,
                governor.in_flight_total.saturating_sub(previous).saturating_add(bytes),
            ),
        ] {
            if observed > configured {
                return Err(ResourceLimited { limit, configured, observed, domain: None });
            }
        }
        governor.report_memory(source, snapshot, 0);
        governor.report_memory(tree, 0, bytes);
        drop(governor);
        self.changed();
        Ok(())
    }

    pub(crate) fn try_retain_scan_memory(&self, tree: TreeNumber, bytes: u64) -> Result<(), ResourceLimited> {
        let mut governor = guard(&self.inner);
        let (snapshot, in_flight) = governor.memory.get(&tree).copied().unwrap_or((0, 0));
        let observed = governor.memory_total.saturating_sub(snapshot).saturating_sub(in_flight).saturating_add(bytes);
        let configured = governor.memory_ceiling();
        if observed > configured {
            return Err(ResourceLimited { limit: ResourceLimit::AccountedMemory, configured, observed, domain: None });
        }
        governor.report_memory(tree, bytes, 0);
        drop(governor);
        self.changed();
        Ok(())
    }

    pub(crate) fn try_return_scan_memory(
        &self,
        reservation: TreeNumber,
        scan: TreeNumber,
        bytes: u64,
    ) -> Result<(), ResourceLimited> {
        let mut governor = guard(&self.inner);
        let (_, reserved) = governor.memory.get(&reservation).copied().unwrap_or((0, 0));
        let (retained, previous) = governor.memory.get(&scan).copied().unwrap_or((0, 0));
        for (limit, configured, observed) in [
            (
                ResourceLimit::AccountedMemory,
                governor.memory_ceiling(),
                governor.memory_total.saturating_sub(reserved).saturating_sub(previous).saturating_add(bytes),
            ),
            (
                ResourceLimit::InFlightBytes,
                governor.config.in_flight_listing_bytes,
                governor.in_flight_total.saturating_sub(reserved).saturating_sub(previous).saturating_add(bytes),
            ),
        ] {
            if observed > configured {
                return Err(ResourceLimited { limit, configured, observed, domain: None });
            }
        }
        governor.report_memory(reservation, 0, 0);
        governor.report_memory(scan, retained, bytes);
        drop(governor);
        self.changed();
        Ok(())
    }

    /// `forget_tree` removes the memory and charge accounting of `tree`.
    pub fn forget_tree(&self, tree: TreeNumber) {
        guard(&self.inner).forget_tree(tree);
        self.changed();
    }

    /// `accounted_memory_excluding` returns the accounted memory of every tree
    /// except `tree`.
    pub fn accounted_memory_excluding(&self, tree: TreeNumber) -> u64 {
        guard(&self.inner).accounted_memory_excluding(tree)
    }

    /// `memory_ceiling` returns [`HostConfig::accounted_memory_ceiling`].
    pub fn memory_ceiling(&self) -> u64 {
        guard(&self.inner).memory_ceiling()
    }

    /// `bytes_estimate` returns the moving mean of listing result bytes on
    /// `domain`.
    ///
    /// An unknown domain returns 0.
    pub fn bytes_estimate(&self, domain: Option<StorageDomainId>) -> u64 {
        guard(&self.inner).bytes_estimate(domain)
    }

    /// `record_bytes` adds a listing result size sample to `domain`.
    pub fn record_bytes(&self, domain: Option<StorageDomainId>, bytes: u64, now: MonotonicTime) {
        guard(&self.inner).record_bytes(domain, bytes, now)
    }

    /// `attribute` moves the reservation and charges of a grant to `domain`.
    ///
    /// Work on the bootstrap scope moves to its resolved domain (RFC §10.3).
    pub fn attribute(&self, id: GrantId, domain: StorageDomainId, now: MonotonicTime) {
        guard(&self.inner).attribute(id, domain, now)
    }

    /// `estimate_of` returns the estimated worker time per operation on
    /// `domain`.
    ///
    /// `None` and unregistered domains use the bootstrap estimate.
    pub fn estimate_of(&self, domain: Option<StorageDomainId>) -> Duration {
        guard(&self.inner).estimate_of(domain)
    }

    /// `cost_of` returns the estimated worker time of `operations` operations.
    pub fn cost_of(&self, domain: Option<StorageDomainId>, operations: u32) -> Duration {
        guard(&self.inner).cost_of(domain, operations)
    }

    /// `account` refills every bucket and charges running grants their
    /// occupancy.
    ///
    /// The charge of each running grant rises to its elapsed occupancy at `now`
    /// (RFC §15.2).
    pub fn account(&self, now: MonotonicTime) {
        guard(&self.inner).account(now)
    }

    /// `quarantined` reports whether a stuck grant quarantines `domain` (RFC
    /// §13.5).
    ///
    /// The bootstrap scope is never quarantined.
    pub fn quarantined(&self, domain: Option<StorageDomainId>) -> bool {
        guard(&self.inner).quarantined(domain)
    }

    /// `window_of` returns the concurrency window of `domain`.
    ///
    /// `None` returns [`HostConfig::maximum_in_flight`]. An unregistered domain
    /// returns 1.
    pub fn window_of(&self, domain: Option<StorageDomainId>) -> usize {
        guard(&self.inner).window_of(domain)
    }

    /// `global_exhausted` reports whether the global `origin` bucket cannot
    /// afford one operation.
    ///
    /// `global_exhausted` prices the operation at the estimate of `domain`.
    /// Open preparations count as spent.
    pub fn global_exhausted(&self, domain: Option<StorageDomainId>, origin: WorkOrigin) -> bool {
        guard(&self.inner).global_exhausted(domain, origin)
    }

    /// `may_start` checks the global in-flight limit and the window of
    /// `domain`.
    ///
    /// `may_start` uses local limits only.
    ///
    /// # Errors
    ///
    /// `may_start` returns [`ThrottleCause::Concurrency`] when either is full.
    pub fn may_start(&self, domain: Option<StorageDomainId>) -> Result<(), ThrottleCause> {
        guard(&self.inner).may_start(domain)
    }

    /// `in_flight` counts the unreleased started grants of this process.
    pub fn in_flight(&self) -> usize {
        guard(&self.inner).in_flight()
    }

    /// `try_admit` admits `reservation` and records a grant.
    ///
    /// The admission charge is irrevocable. `try_admit` derives the protocol
    /// work class from the reservation. A denial changes no grant and only
    /// records the denial (RFC §15.3).
    ///
    /// # Errors
    ///
    /// `try_admit` returns the denial cause. A live grant with the same id
    /// gives [`ThrottleCause::Concurrency`]. A quarantined domain gives
    /// [`ThrottleCause::StuckWorker`]. A memory ceiling gives
    /// [`ThrottleCause::Memory`]. An exhausted bucket or bootstrap allowance
    /// gives [`ThrottleCause::DutyBudget`] or
    /// [`ThrottleCause::ForegroundCeiling`]. A refusal of the shared authority
    /// gives a coordination cause. Watch releases skip the budget and memory
    /// checks.
    pub fn try_admit(&self, reservation: Reservation, now: MonotonicTime) -> Result<Admitted, ThrottleCause> {
        let work = reservation.work();
        self.try_admit_work(reservation, work, now)
    }

    /// `try_admit_work` admits `reservation` under an explicit protocol work
    /// class.
    ///
    /// `try_admit_work` behaves as [`HostGovernor::try_admit`] does. A
    /// process-only governor ignores `work`.
    ///
    /// # Errors
    ///
    /// `try_admit_work` returns the denial causes of
    /// [`HostGovernor::try_admit`].
    pub fn try_admit_work(
        &self,
        reservation: Reservation,
        _work: crate::coordination::protocol::Work,
        now: MonotonicTime,
    ) -> Result<Admitted, ThrottleCause> {
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
        if let Some(shared) = &self.shared {
            return shared.admit(self, reservation, _work, None, now);
        }
        guard(&self.inner).try_admit(reservation, now)
    }

    /// `try_prepare` prepares local budget without an irreversible admission
    /// charge.
    ///
    /// Other admissions observe this hold. `try_prepare` keeps no mutex and no
    /// physical worker. Dropping the returned guard aborts the preparation.
    ///
    /// # Errors
    ///
    /// `try_prepare` returns the denial causes of [`HostGovernor::try_admit`].
    /// It returns [`ThrottleCause::Concurrency`] while
    /// [`HostConfig::maximum_in_flight`] preparations are open.
    pub fn try_prepare(
        &self,
        reservation: Reservation,
        now: MonotonicTime,
    ) -> Result<PreparedAdmission, ThrottleCause> {
        let id = reservation.id;
        let admitted = guard(&self.inner).try_prepare(reservation, now)?;
        Ok(PreparedAdmission { governor: self.clone(), id, admitted, armed: true })
    }

    /// `report` records the cost of one completed step of grant `id`.
    ///
    /// The charge rises to the reported blocking time. Measured occupancy caps
    /// the rise, and the charge stays at least the reservation (RFC §15.2).
    pub fn report(&self, id: GrantId, reported: Reported, now: MonotonicTime) {
        guard(&self.inner).report(id, reported, now)
    }

    /// `overshoot_of` returns the charge of grant `id` beyond its reservation.
    pub fn overshoot_of(&self, id: GrantId) -> Duration {
        guard(&self.inner).overshoot_of(id)
    }

    pub(crate) fn prepared_cost_of(&self, id: GrantId) -> Duration {
        guard(&self.inner).prepared.get(&id).map(|held| held.admitted.cost).unwrap_or_default()
    }

    /// `charge_surcharge` charges [`HostConfig::failure_surcharge`] to the
    /// `origin` bucket of `domain`.
    pub fn charge_surcharge(&self, domain: Option<StorageDomainId>, origin: WorkOrigin, now: MonotonicTime) {
        guard(&self.inner).charge_surcharge(domain, origin, now)
    }

    /// `charged_by_tree` sums the charges of every grant of `tree`.
    pub fn charged_by_tree(&self, tree: TreeNumber) -> Duration {
        guard(&self.inner).charged_by_tree(tree)
    }

    /// `try_start` begins the physical occupancy of grant `id` at `at`.
    ///
    /// A shared authority must also authorize the start.
    ///
    /// # Errors
    ///
    /// `try_start` returns [`ThrottleCause::Concurrency`] for an unknown grant,
    /// a full window or a full in-flight limit. It returns a coordination cause
    /// when a shared authority refuses.
    pub fn try_start(&self, id: GrantId, at: MonotonicTime) -> Result<(), ThrottleCause> {
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
        if let Some(shared) = &self.shared {
            return shared.start(self, id, at);
        }
        guard(&self.inner).try_start(id, at)
    }

    /// `start` begins the physical occupancy of grant `id` without checks.
    ///
    /// `start` skips the concurrency checks. Under a shared authority `start`
    /// calls [`HostGovernor::try_start`] and discards the result.
    pub fn start(&self, id: GrantId, at: MonotonicTime) {
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
        if self.shared.is_some() {
            // Public unchecked entry points must never bypass shared
            // permission. Internal dispatchers use the checked API.
            let _ = self.try_start(id, at);
            return;
        }
        guard(&self.inner).start(id, at)
    }

    /// `dispatch` records when grant `id` began its filesystem work.
    ///
    /// Any watch registration precedes this point. Latency samples count from
    /// here.
    pub fn dispatch(&self, id: GrantId, at: MonotonicTime) {
        guard(&self.inner).dispatch(id, at)
    }

    /// `release` ends grant `id` and returns its slot.
    ///
    /// A started grant adds a latency sample per performed operation and adapts
    /// its domain window (RFC §15.5). `release` ignores an unknown grant.
    pub fn release(&self, id: GrantId, now: MonotonicTime) {
        self.release_was_stuck(id, now);
    }

    pub(crate) fn release_was_stuck(&self, id: GrantId, now: MonotonicTime) -> bool {
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
        if let Some(shared) = &self.shared {
            return shared.release(self, id, now);
        }
        let mut governor = guard(&self.inner);
        let stuck = governor.grants.get(&id).is_some_and(|grant| grant.stuck);
        governor.release(id, now);
        drop(governor);
        self.changed();
        stuck
    }

    /// `record_outcome` adds a success or error sample to the history of
    /// `domain`.
    ///
    /// An error shrinks the domain window.
    pub fn record_outcome(&self, domain: Option<StorageDomainId>, error: bool, now: MonotonicTime) {
        guard(&self.inner).record_outcome(domain, error, now)
    }

    /// `account_and_quarantine` supervises live calls cooperatively, also after
    /// their original waiter left.
    pub(crate) fn account_and_quarantine(&self, now: MonotonicTime) {
        let mut governor = guard(&self.inner);
        governor.account(now);
        let newly_stuck = governor.newly_stuck(now);
        let changed = !newly_stuck.is_empty();
        for id in newly_stuck {
            governor.mark_stuck(id, now);
        }
        drop(governor);
        if changed {
            self.changed();
        }
    }

    pub(crate) fn record_grant_failure(&self, id: GrantId, now: MonotonicTime) {
        guard(&self.inner).record_grant_failure(id, now);
    }

    /// `note_grant_failure` preserves the physical outcome of a failed grant.
    ///
    /// The logical completion path of the tree accounts its local surcharge.
    pub(crate) fn note_grant_failure(&self, id: GrantId) {
        let mut governor = guard(&self.inner);
        if let Some(grant) = governor.grants.get_mut(&id)
            && grant.started.is_some()
        {
            grant.failed = true;
        }
    }

    pub(crate) fn grant_is_stuck(&self, id: GrantId) -> bool {
        guard(&self.inner).grants.get(&id).is_some_and(|grant| grant.stuck)
    }

    pub(crate) fn has_shared_authority(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
        {
            self.shared.is_some()
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "illumos",
            target_os = "macos",
            windows
        )))]
        {
            false
        }
    }

    /// `newly_stuck` returns the running grants that just crossed the stuck
    /// threshold.
    ///
    /// [`HostConfig::stuck_threshold`] sets the threshold. `newly_stuck`
    /// excludes grants with an earlier stuck mark.
    pub fn newly_stuck(&self, now: MonotonicTime) -> Vec<GrantId> {
        guard(&self.inner).newly_stuck(now)
    }

    /// `mark_stuck` declares grant `id` stuck.
    ///
    /// `mark_stuck` quarantines the domain until the grant returns. It refunds
    /// the global overshoot, halves the window and charges the failure
    /// surcharge once (RFC §13.5, §15.3).
    pub fn mark_stuck(&self, id: GrantId, now: MonotonicTime) {
        guard(&self.inner).mark_stuck(id, now)
    }

    /// `domain_of_grant` returns the charged domain of grant `id`.
    pub fn domain_of_grant(&self, id: GrantId) -> Option<StorageDomainId> {
        guard(&self.inner).domain_of_grant(id)
    }

    /// `stuck_grants` returns every grant with a stuck mark.
    pub fn stuck_grants(&self) -> Vec<Grant> {
        guard(&self.inner).stuck_grants().cloned().collect()
    }

    /// `next_stuck_deadline` returns the next time a running grant becomes
    /// stuck.
    pub fn next_stuck_deadline(&self) -> Option<MonotonicTime> {
        guard(&self.inner).next_stuck_deadline()
    }

    /// `admissible_at` returns when `domain` can afford one background
    /// operation.
    ///
    /// `None` means the domain can afford it now or no refill time is
    /// computable. Quarantine has no computable refill time (RFC §12).
    pub fn admissible_at(&self, domain: Option<StorageDomainId>, now: MonotonicTime) -> Option<MonotonicTime> {
        guard(&self.inner).admissible_at(domain, now)
    }

    /// `throttle` returns the host-wide throttle cause and its resume time.
    ///
    /// The resume time is `None` when it is not computable. Coordination
    /// failure and shared retry rank first. Memory ranks second. Exhausted
    /// budgets with an outstanding denial rank third, and stuck workers rank
    /// last. `None` means admission is nominal.
    pub fn throttle(&self, now: MonotonicTime) -> Option<(ThrottleCause, Option<MonotonicTime>)> {
        if self.coordination_error().is_some() {
            return Some((ThrottleCause::CoordinationFailed, None));
        }
        if let Some(at) = self.coordination_retry_at(now) {
            return Some((ThrottleCause::Coordination, Some(at)));
        }
        guard(&self.inner).throttle(now)
    }

    /// `resume_at` returns the earliest time throttled admission may resume.
    ///
    /// `resume_at` returns `None` when no time is computable.
    pub fn resume_at(&self, now: MonotonicTime) -> Option<MonotonicTime> {
        let local = guard(&self.inner).resume_at(now);
        match (local, self.coordination_retry_at(now)) {
            (Some(local), Some(shared)) => Some(local.min(shared)),
            (local, shared) => local.or(shared),
        }
    }

    /// `coordination_error` returns the failure that stopped the shared
    /// authority.
    ///
    /// A process-only governor returns `None`. After a failure no new work
    /// starts.
    pub fn coordination_error(&self) -> Option<String> {
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
        if let Some(shared) = &self.shared {
            return shared.failure();
        }
        None
    }

    /// `coordination_retry_at` returns the next retry time for a refused shared
    /// admission.
    ///
    /// A process-only governor returns `None`.
    pub fn coordination_retry_at(&self, _now: MonotonicTime) -> Option<MonotonicTime> {
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
        if let Some(shared) = &self.shared {
            return shared.retry_at(self, _now);
        }
        None
    }

    fn coordination_quarantined(&self) -> BTreeSet<StorageDomainId> {
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
        if let Some(shared) = &self.shared {
            return shared.quarantined();
        }
        BTreeSet::new()
    }

    /// `timer_hints` returns three timer hints in one call.
    ///
    /// The hints are the resume time, the background resume time and the next
    /// stuck deadline.
    pub fn timer_hints(
        &self,
        now: MonotonicTime,
    ) -> (Option<MonotonicTime>, Option<MonotonicTime>, Option<MonotonicTime>) {
        let governor = guard(&self.inner);
        (governor.resume_at(now), governor.background_resume_at(now), governor.next_stuck_deadline())
    }

    /// `domain_health_map` sets each domain entry of `into` to its resource
    /// health.
    ///
    /// `queued` names the domains with waiting work. A full window reports
    /// [`ThrottleCause::Concurrency`] only for those domains (RFC §15.6).
    pub fn domain_health_map(
        &self,
        now: MonotonicTime,
        queued: &std::collections::BTreeSet<StorageDomainId>,
        into: &mut BTreeMap<StorageDomainId, crate::update::ResourceHealth>,
    ) {
        let shared = self.coordination_quarantined();
        let governor = guard(&self.inner);
        for (id, slot) in into.iter_mut() {
            let health = match shared.contains(id) {
                true => Some((ThrottleCause::StuckWorker, None)),
                false => governor.domain_health(*id, now, queued.contains(id)),
            };
            *slot = match health {
                Some((cause, resume)) => crate::update::ResourceHealth::Throttled { cause, resume },
                None => crate::update::ResourceHealth::Nominal,
            };
        }
    }

    /// `grants` returns every live grant.
    pub fn grants(&self) -> Vec<Grant> {
        guard(&self.inner).grants().cloned().collect()
    }

    /// `new_grants_into` appends every unseen live grant to `into`.
    ///
    /// The `seen` callback receives the id and lease of each grant. It returns
    /// `true` for a known grant.
    pub fn new_grants_into(&self, into: &mut Vec<Grant>, seen: &dyn Fn(GrantId, u32) -> bool) {
        into.extend(guard(&self.inner).grants().filter(|grant| !seen(grant.id, grant.lease)).cloned());
    }

    /// `view` returns the governor state at `now`.
    pub fn view(&self, now: MonotonicTime) -> GovernorView {
        guard(&self.inner).view(now)
    }
}

#[cfg(test)]
mod scan_memory_tests {
    use super::*;

    #[test]
    fn returned_buffers_leave_real_capacity_available_before_reservation_cleanup() {
        let governor = HostGovernor::independent(&HostConfig {
            accounted_memory_ceiling: 1000,
            in_flight_listing_bytes: 1000,
            ..Default::default()
        });
        let scan = governor.next_tree();
        let reservation = governor.next_tree();
        let other = governor.next_tree();
        let other_reservation = governor.next_tree();
        governor.try_reserve_scan_memory(scan, reservation, 800).unwrap();
        governor.try_return_scan_memory(reservation, scan, 400).unwrap();
        // The returned resource owner is still alive. Another scan must be
        // able to reserve all genuinely free capacity before it is dropped.
        governor.try_reserve_scan_memory(other, other_reservation, 600).unwrap();
        assert_eq!(governor.view(MonotonicTime(Duration::ZERO)).accounted_memory, 1000);
        governor.forget_tree(reservation);
        assert_eq!(governor.view(MonotonicTime(Duration::ZERO)).accounted_memory, 1000);
        // Reject an adapter's oversized result without losing either charge.
        assert!(governor.try_return_scan_memory(other_reservation, other, 601).is_err());
        assert_eq!(governor.view(MonotonicTime(Duration::ZERO)).accounted_memory, 1000);
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;

    #[test]
    fn a_physical_failure_is_recorded_once_until_its_lease_is_released() {
        let config = HostConfig { foreground_duty: 1.0, domain_foreground_duty: 1.0, ..Default::default() };
        let mut governor = Governor::new(&config, MonotonicTime::ZERO);
        let domain = StorageDomainId::of(&crate::domain::DomainKey::declared(9876));
        let id = GrantId::Bootstrap(1);
        let now = MonotonicTime::ZERO;
        for lease in 0..2 {
            governor
                .try_admit(
                    Reservation {
                        id,
                        path: RelativePath::root(),
                        reads: 1,
                        registrations: 0,
                        operations: 0,
                        ceiling: None,
                        lease,
                        domain: Some(domain),
                        origin: WorkOrigin::Foreground,
                        listing: false,
                    },
                    now,
                )
                .unwrap();
            governor.record_grant_failure(id, now);
            assert!(governor.failed_grants.is_empty(), "unstarted reservations cannot fail physically");
            governor.start(id, now);
            governor.mark_stuck(id, now);
            governor.mark_stuck(id, now);
            governor.record_grant_failure(id, now); // e.g. a late panic
            assert_eq!(governor.view(now).surcharged, config.failure_surcharge * (lease + 1));
            assert_eq!(governor.domains[&domain].errors.len(), (lease + 1) as usize);
            assert!(governor.domains[&domain].errors.iter().all(|error| *error));
            governor.release(id, now);
            assert!(governor.failed_grants.is_empty());
        }
    }
}
