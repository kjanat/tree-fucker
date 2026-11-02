//! `config` defines the tree and host configuration and validates it.
//!
//! [`HostConfig`] holds the physical ceilings and global budgets of the host
//! governor. One host governor serves the whole process. [`Config`] holds the
//! representation limits and behaviour of one [`Tree`](crate::Tree). RFC §9.2
//! lists every default.

use std::time::Duration;

use crate::domain::DomainCrossing;
use crate::entry::MetadataFields;

const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// `WatchRegistrationFailure` decides the response to a failed watch
/// registration.
///
/// The registration precedes the directory listing. RFC §11.1 specifies both
/// modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchRegistrationFailure {
    /// The tree publishes degraded watcher health and lists the directory
    /// without a watch.
    ReconcileOnly,
    /// The tree withholds the listing until registration succeeds.
    ///
    /// A failure before open makes [`Tree::open`](crate::Tree::open) fail.
    RequireWatcher,
}

/// `LagMode` decides what a full [`UpdateStream`](crate::UpdateStream) does
/// with a new event.
///
/// RFC §9 requires one of these two responses to a lagging consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LagMode {
    /// The stream replaces its queued events with one
    /// [`UpdateEvent::Reset`](crate::update::UpdateEvent::Reset).
    ///
    /// The reset carries the latest snapshot, health and undelivered errors.
    Reset,
    /// The stream drops its queued events, yields
    /// [`StreamError::Lagged`](crate::update::StreamError::Lagged) and closes.
    Disconnect,
}

/// `ClassWeights` divides expedited admission slots among the scheduling
/// classes.
///
/// Every weight must be greater than zero. The defaults are 4, 4, 2, 1 and 2 in
/// field order (RFC §11.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassWeights {
    /// `control` weights initial scan, load, policy invalidation and root
    /// recovery work.
    pub control: u32,
    /// `refresh` weights reads for an explicit `refresh`.
    pub refresh: u32,
    /// `watcher` weights reads for watcher hints.
    pub watcher: u32,
    /// `retry` weights retries of failed reads.
    pub retry: u32,
    /// `priority` weights listings of priority-set directories.
    pub priority: u32,
}

impl Default for ClassWeights {
    fn default() -> Self {
        ClassWeights { control: 4, refresh: 4, watcher: 2, retry: 1, priority: 2 }
    }
}

/// `HostConfig` sets the physical ceilings and budgets of one
/// [`HostGovernor`](crate::HostGovernor).
///
/// One host configuration governs every tree and scan on the governor. A tree
/// may only tighten these limits (RFC §9.2, §15.9). Duty rates are
/// worker-seconds per wall-second. Bursts are worker time (RFC §15.2).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HostConfig {
    /// The governor runs at most this many physical filesystem workers at once.
    ///
    /// The default is 8.
    pub maximum_in_flight: usize,
    /// `per_domain_concurrency` caps the concurrency window of each storage
    /// domain.
    ///
    /// The default is 4. `per_domain_concurrency` must be at least 1 and at
    /// most `maximum_in_flight` (RFC §15.5).
    pub per_domain_concurrency: usize,
    /// `domain_background_duty` refills the background bucket of each storage
    /// domain.
    ///
    /// The default is 0.01.
    pub domain_background_duty: f64,
    /// `background_duty` refills the global background bucket.
    ///
    /// The default is 0.02.
    pub background_duty: f64,
    /// `domain_background_burst` sets the capacity of each domain's background
    /// bucket.
    ///
    /// The default is 250 ms.
    pub domain_background_burst: Duration,
    /// `background_burst` sets the capacity of the global background bucket.
    ///
    /// The default is 500 ms.
    pub background_burst: Duration,
    /// `foreground_duty` refills the global foreground bucket.
    ///
    /// The default is 0.25.
    pub foreground_duty: f64,
    /// `foreground_burst` sets the capacity of the global foreground bucket.
    ///
    /// The default is 2 s.
    pub foreground_burst: Duration,
    /// `domain_foreground_duty` refills the foreground bucket of each storage
    /// domain.
    ///
    /// The default is 0.25.
    pub domain_foreground_duty: f64,
    /// `domain_foreground_burst` sets the capacity of each domain's foreground
    /// bucket.
    ///
    /// The default is 2 s.
    pub domain_foreground_burst: Duration,
    /// Bootstrap work may hold at most this much worker time in reserve.
    ///
    /// Bootstrap work runs before its storage domain is known. Root
    /// canonicalization, root probes and domain resolution are bootstrap work
    /// (RFC §10.3). The default is 500 ms.
    pub bootstrap_allowance: Duration,
    /// All trees together may account at most this many bytes of memory.
    ///
    /// Snapshot bytes and in-flight listing bytes count toward the total. The
    /// default is 512 MiB.
    pub accounted_memory_ceiling: u64,
    /// Open listing sessions of all trees may hold at most this many result
    /// bytes.
    ///
    /// The default is 32 MiB.
    pub in_flight_listing_bytes: u64,
    /// The governor assumes this worker time per operation before it measures
    /// any.
    ///
    /// The default is 20 ms.
    pub initial_cost_estimate: Duration,
    /// The governor declares a running worker stuck after this occupancy.
    ///
    /// The default is 30 s. A stuck worker quarantines its storage domain (RFC
    /// §13.5).
    pub stuck_threshold: Duration,
    /// The governor charges this extra worker time for each failed or stuck
    /// grant.
    ///
    /// The surcharge goes to the grant's storage domain. The default is 20 ms,
    /// and zero disables the surcharge (RFC §13.1).
    pub failure_surcharge: Duration,
}

impl Default for HostConfig {
    fn default() -> Self {
        HostConfig {
            maximum_in_flight: 8,
            per_domain_concurrency: 4,
            domain_background_duty: 0.01,
            background_duty: 0.02,
            domain_background_burst: Duration::from_millis(250),
            background_burst: Duration::from_millis(500),
            foreground_duty: 0.25,
            foreground_burst: Duration::from_secs(2),
            domain_foreground_duty: 0.25,
            domain_foreground_burst: Duration::from_secs(2),
            bootstrap_allowance: Duration::from_millis(500),
            accounted_memory_ceiling: 512 * 1024 * 1024,
            in_flight_listing_bytes: 32 * 1024 * 1024,
            initial_cost_estimate: Duration::from_millis(20),
            stuck_threshold: Duration::from_secs(30),
            failure_surcharge: Duration::from_millis(20),
        }
    }
}

impl HostConfig {
    /// `validate` checks the host rules of RFC §9.2.
    ///
    /// # Errors
    ///
    /// The error message names the first violated rule. The rules reject a zero
    /// `maximum_in_flight` and a `per_domain_concurrency` outside
    /// `1..=maximum_in_flight`. They reject a duty rate that is non-finite, not
    /// positive or above `maximum_in_flight`. They also reject a zero burst,
    /// allowance, estimate, threshold or byte ceiling.
    pub fn validate(&self) -> Result<(), String> {
        if self.maximum_in_flight == 0 {
            return Err("maximum_in_flight must be greater than zero".into());
        }
        if self.per_domain_concurrency < 1 || self.per_domain_concurrency > self.maximum_in_flight {
            return Err("per_domain_concurrency must be at least 1 and at most maximum_in_flight".into());
        }
        let duties = [
            ("background_duty", self.background_duty),
            ("domain_background_duty", self.domain_background_duty),
            ("foreground_duty", self.foreground_duty),
            ("domain_foreground_duty", self.domain_foreground_duty),
        ];
        let workers = Duration::from_secs(u64::try_from(self.maximum_in_flight).unwrap_or(u64::MAX));
        for (name, rate) in duties {
            if !rate.is_finite() || rate <= 0.0 {
                return Err(format!("{name} must be finite, greater than zero and at most maximum_in_flight"));
            }
            if Duration::try_from_secs_f64(rate).unwrap_or(Duration::MAX) > workers {
                return Err(format!("{name} must be finite, greater than zero and at most maximum_in_flight"));
            }
        }
        let bursts = [
            ("background_burst", self.background_burst),
            ("domain_background_burst", self.domain_background_burst),
            ("foreground_burst", self.foreground_burst),
            ("domain_foreground_burst", self.domain_foreground_burst),
            ("bootstrap_allowance", self.bootstrap_allowance),
            ("initial_cost_estimate", self.initial_cost_estimate),
            ("stuck_threshold", self.stuck_threshold),
        ];
        for (name, value) in bursts {
            if value.is_zero() {
                return Err(format!("{name} must be greater than zero"));
            }
        }
        if self.accounted_memory_ceiling == 0 {
            return Err("accounted_memory_ceiling must be greater than zero".into());
        }
        if self.in_flight_listing_bytes == 0 {
            return Err("in_flight_listing_bytes must be greater than zero".into());
        }
        Ok(())
    }
}

/// `Config` sets the representation limits and behaviour of one
/// [`Tree`](crate::Tree).
///
/// [`Tree::open`](crate::Tree::open) rejects a configuration that fails
/// [`Config::validate`]. A tree limit may only tighten the host limit (RFC
/// §9.2).
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// Each dispatch cycle admits at most this many snapshot-producing jobs.
    ///
    /// The default is 64, and `batch_size` must be at least 2 (RFC §11.3).
    pub batch_size: usize,
    /// The tree holds at most this many accepted unfinished commands.
    ///
    /// Waiters of `initial_scan_complete` count as commands. The default is
    /// 1024. A command beyond this capacity fails with
    /// [`Error::Capacity`](crate::Error::Capacity) before acceptance.
    pub command_capacity: usize,
    /// One command may name at most this many paths.
    ///
    /// The default is 65536. A larger command fails with
    /// [`Error::PathLimit`](crate::Error::PathLimit) before acceptance.
    pub paths_per_command: usize,
    /// The priority set may hold at most this many paths.
    ///
    /// The default is 4096. A larger `set_priority` call fails, and the tree
    /// keeps the existing set.
    pub priority_set_limit: usize,
    /// The update stream holds at most this many undelivered events.
    ///
    /// The default is 256. [`Config::lag_mode`] decides what a full stream
    /// does.
    pub update_stream_capacity: usize,
    /// `watcher_path_limit` caps both the pending watcher paths and the watched
    /// paths of the tree.
    ///
    /// The default is 16384. The tree drops and counts hints beyond the limit,
    /// and it schedules coverage repair (RFC §11.6). Directories beyond the
    /// watch limit stay unwatched.
    /// [`Stats::paths_unwatched_by_cap`](crate::Stats::paths_unwatched_by_cap)
    /// counts them.
    pub watcher_path_limit: usize,
    /// One listing may enumerate at most this many children.
    ///
    /// The default is 250000, and `entries_per_directory` must be at least 1. A
    /// larger directory ends its listing as ResourceLimited, and the tree keeps
    /// the previous snapshot (RFC §13.1).
    pub entries_per_directory: usize,
    /// One work lease lets a listing session enumerate this many entries.
    ///
    /// The default is 4096, and `entries_per_lease` must be at least 1 (RFC
    /// §10.2).
    pub entries_per_lease: usize,
    /// One work lease permits at most this many per-child operations.
    ///
    /// The default is 256, and `operations_per_lease` must be at least 1 (RFC
    /// §15.3).
    pub operations_per_lease: usize,
    /// The snapshot may represent at most this many entries.
    ///
    /// The default is 1000000. The tree rejects a larger commit as
    /// ResourceLimited.
    pub represented_entries: usize,
    /// The snapshot may hold at most this many bytes.
    ///
    /// The default is 256 MiB, and `snapshot_bytes` must be greater than zero.
    /// The snapshot also counts toward
    /// [`HostConfig::accounted_memory_ceiling`], and the tighter limit binds.
    pub snapshot_bytes: u64,
    /// The governor admits at most this much worker time for one `refresh` or
    /// `load`.
    ///
    /// The default is 30 s, and `foreground_ceiling_per_command` must be
    /// greater than zero. A command fails with ResourceLimited when it reaches
    /// the ceiling with a required read outstanding (RFC §15.4).
    pub foreground_ceiling_per_command: Duration,
    /// A path becomes degraded after this many consecutive transient failures.
    ///
    /// The default is 3.
    pub transient_degrade_threshold: u32,
    /// Retry and root-probe backoff grows to at most this delay.
    ///
    /// The default is 5 minutes, and `retry_maximum_delay` must be at least
    /// `minimum_period`.
    pub retry_maximum_delay: Duration,
    /// `watch_registration_failure_mode` decides the response to a failed watch
    /// registration.
    ///
    /// The default is [`WatchRegistrationFailure::ReconcileOnly`].
    pub watch_registration_failure_mode: WatchRegistrationFailure,
    /// The tree probes a vanished root with backoff until the root reappears.
    ///
    /// The default is `true`. When `root_reappearance_monitoring` is `false`,
    /// only `refresh` of the root starts a probe (RFC §13.2).
    pub root_reappearance_monitoring: bool,
    /// Periodic baseline cycles start at least this far apart.
    ///
    /// The default is 1 s. `minimum_period` must be greater than zero and at
    /// most `maximum_period`. Retry backoff also starts at this delay.
    pub minimum_period: Duration,
    /// Periodic baseline cycles start at most this far apart while capacity
    /// exists.
    ///
    /// The default is 5 minutes (RFC §12).
    pub maximum_period: Duration,
    /// When `fixed_interval` is set, periodic baseline cycles start this far
    /// apart.
    ///
    /// The default is `None`. A set `fixed_interval` must be greater than zero.
    /// The governor's next admissible time can still delay a fixed cycle.
    pub fixed_interval: Option<Duration>,
    /// Baseline work receives this share of each dispatch cycle.
    ///
    /// The default is 0.5. `baseline_share` must be finite, at least 0 and
    /// below 1. [`Config::baseline_reservation`] derives the slot count.
    pub baseline_share: f64,
    /// `class_weights` divides expedited slots among the scheduling classes.
    pub class_weights: ClassWeights,
    /// Enrichment keeps these metadata fields current.
    ///
    /// The default is no fields (RFC §10.1).
    pub metadata_fields: MetadataFields,
    /// `domain_crossing` applies when traversal reaches another storage domain.
    ///
    /// The default is [`DomainCrossing::LoadOnDemand`]. Scan policy may
    /// override the decision per crossing (RFC §14.3).
    pub domain_crossing: DomainCrossing,
    /// `lag_mode` decides what a full update stream does.
    ///
    /// The default is [`LagMode::Reset`].
    pub lag_mode: LagMode,
    /// `jitter_seed` seeds the retry jitter generator.
    ///
    /// The default is 0. Equal seeds give equal jitter sequences under a
    /// deterministic clock.
    pub jitter_seed: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            batch_size: 64,
            command_capacity: 1024,
            paths_per_command: 65536,
            priority_set_limit: 4096,
            update_stream_capacity: 256,
            watcher_path_limit: 16384,
            entries_per_directory: 250_000,
            entries_per_lease: 4096,
            operations_per_lease: 256,
            represented_entries: 1_000_000,
            snapshot_bytes: 256 * 1024 * 1024,
            foreground_ceiling_per_command: Duration::from_secs(30),
            transient_degrade_threshold: 3,
            retry_maximum_delay: Duration::from_secs(300),
            watch_registration_failure_mode: WatchRegistrationFailure::ReconcileOnly,
            root_reappearance_monitoring: true,
            minimum_period: Duration::from_secs(1),
            maximum_period: Duration::from_secs(300),
            fixed_interval: None,
            baseline_share: 0.5,
            class_weights: ClassWeights::default(),
            metadata_fields: MetadataFields::NONE,
            domain_crossing: DomainCrossing::LoadOnDemand,
            lag_mode: LagMode::Reset,
            jitter_seed: 0,
        }
    }
}

impl Config {
    /// `validate` checks the tree rules of RFC §9.2.
    ///
    /// # Errors
    ///
    /// The error message names the first violated rule. Each field doc on
    /// [`Config`] states its bound.
    pub fn validate(&self) -> Result<(), String> {
        if self.batch_size < 2 {
            return Err("batch_size must be at least 2".into());
        }
        if self.snapshot_bytes == 0 {
            return Err("snapshot_bytes must be greater than zero".into());
        }
        if self.foreground_ceiling_per_command.is_zero() {
            return Err("foreground_ceiling_per_command must be greater than zero".into());
        }
        if self.entries_per_directory == 0 {
            return Err("entries_per_directory must be at least 1".into());
        }
        if self.entries_per_lease == 0 {
            return Err("entries_per_lease must be at least 1".into());
        }
        if self.operations_per_lease == 0 {
            return Err("operations_per_lease must be at least 1".into());
        }
        if self.minimum_period.is_zero() || self.minimum_period > self.maximum_period {
            return Err("minimum_period must be greater than zero and at most maximum_period".into());
        }
        if self.retry_maximum_delay < self.minimum_period {
            return Err("retry_maximum_delay must be at least minimum_period".into());
        }
        if let Some(interval) = self.fixed_interval
            && interval.is_zero()
        {
            return Err("fixed_interval must be greater than zero".into());
        }
        let w = self.class_weights;
        if w.control == 0 || w.refresh == 0 || w.watcher == 0 || w.retry == 0 || w.priority == 0 {
            return Err("every expedited class weight must be greater than zero".into());
        }
        if !self.baseline_share.is_finite() || self.baseline_share < 0.0 || self.baseline_share >= 1.0 {
            return Err("baseline_share must be finite, at least zero and less than 1".into());
        }
        if self.update_stream_capacity == 0 {
            return Err("update_stream_capacity must be greater than zero".into());
        }
        if self.command_capacity == 0 {
            return Err("command_capacity must be greater than zero".into());
        }
        Ok(())
    }

    /// `baseline_reservation` returns the admission slots for baseline work.
    ///
    /// The reservation applies when expedited work is also ready.
    /// `baseline_reservation` returns `clamp(floor(batch_size *
    /// baseline_share), 1, batch_size - 1)` (RFC §11.3).
    ///
    /// # Panics
    ///
    /// `baseline_reservation` panics when `batch_size` is below 2. Callers must
    /// run [`Config::validate`] first.
    pub fn baseline_reservation(&self) -> usize {
        let share = Duration::try_from_secs_f64(self.baseline_share).unwrap_or(Duration::ZERO).as_nanos();
        let batch = u128::try_from(self.batch_size).unwrap_or(u128::MAX);
        let raw = usize::try_from(batch.saturating_mul(share) / NANOS_PER_SECOND).unwrap_or(usize::MAX);
        raw.clamp(1, self.batch_size - 1)
    }
}
