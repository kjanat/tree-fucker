use std::time::Duration;

use crate::domain::DomainCrossing;
use crate::entry::MetadataFields;

const NANOS_PER_SECOND: u128 = 1_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchRegistrationFailure {
    ReconcileOnly,
    RequireWatcher,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LagMode {
    Reset,
    Disconnect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassWeights {
    pub control: u32,
    pub refresh: u32,
    pub watcher: u32,
    pub retry: u32,
    pub priority: u32,
}

impl Default for ClassWeights {
    fn default() -> Self {
        ClassWeights { control: 4, refresh: 4, watcher: 2, retry: 1, priority: 2 }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub batch_size: usize,
    pub max_in_flight: usize,
    pub command_capacity: usize,
    pub paths_per_command: usize,
    pub priority_set_limit: usize,
    pub update_stream_capacity: usize,
    pub watcher_path_limit: usize,
    pub entries_per_directory: usize,
    pub entries_per_lease: usize,
    pub operations_per_lease: usize,
    pub represented_entries: usize,
    pub transient_degrade_threshold: u32,
    pub retry_maximum_delay: Duration,
    pub watch_registration_failure: WatchRegistrationFailure,
    pub root_reappearance_monitoring: bool,
    pub background_duty: f64,
    pub background_burst: Duration,
    pub domain_background_duty: f64,
    pub domain_background_burst: Duration,
    pub foreground_duty: f64,
    pub foreground_burst: Duration,
    pub domain_foreground_duty: f64,
    pub domain_foreground_burst: Duration,
    pub foreground_ceiling_per_command: Duration,
    pub bootstrap_allowance: Duration,
    pub accounted_memory_ceiling: u64,
    pub in_flight_listing_bytes: u64,
    pub snapshot_bytes: u64,
    pub per_domain_concurrency: usize,
    pub failure_surcharge: Duration,
    pub initial_cost_estimate: Duration,
    pub stuck_threshold: Duration,
    pub minimum_period: Duration,
    pub maximum_period: Duration,
    pub fixed_interval: Option<Duration>,
    pub baseline_share: f64,
    pub class_weights: ClassWeights,
    pub metadata_fields: MetadataFields,
    pub domain_crossing: DomainCrossing,
    pub lag_mode: LagMode,
    pub jitter_seed: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            batch_size: 64,
            max_in_flight: 8,
            command_capacity: 1024,
            paths_per_command: 65536,
            priority_set_limit: 65536,
            update_stream_capacity: 256,
            watcher_path_limit: 16384,
            entries_per_directory: 1_000_000,
            entries_per_lease: 4096,
            operations_per_lease: 256,
            represented_entries: 10_000_000,
            transient_degrade_threshold: 3,
            retry_maximum_delay: Duration::from_secs(300),
            watch_registration_failure: WatchRegistrationFailure::ReconcileOnly,
            root_reappearance_monitoring: true,
            background_duty: 0.02,
            background_burst: Duration::from_millis(500),
            domain_background_duty: 0.02,
            domain_background_burst: Duration::from_millis(500),
            foreground_duty: 0.25,
            foreground_burst: Duration::from_secs(2),
            domain_foreground_duty: 0.25,
            domain_foreground_burst: Duration::from_secs(2),
            foreground_ceiling_per_command: Duration::from_secs(30),
            bootstrap_allowance: Duration::from_millis(500),
            accounted_memory_ceiling: 512 * 1024 * 1024,
            in_flight_listing_bytes: 32 * 1024 * 1024,
            snapshot_bytes: 256 * 1024 * 1024,
            per_domain_concurrency: 4,
            failure_surcharge: Duration::from_millis(20),
            initial_cost_estimate: Duration::from_millis(20),
            stuck_threshold: Duration::from_secs(30),
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
    pub fn validate(&self) -> Result<(), String> {
        if self.batch_size < 2 {
            return Err("batch_size must be at least 2".into());
        }
        if self.max_in_flight == 0 {
            return Err("max_in_flight must be greater than zero".into());
        }
        if !self.background_duty.is_finite() || self.background_duty <= 0.0 {
            return Err("background_duty must be finite, greater than zero and at most max_in_flight".into());
        }
        let duty = Duration::try_from_secs_f64(self.background_duty).unwrap_or(Duration::MAX);
        if duty > Duration::from_secs(u64::try_from(self.max_in_flight).unwrap_or(u64::MAX)) {
            return Err("background_duty must be finite, greater than zero and at most max_in_flight".into());
        }
        if self.background_burst.is_zero() {
            return Err("background_burst must be greater than zero".into());
        }
        if !self.domain_background_duty.is_finite() || self.domain_background_duty <= 0.0 {
            return Err("domain_background_duty must be finite, greater than zero and at most max_in_flight".into());
        }
        let domain_duty = Duration::try_from_secs_f64(self.domain_background_duty).unwrap_or(Duration::MAX);
        if domain_duty > Duration::from_secs(u64::try_from(self.max_in_flight).unwrap_or(u64::MAX)) {
            return Err("domain_background_duty must be finite, greater than zero and at most max_in_flight".into());
        }
        if self.domain_background_burst.is_zero() {
            return Err("domain_background_burst must be greater than zero".into());
        }
        if !self.foreground_duty.is_finite() || self.foreground_duty <= 0.0 {
            return Err("foreground_duty must be finite, greater than zero and at most max_in_flight".into());
        }
        let foreground_duty = Duration::try_from_secs_f64(self.foreground_duty).unwrap_or(Duration::MAX);
        if foreground_duty > Duration::from_secs(u64::try_from(self.max_in_flight).unwrap_or(u64::MAX)) {
            return Err("foreground_duty must be finite, greater than zero and at most max_in_flight".into());
        }
        if self.foreground_burst.is_zero() {
            return Err("foreground_burst must be greater than zero".into());
        }
        if !self.domain_foreground_duty.is_finite() || self.domain_foreground_duty <= 0.0 {
            return Err("domain_foreground_duty must be finite, greater than zero and at most max_in_flight".into());
        }
        let domain_foreground_duty = Duration::try_from_secs_f64(self.domain_foreground_duty).unwrap_or(Duration::MAX);
        if domain_foreground_duty > Duration::from_secs(u64::try_from(self.max_in_flight).unwrap_or(u64::MAX)) {
            return Err("domain_foreground_duty must be finite, greater than zero and at most max_in_flight".into());
        }
        if self.domain_foreground_burst.is_zero() {
            return Err("domain_foreground_burst must be greater than zero".into());
        }
        if self.foreground_ceiling_per_command.is_zero() {
            return Err("foreground_ceiling_per_command must be greater than zero".into());
        }
        if self.bootstrap_allowance.is_zero() {
            return Err("bootstrap_allowance must be greater than zero".into());
        }
        if self.accounted_memory_ceiling == 0 {
            return Err("accounted_memory_ceiling must be greater than zero".into());
        }
        if self.in_flight_listing_bytes == 0 {
            return Err("in_flight_listing_bytes must be greater than zero".into());
        }
        if self.snapshot_bytes == 0 {
            return Err("snapshot_bytes must be greater than zero".into());
        }
        if self.per_domain_concurrency < 1 || self.per_domain_concurrency > self.max_in_flight {
            return Err("per_domain_concurrency must be at least 1 and at most max_in_flight".into());
        }
        if self.initial_cost_estimate.is_zero() {
            return Err("initial_cost_estimate must be greater than zero".into());
        }
        if self.stuck_threshold.is_zero() {
            return Err("stuck_threshold must be greater than zero".into());
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

    pub fn baseline_reservation(&self) -> usize {
        let share = Duration::try_from_secs_f64(self.baseline_share).unwrap_or(Duration::ZERO).as_nanos();
        let batch = u128::try_from(self.batch_size).unwrap_or(u128::MAX);
        let raw = usize::try_from(batch.saturating_mul(share) / NANOS_PER_SECOND).unwrap_or(usize::MAX);
        raw.clamp(1, self.batch_size - 1)
    }
}
