//! This module implements the shared admission policy independently of any
//! transport or storage mapping.
//!
//! One authority owns the buckets for its entire lifetime, including periods
//! with no participants. A backend must persist the whole transaction,
//! including the buckets and the ownership ledger, before it publishes an
//! admission decision.

use super::clock_binding::ClockBinding;
use super::protocol::{self, Generation, Ledger, Limits, OperationId, Participant, Phase, Progress, Work};
use crate::HostConfig;

mod codec;

const SECOND: u128 = 1_000_000_000;
/// `MAX_DOMAINS` is the largest domain-table length an authority accepts.
pub const MAX_DOMAINS: u32 = 4096;

/// `Origin` selects the foreground or background buckets for a request.
///
/// RFC §15.4 assigns command reads and one-shot scans to the foreground
/// allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The request draws on the background buckets.
    Background,
    /// The request draws on the foreground buckets.
    Foreground,
}

/// `Budget` configures one token bucket over worker time in exact fixed
/// point.
///
/// RFC §15.3 defines the bucket semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    /// `refill_ns_per_second` holds the worker nanoseconds that the bucket
    /// regains per wall-clock second.
    ///
    /// The rate must be positive and at most one worker-second per second for
    /// each unit of the physical ceiling.
    pub refill_ns_per_second: u64,
    /// `burst_ns` caps the bucket level in worker nanoseconds and must be
    /// positive.
    pub burst_ns: u64,
}

/// `Config` holds the authoritative limits of a shared authority.
///
/// Every participant must present the same configuration, and a joiner
/// cannot replace it. [`Config::from_host`] derives one from a
/// [`HostConfig`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// `ownership` sizes the ownership tables and sets the global physical
    /// ceiling.
    pub ownership: Limits,
    /// `domains` bounds the domain accounts, from 1 to [`MAX_DOMAINS`].
    pub domains: u32,
    /// `background` configures the global background bucket.
    pub background: Budget,
    /// `foreground` configures the global foreground bucket.
    pub foreground: Budget,
    /// `domain_background` configures each domain's background bucket.
    pub domain_background: Budget,
    /// `domain_foreground` configures each domain's foreground bucket.
    pub domain_foreground: Budget,
    /// `bootstrap_ns` bounds the worker time that domainless work may hold in
    /// reservations at once, and it must be positive.
    pub bootstrap_ns: u64,
    /// `per_domain_physical` bounds the operations of one domain that hold
    /// physical capacity at once.
    ///
    /// It must be positive and at most `ownership.physical`.
    pub per_domain_physical: u32,
    /// `initial_estimate_ns` holds the positive per-operation cost that the
    /// authority assumes before a domain has samples, and for all domainless
    /// work.
    pub initial_estimate_ns: u64,
    /// `stuck_after_ns` holds the occupancy after which an operation becomes
    /// stuck and quarantines its domain.
    pub stuck_after_ns: u64,
    /// `failure_surcharge_ns` holds the worker time that the authority charges
    /// to the domain once for each failed or stuck operation.
    pub failure_surcharge_ns: u64,
}

impl Config {
    /// `from_host` converts local policy units without truncating a duration
    /// or counter.
    ///
    /// The caller supplies the table sizes. The shared configuration carries
    /// no ceiling for accounted process memory, and that limit stays local.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] when `host` fails validation, a value
    /// does not fit, or the result fails the authority's bounds.
    pub fn from_host(host: &HostConfig, participants: u32, operations: u32, domains: u32) -> Result<Self, Error> {
        host.validate().map_err(|_| Error::InvalidConfig)?;
        let ns = |d: std::time::Duration| u64::try_from(d.as_nanos()).map_err(|_| Error::InvalidConfig);
        let budget = |duty: f64, burst| -> Result<Budget, Error> {
            Ok(Budget {
                refill_ns_per_second: ns(
                    std::time::Duration::try_from_secs_f64(duty).map_err(|_| Error::InvalidConfig)?
                )?,
                burst_ns: ns(burst)?,
            })
        };
        let config = Self {
            ownership: Limits {
                participants,
                operations,
                physical: host.maximum_in_flight.try_into().map_err(|_| Error::InvalidConfig)?,
            },
            domains,
            background: budget(host.background_duty, host.background_burst)?,
            foreground: budget(host.foreground_duty, host.foreground_burst)?,
            domain_background: budget(host.domain_background_duty, host.domain_background_burst)?,
            domain_foreground: budget(host.domain_foreground_duty, host.domain_foreground_burst)?,
            bootstrap_ns: ns(host.bootstrap_allowance)?,
            per_domain_physical: host.per_domain_concurrency.try_into().map_err(|_| Error::InvalidConfig)?,
            initial_estimate_ns: ns(host.initial_cost_estimate)?,
            stuck_after_ns: ns(host.stuck_threshold)?,
            failure_surcharge_ns: ns(host.failure_surcharge)?,
        };
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.ownership.validate()?;
        if self.domains == 0
            || self.domains > MAX_DOMAINS
            || self.per_domain_physical == 0
            || self.per_domain_physical > self.ownership.physical
            || self.bootstrap_ns == 0
            || self.initial_estimate_ns == 0
            || self.stuck_after_ns == 0
        {
            return Err(Error::InvalidConfig);
        }
        for budget in [self.background, self.foreground, self.domain_background, self.domain_foreground] {
            if budget.burst_ns == 0
                || budget.refill_ns_per_second == 0
                || u128::from(budget.refill_ns_per_second) > u128::from(self.ownership.physical) * SECOND
            {
                return Err(Error::InvalidConfig);
            }
        }
        Ok(())
    }
}

/// `SharedDomainKey` carries positive domain identity evidence from the
/// backend.
///
/// A process-local [`StorageDomainId`](crate::StorageDomainId) or a pathname
/// hash never qualifies as such evidence. Two keys match only when all three
/// components are equal (coordination.md, "Identities and bounded state").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SharedDomainKey {
    /// `namespace` identifies the namespace that qualifies the filesystem
    /// identity.
    pub namespace: [u8; 16],
    /// `filesystem` identifies the filesystem or mount within the namespace.
    pub filesystem: [u8; 16],
    /// `incarnation` bounds the lifetime of the filesystem identity.
    pub incarnation: [u8; 16],
}

/// `DomainId` names one domain account within an authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DomainId {
    /// `generation` names the authority that registered the account.
    pub generation: Generation,
    /// `slot` indexes the account in the domain table.
    pub slot: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DomainKey {
    Shared(SharedDomainKey),
    Private(Participant, u64),
}

/// `Request` describes the work a participant asks the authority to admit.
///
/// The grant covers the required operations plus as many desired operations
/// as the buckets afford, and at least one when any are desired (RFC §15.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// `work` names the source of the work.
    pub work: Work,
    /// `origin` selects the foreground or background buckets.
    pub origin: Origin,
    /// `domain` names the domain account, and `None` marks domainless
    /// bootstrap work.
    pub domain: Option<DomainId>,
    /// `required` holds the operation count that the grant must cover.
    pub required: u32,
    /// `desired` holds the maximum number of optional operations that the
    /// caller asks for.
    pub desired: u32,
    /// `ceiling_ns` caps the reserved worker time in nanoseconds.
    ///
    /// A caller may tighten the scope allowance and can never raise it.
    pub ceiling_ns: u64,
}

/// `Admission` describes the lease that the authority granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admission {
    /// `cost_ns` holds the worker time in nanoseconds that the authority
    /// reserved.
    pub cost_ns: u64,
    /// `operations` counts the total permitted operations, including required
    /// operations.
    pub operations: u32,
    /// `optional_operations` counts the permitted operations beyond the
    /// required ones.
    pub optional_operations: u32,
}

/// `Error` reports why the authority refused a request or transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The ownership ledger rejected the transition.
    Protocol(protocol::Error),
    /// The configuration fails validation.
    InvalidConfig,
    /// The domain table is full, and the authority never evicts an account.
    DomainCapacity,
    /// The domain ID belongs to another generation or names no account.
    UnknownDomain,
    /// The global or domain bucket cannot afford the lease after subtracting
    /// the holds of other preparations.
    Budget,
    /// The minimum lease exceeds the caller's ceiling, and refill can never
    /// admit it.
    Ceiling {
        /// `minimum_ns` holds the cost in nanoseconds of the smallest
        /// admissible lease.
        minimum_ns: u64,
    },
    /// Domainless work would exceed the bootstrap allowance.
    Bootstrap,
    /// The domain has a stuck operation, and the authority admits no new work
    /// on it.
    Quarantined,
    /// The domain already has the configured number of physical operations.
    DomainPhysical,
    /// The reported elapsed time exceeds the occupancy since authorization.
    InvalidReport,
}

impl From<protocol::Error> for Error {
    fn from(error: protocol::Error) -> Self {
        Self::Protocol(error)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(error) => error.fmt(f),
            Self::InvalidConfig => f.write_str("invalid shared admission configuration"),
            Self::DomainCapacity => f.write_str("shared domain table is full"),
            Self::UnknownDomain => f.write_str("domain does not belong to this authority"),
            Self::Budget => f.write_str("shared duty allowance is exhausted"),
            Self::Ceiling { minimum_ns } => {
                write!(f, "shared admission minimum of {minimum_ns} ns exceeds the caller ceiling")
            }
            Self::Bootstrap => f.write_str("shared bootstrap allowance is occupied"),
            Self::Quarantined => f.write_str("shared domain has stuck physical work"),
            Self::DomainPhysical => f.write_str("shared domain physical capacity is occupied"),
            Self::InvalidReport => f.write_str("reported work exceeds physical occupancy"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bucket {
    config: Budget,
    level: i128,
    remainder: u64,
}

impl Bucket {
    fn new(config: Budget) -> Self {
        Self { config, level: i128::from(config.burst_ns), remainder: 0 }
    }

    fn refill(&mut self, elapsed: u64) {
        let amount = u128::from(elapsed) * u128::from(self.config.refill_ns_per_second) + u128::from(self.remainder);
        self.level = self.level.saturating_add((amount / SECOND) as i128).min(i128::from(self.config.burst_ns));
        self.remainder = if self.level == i128::from(self.config.burst_ns) { 0 } else { (amount % SECOND) as u64 };
    }

    fn charge(&mut self, cost: u64) {
        self.level = self.level.saturating_sub(i128::from(cost));
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Domain {
    key: DomainKey,
    background: Bucket,
    foreground: Bucket,
    estimate_ns: u64,
    samples: [u64; 32],
    sample_count: usize,
    next_sample: usize,
}

impl Domain {
    fn sample(&mut self, cost: u64, capacity: u64) {
        self.samples[self.next_sample] = cost;
        self.next_sample = (self.next_sample + 1) % self.samples.len();
        self.sample_count = (self.sample_count + 1).min(self.samples.len());
        let mut sorted = self.samples;
        sorted[..self.sample_count].sort_unstable();
        self.estimate_ns = sorted[self.sample_count / 2].max(1).min(capacity);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Account {
    id: OperationId,
    request: Request,
    estimate_ns: u64,
    charged_ns: u64,
    withheld_ns: u64,
    stuck: bool,
    failed: bool,
}

/// `View` reports the shared accounting of an authority.
///
/// `View` counts the same operations that the local governor totals count.
/// The caller must not add the two together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct View {
    /// `participants` counts the registered participants.
    pub participants: usize,
    /// `domains` counts the registered domain accounts.
    pub domains: usize,
    /// `physical` counts the operations that occupy physical capacity.
    pub physical: u32,
    /// `prepared` counts the operations in the prepared phase.
    pub prepared: usize,
    /// `charged_ns` totals every worker nanosecond charged since the authority
    /// was created.
    pub charged_ns: u128,
    /// `surcharged_ns` totals every failure surcharge since the authority was
    /// created.
    pub surcharged_ns: u128,
    /// `withheld_ns` holds the global debt that stuck operations defer until
    /// they settle or the backend reclaims them.
    pub withheld_ns: u128,
    /// `background_level_ns` holds the global background bucket level, and it
    /// is negative while the bucket is in debt.
    pub background_level_ns: i128,
    /// `foreground_level_ns` holds the global foreground bucket level, and it
    /// is negative while the bucket is in debt.
    pub foreground_level_ns: i128,
    /// `bootstrap_reserved_ns` holds the reservations of live domainless
    /// operations.
    pub bootstrap_reserved_ns: u128,
}

/// `Authority` is the deterministic shared admission state that native
/// backends persist.
///
/// Joiners cannot replace the configuration. Domain accounts survive
/// participant departure, and the authority never evicts one to create a
/// fresh allowance. Every method that takes `now` first refills buckets and
/// charges running occupancy up to that authority time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    config: Config,
    ledger: Ledger,
    background: Bucket,
    foreground: Bucket,
    domains: Vec<Domain>,
    accounts: Vec<Option<Account>>,
    now: u64,
    clock_binding: Option<ClockBinding>,
    charged_ns: u128,
    surcharged_ns: u128,
}

impl Authority {
    /// `new` creates an authority with full buckets at authority time `now`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] for an invalid configuration, and a
    /// protocol error for a zero generation or a failed table allocation.
    pub fn new(generation: Generation, config: Config, now: u64) -> Result<Self, Error> {
        config.validate()?;
        let ledger = Ledger::new(generation, config.ownership)?;
        Self::with_ledger(ledger, config, now)
    }

    // Both constructors validate configuration and ownership before reaching
    // this allocation boundary. Decoding retains its populated ledger.
    fn with_ledger(ledger: Ledger, config: Config, now: u64) -> Result<Self, Error> {
        let mut accounts = Vec::new();
        accounts.try_reserve_exact(config.ownership.operations as usize).map_err(|_| protocol::Error::Allocation)?;
        accounts.resize(config.ownership.operations as usize, None);
        Ok(Self {
            config,
            ledger,
            background: Bucket::new(config.background),
            foreground: Bucket::new(config.foreground),
            domains: Vec::new(),
            accounts,
            now,
            clock_binding: None,
            charged_ns: 0,
            surcharged_ns: 0,
        })
    }

    /// `config` returns the authoritative configuration.
    pub fn config(&self) -> Config {
        self.config
    }

    /// `ledger` returns the ownership ledger.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// `now` returns the latest committed logical timestamp of the authority.
    #[cfg(windows)]
    pub(crate) fn now(&self) -> u64 {
        self.now
    }

    #[cfg(any(windows, test))]
    pub(crate) fn clock_binding(&self) -> Option<ClockBinding> {
        self.clock_binding
    }

    #[cfg(any(windows, test))]
    pub(crate) fn bind_clock(&mut self, binding: ClockBinding) {
        self.clock_binding = Some(binding);
    }

    /// `join` registers a participant through [`Ledger::join`].
    pub fn join(&mut self, version: u32) -> Result<Participant, Error> {
        Ok(self.ledger.join(version)?)
    }

    /// `join_owned` registers a participant with lifetime evidence through
    /// [`Ledger::join_owned`].
    pub fn join_owned(&mut self, version: u32, slot: u32, owner: [u8; 16]) -> Result<Participant, Error> {
        Ok(self.ledger.join_owned(version, slot, owner)?)
    }

    /// `leave` removes a participant through [`Ledger::leave`].
    ///
    /// The participant's private domain accounts survive its departure.
    pub fn leave(&mut self, participant: Participant) -> Result<(), Error> {
        Ok(self.ledger.leave(participant)?)
    }

    /// `register_shared_domain` returns the account for `key` and creates it
    /// on first use.
    ///
    /// Every participant that presents an equal key shares the account.
    pub fn register_shared_domain(&mut self, key: SharedDomainKey) -> Result<DomainId, Error> {
        self.register_domain(DomainKey::Shared(key))
    }

    /// `register_private_domain` returns a participant-private account for a
    /// local domain number.
    ///
    /// A domain with an inconclusive identity receives a private account, and
    /// that account counts against the same global limits as shared accounts.
    /// Matching local numbers in two participants never establish
    /// cross-process filesystem identity.
    pub fn register_private_domain(&mut self, participant: Participant, local: u64) -> Result<DomainId, Error> {
        self.ledger.next_operation(participant)?;
        self.register_domain(DomainKey::Private(participant, local))
    }

    fn register_domain(&mut self, key: DomainKey) -> Result<DomainId, Error> {
        let slot = match self.domains.iter().position(|domain| domain.key == key) {
            Some(slot) => slot,
            None => {
                if self.domains.len() == self.config.domains as usize {
                    return Err(Error::DomainCapacity);
                }
                if self.domains.len() == self.domains.capacity() {
                    // Grow only when a domain is registered. Sparse decoded
                    // authorities must not allocate the configured maximum on
                    // every bookkeeping transaction.
                    let additional = self.domains.len().max(1).min(self.config.domains as usize - self.domains.len());
                    self.domains.try_reserve_exact(additional).map_err(|_| protocol::Error::Allocation)?;
                }
                self.domains.push(Domain {
                    key,
                    background: Bucket::new(self.config.domain_background),
                    foreground: Bucket::new(self.config.domain_foreground),
                    estimate_ns: self.config.initial_estimate_ns,
                    samples: [0; 32],
                    sample_count: 0,
                    next_sample: 0,
                });
                self.domains.len() - 1
            }
        };
        Ok(DomainId { generation: self.ledger.generation(), slot: slot as u32 })
    }

    fn domain(&self, id: DomainId) -> Result<&Domain, Error> {
        if id.generation != self.ledger.generation() {
            return Err(Error::UnknownDomain);
        }
        self.domains.get(id.slot as usize).ok_or(Error::UnknownDomain)
    }

    fn account_slot(&self, id: OperationId) -> Result<usize, Error> {
        self.ledger.record(id)?;
        Ok(self
            .accounts
            .iter()
            .position(|account| account.is_some_and(|account| account.id == id))
            .expect("live ownership has accounting"))
    }

    fn buckets(&self, request: Request) -> (&Bucket, Option<&Bucket>) {
        let global = match request.origin {
            Origin::Background => &self.background,
            Origin::Foreground => &self.foreground,
        };
        let local = request.domain.map(|id| match request.origin {
            Origin::Background => &self.domains[id.slot as usize].background,
            Origin::Foreground => &self.domains[id.slot as usize].foreground,
        });
        (global, local)
    }

    fn available(&self, request: Request, excluding: Option<OperationId>) -> (u64, u64) {
        let (global, local) = self.buckets(request);
        let mut global_held = 0i128;
        let mut local_held = 0i128;
        for account in self.accounts.iter().flatten() {
            if Some(account.id) == excluding || account.request.origin != request.origin {
                continue;
            }
            let record = self.ledger.record(account.id).expect("account owns a live record");
            if record.phase == Phase::Prepared {
                let cost = i128::from(record.reservation.estimated_ns);
                global_held += cost;
                if account.request.domain == request.domain {
                    local_held += cost;
                }
            }
        }
        let capacity = global.config.burst_ns.min(local.map_or(u64::MAX, |bucket| bucket.config.burst_ns));
        let available = (global.level - global_held)
            .min(local.map_or(i128::MAX, |bucket| bucket.level - local_held))
            .min(i128::from(request.ceiling_ns))
            .min(i128::from(capacity))
            .max(0) as u64;
        (available, capacity)
    }

    fn quarantined(&self, domain: Option<DomainId>) -> bool {
        domain.is_some()
            && self.accounts.iter().flatten().any(|account| account.request.domain == domain && account.stuck)
    }

    fn bootstrap_reserved(&self) -> u128 {
        self.accounts
            .iter()
            .flatten()
            .filter(|a| a.request.domain.is_none())
            .map(|account| u128::from(self.ledger.record(account.id).expect("live account").reservation.estimated_ns))
            .sum()
    }

    /// `prepare` holds budget for `id` without spending it.
    ///
    /// All participants observe the hold. The caller passes
    /// [`Ledger::next_operation`] as `id`, and a retry with the same request
    /// returns the original admission. Watch release bypasses the budget,
    /// ceiling, and bootstrap checks.
    pub fn prepare(&mut self, id: OperationId, request: Request, now: u64) -> Result<Admission, Error> {
        self.advance(now)?;
        match self.ledger.record(id) {
            Ok(record) => {
                let account = self.accounts[self.account_slot(id)?].as_ref().expect("account");
                if account.request != request {
                    return Err(protocol::Error::ConflictingRetry.into());
                }
                return Ok(Admission {
                    cost_ns: record.reservation.estimated_ns,
                    operations: record.reservation.operations,
                    optional_operations: record.reservation.operations - request.required,
                });
            }
            Err(protocol::Error::InvalidSequence) if self.ledger.next_operation(id.participant)? == id => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(domain) = request.domain {
            self.domain(domain)?;
        }
        if self.quarantined(request.domain) {
            return Err(Error::Quarantined);
        }
        let minimum =
            request.required.checked_add(request.desired.min(1)).ok_or(protocol::Error::InvalidReservation)?;
        if minimum == 0 {
            return Err(protocol::Error::InvalidReservation.into());
        }
        let estimate =
            request.domain.map_or(self.config.initial_estimate_ns, |id| self.domains[id.slot as usize].estimate_ns);
        let (available, capacity) = self.available(request, None);
        let cleanup = request.work == Work::WatchRelease;
        let floor = estimate.saturating_mul(u64::from(minimum)).min(capacity);
        if !cleanup && floor > request.ceiling_ns {
            return Err(Error::Ceiling { minimum_ns: floor });
        }
        if !cleanup && floor > available {
            return Err(Error::Budget);
        }
        let optional = if request.desired == 0 {
            0
        } else {
            let room = available.saturating_sub(estimate.saturating_mul(u64::from(request.required))) / estimate;
            request.desired.min(room.min(u64::from(u32::MAX)) as u32).max(1)
        };
        let operations = request.required.checked_add(optional).ok_or(protocol::Error::InvalidReservation)?;
        let cost_ns = estimate.saturating_mul(u64::from(operations)).min(capacity);
        if !cleanup
            && request.domain.is_none()
            && self.bootstrap_reserved() + u128::from(cost_ns) > u128::from(self.config.bootstrap_ns)
        {
            return Err(Error::Bootstrap);
        }
        let slot = self.accounts.iter().position(Option::is_none).ok_or(protocol::Error::OperationCapacity)?;
        self.ledger.prepare(id, protocol::Reservation { work: request.work, operations, estimated_ns: cost_ns })?;
        self.accounts[slot] = Some(Account {
            id,
            request,
            estimate_ns: estimate,
            charged_ns: 0,
            withheld_ns: 0,
            stuck: false,
            failed: false,
        });
        Ok(Admission { cost_ns, operations, optional_operations: optional })
    }

    /// `narrow` reduces a prepared lease to `optional_operations` at its
    /// original price.
    ///
    /// The method applies only before authorization, and the count cannot
    /// grow.
    pub fn narrow(&mut self, id: OperationId, optional_operations: u32) -> Result<Admission, Error> {
        let slot = self.account_slot(id)?;
        let account = self.accounts[slot].expect("account");
        let record = *self.ledger.record(id)?;
        let previous = record.reservation.operations - account.request.required;
        if optional_operations > previous {
            return Err(protocol::Error::InvalidReservation.into());
        }
        let operations = account.request.required + optional_operations;
        let cost_ns = account.estimate_ns.saturating_mul(u64::from(operations)).min(record.reservation.estimated_ns);
        self.ledger.narrow(id, operations, cost_ns)?;
        Ok(Admission { cost_ns, operations, optional_operations })
    }

    /// `authorize` consumes shared physical capacity before the caller
    /// dispatches.
    ///
    /// The reserved cost becomes an irreversible charge. A retry after
    /// authorization succeeds without effect.
    pub fn authorize(&mut self, id: OperationId, now: u64) -> Result<(), Error> {
        self.advance(now)?;
        let slot = self.account_slot(id)?;
        let account = self.accounts[slot].expect("account");
        if self.ledger.record(id)?.phase != Phase::Prepared {
            return Ok(());
        }
        if self.quarantined(account.request.domain) {
            return Err(Error::Quarantined);
        }
        if let Some(domain) = account.request.domain {
            let running = self
                .accounts
                .iter()
                .flatten()
                .filter(|a| {
                    a.request.domain == Some(domain)
                        && self.ledger.record(a.id).expect("live account").phase != Phase::Prepared
                })
                .count();
            if running >= self.config.per_domain_physical as usize {
                return Err(Error::DomainPhysical);
            }
        }
        let cost = self.ledger.record(id)?.reservation.estimated_ns;
        if account.request.work != Work::WatchRelease && self.available(account.request, Some(id)).0 < cost {
            return Err(Error::Budget);
        }
        self.ledger.authorize(id, now)?;
        self.charge(slot, cost);
        Ok(())
    }

    fn charge(&mut self, slot: usize, amount: u64) {
        let account = self.accounts[slot].as_mut().expect("account");
        account.charged_ns = account.charged_ns.saturating_add(amount);
        self.charged_ns = self.charged_ns.saturating_add(u128::from(amount));
        if account.stuck {
            account.withheld_ns = account.withheld_ns.saturating_add(amount);
        } else {
            match account.request.origin {
                Origin::Background => self.background.charge(amount),
                Origin::Foreground => self.foreground.charge(amount),
            }
        }
        if let Some(id) = account.request.domain {
            let domain = &mut self.domains[id.slot as usize];
            match account.request.origin {
                Origin::Background => domain.background.charge(amount),
                Origin::Foreground => domain.foreground.charge(amount),
            }
        }
    }

    fn failure(&mut self, slot: usize) {
        let account = self.accounts[slot].as_mut().expect("account");
        if account.failed {
            return;
        }
        account.failed = true;
        self.surcharged_ns = self.surcharged_ns.saturating_add(u128::from(self.config.failure_surcharge_ns));
        if let Some(id) = account.request.domain {
            let domain = &mut self.domains[id.slot as usize];
            match account.request.origin {
                Origin::Background => domain.background.charge(self.config.failure_surcharge_ns),
                Origin::Foreground => domain.foreground.charge(self.config.failure_surcharge_ns),
            }
        }
    }

    /// `advance` refills buckets, charges elapsed occupancy, and detects
    /// stuck operations up to `now`.
    ///
    /// Every access performs this accounting, and no background ticker
    /// supervises work. When an operation becomes stuck, the method moves its
    /// global overshoot to withheld debt and charges the failure surcharge
    /// once.
    pub fn advance(&mut self, now: u64) -> Result<(), Error> {
        let elapsed = now.checked_sub(self.now).ok_or(protocol::Error::ClockRegression)?;
        self.background.refill(elapsed);
        self.foreground.refill(elapsed);
        for domain in &mut self.domains {
            domain.background.refill(elapsed);
            domain.foreground.refill(elapsed);
        }
        self.now = now;
        for slot in 0..self.accounts.len() {
            let Some(account) = self.accounts[slot] else { continue };
            let record = self.ledger.record(account.id).expect("live account");
            let Some(started) = record.authorized_at else { continue };
            let occupancy = now - started;
            let reserved = record.reservation.estimated_ns;
            self.charge(slot, occupancy.saturating_sub(account.charged_ns));
            if !account.stuck && occupancy >= self.config.stuck_after_ns {
                let account = self.accounts[slot].as_mut().expect("account");
                account.stuck = true;
                // Quarantine defers all global overshoot, including occupancy
                // charged before this access discovered the stuck operation.
                account.withheld_ns = account.charged_ns.saturating_sub(reserved);
                let bucket = match account.request.origin {
                    Origin::Background => &mut self.background,
                    Origin::Foreground => &mut self.foreground,
                };
                bucket.level = (bucket.level + i128::from(account.withheld_ns)).min(i128::from(bucket.config.burst_ns));
                if bucket.level == i128::from(bucket.config.burst_ns) {
                    bucket.remainder = 0;
                }
                self.failure(slot);
            }
        }
        Ok(())
    }

    /// `cancel` withdraws the caller's interest in `id`.
    ///
    /// The method returns `true` when the operation already holds physical
    /// capacity. Such an operation only detaches, and its owner must still
    /// settle it. The method returns `false` after it releases a prepared hold
    /// or finds the operation already retired.
    pub fn cancel(&mut self, id: OperationId, now: u64) -> Result<bool, Error> {
        self.advance(now)?;
        let slot = match self.account_slot(id) {
            Err(Error::Protocol(protocol::Error::RetiredOperation)) => return Ok(false),
            result => result?,
        };
        let effect = self.ledger.cancel(id)?;
        if !effect.detached {
            self.accounts[slot] = None;
        }
        Ok(effect.detached)
    }

    /// `report` applies cumulative progress for an authorized operation.
    ///
    /// The first failed report charges the failure surcharge.
    pub fn report(&mut self, id: OperationId, progress: Progress, now: u64) -> Result<(), Error> {
        self.advance(now)?;
        let slot = self.account_slot(id)?;
        let record = self.ledger.record(id)?;
        let started = record.authorized_at.ok_or(protocol::Error::InvalidTransition)?;
        if progress.elapsed_ns > now - started {
            return Err(Error::InvalidReport);
        }
        self.ledger.report(id, progress)?;
        if progress.failed {
            self.failure(slot);
        }
        Ok(())
    }

    /// `settle` applies the final report, retires the operation, and restores
    /// its withheld debt.
    ///
    /// A settlement for an operation that already retired has no effect. A
    /// successful settlement on a domain updates that domain's cost estimate.
    pub fn settle(&mut self, id: OperationId, progress: Progress, now: u64) -> Result<(), Error> {
        self.advance(now)?;
        let slot = match self.account_slot(id) {
            Err(Error::Protocol(protocol::Error::RetiredOperation)) => return Ok(()),
            result => result?,
        };
        self.report(id, progress, now)?;
        let account = self.accounts[slot].expect("account");
        let record = *self.ledger.record(id)?;
        self.ledger.settle(id, progress)?;
        self.retire(slot);
        if !account.failed
            && account.request.work != Work::WatchRelease
            && let Some(domain) = account.request.domain
        {
            let elapsed = now - record.authorized_at.expect("authorized");
            let capacity = self.buckets(account.request).0.config.burst_ns;
            self.domains[domain.slot as usize].sample(elapsed / u64::from(progress.operations.max(1)), capacity);
        }
        Ok(())
    }

    fn retire(&mut self, slot: usize) {
        let account = self.accounts[slot].take().expect("account");
        match account.request.origin {
            Origin::Background => self.background.charge(account.withheld_ns),
            Origin::Foreground => self.foreground.charge(account.withheld_ns),
        }
    }

    /// `reclaim_after_owner_exit` retires `id` after its owner exited.
    ///
    /// The backend must establish incarnation-qualified owner exit first. A
    /// physical operation receives the failure surcharge, and its occupancy
    /// up to `now` stays charged.
    pub fn reclaim_after_owner_exit(&mut self, id: OperationId, now: u64) -> Result<(), Error> {
        self.advance(now)?;
        let slot = match self.account_slot(id) {
            Err(Error::Protocol(protocol::Error::RetiredOperation)) => return Ok(()),
            result => result?,
        };
        let physical = self.ledger.record(id)?.phase != Phase::Prepared;
        self.ledger.reclaim_after_owner_exit(id, now)?;
        if physical {
            self.failure(slot);
        }
        self.retire(slot);
        Ok(())
    }

    /// `view` returns the shared accounting as of the last committed time.
    pub fn view(&self) -> View {
        View {
            participants: self.ledger.participant_count(),
            domains: self.domains.len(),
            physical: self.ledger.physical(),
            prepared: self.ledger.records().filter(|record| record.phase == Phase::Prepared).count(),
            charged_ns: self.charged_ns,
            surcharged_ns: self.surcharged_ns,
            withheld_ns: self.accounts.iter().flatten().map(|a| u128::from(a.withheld_ns)).sum(),
            background_level_ns: self.background.level,
            foreground_level_ns: self.foreground.level,
            bootstrap_reserved_ns: self.bootstrap_reserved(),
        }
    }
}
