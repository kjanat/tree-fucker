//! Shared admission policy, independent of any transport or storage mapping.
//!
//! One authority owns the buckets for its entire lifetime, including periods
//! with no participants. A backend must persist the whole transaction, not
//! only the ownership ledger, before publishing an admission decision.

use super::protocol::{self, Generation, Ledger, Limits, OperationId, Participant, Phase, Progress, Work};
use crate::HostConfig;

mod codec;

const SECOND: u128 = 1_000_000_000;
pub const MAX_DOMAINS: u32 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Background,
    Foreground,
}

/// Exact fixed-point refill and burst configuration, in worker nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub refill_ns_per_second: u64,
    pub burst_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub ownership: Limits,
    pub domains: u32,
    pub background: Budget,
    pub foreground: Budget,
    pub domain_background: Budget,
    pub domain_foreground: Budget,
    pub bootstrap_ns: u64,
    pub per_domain_physical: u32,
    pub initial_estimate_ns: u64,
    pub stuck_after_ns: u64,
    pub failure_surcharge_ns: u64,
}

impl Config {
    /// Convert local policy units without truncating a duration or counter.
    /// Accounted process memory is intentionally not a shared-memory ceiling.
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

/// Positive identity evidence established by the backend, not a local
/// StorageDomainId or pathname hash. All three components qualify equality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SharedDomainKey {
    pub namespace: [u8; 16],
    pub filesystem: [u8; 16],
    pub incarnation: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DomainId {
    pub generation: Generation,
    pub slot: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DomainKey {
    Shared(SharedDomainKey),
    Private(Participant, u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub work: Work,
    pub origin: Origin,
    pub domain: Option<DomainId>,
    pub required: u32,
    pub desired: u32,
    /// A caller may tighten the scope allowance, never raise it.
    pub ceiling_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admission {
    pub cost_ns: u64,
    /// Total permitted operations, including required operations.
    pub operations: u32,
    pub optional_operations: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Protocol(protocol::Error),
    InvalidConfig,
    DomainCapacity,
    UnknownDomain,
    Budget,
    Bootstrap,
    Quarantined,
    DomainPhysical,
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

/// Values are separate from local governor totals and must not be added to
/// them as if two filesystem operations occurred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct View {
    pub participants: usize,
    pub domains: usize,
    pub physical: u32,
    pub prepared: usize,
    pub charged_ns: u128,
    pub surcharged_ns: u128,
    pub withheld_ns: u128,
    pub background_level_ns: i128,
    pub foreground_level_ns: i128,
    pub bootstrap_reserved_ns: u128,
}

/// The deterministic shared authority used by storage adapters.
///
/// Configuration cannot be replaced by joiners. Domain accounts deliberately
/// survive departure and are not evicted to manufacture a fresh allowance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    config: Config,
    ledger: Ledger,
    background: Bucket,
    foreground: Bucket,
    domains: Vec<Domain>,
    accounts: Vec<Option<Account>>,
    now: u64,
    charged_ns: u128,
    surcharged_ns: u128,
}

impl Authority {
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
        let mut domains = Vec::new();
        domains.try_reserve_exact(config.domains as usize).map_err(|_| protocol::Error::Allocation)?;
        Ok(Self {
            config,
            ledger,
            background: Bucket::new(config.background),
            foreground: Bucket::new(config.foreground),
            domains,
            accounts,
            now,
            charged_ns: 0,
            surcharged_ns: 0,
        })
    }

    pub fn config(&self) -> Config {
        self.config
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Latest committed logical timestamp used by the shared authority.
    #[cfg(windows)]
    pub(crate) fn now(&self) -> u64 {
        self.now
    }

    pub fn join(&mut self, version: u32) -> Result<Participant, Error> {
        Ok(self.ledger.join(version)?)
    }

    pub fn join_owned(&mut self, version: u32, slot: u32, owner: [u8; 16]) -> Result<Participant, Error> {
        Ok(self.ledger.join_owned(version, slot, owner)?)
    }

    pub fn leave(&mut self, participant: Participant) -> Result<(), Error> {
        Ok(self.ledger.leave(participant)?)
    }

    pub fn register_shared_domain(&mut self, key: SharedDomainKey) -> Result<DomainId, Error> {
        self.register_domain(DomainKey::Shared(key))
    }

    /// Inconclusive identities get private domain accounts under the same
    /// aggregate envelope. Matching local numbers in two participants never
    /// establishes cross-process filesystem identity.
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

    /// Prepare budget without spending it; all participants observe the hold.
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

    /// Reduce a prepared lease using its original price, before authorization.
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

    /// Consume shared physical capacity before the caller can dispatch.
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

    /// Account elapsed physical work and detect stuck ownership on access.
    /// No background ticker is required to refill buckets or supervise work.
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
            self.charge(slot, occupancy.saturating_sub(account.charged_ns));
            if !account.stuck && occupancy >= self.config.stuck_after_ns {
                self.accounts[slot].as_mut().expect("account").stuck = true;
                self.failure(slot);
            }
        }
        Ok(())
    }

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

    /// The backend must establish incarnation-qualified owner exit first.
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
