use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::coordination::protocol::codec::{read_work, write_work};
use crate::coordination::wire::{MAX_STATE_BYTES, Reader, Writer, checksum};

const MAGIC: &[u8; 8] = b"TFCSTATE";
const FORMAT: u32 = 2;

fn malformed() -> Error {
    protocol::Error::MalformedState.into()
}

impl Config {
    fn write(&self, w: &mut Writer) {
        w.u32(self.ownership.participants);
        w.u32(self.ownership.operations);
        w.u32(self.ownership.physical);
        w.u32(self.domains);
        for budget in [self.background, self.foreground, self.domain_background, self.domain_foreground] {
            w.u64(budget.refill_ns_per_second);
            w.u64(budget.burst_ns);
        }
        w.u64(self.bootstrap_ns);
        w.u32(self.per_domain_physical);
        w.u64(self.initial_estimate_ns);
        w.u64(self.stuck_after_ns);
        w.u64(self.failure_surcharge_ns);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        fn budget(r: &mut Reader<'_>) -> Result<Budget, Error> {
            Ok(Budget { refill_ns_per_second: r.u64()?, burst_ns: r.u64()? })
        }
        let config = Self {
            ownership: Limits { participants: r.u32()?, operations: r.u32()?, physical: r.u32()? },
            domains: r.u32()?,
            background: budget(r)?,
            foreground: budget(r)?,
            domain_background: budget(r)?,
            domain_foreground: budget(r)?,
            bootstrap_ns: r.u64()?,
            per_domain_physical: r.u32()?,
            initial_estimate_ns: r.u64()?,
            stuck_after_ns: r.u64()?,
            failure_surcharge_ns: r.u64()?,
        };
        config.validate()?;
        Ok(config)
    }
}

impl Bucket {
    fn write(&self, w: &mut Writer) {
        w.i128(self.level);
        w.u64(self.remainder);
    }

    fn read(r: &mut Reader<'_>, config: Budget) -> Result<Self, Error> {
        let bucket = Self { config, level: r.i128()?, remainder: r.u64()? };
        if bucket.level > i128::from(config.burst_ns)
            || u128::from(bucket.remainder) >= SECOND
            || (bucket.level == i128::from(config.burst_ns) && bucket.remainder != 0)
        {
            return Err(malformed());
        }
        Ok(bucket)
    }
}

impl Request {
    fn write(&self, w: &mut Writer) {
        write_work(w, self.work);
        w.u8(match self.origin {
            Origin::Background => 0,
            Origin::Foreground => 1,
        });
        w.u8(u8::from(self.domain.is_some()));
        if let Some(domain) = self.domain {
            w.u32(domain.slot);
        }
        w.u32(self.required);
        w.u32(self.desired);
        w.u64(self.ceiling_ns);
    }

    fn read(r: &mut Reader<'_>, generation: Generation) -> Result<Self, Error> {
        Ok(Self {
            work: read_work(r)?,
            origin: match r.u8()? {
                0 => Origin::Background,
                1 => Origin::Foreground,
                _ => return Err(malformed()),
            },
            domain: if r.boolean()? { Some(DomainId { generation, slot: r.u32()? }) } else { None },
            required: r.u32()?,
            desired: r.u32()?,
            ceiling_ns: r.u64()?,
        })
    }
}

impl Authority {
    /// Encode bounded, checked fields and a corruption checksum.
    ///
    /// The bytes are a snapshot, not a commit protocol. A backend must retain
    /// a recoverable previous snapshot while publishing a replacement.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let capacity = 1024
            + self.ledger.participant_count() * 64
            + self.ledger.records().count() * 128
            + self.domains.len() * 384
            + self.accounts.iter().flatten().count() * 128;
        let mut w = Writer::new(capacity)?;
        w.bytes(MAGIC);
        w.u32(FORMAT);
        w.u32(protocol::VERSION);
        self.config.write(&mut w);
        w.u64(self.now);
        self.background.write(&mut w);
        self.foreground.write(&mut w);
        w.u128(self.charged_ns);
        w.u128(self.surcharged_ns);
        self.ledger.write(&mut w);
        w.u32(self.domains.len() as u32);
        for domain in &self.domains {
            match domain.key {
                DomainKey::Shared(key) => {
                    w.u8(0);
                    w.bytes(&key.namespace);
                    w.bytes(&key.filesystem);
                    w.bytes(&key.incarnation);
                }
                DomainKey::Private(participant, local) => {
                    w.u8(1);
                    participant.write(&mut w);
                    w.u64(local);
                }
            }
            domain.background.write(&mut w);
            domain.foreground.write(&mut w);
            w.u64(domain.estimate_ns);
            w.u32(domain.sample_count as u32);
            w.u32(domain.next_sample as u32);
            for sample in domain.samples {
                w.u64(sample);
            }
        }
        w.u32(self.accounts.iter().flatten().count() as u32);
        for (slot, account) in self.accounts.iter().enumerate() {
            let Some(account) = account else { continue };
            w.u32(slot as u32);
            account.id.write(&mut w);
            account.request.write(&mut w);
            w.u64(account.estimate_ns);
            w.u64(account.charged_ns);
            w.u64(account.withheld_ns);
            w.u8(u8::from(account.stuck));
            w.u8(u8::from(account.failed));
        }
        let sum = checksum(&w.0);
        w.u64(sum);
        if w.0.len() > MAX_STATE_BYTES {
            return Err(malformed());
        }
        Ok(w.0)
    }

    /// Decode a complete snapshot, validating bounds and cross-record
    /// ownership before it can admit work. Trailing or truncated data fails.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 24 || bytes.len() > MAX_STATE_BYTES {
            return Err(malformed());
        }
        let (payload, sum) = bytes.split_at(bytes.len() - 8);
        if checksum(payload) != u64::from_le_bytes(sum.try_into().expect("eight checksum bytes")) {
            return Err(malformed());
        }
        let mut r = Reader(payload);
        if &r.bytes::<8>()? != MAGIC {
            return Err(malformed());
        }
        if r.u32()? != FORMAT || r.u32()? != protocol::VERSION {
            return Err(protocol::Error::IncompatibleVersion.into());
        }
        let config = Config::read(&mut r)?;
        let now = r.u64()?;
        let background = Bucket::read(&mut r, config.background)?;
        let foreground = Bucket::read(&mut r, config.foreground)?;
        let charged_ns = r.u128()?;
        let surcharged_ns = r.u128()?;
        let ledger = Ledger::read(&mut r, config.ownership)?;
        if ledger.clock() > now {
            return Err(malformed());
        }
        let mut authority = Self::with_ledger(ledger, config, now)?;
        authority.background = background;
        authority.foreground = foreground;
        authority.charged_ns = charged_ns;
        authority.surcharged_ns = surcharged_ns;
        let count = r.u32()?;
        if count > config.domains {
            return Err(malformed());
        }
        let mut keys = BTreeSet::new();
        for _ in 0..count {
            let key = match r.u8()? {
                0 => DomainKey::Shared(SharedDomainKey {
                    namespace: r.bytes()?,
                    filesystem: r.bytes()?,
                    incarnation: r.bytes()?,
                }),
                1 => {
                    let participant = Participant::read(&mut r, authority.ledger.generation())?;
                    if !authority.ledger.valid_historical_participant(participant) {
                        return Err(malformed());
                    }
                    DomainKey::Private(participant, r.u64()?)
                }
                _ => return Err(malformed()),
            };
            if !keys.insert(key) {
                return Err(malformed());
            }
            let mut domain = Domain {
                key,
                background: Bucket::read(&mut r, config.domain_background)?,
                foreground: Bucket::read(&mut r, config.domain_foreground)?,
                estimate_ns: r.u64()?,
                sample_count: r.u32()? as usize,
                next_sample: r.u32()? as usize,
                samples: [0; 32],
            };
            if domain.estimate_ns == 0
                || domain.sample_count > 32
                || domain.next_sample >= 32
                || (domain.sample_count < 32 && domain.next_sample != domain.sample_count)
            {
                return Err(malformed());
            }
            for sample in &mut domain.samples {
                *sample = r.u64()?;
            }
            if domain.samples[domain.sample_count..].iter().any(|sample| *sample != 0) {
                return Err(malformed());
            }
            authority.domains.push(domain);
        }
        let count = r.u32()?;
        if count as usize != authority.ledger.records().count() {
            return Err(malformed());
        }
        let mut ids = BTreeSet::new();
        let mut physical_domains = BTreeMap::<DomainId, u32>::new();
        for _ in 0..count {
            let slot = r.u32()? as usize;
            let account = Account {
                id: OperationId::read(&mut r, authority.ledger.generation())?,
                request: Request::read(&mut r, authority.ledger.generation())?,
                estimate_ns: r.u64()?,
                charged_ns: r.u64()?,
                withheld_ns: r.u64()?,
                stuck: r.boolean()?,
                failed: r.boolean()?,
            };
            if !ids.insert(account.id) {
                return Err(malformed());
            }
            authority.validate_account(account)?;
            if authority.ledger.record(account.id)?.authorized_at.is_some()
                && let Some(domain) = account.request.domain
            {
                let physical = physical_domains.entry(domain).or_default();
                *physical += 1;
                if *physical > config.per_domain_physical {
                    return Err(malformed());
                }
            }
            let destination = authority.accounts.get_mut(slot).ok_or_else(malformed)?;
            if destination.is_some() {
                return Err(malformed());
            }
            *destination = Some(account);
        }
        if !r.0.is_empty()
            || authority.accounts.iter().flatten().map(|a| u128::from(a.charged_ns)).sum::<u128>() > charged_ns
        {
            return Err(malformed());
        }
        Ok(authority)
    }

    fn validate_account(&self, account: Account) -> Result<(), Error> {
        let record = self.ledger.record(account.id).map_err(|_| malformed())?;
        if let Some(domain) = account.request.domain {
            self.domain(domain).map_err(|_| malformed())?;
        }
        let min = account.request.required.max(1);
        let max = u64::from(account.request.required) + u64::from(account.request.desired);
        let cost = record.reservation.estimated_ns;
        let (global, local) = self.buckets(account.request);
        let capacity = global.config.burst_ns.min(local.map_or(u64::MAX, |bucket| bucket.config.burst_ns));
        if account.estimate_ns == 0
            || record.reservation.work != account.request.work
            || record.reservation.operations < min
            || u64::from(record.reservation.operations) > max
            || cost != account.estimate_ns.saturating_mul(u64::from(record.reservation.operations)).min(capacity)
            || (account.request.work != Work::WatchRelease && cost > account.request.ceiling_ns)
        {
            return Err(malformed());
        }
        match record.authorized_at {
            None if account.charged_ns == 0 && account.withheld_ns == 0 && !account.stuck && !account.failed => {}
            Some(started) => {
                let occupancy = self.now.checked_sub(started).ok_or_else(malformed)?;
                if account.charged_ns != occupancy.max(cost)
                    || record.progress.elapsed_ns > occupancy
                    || account.withheld_ns > account.charged_ns.saturating_sub(cost)
                    || (account.stuck && (!account.failed || occupancy < self.config.stuck_after_ns))
                    || (!account.stuck && occupancy >= self.config.stuck_after_ns)
                    || (!account.stuck && account.withheld_ns != 0)
                    || (record.progress.failed && !account.failed)
                {
                    return Err(malformed());
                }
            }
            _ => return Err(malformed()),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HostConfig;

    fn fixture() -> Authority {
        let config = Config::from_host(&HostConfig::default(), 4, 16, 8).unwrap();
        let mut authority = Authority::new(Generation([1; 16]), config, 0).unwrap();
        let participant = authority.join(protocol::VERSION).unwrap();
        let domain = authority.register_private_domain(participant, 1).unwrap();
        let id = authority.ledger.next_operation(participant).unwrap();
        authority
            .prepare(
                id,
                Request {
                    work: Work::LazyRead,
                    origin: Origin::Foreground,
                    domain: Some(domain),
                    required: 1,
                    desired: 0,
                    ceiling_ns: u64::MAX,
                },
                0,
            )
            .unwrap();
        authority.authorize(id, 0).unwrap();
        authority
    }

    #[test]
    fn a_valid_checksum_cannot_hide_invalid_accounting_or_ownership() {
        for fault in 0..10 {
            let mut authority = fixture();
            match fault {
                0 => authority.foreground.level = i128::from(authority.config.foreground.burst_ns) + 1,
                1 => authority.accounts[0].as_mut().unwrap().id.sequence += 1,
                2 => authority.accounts[0].as_mut().unwrap().request.required = 100,
                3 => authority.accounts[0].as_mut().unwrap().withheld_ns = 1,
                4 => authority.accounts[0].as_mut().unwrap().charged_ns -= 1,
                5 => authority.accounts[0].as_mut().unwrap().request.domain.as_mut().unwrap().slot = u32::MAX,
                6 => authority.accounts[0] = None,
                7 => authority.now = 100_000_000,
                8 => authority.domains[0].samples[31] = 1,
                _ => authority.config.ownership.operations = protocol::MAX_OPERATIONS + 1,
            }
            // Encoding regenerates the checksum, so this exercises structural
            // and cross-record validation instead of checksum rejection.
            let bytes = authority.encode().unwrap();
            assert!(Authority::decode(&bytes).is_err(), "fault {fault}");
        }
    }

    #[test]
    fn unsupported_versions_are_explicit_even_with_an_intact_checksum() {
        let mut bytes = fixture().encode().unwrap();
        bytes[12..16].copy_from_slice(&(protocol::VERSION + 1).to_le_bytes());
        let payload = bytes.len() - 8;
        let sum = checksum(&bytes[..payload]);
        bytes[payload..].copy_from_slice(&sum.to_le_bytes());
        assert_eq!(Authority::decode(&bytes), Err(protocol::Error::IncompatibleVersion.into()));
    }
}
