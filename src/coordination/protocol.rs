//! Bounded participant and operation ownership.
//!
//! This module contains no OS clock, process identifiers, pointers in its
//! records, or filesystem calls. A backend supplies scope-relative time and
//! verified owner-lifetime evidence. Admission policy runs before preparation;
//! preparation and policy changes must commit in the same transaction.

pub(crate) mod codec;

/// The rendezvous protocol version, independent of the crate version.
pub const VERSION: u32 = 1;
/// Maximum accepted participant-table length.
pub const MAX_PARTICIPANTS: u32 = 4096;
/// Maximum accepted operation-table length.
pub const MAX_OPERATIONS: u32 = 65_536;

/// Accounting authority identity. Zero is not a valid generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Generation(pub [u8; 16]);

/// A participant incarnation, qualified by its authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Participant {
    pub generation: Generation,
    pub slot: u32,
    pub incarnation: u64,
}

/// An operation identity that cannot be reused within an incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OperationId {
    pub participant: Participant,
    pub sequence: u64,
}

/// Fixed ownership-table and physical-capacity limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub participants: u32,
    pub operations: u32,
    pub physical: u32,
}

impl Limits {
    pub fn validate(self) -> Result<(), Error> {
        if self.participants == 0
            || self.participants > MAX_PARTICIPANTS
            || self.operations == 0
            || self.operations > MAX_OPERATIONS
            || self.physical == 0
            || self.physical > self.operations
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
}

/// The work source is recorded without sharing paths or application state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Work {
    Bootstrap,
    DomainDiscovery,
    Listing,
    Enrichment,
    LazyRead,
    WatchRegistration,
    WatchRelease,
}

/// Ownership changes before a syscall starts, not after it returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Prepared,
    StartAuthorized,
    Running,
}

/// A policy-approved reservation. This is not permission to dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub work: Work,
    pub operations: u32,
    pub estimated_ns: u64,
}

/// Cumulative facts, rather than additive messages that can be charged twice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub revision: u64,
    pub operations: u32,
    pub elapsed_ns: u64,
    pub failed: bool,
}

/// Live operation record. Terminal records are represented by the watermark.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub id: OperationId,
    pub reservation: Reservation,
    pub phase: Phase,
    pub authorized_at: Option<u64>,
    pub progress: Progress,
}

/// A transition's accounting effect, committed with its ownership change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Effect {
    /// Provisional reservation returned without a permanent charge.
    pub aborted_ns: u64,
    /// Additional irreversible charge; a replay returns zero.
    pub charged_ns: u64,
    /// Newly observed failure; a replay never applies another surcharge.
    pub failed: bool,
    /// Logical cancellation detached from physical work still owned.
    pub detached: bool,
}

/// Explicit failures never authorize fallback or a new authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidLimits,
    InvalidGeneration,
    IncompatibleVersion,
    ParticipantCapacity,
    OperationCapacity,
    PhysicalCapacity,
    Allocation,
    IdentityExhausted,
    WrongGeneration,
    StaleParticipant,
    InvalidSequence,
    RetiredOperation,
    ConflictingRetry,
    InvalidReservation,
    InvalidTransition,
    InvalidProgress,
    ClockRegression,
    ParticipantBusy,
    MalformedState,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "invalid coordination capacity limits",
            Self::InvalidGeneration => "invalid coordination authority generation",
            Self::IncompatibleVersion => "incompatible coordination protocol",
            Self::ParticipantCapacity => "coordination participant table is full",
            Self::OperationCapacity => "coordination operation table is full",
            Self::PhysicalCapacity => "shared physical capacity is occupied",
            Self::Allocation => "cannot allocate bounded coordination tables",
            Self::IdentityExhausted => "coordination identity counter is exhausted",
            Self::WrongGeneration => "operation belongs to another authority generation",
            Self::StaleParticipant => "participant incarnation is no longer registered",
            Self::InvalidSequence => "operation sequence was not issued by this participant",
            Self::RetiredOperation => "operation is already terminal",
            Self::ConflictingRetry => "retry differs from the original operation",
            Self::InvalidReservation => "reservation must permit positive work and cost",
            Self::InvalidTransition => "operation cannot perform that lifecycle transition",
            Self::InvalidProgress => "progress is not a valid cumulative report",
            Self::ClockRegression => "coordination clock moved backward",
            Self::ParticipantBusy => "participant still owns operations",
            Self::MalformedState => "malformed coordination state",
        })
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Member {
    incarnation: u64,
    next_sequence: u64,
    owner: Option<[u8; 16]>,
}

/// A bounded ownership state machine, suitable for deterministic replay.
///
/// This is not a synchronization primitive. A backend must serialize access
/// and persist accounting effects in the same transaction as these records.
/// The representation is not an on-disk format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ledger {
    generation: Generation,
    limits: Limits,
    next_incarnation: u64,
    members: Vec<Option<Member>>,
    records: Vec<Option<Record>>,
    physical: u32,
    clock: u64,
}

impl Ledger {
    pub fn new(generation: Generation, limits: Limits) -> Result<Self, Error> {
        if generation.0 == [0; 16] {
            return Err(Error::InvalidGeneration);
        }
        limits.validate()?;
        let mut members = Vec::new();
        members.try_reserve_exact(limits.participants as usize).map_err(|_| Error::Allocation)?;
        members.resize(limits.participants as usize, None);
        let mut records = Vec::new();
        records.try_reserve_exact(limits.operations as usize).map_err(|_| Error::Allocation)?;
        records.resize(limits.operations as usize, None);
        Ok(Self { generation, limits, next_incarnation: 1, members, records, physical: 0, clock: 0 })
    }

    pub fn generation(&self) -> Generation {
        self.generation
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub fn physical(&self) -> u32 {
        self.physical
    }

    pub fn participant_count(&self) -> usize {
        self.members.iter().flatten().count()
    }

    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records.iter().flatten()
    }

    /// A join is committed before the backend publishes this identity.
    pub fn join(&mut self, version: u32) -> Result<Participant, Error> {
        if version != VERSION {
            return Err(Error::IncompatibleVersion);
        }
        let slot = self.members.iter().position(Option::is_none).ok_or(Error::ParticipantCapacity)?;
        self.join_slot(version, slot, None)
    }

    /// Native backends bind a slot to independently verified lifetime evidence.
    pub fn join_owned(&mut self, version: u32, slot: u32, owner: [u8; 16]) -> Result<Participant, Error> {
        self.join_slot(version, slot as usize, Some(owner))
    }

    fn join_slot(&mut self, version: u32, slot: usize, owner: Option<[u8; 16]>) -> Result<Participant, Error> {
        if version != VERSION {
            return Err(Error::IncompatibleVersion);
        }
        if !self.members.get(slot).is_some_and(Option::is_none) {
            return Err(Error::ParticipantCapacity);
        }
        let next = self.next_incarnation.checked_add(1).ok_or(Error::IdentityExhausted)?;
        let incarnation = self.next_incarnation;
        self.members[slot] = Some(Member { incarnation, next_sequence: 1, owner });
        self.next_incarnation = next;
        Ok(Participant { generation: self.generation, slot: slot as u32, incarnation })
    }

    pub fn participants(&self) -> impl Iterator<Item = Participant> + '_ {
        self.members.iter().enumerate().filter_map(|(slot, member)| {
            member.map(|member| Participant {
                generation: self.generation,
                slot: slot as u32,
                incarnation: member.incarnation,
            })
        })
    }

    pub fn owner(&self, participant: Participant) -> Result<Option<[u8; 16]>, Error> {
        Ok(self.member(participant)?.owner)
    }

    /// Orderly departure cannot forget outstanding physical ownership.
    pub fn leave(&mut self, participant: Participant) -> Result<(), Error> {
        self.member(participant)?;
        if self.records().any(|record| record.id.participant == participant) {
            return Err(Error::ParticipantBusy);
        }
        self.members[participant.slot as usize] = None;
        Ok(())
    }

    /// Obtain the identity for the next prepare attempt, including retries.
    pub fn next_operation(&self, participant: Participant) -> Result<OperationId, Error> {
        Ok(OperationId { participant, sequence: self.member(participant)?.next_sequence })
    }

    fn member(&self, participant: Participant) -> Result<&Member, Error> {
        if participant.generation != self.generation {
            return Err(Error::WrongGeneration);
        }
        self.members
            .get(participant.slot as usize)
            .and_then(Option::as_ref)
            .filter(|member| member.incarnation == participant.incarnation)
            .ok_or(Error::StaleParticipant)
    }

    fn index(&self, id: OperationId) -> Result<usize, Error> {
        let member = self.member(id.participant)?;
        if id.sequence == 0 || id.sequence >= member.next_sequence {
            return Err(Error::InvalidSequence);
        }
        self.records.iter().position(|record| record.is_some_and(|r| r.id == id)).ok_or(Error::RetiredOperation)
    }

    pub fn record(&self, id: OperationId) -> Result<&Record, Error> {
        Ok(self.records[self.index(id)?].as_ref().expect("index identifies a live record"))
    }

    /// Prepare exactly once. A repeated request must match the first one.
    ///
    /// Reclaiming terminal records does not permit replaying their IDs.
    pub fn prepare(&mut self, id: OperationId, reservation: Reservation) -> Result<(), Error> {
        let member = self.member(id.participant)?;
        if id.sequence < member.next_sequence {
            return match self.record(id) {
                Ok(record) if record.reservation == reservation => Ok(()),
                Ok(_) => Err(Error::ConflictingRetry),
                Err(error) => Err(error),
            };
        }
        if id.sequence != member.next_sequence {
            return Err(Error::InvalidSequence);
        }
        let next = member.next_sequence.checked_add(1).ok_or(Error::IdentityExhausted)?;
        if reservation.operations == 0 || reservation.estimated_ns == 0 {
            return Err(Error::InvalidReservation);
        }
        let slot = self.records.iter().position(Option::is_none).ok_or(Error::OperationCapacity)?;
        self.records[slot] = Some(Record {
            id,
            reservation,
            phase: Phase::Prepared,
            authorized_at: None,
            progress: Progress::default(),
        });
        self.members[id.participant.slot as usize].as_mut().expect("validated participant").next_sequence = next;
        Ok(())
    }

    /// Reduce a prepared lease to the allowance approved by both authorities.
    ///
    /// Neither operation count nor cost may grow. Physical authorization
    /// freezes the allowance; afterward a new lease needs a new operation ID.
    pub fn narrow(&mut self, id: OperationId, operations: u32, estimated_ns: u64) -> Result<Effect, Error> {
        let slot = self.index(id)?;
        let record = self.records[slot].as_mut().expect("live record");
        if record.phase != Phase::Prepared {
            return Err(Error::InvalidTransition);
        }
        if operations == 0
            || operations > record.reservation.operations
            || estimated_ns == 0
            || estimated_ns > record.reservation.estimated_ns
        {
            return Err(Error::InvalidReservation);
        }
        let aborted_ns = record.reservation.estimated_ns - estimated_ns;
        record.reservation.operations = operations;
        record.reservation.estimated_ns = estimated_ns;
        Ok(Effect { aborted_ns, ..Effect::default() })
    }

    /// Start authorization reserves physical occupancy before dispatch.
    ///
    /// The minimum charge becomes irreversible here. An authorization retry
    /// must not reset its timestamp or increment occupancy.
    pub fn authorize(&mut self, id: OperationId, now: u64) -> Result<Effect, Error> {
        let slot = self.index(id)?;
        let record = self.records[slot].as_ref().expect("live record");
        if record.phase != Phase::Prepared {
            return Ok(Effect::default());
        }
        if now < self.clock {
            return Err(Error::ClockRegression);
        }
        if self.physical == self.limits.physical {
            return Err(Error::PhysicalCapacity);
        }
        let record = self.records[slot].as_mut().expect("live record");
        record.phase = Phase::StartAuthorized;
        record.authorized_at = Some(now);
        self.physical += 1;
        self.clock = now;
        Ok(Effect { charged_ns: record.reservation.estimated_ns, ..Effect::default() })
    }

    /// Optional diagnostic acknowledgment; occupancy is already held.
    pub fn running(&mut self, id: OperationId) -> Result<(), Error> {
        let slot = self.index(id)?;
        let record = self.records[slot].as_mut().expect("live record");
        if record.phase == Phase::Prepared {
            return Err(Error::InvalidTransition);
        }
        record.phase = Phase::Running;
        Ok(())
    }

    /// Cancel logical interest. Physical ownership cannot be cancelled.
    pub fn cancel(&mut self, id: OperationId) -> Result<Effect, Error> {
        let slot = match self.index(id) {
            Err(Error::RetiredOperation) => return Ok(Effect::default()),
            result => result?,
        };
        let record = self.records[slot].as_ref().expect("live record");
        if record.phase != Phase::Prepared {
            return Ok(Effect { detached: true, ..Effect::default() });
        }
        let aborted_ns = record.reservation.estimated_ns;
        self.records[slot] = None;
        Ok(Effect { aborted_ns, ..Effect::default() })
    }

    fn validate_progress(record: &Record, progress: Progress) -> Result<(), Error> {
        let old = record.progress;
        if record.phase == Phase::Prepared {
            return Err(Error::InvalidTransition);
        }
        if progress == old {
            return Ok(());
        }
        if progress.revision <= old.revision
            || progress.operations < old.operations
            || progress.operations > record.reservation.operations
            || progress.elapsed_ns < old.elapsed_ns
            || (old.failed && !progress.failed)
        {
            return Err(Error::InvalidProgress);
        }
        Ok(())
    }

    /// Apply cumulative progress. Duplicate delivery has zero accounting
    /// effect.
    pub fn report(&mut self, id: OperationId, progress: Progress) -> Result<Effect, Error> {
        let slot = self.index(id)?;
        let record = self.records[slot].as_mut().expect("live record");
        Self::validate_progress(record, progress)?;
        let floor = record.reservation.estimated_ns;
        let charged_ns = progress.elapsed_ns.max(floor) - record.progress.elapsed_ns.max(floor);
        let failed = progress.failed && !record.progress.failed;
        record.progress = progress;
        Ok(Effect { charged_ns, failed, ..Effect::default() })
    }

    /// Commit final facts and retire the operation in one storage transaction.
    pub fn settle(&mut self, id: OperationId, progress: Progress) -> Result<Effect, Error> {
        let slot = match self.index(id) {
            Err(Error::RetiredOperation) => return Ok(Effect::default()),
            result => result?,
        };
        let effect = self.report(id, progress)?;
        self.records[slot] = None;
        self.physical -= 1;
        Ok(effect)
    }

    /// Reclaim one operation after the backend proves its owner has exited.
    ///
    /// This pure transition cannot establish that evidence itself. The backend
    /// must verify the *incarnation*, not just a PID, heartbeat, timeout, or
    /// bookkeeping-lock abandonment. It must commit the returned accounting
    /// effect before reusing the released capacity.
    ///
    /// Reclamation is one record per call so recovery work can be bounded per
    /// scheduling turn. The participant may leave after all records retire.
    pub fn reclaim_after_owner_exit(&mut self, id: OperationId, now: u64) -> Result<Effect, Error> {
        let slot = match self.index(id) {
            Err(Error::RetiredOperation) => return Ok(Effect::default()),
            result => result?,
        };
        if now < self.clock {
            return Err(Error::ClockRegression);
        }
        let record = self.records[slot].as_ref().expect("live record");
        if record.phase == Phase::Prepared {
            return self.cancel(id);
        }
        // Recovery needs no fresh report revision: it is a distinct terminal
        // transaction, including when a report counter has reached u64::MAX.
        let elapsed = now.saturating_sub(record.authorized_at.expect("physical authorization has a clock"));
        let charged_ns = elapsed.saturating_sub(record.progress.elapsed_ns.max(record.reservation.estimated_ns));
        let failed = !record.progress.failed;
        self.records[slot] = None;
        self.physical -= 1;
        self.clock = now;
        Ok(Effect { charged_ns, failed, ..Effect::default() })
    }
}
