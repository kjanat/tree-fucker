//! This module tracks bounded participant and operation ownership.
//!
//! This module contains no OS clock, process identifiers, pointers in its
//! records, or filesystem calls. A backend supplies scope-relative time and
//! verified owner-lifetime evidence. Admission policy runs before preparation.
//! The backend must commit preparation and policy changes in the same
//! transaction.

pub(crate) mod codec;

/// `VERSION` is the rendezvous protocol version.
///
/// The protocol version changes independently of the crate version. A joining
/// participant with another version receives [`Error::IncompatibleVersion`].
pub const VERSION: u32 = 1;
/// `MAX_PARTICIPANTS` is the largest participant-table length a ledger accepts.
pub const MAX_PARTICIPANTS: u32 = 4096;
/// `MAX_OPERATIONS` is the largest operation-table length a ledger accepts.
pub const MAX_OPERATIONS: u32 = 65_536;

/// `Generation` identifies one accounting authority.
///
/// Native backends draw a random value when they create the authority, and
/// the authority keeps it for its retained lifetime. Zero is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Generation(pub [u8; 16]);

/// `Participant` identifies one participant incarnation within an authority.
///
/// A reused slot receives a new incarnation, and the old identity can never
/// release the new participant's work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Participant {
    /// `generation` names the authority that issued the identity.
    pub generation: Generation,
    /// `slot` indexes the participant table.
    pub slot: u32,
    /// `incarnation` is a counter that the authority allocates monotonically
    /// and never reuses within the generation.
    pub incarnation: u64,
}

/// `OperationId` identifies one operation of a participant incarnation.
///
/// The participant never reuses an identity, including after the authority
/// reclaims the operation's record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OperationId {
    /// `participant` names the participant incarnation that owns the
    /// operation.
    pub participant: Participant,
    /// `sequence` is a nonzero number that the participant allocates
    /// monotonically.
    pub sequence: u64,
}

/// `Limits` fixes the ownership-table sizes and the shared physical ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// `participants` bounds the participant table, from 1 to
    /// [`MAX_PARTICIPANTS`].
    pub participants: u32,
    /// `operations` bounds the live operation table, from 1 to
    /// [`MAX_OPERATIONS`].
    pub operations: u32,
    /// `physical` bounds the operations that hold physical capacity at once.
    ///
    /// It must be positive and at most `operations`.
    pub physical: u32,
}

impl Limits {
    /// `validate` checks every bound on the fields.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLimits`] when any field is zero or exceeds its
    /// bound.
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

/// `Work` names the source of an operation.
///
/// The ledger records the source without sharing paths or application state.
/// Every source passes through the shared boundary (coordination.md,
/// "Composing the authorities").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Work {
    /// The operation canonicalizes or probes a root before its domain is known.
    Bootstrap,
    /// The operation resolves the storage domain of a path.
    DomainDiscovery,
    /// The operation reads a directory listing under a lease.
    Listing,
    /// The operation reads metadata for one entry or a batch of listed
    /// children.
    Enrichment,
    /// The operation performs a lazy read for a scan.
    LazyRead,
    /// The operation registers a filesystem watch.
    WatchRegistration,
    /// The operation releases a filesystem watch.
    ///
    /// Release bypasses the duty budget and still consumes physical capacity.
    WatchRelease,
}

/// `Phase` records the ownership state of a live operation.
///
/// Ownership changes before the syscall starts (coordination.md, "Operation
/// ownership").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The operation holds provisional budget and record space and holds no
    /// physical capacity.
    Prepared,
    /// The operation occupies physical capacity, and peers treat it as
    /// possibly running.
    StartAuthorized,
    /// The owner acknowledged dispatch, and this phase serves diagnostics
    /// only.
    Running,
}

/// `Reservation` records the work and cost that policy approved for an
/// operation.
///
/// A reservation grants no permission to dispatch. Dispatch needs
/// [`Ledger::authorize`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    /// `work` names the source of the work.
    pub work: Work,
    /// `operations` bounds the filesystem operations the grant permits.
    pub operations: u32,
    /// `estimated_ns` holds the reserved worker time in nanoseconds.
    pub estimated_ns: u64,
}

/// `Progress` carries cumulative facts about a physical operation.
///
/// Each report replaces the previous one. A duplicate report adds no charge.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    /// `revision` increases with every changed report.
    pub revision: u64,
    /// `operations` counts the operations performed so far, up to the
    /// reserved count.
    pub operations: u32,
    /// `elapsed_ns` holds the worker time occupied so far in nanoseconds.
    pub elapsed_ns: u64,
    /// `failed` records a failure, and a later report cannot clear it.
    pub failed: bool,
}

/// `Record` describes one live operation.
///
/// The ledger drops terminal records. The participant's sequence watermark
/// still marks their identities as issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    /// `id` identifies the operation.
    pub id: OperationId,
    /// `reservation` holds the current approved reservation.
    pub reservation: Reservation,
    /// `phase` holds the ownership phase.
    pub phase: Phase,
    /// `authorized_at` holds the authority time of start authorization.
    ///
    /// It is `None` while the operation is prepared.
    pub authorized_at: Option<u64>,
    /// `progress` holds the latest accepted cumulative report.
    pub progress: Progress,
}

/// `Effect` describes the accounting change of one transition.
///
/// The backend commits the effect together with the ownership change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Effect {
    /// `aborted_ns` holds the provisional reservation that returns without a
    /// permanent charge.
    pub aborted_ns: u64,
    /// `charged_ns` holds the added irreversible charge, and a replay returns
    /// zero.
    pub charged_ns: u64,
    /// `failed` reports a newly observed failure, and a replay never applies
    /// another surcharge.
    pub failed: bool,
    /// `detached` reports that cancellation detached the caller from physical
    /// work, and the operation keeps its physical ownership.
    pub detached: bool,
}

/// `Error` reports a rejected ownership transition.
///
/// No error authorizes fallback or the creation of a new authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The limits fail [`Limits::validate`].
    InvalidLimits,
    /// The caller supplied the zero generation.
    InvalidGeneration,
    /// The caller speaks a protocol version other than [`VERSION`].
    IncompatibleVersion,
    /// The requested participant slot is occupied or out of range, or the
    /// table is full.
    ParticipantCapacity,
    /// The operation table has no free record.
    OperationCapacity,
    /// Every unit of shared physical capacity is occupied.
    PhysicalCapacity,
    /// The process could not allocate a bounded table.
    Allocation,
    /// An incarnation or sequence counter reached its maximum value.
    IdentityExhausted,
    /// The identity belongs to another authority generation.
    WrongGeneration,
    /// The participant incarnation is no longer registered.
    StaleParticipant,
    /// The participant never issued this sequence, or the sequence skips the
    /// next one.
    InvalidSequence,
    /// The operation already reached a terminal state.
    RetiredOperation,
    /// A repeated preparation differs from the original request.
    ConflictingRetry,
    /// The reservation permits zero operations or zero cost, or a narrowing
    /// tries to grow it.
    InvalidReservation,
    /// The operation's phase does not permit the requested transition.
    InvalidTransition,
    /// The report regresses or exceeds a cumulative field, or it reuses a
    /// revision with different facts.
    InvalidProgress,
    /// The supplied time is earlier than the last committed authority time.
    ClockRegression,
    /// The participant still owns live operations and cannot leave.
    ParticipantBusy,
    /// Decoded state violates a structural invariant.
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

/// `Ledger` is a bounded ownership state machine for deterministic replay.
///
/// The ledger provides no synchronization. A backend must serialize access
/// and persist accounting effects in the same transaction as these records.
/// The in-memory representation defines no on-disk format.
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
    /// `new` creates an empty ledger for `generation` with fixed `limits`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidGeneration`] for the zero generation,
    /// [`Error::InvalidLimits`] for invalid limits, and [`Error::Allocation`]
    /// when the tables cannot be allocated.
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

    /// `generation` returns the authority generation of this ledger.
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// `limits` returns the fixed table and physical limits.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// `physical` returns the number of operations that hold physical
    /// capacity.
    pub fn physical(&self) -> u32 {
        self.physical
    }

    /// `participant_count` returns the number of registered participants.
    pub fn participant_count(&self) -> usize {
        self.members.iter().flatten().count()
    }

    /// `records` iterates over every live operation record.
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records.iter().flatten()
    }

    /// `join` registers a participant in the first free slot without lifetime
    /// evidence.
    ///
    /// The backend commits the join before it publishes the returned identity.
    pub fn join(&mut self, version: u32) -> Result<Participant, Error> {
        if version != VERSION {
            return Err(Error::IncompatibleVersion);
        }
        let slot = self.members.iter().position(Option::is_none).ok_or(Error::ParticipantCapacity)?;
        self.join_slot(version, slot, None)
    }

    /// `join_owned` registers a participant in `slot` and binds it to `owner`.
    ///
    /// Native backends pass independently verified lifetime evidence as
    /// `owner`, and [`Ledger::owner`] returns it during recovery.
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

    /// `participants` iterates over every registered participant identity.
    pub fn participants(&self) -> impl Iterator<Item = Participant> + '_ {
        self.members.iter().enumerate().filter_map(|(slot, member)| {
            member.map(|member| Participant {
                generation: self.generation,
                slot: slot as u32,
                incarnation: member.incarnation,
            })
        })
    }

    /// `owner` returns the lifetime evidence bound by [`Ledger::join_owned`].
    ///
    /// The result is `None` for a participant that joined through
    /// [`Ledger::join`].
    pub fn owner(&self, participant: Participant) -> Result<Option<[u8; 16]>, Error> {
        Ok(self.member(participant)?.owner)
    }

    /// `leave` removes a participant that owns no live operations.
    ///
    /// Orderly departure cannot forget outstanding ownership, and a
    /// participant with live records receives [`Error::ParticipantBusy`].
    pub fn leave(&mut self, participant: Participant) -> Result<(), Error> {
        self.member(participant)?;
        if self.records().any(|record| record.id.participant == participant) {
            return Err(Error::ParticipantBusy);
        }
        self.members[participant.slot as usize] = None;
        Ok(())
    }

    /// `next_operation` returns the identity for the participant's next
    /// preparation.
    ///
    /// The identity stays the same until a preparation succeeds, and the
    /// caller reuses it for retries.
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

    /// `record` returns the live record of `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RetiredOperation`] after the operation reaches a
    /// terminal state, and [`Error::InvalidSequence`] for an identity the
    /// participant never issued.
    pub fn record(&self, id: OperationId) -> Result<&Record, Error> {
        Ok(self.records[self.index(id)?].as_ref().expect("index identifies a live record"))
    }

    /// `prepare` records a reservation for `id` exactly once.
    ///
    /// A repeated request with the same reservation succeeds without effect,
    /// and a different one fails with [`Error::ConflictingRetry`]. The
    /// identity of a reclaimed terminal record can never prepare again.
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

    /// `narrow` reduces a prepared lease to the allowance both authorities
    /// approved.
    ///
    /// Neither the operation count nor the cost may grow. Physical
    /// authorization freezes the allowance, and a larger lease afterward needs
    /// a new operation ID.
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

    /// `authorize` reserves physical occupancy for `id` before dispatch.
    ///
    /// The reserved cost becomes an irreversible charge here. A retry after
    /// authorization returns an empty effect and keeps the original timestamp
    /// and occupancy.
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

    /// `running` records the owner's optional dispatch acknowledgment.
    ///
    /// The operation already holds its occupancy, and this transition changes
    /// no accounting.
    pub fn running(&mut self, id: OperationId) -> Result<(), Error> {
        let slot = self.index(id)?;
        let record = self.records[slot].as_mut().expect("live record");
        if record.phase == Phase::Prepared {
            return Err(Error::InvalidTransition);
        }
        record.phase = Phase::Running;
        Ok(())
    }

    /// `cancel` withdraws the caller's interest in `id`.
    ///
    /// A prepared operation retires and returns its hold as `aborted_ns`. A
    /// physical operation keeps its ownership, and the effect reports
    /// `detached`.
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

    /// `report` applies a cumulative progress report to a physical operation.
    ///
    /// A duplicate delivery has zero accounting effect. Elapsed time beyond
    /// the reservation adds a charge, and the first failure sets `failed`.
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

    /// `settle` applies the final report and retires the operation.
    ///
    /// The backend commits both in one storage transaction. A settlement for
    /// an operation that already retired has no effect.
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

    /// `reclaim_after_owner_exit` retires one operation after the backend
    /// proves that its owner exited.
    ///
    /// `reclaim_after_owner_exit` cannot establish that evidence itself. The
    /// backend must verify that the recorded *incarnation* exited. A PID,
    /// heartbeat, timeout, or bookkeeping-lock abandonment alone is
    /// insufficient evidence. The backend must commit the returned
    /// accounting effect before it reuses the released capacity.
    ///
    /// Each call reclaims one record, and the backend bounds its recovery work
    /// per scheduling turn. The participant may leave after all records
    /// retire.
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
