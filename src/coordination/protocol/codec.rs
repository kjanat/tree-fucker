use std::collections::BTreeSet;

use super::*;
use crate::coordination::wire::{Reader, Writer};

pub(crate) fn write_work(writer: &mut Writer, work: Work) {
    writer.u8(match work {
        Work::Bootstrap => 0,
        Work::DomainDiscovery => 1,
        Work::Listing => 2,
        Work::Enrichment => 3,
        Work::LazyRead => 4,
        Work::WatchRegistration => 5,
        Work::WatchRelease => 6,
    });
}

pub(crate) fn read_work(reader: &mut Reader<'_>) -> Result<Work, Error> {
    match reader.u8()? {
        0 => Ok(Work::Bootstrap),
        1 => Ok(Work::DomainDiscovery),
        2 => Ok(Work::Listing),
        3 => Ok(Work::Enrichment),
        4 => Ok(Work::LazyRead),
        5 => Ok(Work::WatchRegistration),
        6 => Ok(Work::WatchRelease),
        _ => Err(Error::MalformedState),
    }
}

impl Participant {
    pub(crate) fn write(&self, writer: &mut Writer) {
        writer.u32(self.slot);
        writer.u64(self.incarnation);
    }

    pub(crate) fn read(reader: &mut Reader<'_>, generation: Generation) -> Result<Self, Error> {
        Ok(Self { generation, slot: reader.u32()?, incarnation: reader.u64()? })
    }
}

impl OperationId {
    pub(crate) fn write(&self, writer: &mut Writer) {
        self.participant.write(writer);
        writer.u64(self.sequence);
    }

    pub(crate) fn read(reader: &mut Reader<'_>, generation: Generation) -> Result<Self, Error> {
        Ok(Self { participant: Participant::read(reader, generation)?, sequence: reader.u64()? })
    }
}

impl Ledger {
    pub(crate) fn write(&self, writer: &mut Writer) {
        writer.bytes(&self.generation.0);
        writer.u64(self.next_incarnation);
        writer.u64(self.clock);
        writer.u32(self.physical);
        writer.u32(self.participant_count() as u32);
        for (slot, member) in self.members.iter().enumerate() {
            if let Some(member) = member {
                writer.u32(slot as u32);
                writer.u64(member.incarnation);
                writer.u64(member.next_sequence);
                writer.u8(u8::from(member.owner.is_some()));
                if let Some(owner) = member.owner {
                    writer.bytes(&owner);
                }
            }
        }
        writer.u32(self.records().count() as u32);
        for (slot, record) in self.records.iter().enumerate() {
            let Some(record) = record else { continue };
            writer.u32(slot as u32);
            record.id.write(writer);
            write_work(writer, record.reservation.work);
            writer.u32(record.reservation.operations);
            writer.u64(record.reservation.estimated_ns);
            writer.u8(match record.phase {
                Phase::Prepared => 0,
                Phase::StartAuthorized => 1,
                Phase::Running => 2,
            });
            writer.u8(u8::from(record.authorized_at.is_some()));
            if let Some(at) = record.authorized_at {
                writer.u64(at);
            }
            writer.u64(record.progress.revision);
            writer.u32(record.progress.operations);
            writer.u64(record.progress.elapsed_ns);
            writer.u8(u8::from(record.progress.failed));
        }
    }

    pub(crate) fn read(reader: &mut Reader<'_>, limits: Limits) -> Result<Self, Error> {
        let mut ledger = Self::new(Generation(reader.bytes()?), limits)?;
        ledger.next_incarnation = reader.u64()?;
        ledger.clock = reader.u64()?;
        let physical = reader.u32()?;
        if ledger.next_incarnation == 0 || physical > limits.physical {
            return Err(Error::MalformedState);
        }
        let count = reader.u32()?;
        if count > limits.participants {
            return Err(Error::MalformedState);
        }
        let mut incarnations = BTreeSet::new();
        for _ in 0..count {
            let slot = reader.u32()? as usize;
            let member = Member {
                incarnation: reader.u64()?,
                next_sequence: reader.u64()?,
                owner: if reader.boolean()? { Some(reader.bytes()?) } else { None },
            };
            let destination = ledger.members.get_mut(slot).ok_or(Error::MalformedState)?;
            if destination.is_some()
                || member.incarnation == 0
                || member.incarnation >= ledger.next_incarnation
                || member.next_sequence == 0
                || !incarnations.insert(member.incarnation)
            {
                return Err(Error::MalformedState);
            }
            *destination = Some(member);
        }
        let count = reader.u32()?;
        if count > limits.operations {
            return Err(Error::MalformedState);
        }
        let mut ids = BTreeSet::new();
        for _ in 0..count {
            let slot = reader.u32()? as usize;
            let id = OperationId::read(reader, ledger.generation)?;
            let reservation =
                Reservation { work: read_work(reader)?, operations: reader.u32()?, estimated_ns: reader.u64()? };
            let phase = match reader.u8()? {
                0 => Phase::Prepared,
                1 => Phase::StartAuthorized,
                2 => Phase::Running,
                _ => return Err(Error::MalformedState),
            };
            let authorized_at = if reader.boolean()? { Some(reader.u64()?) } else { None };
            let progress = Progress {
                revision: reader.u64()?,
                operations: reader.u32()?,
                elapsed_ns: reader.u64()?,
                failed: reader.boolean()?,
            };
            let member = ledger.member(id.participant).map_err(|_| Error::MalformedState)?;
            if id.sequence == 0
                || id.sequence >= member.next_sequence
                || !ids.insert(id)
                || reservation.operations == 0
                || reservation.estimated_ns == 0
                || progress.operations > reservation.operations
                || (progress.revision == 0 && progress != Progress::default())
            {
                return Err(Error::MalformedState);
            }
            match (phase, authorized_at) {
                (Phase::Prepared, None) if progress == Progress::default() => {}
                (Phase::StartAuthorized | Phase::Running, Some(at)) if at <= ledger.clock => ledger.physical += 1,
                _ => return Err(Error::MalformedState),
            }
            let destination = ledger.records.get_mut(slot).ok_or(Error::MalformedState)?;
            if destination.is_some() {
                return Err(Error::MalformedState);
            }
            *destination = Some(Record { id, reservation, phase, authorized_at, progress });
        }
        if ledger.physical != physical {
            return Err(Error::MalformedState);
        }
        Ok(ledger)
    }

    pub(crate) fn valid_historical_participant(&self, participant: Participant) -> bool {
        participant.generation == self.generation
            && participant.slot < self.limits.participants
            && participant.incarnation > 0
            && participant.incarnation < self.next_incarnation
    }

    pub(crate) fn clock(&self) -> u64 {
        self.clock
    }
}
