//! Two bounded snapshots with an explicit commit decision.
//!
//! The caller holds the backend's interprocess lock for every method. Storage
//! must be unbuffered, host-local, and preserve completed writes across process
//! exit. This is a process-crash protocol, not a power-loss durability claim.
//! A corrupt committed slot fails closed; it never falls back to older debt.

use std::io::{self, Read, Seek, SeekFrom, Write};

use super::authority::{Authority, Config, Error as AuthorityError};
use super::protocol::Generation;
use super::wire::{MAX_STATE_BYTES, Reader, Writer, checksum};

pub(crate) const HEADER: u64 = 64;
const SLOT_HEADER: u64 = 32;
const MAGIC: &[u8; 8] = b"TFJOURN1";
const FORMAT: u32 = 1;
// A single byte cannot be partially written. The distinct bit patterns also
// make any single-bit damage an invalid marker rather than another decision.
const PREPARING: u8 = 0x5a;
const COMMITTED: u8 = 0xa5;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    State(AuthorityError),
    Malformed,
    Incompatible,
    Uninitialized,
    SequenceExhausted,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::State(error) => error.fmt(f),
            Self::Malformed => f.write_str("malformed coordination journal"),
            Self::Incompatible => f.write_str("incompatible coordination journal"),
            Self::Uninitialized => f.write_str("coordination journal has no recoverable initial state"),
            Self::SequenceExhausted => f.write_str("coordination journal sequence is exhausted"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::State(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<AuthorityError> for Error {
    fn from(error: AuthorityError) -> Self {
        Self::State(error)
    }
}

/// A journal handle. It does not acquire an OS lock by itself.
pub struct Journal<S> {
    storage: S,
    capacity: u32,
    generation: Generation,
    validated: Option<Validated>,
    // Reuse bounded per-slot read buffers. The selected payload is decoded
    // afresh below so another process's accounting is never cached.
    payloads: [Vec<u8>; 2],
}

struct Snapshot {
    sequence: u64,
    authority: Authority,
}

// Retain only the last validated payload, never an authority used for mutation.
// An exact byte match can reuse structural validation, not current accounting.
struct Validated {
    sequence: u64,
    payload: Vec<u8>,
    config: Config,
}

struct Candidate {
    slot: u64,
    prepared: bool,
    sequence: u64,
    config: Config,
    authority: Option<Authority>,
}

impl<S: Read + Write + Seek> Journal<S> {
    /// Initialize a new empty object; never overwrite an existing rendezvous.
    pub fn create(mut storage: S, authority: &Authority) -> Result<Self, Error> {
        if storage.seek(SeekFrom::End(0))? != 0 {
            return Err(Error::Malformed);
        }
        let cfg = authority.config();
        let capacity = 1024u32 + cfg.ownership.participants * 64 + cfg.ownership.operations * 256 + cfg.domains * 384;
        if capacity as usize > MAX_STATE_BYTES {
            return Err(Error::Malformed);
        }
        let generation = authority.ledger().generation();
        let mut header = Writer::new(HEADER as usize).map_err(AuthorityError::from)?;
        header.bytes(MAGIC);
        header.u32(FORMAT);
        header.u32(capacity);
        header.bytes(&generation.0);
        header.bytes(&[0; 24]);
        header.u64(checksum(&header.0));
        storage.seek(SeekFrom::Start(0))?;
        storage.write_all(&header.0)?;
        let mut journal = Self { storage, capacity, generation, validated: None, payloads: [Vec::new(), Vec::new()] };
        journal.storage.seek(SeekFrom::Start(journal.length() - 1))?;
        journal.storage.write_all(&[0])?;
        journal.storage.flush()?;
        journal.publish(1, authority)?;
        Ok(journal)
    }

    pub fn open(mut storage: S) -> Result<Self, Error> {
        let mut bytes = [0; HEADER as usize];
        storage.seek(SeekFrom::Start(0))?;
        storage.read_exact(&mut bytes)?;
        if checksum(&bytes[..56]) != u64::from_le_bytes(bytes[56..].try_into().expect("checksum")) {
            return Err(Error::Malformed);
        }
        let mut r = Reader(&bytes);
        let read_error = |_| Error::Malformed;
        if &r.bytes::<8>().map_err(read_error)? != MAGIC {
            return Err(Error::Malformed);
        }
        if r.u32().map_err(read_error)? != FORMAT {
            return Err(Error::Incompatible);
        }
        let capacity = r.u32().map_err(read_error)?;
        let generation = Generation(r.bytes().map_err(read_error)?);
        if capacity == 0
            || capacity as usize > MAX_STATE_BYTES
            || generation.0 == [0; 16]
            || r.bytes::<24>().map_err(read_error)? != [0; 24]
        {
            return Err(Error::Malformed);
        }
        let mut journal = Self { storage, capacity, generation, validated: None, payloads: [Vec::new(), Vec::new()] };
        if journal.storage.seek(SeekFrom::End(0))? != journal.length() {
            return Err(Error::Malformed);
        }
        Ok(journal)
    }

    fn length(&self) -> u64 {
        HEADER + 2 * (SLOT_HEADER + u64::from(self.capacity))
    }

    fn offset(&self, slot: u64) -> u64 {
        HEADER + slot * (SLOT_HEADER + u64::from(self.capacity))
    }

    fn read_at(&mut self, at: u64, bytes: &mut [u8]) -> Result<(), Error> {
        self.storage.seek(SeekFrom::Start(at))?;
        self.storage.read_exact(bytes)?;
        Ok(())
    }

    fn write_at(&mut self, at: u64, bytes: &[u8]) -> Result<(), Error> {
        self.storage.seek(SeekFrom::Start(at))?;
        self.storage.write_all(bytes)?;
        Ok(())
    }

    fn snapshot(&mut self, slot: u64) -> Result<Option<Candidate>, Error> {
        let offset = self.offset(slot);
        let mut header = [0; SLOT_HEADER as usize];
        self.read_at(offset, &mut header)?;
        if header == [0; SLOT_HEADER as usize] {
            return Ok(None);
        }
        let prepared = match header[0] {
            PREPARING => true,
            COMMITTED => false,
            _ => return Err(Error::Malformed),
        };
        let invalid = || if prepared { Ok(None) } else { Err(Error::Malformed) };
        if header[1..8] != [0; 7] || header[20..24] != [0; 4] {
            return invalid();
        }
        let sequence = u64::from_le_bytes(header[8..16].try_into().expect("sequence"));
        let length = u32::from_le_bytes(header[16..20].try_into().expect("length"));
        let sum = u64::from_le_bytes(header[24..32].try_into().expect("checksum"));
        if sequence == 0 || (sequence - 1) % 2 != slot || length == 0 || length > self.capacity {
            return invalid();
        }
        let payload = &mut self.payloads[slot as usize];
        if payload.capacity() < length as usize {
            payload
                .try_reserve_exact(length as usize - payload.len())
                .map_err(|_| io::Error::other("cannot allocate journal snapshot"))?;
        }
        payload.resize(length as usize, 0);
        self.storage.seek(SeekFrom::Start(offset + SLOT_HEADER))?;
        self.storage.read_exact(payload)?;
        if digest(self.generation, sequence, payload) != sum {
            return invalid();
        }
        // A complete but incompatible/malformed state is not an interrupted
        // write. Never fall back to an older compatible budget.
        let cached = self.validated.as_ref().filter(|cached| cached.sequence == sequence && cached.payload == *payload);
        let (config, authority) = if let Some(cached) = cached {
            (cached.config, None)
        } else {
            let authority = Authority::decode(payload)?;
            if authority.ledger().generation() != self.generation {
                return Err(Error::Malformed);
            }
            (authority.config(), Some(authority))
        };
        Ok(Some(Candidate { slot, prepared, sequence, config, authority }))
    }

    fn latest(&mut self) -> Result<Snapshot, Error> {
        let first = self.snapshot(0)?;
        let second = self.snapshot(1)?;
        let latest = match (first, second) {
            (Some(a), Some(b)) => {
                if a.sequence.abs_diff(b.sequence) != 1 || a.config != b.config {
                    return Err(Error::Malformed);
                }
                if a.sequence > b.sequence { a } else { b }
            }
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => return Err(Error::Uninitialized),
        };
        if latest.prepared {
            // The payload is complete. Conservatively adopt its accounting
            // even if its writer died before acknowledging the commit.
            self.write_at(self.offset(latest.slot), &[COMMITTED])?;
            self.storage.flush()?;
        }
        let authority = match latest.authority {
            Some(authority) => authority,
            None => Authority::decode(&self.payloads[latest.slot as usize])?,
        };
        let sequence = latest.sequence;
        let selected = &self.payloads[latest.slot as usize];
        let cache_matches = self
            .validated
            .as_ref()
            .is_some_and(|cached| cached.sequence == sequence && cached.payload.as_slice() == selected.as_slice());
        if !cache_matches {
            self.validated = Some(Validated { sequence, payload: selected.clone(), config: latest.config });
        }
        Ok(Snapshot { sequence, authority })
    }

    /// Recover a complete state under the backend's exclusive lock.
    pub fn load(&mut self) -> Result<Authority, Error> {
        Ok(self.latest()?.authority)
    }

    /// Commit ownership and accounting together. No target-filesystem work
    /// may execute in this closure. An error after writing begins is an
    /// uncertain outcome: callers must reconnect/recover, never mint fallback
    /// capacity or blindly dispatch the requested operation.
    pub fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&mut Authority) -> Result<T, AuthorityError>,
    ) -> Result<T, Error> {
        self.transaction_with(|state| operation(state).map_err(Error::from))
    }

    /// Include backend lifetime checks in the same loaded-state transaction.
    /// A callback error publishes nothing. Native backends can preserve their
    /// own I/O and identity errors without loading and decoding state twice.
    pub fn transaction_with<T, E: From<Error>>(
        &mut self,
        operation: impl FnOnce(&mut Authority) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut latest = self.latest().map_err(E::from)?;
        let configuration = latest.authority.config();
        let result = operation(&mut latest.authority)?;
        if latest.authority.config() != configuration {
            return Err(Error::Incompatible.into());
        }
        let next = latest.sequence.checked_add(1).ok_or(Error::SequenceExhausted).map_err(E::from)?;
        self.publish(next, &latest.authority).map_err(E::from)?;
        Ok(result)
    }

    fn publish(&mut self, sequence: u64, authority: &Authority) -> Result<(), Error> {
        let payload = authority.encode()?;
        if payload.len() > self.capacity as usize || authority.ledger().generation() != self.generation {
            return Err(Error::Malformed);
        }
        let slot = (sequence - 1) % 2;
        let offset = self.offset(slot);
        let mut header = Writer::new(SLOT_HEADER as usize).map_err(AuthorityError::from)?;
        header.u8(PREPARING);
        header.bytes(&[0; 7]);
        header.u64(sequence);
        header.u32(payload.len() as u32);
        header.bytes(&[0; 4]);
        header.u64(digest(self.generation, sequence, &payload));
        // Invalidate the old inactive commit before touching any of its data.
        self.write_at(offset, &[PREPARING])?;
        self.storage.flush()?;
        self.write_at(offset + 1, &header.0[1..])?;
        self.write_at(offset + SLOT_HEADER, &payload)?;
        self.storage.flush()?;
        // Only this final one-byte decision permits publication/dispatch.
        self.write_at(offset, &[COMMITTED])?;
        self.storage.flush()?;
        Ok(())
    }

    pub fn into_inner(self) -> S {
        self.storage
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
    pub(crate) fn storage(&self) -> &S {
        &self.storage
    }
}

fn digest(generation: Generation, sequence: u64, bytes: &[u8]) -> u64 {
    // Length and authority/transaction identity are bound to the payload.
    let prefix = generation.0.into_iter().chain(sequence.to_le_bytes()).chain((bytes.len() as u64).to_le_bytes());
    prefix
        .chain(bytes.iter().copied())
        .fold(0xcbf2_9ce4_8422_2325, |hash, byte| (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::HostConfig;
    use crate::coordination::authority::{Config, Origin, Request};
    use crate::coordination::protocol::{OperationId, VERSION, Work};

    struct Device {
        bytes: Cursor<Vec<u8>>,
        remaining: usize,
        written: usize,
    }

    impl Read for Device {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.bytes.read(bytes)
        }
    }

    impl Seek for Device {
        fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
            self.bytes.seek(at)
        }
    }

    impl Write for Device {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::other("injected process interruption"));
            }
            let count = bytes.len().min(self.remaining);
            self.bytes.write_all(&bytes[..count])?;
            self.remaining -= count;
            self.written += count;
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn fixture() -> (Vec<u8>, OperationId) {
        let config = Config::from_host(&HostConfig::default(), 4, 16, 8).unwrap();
        let mut authority = Authority::new(Generation([1; 16]), config, 0).unwrap();
        let participant = authority.join(VERSION).unwrap();
        let id = authority.ledger().next_operation(participant).unwrap();
        authority
            .prepare(
                id,
                Request {
                    work: Work::Bootstrap,
                    origin: Origin::Background,
                    domain: None,
                    required: 1,
                    desired: 0,
                    ceiling_ns: u64::MAX,
                },
                0,
            )
            .unwrap();
        let journal = Journal::create(Cursor::new(Vec::new()), &authority).unwrap();
        (journal.into_inner().into_inner(), id)
    }

    #[test]
    fn interruption_after_every_written_byte_recovers_whole_ownership_and_accounting() {
        let (bytes, id) = fixture();
        let device = Device { bytes: Cursor::new(bytes.clone()), remaining: usize::MAX, written: 0 };
        let mut complete = Journal::open(device).unwrap();
        complete.transaction(|authority| authority.authorize(id, 0)).unwrap();
        let total = complete.into_inner().written;
        for limit in 0..total {
            let device = Device { bytes: Cursor::new(bytes.clone()), remaining: limit, written: 0 };
            let mut interrupted = Journal::open(device).unwrap();
            assert!(interrupted.transaction(|authority| authority.authorize(id, 0)).is_err(), "cut {limit}");
            let persisted = interrupted.into_inner().bytes;
            let mut recovered = Journal::open(persisted).unwrap();
            let state = recovered.load().unwrap_or_else(|error| panic!("cut {limit}: {error}"));
            let view = state.view();
            match view.physical {
                0 => {
                    assert_eq!(view.charged_ns, 0, "cut {limit}");
                    assert_eq!(view.prepared, 1);
                }
                1 => {
                    assert_eq!(view.charged_ns, 20_000_000, "cut {limit}");
                    assert_eq!(view.prepared, 0);
                }
                _ => panic!("unexpected occupancy"),
            }
            // Retry after recovery: never charge or occupy a second time.
            recovered.transaction(|authority| authority.authorize(id, 0)).unwrap();
            let state = recovered.load().unwrap();
            assert_eq!(state.view().physical, 1);
            assert_eq!(state.view().charged_ns, 20_000_000);
        }
    }

    #[test]
    fn committed_corruption_never_falls_back_to_the_older_budget() {
        let (bytes, id) = fixture();
        let mut journal = Journal::open(Cursor::new(bytes)).unwrap();
        journal.transaction(|authority| authority.authorize(id, 0)).unwrap();
        let offset = journal.offset(1) + SLOT_HEADER;
        let mut bytes = journal.into_inner().into_inner();
        bytes[offset as usize + 10] ^= 1;
        let mut reopened = Journal::open(Cursor::new(bytes)).unwrap();
        assert!(matches!(reopened.load(), Err(Error::Malformed)));
    }

    #[test]
    fn cached_validation_still_checks_old_and_latest_payload_bytes() {
        for slot in [0, 1] {
            let (bytes, id) = fixture();
            let mut journal = Journal::open(Cursor::new(bytes)).unwrap();
            journal.transaction(|authority| authority.authorize(id, 0)).unwrap();
            if slot == 1 {
                journal.load().unwrap();
            }
            assert_eq!(journal.validated.as_ref().unwrap().sequence, slot + 1);
            let offset = journal.offset(slot);
            let length = journal.validated.as_ref().unwrap().payload.len();
            let payload_start = (offset + SLOT_HEADER) as usize;
            // Change a cached state's protocol version and repair both
            // checksums. Even a well-framed payload must be decoded
            // when any byte changes.
            let bytes = journal.storage.get_mut();
            let payload = &mut bytes[payload_start..payload_start + length];
            payload[12..16].copy_from_slice(&(VERSION + 1).to_le_bytes());
            let sum = checksum(&payload[..length - 8]);
            payload[length - 8..].copy_from_slice(&sum.to_le_bytes());
            let sum = digest(journal.generation, slot + 1, payload);
            bytes[offset as usize + 24..offset as usize + 32].copy_from_slice(&sum.to_le_bytes());
            assert!(matches!(journal.load(), Err(Error::State(_))));
        }
    }

    #[test]
    fn cached_validation_never_reuses_mutated_or_other_writers_accounting() {
        let (bytes, id) = fixture();
        let mut reader = Journal::open(Cursor::new(bytes)).unwrap();
        let mut state = reader.load().unwrap();
        state.authorize(id, 0).unwrap();
        assert_eq!(reader.load().unwrap().view().physical, 0, "returned authority is independent of the cache");

        let mut writer = Journal::open(reader.storage.clone()).unwrap();
        writer.transaction(|authority| authority.authorize(id, 0)).unwrap();
        reader.storage = writer.into_inner();
        let current = reader.load().unwrap();
        assert_eq!(current.view().physical, 1);
        assert_eq!(current.view().charged_ns, 20_000_000);
        assert_eq!(reader.load().unwrap().encode().unwrap(), current.encode().unwrap());
    }

    #[test]
    fn settlement_interruption_during_slot_reuse_does_not_forget_occupancy_or_debt() {
        use crate::coordination::protocol::Progress;
        let (bytes, id) = fixture();
        let mut journal = Journal::open(Cursor::new(bytes)).unwrap();
        journal.transaction(|authority| authority.authorize(id, 0)).unwrap();
        let bytes = journal.into_inner().into_inner();
        let progress = Progress { revision: 1, operations: 1, elapsed_ns: 40_000_000, failed: true };
        let finish = |authority: &mut Authority| authority.settle(id, progress, 40_000_000);
        let device = Device { bytes: Cursor::new(bytes.clone()), remaining: usize::MAX, written: 0 };
        let mut complete = Journal::open(device).unwrap();
        complete.transaction(finish).unwrap();
        let total = complete.into_inner().written;
        for limit in 0..total {
            let device = Device { bytes: Cursor::new(bytes.clone()), remaining: limit, written: 0 };
            let mut interrupted = Journal::open(device).unwrap();
            assert!(interrupted.transaction(finish).is_err(), "cut {limit}");
            let mut recovered = Journal::open(interrupted.into_inner().bytes).unwrap();
            let view = recovered.load().unwrap_or_else(|error| panic!("cut {limit}: {error}")).view();
            match view.physical {
                1 => {
                    assert_eq!(view.charged_ns, 20_000_000);
                    assert_eq!(view.surcharged_ns, 0);
                }
                0 => {
                    assert_eq!(view.charged_ns, 40_000_000);
                    assert_eq!(view.surcharged_ns, 20_000_000);
                }
                _ => panic!("unexpected physical count"),
            }
            recovered.transaction(finish).unwrap();
            let view = recovered.load().unwrap().view();
            assert_eq!(view.physical, 0);
            assert_eq!(view.charged_ns, 40_000_000);
            assert_eq!(view.surcharged_ns, 20_000_000);
        }
    }

    #[test]
    fn existing_objects_cannot_be_reinitialized() {
        let (bytes, _) = fixture();
        let mut journal = Journal::open(Cursor::new(bytes.clone())).unwrap();
        let authority = journal.load().unwrap();
        assert!(matches!(Journal::create(Cursor::new(bytes), &authority), Err(Error::Malformed)));
    }
}
