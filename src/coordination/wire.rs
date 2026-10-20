//! Explicit little-endian fields; no native Rust layouts enter shared state.

use super::protocol::Error;

pub(crate) const MAX_STATE_BYTES: usize = 32 * 1024 * 1024;

pub(crate) struct Writer(pub Vec<u8>);

impl Writer {
    pub fn new(capacity: usize) -> Result<Self, Error> {
        if capacity > MAX_STATE_BYTES {
            return Err(Error::MalformedState);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(capacity).map_err(|_| Error::Allocation)?;
        Ok(Self(bytes))
    }

    pub fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }

    pub fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    pub fn u32(&mut self, value: u32) {
        self.bytes(&value.to_le_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.bytes(&value.to_le_bytes());
    }

    pub fn u128(&mut self, value: u128) {
        self.bytes(&value.to_le_bytes());
    }

    pub fn i128(&mut self, value: i128) {
        self.bytes(&value.to_le_bytes());
    }
}

pub(crate) struct Reader<'a>(pub &'a [u8]);

impl Reader<'_> {
    pub fn bytes<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (value, remaining) = self.0.split_at_checked(N).ok_or(Error::MalformedState)?;
        self.0 = remaining;
        Ok(value.try_into().expect("checked size"))
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.bytes::<1>()?[0])
    }

    pub fn boolean(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::MalformedState),
        }
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.bytes()?))
    }

    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.bytes()?))
    }

    pub fn u128(&mut self) -> Result<u128, Error> {
        Ok(u128::from_le_bytes(self.bytes()?))
    }

    pub fn i128(&mut self) -> Result<i128, Error> {
        Ok(i128::from_le_bytes(self.bytes()?))
    }
}

/// Accidental-corruption detection, not authentication of cooperating peers.
pub(crate) fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| (hash ^ u64::from(*byte)).wrapping_mul(0x100_0000_01b3))
}
