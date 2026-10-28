//! One persisted mapping from a boot-qualified counter to authority time.

use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClockBinding {
    pub epoch: [u8; 32],
    pub offset_ns: i64,
}

impl ClockBinding {
    pub(crate) fn checked(epoch: [u8; 32], offset_ns: i64) -> io::Result<Self> {
        if epoch == [0; 32] {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty coordination clock epoch"));
        }
        Ok(Self { epoch, offset_ns })
    }

    #[cfg(any(windows, test))]
    pub(crate) fn from_origin(epoch: [u8; 32], raw_ns: u64, logical_ns: u64) -> io::Result<Self> {
        let offset = i64::try_from(i128::from(logical_ns) - i128::from(raw_ns))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "coordination clock offset is out of range"))?;
        Self::checked(epoch, offset)
    }

    #[cfg(any(windows, test))]
    pub(crate) fn at(self, raw_ns: u64) -> io::Result<u64> {
        u64::try_from(i128::from(raw_ns) + i128::from(self.offset_ns))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "coordination logical clock is out of range"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reboot_binding_uses_retained_time_when_new_counter_is_larger() {
        let binding = ClockBinding::from_origin([1; 32], 50_000, 12_000).unwrap();
        assert_eq!(binding.offset_ns, -38_000);
        assert_eq!(binding.at(50_000).unwrap(), 12_000);
        assert_eq!(binding.at(51_000).unwrap(), 13_000);
    }

    #[test]
    fn persisted_binding_preserves_elapsed_time_across_reopening() {
        for raw in [925, 50_000] {
            let binding = ClockBinding::from_origin([1; 32], raw, 12_000).unwrap();
            for elapsed in [0, 1, 1_000, 10_000_000_000] {
                let reopened = ClockBinding::checked(binding.epoch, binding.offset_ns).unwrap();
                assert_eq!(reopened.at(raw + elapsed).unwrap(), 12_000 + elapsed);
            }
        }
    }

    #[test]
    fn invalid_binding_and_overflow_fail_without_saturating_time() {
        assert!(ClockBinding::checked([0; 32], 0).is_err());
        assert!(ClockBinding::from_origin([1; 32], 0, u64::MAX).is_err());
        assert!(ClockBinding::from_origin([1; 32], u64::MAX, 0).is_err());
        assert!(ClockBinding::checked([1; 32], -1).unwrap().at(0).is_err());
        assert!(ClockBinding::checked([1; 32], 1).unwrap().at(u64::MAX).is_err());
        let binding = ClockBinding::from_origin([1; 32], 1u64 << 63, 0).unwrap();
        assert_eq!(binding.offset_ns, i64::MIN);
        assert_eq!(binding.at(1u64 << 63).unwrap(), 0);
    }
}
