//! Boot-qualified performance-counter time for cooperating processes.

use std::io;

use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
use windows_sys::Wdk::System::SystemServices::KUSER_SHARED_DATA;
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

use super::ClockBinding;

const BOOT_ENVIRONMENT: i32 = 90;

#[repr(C)]
#[derive(Default)]
struct BootEnvironment {
    entry: [u8; 16],
    firmware: u32,
    reserved: u32,
    flags: u64,
}

const _: () = assert!(size_of::<BootEnvironment>() == 32);
const _: () = assert!(std::mem::offset_of!(KUSER_SHARED_DATA, BootId) == 0x2c4);

/// The entry GUID is not a per-boot nonce. The loader's boot sequence is also
/// required. Neither value selects a new rendezvous or resets retained debt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Epoch {
    pub entry: [u8; 16],
    pub sequence: u32,
    pub frequency: u64,
}

impl Epoch {
    fn checked(entry: [u8; 16], sequence: u32, frequency: u64) -> io::Result<Self> {
        if entry == [0; 16] || sequence == 0 || sequence == u32::MAX || frequency == 0 || frequency > i64::MAX as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid Windows clock epoch"));
        }
        Ok(Self { entry, sequence, frequency })
    }

    pub(crate) fn encode(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&self.entry);
        bytes[16..20].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[24..].copy_from_slice(&self.frequency.to_le_bytes());
        bytes
    }

    pub(crate) fn decode(bytes: [u8; 32]) -> io::Result<Self> {
        if bytes[20..24] != [0; 4] {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid Windows epoch reserved bytes"));
        }
        Self::checked(
            bytes[..16].try_into().expect("entry"),
            u32::from_le_bytes(bytes[16..20].try_into().expect("sequence")),
            u64::from_le_bytes(bytes[24..].try_into().expect("frequency")),
        )
    }

    pub(crate) fn require_counter(self, retained: Self) -> io::Result<()> {
        if self.frequency != retained.frequency {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "retained coordination clock uses a different performance counter",
            ));
        }
        Ok(())
    }

    fn nanos(self, ticks: i64) -> io::Result<u64> {
        let ticks = u64::try_from(ticks)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative performance counter"))?;
        u64::try_from(u128::from(ticks) * 1_000_000_000 / u128::from(self.frequency))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "performance counter exceeds nanosecond range"))
    }
}

pub(crate) struct Clock {
    pub epoch: Epoch,
    binding: ClockBinding,
}

impl Clock {
    pub(crate) fn current() -> io::Result<Self> {
        let mut information = BootEnvironment::default();
        let mut length = 0;
        // SAFETY: exact Windows 8+ SYSTEM_BOOT_ENVIRONMENT_INFORMATION layout,
        // aligned live output and a checked returned size. This query is never
        // replaced with a random ID or a wall-clock approximation on failure.
        let status = unsafe {
            NtQuerySystemInformation(
                BOOT_ENVIRONMENT,
                (&mut information as *mut BootEnvironment).cast(),
                size_of::<BootEnvironment>() as u32,
                &mut length,
            )
        };
        if status != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Windows boot environment query failed: NTSTATUS {status:#x}"),
            ));
        }
        if length as usize != size_of::<BootEnvironment>() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected Windows boot environment layout"));
        }
        // SAFETY: Windows maps the read-only shared-user page at this fixed
        // user-mode address. Read only the aligned BootId field, whose offset
        // is checked against the SDK type above; do not borrow the whole page.
        let sequence =
            unsafe { std::ptr::addr_of!((*(0x7ffe_0000usize as *const KUSER_SHARED_DATA)).BootId).read_volatile() };
        let mut frequency = 0;
        // SAFETY: live correctly sized output for the boot-constant frequency.
        if unsafe { QueryPerformanceFrequency(&mut frequency) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let frequency = u64::try_from(frequency)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative performance counter frequency"))?;
        let epoch = Epoch::checked(information.entry, sequence, frequency)?;
        Ok(Self { epoch, binding: ClockBinding::checked(epoch.encode(), 0)? })
    }

    fn raw_now(&self) -> io::Result<u64> {
        let mut ticks = 0;
        // SAFETY: live correctly sized output; no process-relative origin or
        // floating-point conversion is introduced into shared timestamps.
        if unsafe { QueryPerformanceCounter(&mut ticks) } == 0 {
            return Err(io::Error::last_os_error());
        }
        self.epoch.nanos(ticks)
    }

    pub(crate) fn now(&self) -> io::Result<u64> {
        let raw = self.raw_now()?;
        self.binding.at(raw)
    }

    pub(crate) fn binding(&self) -> ClockBinding {
        self.binding
    }

    /// Choose once under bookkeeping exclusion, then publish in the journal.
    pub(crate) fn retained_binding(
        &self,
        retained: Option<ClockBinding>,
        creation_epoch: Epoch,
        logical_now: u64,
    ) -> io::Result<ClockBinding> {
        let epoch = match retained {
            Some(binding) => Epoch::decode(binding.epoch)?,
            None => creation_epoch,
        };
        self.epoch.require_counter(epoch)?;
        if epoch == self.epoch {
            Ok(retained.unwrap_or(self.binding))
        } else {
            ClockBinding::from_origin(self.epoch.encode(), self.raw_now()?, logical_now)
        }
    }

    /// Bind before the connection is shared. Transactions never move its
    /// origin.
    pub(crate) fn bind(&mut self, binding: ClockBinding) -> io::Result<()> {
        if Epoch::decode(binding.epoch)? != self.epoch {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "coordination clock epoch changed"));
        }
        binding.at(self.raw_now()?)?;
        self.binding = binding;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_epoch_checks_counter_compatibility_and_malformed_headers() {
        let epoch = Epoch::checked([1; 16], 7, 10_000_000).unwrap();
        assert_eq!(Epoch::decode(epoch.encode()).unwrap(), epoch);
        epoch.require_counter(epoch).unwrap();
        Epoch { sequence: 8, ..epoch }.require_counter(epoch).unwrap();
        Epoch { entry: [2; 16], ..epoch }.require_counter(epoch).unwrap();
        assert!(
            matches!(Epoch { frequency: 1, ..epoch }.require_counter(epoch), Err(error) if error.kind() == io::ErrorKind::InvalidData)
        );
        for other in [
            Epoch { sequence: 0, ..epoch },
            Epoch { sequence: u32::MAX, ..epoch },
            Epoch { entry: [0; 16], ..epoch },
            Epoch { frequency: 0, ..epoch },
            Epoch { frequency: u64::MAX, ..epoch },
        ] {
            assert!(Epoch::decode(other.encode()).is_err());
        }
        let mut reserved = epoch.encode();
        reserved[20] = 1;
        assert!(Epoch::decode(reserved).is_err());
    }

    #[test]
    fn clock_conversion_is_integer_checked_and_keeps_subsecond_precision() {
        let epoch = Epoch::checked([1; 16], 7, 3).unwrap();
        assert_eq!(epoch.nanos(0).unwrap(), 0);
        assert_eq!(epoch.nanos(1).unwrap(), 333_333_333);
        assert_eq!(epoch.nanos(3).unwrap(), 1_000_000_000);
        assert!(epoch.nanos(-1).is_err());
        assert!(epoch.nanos(i64::MAX).is_err());
        let fine = Epoch::checked([1; 16], 7, 10_000_000).unwrap();
        assert_eq!(fine.nanos(123_456_789).unwrap(), 12_345_678_900);
    }

    #[test]
    fn native_clock_epoch_is_stable_across_connections_and_threads() {
        let first = Clock::current().unwrap();
        let before = first.now().unwrap();
        let retained = first.epoch;
        for _ in 0..8 {
            std::thread::spawn(move || {
                let clock = Clock::current().unwrap();
                clock.epoch.require_counter(retained).unwrap();
                assert!(clock.now().unwrap() >= before);
            })
            .join()
            .unwrap();
        }
        assert!(first.now().unwrap() >= before);
    }

    #[test]
    fn native_clock_rebase_continues_from_retained_logical_time() {
        let mut clock = Clock::current().unwrap();
        let retained = clock.now().unwrap().saturating_add(60_000_000_000);
        let binding = ClockBinding::from_origin(clock.epoch.encode(), clock.raw_now().unwrap(), retained).unwrap();
        clock.bind(binding).unwrap();
        assert!(clock.now().unwrap() >= retained);
        assert_eq!(clock.binding(), binding);
        assert_eq!(clock.retained_binding(Some(binding), clock.epoch, 0).unwrap(), binding);
    }

    #[test]
    fn boot_sequence_changes_preserve_counter_compatibility() {
        let previous = Epoch::checked([1; 16], 7, 10_000_000).unwrap();
        let rebooted = Epoch { sequence: 8, ..previous };
        rebooted.require_counter(previous).unwrap();
        assert!(Epoch { frequency: 1, ..rebooted }.require_counter(previous).is_err());
    }
}
