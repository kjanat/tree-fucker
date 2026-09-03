use std::fmt;

macro_rules! counter_type {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(u64);

        impl $name {
            pub const fn new(value: u64) -> Self {
                $name(value)
            }

            pub const fn get(self) -> u64 {
                self.0
            }

            pub const fn next(self) -> Self {
                $name(self.0 + 1)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

counter_type!(EntryId);
counter_type!(SnapshotVersion);
counter_type!(Sequence);
counter_type!(ReconciliationGeneration);
counter_type!(LoadGeneration);
counter_type!(EntryGeneration);
counter_type!(PolicyRevision);
counter_type!(PolicyFence);
counter_type!(ContextGeneration);
counter_type!(ChildStateGeneration);
counter_type!(StateGeneration);
counter_type!(ChangeEpoch);
counter_type!(RootIncarnation);
counter_type!(CommandId);
counter_type!(JobId);
counter_type!(WatchId);
counter_type!(WatchRequestId);
counter_type!(TimerId);

#[derive(Clone, Copy, Debug, Default)]
pub struct IdHasher(u64);

impl std::hash::Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = (self.0 ^ value).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }

    fn write_u32(&mut self, value: u32) {
        self.write_u64(u64::from(value));
    }

    fn write_usize(&mut self, value: usize) {
        self.write_u64(u64::try_from(value).unwrap_or(u64::MAX));
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IdHashing;

impl std::hash::BuildHasher for IdHashing {
    type Hasher = IdHasher;

    fn build_hasher(&self) -> IdHasher {
        IdHasher::default()
    }
}

pub type IdMap<K, V> = std::collections::HashMap<K, V, IdHashing>;
pub type SharedIdMap<K, V> = imbl::GenericHashMap<K, V, IdHashing, imbl::shared_ptr::DefaultSharedPtr>;
