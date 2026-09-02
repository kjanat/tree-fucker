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
