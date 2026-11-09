//! This module defines the typed `u64` identifiers, generations and counters of
//! a tree.
//!
//! Each type wraps one `u64`, orders by its value and advances with
//! `next`. A job captures generations at dispatch, and its publication
//! guards compare them with the current generations (RFC §11.4).
//! [`IdMap`] and [`SharedIdMap`] key maps by these types and hash them
//! with [`IdHashing`].

use std::fmt;

macro_rules! counter_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(u64);

        impl $name {
            /// `new` wraps a raw value.
            pub const fn new(value: u64) -> Self {
                $name(value)
            }

            /// `get` returns the raw value.
            pub const fn get(self) -> u64 {
                self.0
            }

            /// `next` returns the value one greater than `self`.
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

counter_type!(
    /// `EntryId` identifies one entry for the lifetime of a tree instance.
    ///
    /// A tree never reuses an `EntryId` during its lifetime (RFC §7.1). A
    /// rename keeps the id only when the storage domain supplies stable
    /// identity. Consumers must also accept a rename as a removal plus an
    /// addition.
    EntryId
);
counter_type!(
    /// `SnapshotVersion` orders published snapshots.
    ///
    /// Updates arrive in snapshot version order (RFC §7.4).
    SnapshotVersion
);
counter_type!(
    /// `Sequence` holds a value from the coordinator-wide monotonic sequence
    /// (RFC §2).
    ///
    /// The coordinator takes each accepted command's causal barrier and each
    /// admitted job's dispatch generation from this sequence. A read
    /// satisfies barrier `B` only when its dispatch generation exceeds `B`
    /// (RFC §9).
    Sequence
);
counter_type!(
    /// `ReconciliationGeneration` tags coverage for a reconciliation round (RFC
    /// §11.4).
    ///
    /// The coordinator allocates a new value when a round begins. A
    /// mismatch keeps a result from satisfying round, overflow or
    /// watcher-restart coverage for a newer generation. The result can
    /// still commit.
    ReconciliationGeneration
);
counter_type!(
    /// `LoadGeneration` versions the load state of a directory (RFC §11.4).
    ///
    /// It advances on every transition among Loading, Loaded, Unloaded and
    /// Excluded. It guards directory jobs and keys round obligations
    /// (RFC §2). The tree counts every load of a directory.
    LoadGeneration
);
counter_type!(
    /// `EntryGeneration` versions the path binding and kind of an entry (RFC
    /// §11.4).
    ///
    /// It advances when the path-to-[`EntryId`] binding or the kind of the
    /// entry changes. A directory rename advances it on every moved binding
    /// (RFC §7.4). It guards every job for the entry.
    EntryGeneration
);
counter_type!(
    /// `PolicyRevision` versions the scan policy (RFC §8).
    ///
    /// It advances when the consumer invalidates policy.
    PolicyRevision
);
counter_type!(
    /// `PolicyFence` marks the revision fence of policy invalidation (RFC §8).
    ///
    /// The coordinator advances it on each accepted policy invalidation, and
    /// jobs capture it at dispatch. A result from before the current fence
    /// must not commit within the invalidated scope.
    PolicyFence
);
counter_type!(
    /// `ContextGeneration` versions the policy context of a directory (RFC §8,
    /// §11.4).
    ///
    /// It advances when the policy context for the directory's children
    /// changes.
    ContextGeneration
);
counter_type!(
    /// `ChildStateGeneration` holds the child-binding generation of a directory
    /// (RFC §2, §11.4).
    ///
    /// It versions the mapping from immediate-child names to [`EntryId`]s.
    /// It advances when the directory gains, loses, replaces or renames an
    /// immediate child.
    ChildStateGeneration
);
counter_type!(
    /// `StateGeneration` holds the target-state generation of an entry (RFC §2,
    /// §11.4).
    ///
    /// It versions the entry's publication domain. That domain covers the
    /// binding and path, kind, configured metadata and load state of the
    /// entry. It also covers the immediate children of the entry. A listing
    /// of the entry reconciles those children.
    StateGeneration
);
counter_type!(
    /// `ChangeEpoch` versions a listing or metadata target (RFC §11.2).
    ///
    /// It advances for every accepted watcher hint and every explicit
    /// invalidation. A job is stale when its captured epoch is older at
    /// completion.
    ChangeEpoch
);
counter_type!(
    /// `RootIncarnation` holds the root-incarnation generation (RFC §2, §7.4).
    ///
    /// It advances each time the coordinator confirms that a missing root
    /// has reappeared. Every reappearance gets its own number.
    RootIncarnation
);
counter_type!(
    /// `CommandId` identifies one consumer command to a tree.
    CommandId
);
counter_type!(
    /// `JobId` identifies one admitted filesystem job.
    JobId
);
counter_type!(
    /// `WatchId` identifies an active watch.
    ///
    /// [`crate::fs::FileSystem::watch`] returns it, and
    /// [`crate::fs::FileSystem::unwatch`] takes it to remove the watch.
    WatchId
);
counter_type!(
    /// `WatchRequestId` identifies one pending watch registration request.
    WatchRequestId
);
counter_type!(
    /// `WatchReleaseId` identifies one pending watch removal.
    WatchReleaseId
);
counter_type!(
    /// `TimerId` identifies one armed coordinator timer.
    ///
    /// The coordinator acts only on the most recently armed id and ignores
    /// earlier ones.
    TimerId
);

/// `IdHasher` hashes the identifier types of this module.
///
/// It mixes each word with one multiplication. Callers must hash only
/// crate-allocated keys with it. Caller-chosen keys can force collisions.
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

/// `IdHashing` builds [`IdHasher`] instances for [`IdMap`] and [`SharedIdMap`].
#[derive(Clone, Copy, Debug, Default)]
pub struct IdHashing;

impl std::hash::BuildHasher for IdHashing {
    type Hasher = IdHasher;

    fn build_hasher(&self) -> IdHasher {
        IdHasher::default()
    }
}

/// `IdMap` is a mutable hash map that hashes identifier keys with
/// [`IdHashing`].
pub type IdMap<K, V> = std::collections::HashMap<K, V, IdHashing>;
/// `SharedIdMap` is a persistent hash map that hashes identifier keys with
/// [`IdHashing`].
///
/// Its clones share structure.
pub type SharedIdMap<K, V> = imbl::GenericHashMap<K, V, IdHashing, imbl::shared_ptr::DefaultSharedPtr>;
