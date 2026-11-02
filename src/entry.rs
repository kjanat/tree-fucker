//! This module defines the record a snapshot stores for each path.
//!
//! An [`Entry`] carries every field of RFC §7.1. [`Shape`]
//! couples the entry kind with the directory load state of RFC §7.2, and
//! only directories carry a load state.

use std::time::SystemTime;

use crate::ids::{EntryGeneration, EntryId};
use crate::path::RelativePath;

/// `EntryKind` names the kind of filesystem object behind an entry (RFC §10.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// The entry is a regular file.
    File,
    /// The entry is a directory.
    Directory,
    /// The entry is a symbolic link.
    ///
    /// The tree represents the link and never follows it (RFC §14.2).
    Symlink,
    /// The entry is a socket, device, FIFO or other special file (RFC §14.4).
    Other,
}

/// `LoadState` gives the load state of a directory entry (RFC §7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LoadState {
    /// The tree knows the directory, omits its children and never reconciles
    /// it.
    Unloaded,
    /// The directory awaits its first accepted listing, and the tree omits its
    /// children.
    Loading,
    /// The tree represents the children, and every reconciliation round lists
    /// the directory.
    Loaded,
    /// Policy excludes the descendants, and the tree still represents the
    /// directory.
    Excluded,
}

/// `Shape` combines the entry kind with the load state of a directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Shape {
    /// The entry is a regular file.
    File,
    /// The entry is a directory in the given load state.
    Directory(LoadState),
    /// The entry is a symbolic link.
    Symlink,
    /// The entry is a special file.
    Other,
}

impl Shape {
    /// `kind` returns the entry kind without the load state.
    pub fn kind(self) -> EntryKind {
        match self {
            Shape::File => EntryKind::File,
            Shape::Directory(_) => EntryKind::Directory,
            Shape::Symlink => EntryKind::Symlink,
            Shape::Other => EntryKind::Other,
        }
    }

    /// `load_state` returns the load state of a directory, or `None` for other
    /// kinds.
    pub fn load_state(self) -> Option<LoadState> {
        match self {
            Shape::Directory(state) => Some(state),
            _ => None,
        }
    }

    /// `from_kind` builds a shape from `kind`.
    ///
    /// It applies `load_state` only when `kind` is a directory.
    pub fn from_kind(kind: EntryKind, load_state: LoadState) -> Shape {
        match kind {
            EntryKind::File => Shape::File,
            EntryKind::Directory => Shape::Directory(load_state),
            EntryKind::Symlink => Shape::Symlink,
            EntryKind::Other => Shape::Other,
        }
    }
}

/// `Metadata` holds the configured metadata of an entry (RFC §5.4).
///
/// A field is `None` when the configuration disables it or the adapter
/// cannot supply it. Metadata never proves directory contents unchanged,
/// and equal modification times must not suppress a listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Metadata {
    /// `modified` holds the last modification time.
    pub modified: Option<SystemTime>,
    /// `created` holds the creation time.
    pub created: Option<SystemTime>,
    /// `size` holds the size in bytes.
    pub size: Option<u64>,
    /// `permissions` holds the permission bits from the adapter.
    ///
    /// These bits carry no ACL and no effective-access decision. An adapter
    /// returns `None` when permission bits have no meaning on its platform
    /// (RFC §5.4).
    pub permissions: Option<u32>,
}

impl Metadata {
    /// `project` keeps the fields in `fields` and sets the rest to `None`.
    pub fn project(&self, fields: MetadataFields) -> Metadata {
        Metadata {
            modified: if fields.modified { self.modified } else { None },
            created: if fields.created { self.created } else { None },
            size: if fields.size { self.size } else { None },
            permissions: if fields.permissions { self.permissions } else { None },
        }
    }

    /// `merged` copies the fields in `fields` from `supplied` and keeps the
    /// rest of `self`.
    pub fn merged(&self, supplied: Metadata, fields: MetadataFields) -> Metadata {
        Metadata {
            modified: if fields.modified { supplied.modified } else { self.modified },
            created: if fields.created { supplied.created } else { self.created },
            size: if fields.size { supplied.size } else { self.size },
            permissions: if fields.permissions { supplied.permissions } else { self.permissions },
        }
    }
}

/// `MetadataFields` selects a set of [`Metadata`] fields with one flag per
/// field.
///
/// The configuration uses it to enable enrichment fields (RFC §10.1). The
/// default value enables none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MetadataFields {
    /// `modified` selects [`Metadata::modified`].
    pub modified: bool,
    /// `created` selects [`Metadata::created`].
    pub created: bool,
    /// `size` selects [`Metadata::size`].
    pub size: bool,
    /// `permissions` selects [`Metadata::permissions`].
    pub permissions: bool,
}

impl MetadataFields {
    /// `NONE` selects no field.
    pub const NONE: MetadataFields =
        MetadataFields { modified: false, created: false, size: false, permissions: false };
    /// `ALL` selects every field.
    pub const ALL: MetadataFields = MetadataFields { modified: true, created: true, size: true, permissions: true };

    /// `any` reports whether the set selects at least one field.
    pub const fn any(self) -> bool {
        self.modified || self.created || self.size || self.permissions
    }

    /// `intersect` returns the intersection of both sets.
    pub const fn intersect(self, other: MetadataFields) -> MetadataFields {
        MetadataFields {
            modified: self.modified && other.modified,
            created: self.created && other.created,
            size: self.size && other.size,
            permissions: self.permissions && other.permissions,
        }
    }

    /// `without` removes the fields of `other` from `self` and returns the
    /// result.
    pub const fn without(self, other: MetadataFields) -> MetadataFields {
        MetadataFields {
            modified: self.modified && !other.modified,
            created: self.created && !other.created,
            size: self.size && !other.size,
            permissions: self.permissions && !other.permissions,
        }
    }
}

/// `FileIdentity` identifies a filesystem object within the identity space of
/// its storage domain.
///
/// Two identities compare meaningfully only when both domains declare the
/// same identity space (RFC §7.1). An identity establishes a rename only
/// when both domains declare stable identity, as
/// [`crate::domain::DomainCapabilities::establishes_rename`] checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    /// `device` holds the device number on Unix or the volume serial number on
    /// Windows.
    pub device: u64,
    /// `inode` holds the inode number on Unix or the 128-bit file identifier on
    /// Windows.
    pub inode: u128,
}

/// `Entry` represents one filesystem object in a snapshot (RFC §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// `id` identifies the entry for the lifetime of the tree.
    pub id: EntryId,
    /// `path` holds the normalized path below the root in display casing.
    pub path: RelativePath,
    /// `shape` holds the kind and, for a directory, the load state.
    pub shape: Shape,
    /// `metadata` holds the configured metadata.
    pub metadata: Metadata,
    /// `identity` holds the filesystem identity when the storage domain
    /// supplies one.
    pub identity: Option<FileIdentity>,
    /// `generation` advances when the path binding or kind of this entry
    /// changes (RFC §11.4).
    pub generation: EntryGeneration,
}

impl Entry {
    /// `kind` returns the entry kind.
    pub fn kind(&self) -> EntryKind {
        self.shape.kind()
    }

    /// `load_state` returns the load state of a directory, or `None` for other
    /// kinds.
    pub fn load_state(&self) -> Option<LoadState> {
        self.shape.load_state()
    }

    /// `is_directory` reports whether the entry is a directory in any load
    /// state.
    pub fn is_directory(&self) -> bool {
        matches!(self.shape, Shape::Directory(_))
    }

    /// `is_loaded` reports whether the entry is a directory in
    /// [`LoadState::Loaded`].
    pub fn is_loaded(&self) -> bool {
        self.shape == Shape::Directory(LoadState::Loaded)
    }

    /// `depth` returns the number of path components; the root has depth 0.
    pub fn depth(&self) -> usize {
        self.path.depth()
    }
}

/// `entry_bytes` estimates the snapshot memory of one entry in bytes.
///
/// A snapshot sums this estimate over its entries, and the tree compares
/// the sum with [`crate::config::Config::snapshot_bytes`].
pub fn entry_bytes(entry: &Entry) -> u64 {
    let path: usize = entry.path.components().iter().map(|name| name.len()).sum();
    u64::try_from(std::mem::size_of::<Entry>() + path).unwrap_or(u64::MAX)
}

/// `CollisionKey` orders candidates when several names fold to one
/// [`crate::path::PathKey`].
///
/// Several names can collide under a case-insensitive rule. The tree then
/// keeps the candidate with the smallest key and drops the others. The
/// tuple compares name bytes first, then [`kind_rank`] and identity. It
/// compares modification time, creation time, size and permissions last.
pub type CollisionKey<'a> = (
    &'a std::ffi::OsStr,
    u8,
    Option<(u64, u128)>,
    Option<std::time::SystemTime>,
    Option<std::time::SystemTime>,
    Option<u64>,
    Option<u32>,
);

/// `kind_rank` ranks kinds for [`CollisionKey`].
///
/// A directory ranks first, then a file, a symbolic link and a special
/// file.
pub fn kind_rank(kind: EntryKind) -> u8 {
    match kind {
        EntryKind::Directory => 0,
        EntryKind::File => 1,
        EntryKind::Symlink => 2,
        EntryKind::Other => 3,
    }
}

/// `collision_key` builds the [`CollisionKey`] of one candidate.
pub fn collision_key<'a>(
    name: &'a std::ffi::OsStr,
    kind: EntryKind,
    metadata: &Metadata,
    identity: Option<FileIdentity>,
) -> CollisionKey<'a> {
    (
        name,
        kind_rank(kind),
        identity.map(|id| (id.device, id.inode)),
        metadata.modified,
        metadata.created,
        metadata.size,
        metadata.permissions,
    )
}
