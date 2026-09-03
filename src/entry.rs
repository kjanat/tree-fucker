use std::time::SystemTime;

use crate::ids::{EntryGeneration, EntryId};
use crate::path::RelativePath;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LoadState {
    Unloaded,
    Loading,
    Loaded,
    Excluded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Shape {
    File,
    Directory(LoadState),
    Symlink,
    Other,
}

impl Shape {
    pub fn kind(self) -> EntryKind {
        match self {
            Shape::File => EntryKind::File,
            Shape::Directory(_) => EntryKind::Directory,
            Shape::Symlink => EntryKind::Symlink,
            Shape::Other => EntryKind::Other,
        }
    }

    pub fn load_state(self) -> Option<LoadState> {
        match self {
            Shape::Directory(state) => Some(state),
            _ => None,
        }
    }

    pub fn from_kind(kind: EntryKind, load_state: LoadState) -> Shape {
        match kind {
            EntryKind::File => Shape::File,
            EntryKind::Directory => Shape::Directory(load_state),
            EntryKind::Symlink => Shape::Symlink,
            EntryKind::Other => Shape::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Metadata {
    pub modified: Option<SystemTime>,
    pub created: Option<SystemTime>,
    pub size: Option<u64>,
    pub permissions: Option<u32>,
}

impl Metadata {
    pub fn project(&self, fields: MetadataFields) -> Metadata {
        Metadata {
            modified: if fields.modified { self.modified } else { None },
            created: if fields.created { self.created } else { None },
            size: if fields.size { self.size } else { None },
            permissions: if fields.permissions { self.permissions } else { None },
        }
    }

    pub fn merged(&self, supplied: Metadata, fields: MetadataFields) -> Metadata {
        Metadata {
            modified: if fields.modified { supplied.modified } else { self.modified },
            created: if fields.created { supplied.created } else { self.created },
            size: if fields.size { supplied.size } else { self.size },
            permissions: if fields.permissions { supplied.permissions } else { self.permissions },
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MetadataFields {
    pub modified: bool,
    pub created: bool,
    pub size: bool,
    pub permissions: bool,
}

impl MetadataFields {
    pub const NONE: MetadataFields =
        MetadataFields { modified: false, created: false, size: false, permissions: false };
    pub const ALL: MetadataFields = MetadataFields { modified: true, created: true, size: true, permissions: true };

    pub const fn any(self) -> bool {
        self.modified || self.created || self.size || self.permissions
    }

    pub const fn intersect(self, other: MetadataFields) -> MetadataFields {
        MetadataFields {
            modified: self.modified && other.modified,
            created: self.created && other.created,
            size: self.size && other.size,
            permissions: self.permissions && other.permissions,
        }
    }

    pub const fn without(self, other: MetadataFields) -> MetadataFields {
        MetadataFields {
            modified: self.modified && !other.modified,
            created: self.created && !other.created,
            size: self.size && !other.size,
            permissions: self.permissions && !other.permissions,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: EntryId,
    pub path: RelativePath,
    pub shape: Shape,
    pub metadata: Metadata,
    pub identity: Option<FileIdentity>,
    pub generation: EntryGeneration,
}

impl Entry {
    pub fn kind(&self) -> EntryKind {
        self.shape.kind()
    }

    pub fn load_state(&self) -> Option<LoadState> {
        self.shape.load_state()
    }

    pub fn is_directory(&self) -> bool {
        matches!(self.shape, Shape::Directory(_))
    }

    pub fn is_loaded(&self) -> bool {
        self.shape == Shape::Directory(LoadState::Loaded)
    }

    pub fn depth(&self) -> usize {
        self.path.depth()
    }
}

pub fn entry_bytes(entry: &Entry) -> u64 {
    let path: usize = entry.path.components().iter().map(|name| name.len()).sum();
    u64::try_from(std::mem::size_of::<Entry>() + path).unwrap_or(u64::MAX)
}

pub type CollisionKey<'a> = (
    &'a std::ffi::OsStr,
    u8,
    Option<(u64, u64)>,
    Option<std::time::SystemTime>,
    Option<std::time::SystemTime>,
    Option<u64>,
    Option<u32>,
);

pub fn kind_rank(kind: EntryKind) -> u8 {
    match kind {
        EntryKind::Directory => 0,
        EntryKind::File => 1,
        EntryKind::Symlink => 2,
        EntryKind::Other => 3,
    }
}

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
