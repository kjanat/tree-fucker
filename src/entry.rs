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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
}

impl Default for MetadataFields {
    fn default() -> Self {
        MetadataFields { modified: true, created: false, size: true, permissions: false }
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
