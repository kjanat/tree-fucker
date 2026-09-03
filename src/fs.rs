use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::entry::{EntryKind, FileIdentity, Metadata, MetadataFields};
use crate::ids::WatchId;
use crate::path::{CaseSensitivity, RelativePath};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FsError {
    NotFound,
    NotDirectory,
    PermissionDenied,
    Transient(String),
    Unsupported(String),
    Fatal(String),
}

impl FsError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, FsError::PermissionDenied | FsError::Transient(_) | FsError::Unsupported(_))
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsError::NotFound => f.write_str("not found"),
            FsError::NotDirectory => f.write_str("not a directory"),
            FsError::PermissionDenied => f.write_str("permission denied"),
            FsError::Transient(m) => write!(f, "transient failure: {m}"),
            FsError::Unsupported(m) => write!(f, "unsupported: {m}"),
            FsError::Fatal(m) => write!(f, "fatal: {m}"),
        }
    }
}

impl std::error::Error for FsError {}

impl From<std::io::Error> for FsError {
    fn from(err: std::io::Error) -> Self {
        use std::io::ErrorKind;
        match err.kind() {
            ErrorKind::NotFound => FsError::NotFound,
            ErrorKind::NotADirectory => FsError::NotDirectory,
            ErrorKind::PermissionDenied => FsError::PermissionDenied,
            ErrorKind::Unsupported => FsError::Unsupported(err.to_string()),
            _ => FsError::Transient(err.to_string()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryInfo {
    pub kind: EntryKind,
    pub metadata: Metadata,
    pub identity: Option<FileIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObservedKind {
    Resolved(EntryKind),
    Unresolved,
}

impl ObservedKind {
    pub fn resolved(self) -> Option<EntryKind> {
        match self {
            ObservedKind::Resolved(kind) => Some(kind),
            ObservedKind::Unresolved => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub kind: ObservedKind,
    pub metadata: Metadata,
    pub identity: Option<FileIdentity>,
}

impl Observation {
    pub fn resolved(info: EntryInfo) -> Observation {
        Observation { kind: ObservedKind::Resolved(info.kind), metadata: info.metadata, identity: info.identity }
    }

    pub fn info(self) -> Option<EntryInfo> {
        Some(EntryInfo { kind: self.kind.resolved()?, metadata: self.metadata, identity: self.identity })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: OsString,
    pub info: Observation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryListing {
    pub directory: EntryInfo,
    pub entries: Vec<DirEntry>,
    pub supplied_fields: MetadataFields,
    pub metadata_operations: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrichment {
    pub directory: Option<Metadata>,
    pub children: Vec<(OsString, Metadata)>,
    pub supplied_fields: MetadataFields,
    pub metadata_operations: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldSource {
    Inline,
    PerChildRead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KindSource {
    Always,
    Sometimes,
    Never,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IdentitySource {
    Inline,
    PerChildRead,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MetadataSources {
    pub modified: FieldSource,
    pub created: FieldSource,
    pub size: FieldSource,
    pub permissions: FieldSource,
}

impl MetadataSources {
    pub const INLINE: MetadataSources = MetadataSources {
        modified: FieldSource::Inline,
        created: FieldSource::Inline,
        size: FieldSource::Inline,
        permissions: FieldSource::Inline,
    };
    pub const PER_CHILD_READ: MetadataSources = MetadataSources {
        modified: FieldSource::PerChildRead,
        created: FieldSource::PerChildRead,
        size: FieldSource::PerChildRead,
        permissions: FieldSource::PerChildRead,
    };

    pub fn inline(self) -> MetadataFields {
        MetadataFields {
            modified: self.modified == FieldSource::Inline,
            created: self.created == FieldSource::Inline,
            size: self.size == FieldSource::Inline,
            permissions: self.permissions == FieldSource::Inline,
        }
    }

    pub fn per_child_read(self) -> MetadataFields {
        MetadataFields::ALL.without(self.inline())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObservationSources {
    pub kind: KindSource,
    pub identity: IdentitySource,
    pub metadata: MetadataSources,
}

impl ObservationSources {
    pub const INLINE: ObservationSources = ObservationSources {
        kind: KindSource::Always,
        identity: IdentitySource::Inline,
        metadata: MetadataSources::INLINE,
    };
    pub const UNIX: ObservationSources = ObservationSources {
        kind: KindSource::Sometimes,
        identity: IdentitySource::Inline,
        metadata: MetadataSources::PER_CHILD_READ,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WatcherKind {
    None,
    Recursive,
    NonRecursive,
    Polling,
}

impl WatcherKind {
    pub fn is_present(self) -> bool {
        !matches!(self, WatcherKind::None)
    }

    pub fn is_per_directory(self) -> bool {
        matches!(self, WatcherKind::NonRecursive)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsCapabilities {
    pub case: CaseSensitivity,
    pub stable_identity: bool,
    pub watcher: WatcherKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HintKind {
    Create,
    Remove,
    Rename,
    Modify,
    Metadata,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatcherEvent {
    Hint { paths: Vec<RelativePath>, kind: HintKind },
    Overflow,
    Failed { message: String },
    Dropped { count: u64 },
}

pub trait WatcherSink: Send + Sync {
    fn deliver(&self, event: WatcherEvent);
}

impl<F: Fn(WatcherEvent) + Send + Sync> WatcherSink for F {
    fn deliver(&self, event: WatcherEvent) {
        self(event)
    }
}

pub trait FileSystem: Send + Sync {
    fn capabilities(&self) -> FsCapabilities;
    fn canonicalize(&self, root: &Path) -> Result<PathBuf, FsError>;
    fn observation_sources(&self, path: &RelativePath) -> ObservationSources;
    fn metadata(&self, root: &Path, path: &RelativePath) -> Result<EntryInfo, FsError>;
    fn read_dir(&self, root: &Path, path: &RelativePath) -> Result<DirectoryListing, FsError>;
    fn enrich(&self, root: &Path, path: &RelativePath, fields: MetadataFields) -> Result<Enrichment, FsError>;
    fn watch(
        &self,
        root: &Path,
        path: &RelativePath,
        recursive: bool,
        sink: Arc<dyn WatcherSink>,
    ) -> Result<WatchId, FsError>;
    fn unwatch(&self, watch: WatchId);
}
