use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::entry::{EntryKind, FileIdentity, Metadata};
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: OsString,
    pub info: EntryInfo,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryListing {
    pub directory: EntryInfo,
    pub entries: Vec<DirEntry>,
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
    fn metadata(&self, root: &Path, path: &RelativePath) -> Result<EntryInfo, FsError>;
    fn read_dir(&self, root: &Path, path: &RelativePath) -> Result<DirectoryListing, FsError>;
    fn watch(
        &self,
        root: &Path,
        path: &RelativePath,
        recursive: bool,
        sink: Arc<dyn WatcherSink>,
    ) -> Result<WatchId, FsError>;
    fn unwatch(&self, watch: WatchId);
}
