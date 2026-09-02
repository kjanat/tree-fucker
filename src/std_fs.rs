use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::entry::{EntryKind, FileIdentity, Metadata};
use crate::fs::{DirEntry, DirectoryListing, EntryInfo, FileSystem, FsCapabilities, FsError, WatcherKind, WatcherSink};
use crate::ids::WatchId;
use crate::path::{CaseSensitivity, RelativePath};

pub struct StdFileSystem {
    case: CaseSensitivity,
}

impl StdFileSystem {
    pub fn new() -> StdFileSystem {
        StdFileSystem {
            case: if cfg!(any(windows, target_os = "macos")) {
                CaseSensitivity::Insensitive
            } else {
                CaseSensitivity::Sensitive
            },
        }
    }

    pub fn with_case(case: CaseSensitivity) -> StdFileSystem {
        StdFileSystem { case }
    }
}

impl Default for StdFileSystem {
    fn default() -> Self {
        StdFileSystem::new()
    }
}

fn info_from(metadata: &std::fs::Metadata) -> EntryInfo {
    let file_type = metadata.file_type();
    let kind = if file_type.is_symlink() {
        EntryKind::Symlink
    } else if file_type.is_dir() {
        EntryKind::Directory
    } else if file_type.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    };
    EntryInfo {
        kind,
        metadata: Metadata {
            modified: metadata.modified().ok(),
            created: metadata.created().ok(),
            size: Some(metadata.len()),
            permissions: permissions_of(metadata),
        },
        identity: identity_of(metadata),
    }
}

#[cfg(unix)]
fn permissions_of(metadata: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(metadata.permissions().mode())
}

#[cfg(not(unix))]
fn permissions_of(metadata: &std::fs::Metadata) -> Option<u32> {
    Some(u32::from(metadata.permissions().readonly()))
}

#[cfg(unix)]
fn identity_of(metadata: &std::fs::Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    Some(FileIdentity { device: metadata.dev(), inode: metadata.ino() })
}

#[cfg(not(unix))]
fn identity_of(_metadata: &std::fs::Metadata) -> Option<FileIdentity> {
    None
}

impl FileSystem for StdFileSystem {
    fn capabilities(&self) -> FsCapabilities {
        FsCapabilities { case: self.case, stable_identity: cfg!(unix), watcher: WatcherKind::None }
    }

    fn canonicalize(&self, root: &Path) -> Result<PathBuf, FsError> {
        Ok(std::fs::canonicalize(root)?)
    }

    fn metadata(&self, root: &Path, path: &RelativePath) -> Result<EntryInfo, FsError> {
        let full = path.under(root);
        let metadata = std::fs::symlink_metadata(&full)?;
        Ok(info_from(&metadata))
    }

    fn read_dir(&self, root: &Path, path: &RelativePath) -> Result<DirectoryListing, FsError> {
        let full = path.under(root);
        let own = std::fs::symlink_metadata(&full)?;
        let directory = info_from(&own);
        if directory.kind != EntryKind::Directory {
            return Err(FsError::NotDirectory);
        }
        let mut entries = Vec::new();
        for item in std::fs::read_dir(&full)? {
            let item = item?;
            let metadata = match item.metadata() {
                Ok(m) => m,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err.into()),
            };
            entries.push(DirEntry { name: item.file_name(), info: info_from(&metadata) });
        }
        Ok(DirectoryListing { directory, entries })
    }

    fn watch(
        &self,
        _root: &Path,
        _path: &RelativePath,
        _recursive: bool,
        _sink: Arc<dyn WatcherSink>,
    ) -> Result<WatchId, FsError> {
        Err(FsError::Unsupported("StdFileSystem has no watcher".into()))
    }

    fn unwatch(&self, _watch: WatchId) {}
}
