use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::entry::{EntryKind, FileIdentity, Metadata, MetadataFields};
use crate::fs::{
    DirEntry, DirectoryListing, Enrichment, EntryInfo, FileSystem, FsCapabilities, FsError, IdentitySource, KindSource,
    MetadataSources, Observation, ObservationSources, ObservedKind, WatcherKind, WatcherSink,
};
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

fn kind_of(file_type: std::fs::FileType) -> EntryKind {
    if file_type.is_symlink() {
        EntryKind::Symlink
    } else if file_type.is_dir() {
        EntryKind::Directory
    } else if file_type.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    }
}

#[cfg(unix)]
fn inline_identity(directory: &std::fs::Metadata, item: &std::fs::DirEntry) -> Option<FileIdentity> {
    use std::os::unix::fs::{DirEntryExt, MetadataExt};
    Some(FileIdentity { device: directory.dev(), inode: item.ino() })
}

#[cfg(not(unix))]
fn inline_identity(_directory: &std::fs::Metadata, _item: &std::fs::DirEntry) -> Option<FileIdentity> {
    None
}

fn info_from(metadata: &std::fs::Metadata) -> EntryInfo {
    EntryInfo {
        kind: kind_of(metadata.file_type()),
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
        let mut metadata_operations = 0;
        for item in std::fs::read_dir(&full)? {
            let item = item?;
            let kind = match item.file_type() {
                Ok(file_type) => ObservedKind::Resolved(kind_of(file_type)),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => {
                    metadata_operations += 1;
                    match std::fs::symlink_metadata(item.path()) {
                        Ok(metadata) => ObservedKind::Resolved(kind_of(metadata.file_type())),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(_) => ObservedKind::Unresolved,
                    }
                }
            };
            let info = Observation { kind, metadata: Metadata::default(), identity: inline_identity(&own, &item) };
            entries.push(DirEntry { name: item.file_name(), info });
        }
        Ok(DirectoryListing {
            directory,
            entries,
            supplied_fields: MetadataSources::PER_CHILD_READ.inline(),
            metadata_operations,
        })
    }

    fn observation_sources(&self, _path: &RelativePath) -> ObservationSources {
        ObservationSources {
            kind: KindSource::Sometimes,
            identity: if cfg!(unix) { IdentitySource::Inline } else { IdentitySource::None },
            metadata: MetadataSources::PER_CHILD_READ,
        }
    }

    fn enrich(&self, root: &Path, path: &RelativePath, fields: MetadataFields) -> Result<Enrichment, FsError> {
        let full = path.under(root);
        let own = std::fs::symlink_metadata(&full)?;
        let mut metadata_operations = 1;
        let directory = Some(info_from(&own).metadata.project(fields));
        let mut children = Vec::new();
        for item in std::fs::read_dir(&full)? {
            let item = item?;
            metadata_operations += 1;
            let metadata = match std::fs::symlink_metadata(item.path()) {
                Ok(metadata) => metadata,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err.into()),
            };
            children.push((item.file_name(), info_from(&metadata).metadata.project(fields)));
        }
        Ok(Enrichment { directory, children, supplied_fields: fields, metadata_operations })
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
