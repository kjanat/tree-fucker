use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crate::domain::{DeclarationSource, DomainProbe, IdentitySource, KindSource, MetadataSources, ProbeResult};
use crate::entry::{EntryKind, FileIdentity, Metadata, MetadataFields};
use crate::fs::{
    CancellationToken, Continuation, DirEntry, DirectoryListing, Enrichment, EntryInfo, FileSystem, FsCapabilities,
    FsError, Lease, ListingSession, Observation, ObservedKind, SessionCost, SessionOutcome, WatcherKind, WatcherSink,
    entry_bytes,
};
use crate::ids::WatchId;
use crate::path::{CaseSensitivity, RelativePath};

pub struct StdFileSystem {
    case: CaseSensitivity,
    probe: Arc<dyn DomainProbe>,
}

fn platform_probe() -> Arc<dyn DomainProbe> {
    #[cfg(target_os = "linux")]
    {
        Arc::new(crate::domain::LinuxProbe::new())
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(crate::domain::MacOsProbe::new())
    }
    #[cfg(windows)]
    {
        Arc::new(crate::domain::WindowsProbe::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Arc::new(crate::domain::UnknownProbe)
    }
}

impl StdFileSystem {
    pub fn new() -> StdFileSystem {
        StdFileSystem {
            case: if cfg!(any(windows, target_os = "macos")) {
                CaseSensitivity::Insensitive
            } else {
                CaseSensitivity::Sensitive
            },
            probe: platform_probe(),
        }
    }

    pub fn with_case(case: CaseSensitivity) -> StdFileSystem {
        StdFileSystem { case, probe: platform_probe() }
    }

    pub fn with_probe(case: CaseSensitivity, probe: Arc<dyn DomainProbe>) -> StdFileSystem {
        StdFileSystem { case, probe }
    }
}

fn probe_at(probe: &dyn DomainProbe, full: &Path, parent: Option<&ProbeResult>) -> Result<ProbeResult, FsError> {
    let mut result = probe.probe(full, parent)?;
    result.capabilities.kind_source = KindSource::Sometimes;
    result.capabilities.identity_source = if cfg!(unix) { IdentitySource::Inline } else { IdentitySource::None };
    result.capabilities.metadata_sources = MetadataSources::PER_CHILD_READ;
    result.capabilities.sources.observation = DeclarationSource::Declared;
    Ok(result)
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
        FsCapabilities { case: self.case, watcher: WatcherKind::None }
    }

    fn canonicalize(&self, root: &Path) -> Result<PathBuf, FsError> {
        Ok(std::fs::canonicalize(root)?)
    }

    fn resolve_domain(
        &self,
        root: &Path,
        path: &RelativePath,
        parent: Option<&ProbeResult>,
    ) -> Result<ProbeResult, FsError> {
        probe_at(self.probe.as_ref(), &path.under(root), parent)
    }

    fn metadata(&self, root: &Path, path: &RelativePath) -> Result<EntryInfo, FsError> {
        let full = path.under(root);
        let metadata = std::fs::symlink_metadata(&full)?;
        Ok(info_from(&metadata))
    }

    fn open_listing(
        &self,
        root: &Path,
        path: &RelativePath,
        ceiling: usize,
        cancel: CancellationToken,
    ) -> Box<dyn ListingSession> {
        Box::new(StdSession {
            full: path.under(root),
            probe: self.probe.clone(),
            ceiling,
            cancel,
            opened: None,
            entries: Vec::new(),
            bytes: 0,
        })
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

const STD_CHUNK: usize = 1024;

struct Opened {
    directory: EntryInfo,
    own: std::fs::Metadata,
    iterator: std::fs::ReadDir,
    domain: ProbeResult,
    exhausted: bool,
}

struct StdSession {
    full: PathBuf,
    probe: Arc<dyn DomainProbe>,
    ceiling: usize,
    cancel: CancellationToken,
    opened: Option<Opened>,
    entries: Vec<DirEntry>,
    bytes: u64,
}

impl StdSession {
    fn open(&mut self, cost: &mut SessionCost) -> Result<(), FsError> {
        if self.opened.is_some() {
            return Ok(());
        }
        cost.listing_operations += 1;
        let own = std::fs::symlink_metadata(&self.full)?;
        let directory = info_from(&own);
        if directory.kind != EntryKind::Directory {
            return Err(FsError::NotDirectory);
        }
        let domain = probe_at(self.probe.as_ref(), &self.full, None)?;
        let iterator = std::fs::read_dir(&self.full)?;
        self.opened = Some(Opened { directory, own, iterator, domain, exhausted: false });
        Ok(())
    }

    fn chunk(&mut self, budget: usize, cost: &mut SessionCost) -> Result<usize, FsError> {
        let Some(opened) = self.opened.as_mut() else {
            return Ok(0);
        };
        let mut taken = 0;
        while taken < budget {
            let Some(item) = opened.iterator.next() else {
                opened.exhausted = true;
                return Ok(taken);
            };
            let item = item?;
            let kind = match item.file_type() {
                Ok(file_type) => ObservedKind::Resolved(kind_of(file_type)),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => {
                    cost.metadata_operations += 1;
                    cost.kind_resolutions += 1;
                    match std::fs::symlink_metadata(item.path()) {
                        Ok(metadata) => ObservedKind::Resolved(kind_of(metadata.file_type())),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(_) => ObservedKind::Unresolved,
                    }
                }
            };
            let info =
                Observation { kind, metadata: Metadata::default(), identity: inline_identity(&opened.own, &item) };
            let name = item.file_name();
            self.bytes += entry_bytes(&name);
            self.entries.push(DirEntry::new(name, info));
            taken += 1;
            cost.entries_enumerated += 1;
        }
        Ok(taken)
    }

    fn complete(&mut self) -> SessionOutcome {
        let Some(opened) = self.opened.as_ref() else {
            return SessionOutcome::Failed(FsError::NotFound);
        };
        SessionOutcome::Complete(DirectoryListing {
            directory: opened.directory,
            entries: std::mem::take(&mut self.entries),
            supplied_fields: MetadataSources::PER_CHILD_READ.inline(),
            domain: Box::new(opened.domain.clone()),
        })
    }
}

impl ListingSession for StdSession {
    fn resume(mut self: Box<Self>, lease: Lease) -> (Continuation, SessionCost) {
        let started = Instant::now();
        let mut cost = SessionCost::default();
        let finish = |cost: &mut SessionCost, bytes: u64, started: Instant, outcome: SessionOutcome| {
            cost.blocking = Some(started.elapsed());
            cost.bytes = bytes;
            (Continuation::Finished(outcome), *cost)
        };
        if let Err(err) = self.open(&mut cost) {
            return finish(&mut cost, self.bytes, started, SessionOutcome::Failed(err));
        }
        let mut entries_left = lease.entries;
        let mut operations_left = lease.operations;
        loop {
            if self.cancel.is_cancelled() {
                return finish(&mut cost, self.bytes, started, SessionOutcome::Cancelled);
            }
            if self.opened.as_ref().map(|o| o.exhausted).unwrap_or(true) {
                let outcome = self.complete();
                return finish(&mut cost, self.bytes, started, outcome);
            }
            if entries_left == 0 || operations_left == 0 {
                cost.blocking = Some(started.elapsed());
                cost.bytes = self.bytes;
                return (Continuation::Suspended(self), cost);
            }
            let budget = STD_CHUNK.min(entries_left).min(operations_left);
            let resolutions = cost.kind_resolutions;
            let taken = match self.chunk(budget, &mut cost) {
                Ok(taken) => taken,
                Err(err) => return finish(&mut cost, self.bytes, started, SessionOutcome::Failed(err)),
            };
            let resolved = usize::try_from(cost.kind_resolutions - resolutions).unwrap_or(usize::MAX);
            entries_left -= taken;
            operations_left = operations_left.saturating_sub(taken.saturating_add(resolved));
            if self.entries.len() > self.ceiling {
                let seen = self.entries.len();
                return finish(&mut cost, self.bytes, started, SessionOutcome::ResourceLimited { seen });
            }
        }
    }
}
