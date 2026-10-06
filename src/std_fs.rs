use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crate::domain::{
    DeclarationSource, DomainProbe, IdentitySource, KindSource, MetadataSource, MetadataSources, ProbeResult,
};
use crate::entry::{EntryKind, FileIdentity, Metadata};
use crate::fs::{
    Anchor, CancellationToken, Ceilings, Continuation, DirEntry, DirectoryListing, Enrichment, EnrichmentBatch,
    EntryInfo, FileSystem, FsCapabilities, FsError, Lease, ListingAt, ListingSession, Observation, ObservedKind,
    SessionCost, SessionOutcome, WatcherKind, WatcherSink, entry_bytes,
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
    #[cfg(target_os = "freebsd")]
    {
        Arc::new(crate::domain::FreeBsdProbe::new())
    }
    #[cfg(any(target_os = "illumos", target_os = "solaris"))]
    {
        Arc::new(crate::domain::IllumosProbe::new())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "solaris",
        windows
    )))]
    {
        Arc::new(crate::domain::UnknownProbe)
    }
}

pub fn inline_metadata_sources() -> MetadataSources {
    if cfg!(windows) {
        MetadataSources {
            modified: MetadataSource::Inline,
            created: MetadataSource::Inline,
            size: MetadataSource::Inline,
            permissions: MetadataSource::PerChildRead,
        }
    } else {
        MetadataSources::PER_CHILD_READ
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
    Ok(declare(probe.probe(full, parent)?))
}

fn declare(mut result: ProbeResult) -> ProbeResult {
    if result.capabilities.kind_source == KindSource::Unknown {
        result.capabilities.kind_source = KindSource::Sometimes;
    }
    if cfg!(unix) {
        result.capabilities.identity_source = IdentitySource::Inline;
    } else if !cfg!(windows) {
        result.capabilities.identity_source = IdentitySource::None;
    }
    result.capabilities.metadata_sources = inline_metadata_sources();
    result.capabilities.sources.observation = DeclarationSource::Declared;
    result
}

#[cfg(unix)]
fn anchored_parent<'a>(beneath: Option<&'a Anchor>, full: &Path) -> Option<&'a DirectoryAnchor> {
    let parent = beneath?.get::<DirectoryAnchor>()?;
    (full.parent().map(Path::as_os_str) == Some(parent.path().as_os_str())).then_some(parent)
}

impl StdFileSystem {
    fn session(
        &self,
        root: &Path,
        path: &RelativePath,
        ceilings: Ceilings,
        cancel: CancellationToken,
        beneath: Option<Anchor>,
    ) -> StdSession<PlatformSource> {
        let full = path.under(root);
        let probe = self.probe.clone();
        let opener = {
            let full = full.clone();
            move || open_platform(probe.as_ref(), &full, beneath.as_ref())
        };
        StdSession::new(full, ceilings, cancel, opener)
    }
}

pub struct DirectoryAnchor {
    path: PathBuf,
    #[cfg(unix)]
    fd: rustix::fd::OwnedFd,
}

impl DirectoryAnchor {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
impl rustix::fd::AsFd for DirectoryAnchor {
    fn as_fd(&self) -> rustix::fd::BorrowedFd<'_> {
        self.fd.as_fd()
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
    Some(FileIdentity { device: metadata.dev(), inode: u128::from(metadata.ino()) })
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
        ceilings: Ceilings,
        cancel: CancellationToken,
    ) -> Box<dyn ListingSession> {
        Box::new(self.session(root, path, ceilings, cancel, None))
    }

    fn open_listing_at(
        &self,
        root: &Path,
        path: &RelativePath,
        at: ListingAt<'_>,
        ceilings: Ceilings,
        cancel: CancellationToken,
    ) -> Box<dyn ListingSession> {
        let session = self.session(root, path, ceilings, cancel, at.beneath.cloned());
        match at.anchored {
            true => Box::new(session.anchored()),
            false => Box::new(session),
        }
    }

    #[cfg(unix)]
    fn resolve_domain_beneath(
        &self,
        root: &Path,
        path: &RelativePath,
        beneath: Option<&Anchor>,
        parent: Option<&ProbeResult>,
    ) -> Result<ProbeResult, FsError> {
        use rustix::fd::AsFd;
        let full = path.under(root);
        match (anchored_parent(beneath, &full), full.file_name()) {
            (Some(anchor), Some(name)) => Ok(declare(self.probe.probe_beneath(anchor.as_fd(), name, &full, parent)?)),
            _ => self.resolve_domain(root, path, parent),
        }
    }

    fn enrich(&self, root: &Path, path: &RelativePath, batch: &EnrichmentBatch) -> Result<Enrichment, FsError> {
        let full = path.under(root);
        let mut metadata_operations = 0;
        let directory = if batch.directory {
            metadata_operations += 1;
            let own = std::fs::symlink_metadata(&full)?;
            Some(info_from(&own).metadata.project(batch.fields))
        } else {
            None
        };
        let mut children = Vec::with_capacity(batch.children.len());
        let mut failed = Vec::new();
        for name in &batch.children {
            metadata_operations += 1;
            match std::fs::symlink_metadata(full.join(name)) {
                Ok(metadata) => children.push((name.clone(), info_from(&metadata).metadata.project(batch.fields))),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => failed.push((name.clone(), err.into())),
            }
        }
        Ok(Enrichment { directory, children, failed, supplied_fields: batch.fields, metadata_operations })
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

pub struct RawEntry {
    pub name: OsString,
    pub kind: Option<EntryKind>,
    pub identity: Option<FileIdentity>,
    pub metadata: Metadata,
}

pub trait EntrySource: Send {
    fn next_entry(&mut self) -> Option<Result<RawEntry, FsError>>;
    fn resolve_kind(&mut self, name: &OsStr) -> Result<EntryKind, FsError>;
    fn resolve_identity(&mut self, name: &OsStr) -> Result<Option<FileIdentity>, FsError>;
    fn resolves_by_descriptor(&self) -> bool;

    fn anchor(&self, _path: &Path) -> Option<Anchor> {
        None
    }
}

pub struct Opened<S> {
    pub directory: EntryInfo,
    pub domain: ProbeResult,
    pub source: S,
}

#[cfg(unix)]
fn open_platform(
    probe: &dyn DomainProbe,
    full: &Path,
    beneath: Option<&Anchor>,
) -> Result<Opened<PlatformSource>, FsError> {
    use std::os::unix::fs::MetadataExt;

    use rustix::fd::AsFd;
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let opened = match (anchored_parent(beneath, full), full.file_name()) {
        (Some(parent), Some(name)) => rustix::fs::openat(parent, name, flags, Mode::empty()),
        _ => rustix::fs::open(full, flags, Mode::empty()),
    };
    let handle = std::fs::File::from(opened.map_err(directory_error)?);
    let own = handle.metadata()?;
    let directory = info_from(&own);
    if directory.kind != EntryKind::Directory {
        return Err(FsError::NotDirectory);
    }
    let domain = declare(probe.probe_opened(handle.as_fd(), full, None)?);
    let entries = rustix::fs::Dir::new(rustix::fd::OwnedFd::from(handle)).map_err(std::io::Error::from)?;
    Ok(Opened { directory, domain, source: PlatformSource { device: own.dev(), entries } })
}

#[cfg(unix)]
fn directory_error(errno: rustix::io::Errno) -> FsError {
    match errno {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => FsError::NotDirectory,
        other => std::io::Error::from(other).into(),
    }
}

#[cfg(not(unix))]
fn open_platform(
    probe: &dyn DomainProbe,
    full: &Path,
    _beneath: Option<&Anchor>,
) -> Result<Opened<PlatformSource>, FsError> {
    let own = std::fs::symlink_metadata(full)?;
    let directory = info_from(&own);
    if directory.kind != EntryKind::Directory {
        return Err(FsError::NotDirectory);
    }
    let domain = probe_at(probe, full, None)?;
    let source = PlatformSource::open(full, &own)?;
    Ok(Opened { directory, domain, source })
}

pub struct PlatformSource {
    #[cfg(not(unix))]
    full: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    entries: rustix::fs::Dir,
    #[cfg(not(unix))]
    entries: std::fs::ReadDir,
}

impl PlatformSource {
    #[cfg(not(unix))]
    fn open(full: &Path, _own: &std::fs::Metadata) -> Result<PlatformSource, FsError> {
        Ok(PlatformSource { full: full.to_path_buf(), entries: std::fs::read_dir(full)? })
    }
}

#[cfg(unix)]
fn unix_kind(file_type: rustix::fs::FileType) -> Option<EntryKind> {
    use rustix::fs::FileType;
    match file_type {
        FileType::RegularFile => Some(EntryKind::File),
        FileType::Directory => Some(EntryKind::Directory),
        FileType::Symlink => Some(EntryKind::Symlink),
        FileType::Unknown => None,
        _ => Some(EntryKind::Other),
    }
}

#[cfg(all(unix, not(any(target_os = "illumos", target_os = "solaris"))))]
fn dirent_kind(entry: &rustix::fs::DirEntry) -> Option<EntryKind> {
    unix_kind(entry.file_type())
}

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
fn dirent_kind(_entry: &rustix::fs::DirEntry) -> Option<EntryKind> {
    None
}

#[cfg(windows)]
fn inline_metadata(item: &std::fs::DirEntry) -> Metadata {
    match item.metadata() {
        Ok(metadata) => Metadata {
            modified: metadata.modified().ok(),
            created: metadata.created().ok(),
            size: Some(metadata.len()),
            permissions: None,
        },
        Err(_) => Metadata::default(),
    }
}

#[cfg(not(any(unix, windows)))]
fn inline_metadata(_item: &std::fs::DirEntry) -> Metadata {
    Metadata::default()
}

impl EntrySource for PlatformSource {
    #[cfg(unix)]
    fn next_entry(&mut self) -> Option<Result<RawEntry, FsError>> {
        use std::os::unix::ffi::OsStrExt;
        loop {
            let entry = match self.entries.next()? {
                Ok(entry) => entry,
                Err(err) => return Some(Err(std::io::Error::from(err).into())),
            };
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            return Some(Ok(RawEntry {
                name: OsStr::from_bytes(bytes).to_os_string(),
                kind: dirent_kind(&entry),
                identity: Some(FileIdentity { device: self.device, inode: u128::from(entry.ino()) }),
                metadata: Metadata::default(),
            }));
        }
    }

    #[cfg(not(unix))]
    fn next_entry(&mut self) -> Option<Result<RawEntry, FsError>> {
        let item = match self.entries.next()? {
            Ok(item) => item,
            Err(err) => return Some(Err(err.into())),
        };
        Some(Ok(RawEntry {
            name: item.file_name(),
            kind: item.file_type().ok().map(kind_of),
            identity: None,
            metadata: inline_metadata(&item),
        }))
    }

    #[cfg(unix)]
    fn resolve_kind(&mut self, name: &OsStr) -> Result<EntryKind, FsError> {
        use rustix::fs::{AtFlags, FileType, statat};
        let directory = self.entries.fd().map_err(std::io::Error::from)?;
        let stat = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(std::io::Error::from)?;
        Ok(unix_kind(FileType::from_raw_mode(stat.st_mode)).unwrap_or(EntryKind::Other))
    }

    #[cfg(not(unix))]
    fn resolve_kind(&mut self, name: &OsStr) -> Result<EntryKind, FsError> {
        Ok(kind_of(std::fs::symlink_metadata(self.full.join(name))?.file_type()))
    }

    #[cfg(windows)]
    fn resolve_identity(&mut self, name: &OsStr) -> Result<Option<FileIdentity>, FsError> {
        crate::domain::windows_file_identity(&self.full.join(name))
    }

    #[cfg(not(windows))]
    fn resolve_identity(&mut self, _name: &OsStr) -> Result<Option<FileIdentity>, FsError> {
        Ok(None)
    }

    fn resolves_by_descriptor(&self) -> bool {
        cfg!(unix)
    }

    #[cfg(unix)]
    fn anchor(&self, path: &Path) -> Option<Anchor> {
        let directory = self.entries.fd().ok()?;
        let fd = rustix::io::fcntl_dupfd_cloexec(directory, 0).ok()?;
        Some(Anchor::new(DirectoryAnchor { path: path.to_path_buf(), fd }))
    }

    #[cfg(not(unix))]
    fn anchor(&self, path: &Path) -> Option<Anchor> {
        Some(Anchor::new(DirectoryAnchor { path: path.to_path_buf() }))
    }
}

enum Stream<S> {
    Unopened(Box<dyn FnOnce() -> Result<Opened<S>, FsError> + Send>),
    Open(Opened<S>),
    Exhausted(Opened<S>),
    Failed,
}

enum ChunkEnd {
    Ready,
    Exhausted,
    Suspended,
}

pub struct StdSession<S> {
    full: PathBuf,
    ceilings: Ceilings,
    cancel: CancellationToken,
    stream: Stream<S>,
    stashed: Option<RawEntry>,
    entries: Vec<DirEntry>,
    bytes: u64,
    anchored: bool,
}

impl<S: EntrySource + 'static> StdSession<S> {
    pub fn new(
        full: PathBuf,
        ceilings: Ceilings,
        cancel: CancellationToken,
        opener: impl FnOnce() -> Result<Opened<S>, FsError> + Send + 'static,
    ) -> StdSession<S> {
        StdSession {
            full,
            ceilings,
            cancel,
            stream: Stream::Unopened(Box::new(opener)),
            stashed: None,
            entries: Vec::new(),
            bytes: 0,
            anchored: false,
        }
    }

    pub fn anchored(mut self) -> StdSession<S> {
        self.anchored = true;
        self
    }

    fn open(&mut self, cost: &mut SessionCost) -> Result<(), FsError> {
        let stream = std::mem::replace(&mut self.stream, Stream::Failed);
        self.stream = match stream {
            Stream::Unopened(opener) => {
                cost.listing_operations += 1;
                Stream::Open(opener()?)
            }
            other => other,
        };
        Ok(())
    }

    fn push(&mut self, name: OsString, kind: ObservedKind, identity: Option<FileIdentity>, metadata: Metadata) {
        self.bytes += entry_bytes(&name);
        self.entries.push(DirEntry::new(name, Observation { kind, metadata, identity }));
    }

    fn per_child_identity(&self) -> bool {
        match &self.stream {
            Stream::Open(opened) | Stream::Exhausted(opened) => {
                opened.domain.capabilities.identity_source == IdentitySource::PerChildRead
            }
            Stream::Unopened(_) | Stream::Failed => false,
        }
    }

    fn by_descriptor(&self) -> bool {
        match &self.stream {
            Stream::Open(opened) | Stream::Exhausted(opened) => opened.source.resolves_by_descriptor(),
            Stream::Unopened(_) | Stream::Failed => false,
        }
    }

    fn admit(&mut self, raw: RawEntry, operations_left: &mut usize, cost: &mut SessionCost) -> bool {
        let RawEntry { name, kind, identity, metadata } = raw;
        let kind = match kind {
            Some(kind) => ObservedKind::Resolved(kind),
            None => {
                if *operations_left == 0 {
                    self.stashed = Some(RawEntry { name, kind, identity, metadata });
                    return false;
                }
                *operations_left -= 1;
                cost.metadata_operations += 1;
                cost.kind_resolutions += 1;
                let resolved = match &mut self.stream {
                    Stream::Open(opened) | Stream::Exhausted(opened) => opened.source.resolve_kind(&name),
                    Stream::Unopened(_) | Stream::Failed => Err(FsError::NotFound),
                };
                let vanished = self.by_descriptor();
                match resolved {
                    Ok(kind) => ObservedKind::Resolved(kind),
                    Err(FsError::NotFound) if vanished => {
                        cost.entries_enumerated += 1;
                        return true;
                    }
                    Err(_) => ObservedKind::Unresolved,
                }
            }
        };
        let identity = match identity {
            Some(identity) => Some(identity),
            None if self.per_child_identity() => {
                if *operations_left == 0 {
                    self.stashed = Some(RawEntry { name, kind: kind.resolved(), identity, metadata });
                    return false;
                }
                *operations_left -= 1;
                cost.identity_reads += 1;
                let vanished = self.by_descriptor();
                let resolved = match &mut self.stream {
                    Stream::Open(opened) | Stream::Exhausted(opened) => opened.source.resolve_identity(&name),
                    Stream::Unopened(_) | Stream::Failed => Ok(None),
                };
                match resolved {
                    Ok(identity) => identity,
                    Err(FsError::NotFound) if vanished => {
                        cost.entries_enumerated += 1;
                        return true;
                    }
                    Err(_) => None,
                }
            }
            None => None,
        };
        cost.entries_enumerated += 1;
        self.push(name, kind, identity, metadata);
        true
    }

    fn chunk(
        &mut self,
        entries_left: &mut usize,
        operations_left: &mut usize,
        cost: &mut SessionCost,
    ) -> Result<ChunkEnd, FsError> {
        let budget = STD_CHUNK.min(*entries_left);
        let mut taken = 0;
        while taken < budget {
            let next = match self.stashed.take() {
                Some(raw) => Some(Ok(raw)),
                None => match &mut self.stream {
                    Stream::Open(opened) => opened.source.next_entry(),
                    Stream::Exhausted(_) | Stream::Unopened(_) | Stream::Failed => None,
                },
            };
            let Some(next) = next else {
                if let Stream::Open(opened) = std::mem::replace(&mut self.stream, Stream::Failed) {
                    self.stream = Stream::Exhausted(opened);
                }
                return Ok(ChunkEnd::Exhausted);
            };
            let raw = next?;
            if !self.admit(raw, operations_left, cost) {
                return Ok(ChunkEnd::Suspended);
            }
            taken += 1;
            *entries_left -= 1;
        }
        Ok(ChunkEnd::Ready)
    }

    fn complete(&mut self) -> SessionOutcome {
        let (Stream::Open(opened) | Stream::Exhausted(opened)) = &self.stream else {
            return SessionOutcome::Failed(FsError::NotFound);
        };
        SessionOutcome::Complete(DirectoryListing {
            directory: opened.directory,
            entries: std::mem::take(&mut self.entries),
            supplied_fields: inline_metadata_sources().inline(),
            domain: Box::new(opened.domain.clone()),
            anchor: if self.anchored { opened.source.anchor(&self.full) } else { None },
        })
    }

    fn exhausted(&self) -> bool {
        self.stashed.is_none() && matches!(self.stream, Stream::Exhausted(_))
    }

    pub fn path(&self) -> &Path {
        &self.full
    }
}

impl<S: EntrySource + 'static> ListingSession for StdSession<S> {
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
            if self.exhausted() {
                let outcome = self.complete();
                return finish(&mut cost, self.bytes, started, outcome);
            }
            if entries_left == 0 {
                cost.blocking = Some(started.elapsed());
                cost.bytes = self.bytes;
                return (Continuation::Suspended(self), cost);
            }
            let end = match self.chunk(&mut entries_left, &mut operations_left, &mut cost) {
                Ok(end) => end,
                Err(err) => return finish(&mut cost, self.bytes, started, SessionOutcome::Failed(err)),
            };
            if let Some(limited) = self.ceilings.exceeded_by(self.entries.len(), self.bytes) {
                return finish(&mut cost, self.bytes, started, SessionOutcome::ResourceLimited(limited));
            }
            match end {
                ChunkEnd::Ready | ChunkEnd::Exhausted => {}
                ChunkEnd::Suspended => {
                    cost.blocking = Some(started.elapsed());
                    cost.bytes = self.bytes;
                    return (Continuation::Suspended(self), cost);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};

    use super::*;
    use crate::domain::{DomainIdentity, ProbeResult};
    use crate::entry::MetadataFields;

    struct Scripted {
        entries: VecDeque<RawEntry>,
        kinds: HashMap<OsString, EntryKind>,
        identities: HashMap<OsString, FileIdentity>,
        resolutions: usize,
        by_descriptor: bool,
    }

    impl EntrySource for Scripted {
        fn next_entry(&mut self) -> Option<Result<RawEntry, FsError>> {
            self.entries.pop_front().map(Ok)
        }

        fn resolve_kind(&mut self, name: &OsStr) -> Result<EntryKind, FsError> {
            self.resolutions += 1;
            self.kinds.get(name).copied().ok_or(FsError::NotFound)
        }

        fn resolve_identity(&mut self, name: &OsStr) -> Result<Option<FileIdentity>, FsError> {
            self.resolutions += 1;
            self.identities.get(name).copied().map(Some).ok_or(FsError::NotFound)
        }

        fn resolves_by_descriptor(&self) -> bool {
            self.by_descriptor
        }
    }

    fn raw(name: &str, kind: Option<EntryKind>) -> RawEntry {
        RawEntry { name: OsString::from(name), kind, identity: None, metadata: Metadata::default() }
    }

    fn scripted(entries: Vec<RawEntry>, kinds: Vec<(&str, EntryKind)>) -> Box<dyn ListingSession> {
        scripted_with(entries, kinds, Vec::new(), IdentitySource::Unknown, true)
    }

    fn scripted_with(
        entries: Vec<RawEntry>,
        kinds: Vec<(&str, EntryKind)>,
        identities: Vec<(&str, FileIdentity)>,
        identity_source: IdentitySource,
        by_descriptor: bool,
    ) -> Box<dyn ListingSession> {
        let source = Scripted {
            entries: entries.into_iter().collect(),
            kinds: kinds.into_iter().map(|(name, kind)| (OsString::from(name), kind)).collect(),
            identities: identities.into_iter().map(|(name, identity)| (OsString::from(name), identity)).collect(),
            resolutions: 0,
            by_descriptor,
        };
        let opener = move || {
            let mut domain = ProbeResult { identity: DomainIdentity::Unknown, ..ProbeResult::unknown() };
            domain.capabilities.identity_source = identity_source;
            Ok(Opened {
                directory: EntryInfo { kind: EntryKind::Directory, metadata: Metadata::default(), identity: None },
                domain,
                source,
            })
        };
        Box::new(StdSession::new(PathBuf::from("/scripted"), Ceilings::UNBOUNDED, CancellationToken::new(), opener))
    }

    #[test]
    fn a_per_child_identity_read_is_leased_and_counted_only_where_the_domain_declares_it() {
        let identity = FileIdentity { device: 9, inode: 1 << 70 };
        let entries: Vec<RawEntry> = (0..3).map(|i| raw(&format!("e{i}"), Some(EntryKind::File))).collect();
        let session = scripted_with(
            entries,
            Vec::new(),
            vec![("e0", identity), ("e2", identity)],
            IdentitySource::PerChildRead,
            false,
        );
        let (listing, costs, suspensions) = drain(session, Lease { entries: 64, operations: 1 });
        assert_eq!(
            suspensions, 2,
            "RFC 10.2: a per-child identity read holds the operations lease like any other per-child operation"
        );
        assert_eq!(costs.iter().map(|cost| cost.identity_reads).sum::<u32>(), 3);
        assert_eq!(costs.iter().map(|cost| cost.metadata_operations).sum::<u32>(), 0);
        let identities: Vec<Option<FileIdentity>> = listing.entries.iter().map(|entry| entry.info.identity).collect();
        assert_eq!(
            identities,
            vec![Some(identity), None, Some(identity)],
            "a path-based identity lookup that answers NotFound keeps the child with identity None, never drops it"
        );
        assert_eq!(listing.entries.len(), 3, "no child is dropped when its path-based identity lookup fails");

        let entries: Vec<RawEntry> = (0..3).map(|i| raw(&format!("e{i}"), Some(EntryKind::File))).collect();
        let inline = scripted_with(entries, Vec::new(), vec![("e0", identity)], IdentitySource::Inline, false);
        let (_, costs, suspensions) = drain(inline, Lease { entries: 64, operations: 1 });
        assert_eq!((suspensions, costs.iter().map(|cost| cost.identity_reads).sum::<u32>()), (0, 0));
    }

    #[test]
    fn a_directory_renamed_during_a_path_based_enumeration_keeps_every_remaining_child() {
        let entries: Vec<RawEntry> = (0..3).map(|i| raw(&format!("e{i}"), None)).collect();
        let session = scripted_with(entries, Vec::new(), Vec::new(), IdentitySource::None, false);
        let (listing, _costs, _) = drain(session, Lease { entries: 64, operations: 64 });
        assert_eq!(
            listing.entries.len(),
            3,
            "RFC 10.1: on a path-based source NotFound is not proof the entry vanished, so a directory renamed \
             mid-enumeration does not silently lose the children whose path-based kind lookup now fails"
        );
        assert!(
            listing.entries.iter().all(|entry| entry.info.kind == ObservedKind::Unresolved),
            "a failed path-based kind lookup leaves the child unresolved, never removed"
        );
    }

    fn drain(mut session: Box<dyn ListingSession>, lease: Lease) -> (DirectoryListing, Vec<SessionCost>, usize) {
        let mut costs = Vec::new();
        let mut suspensions = 0;
        loop {
            let (continuation, cost) = session.resume(lease);
            costs.push(cost);
            match continuation {
                Continuation::Suspended(next) => {
                    suspensions += 1;
                    session = next;
                }
                Continuation::Finished(SessionOutcome::Complete(listing)) => return (listing, costs, suspensions),
                Continuation::Finished(other) => panic!("the session ended {other:?}"),
            }
        }
    }

    #[test]
    fn an_unknown_kind_is_resolved_counted_and_charged_as_a_metadata_operation() {
        let session = scripted(
            vec![
                raw("known", Some(EntryKind::File)),
                raw("unknown-dir", None),
                raw("known-dir", Some(EntryKind::Directory)),
                raw("unknown-file", None),
            ],
            vec![("unknown-dir", EntryKind::Directory), ("unknown-file", EntryKind::File)],
        );
        let (listing, costs, suspensions) = drain(session, Lease { entries: 64, operations: 64 });
        assert_eq!(suspensions, 0);
        let total: u32 = costs.iter().map(|cost| cost.kind_resolutions).sum();
        let metadata: u32 = costs.iter().map(|cost| cost.metadata_operations).sum();
        assert_eq!(
            (total, metadata),
            (2, 2),
            "RFC 10.1: kind resolution reads are counted and charged as metadata operations"
        );
        let kinds: Vec<Option<EntryKind>> = listing.entries.iter().map(|entry| entry.info.kind.resolved()).collect();
        assert_eq!(
            kinds,
            vec![Some(EntryKind::File), Some(EntryKind::Directory), Some(EntryKind::Directory), Some(EntryKind::File)]
        );
        let enumerated: u64 = costs.iter().map(|cost| cost.entries_enumerated).sum();
        assert_eq!(enumerated, 4);
    }

    #[test]
    fn a_session_holds_operations_lease_before_each_kind_resolution() {
        let entries: Vec<RawEntry> =
            (0..6).map(|i| raw(&format!("e{i}"), if i % 2 == 0 { None } else { Some(EntryKind::File) })).collect();
        let kinds = vec![("e0", EntryKind::File), ("e2", EntryKind::Directory), ("e4", EntryKind::File)];
        let session = scripted(entries, kinds);
        let (listing, costs, suspensions) = drain(session, Lease { entries: 64, operations: 1 });
        assert_eq!(
            suspensions, 2,
            "RFC 10.2: before each kind-resolution read the session must hold remaining lease; three unknown kinds \
             under a one-operation lease take three leases"
        );
        for cost in &costs {
            assert!(cost.kind_resolutions <= 1, "one lease covered {} resolutions", cost.kind_resolutions);
        }
        assert_eq!(listing.entries.len(), 6, "every entry is enumerated exactly once across the leases");
        let names: Vec<&OsStr> = listing.entries.iter().map(|entry| entry.name.as_os_str()).collect();
        assert_eq!(names, ["e0", "e1", "e2", "e3", "e4", "e5"]);
        assert!(listing.entries.iter().all(|entry| entry.info.kind.resolved().is_some()));
    }

    #[test]
    fn a_vanished_unknown_entry_is_skipped_and_a_failed_resolution_is_unresolved() {
        let session = scripted(vec![raw("gone", None), raw("kept", Some(EntryKind::File))], Vec::new());
        let (listing, costs, _) = drain(session, Lease { entries: 64, operations: 64 });
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(costs.iter().map(|cost| cost.kind_resolutions).sum::<u32>(), 1);
    }

    fn temp_directory(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tree-fucker-std-fs-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn the_platform_session_lists_a_real_directory_with_inline_kinds() {
        let dir = temp_directory("listing");
        std::fs::write(dir.join("file"), b"abc").expect("file");
        std::fs::create_dir(dir.join("sub")).expect("dir");
        let fs = StdFileSystem::new();
        let outcome = crate::fs::list_directory(&fs, &dir, &RelativePath::root(), Ceilings::UNBOUNDED);
        let SessionOutcome::Complete(listing) = outcome else {
            panic!("the listing ended {outcome:?}");
        };
        let mut names: Vec<String> = listing.entries.iter().map(|e| e.name.to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names, ["file", "sub"]);
        for entry in &listing.entries {
            assert!(entry.info.kind.resolved().is_some(), "{:?}", entry.info.kind);
            if cfg!(unix) {
                assert!(entry.info.identity.is_some(), "RFC 10.1: the inode is inline in the directory entry");
            }
        }
        let batch = EnrichmentBatch {
            fields: MetadataFields::ALL,
            directory: true,
            children: vec![OsString::from("file"), OsString::from("missing")],
        };
        let enriched = fs.enrich(&dir, &RelativePath::root(), &batch).expect("enrich");
        assert_eq!(enriched.children.len(), 1);
        assert_eq!(enriched.children[0].1.size, Some(3));
        assert!(enriched.failed.is_empty());
        assert!(enriched.directory.is_some());
        assert_eq!(enriched.metadata_operations, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_kind_resolution_between_leases_follows_the_held_descriptor_across_a_rename() {
        let dir = temp_directory("renamed");
        std::fs::write(dir.join("file"), b"abc").expect("file");
        std::fs::create_dir(dir.join("sub")).expect("dir");
        let moved = dir.with_file_name(format!("tree-fucker-std-fs-{}-renamed-target", std::process::id()));
        let _ = std::fs::remove_dir_all(&moved);

        let mut opened = open_platform(&crate::domain::UnknownProbe, &dir, None).expect("open");
        std::fs::rename(&dir, &moved).expect("rename");
        assert!(
            std::fs::symlink_metadata(dir.join("file")).is_err(),
            "the old path no longer resolves, so a path-based resolution would report NotFound"
        );
        assert_eq!(opened.source.resolve_kind(OsStr::new("file")), Ok(EntryKind::File));
        assert_eq!(opened.source.resolve_kind(OsStr::new("sub")), Ok(EntryKind::Directory));
        assert_eq!(opened.source.resolve_kind(OsStr::new("missing")), Err(FsError::NotFound));
        std::fs::rename(&moved, &dir).expect("rename back");

        let fs = StdFileSystem::new();
        let session = fs.open_listing(&dir, &RelativePath::root(), Ceilings::UNBOUNDED, CancellationToken::new());
        let (continuation, _) = session.resume(Lease { entries: 1, operations: 64 });
        let Continuation::Suspended(next) = continuation else {
            panic!("a one-entry lease over two entries must suspend");
        };
        std::fs::rename(&dir, &moved).expect("rename between leases");
        let (continuation, _) = next.resume(Lease::UNBOUNDED);
        let Continuation::Finished(SessionOutcome::Complete(listing)) = continuation else {
            panic!("the listing did not complete after the rename");
        };
        let mut names: Vec<String> = listing.entries.iter().map(|e| e.name.to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names, ["file", "sub"], "RFC 10.2: continuation state is the held descriptor, never the path");
        assert!(listing.entries.iter().all(|entry| entry.info.kind.resolved().is_some()));
        let _ = std::fs::remove_dir_all(&moved);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn anchored_listing(
        fs: &StdFileSystem,
        root: &Path,
        path: &RelativePath,
        beneath: Option<&Anchor>,
    ) -> SessionOutcome {
        let at = ListingAt { beneath, anchored: true };
        let mut session = fs.open_listing_at(root, path, at, Ceilings::UNBOUNDED, CancellationToken::new());
        loop {
            match session.resume(Lease::UNBOUNDED).0 {
                Continuation::Suspended(next) => session = next,
                Continuation::Finished(outcome) => return outcome,
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_listing_beneath_an_anchor_follows_the_parent_descriptor_across_a_rename() {
        let dir = temp_directory("beneath");
        std::fs::create_dir(dir.join("sub")).expect("dir");
        std::fs::write(dir.join("sub/file"), b"abc").expect("file");
        let moved = dir.with_file_name(format!("tree-fucker-std-fs-{}-beneath-moved", std::process::id()));
        let _ = std::fs::remove_dir_all(&moved);
        let fs = StdFileSystem::new();
        let SessionOutcome::Complete(parent) = anchored_listing(&fs, &dir, &RelativePath::root(), None) else {
            panic!("the parent listing did not complete");
        };
        let anchor = parent.anchor.expect("an anchored listing carries its anchor");
        std::fs::rename(&dir, &moved).expect("rename");
        let sub = RelativePath::parse("sub").expect("path");
        let SessionOutcome::Complete(child) = anchored_listing(&fs, &dir, &sub, Some(&anchor)) else {
            panic!("RFC 20: a listing beneath an anchor opens relative to the held descriptor, never the old path");
        };
        let names: Vec<&OsStr> = child.entries.iter().map(|entry| entry.name.as_os_str()).collect();
        assert_eq!(names, ["file"]);
        assert!(fs.resolve_domain_beneath(&dir, &sub, Some(&anchor), Some(&parent.domain)).is_ok());
        assert!(fs.resolve_domain(&dir, &sub, Some(&parent.domain)).is_err(), "the path no longer resolves");
        let _ = std::fs::remove_dir_all(&moved);
    }

    #[cfg(unix)]
    #[test]
    fn an_anchor_for_another_directory_is_ignored_and_the_path_decides() {
        let dir = temp_directory("foreign-anchor");
        for side in ["left", "right"] {
            std::fs::create_dir_all(dir.join(side).join("sub")).expect("dir");
            std::fs::write(dir.join(side).join("sub").join(side), b"x").expect("file");
        }
        let fs = StdFileSystem::new();
        let SessionOutcome::Complete(left) = anchored_listing(&fs, &dir.join("left"), &RelativePath::root(), None)
        else {
            panic!("the left listing did not complete");
        };
        let foreign = left.anchor.expect("anchor");
        let sub = RelativePath::parse("sub").expect("path");
        let SessionOutcome::Complete(right) = anchored_listing(&fs, &dir.join("right"), &sub, Some(&foreign)) else {
            panic!("the right listing did not complete");
        };
        let names: Vec<&OsStr> = right.entries.iter().map(|entry| entry.name.as_os_str()).collect();
        assert_eq!(names, ["right"], "an anchor whose directory is not the parent is never used");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_is_never_listed_as_the_directory_it_names() {
        let dir = temp_directory("listed-link");
        std::fs::create_dir(dir.join("target")).expect("dir");
        std::os::unix::fs::symlink(dir.join("target"), dir.join("link")).expect("symlink");
        let fs = StdFileSystem::new();
        let SessionOutcome::Complete(parent) = anchored_listing(&fs, &dir, &RelativePath::root(), None) else {
            panic!("the parent listing did not complete");
        };
        let link = RelativePath::parse("link").expect("path");
        for beneath in [None, parent.anchor.as_ref()] {
            assert_eq!(
                anchored_listing(&fs, &dir, &link, beneath),
                SessionOutcome::Failed(FsError::NotDirectory),
                "RFC 14.2: symbolic links are represented and never traversed"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn the_windows_session_supplies_timestamps_and_size_inline() {
        let dir = temp_directory("inline");
        std::fs::write(dir.join("file"), b"abcd").expect("file");
        let fs = StdFileSystem::new();
        let outcome = crate::fs::list_directory(&fs, &dir, &RelativePath::root(), Ceilings::UNBOUNDED);
        let SessionOutcome::Complete(listing) = outcome else {
            panic!("the listing ended {outcome:?}");
        };
        assert_eq!(
            listing.supplied_fields,
            MetadataFields { modified: true, created: true, size: true, permissions: false }
        );
        let file = listing.entries.iter().find(|e| e.name == "file").expect("file");
        assert_eq!(file.info.metadata.size, Some(4));
        assert!(file.info.metadata.modified.is_some());
        assert_eq!(listing.domain.capabilities.metadata_sources, inline_metadata_sources());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
