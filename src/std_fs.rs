use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crate::domain::{
    DeclarationSource, DomainProbe, IdentitySource, KindSource, MetadataSource, MetadataSources, ProbeResult,
};
use crate::entry::{EntryKind, FileIdentity, Metadata};
use crate::fs::{
    CancellationToken, Ceilings, Continuation, DirEntry, DirectoryListing, Enrichment, EnrichmentBatch, EntryInfo,
    FileSystem, FsCapabilities, FsError, Lease, ListingSession, Observation, ObservedKind, SessionCost, SessionOutcome,
    WatcherKind, WatcherSink, entry_bytes,
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
    let mut result = probe.probe(full, parent)?;
    result.capabilities.kind_source = KindSource::Sometimes;
    result.capabilities.identity_source = if cfg!(unix) { IdentitySource::Inline } else { IdentitySource::None };
    result.capabilities.metadata_sources = inline_metadata_sources();
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
        ceilings: Ceilings,
        cancel: CancellationToken,
    ) -> Box<dyn ListingSession> {
        let full = path.under(root);
        let probe = self.probe.clone();
        let opener = {
            let full = full.clone();
            move || open_platform(probe.as_ref(), &full)
        };
        Box::new(StdSession::new(full, ceilings, cancel, opener))
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
}

pub struct Opened<S> {
    pub directory: EntryInfo,
    pub domain: ProbeResult,
    pub source: S,
}

fn open_platform(probe: &dyn DomainProbe, full: &Path) -> Result<Opened<PlatformSource>, FsError> {
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
    #[cfg(unix)]
    fn open(full: &Path, own: &std::fs::Metadata) -> Result<PlatformSource, FsError> {
        use std::os::unix::fs::MetadataExt;

        use rustix::fs::{Mode, OFlags};
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        let fd = rustix::fs::open(full, flags, Mode::empty()).map_err(std::io::Error::from)?;
        let entries = rustix::fs::Dir::new(fd).map_err(std::io::Error::from)?;
        Ok(PlatformSource { device: own.dev(), entries })
    }

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
                kind: unix_kind(entry.file_type()),
                identity: Some(FileIdentity { device: self.device, inode: entry.ino() }),
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
        }
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
                match resolved {
                    Ok(kind) => ObservedKind::Resolved(kind),
                    Err(FsError::NotFound) => {
                        cost.entries_enumerated += 1;
                        return true;
                    }
                    Err(_) => ObservedKind::Unresolved,
                }
            }
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
        resolutions: usize,
    }

    impl EntrySource for Scripted {
        fn next_entry(&mut self) -> Option<Result<RawEntry, FsError>> {
            self.entries.pop_front().map(Ok)
        }

        fn resolve_kind(&mut self, name: &OsStr) -> Result<EntryKind, FsError> {
            self.resolutions += 1;
            self.kinds.get(name).copied().ok_or(FsError::NotFound)
        }
    }

    fn raw(name: &str, kind: Option<EntryKind>) -> RawEntry {
        RawEntry { name: OsString::from(name), kind, identity: None, metadata: Metadata::default() }
    }

    fn scripted(entries: Vec<RawEntry>, kinds: Vec<(&str, EntryKind)>) -> Box<dyn ListingSession> {
        let source = Scripted {
            entries: entries.into_iter().collect(),
            kinds: kinds.into_iter().map(|(name, kind)| (OsString::from(name), kind)).collect(),
            resolutions: 0,
        };
        let opener = move || {
            Ok(Opened {
                directory: EntryInfo { kind: EntryKind::Directory, metadata: Metadata::default(), identity: None },
                domain: ProbeResult { identity: DomainIdentity::Unknown, ..ProbeResult::unknown() },
                source,
            })
        };
        Box::new(StdSession::new(PathBuf::from("/scripted"), Ceilings::UNBOUNDED, CancellationToken::new(), opener))
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

        let mut opened = open_platform(&crate::domain::UnknownProbe, &dir).expect("open");
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
