use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::entry::{EntryKind, FileIdentity, Metadata, MetadataFields};
use crate::fs::{
    DirEntry, DirectoryListing, Enrichment, EntryInfo, FileSystem, FsCapabilities, FsError, HintKind, IdentitySource,
    KindSource, Observation, ObservationSources, ObservedKind, WatcherEvent, WatcherKind, WatcherSink,
};
use crate::ids::WatchId;
use crate::path::{CaseSensitivity, RelativePath};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FakeOp {
    Metadata,
    ReadDir,
    ResolveKind,
    Enrich,
    Watch,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId(u64);

impl DomainId {
    pub const ROOT: DomainId = DomainId(0);

    pub const fn new(value: u64) -> DomainId {
        DomainId(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for DomainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "domain {}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CostScope {
    Path(RelativePath),
    Domain(DomainId),
    Everything,
}

impl CostScope {
    pub fn path(p: &str) -> CostScope {
        CostScope::Path(FakeFileSystem::path(p))
    }
}

#[derive(Clone, Debug)]
pub enum FailureMode {
    Once(FsError),
    Times(u32, FsError),
    Always(FsError),
}

struct Failure {
    path: RelativePath,
    op: FakeOp,
    mode: FailureMode,
}

struct Watch {
    path: RelativePath,
    recursive: bool,
    sink: Arc<dyn WatcherSink>,
}

struct InjectedChild {
    dir: RelativePath,
    name: std::ffi::OsString,
    info: EntryInfo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InjectedPosition {
    Last,
    First,
}

struct Inner {
    nodes: BTreeMap<RelativePath, EntryInfo>,
    root_present: bool,
    caps: FsCapabilities,
    failures: Vec<Failure>,
    panics: Vec<(RelativePath, FakeOp)>,
    injected: Vec<InjectedChild>,
    injected_position: InjectedPosition,
    watches: HashMap<WatchId, Watch>,
    next_watch: u64,
    next_inode: u64,
    clock: SystemTime,
    drop_events: bool,
    paused: bool,
    paused_queue: VecDeque<(WatchId, WatcherEvent)>,
    ops: Vec<(FakeOp, RelativePath)>,
    root_kind: EntryKind,
    costs: HashMap<(CostScope, FakeOp), Duration>,
    domains: Vec<(RelativePath, DomainId)>,
    sources: HashMap<DomainId, ObservationSources>,
    default_sources: ObservationSources,
    unknown_kinds: BTreeSet<RelativePath>,
}

pub struct FakeFileSystem {
    root: PathBuf,
    inner: Mutex<Inner>,
}

fn lock(inner: &Mutex<Inner>) -> std::sync::MutexGuard<'_, Inner> {
    match inner.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl FakeFileSystem {
    pub fn new(watcher: WatcherKind) -> FakeFileSystem {
        FakeFileSystem::with_capabilities(FsCapabilities {
            case: CaseSensitivity::Sensitive,
            stable_identity: true,
            watcher,
        })
    }

    pub fn with_capabilities(caps: FsCapabilities) -> FakeFileSystem {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut nodes = BTreeMap::new();
        nodes.insert(
            RelativePath::root(),
            EntryInfo {
                kind: EntryKind::Directory,
                metadata: Metadata {
                    modified: Some(base),
                    created: Some(base),
                    size: Some(0),
                    permissions: Some(0o755),
                },
                identity: Some(FileIdentity { device: 1, inode: 1 }),
            },
        );
        FakeFileSystem {
            root: PathBuf::from("/fake"),
            inner: Mutex::new(Inner {
                nodes,
                root_present: true,
                caps,
                failures: Vec::new(),
                panics: Vec::new(),
                injected: Vec::new(),
                injected_position: InjectedPosition::Last,
                watches: HashMap::new(),
                next_watch: 1,
                next_inode: 2,
                clock: base,
                drop_events: false,
                paused: false,
                paused_queue: VecDeque::new(),
                ops: Vec::new(),
                root_kind: EntryKind::Directory,
                costs: HashMap::new(),
                domains: Vec::new(),
                sources: HashMap::new(),
                default_sources: ObservationSources::INLINE,
                unknown_kinds: BTreeSet::new(),
            }),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn path(p: &str) -> RelativePath {
        RelativePath::parse(p).expect("valid test path")
    }

    fn tick(inner: &mut Inner) -> SystemTime {
        inner.clock += Duration::from_secs(1);
        inner.clock
    }

    fn touch_parent(inner: &mut Inner, path: &RelativePath) {
        let Some(parent) = path.parent() else { return };
        let now = Self::tick(inner);
        if let Some(info) = inner.nodes.get_mut(&parent) {
            info.metadata.modified = Some(now);
        }
    }

    pub fn mkdir(&self, p: &str) {
        let path = Self::path(p);
        let mut inner = lock(&self.inner);
        let now = Self::tick(&mut inner);
        let inode = inner.next_inode;
        inner.next_inode += 1;
        inner.nodes.insert(
            path.clone(),
            EntryInfo {
                kind: EntryKind::Directory,
                metadata: Metadata { modified: Some(now), created: Some(now), size: Some(0), permissions: Some(0o755) },
                identity: Some(FileIdentity { device: 1, inode }),
            },
        );
        Self::touch_parent(&mut inner, &path);
        Self::emit(&mut inner, vec![path], HintKind::Create);
    }

    pub fn create_file(&self, p: &str, size: u64) {
        self.create_kind(p, EntryKind::File, size);
    }

    pub fn create_symlink(&self, p: &str) {
        self.create_kind(p, EntryKind::Symlink, 0);
    }

    pub fn create_kind(&self, p: &str, kind: EntryKind, size: u64) {
        let path = Self::path(p);
        let mut inner = lock(&self.inner);
        let now = Self::tick(&mut inner);
        let inode = inner.next_inode;
        inner.next_inode += 1;
        inner.nodes.insert(
            path.clone(),
            EntryInfo {
                kind,
                metadata: Metadata {
                    modified: Some(now),
                    created: Some(now),
                    size: Some(size),
                    permissions: Some(0o644),
                },
                identity: Some(FileIdentity { device: 1, inode }),
            },
        );
        Self::touch_parent(&mut inner, &path);
        Self::emit(&mut inner, vec![path], HintKind::Create);
    }

    pub fn remove(&self, p: &str) {
        let path = Self::path(p);
        let mut inner = lock(&self.inner);
        let keys: Vec<RelativePath> = inner.nodes.keys().filter(|k| k.starts_with(&path)).cloned().collect();
        for key in keys {
            inner.nodes.remove(&key);
        }
        Self::touch_parent(&mut inner, &path);
        Self::emit(&mut inner, vec![path], HintKind::Remove);
    }

    pub fn rename(&self, from: &str, to: &str) {
        let from = Self::path(from);
        let to = Self::path(to);
        let mut inner = lock(&self.inner);
        let moved: Vec<(RelativePath, EntryInfo)> =
            inner.nodes.iter().filter(|(k, _)| k.starts_with(&from)).map(|(k, v)| (k.clone(), *v)).collect();
        for (key, _) in &moved {
            inner.nodes.remove(key);
        }
        for (key, info) in moved {
            if let Some(rebased) = key.rebase(&from, &to) {
                inner.nodes.insert(rebased, info);
            }
        }
        Self::touch_parent(&mut inner, &from);
        Self::touch_parent(&mut inner, &to);
        Self::emit(&mut inner, vec![from, to], HintKind::Rename);
    }

    pub fn set_size_silently(&self, p: &str, size: u64) {
        let path = Self::path(p);
        let mut inner = lock(&self.inner);
        if let Some(info) = inner.nodes.get_mut(&path) {
            info.metadata.size = Some(size);
        }
    }

    pub fn add_silently(&self, p: &str, kind: EntryKind) {
        let path = Self::path(p);
        let mut inner = lock(&self.inner);
        let now = inner.clock;
        let inode = inner.next_inode;
        inner.next_inode += 1;
        inner.nodes.insert(
            path,
            EntryInfo {
                kind,
                metadata: Metadata { modified: Some(now), created: Some(now), size: Some(0), permissions: Some(0o644) },
                identity: Some(FileIdentity { device: 1, inode }),
            },
        );
    }

    pub fn remove_silently(&self, p: &str) {
        let path = Self::path(p);
        let mut inner = lock(&self.inner);
        let keys: Vec<RelativePath> = inner.nodes.keys().filter(|k| k.starts_with(&path)).cloned().collect();
        for key in keys {
            inner.nodes.remove(&key);
        }
    }

    pub fn clear_identity(&self, p: &str) {
        let path = Self::path(p);
        let mut inner = lock(&self.inner);
        if let Some(info) = inner.nodes.get_mut(&path) {
            info.identity = None;
        }
    }

    pub fn set_mtime(&self, p: &str, mtime: SystemTime) {
        let path = Self::path(p);
        let mut inner = lock(&self.inner);
        if let Some(info) = inner.nodes.get_mut(&path) {
            info.metadata.modified = Some(mtime);
        }
    }

    pub fn mtime(&self, p: &str) -> Option<SystemTime> {
        let path = Self::path(p);
        lock(&self.inner).nodes.get(&path).and_then(|i| i.metadata.modified)
    }

    pub fn touch(&self, p: &str) {
        let path = Self::path(p);
        let mut inner = lock(&self.inner);
        let now = Self::tick(&mut inner);
        if let Some(info) = inner.nodes.get_mut(&path) {
            info.metadata.modified = Some(now);
        }
        Self::emit(&mut inner, vec![path], HintKind::Modify);
    }

    pub fn replace_with_kind(&self, p: &str, kind: EntryKind) {
        let path = Self::path(p);
        let mut inner = lock(&self.inner);
        let keys: Vec<RelativePath> =
            inner.nodes.keys().filter(|k| k.starts_with(&path) && **k != path).cloned().collect();
        for key in keys {
            inner.nodes.remove(&key);
        }
        let now = Self::tick(&mut inner);
        let inode = inner.next_inode;
        inner.next_inode += 1;
        inner.nodes.insert(
            path.clone(),
            EntryInfo {
                kind,
                metadata: Metadata { modified: Some(now), created: Some(now), size: Some(0), permissions: Some(0o644) },
                identity: Some(FileIdentity { device: 1, inode }),
            },
        );
        Self::emit(&mut inner, vec![path], HintKind::Unknown);
    }

    pub fn remove_root(&self) {
        let mut inner = lock(&self.inner);
        inner.root_present = false;
        Self::emit(&mut inner, vec![RelativePath::root()], HintKind::Remove);
    }

    pub fn restore_root(&self) {
        let mut inner = lock(&self.inner);
        inner.root_present = true;
        inner.nodes.retain(|k, _| k.is_root());
        let now = Self::tick(&mut inner);
        let inode = inner.next_inode;
        inner.next_inode += 1;
        if let Some(root) = inner.nodes.get_mut(&RelativePath::root()) {
            root.identity = Some(FileIdentity { device: 1, inode });
            root.metadata.modified = Some(now);
        }
    }

    pub fn set_root_kind(&self, kind: EntryKind) {
        let mut inner = lock(&self.inner);
        inner.root_kind = kind;
        if let Some(root) = inner.nodes.get_mut(&RelativePath::root()) {
            root.kind = kind;
        }
    }

    pub fn fail(&self, p: &str, op: FakeOp, mode: FailureMode) {
        let path = Self::path(p);
        lock(&self.inner).failures.push(Failure { path, op, mode });
    }

    pub fn clear_failures(&self) {
        lock(&self.inner).failures.clear();
    }

    pub fn panic_once(&self, p: &str, op: FakeOp) {
        let path = Self::path(p);
        lock(&self.inner).panics.push((path, op));
    }

    fn take_panic(inner: &mut Inner, path: &RelativePath, op: FakeOp) -> bool {
        match inner.panics.iter().position(|(p, o)| p == path && *o == op) {
            Some(index) => {
                inner.panics.remove(index);
                true
            }
            None => false,
        }
    }

    pub fn inject_child(&self, dir: &str, name: impl Into<std::ffi::OsString>, kind: EntryKind) {
        let dir = Self::path(dir);
        let mut inner = lock(&self.inner);
        let now = Self::tick(&mut inner);
        let inode = inner.next_inode;
        inner.next_inode += 1;
        inner.injected.push(InjectedChild {
            dir,
            name: name.into(),
            info: EntryInfo {
                kind,
                metadata: Metadata { modified: Some(now), created: Some(now), size: Some(0), permissions: Some(0o644) },
                identity: Some(FileIdentity { device: 1, inode }),
            },
        });
    }

    pub fn clear_injected_children(&self) {
        lock(&self.inner).injected.clear();
    }

    pub fn set_injected_position(&self, position: InjectedPosition) {
        lock(&self.inner).injected_position = position;
    }

    pub fn drop_events(&self, drop: bool) {
        lock(&self.inner).drop_events = drop;
    }

    pub fn pause_events(&self) {
        lock(&self.inner).paused = true;
    }

    pub fn resume_events(&self) {
        let mut inner = lock(&self.inner);
        inner.paused = false;
        let queued: Vec<(WatchId, WatcherEvent)> = inner.paused_queue.drain(..).collect();
        for (watch, event) in queued {
            if let Some(w) = inner.watches.get(&watch) {
                w.sink.deliver(event);
            }
        }
    }

    pub fn set_cost(&self, scope: CostScope, op: FakeOp, cost: Duration) {
        lock(&self.inner).costs.insert((scope, op), cost);
    }

    pub fn cost_of(&self, op: FakeOp, path: &RelativePath) -> Duration {
        Self::scoped_cost(&lock(&self.inner), op, path)
    }

    pub fn set_sources(&self, domain: DomainId, sources: ObservationSources) {
        lock(&self.inner).sources.insert(domain, sources);
    }

    pub fn set_default_sources(&self, sources: ObservationSources) {
        lock(&self.inner).default_sources = sources;
    }

    pub fn report_unknown_kind(&self, p: &str) {
        let path = Self::path(p);
        lock(&self.inner).unknown_kinds.insert(path);
    }

    pub fn sources_of(&self, path: &RelativePath) -> ObservationSources {
        let inner = lock(&self.inner);
        Self::sources_for(&inner, path)
    }

    fn sources_for(inner: &Inner, path: &RelativePath) -> ObservationSources {
        let domain = Self::domain_for(inner, path);
        inner.sources.get(&domain).copied().unwrap_or(inner.default_sources)
    }

    fn enumerated_kind(inner: &Inner, path: &RelativePath, kind: EntryKind) -> ObservedKind {
        match Self::sources_for(inner, path).kind {
            KindSource::Always => ObservedKind::Resolved(kind),
            KindSource::Never => ObservedKind::Unresolved,
            KindSource::Sometimes => {
                if inner.unknown_kinds.contains(path) {
                    ObservedKind::Unresolved
                } else {
                    ObservedKind::Resolved(kind)
                }
            }
        }
    }

    fn observe(inner: &mut Inner, path: &RelativePath, info: EntryInfo) -> (Observation, u32) {
        let sources = Self::sources_for(inner, path);
        let identity = match sources.identity {
            IdentitySource::Inline => info.identity,
            IdentitySource::PerChildRead | IdentitySource::None => None,
        };
        let metadata = info.metadata.project(sources.metadata.inline());
        let mut operations = 0;
        let kind = match Self::enumerated_kind(inner, path, info.kind) {
            ObservedKind::Resolved(kind) => ObservedKind::Resolved(kind),
            ObservedKind::Unresolved => {
                operations += 1;
                inner.ops.push((FakeOp::ResolveKind, path.clone()));
                match Self::take_failure(inner, path, FakeOp::ResolveKind) {
                    Some(_) => ObservedKind::Unresolved,
                    None => match Self::lookup(inner, path) {
                        Ok(resolved) => ObservedKind::Resolved(resolved.kind),
                        Err(_) => ObservedKind::Unresolved,
                    },
                }
            }
        };
        (Observation { kind, metadata, identity }, operations)
    }

    pub fn listing_cost(&self, path: &RelativePath) -> Duration {
        let inner = lock(&self.inner);
        let mut total = Self::scoped_cost(&inner, FakeOp::ReadDir, path);
        for child in Self::child_paths(&inner, path) {
            let kind = inner.nodes.get(&child).map(|info| info.kind).unwrap_or(EntryKind::Other);
            if Self::enumerated_kind(&inner, &child, kind) == ObservedKind::Unresolved {
                total += Self::scoped_cost(&inner, FakeOp::ResolveKind, &child);
            }
        }
        total
    }

    pub fn enrichment_cost(&self, path: &RelativePath) -> Duration {
        let inner = lock(&self.inner);
        let mut total = Self::scoped_cost(&inner, FakeOp::Enrich, path);
        for child in Self::child_paths(&inner, path) {
            total += Self::scoped_cost(&inner, FakeOp::Enrich, &child);
        }
        total
    }

    fn child_paths(inner: &Inner, path: &RelativePath) -> Vec<RelativePath> {
        let mut children: Vec<RelativePath> =
            inner.nodes.keys().filter(|k| k.parent().map(|p| p == *path).unwrap_or(false)).cloned().collect();
        for injected in inner.injected.iter().filter(|c| c.dir == *path) {
            if let Ok(child) = path.join(&injected.name) {
                children.push(child);
            }
        }
        children
    }

    fn scoped_cost(inner: &Inner, op: FakeOp, path: &RelativePath) -> Duration {
        if let Some(cost) = inner.costs.get(&(CostScope::Path(path.clone()), op)) {
            return *cost;
        }
        let domain = Self::domain_for(inner, path);
        if let Some(cost) = inner.costs.get(&(CostScope::Domain(domain), op)) {
            return *cost;
        }
        inner.costs.get(&(CostScope::Everything, op)).copied().unwrap_or(Duration::ZERO)
    }

    pub fn set_domain(&self, prefix: &str, domain: DomainId) {
        let path = Self::path(prefix);
        let mut inner = lock(&self.inner);
        Self::assign_domain(&mut inner, path, domain);
    }

    pub fn remount(&self, prefix: &str, domain: DomainId) {
        let path = Self::path(prefix);
        let mut inner = lock(&self.inner);
        assert!(inner.nodes.contains_key(&path), "remount of {path}, which the fake filesystem does not contain");
        Self::assign_domain(&mut inner, path, domain);
    }

    pub fn domain_of(&self, path: &RelativePath) -> DomainId {
        Self::domain_for(&lock(&self.inner), path)
    }

    fn assign_domain(inner: &mut Inner, path: RelativePath, domain: DomainId) {
        match inner.domains.iter_mut().find(|(prefix, _)| *prefix == path) {
            Some(slot) => slot.1 = domain,
            None => inner.domains.push((path, domain)),
        }
    }

    fn domain_for(inner: &Inner, path: &RelativePath) -> DomainId {
        inner
            .domains
            .iter()
            .filter(|(prefix, _)| path.starts_with(prefix))
            .max_by_key(|(prefix, _)| prefix.depth())
            .map(|(_, domain)| *domain)
            .unwrap_or(DomainId::ROOT)
    }

    pub fn emit_storm(&self, paths: &[&str], kind: HintKind, repeat: usize) -> usize {
        let targets: Vec<RelativePath> = paths.iter().map(|p| Self::path(p)).collect();
        let mut inner = lock(&self.inner);
        for _ in 0..repeat {
            Self::emit(&mut inner, targets.clone(), kind);
        }
        repeat * targets.len()
    }

    pub fn emit_overflow(&self) {
        let inner = lock(&self.inner);
        for watch in inner.watches.values() {
            watch.sink.deliver(WatcherEvent::Overflow);
        }
    }

    pub fn emit_watcher_failure(&self, message: &str) {
        let mut inner = lock(&self.inner);
        let watches: Vec<Arc<dyn WatcherSink>> = inner.watches.drain().map(|(_, w)| w.sink).collect();
        for sink in watches {
            sink.deliver(WatcherEvent::Failed { message: message.to_string() });
        }
    }

    pub fn watch_count(&self) -> usize {
        lock(&self.inner).watches.len()
    }

    pub fn ops(&self) -> Vec<(FakeOp, RelativePath)> {
        lock(&self.inner).ops.clone()
    }

    pub fn clear_ops(&self) {
        lock(&self.inner).ops.clear();
    }

    pub fn count_ops(&self, op: FakeOp, p: &str) -> usize {
        let path = Self::path(p);
        lock(&self.inner).ops.iter().filter(|(o, k)| *o == op && *k == path).count()
    }

    pub fn contains(&self, p: &str) -> bool {
        lock(&self.inner).nodes.contains_key(&Self::path(p))
    }

    fn emit(inner: &mut Inner, paths: Vec<RelativePath>, kind: HintKind) {
        if inner.drop_events {
            return;
        }
        let targets: Vec<(WatchId, Arc<dyn WatcherSink>)> = inner
            .watches
            .iter()
            .filter(|(_, w)| {
                paths.iter().any(|p| {
                    if w.recursive {
                        p.starts_with(&w.path)
                    } else {
                        *p == w.path || p.parent().map(|parent| parent == w.path).unwrap_or(false)
                    }
                })
            })
            .map(|(id, w)| (*id, w.sink.clone()))
            .collect();
        for (id, sink) in targets {
            let event = WatcherEvent::Hint { paths: paths.clone(), kind };
            if inner.paused {
                inner.paused_queue.push_back((id, event));
            } else {
                sink.deliver(event);
            }
        }
    }

    fn take_failure(inner: &mut Inner, path: &RelativePath, op: FakeOp) -> Option<FsError> {
        let index = inner.failures.iter().position(|f| f.path == *path && f.op == op)?;
        let error = match &mut inner.failures[index].mode {
            FailureMode::Always(err) => err.clone(),
            FailureMode::Once(err) => {
                let err = err.clone();
                inner.failures.remove(index);
                err
            }
            FailureMode::Times(n, err) => {
                let err = err.clone();
                *n -= 1;
                if *n == 0 {
                    inner.failures.remove(index);
                }
                err
            }
        };
        Some(error)
    }

    fn lookup(inner: &Inner, path: &RelativePath) -> Result<EntryInfo, FsError> {
        if !inner.root_present {
            return Err(FsError::NotFound);
        }
        if path.is_root() {
            let mut info = inner.nodes.get(path).copied().ok_or(FsError::NotFound)?;
            info.kind = inner.root_kind;
            return Ok(info);
        }
        let mut cursor = path.parent();
        while let Some(candidate) = cursor {
            match inner.nodes.get(&candidate) {
                Some(info) if info.kind == EntryKind::Directory => {}
                Some(_) => return Err(FsError::NotDirectory),
                None => return Err(FsError::NotFound),
            }
            cursor = candidate.parent();
        }
        inner.nodes.get(path).copied().ok_or(FsError::NotFound)
    }
}

impl FileSystem for FakeFileSystem {
    fn capabilities(&self) -> FsCapabilities {
        lock(&self.inner).caps
    }

    fn canonicalize(&self, root: &Path) -> Result<PathBuf, FsError> {
        Ok(root.to_path_buf())
    }

    fn metadata(&self, _root: &Path, path: &RelativePath) -> Result<EntryInfo, FsError> {
        let mut inner = lock(&self.inner);
        inner.ops.push((FakeOp::Metadata, path.clone()));
        if Self::take_panic(&mut inner, path, FakeOp::Metadata) {
            drop(inner);
            panic!("injected metadata panic for {path}");
        }
        if let Some(err) = Self::take_failure(&mut inner, path, FakeOp::Metadata) {
            return Err(err);
        }
        Self::lookup(&inner, path)
    }

    fn read_dir(&self, _root: &Path, path: &RelativePath) -> Result<DirectoryListing, FsError> {
        let mut inner = lock(&self.inner);
        inner.ops.push((FakeOp::ReadDir, path.clone()));
        if Self::take_panic(&mut inner, path, FakeOp::ReadDir) {
            drop(inner);
            panic!("injected listing panic for {path}");
        }
        if let Some(err) = Self::take_failure(&mut inner, path, FakeOp::ReadDir) {
            return Err(err);
        }
        let directory = Self::lookup(&inner, path)?;
        if directory.kind != EntryKind::Directory {
            return Err(FsError::NotDirectory);
        }
        let real: Vec<(Option<RelativePath>, std::ffi::OsString, EntryInfo)> = inner
            .nodes
            .iter()
            .filter(|(k, _)| k.parent().map(|p| p == *path).unwrap_or(false))
            .filter_map(|(k, info)| Some((Some(k.clone()), k.file_name()?.to_os_string(), *info)))
            .collect();
        let injected: Vec<(Option<RelativePath>, std::ffi::OsString, EntryInfo)> = inner
            .injected
            .iter()
            .filter(|c| c.dir == *path)
            .map(|c| (path.join(&c.name).ok(), c.name.clone(), c.info))
            .collect();
        let observed: Vec<(Option<RelativePath>, std::ffi::OsString, EntryInfo)> = match inner.injected_position {
            InjectedPosition::Last => real.into_iter().chain(injected).collect(),
            InjectedPosition::First => injected.into_iter().chain(real).collect(),
        };
        let mut entries = Vec::with_capacity(observed.len());
        let mut metadata_operations = 0;
        for (child, name, info) in observed {
            let observation = match child {
                Some(child) => {
                    let (observation, operations) = Self::observe(&mut inner, &child, info);
                    metadata_operations += operations;
                    observation
                }
                None => Observation::resolved(info),
            };
            entries.push(DirEntry { name, info: observation });
        }
        let supplied_fields = Self::sources_for(&inner, path).metadata.inline();
        Ok(DirectoryListing { directory, entries, supplied_fields, metadata_operations })
    }

    fn observation_sources(&self, path: &RelativePath) -> ObservationSources {
        Self::sources_for(&lock(&self.inner), path)
    }

    fn enrich(&self, _root: &Path, path: &RelativePath, fields: MetadataFields) -> Result<Enrichment, FsError> {
        let mut inner = lock(&self.inner);
        inner.ops.push((FakeOp::Enrich, path.clone()));
        if Self::take_panic(&mut inner, path, FakeOp::Enrich) {
            drop(inner);
            panic!("injected enrichment panic for {path}");
        }
        if let Some(err) = Self::take_failure(&mut inner, path, FakeOp::Enrich) {
            return Err(err);
        }
        let own = Self::lookup(&inner, path)?;
        let mut metadata_operations = 1;
        let directory = Some(own.metadata.project(fields));
        let mut children = Vec::new();
        for child in Self::child_paths(&inner, path) {
            let Some(name) = child.file_name().map(|n| n.to_os_string()) else {
                continue;
            };
            inner.ops.push((FakeOp::Enrich, child.clone()));
            metadata_operations += 1;
            if Self::take_failure(&mut inner, &child, FakeOp::Enrich).is_some() {
                continue;
            }
            let Ok(info) = Self::lookup(&inner, &child) else {
                continue;
            };
            children.push((name, info.metadata.project(fields)));
        }
        Ok(Enrichment { directory, children, supplied_fields: fields, metadata_operations })
    }

    fn watch(
        &self,
        _root: &Path,
        path: &RelativePath,
        recursive: bool,
        sink: Arc<dyn WatcherSink>,
    ) -> Result<WatchId, FsError> {
        let mut inner = lock(&self.inner);
        inner.ops.push((FakeOp::Watch, path.clone()));
        if Self::take_panic(&mut inner, path, FakeOp::Watch) {
            drop(inner);
            panic!("injected watch panic for {path}");
        }
        if let Some(err) = Self::take_failure(&mut inner, path, FakeOp::Watch) {
            return Err(err);
        }
        if !inner.caps.watcher.is_present() {
            return Err(FsError::Unsupported("no watcher".into()));
        }
        let id = WatchId::new(inner.next_watch);
        inner.next_watch += 1;
        inner.watches.insert(id, Watch { path: path.clone(), recursive, sink });
        Ok(id)
    }

    fn unwatch(&self, watch: WatchId) {
        lock(&self.inner).watches.remove(&watch);
    }
}
