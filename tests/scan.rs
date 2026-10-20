use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tree_fucker::core::{GrantId, MonotonicTime, Reservation, WorkOrigin};
use tree_fucker::domain::ProbeResult;
use tree_fucker::testing::{CostScope, DomainId, FailureMode, FakeFileSystem, FakeOp};
use tree_fucker::update::ResourceLimit;
use tree_fucker::{
    CancellationToken, Ceilings, Clock, Continuation, Descent, DomainCapabilities, DomainCrossing, Enrichment,
    EnrichmentBatch, EntryInfo, EntryKind, Error, FileSystem, FsCapabilities, FsError, HostConfig, HostGovernor,
    KindSource, Lease, ListingSession, LoadAll, LoadDepth, MetadataFields, MetadataSource, MetadataSources,
    ObservedKind, RelativePath, Scan, ScanEntry, ScanEvent, ScanFailure, ScanOptions, ScanPolicy, SessionCost,
    StorageDomainId, SystemClock, WatchId, WatcherKind, WatcherSink,
};

const MEDIA: DomainId = DomainId::new(7);

#[test]
fn required_anchors_fail_explicitly_when_disabled_or_unsupported() {
    for budget in [0, 2] {
        let Opened { mut scan, .. } = open(
            fixture(),
            ScanOptions { anchors: budget, anchor_policy: tree_fucker::AnchorPolicy::Required, ..follow() },
        );
        let events = drain(&mut scan);
        assert_eq!(entries(&events).len(), 1, "only the bootstrap root may lack an anchor");
        assert!(events.iter().any(|event| matches!(
            event,
            ScanEvent::Unlisted { failure: ScanFailure::ResourceLimited(limited), .. }
                if limited.limit == ResourceLimit::Anchors && limited.configured == 0 && limited.observed == 1
        )));
    }
}

fn disk_scan(root: &Path, options: ScanOptions) -> Scan {
    Scan::open_outside_host_governor(
        Arc::new(tree_fucker::std_fs::StdFileSystem::new()),
        root.to_path_buf(),
        Arc::new(LoadAll),
        options,
        HostGovernor::independent(&HostConfig {
            foreground_duty: 1.0,
            domain_foreground_duty: 1.0,
            ..Default::default()
        }),
        Arc::new(SystemClock),
    )
    .unwrap()
}

#[test]
fn streaming_yields_the_first_lease_and_bounds_wide_directory_buffering() {
    let root = tempfile::tempdir().unwrap();
    for i in 0..1000 {
        std::fs::write(root.path().join(format!("f{i:04}")), b"").unwrap();
    }
    for bounded in [false, true] {
        let mut scan = disk_scan(
            root.path(),
            ScanOptions { streaming: true, entries_per_lease: 7, ceiling: Duration::MAX, ..follow() },
        );
        if bounded {
            scan = scan.with_listing_executor(tree_fucker::ListingExecutor::new(2).unwrap());
        }
        assert!(matches!(scan.next().unwrap().unwrap(), ScanEvent::Entry(entry) if entry.path.is_root()));
        let first = scan.next().unwrap().unwrap();
        assert!(matches!(first, ScanEvent::Entry(_)));
        assert_eq!(scan.stats().entries_enumerated, 7, "first result precedes directory completion");
        let remaining = drain(&mut scan);
        assert_eq!(entries(&remaining).len(), 999);
        assert_eq!(scan.stats().entries_enumerated, 1000);
        assert!(scan.stats().peak_buffered_bytes <= 7 * tree_fucker::entry_bytes(std::ffi::OsStr::new("f0000")));
        assert_eq!(scan.stats().buffered_bytes, 0);
    }
}

#[test]
fn streaming_preserves_total_directory_entry_limits_and_prior_observations() {
    let root = tempfile::tempdir().unwrap();
    for i in 0..20 {
        std::fs::write(root.path().join(format!("f{i}")), b"").unwrap();
    }
    let mut scan = disk_scan(
        root.path(),
        ScanOptions { streaming: true, entries_per_lease: 2, entries_per_directory: 5, ..follow() },
    );
    let events = drain(&mut scan);
    assert_eq!(entries(&events).len(), 5, "root plus two completed chunks survive the later limit");
    assert!(events.iter().any(|event| matches!(
        event,
        ScanEvent::Unlisted { failure: ScanFailure::ResourceLimited(limited), .. }
            if limited.limit == ResourceLimit::EntriesPerDirectory
    )));
}

#[test]
fn deep_streaming_retention_respects_the_host_memory_limit_and_cleans_up() {
    let root = tempfile::tempdir().unwrap();
    let mut path = root.path().to_path_buf();
    for _ in 0..40 {
        path.push("nested");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("sibling"), b"").unwrap();
    }
    let ceiling = 1024;
    let governor = HostGovernor::independent(&HostConfig {
        accounted_memory_ceiling: ceiling,
        in_flight_listing_bytes: ceiling,
        foreground_duty: 1.0,
        domain_foreground_duty: 1.0,
        ..Default::default()
    });
    let mut scan = Scan::open_outside_host_governor(
        Arc::new(tree_fucker::std_fs::StdFileSystem::new()),
        root.path().to_path_buf(),
        Arc::new(LoadAll),
        ScanOptions { streaming: true, entries_per_lease: 1, ceiling: Duration::MAX, ..follow() },
        governor.clone(),
        Arc::new(SystemClock),
    )
    .unwrap();
    let mut seen = 0;
    let mut limited = false;
    for result in scan.by_ref() {
        match result {
            Ok(ScanEvent::Entry(_)) => seen += 1,
            Err(Error::ResourceLimited(limit)) => {
                assert_eq!(limit.limit, ResourceLimit::AccountedMemory);
                limited = true;
            }
            Ok(ScanEvent::Unlisted { failure: ScanFailure::ResourceLimited(limit), .. }) => {
                assert_eq!(limit.limit, ResourceLimit::ListingBytes);
                limited = true;
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
    assert!(seen > 1 && seen < 81);
    assert!(limited, "a deep active descent must terminate at the explicit host bound");
    assert!(scan.stats().peak_buffered_bytes <= ceiling);
    assert!(governor.grants().is_empty());
    assert_eq!(governor.view(MonotonicTime(Duration::from_secs(1))).accounted_memory, 0);
}

#[test]
fn dropping_between_streaming_chunks_discards_the_session_and_memory() {
    let root = tempfile::tempdir().unwrap();
    for i in 0..100 {
        std::fs::write(root.path().join(i.to_string()), b"").unwrap();
    }
    let governor = HostGovernor::independent(&HostConfig::default());
    let mut scan = Scan::open_outside_host_governor(
        Arc::new(tree_fucker::std_fs::StdFileSystem::new()),
        root.path().to_path_buf(),
        Arc::new(LoadAll),
        ScanOptions { streaming: true, entries_per_lease: 1, anchors: 1, ..follow() },
        governor.clone(),
        Arc::new(SystemClock),
    )
    .unwrap()
    .with_listing_executor(tree_fucker::ListingExecutor::new(2).unwrap());
    scan.next().unwrap().unwrap();
    let ScanEvent::Entry(entry) = scan.next().unwrap().unwrap() else { panic!("entry") };
    assert_eq!(scan.stats().entries_enumerated, 1);
    assert!(scan.stats().buffered_bytes > 0);
    let cancellation = scan.cancellation();
    drop(scan);
    // The consumer owns its observation independently of the discarded cursor.
    assert_eq!(entry.path.depth(), 1);
    assert!(cancellation.is_cancelled());
    assert!(governor.grants().is_empty());
    assert_eq!(governor.view(MonotonicTime(Duration::from_secs(1))).accounted_memory, 0);
}

#[cfg(unix)]
#[test]
fn required_streaming_anchors_survive_rename_and_share_one_budget_slot() {
    use rustix::fs::{AtFlags, statat};
    use tree_fucker::std_fs::DirectoryAnchor;
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("root");
    std::fs::create_dir(&root).unwrap();
    for i in 0..20 {
        std::fs::write(root.join(format!("f{i}")), b"").unwrap();
    }
    let mut scan = disk_scan(
        &root,
        ScanOptions {
            streaming: true,
            entries_per_lease: 1,
            anchors: 1,
            anchor_policy: tree_fucker::AnchorPolicy::Required,
            ..follow()
        },
    );
    scan.next().unwrap().unwrap();
    let ScanEvent::Entry(first) = scan.next().unwrap().unwrap() else { panic!("entry") };
    std::fs::rename(&root, parent.path().join("moved")).unwrap();
    let mut held = vec![first];
    for event in scan.by_ref() {
        let ScanEvent::Entry(entry) = event.unwrap() else { panic!("no fallback") };
        held.push(entry);
    }
    assert_eq!(held.len(), 20);
    assert_eq!(scan.stats().anchors_peak, 1);
    for entry in &held {
        let anchor = entry.anchor.as_ref().unwrap().get::<DirectoryAnchor>().unwrap();
        statat(anchor, entry.path.name().unwrap(), AtFlags::SYMLINK_NOFOLLOW).unwrap();
    }
    drop(held);
    assert_eq!(scan.stats().anchors_live, 0);
}

#[cfg(unix)]
#[test]
fn required_anchor_exhaustion_reports_the_subtree_without_unanchored_children() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("child")).unwrap();
    std::fs::write(root.path().join("child/file"), b"").unwrap();
    let mut scan = disk_scan(
        root.path(),
        ScanOptions { anchors: 1, anchor_policy: tree_fucker::AnchorPolicy::Required, ..follow() },
    );
    let events = drain(&mut scan);
    assert_eq!(entries(&events).len(), 2);
    assert!(events.iter().any(|event| matches!(event,
        ScanEvent::Unlisted { failure: ScanFailure::ResourceLimited(limited), .. }
            if limited.limit == ResourceLimit::Anchors && limited.configured == 1 && limited.observed == 2
    )));
}

#[test]
fn lazy_reads_are_admitted_on_demand_and_release_on_panic_or_cancellation() {
    let Opened { mut scan, governor, clock } = open(fixture(), follow());
    let ScanEvent::Entry(entry) = scan.next().unwrap().unwrap() else { panic!("root") };
    let before = scan.stats().metadata_operations;
    let result = scan
        .read(&entry, |_| {
            assert_eq!(governor.view(now(&governor, &clock)).in_flight, 1);
            Ok(42)
        })
        .unwrap();
    assert_eq!(result, 42);
    assert_eq!(scan.stats().metadata_operations, before + 1);
    assert!(governor.grants().is_empty());
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), Error> = scan.read(&entry, |_| {
            clock.advance(Duration::from_secs(60));
            panic!("adapter read");
        });
    }));
    assert!(panicked.is_err());
    assert!(governor.grants().is_empty());
    assert!(scan.stats().admitted >= Duration::from_secs(60), "unwinding cannot erase physical cost");
    scan.cancellation().cancel();
    assert_eq!(
        scan.read(&entry, |_| -> Result<(), FsError> { panic!("cancelled before admission") }),
        Err(Error::Cancelled)
    );
}

#[cfg(unix)]
#[test]
fn a_query_can_read_only_selected_metadata_through_the_original_anchor() {
    use rustix::fs::{AtFlags, statat};
    use tree_fucker::std_fs::DirectoryAnchor;
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("selected"), b"abc").unwrap();
    let mut scan = disk_scan(
        &root,
        ScanOptions {
            streaming: true,
            anchors: 1,
            anchor_policy: tree_fucker::AnchorPolicy::Required,
            fields: MetadataFields::NONE,
            ..follow()
        },
    );
    scan.next().unwrap().unwrap();
    let ScanEvent::Entry(entry) = scan.next().unwrap().unwrap() else { panic!("file") };
    // Listing may need metadata to resolve the entry kind (for example,
    // illumos dirents have no inline kind). Consumer reads are additional.
    let before = scan.stats();
    assert_eq!(before.enrichments, 0, "no metadata fields were requested");
    assert_eq!(entry.path.under(&root), root.join("selected"));
    assert_eq!(scan.stats(), before, "reading the yielded path performs no filesystem work");
    std::fs::rename(&root, parent.path().join("moved")).unwrap();
    let size = scan
        .read(&entry, |entry| {
            let anchor = entry.anchor.as_ref().unwrap().get::<DirectoryAnchor>().unwrap();
            statat(anchor, entry.path.name().unwrap(), AtFlags::SYMLINK_NOFOLLOW)
                .map(|stat| stat.st_size)
                .map_err(|error| FsError::from(std::io::Error::from(error)))
        })
        .unwrap();
    assert_eq!(size, 3);
    assert_eq!(scan.stats().metadata_operations, before.metadata_operations + 1);
    assert!(scan.next().is_none());
}

#[test]
fn bounded_command_cost_matches_the_governor_without_double_reservations() {
    let Opened { scan, governor, clock } = open(fixture(), ScanOptions { ceiling: Duration::MAX, ..follow() });
    let mut scan = scan.with_listing_executor(tree_fucker::ListingExecutor::new(2).unwrap());
    drain(&mut scan);
    assert_eq!(scan.stats().admitted, governor.view(now(&governor, &clock)).charged);
}

#[test]
fn bounded_resolution_reserves_only_the_resolution_operation() {
    let fs = fixture();
    fs.report_inline_domains(false);
    let governor = HostGovernor::independent(&HostConfig::default());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let observer = observed.clone();
    let host = governor.clone();
    let timed = Arc::new(Timed {
        inner: fs.clone(),
        clock: ManualClock::new(),
        on_resolve: Some(Arc::new(move || {
            let grant = host.grants().into_iter().next().expect("admitted resolution");
            observer.lock().unwrap().push((grant.required, grant.operations, grant.listing));
        })),
    });
    let mut scan = Scan::open_outside_host_governor(
        timed.clone(),
        fs.root().to_path_buf(),
        Arc::new(LoadAll),
        follow(),
        governor,
        timed.clock.clone(),
    )
    .unwrap()
    .with_listing_executor(tree_fucker::ListingExecutor::new(2).unwrap());
    drain(&mut scan);
    let observed = observed.lock().unwrap();
    assert!(observed.len() > 1, "root plus child domain resolution");
    assert!(
        observed.iter().all(|&(reads, operations, listing)| reads == 1 && operations == 0 && !listing),
        "{observed:?}"
    );
}

struct ManualClock {
    start: Instant,
    offset: Mutex<Duration>,
}

impl ManualClock {
    fn new() -> Arc<ManualClock> {
        Arc::new(ManualClock { start: Instant::now(), offset: Mutex::new(Duration::ZERO) })
    }

    fn advance(&self, by: Duration) {
        let mut offset = self.offset.lock().expect("clock");
        *offset += by;
    }

    fn elapsed(&self) -> Duration {
        *self.offset.lock().expect("clock")
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.start + self.elapsed()
    }

    fn sleep(&self, duration: Duration) {
        self.advance(duration);
    }

    fn wait_for_change(&self, _governor: &HostGovernor, _seen: u64, timeout: Duration) {
        self.advance(timeout);
    }
}

struct Timed {
    inner: Arc<FakeFileSystem>,
    clock: Arc<ManualClock>,
    on_resolve: Option<Arc<dyn Fn() + Send + Sync>>,
}

struct TimedSession {
    inner: Box<dyn ListingSession>,
    clock: Arc<ManualClock>,
}

impl ListingSession for TimedSession {
    fn resume(self: Box<Self>, lease: Lease) -> (Continuation, SessionCost) {
        let TimedSession { inner, clock } = *self;
        let (continuation, cost) = inner.resume(lease);
        clock.advance(cost.blocking.unwrap_or_default());
        let continuation = match continuation {
            Continuation::Suspended(next) => Continuation::Suspended(Box::new(TimedSession { inner: next, clock })),
            finished => finished,
        };
        (continuation, cost)
    }
}

impl FileSystem for Timed {
    fn capabilities(&self) -> FsCapabilities {
        self.inner.capabilities()
    }

    fn canonicalize(&self, root: &Path) -> Result<PathBuf, FsError> {
        self.inner.canonicalize(root)
    }

    fn resolve_domain(
        &self,
        root: &Path,
        path: &RelativePath,
        parent: Option<&ProbeResult>,
    ) -> Result<ProbeResult, FsError> {
        if let Some(observe) = &self.on_resolve {
            observe();
        }
        self.clock.advance(self.inner.domain_resolution_cost(path));
        self.inner.resolve_domain(root, path, parent)
    }

    fn metadata(&self, root: &Path, path: &RelativePath) -> Result<EntryInfo, FsError> {
        self.clock.advance(self.inner.cost_of(FakeOp::Metadata, path));
        self.inner.metadata(root, path)
    }

    fn open_listing(
        &self,
        root: &Path,
        path: &RelativePath,
        ceilings: Ceilings,
        cancel: CancellationToken,
    ) -> Box<dyn ListingSession> {
        Box::new(TimedSession {
            inner: self.inner.open_listing(root, path, ceilings, cancel),
            clock: self.clock.clone(),
        })
    }

    fn enrich(&self, root: &Path, path: &RelativePath, batch: &EnrichmentBatch) -> Result<Enrichment, FsError> {
        self.clock.advance(self.inner.enrichment_cost(path, batch));
        self.inner.enrich(root, path, batch)
    }

    fn watch(
        &self,
        root: &Path,
        path: &RelativePath,
        recursive: bool,
        sink: Arc<dyn WatcherSink>,
    ) -> Result<WatchId, FsError> {
        self.inner.watch(root, path, recursive, sink)
    }

    fn unwatch(&self, watch: WatchId) {
        self.inner.unwatch(watch)
    }
}

fn path(p: &str) -> RelativePath {
    RelativePath::parse(p).expect("valid path")
}

fn fixture() -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("a");
    fs.mkdir("a/b");
    fs.create_file("a/x", 1);
    fs.create_file("a/b/y", 2);
    fs.mkdir("c");
    fs.create_file("c/z", 3);
    fs.create_file("f", 4);
    fs
}

struct Opened {
    scan: Scan,
    governor: HostGovernor,
    clock: Arc<ManualClock>,
}

fn open_with(fs: Arc<FakeFileSystem>, policy: Arc<dyn ScanPolicy>, options: ScanOptions, host: HostConfig) -> Opened {
    let governor = HostGovernor::independent(&host);
    let clock = ManualClock::new();
    let timed = Arc::new(Timed { inner: fs.clone(), clock: clock.clone(), on_resolve: None });
    let scan = Scan::open_outside_host_governor(
        timed,
        fs.root().to_path_buf(),
        policy,
        options,
        governor.clone(),
        clock.clone(),
    )
    .expect("open");
    Opened { scan, governor, clock }
}

fn open(fs: Arc<FakeFileSystem>, options: ScanOptions) -> Opened {
    open_with(fs, Arc::new(LoadAll), options, HostConfig::default())
}

fn follow() -> ScanOptions {
    ScanOptions { crossing: DomainCrossing::Follow, ..ScanOptions::default() }
}

fn drain(scan: &mut Scan) -> Vec<ScanEvent> {
    scan.by_ref().map(|event| event.expect("event")).collect()
}

fn entries(events: &[ScanEvent]) -> Vec<&ScanEntry> {
    events
        .iter()
        .filter_map(|event| match event {
            ScanEvent::Entry(entry) => Some(entry),
            ScanEvent::Boundary { .. } | ScanEvent::Unlisted { .. } => None,
        })
        .collect()
}

fn paths(events: &[ScanEvent]) -> Vec<String> {
    entries(events).iter().map(|entry| entry.path.to_string()).collect()
}

fn entry<'a>(events: &'a [ScanEvent], p: &str) -> &'a ScanEntry {
    let wanted = path(p);
    entries(events).into_iter().find(|entry| entry.path.path() == wanted).unwrap_or_else(|| panic!("no entry for {p}"))
}

fn now(governor: &HostGovernor, clock: &ManualClock) -> MonotonicTime {
    MonotonicTime(clock.now().saturating_duration_since(governor.base(clock.now())))
}

#[test]
fn a_scan_streams_the_root_then_each_subtree_depth_first() {
    let fs = fixture();
    let Opened { mut scan, .. } = open(fs.clone(), follow());
    let first = scan.next().expect("root").expect("root event");
    let ScanEvent::Entry(root) = first else {
        panic!("the first event is the root entry, not {first:?}");
    };
    assert!(root.path.is_root());
    assert_eq!(root.descent, Descent::Descending);
    assert_eq!(fs.count_ops(FakeOp::ReadDir, ""), 0, "the root entry is yielded before any listing");

    let second = scan.next().expect("child").expect("child event");
    let ScanEvent::Entry(child) = second else {
        panic!("the second event is a child entry, not {second:?}");
    };
    assert_eq!(child.path.path(), path("a"));
    assert_eq!(fs.count_ops(FakeOp::ReadDir, ""), 1);
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a"), 0, "a child directory is yielded before it is listed");

    let rest = drain(&mut scan);
    let mut all = vec![root.path.to_string(), child.path.to_string()];
    all.extend(paths(&rest));
    assert_eq!(all, [".", "a", "a/b", "a/b/y", "a/x", "c", "c/z", "f"]);
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a/b"), 1);
}

#[test]
fn a_depth_limit_yields_the_child_directory_without_listing_it() {
    let fs = fixture();
    let Opened { mut scan, .. } =
        open_with(fs.clone(), Arc::new(LoadDepth { depth: 1 }), follow(), HostConfig::default());
    let events = drain(&mut scan);
    assert_eq!(paths(&events), [".", "a", "c", "f"]);
    assert_eq!(entry(&events, "a").descent, Descent::Withheld);
    assert_eq!(entry(&events, "f").descent, Descent::Leaf);
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a"), 0);
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "c"), 0);

    let Opened { mut scan, .. } =
        open_with(fs.clone(), Arc::new(LoadDepth { depth: 0 }), follow(), HostConfig::default());
    let events = drain(&mut scan);
    assert_eq!(paths(&events), ["."], "a depth of zero yields the root alone");
    assert_eq!(entry(&events, ".").descent, Descent::Withheld);
}

#[test]
fn an_excluded_crossing_yields_the_mount_point_and_never_reads_beneath_it() {
    let fs = fixture();
    fs.mkdir("mnt");
    fs.create_file("mnt/hidden", 1);
    fs.set_domain("mnt", MEDIA);
    for inline in [true, false] {
        fs.report_inline_domains(inline);
        fs.clear_ops();
        let options = ScanOptions { crossing: DomainCrossing::Exclude, ..ScanOptions::default() };
        let Opened { mut scan, .. } = open(fs.clone(), options);
        let events = drain(&mut scan);
        assert!(paths(&events).contains(&"mnt".to_owned()), "the mount point itself is an entry");
        assert!(!paths(&events).contains(&"mnt/hidden".to_owned()));
        let media = StorageDomainId::of(&FakeFileSystem::domain_key(MEDIA));
        let boundary = ScanEvent::Boundary { path: path("mnt"), mode: DomainCrossing::Exclude, domain: media };
        assert!(events.contains(&boundary), "{events:?}");
        assert_eq!(
            fs.count_ops(FakeOp::ReadDir, "mnt"),
            0,
            "RFC 14.3: an excluded domain's descendants are never read"
        );
        assert_eq!(
            fs.count_ops(FakeOp::ResolveDomain, "mnt"),
            usize::from(!inline),
            "a domain the listing reports inline needs no separate resolution"
        );
        assert_eq!(scan.stats().boundaries, 1);
    }

    let Opened { mut scan, .. } = open(fs.clone(), follow());
    let events = drain(&mut scan);
    let hidden = entry(&events, "mnt/hidden");
    assert_eq!(hidden.domain, StorageDomainId::of(&FakeFileSystem::domain_key(MEDIA)));
    assert_ne!(hidden.domain, entry(&events, "a/x").domain, "a followed crossing reports the child domain");
}

#[test]
fn the_default_crossing_mode_leaves_a_foreign_domain_unread() {
    let fs = fixture();
    fs.mkdir("mnt");
    fs.create_file("mnt/hidden", 1);
    fs.set_domain("mnt", MEDIA);
    let Opened { mut scan, .. } = open(fs.clone(), ScanOptions::default());
    let events = drain(&mut scan);
    assert!(events.iter().any(|event| matches!(event, ScanEvent::Boundary { mode: DomainCrossing::LoadOnDemand, .. })));
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "mnt"), 0, "RFC 14.3: the default crossing reads nothing beneath");
}

#[test]
fn a_symbolic_link_is_yielded_and_never_traversed() {
    let fs = fixture();
    fs.create_symlink("link");
    let Opened { mut scan, .. } = open(fs.clone(), follow());
    let events = drain(&mut scan);
    let link = entry(&events, "link");
    assert_eq!(link.kind, ObservedKind::Resolved(EntryKind::Symlink));
    assert_eq!(link.descent, Descent::Leaf, "RFC 14.2: symbolic links are represented and never traversed");
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "link"), 0);
}

#[test]
fn an_unreadable_directory_is_reported_and_its_siblings_continue() {
    let fs = fixture();
    fs.fail("a", FakeOp::ReadDir, FailureMode::Always(FsError::PermissionDenied));
    let Opened { mut scan, .. } = open(fs.clone(), follow());
    let events = drain(&mut scan);
    let a = events.iter().position(|event| matches!(event, ScanEvent::Entry(e) if e.path.path() == path("a")));
    let failed = events.iter().position(|event| {
        *event == ScanEvent::Unlisted { path: path("a"), failure: ScanFailure::Fs(FsError::PermissionDenied) }
    });
    assert!(a.is_some() && failed.is_some() && a < failed, "the entry precedes its descent failure: {events:?}");
    assert_eq!(paths(&events), [".", "a", "c", "c/z", "f"]);
    assert_eq!(scan.stats().unlisted, 1);
}

#[test]
fn a_directory_over_its_entry_ceiling_is_reported_and_the_scan_continues() {
    let fs = fixture();
    fs.mkdir("huge");
    fs.set_synthetic_children("huge", 5000);
    fs.set_chunk_size(16);
    let options = ScanOptions { entries_per_directory: 100, ..follow() };
    let Opened { mut scan, .. } = open(fs.clone(), options);
    let events = drain(&mut scan);
    let limited = events.iter().find_map(|event| match event {
        ScanEvent::Unlisted { path: p, failure: ScanFailure::ResourceLimited(limited) } if *p == path("huge") => {
            Some(*limited)
        }
        _ => None,
    });
    let limited = limited.expect("a resource-limited descent of huge");
    assert_eq!(limited.limit, ResourceLimit::EntriesPerDirectory);
    assert!(limited.observed <= 116, "RFC 10.2: at most the ceiling plus one chunk is held: {limited:?}");
    assert!(!paths(&events).iter().any(|p| p.starts_with("huge/")), "RFC 20: a limited listing yields no child");
    assert!(paths(&events).contains(&"c/z".to_owned()));
}

#[test]
fn every_operation_is_granted_and_nothing_is_held_once_the_scan_ends() {
    let fs = fixture();
    fs.report_inline_domains(false);
    let Opened { mut scan, governor, clock } = open(fs.clone(), follow());
    let _ = drain(&mut scan);
    let stats = scan.stats();
    let view = governor.view(now(&governor, &clock));
    assert_eq!(view.grants, stats.grants, "every grant the governor issued belongs to this scan");
    let reads = fs.count_ops(FakeOp::ReadDir, "")
        + fs.count_ops(FakeOp::ReadDir, "a")
        + fs.count_ops(FakeOp::ReadDir, "a/b")
        + fs.count_ops(FakeOp::ReadDir, "c");
    let resolutions = fs.ops().iter().filter(|(op, _)| *op == FakeOp::ResolveDomain).count();
    let metadata = fs.ops().iter().filter(|(op, _)| *op == FakeOp::Metadata).count();
    assert_eq!((reads, resolutions, metadata), (4, 4, 1));
    assert_eq!(
        stats.grants, 7,
        "RFC 15.1: canonicalization, the root read and the root resolution run under bootstrap grants, and each \
         child directory's resolution runs under the grant of its first listing lease"
    );
    assert_eq!(view.grants, view.domains.values().map(|domain| domain.grants).sum::<u64>() + view.bootstrap.grants);
    assert!(governor.grants().is_empty(), "no grant outlives its operation");
    assert_eq!(governor.in_flight(), 0);
    assert_eq!(view.accounted_memory, 0, "a finished scan accounts no memory");
}

#[test]
fn dropping_a_scan_between_events_leaves_no_grant_or_memory_behind() {
    let fs = fixture();
    let Opened { mut scan, governor, clock } = open(fs.clone(), follow());
    let _ = scan.next();
    let _ = scan.next();
    assert!(governor.view(now(&governor, &clock)).accounted_memory > 0, "the buffered listing is accounted");
    drop(scan);
    assert!(governor.grants().is_empty());
    assert_eq!(governor.in_flight(), 0);
    assert_eq!(governor.view(now(&governor, &clock)).accounted_memory, 0, "dropping a scan forgets its memory");
}

#[test]
fn two_scans_share_one_envelope_and_one_domain_account() {
    let fs = fixture();
    let governor = HostGovernor::independent(&HostConfig::default());
    let clock = ManualClock::new();
    let open = || {
        let timed = Arc::new(Timed { inner: fs.clone(), clock: clock.clone(), on_resolve: None });
        Scan::open_outside_host_governor(
            timed,
            fs.root().to_path_buf(),
            Arc::new(LoadAll),
            follow(),
            governor.clone(),
            clock.clone(),
        )
        .expect("open")
    };
    let mut first = open();
    let mut second = open();
    let mut seen = Vec::new();
    loop {
        let a = first.next();
        let b = second.next();
        if a.is_none() && b.is_none() {
            break;
        }
        seen.extend(a.into_iter().chain(b).map(|event| event.expect("event")));
    }
    let root = entry(&seen, ".").domain;
    assert!(entries(&seen).iter().all(|entry| entry.domain == root), "both scans bind the same domain");
    let view = governor.view(now(&governor, &clock));
    assert_eq!(view.grants, first.stats().grants + second.stats().grants, "RFC 15.9: one governor admitted both");
    let account = view.domains.get(&root).expect("the shared domain account");
    assert!(account.grants > 0 && account.charged > Duration::ZERO, "{account:?}");
}

#[test]
fn a_throttled_scan_waits_for_its_budget_and_never_exceeds_the_envelope() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    for index in 0..20 {
        fs.mkdir(&format!("d{index}"));
    }
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(50));
    let duty = 0.1;
    let burst = Duration::from_millis(100);
    let host = HostConfig {
        foreground_duty: duty,
        domain_foreground_duty: duty,
        foreground_burst: burst,
        domain_foreground_burst: burst,
        ..HostConfig::default()
    };
    let Opened { mut scan, clock, .. } = open_with(fs.clone(), Arc::new(LoadAll), follow(), host);
    let events = drain(&mut scan);
    assert_eq!(entries(&events).len(), 21, "a throttled scan is slow, never truncated");
    let stats = scan.stats();
    assert!(stats.throttled > Duration::ZERO, "{stats:?}");
    let work = Duration::from_millis(50 * 21);
    let floor = Duration::from_secs_f64((work.saturating_sub(burst)).as_secs_f64() / duty);
    assert!(
        clock.elapsed() >= floor.mul_f64(0.9),
        "RFC 15: {work:?} of foreground work at a duty of {duty} cannot finish in {:?}",
        clock.elapsed()
    );
}

#[test]
fn a_scan_past_its_ceiling_ends_resource_limited_after_what_it_already_yielded() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    for index in 0..20 {
        fs.mkdir(&format!("d{index}"));
        fs.create_file(&format!("d{index}/f"), 1);
    }
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(20));
    let options = ScanOptions { ceiling: Duration::from_millis(150), ..follow() };
    let Opened { mut scan, governor, .. } = open(fs.clone(), options);
    let mut yielded = 0;
    let terminal = loop {
        match scan.next() {
            Some(Ok(ScanEvent::Entry(_))) => yielded += 1,
            Some(Ok(_)) => {}
            Some(Err(error)) => break error,
            None => panic!("the scan finished inside a ceiling it cannot fit in"),
        }
    };
    let Error::ResourceLimited(limited) = terminal else {
        panic!("RFC 15.4: a scan past its ceiling fails ResourceLimited, not {terminal:?}");
    };
    assert_eq!(limited.limit, ResourceLimit::CommandWorkerTime);
    assert!(yielded > 1, "entries yielded before the ceiling stand");
    assert!(scan.next().is_none(), "a terminated scan yields nothing more");
    assert!(governor.grants().is_empty());
}

#[test]
fn a_quarantined_domain_is_reported_and_healthy_domains_continue() {
    let fs = fixture();
    fs.mkdir("mnt");
    fs.create_file("mnt/f", 1);
    fs.set_domain("mnt", MEDIA);
    let governor = HostGovernor::independent(&HostConfig::default());
    let clock = ManualClock::new();
    let media = StorageDomainId::of(&FakeFileSystem::domain_key(MEDIA));
    governor.register_domain(media, &DomainCapabilities::inline(), now(&governor, &clock));
    let stuck = GrantId::Bootstrap(u64::MAX);
    let reservation = Reservation {
        id: stuck,
        path: path("mnt"),
        reads: 1,
        registrations: 0,
        operations: 0,
        ceiling: None,
        lease: 0,
        domain: Some(media),
        origin: WorkOrigin::Background,
        listing: true,
    };
    governor.try_admit(reservation, now(&governor, &clock)).expect("admit the stuck call");
    governor.try_start(stuck, now(&governor, &clock)).expect("start the stuck call");
    governor.mark_stuck(stuck, now(&governor, &clock));

    let timed = Arc::new(Timed { inner: fs.clone(), clock: clock.clone(), on_resolve: None });
    let mut scan = Scan::open_outside_host_governor(
        timed,
        fs.root().to_path_buf(),
        Arc::new(LoadAll),
        follow(),
        governor.clone(),
        clock.clone(),
    )
    .expect("open");
    let events = drain(&mut scan);
    let quarantined = ScanEvent::Unlisted { path: path("mnt"), failure: ScanFailure::Quarantined(media) };
    assert!(events.contains(&quarantined), "RFC 13.5: a stuck worker quarantines its domain: {events:?}");
    assert!(paths(&events).contains(&"c/z".to_owned()), "a healthy domain keeps its coverage");
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "mnt"), 0, "no new work is admitted on a quarantined domain");
    governor.release(stuck, now(&governor, &clock));
}

#[test]
fn cancellation_ends_the_scan_and_releases_everything() {
    let fs = fixture();
    let Opened { mut scan, governor, .. } = open(fs.clone(), follow());
    let token = scan.cancellation();
    let _ = scan.next();
    token.cancel();
    assert_eq!(scan.next(), Some(Err(Error::Cancelled)));
    assert_eq!(scan.next(), None);
    assert!(governor.grants().is_empty());
}

#[test]
fn requested_metadata_is_enriched_and_a_failed_read_marks_only_its_entry() {
    let fs = fixture();
    fs.set_default_capabilities(DomainCapabilities {
        metadata_sources: MetadataSources { size: MetadataSource::PerChildRead, ..MetadataSources::INLINE },
        ..DomainCapabilities::inline()
    });
    fs.fail("a/x", FakeOp::Enrich, FailureMode::Always(FsError::PermissionDenied));
    let size = MetadataFields { size: true, ..MetadataFields::NONE };
    let options = ScanOptions { fields: size, ..follow() };
    let Opened { mut scan, .. } = open(fs.clone(), options);
    let events = drain(&mut scan);
    let y = entry(&events, "a/b/y");
    assert_eq!((y.metadata.size, y.fields, y.metadata_error.clone()), (Some(2), size, None));
    let x = entry(&events, "a/x");
    assert_eq!(x.metadata_error, Some(FsError::PermissionDenied), "RFC 10.1: enrichment failure is per entry");
    assert_eq!(x.metadata.size, None);
    assert!(scan.stats().enrichments > 0);

    let Opened { mut scan, .. } = open(fs.clone(), follow());
    let events = drain(&mut scan);
    assert_eq!(entry(&events, "a/b/y").fields, MetadataFields::NONE, "no field is read unless requested");
    assert_eq!(scan.stats().enrichments, 0);
}

#[test]
fn an_unresolved_kind_is_yielded_and_never_traversed() {
    let fs = fixture();
    fs.set_default_capabilities(DomainCapabilities {
        kind_source: KindSource::Sometimes,
        ..DomainCapabilities::inline()
    });
    fs.report_unknown_kind("a");
    fs.fail("a", FakeOp::ResolveKind, FailureMode::Always(FsError::Transient("busy".into())));
    let Opened { mut scan, .. } = open(fs.clone(), follow());
    let events = drain(&mut scan);
    let a = entry(&events, "a");
    assert_eq!((a.kind, a.descent), (ObservedKind::Unresolved, Descent::Unresolved));
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a"), 0, "RFC 10.1: an unresolved child is never traversed on a guess");
}

#[test]
fn a_root_that_is_not_a_directory_fails_open() {
    let fs = fixture();
    fs.set_root_kind(EntryKind::File);
    let governor = HostGovernor::independent(&HostConfig::default());
    let opened = Scan::open_outside_host_governor(
        fs.clone(),
        fs.root().to_path_buf(),
        Arc::new(LoadAll),
        follow(),
        governor.clone(),
        Arc::new(SystemClock),
    );
    assert!(matches!(opened, Err(Error::NotDirectory)));
    assert!(governor.grants().is_empty());
}

#[test]
fn a_scan_waits_for_a_held_slot_without_polling_and_proceeds_once_it_frees() {
    let fs = fixture();
    let host = HostConfig { maximum_in_flight: 1, per_domain_concurrency: 1, ..HostConfig::default() };
    let governor = HostGovernor::independent(&host);
    let base = governor.base(Instant::now());
    let at = || MonotonicTime(Instant::now().saturating_duration_since(base));
    let held = GrantId::Bootstrap(u64::MAX);
    let reservation = Reservation {
        id: held,
        path: RelativePath::root(),
        reads: 1,
        registrations: 0,
        operations: 0,
        ceiling: None,
        lease: 0,
        domain: None,
        origin: WorkOrigin::Background,
        listing: false,
    };
    governor.try_admit(reservation, at()).expect("admit");
    governor.try_start(held, at()).expect("start");

    let worker = {
        let fs = fs.clone();
        let governor = governor.clone();
        std::thread::spawn(move || {
            let scan = Scan::open_outside_host_governor(
                fs.clone(),
                fs.root().to_path_buf(),
                Arc::new(LoadAll),
                follow(),
                governor,
                Arc::new(SystemClock),
            )
            .expect("open");
            scan.collect::<Result<Vec<ScanEvent>, Error>>().expect("events").len()
        })
    };
    let waiting = loop {
        let pending = governor.grants().into_iter().find(|grant| grant.id != held && grant.started.is_none());
        if let Some(pending) = pending {
            break pending;
        }
        std::thread::yield_now();
    };
    assert!(matches!(waiting.id, GrantId::Bootstrap(_)), "the scan holds an admitted grant waiting on the slot");
    assert!(fs.ops().is_empty(), "RFC 15.3: no operation starts without a free slot");
    governor.release(held, at());
    let events = worker.join().expect("worker");
    assert!(events >= 8, "the scan completed once the slot freed: {events}");
}

#[cfg(unix)]
#[test]
fn anchors_are_bounded_and_resolve_children_against_the_listed_directory() {
    use rustix::fs::{AtFlags, statat};
    use tree_fucker::std_fs::{DirectoryAnchor, StdFileSystem};

    let dir = std::env::temp_dir().join(format!("tree-fucker-scan-anchors-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["one", "two", "three", "four"] {
        std::fs::create_dir_all(dir.join(sub)).expect("dir");
        std::fs::write(dir.join(sub).join("file"), sub.as_bytes()).expect("file");
    }
    let governor = HostGovernor::independent(&HostConfig::default());
    let options = ScanOptions { anchors: 2, ..follow() };
    let scan = Scan::open_outside_host_governor(
        Arc::new(StdFileSystem::new()),
        dir.clone(),
        Arc::new(LoadAll),
        options,
        governor,
        Arc::new(SystemClock),
    )
    .expect("open");
    let root = scan.root().to_path_buf();
    let mut held = Vec::new();
    let mut scan = scan;
    for event in scan.by_ref() {
        if let ScanEvent::Entry(entry) = event.expect("event") {
            held.push(entry);
        }
    }
    let stats = scan.stats();
    assert!(stats.anchors_peak <= 2, "RFC 9.3: live anchors never exceed the configured bound: {stats:?}");
    assert!(stats.anchors_withheld > 0, "a listing past the bound runs without an anchor: {stats:?}");
    let anchored: Vec<&ScanEntry> = held.iter().filter(|entry| entry.anchor.is_some()).collect();
    assert!(!anchored.is_empty());
    for entry in &anchored {
        let anchor = entry.anchor.as_ref().and_then(|anchor| anchor.get::<DirectoryAnchor>()).expect("std anchor");
        let parent = entry.path.directory().expect("a child");
        assert_eq!(anchor.path(), parent.under(&root));
        let name = entry.path.name().expect("name");
        let through_anchor = statat(anchor, name, AtFlags::SYMLINK_NOFOLLOW).expect("stat through the anchor");
        let through_path = std::fs::symlink_metadata(entry.path.under(&root)).expect("stat through the path");
        assert_eq!(through_anchor.st_ino, std::os::unix::fs::MetadataExt::ino(&through_path));
    }
    drop(held);
    assert_eq!(scan.stats().anchors_live, 0, "an anchor closes when its last entry is dropped");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_bootstrap_estimate_learns_from_the_operations_it_admitted() {
    let fs = fixture();
    fs.set_cost(CostScope::Everything, FakeOp::Metadata, Duration::from_micros(40));
    let host = HostConfig::default();
    let Opened { mut scan, governor, clock } = open(fs.clone(), follow());
    let _ = drain(&mut scan);
    let learned = governor.view(now(&governor, &clock)).bootstrap_estimate;
    assert!(
        learned < host.initial_cost_estimate,
        "RFC 15.2: every released grant updates the estimate, the bootstrap scope's included: {learned:?}"
    );
}

#[test]
fn a_large_directory_progresses_lease_by_lease_under_its_ceiling() {
    let fs = fixture();
    fs.mkdir("wide");
    fs.set_synthetic_children("wide", 10_000);
    fs.set_chunk_size(100);
    let options = ScanOptions { entries_per_lease: 1_000, ..follow() };
    let Opened { mut scan, governor, clock } = open(fs.clone(), options);
    let events = drain(&mut scan);
    assert_eq!(entries(&events).iter().filter(|entry| entry.path.to_string().starts_with("wide/")).count(), 10_000);
    let stats = scan.stats();
    assert!(stats.leases >= 10 + 4, "RFC 10.2: every lease covers at most its entries: {stats:?}");
    assert_eq!(governor.view(now(&governor, &clock)).lease_grants, stats.leases - 5, "each further lease is granted");
    assert!(governor.grants().is_empty());
}

// Barriers establish physical start/completion. Timeouts only bound a broken
// test.
struct ListingGate {
    entered: std::sync::mpsc::Sender<()>,
    released: Mutex<bool>,
    changed: std::sync::Condvar,
}

impl ListingGate {
    fn wait(&self) {
        self.entered.send(()).expect("start notification");
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.changed.wait(released).unwrap();
        }
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

struct ReleaseListing(Arc<ListingGate>);
impl Drop for ReleaseListing {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct BlockedListing {
    inner: Arc<FakeFileSystem>,
    gate: Arc<ListingGate>,
}

struct BlockedSession {
    inner: Box<dyn ListingSession>,
    gate: Arc<ListingGate>,
}

impl ListingSession for BlockedSession {
    fn resume(self: Box<Self>, lease: Lease) -> (Continuation, SessionCost) {
        self.gate.wait();
        self.inner.resume(lease)
    }
}

impl FileSystem for BlockedListing {
    fn capabilities(&self) -> FsCapabilities {
        self.inner.capabilities()
    }
    fn canonicalize(&self, root: &Path) -> Result<PathBuf, FsError> {
        self.inner.canonicalize(root)
    }
    fn metadata(&self, root: &Path, path: &RelativePath) -> Result<EntryInfo, FsError> {
        self.inner.metadata(root, path)
    }
    fn resolve_domain(
        &self,
        root: &Path,
        path: &RelativePath,
        parent: Option<&ProbeResult>,
    ) -> Result<ProbeResult, FsError> {
        self.inner.resolve_domain(root, path, parent)
    }
    fn open_listing(
        &self,
        root: &Path,
        path: &RelativePath,
        ceilings: Ceilings,
        cancel: CancellationToken,
    ) -> Box<dyn ListingSession> {
        let inner = self.inner.open_listing(root, path, ceilings, cancel);
        if path.to_string() == "a" { Box::new(BlockedSession { inner, gate: self.gate.clone() }) } else { inner }
    }
    fn enrich(&self, root: &Path, path: &RelativePath, batch: &EnrichmentBatch) -> Result<Enrichment, FsError> {
        self.inner.enrich(root, path, batch)
    }
    fn watch(
        &self,
        root: &Path,
        path: &RelativePath,
        recursive: bool,
        sink: Arc<dyn WatcherSink>,
    ) -> Result<WatchId, FsError> {
        self.inner.watch(root, path, recursive, sink)
    }
    fn unwatch(&self, watch: WatchId) {
        self.inner.unwatch(watch)
    }
}

fn eventually(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "condition did not become true");
        std::thread::yield_now();
    }
}

fn blocked_scan(
    ceiling: Duration,
) -> (Scan, HostGovernor, Arc<ManualClock>, Arc<ListingGate>, std::sync::mpsc::Receiver<()>) {
    let fs = fixture();
    fs.set_domain("a", MEDIA);
    fs.mkdir("b");
    fs.set_domain("b", MEDIA);
    let (entered, receiver) = std::sync::mpsc::channel();
    let gate = Arc::new(ListingGate { entered, released: Mutex::new(false), changed: std::sync::Condvar::new() });
    let governor = HostGovernor::independent(&HostConfig {
        foreground_duty: 1.0,
        domain_foreground_duty: 1.0,
        ..Default::default()
    });
    let clock = ManualClock::new();
    let scan = Scan::open_outside_host_governor(
        Arc::new(BlockedListing { inner: fs.clone(), gate: gate.clone() }),
        fs.root().to_path_buf(),
        Arc::new(LoadAll),
        ScanOptions { ceiling, ..follow() },
        governor.clone(),
        clock.clone(),
    )
    .unwrap();
    (scan, governor, clock, gate, receiver)
}

#[test]
fn a_freshly_blocked_listing_is_quarantined_without_abandoning_physical_ownership() {
    let (scan, governor, clock, gate, entered) = blocked_scan(Duration::MAX);
    let _release = ReleaseListing(gate.clone());
    let executor = tree_fucker::ListingExecutor::new(2).unwrap();
    let (done, results) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut scan = scan.with_listing_executor(executor);
        let events = drain(&mut scan);
        drop(scan);
        done.send(events).unwrap();
    });
    entered.recv_timeout(Duration::from_secs(5)).expect("held listing started");
    clock.advance(Duration::from_secs(31));
    let events = results.recv_timeout(Duration::from_secs(5)).expect("healthy siblings must make progress");
    let media = StorageDomainId::of(&FakeFileSystem::domain_key(MEDIA));
    assert!(events.contains(&ScanEvent::Unlisted { path: path("a"), failure: ScanFailure::Quarantined(media) }));
    assert!(paths(&events).contains(&"c/z".to_owned()));
    assert!(!paths(&events).contains(&"a/x".to_owned()));
    assert_eq!(governor.stuck_grants().len(), 1);
    assert_eq!(governor.view(now(&governor, &clock)).in_flight, 1);
    assert_eq!(
        governor.view(now(&governor, &clock)).accounted_memory,
        governor.limits().in_flight_listing_bytes / governor.limits().maximum_in_flight as u64
    );
    gate.release();
    worker.join().unwrap();
    eventually(|| governor.grants().is_empty() && governor.view(now(&governor, &clock)).accounted_memory == 0);
}

#[test]
fn cancelling_a_running_listing_returns_without_releasing_its_physical_slot() {
    let (scan, governor, clock, gate, entered) = blocked_scan(Duration::MAX);
    let _release = ReleaseListing(gate.clone());
    let cancel = scan.cancellation();
    let (done, results) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut scan = scan.with_listing_executor(tree_fucker::ListingExecutor::new(1).unwrap());
        let result = scan.by_ref().collect::<Result<Vec<_>, _>>();
        assert!(scan.next().is_none());
        drop(scan);
        done.send(result).unwrap();
    });
    entered.recv_timeout(Duration::from_secs(5)).expect("held listing started");
    cancel.cancel();
    assert!(matches!(results.recv_timeout(Duration::from_secs(5)).unwrap(), Err(Error::Cancelled)));
    assert_eq!(governor.view(now(&governor, &clock)).in_flight, 1);
    assert!(governor.view(now(&governor, &clock)).accounted_memory > 0);
    gate.release();
    worker.join().unwrap();
    eventually(|| governor.grants().is_empty() && governor.view(now(&governor, &clock)).accounted_memory == 0);
}

#[test]
fn inline_listing_waits_for_physical_completion_even_after_cancellation() {
    let (scan, governor, clock, gate, entered) = blocked_scan(Duration::MAX);
    let _release = ReleaseListing(gate.clone());
    let cancel = scan.cancellation();
    let (done, results) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        done.send(scan.collect::<Result<Vec<_>, _>>()).unwrap();
    });
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    cancel.cancel();
    // Cancellation cannot interrupt the inline adapter, and the start barrier
    // proves the call is active before we check its physical ownership.
    assert_eq!(governor.view(now(&governor, &clock)).in_flight, 1);
    assert!(matches!(results.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));
    gate.release();
    assert!(matches!(results.recv_timeout(Duration::from_secs(5)).unwrap(), Err(Error::Cancelled)));
    worker.join().unwrap();
    assert!(governor.grants().is_empty());
}

struct NotifyingClock(std::sync::mpsc::Sender<()>);
impl Clock for NotifyingClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, duration: Duration) {
        let _ = self.0.send(());
        std::thread::sleep(duration.min(Duration::from_millis(10)));
    }
    fn wait_for_change(&self, governor: &HostGovernor, seen: u64, timeout: Duration) {
        let _ = self.0.send(());
        governor.wait_for_change(seen, timeout.min(Duration::from_millis(10)));
    }
}

#[test]
fn cancellation_while_waiting_for_admission_or_physical_capacity_leaks_no_reservation() {
    for capacity in [false, true] {
        let fs = fixture();
        let governor = HostGovernor::independent(&HostConfig {
            maximum_in_flight: 1,
            per_domain_concurrency: 1,
            failure_surcharge: Duration::from_secs(60),
            foreground_duty: 1.0,
            domain_foreground_duty: 1.0,
            ..Default::default()
        });
        let (waiting, waits) = std::sync::mpsc::channel();
        let clock = Arc::new(NotifyingClock(waiting));
        let mut scan = Scan::open_outside_host_governor(
            fs.clone(),
            fs.root().to_path_buf(),
            Arc::new(LoadAll),
            follow(),
            governor.clone(),
            clock.clone(),
        )
        .unwrap()
        .with_listing_executor(tree_fucker::ListingExecutor::new(1).unwrap());
        let Some(Ok(ScanEvent::Entry(root))) = scan.next() else { panic!("root") };
        while waits.try_recv().is_ok() {}
        let base = governor.base(clock.now());
        let at = || MonotonicTime(clock.now().saturating_duration_since(base));
        let held = GrantId::Bootstrap(u64::MAX);
        if capacity {
            governor
                .try_admit(
                    Reservation {
                        id: held,
                        path: RelativePath::root(),
                        reads: 1,
                        registrations: 0,
                        operations: 0,
                        ceiling: None,
                        lease: 0,
                        domain: None,
                        origin: WorkOrigin::Background,
                        listing: false,
                    },
                    at(),
                )
                .unwrap();
            governor.try_start(held, at()).unwrap();
        } else {
            governor.charge_surcharge(Some(root.domain), WorkOrigin::Foreground, at());
        }
        let cancel = scan.cancellation();
        let (done, results) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = scan.next();
            drop(scan);
            done.send(result).unwrap();
        });
        waits.recv_timeout(Duration::from_secs(5)).expect("scan entered the waiting path");
        assert_eq!(fs.count_ops(FakeOp::ReadDir, ""), 0);
        if capacity {
            assert!(governor.grants().iter().any(|grant| grant.id != held && grant.started.is_none()));
        } else {
            assert!(governor.grants().is_empty(), "admission was denied before any reservation");
        }
        cancel.cancel();
        assert!(matches!(results.recv_timeout(Duration::from_secs(5)).unwrap(), Some(Err(Error::Cancelled))));
        worker.join().unwrap();
        assert_eq!(governor.grants().len(), usize::from(capacity));
        if capacity {
            governor.release(held, at());
        }
        assert!(governor.grants().is_empty());
    }
}

#[test]
fn bounded_listings_transfer_their_buffer_across_leases_without_double_reservation() {
    let fs = fixture();
    let Opened { scan, governor, clock } = open_with(
        fs,
        Arc::new(LoadAll),
        ScanOptions { entries_per_lease: 1, ..follow() },
        HostConfig { maximum_in_flight: 1, per_domain_concurrency: 1, ..Default::default() },
    );
    let mut scan = scan.with_listing_executor(tree_fucker::ListingExecutor::new(1).unwrap());
    let events = drain(&mut scan);
    assert_eq!(entries(&events).len(), 8);
    assert!(scan.stats().leases > scan.stats().listings);
    drop(scan);
    assert!(governor.grants().is_empty());
    assert_eq!(governor.view(now(&governor, &clock)).accounted_memory, 0);
}

#[test]
fn a_running_listing_cannot_hide_the_command_ceiling() {
    let (scan, governor, clock, gate, entered) = blocked_scan(Duration::from_secs(2));
    let _release = ReleaseListing(gate.clone());
    let (done, results) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        done.send(
            scan.with_listing_executor(tree_fucker::ListingExecutor::new(2).unwrap()).collect::<Result<Vec<_>, _>>(),
        )
        .unwrap();
    });
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    clock.advance(Duration::from_secs(3));
    let result = results.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        matches!(result, Err(Error::ResourceLimited(limited)) if limited.limit == ResourceLimit::CommandWorkerTime)
    );
    assert_eq!(governor.view(now(&governor, &clock)).in_flight, 1);
    gate.release();
    worker.join().unwrap();
    eventually(|| governor.grants().is_empty() && governor.view(now(&governor, &clock)).accounted_memory == 0);
}

#[test]
fn an_adapter_panic_releases_its_grant_and_reserved_buffer() {
    let (scan, governor, clock, gate, entered) = blocked_scan(Duration::MAX);
    let _release = ReleaseListing(gate);
    // The fake adapter panics sending its start notification to a closed
    // channel.
    drop(entered);
    let result =
        scan.with_listing_executor(tree_fucker::ListingExecutor::new(1).unwrap()).collect::<Result<Vec<_>, _>>();
    assert!(matches!(result, Err(Error::WorkerLost)));
    eventually(|| governor.grants().is_empty() && governor.view(now(&governor, &clock)).accounted_memory == 0);
    assert_eq!(governor.view(now(&governor, &clock)).surcharged, governor.limits().failure_surcharge);
}

#[test]
fn a_quarantined_sibling_does_not_wait_for_an_exhausted_executor() {
    let (scan, governor, clock, gate, entered) = blocked_scan(Duration::MAX);
    let _release = ReleaseListing(gate.clone());
    let cancel = scan.cancellation();
    let (events, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        for event in scan.with_listing_executor(tree_fucker::ListingExecutor::new(1).unwrap()) {
            events.send(event).unwrap();
        }
    });
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    clock.advance(Duration::from_secs(31));
    loop {
        let event = receiver.recv_timeout(Duration::from_secs(5)).expect("quarantined sibling must not need a worker");
        if matches!(event, Ok(ScanEvent::Unlisted { path: p, failure: ScanFailure::Quarantined(_) }) if p == path("b"))
        {
            break;
        }
    }
    cancel.cancel();
    worker.join().unwrap();
    assert_eq!(governor.view(now(&governor, &clock)).in_flight, 1);
    gate.release();
    eventually(|| governor.grants().is_empty());
}
