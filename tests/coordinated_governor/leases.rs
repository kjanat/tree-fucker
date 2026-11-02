use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use tree_fucker::testing::{FakeFileSystem, FakeOp};
use tree_fucker::{
    CancellationToken, Ceilings, Continuation, DirectoryListing, DomainCapabilities, DomainCrossing, Enrichment,
    EnrichmentBatch, EntryInfo, FileSystem, FsCapabilities, FsError, IdentitySource, Lease, ListingSession, LoadAll,
    MetadataFields, MetadataSources, ProbeResult, Scan, ScanEvent, ScanOptions, SessionCost, SystemClock, WatchId,
    WatcherKind, WatcherSink,
};

use super::*;

#[derive(Clone)]
struct ObservedFileSystem {
    inner: Arc<FakeFileSystem>,
    host: HostGovernor,
    scope: Option<Arc<Scope>>,
    leases: Arc<Mutex<Vec<(Lease, SessionCost)>>>,
    listings: Arc<AtomicUsize>,
    initial_identity_reads: Arc<Mutex<Option<Vec<usize>>>>,
    enrichment_batches: Arc<Mutex<Vec<EnrichmentBatch>>>,
}

struct ObservedSession {
    inner: Box<dyn ListingSession>,
    observer: ObservedFileSystem,
    initial: bool,
    path: RelativePath,
}

impl ListingSession for ObservedSession {
    fn resume(self: Box<Self>, lease: Lease) -> (Continuation, SessionCost) {
        let Self { inner, observer, initial, path } = *self;
        let grants: Vec<_> = observer.host.grants().into_iter().filter(|grant| grant.started.is_some()).collect();
        assert_eq!(grants.len(), 1, "one physical listing lease");
        assert!(grants[0].listing);
        let expected_domain =
            tree_fucker::StorageDomainId::of(&FakeFileSystem::domain_key(observer.inner.domain_of(&path)));
        if !path.is_root() {
            assert_eq!(
                grants[0].domain,
                Some(expected_domain),
                "listing must hold permission for its resolved domain: {path}"
            );
        }
        assert_eq!(lease.operations, grants[0].operations as usize, "adapter must receive the negotiated allowance");
        if let Some(scope) = &observer.scope {
            assert_eq!(scope.view().unwrap().physical, 1);
        }
        let (continuation, cost) = inner.resume(lease);
        assert!(cost.per_child_operations() as usize <= lease.operations);
        assert!(cost.listing_operations + cost.per_child_operations() <= grants[0].required + grants[0].operations);
        if initial {
            observer.leases.lock().unwrap().push((lease, cost));
            if matches!(&continuation, Continuation::Finished(_)) {
                *observer.initial_identity_reads.lock().unwrap() = Some(
                    (0..40)
                        .map(|index| observer.inner.count_ops(FakeOp::ResolveIdentity, &format!("file-{index:02}")))
                        .collect(),
                );
            }
        }
        let continuation = match continuation {
            Continuation::Suspended(inner) => {
                Continuation::Suspended(Box::new(Self { inner, observer, initial, path }))
            }
            finished => finished,
        };
        (continuation, cost)
    }

    fn take_chunk(&mut self) -> Option<DirectoryListing> {
        self.inner.take_chunk()
    }

    fn supports_chunks(&self) -> bool {
        self.inner.supports_chunks()
    }
}

impl FileSystem for ObservedFileSystem {
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
        self.inner.resolve_domain(root, path, parent)
    }

    fn metadata(&self, root: &Path, path: &RelativePath) -> Result<EntryInfo, FsError> {
        self.inner.metadata(root, path)
    }

    fn open_listing(
        &self,
        root: &Path,
        path: &RelativePath,
        ceilings: Ceilings,
        cancel: CancellationToken,
    ) -> Box<dyn ListingSession> {
        Box::new(ObservedSession {
            inner: self.inner.open_listing(root, path, ceilings, cancel),
            observer: self.clone(),
            initial: self.listings.fetch_add(1, Ordering::Relaxed) == 0,
            path: path.clone(),
        })
    }

    fn enrich(&self, root: &Path, path: &RelativePath, batch: &EnrichmentBatch) -> Result<Enrichment, FsError> {
        let grants: Vec<_> = self.host.grants().into_iter().filter(|grant| grant.started.is_some()).collect();
        assert_eq!(grants.len(), 1, "one physical enrichment batch");
        let grant = &grants[0];
        assert!(!grant.listing);
        assert!(batch.children.len() <= grant.operations as usize, "children must fit the negotiated allowance");
        if let Some(scope) = &self.scope {
            assert_eq!(scope.view().unwrap().physical, 1);
        }
        let result = self.inner.enrich(root, path, batch)?;
        assert!(result.metadata_operations <= grant.required + grant.operations);
        let mut batches = self.enrichment_batches.lock().unwrap();
        if batches.iter().map(|batch| batch.children.len()).sum::<usize>() < 40 {
            batches.push(batch.clone());
        }
        Ok(result)
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
        self.inner.unwatch(watch);
    }
}

fn setup(shared: bool) -> (tempfile::TempDir, Arc<ObservedFileSystem>) {
    let mut builder = tempfile::Builder::new();
    builder.prefix("tree-fucker-negotiated-leases-");
    #[cfg(windows)]
    let root = builder.tempdir().unwrap();
    #[cfg(not(windows))]
    let root = builder.tempdir_in(coordination_support::RENDEZVOUS).unwrap();
    let local = HostConfig {
        maximum_in_flight: 1,
        per_domain_concurrency: 1,
        background_duty: 1.0,
        domain_background_duty: 1.0,
        foreground_duty: 1.0,
        domain_foreground_duty: 1.0,
        background_burst: Duration::from_secs(1),
        domain_background_burst: Duration::from_secs(1),
        foreground_burst: Duration::from_secs(1),
        domain_foreground_burst: Duration::from_secs(1),
        initial_cost_estimate: Duration::from_micros(100),
        ..HostConfig::default()
    };
    let scope = shared.then(|| {
        let mut limits = Config::from_host(&local, 8, 16, 16).unwrap();
        limits.initial_estimate_ns = 1_000_000;
        limits.background.burst_ns = 13_000_000;
        limits.foreground.burst_ns = 13_000_000;
        limits.domain_background.burst_ns = 13_000_000;
        limits.domain_foreground.burst_ns = 13_000_000;
        Scope::open(root.path().join("scope"), limits).unwrap()
    });
    let host = match &scope {
        Some(scope) => HostGovernor::with_coordination(&local, scope.clone()).unwrap(),
        None => HostGovernor::independent(&local),
    };
    let inner = Arc::new(FakeFileSystem::new(WatcherKind::None));
    inner.set_default_capabilities(DomainCapabilities {
        identity_source: IdentitySource::PerChildRead,
        ..DomainCapabilities::inline()
    });
    for index in 0..40 {
        inner.create_file(&format!("file-{index:02}"), index);
    }
    (
        root,
        Arc::new(ObservedFileSystem {
            inner,
            host,
            scope,
            leases: Arc::default(),
            listings: Arc::default(),
            initial_identity_reads: Arc::default(),
            enrichment_batches: Arc::default(),
        }),
    )
}

const SIZE: MetadataFields = MetadataFields { size: true, ..MetadataFields::NONE };

fn request_enrichment(filesystem: &ObservedFileSystem) {
    filesystem.inner.set_default_capabilities(DomainCapabilities {
        metadata_sources: MetadataSources::PER_CHILD_READ,
        ..DomainCapabilities::inline()
    });
}

fn verify_enrichment(filesystem: &ObservedFileSystem, shared: bool) {
    let batches = filesystem.enrichment_batches.lock().unwrap();
    let sizes: Vec<_> = batches.iter().map(|batch| batch.children.len()).collect();
    assert_eq!(sizes.iter().sum::<usize>(), 40);
    if shared {
        // Every batch is checked against its active shared grant by the
        // observed adapter. Whether the whole pass splits depends on how much
        // duty budget has refilled while the preceding listing ran.
        assert!(sizes.iter().all(|size| *size > 0));
    } else {
        assert_eq!(sizes, [40]);
    }
    let mut names: Vec<_> = batches.iter().flat_map(|batch| batch.children.iter().cloned()).collect();
    names.sort();
    let expected: Vec<std::ffi::OsString> = (0..40).map(|index| format!("file-{index:02}").into()).collect();
    assert_eq!(names, expected, "the first enrichment pass reads each child once");
    verify_settled(filesystem);
}

fn verify(filesystem: &ObservedFileSystem, shared: bool) {
    let leases = filesystem.leases.lock().unwrap();
    assert!(
        leases.iter().skip_while(|(_, cost)| cost.per_child_operations() == 0).all(|(lease, _)| lease.operations > 0),
        "a listing that performed per-child work must retain an operations allowance on resume: {leases:?}"
    );
    let optional: Vec<_> = leases.iter().filter(|(lease, _)| lease.operations > 0).collect();
    assert!(!optional.is_empty());
    if shared {
        assert!(
            (1..=12).contains(&optional[0].0.operations),
            "shared initial allowance must constrain the first per-child lease: {optional:?}"
        );
        assert!(optional.len() > 1, "listing must resume after exhausting its smaller allowance");
    } else {
        assert_eq!(optional[0].0.operations, 64, "local control permits the requested allowance");
        assert_eq!(optional.len(), 1);
    }
    assert_eq!(
        leases.iter().map(|(_, cost)| cost.per_child_operations()).sum::<u32>(),
        40,
        "shared={shared}; leases={leases:?}; directory reads={}",
        filesystem.inner.count_ops(FakeOp::ReadDir, ".")
    );
    assert_eq!(*filesystem.initial_identity_reads.lock().unwrap(), Some(vec![1; 40]));
    verify_settled(filesystem);
}

fn verify_settled(filesystem: &ObservedFileSystem) {
    assert!(filesystem.host.coordination_error().is_none());
    let local = filesystem.host.view(NOW);
    assert_eq!(local.in_flight, 0);
    assert_eq!(local.preparations, 0);
    if let Some(scope) = &filesystem.scope {
        let shared = scope.view().unwrap();
        assert_eq!((shared.physical, shared.prepared), (0, 0));
    }
}

#[test]
fn scan_passes_negotiated_allowances_to_initial_and_resumed_listing_leases() {
    scan_allowances(false);
}

#[test]
fn scan_enrichment_batches_respect_the_active_grant() {
    scan_allowances(true);
}

fn scan_allowances(enrichment: bool) {
    for shared in [false, true] {
        let (_root, filesystem) = setup(shared);
        if enrichment {
            request_enrichment(&filesystem);
        }
        let scan = Scan::open_outside_host_governor(
            filesystem.clone(),
            filesystem.inner.root().to_path_buf(),
            Arc::new(LoadAll),
            ScanOptions {
                fields: if enrichment { SIZE } else { MetadataFields::NONE },
                crossing: DomainCrossing::Follow,
                entries_per_lease: 64,
                operations_per_lease: 64,
                streaming: false,
                ceiling: Duration::MAX,
                ..ScanOptions::default()
            },
            filesystem.host.clone(),
            Arc::new(SystemClock),
        )
        .unwrap();
        let mut paths = Vec::new();
        for event in scan {
            match event.unwrap() {
                ScanEvent::Entry(entry) => {
                    assert!(entry.identity.is_some());
                    if enrichment && entry.path.path().to_string() != "." {
                        let index: u64 = entry.path.path().to_string().strip_prefix("file-").unwrap().parse().unwrap();
                        assert_eq!(entry.metadata.size, Some(index));
                        assert!(entry.metadata_error.is_none());
                    }
                    paths.push(entry.path.path().to_string());
                }
                other => panic!("unexpected scan event: {other:?}"),
            }
        }
        paths.sort();
        let expected: Vec<_> =
            std::iter::once(".".into()).chain((0..40).map(|index| format!("file-{index:02}"))).collect();
        assert_eq!(paths, expected);
        if enrichment {
            verify_enrichment(&filesystem, shared);
        } else {
            verify(&filesystem, shared);
        }
    }
}

#[test]
#[cfg(feature = "tokio")]
fn tree_passes_negotiated_allowances_to_initial_and_resumed_listing_leases() {
    tree_allowances(false);
}

#[test]
#[cfg(feature = "tokio")]
fn tree_enrichment_batches_respect_the_active_grant() {
    tree_allowances(true);
}

#[cfg(feature = "tokio")]
fn tree_allowances(enrichment: bool) {
    use tree_fucker::Tree;
    use tree_fucker::runtime::TokioRuntime;

    for shared in [false, true] {
        let (_root, filesystem) = setup(shared);
        if enrichment {
            request_enrichment(&filesystem);
        }
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(15), async {
                let (handle, mut updates) = Tree::open_outside_host_governor(
                    filesystem.clone(),
                    filesystem.inner.root().to_path_buf(),
                    Arc::new(LoadAll),
                    tree_fucker::Config {
                        metadata_fields: if enrichment { SIZE } else { MetadataFields::NONE },
                        entries_per_lease: 64,
                        operations_per_lease: 64,
                        // Defer periodic rounds beyond this test.
                        fixed_interval: Some(Duration::from_secs(3600)),
                        ..tree_fucker::Config::default()
                    },
                    Arc::new(TokioRuntime::current()),
                    filesystem.host.clone(),
                )
                .await
                .unwrap();
                handle.initial_scan_complete().await.unwrap();
                if enrichment {
                    loop {
                        let snapshot = handle.snapshot();
                        let ready = (0..40).all(|index| {
                            let path = RelativePath::parse(format!("file-{index:02}")).unwrap();
                            snapshot.get(&path).is_some_and(|entry| entry.metadata.size == Some(index))
                        });
                        if ready {
                            break;
                        }
                        updates.next().await.expect("tree remains open").expect("enrichment update");
                    }
                }
                let snapshot = handle.snapshot();
                assert_eq!(snapshot.entries().count(), 41);
                for index in 0..40 {
                    let path = RelativePath::parse(format!("file-{index:02}")).unwrap();
                    assert!(snapshot.get(&path).unwrap().identity.is_some());
                    if enrichment {
                        assert_eq!(snapshot.get(&path).unwrap().metadata.size, Some(index));
                    }
                }
                handle.shutdown().await.unwrap();
                // Logical shutdown retains already dispatched physical work.
                // Let the completion owner settle before inspecting ownership.
                loop {
                    let local = filesystem.host.view(NOW);
                    let shared_settled = filesystem.scope.as_ref().is_none_or(|scope| match scope.view() {
                        Ok(view) => view.physical == 0 && view.prepared == 0,
                        Err(coordination_support::native::Error::Busy) => false,
                        Err(error) => panic!("settlement failed: {error}"),
                    });
                    if local.in_flight == 0 && local.preparations == 0 && shared_settled {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
        });
        if enrichment {
            verify_enrichment(&filesystem, shared);
        } else {
            verify(&filesystem, shared);
        }
    }
}

#[test]
fn inline_scan_reacquires_listing_permission_for_a_new_domain() {
    for shared in [false, true] {
        let (_root, filesystem) = setup(shared);
        filesystem.inner.report_inline_domains(false);
        filesystem.inner.mkdir("mounted");
        filesystem.inner.create_file("mounted/leaf", 1);
        filesystem.inner.set_domain("mounted", tree_fucker::testing::DomainId::new(42));
        let scan = Scan::open_outside_host_governor(
            filesystem.clone(),
            filesystem.inner.root().to_path_buf(),
            Arc::new(LoadAll),
            ScanOptions {
                crossing: DomainCrossing::Follow,
                streaming: false,
                ceiling: Duration::MAX,
                ..ScanOptions::default()
            },
            filesystem.host.clone(),
            Arc::new(SystemClock),
        )
        .unwrap();
        let paths: Vec<_> = scan
            .map(|event| match event.unwrap() {
                ScanEvent::Entry(entry) => entry.path.path().to_string(),
                other => panic!("unexpected event: {other:?}"),
            })
            .collect();
        assert!(paths.iter().any(|path| path == "mounted/leaf"));
    }
}
