use std::time::Instant;

use tree_fucker::testing::FakeFileSystem;
use tree_fucker::{Clock, Error, LoadAll, ResourceLimit, Scan, ScanOptions, WatcherKind};

use super::*;

struct NoWait;

impl Clock for NoWait {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, _: Duration) {
        panic!("an impossible admission must not wait for refill");
    }

    fn wait_for_change(&self, _: &HostGovernor, _: u64, _: Duration) {
        panic!("an impossible admission must not wait for a change");
    }
}

#[test]
fn scan_reports_a_shared_estimate_above_its_bootstrap_ceiling() {
    let (root, _) = fixture();
    let local = host_config();
    let mut config = Config::from_host(&local, 8, 16, 16).unwrap();
    config.initial_estimate_ns = 10_000_000;
    let scope = Scope::open(root.path().join("expensive"), config).unwrap();
    let host = HostGovernor::with_coordination(&local, scope.clone()).unwrap();
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    let result = Scan::open_outside_host_governor(
        fs.clone(),
        fs.root().to_path_buf(),
        Arc::new(LoadAll),
        ScanOptions { ceiling: Duration::from_millis(5), ..ScanOptions::default() },
        host.clone(),
        Arc::new(NoWait),
    );
    let Err(Error::ResourceLimited(limited)) = result else { panic!("expected a command ceiling error") };
    assert_eq!(limited.limit, ResourceLimit::CommandWorkerTime);
    assert_eq!(limited.configured, 5_000_000);
    assert_eq!(limited.observed, 10_000_000);
    assert_eq!(host.view(NOW).preparations, 0);
    let shared = scope.view().unwrap();
    assert_eq!((shared.prepared, shared.physical, shared.charged_ns), (0, 0, 0));
}

#[cfg(target_os = "linux")]
mod quarantine {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use tree_fucker::domain::{DeclaredProbe, LinuxProbe};
    use tree_fucker::testing::FakeOp;
    use tree_fucker::{
        CancellationToken, Ceilings, DomainCapabilities, DomainCrossing, DomainIdentity, DomainProbe, Enrichment,
        EnrichmentBatch, EntryInfo, FileSystem, FsCapabilities, FsError, ListingSession, ProbeResult, ScanEvent,
        ScanFailure, StorageDomainId, WatchId, WatcherSink,
    };

    use super::*;

    struct StartOnPreparation {
        host: HostGovernor,
        armed: Arc<AtomicBool>,
        peer: Mutex<Option<(HostGovernor, GrantId)>>,
    }

    impl Clock for StartOnPreparation {
        fn now(&self) -> Instant {
            if self.armed.load(Ordering::SeqCst)
                && self.host.view(NOW).preparations > 0
                && let Some((peer, id)) = self.peer.lock().unwrap().take()
            {
                peer.try_start(id, NOW).unwrap();
            }
            Instant::now()
        }
        fn sleep(&self, duration: Duration) {
            NoWait.sleep(duration);
        }
        fn wait_for_change(&self, host: &HostGovernor, seen: u64, duration: Duration) {
            NoWait.wait_for_change(host, seen, duration);
        }
    }

    struct Domains {
        inner: Arc<FakeFileSystem>,
        healthy: DomainIdentity,
        stuck: DomainIdentity,
        armed: Arc<AtomicBool>,
    }

    impl FileSystem for Domains {
        fn capabilities(&self) -> FsCapabilities {
            self.inner.capabilities()
        }
        fn canonicalize(&self, root: &Path) -> Result<PathBuf, FsError> {
            self.inner.canonicalize(root)
        }
        fn resolve_domain(
            &self,
            _: &Path,
            path: &RelativePath,
            parent: Option<&ProbeResult>,
        ) -> Result<ProbeResult, FsError> {
            let bad = path.to_string() == "bad";
            if bad {
                self.armed.store(true, Ordering::SeqCst);
            }
            DeclaredProbe::new(
                if bad { self.stuck.clone() } else { self.healthy.clone() },
                DomainCapabilities::inline(),
                bad || path.is_root(),
            )
            .probe(Path::new("."), parent)
            .map_err(|_| FsError::PermissionDenied)
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
            self.inner.open_listing(root, path, ceilings, cancel)
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
        fn enrich(&self, root: &Path, path: &RelativePath, batch: &EnrichmentBatch) -> Result<Enrichment, FsError> {
            self.inner.enrich(root, path, batch)
        }
        fn unwatch(&self, watch: WatchId) {
            self.inner.unwatch(watch);
        }
    }

    fn scan_with_stuck_peer(at_start: bool) {
        let (root, _) = fixture();
        let local = HostConfig {
            maximum_in_flight: 2,
            per_domain_concurrency: 1,
            domain_foreground_burst: Duration::from_secs(1),
            ..host_config()
        };
        let mut config = Config::from_host(&local, 8, 16, 16).unwrap();
        config.stuck_after_ns = 1;
        let scope = Scope::open(root.path().join("quarantine"), config).unwrap();
        let peer = HostGovernor::with_coordination(&local, scope.clone()).unwrap();
        let host = HostGovernor::with_coordination(&local, scope.clone()).unwrap();
        let healthy = LinuxProbe::new().probe(Path::new("/"), None).unwrap().identity;
        let stuck = LinuxProbe::new().probe(Path::new("/dev/shm"), None).unwrap().identity;
        assert_ne!(healthy.key(), stuck.key());
        let domain = StorageDomainId::of(stuck.key().unwrap());
        peer.register_domain(domain, &DomainCapabilities::inline(), NOW);
        let mut reservation = request(&peer);
        reservation.domain = Some(domain);
        let id = reservation.id;
        peer.try_admit(reservation, NOW).unwrap();
        if !at_start {
            peer.try_start(id, NOW).unwrap();
        }
        let inner = Arc::new(FakeFileSystem::new(WatcherKind::None));
        inner.mkdir("bad");
        inner.create_file("bad/hidden", 1);
        inner.mkdir("healthy");
        inner.create_file("healthy/visible", 1);
        inner.report_inline_domains(false);
        let armed = Arc::new(AtomicBool::new(false));
        let fs = Arc::new(Domains { inner: inner.clone(), healthy, stuck, armed: armed.clone() });
        let clock: Arc<dyn Clock> = if at_start {
            Arc::new(StartOnPreparation { host: host.clone(), armed, peer: Mutex::new(Some((peer.clone(), id))) })
        } else {
            Arc::new(NoWait)
        };
        let scan = Scan::open_outside_host_governor(
            fs,
            inner.root().to_path_buf(),
            Arc::new(LoadAll),
            ScanOptions { crossing: DomainCrossing::Follow, ceiling: Duration::MAX, ..ScanOptions::default() },
            host.clone(),
            clock,
        )
        .unwrap();
        let events: Vec<_> = scan.map(Result::unwrap).collect();
        assert!(events.iter().any(|event| matches!(event,
            ScanEvent::Unlisted { path, failure: ScanFailure::Quarantined(id) } if path.to_string() == "bad" && *id == domain
        )), "{events:?}");
        assert!(
            events
                .iter()
                .any(|event| matches!(event, ScanEvent::Entry(entry) if entry.path.to_string() == "healthy/visible"))
        );
        assert_eq!(inner.count_ops(FakeOp::ReadDir, "bad"), 0);
        assert!(!host.quarantined(Some(domain)), "quarantine belongs to the other participant");
        assert_eq!(host.view(NOW).preparations, 0);
        let shared = scope.view().unwrap();
        assert_eq!((shared.prepared, shared.physical), (0, 1));
        peer.release(id, NOW);
        assert_eq!(scope.view().unwrap().physical, 0);
    }

    #[test]
    fn scan_skips_shared_quarantine_during_preparation() {
        scan_with_stuck_peer(false);
    }

    #[test]
    fn scan_skips_shared_quarantine_between_preparation_and_start() {
        scan_with_stuck_peer(true);
    }
}
