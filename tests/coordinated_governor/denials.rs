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
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::OpenOptions;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use rustix::fs::{FlockOperation, flock};
    use tree_fucker::domain::{DeclaredProbe, LinuxProbe};
    use tree_fucker::testing::FakeOp;
    use tree_fucker::{
        CancellationToken, Ceilings, DomainCapabilities, DomainCrossing, DomainIdentity, DomainKey, DomainProbe,
        Enrichment, EnrichmentBatch, EntryInfo, FileSystem, FsCapabilities, FsError, ListingSession, ProbeResult,
        ResourceHealth, ScanEvent, ScanFailure, StorageDomainId, WatchId, WatcherSink,
    };

    use super::*;

    struct StartOnPreparation {
        host: HostGovernor,
        armed: Arc<AtomicBool>,
        peer: Mutex<Option<(HostGovernor, GrantId)>>,
        at: Mutex<Instant>,
    }

    impl Clock for StartOnPreparation {
        fn now(&self) -> Instant {
            if self.armed.load(Ordering::SeqCst)
                && self.host.view(NOW).preparations > 0
                && let Some((peer, id)) = self.peer.lock().unwrap().take()
            {
                peer.try_start(id, NOW).unwrap();
            }
            *self.at.lock().unwrap()
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
        let clock = Arc::new(StartOnPreparation {
            host: host.clone(),
            armed,
            peer: Mutex::new(at_start.then(|| (peer.clone(), id))),
            at: Mutex::new(Instant::now()),
        });
        let mut scan = Scan::open_outside_host_governor(
            fs,
            inner.root().to_path_buf(),
            Arc::new(LoadAll),
            ScanOptions { crossing: DomainCrossing::Follow, ceiling: Duration::from_secs(1), ..ScanOptions::default() },
            host.clone(),
            clock,
        )
        .unwrap();
        let events: Vec<_> = scan.by_ref().map(Result::unwrap).collect();
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
        assert_eq!(scan.stats().admitted, host.view(NOW).charged, "only authorized work spends the Scan ceiling");
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

    #[test]
    fn repeated_lazy_read_start_quarantine_spends_no_scan_allowance() {
        let (root, _) = fixture();
        let local = host_config();
        let mut config = Config::from_host(&local, 8, 16, 16).unwrap();
        config.stuck_after_ns = 1;
        let scope = Scope::open(root.path().join("lazy-quarantine"), config).unwrap();
        let host = HostGovernor::with_coordination(&local, scope.clone()).unwrap();
        let peer = HostGovernor::with_coordination(&local, scope.clone()).unwrap();
        let inner = Arc::new(FakeFileSystem::new(WatcherKind::None));
        inner.report_inline_domains(false);
        let healthy = LinuxProbe::new().probe(Path::new("/"), None).unwrap().identity;
        let stuck = LinuxProbe::new().probe(Path::new("/dev/shm"), None).unwrap().identity;
        let armed = Arc::new(AtomicBool::new(false));
        let clock = Arc::new(StartOnPreparation {
            host: host.clone(),
            armed: armed.clone(),
            peer: Mutex::new(None),
            at: Mutex::new(Instant::now()),
        });
        let mut scan = Scan::open_outside_host_governor(
            Arc::new(Domains { inner: inner.clone(), healthy, stuck, armed: armed.clone() }),
            inner.root().to_path_buf(),
            Arc::new(LoadAll),
            ScanOptions { ceiling: Duration::from_secs(1), ..ScanOptions::default() },
            host.clone(),
            clock.clone(),
        )
        .unwrap();
        let ScanEvent::Entry(entry) = scan.next().unwrap().unwrap() else { panic!("root entry") };
        peer.register_domain(entry.domain, &DomainCapabilities::inline(), NOW);
        let charged = scan.stats().admitted;
        for _ in 0..3 {
            let reservation = Reservation { domain: Some(entry.domain), ..request(&peer) };
            let id = reservation.id;
            peer.try_admit(reservation, NOW).unwrap();
            *clock.peer.lock().unwrap() = Some((peer.clone(), id));
            armed.store(true, Ordering::SeqCst);
            let result = scan.read(&entry, |_| -> Result<(), FsError> { panic!("quarantined read started") });
            assert!(matches!(result, Err(Error::Stuck)), "{result:?}");
            assert!(clock.peer.lock().unwrap().is_none(), "peer must start after preparation");
            assert_eq!(scan.stats().admitted, charged, "an unstarted read cannot spend the Scan ceiling");
            assert_eq!(host.view(NOW).preparations, 0);
            peer.release(id, NOW);
            *clock.at.lock().unwrap() += Duration::from_secs(1);
        }
        scan.read(&entry, |_| Ok(())).expect("settled quarantine leaves the original read allowance available");
        assert_eq!(scan.stats().metadata_operations, 1);
        assert!(scan.stats().admitted > charged, "physically authorized work still spends allowance");
    }

    fn hold_bookkeeping(root: &tempfile::TempDir) -> std::fs::File {
        let anchor =
            OpenOptions::new().read(true).write(true).open(root.path().join("quarantine.authority.lock")).unwrap();
        flock(&anchor, FlockOperation::LockExclusive).unwrap();
        anchor
    }

    fn stuck_peer() -> (tempfile::TempDir, HostGovernor, HostGovernor, Reservation, GrantId) {
        let (root, _) = fixture();
        let local = HostConfig { domain_foreground_burst: Duration::from_secs(1), ..host_config() };
        let mut config = Config::from_host(&local, 8, 16, 16).unwrap();
        config.stuck_after_ns = 1;
        let scope = Scope::open(root.path().join("quarantine"), config).unwrap();
        let peer = HostGovernor::with_coordination(&local, scope.clone()).unwrap();
        let host = HostGovernor::with_coordination(&local, scope).unwrap();
        let stuck = LinuxProbe::new().probe(Path::new("/dev/shm"), None).unwrap().identity;
        let domain = StorageDomainId::of(stuck.key().unwrap());
        peer.register_domain(domain, &DomainCapabilities::inline(), NOW);
        host.register_domain(domain, &DomainCapabilities::inline(), NOW);
        let mut held = request(&peer);
        held.domain = Some(domain);
        let id = held.id;
        peer.try_admit(held, NOW).unwrap();
        peer.try_start(id, NOW).unwrap();
        std::thread::sleep(Duration::from_millis(1));
        let mut reservation = request(&host);
        reservation.domain = Some(domain);
        (root, peer, host, reservation, id)
    }

    #[test]
    fn shared_quarantine_retry_doubles_to_its_cap_and_resets_on_admission() {
        let (root, peer, host, reservation, held) = stuck_peer();
        let healthy = StorageDomainId::of(&DomainKey::declared(902));
        host.register_domain(healthy, &DomainCapabilities::inline(), NOW);
        let mut now = NOW;
        for delay_ms in [10, 20, 40, 80, 160, 320, 640, 1000, 1000] {
            assert_eq!(host.try_admit(reservation.clone(), now), Err(ThrottleCause::StuckWorker));
            let retry = now + Duration::from_millis(delay_ms);
            assert_eq!(host.coordination_retry_at(now), Some(retry), "delay={delay_ms}ms");
            if delay_ms == 10 {
                let anchor = hold_bookkeeping(&root);
                assert_eq!(
                    host.try_admit(reservation.clone(), now),
                    Err(ThrottleCause::StuckWorker),
                    "a backing-off domain is refused without a shared attempt"
                );
                flock(&anchor, FlockOperation::Unlock).unwrap();
                let mut other = request(&host);
                other.domain = Some(healthy);
                let id = other.id;
                host.try_admit(other, now).expect("another domain proceeds during the quarantine backoff");
                host.release(id, now);
                assert_eq!(host.coordination_retry_at(now), Some(retry));
            }
            now = retry;
        }
        peer.release(held, NOW);
        host.try_admit(reservation.clone(), now).unwrap();
        host.try_start(reservation.id, now).unwrap();
        assert_eq!(host.coordination_retry_at(now), None);
        host.release(reservation.id, now);
        assert_eq!(host.coordination_retry_at(now), None);
    }

    #[test]
    fn busy_shared_denial_keeps_the_quarantine_health_report_and_delay() {
        let (root, peer, host, reservation, held) = stuck_peer();
        let domain = reservation.domain.unwrap();
        let health = || {
            let mut health = BTreeMap::from([(domain, ResourceHealth::Nominal)]);
            host.domain_health_map(NOW, &BTreeSet::new(), &mut health);
            health[&domain].cause()
        };
        let mut now = NOW;
        for delay_ms in [10, 20, 40] {
            assert_eq!(host.try_admit(reservation.clone(), now), Err(ThrottleCause::StuckWorker));
            let retry = now + Duration::from_millis(delay_ms);
            assert_eq!(host.coordination_retry_at(now), Some(retry));
            now = retry;
        }
        assert_eq!(health(), Some(ThrottleCause::StuckWorker));
        let anchor = hold_bookkeeping(&root);
        assert_eq!(host.try_admit(reservation.clone(), now), Err(ThrottleCause::Coordination));
        assert_eq!(host.coordination_retry_at(now), Some(now + Duration::from_millis(3)));
        assert_eq!(health(), Some(ThrottleCause::StuckWorker));
        flock(&anchor, FlockOperation::Unlock).unwrap();
        now = now + Duration::from_millis(3);
        assert_eq!(host.try_admit(reservation.clone(), now), Err(ThrottleCause::StuckWorker));
        assert_eq!(host.coordination_retry_at(now), Some(now + Duration::from_millis(80)));
        peer.release(held, NOW);
    }
}

#[test]
fn shared_budget_backoff_does_not_block_the_other_origin() {
    use tree_fucker::coordination::authority::{Origin, Request};
    use tree_fucker::coordination::protocol::Work;
    use tree_fucker::{DomainCapabilities, StorageDomainId};

    for origin in [WorkOrigin::Background, WorkOrigin::Foreground] {
        let (_root, scope) = fixture();
        let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
        let holder = scope.join().unwrap();
        let domain = holder.register_private_domain(1).unwrap();
        let held = holder
            .prepare(Request {
                work: Work::Listing,
                origin: match origin {
                    WorkOrigin::Background => Origin::Background,
                    WorkOrigin::Foreground => Origin::Foreground,
                },
                domain: Some(domain),
                required: 1000,
                desired: 0,
                ceiling_ns: u64::MAX,
            })
            .unwrap();
        let local_domain = StorageDomainId::fresh();
        host.register_domain(local_domain, &DomainCapabilities::inline(), NOW);
        let denied = Reservation { origin, domain: Some(local_domain), ..request(&host) };
        assert_eq!(host.try_admit(denied.clone(), NOW), Err(ThrottleCause::Coordination));
        let cleanup = Reservation {
            id: GrantId::WatchRelease(host.next_tree(), tree_fucker::WatchReleaseId::new(1)),
            origin,
            domain: Some(local_domain),
            ..request(&host)
        };
        host.try_admit(cleanup.clone(), NOW).expect("cleanup is exempt from budget backoff");
        host.try_start(cleanup.id, NOW).unwrap();
        host.release(cleanup.id, NOW);
        let other = match origin {
            WorkOrigin::Background => WorkOrigin::Foreground,
            WorkOrigin::Foreground => WorkOrigin::Background,
        };
        let admitted = Reservation { origin: other, domain: Some(local_domain), ..request(&host) };
        host.try_admit(admitted.clone(), NOW).expect("one exhausted origin cannot withhold the other");
        host.try_start(admitted.id, NOW).unwrap();
        host.release(admitted.id, NOW);
        let attempts = scope.diagnostics().unwrap().access.attempts;
        assert_eq!(host.try_admit(denied.clone(), NOW), Err(ThrottleCause::Coordination));
        assert_eq!(
            scope.diagnostics().unwrap().access.attempts,
            attempts,
            "other-origin progress preserves the backoff"
        );
        drop(held);
        let retry = NOW + Duration::from_millis(10);
        host.try_admit(denied.clone(), retry).unwrap();
        host.try_start(denied.id, retry).unwrap();
        host.release(denied.id, retry);
        assert_eq!(host.coordination_retry_at(retry), None);
    }
}

#[test]
fn shared_domain_budget_backoff_does_not_block_another_domain() {
    use tree_fucker::{DomainCapabilities, StorageDomainId};

    for origin in [WorkOrigin::Background, WorkOrigin::Foreground] {
        let (root, original) = fixture();
        let mut config = original.diagnostics().unwrap().config;
        config.domain_background.burst_ns = 10_000_000;
        config.domain_foreground.burst_ns = 10_000_000;
        let scope = Scope::open(root.path().join("domain-budget"), config).unwrap();
        let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
        let a = StorageDomainId::fresh();
        let b = StorageDomainId::fresh();
        for domain in [a, b] {
            host.register_domain(domain, &DomainCapabilities::inline(), NOW);
        }
        let held = Reservation { origin, domain: Some(a), operations: 9, ..request(&host) };
        host.try_admit(held.clone(), NOW).unwrap();
        let denied = Reservation { origin, domain: Some(a), ..request(&host) };
        assert_eq!(host.try_admit(denied.clone(), NOW), Err(ThrottleCause::Coordination));
        let healthy = Reservation { origin, domain: Some(b), ..request(&host) };
        host.try_admit(healthy.clone(), NOW).expect("one domain's budget must not withhold another domain");
        host.try_start(healthy.id, NOW).unwrap();
        host.release(healthy.id, NOW);
        let attempts = scope.diagnostics().unwrap().access.attempts;
        assert_eq!(host.try_admit(denied.clone(), NOW), Err(ThrottleCause::Coordination));
        assert_eq!(scope.diagnostics().unwrap().access.attempts, attempts);
        host.release(held.id, NOW);
        let retry = NOW + Duration::from_millis(10);
        host.try_admit(denied.clone(), retry).unwrap();
        host.try_start(denied.id, retry).unwrap();
        host.release(denied.id, retry);
        assert_eq!(host.coordination_retry_at(retry), None);
    }
}

#[test]
fn shared_domain_capacity_backoff_does_not_block_another_domain() {
    use tree_fucker::{AccessTopology, DomainCapabilities, StorageDomainId};

    let (root, original) = fixture();
    let mut config = original.diagnostics().unwrap().config;
    config.ownership.physical = 2;
    let scope = Scope::open(root.path().join("domain-capacity"), config).unwrap();
    let host = HostGovernor::with_coordination(&host_config(), scope.clone()).unwrap();
    let a = StorageDomainId::fresh();
    let b = StorageDomainId::fresh();
    for domain in [a, b] {
        host.register_domain(
            domain,
            &DomainCapabilities { topology: AccessTopology::Local, ..DomainCapabilities::inline() },
            NOW,
        );
    }
    let held = Reservation { domain: Some(a), ..request(&host) };
    host.try_admit(held.clone(), NOW).unwrap();
    host.try_start(held.id, NOW).unwrap();
    let denied = Reservation { domain: Some(a), ..request(&host) };
    host.try_admit(denied.clone(), NOW).unwrap();
    assert_eq!(host.try_start(denied.id, NOW), Err(ThrottleCause::Coordination));
    let healthy = Reservation { domain: Some(b), ..request(&host) };
    host.try_admit(healthy.clone(), NOW).expect("one full domain cannot withhold another domain");
    host.try_start(healthy.id, NOW).unwrap();
    assert_eq!(scope.view().unwrap().physical, 2);
    host.release(healthy.id, NOW);
    let attempts = scope.diagnostics().unwrap().access.attempts;
    assert_eq!(host.try_start(denied.id, NOW), Err(ThrottleCause::Coordination));
    assert_eq!(scope.diagnostics().unwrap().access.attempts, attempts);
    let mut now = NOW;
    let mut retry = NOW;
    for delay in [3, 6, 10] {
        retry = now + Duration::from_millis(delay);
        assert_eq!(host.coordination_retry_at(now), Some(retry));
        if delay != 10 {
            now = retry;
            assert_eq!(host.try_start(denied.id, now), Err(ThrottleCause::Coordination));
        }
    }
    host.release(held.id, now);
    host.try_start(denied.id, retry).unwrap();
    host.release(denied.id, retry);
    assert_eq!(host.coordination_retry_at(retry), None);
}
