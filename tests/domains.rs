use std::sync::Arc;
use std::time::Duration;

use tree_fucker::core::{Command, JobOperation};
use tree_fucker::fs::FsCapabilities;
use tree_fucker::policy::{PolicyContext, ScanDecision, ScanPolicy};
use tree_fucker::testing::{CostScope, DomainId, FakeFileSystem, FakeOp, Harness};
use tree_fucker::update::{ResourceHealth, ThrottleCause, UpdateEvent};
use tree_fucker::{
    AccessTopology, Answer, CaseSensitivity, Config, DeclarationSource, DirectoryListing, DomainCapabilities,
    DomainCaseSensitivity, DomainCrossing, DomainIdentity, EntryInfo, FilesystemSemantics, IdentityReliability,
    LoadAll, LoadState, MediaHint, PolicyRevision, RelativePath, TransportHint, WatcherAvailability,
    WatcherCapabilities, WatcherKind, WatcherScope,
};

const MEDIA: DomainId = DomainId::new(2);
const BIND: DomainId = DomainId::new(3);
const SUBVOLUME: DomainId = DomainId::new(4);

fn path(p: &str) -> RelativePath {
    RelativePath::parse(p).expect("valid path")
}

fn mounted() -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("local");
    fs.create_file("local/f", 1);
    fs.mkdir("mnt");
    fs.mkdir("mnt/inner");
    fs.create_file("mnt/inner/deep", 1);
    fs.set_domain("mnt", MEDIA);
    fs
}

fn crossing(mode: DomainCrossing) -> Config {
    Config { domain_crossing: mode, ..Default::default() }
}

fn reads(fs: &FakeFileSystem, p: &str) -> usize {
    fs.count_ops(FakeOp::ReadDir, p)
}

#[test]
fn a_crossing_is_detected_before_the_child_is_first_listed_under_each_mode() {
    for (mode, expected) in [
        (DomainCrossing::Follow, LoadState::Loaded),
        (DomainCrossing::Exclude, LoadState::Excluded),
        (DomainCrossing::LoadOnDemand, LoadState::Unloaded),
    ] {
        let fs = mounted();
        let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), crossing(mode)).expect("open");
        h.run_until_idle();

        let recorded = h.stats().crossings;
        assert!(
            recorded.iter().any(|event| event.path == path("mnt") && event.mode == mode),
            "RFC 14.3 and 16: a domain crossing must be detected and reported under {mode}; the tree recorded \
             {recorded:?}"
        );
        assert_eq!(
            h.entry("mnt").and_then(|e| e.load_state()),
            Some(expected),
            "RFC 14.3: under {mode} the mount point must be represented as {expected:?}"
        );
        let listed = reads(&fs, "mnt");
        if mode == DomainCrossing::Follow {
            assert!(listed > 0, "RFC 14.3: Follow traverses the child domain like any other directory");
        } else {
            assert_eq!(
                listed, 0,
                "RFC 14.3: the crossing mode is applied before a directory whose domain differs from its \
                 parent's is first listed; under {mode} the mount point was listed {listed} times"
            );
        }
        assert!(reads(&fs, "local") > 0, "the crossing stopped traversal of the parent domain as well");
    }
}

#[test]
fn exclude_never_reads_beneath_the_mount_point() {
    let fs = mounted();
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), crossing(DomainCrossing::Exclude)).expect("open");
    h.run_until_idle();
    h.run_round();

    assert_eq!(
        (reads(&fs, "mnt"), reads(&fs, "mnt/inner")),
        (0, 0),
        "RFC 14.3: under Exclude the mount point's descendants are never read"
    );
    assert!(
        !h.paths().contains(&"mnt/inner".to_string()),
        "RFC 7.2 and 14.3: an Excluded directory has no represented descendants"
    );
    let t = h.command(Command::Load(path("mnt")));
    h.run_until_idle();
    assert_eq!(
        h.result(t),
        Some(Err(tree_fucker::Error::PolicyDenied)),
        "RFC 8 and 14.3: Excluded takes precedence over every explicit load request"
    );
}

#[test]
fn a_load_on_demand_mount_point_is_unloaded_and_listed_after_load() {
    let fs = mounted();
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();
    assert_eq!(h.entry("mnt").and_then(|e| e.load_state()), Some(LoadState::Unloaded));
    assert_eq!(reads(&fs, "mnt"), 0);

    let t = h.command(Command::Load(path("mnt")));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert!(
        h.paths().contains(&"mnt/inner/deep".to_string()),
        "RFC 14.3: under LoadOnDemand the mount point's descendants are read after an explicit load; the tree \
         holds {:?}",
        h.paths()
    );

    h.run_round();
    assert_eq!(
        h.entry("mnt").and_then(|e| e.load_state()),
        Some(LoadState::Loaded),
        "RFC 14.3: a later listing of the parent must not undo the explicit load of a mount point"
    );
}

#[test]
fn a_local_root_never_traverses_a_remote_mount_beneath_it_by_default() {
    let fs = mounted();
    fs.set_capabilities(MEDIA, DomainCapabilities { topology: AccessTopology::Remote, ..DomainCapabilities::inline() });
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();
    h.run_round();

    assert_eq!(
        (reads(&fs, "mnt"), reads(&fs, "mnt/inner")),
        (0, 0),
        "RFC 14.3: a tree rooted on a local filesystem MUST NOT traverse a network filesystem mounted beneath \
         the root unless the consumer asks for it"
    );
    assert_eq!(h.entry("mnt").and_then(|e| e.load_state()), Some(LoadState::Unloaded));
    assert!(h.paths().contains(&"local/f".to_string()), "the local subtree was traversed");
}

#[test]
fn a_domain_not_reported_inline_is_resolved_by_a_separate_governed_operation() {
    let fs = mounted();
    fs.report_inline_domains(false);
    fs.set_cost(CostScope::Everything, FakeOp::ResolveDomain, Duration::from_millis(3));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), crossing(DomainCrossing::Follow)).expect("open");
    h.run_until_idle();

    let ops = fs.ops();
    let resolutions = ops.iter().filter(|(op, _)| *op == FakeOp::ResolveDomain).count();
    assert!(
        resolutions > 0,
        "RFC 10.3: a directory whose domain enumeration does not report inline needs a separate resolution"
    );
    let resolved = ops.iter().position(|(op, target)| *op == FakeOp::ResolveDomain && *target == path("mnt"));
    let listed = ops.iter().position(|(op, target)| *op == FakeOp::ReadDir && *target == path("mnt"));
    assert!(
        resolved.is_some() && listed.is_some() && resolved < listed,
        "RFC 14.3: the domain of a candidate directory is resolved before that directory is first listed; the \
         adapter performed {ops:?}"
    );

    let grants: Vec<_> = h.admissions().into_iter().filter(|a| a.operation == JobOperation::DomainResolution).collect();
    assert!(
        grants.len() >= resolutions,
        "RFC 15.1 item 1: {resolutions} domain resolutions ran against {} governor grants",
        grants.len()
    );
    assert!(h.stats().domain_resolutions >= 1);
    assert!(
        h.stats().crossings.iter().any(|event| event.path == path("mnt")),
        "the separate resolution did not report the crossing it detected"
    );
    assert!(h.paths().contains(&"mnt/inner/deep".to_string()), "Follow did not traverse the resolved domain");
}

#[test]
fn a_candidate_domain_resolution_is_charged_to_the_bootstrap_scope_and_attributed_to_the_resolved_domain() {
    let fs = mounted();
    fs.report_inline_domains(false);
    fs.set_cost(CostScope::Everything, FakeOp::ResolveDomain, Duration::from_millis(3));
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(2));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), crossing(DomainCrossing::Follow)).expect("open");
    h.run_until_idle();

    let resolutions: Vec<_> =
        h.admissions().into_iter().filter(|a| a.operation == JobOperation::DomainResolution).collect();
    assert!(!resolutions.is_empty(), "no candidate domain was resolved, so the property was never tested");
    assert!(
        resolutions.iter().all(|a| a.domain.is_none()),
        "RFC 10.3: a domain resolution runs before the candidate's domain is known, so it is charged to the \
         bootstrap scope, never to a domain bucket; the tree admitted {resolutions:?}"
    );
    let view = h.governor();
    assert_eq!(
        view.bootstrap.charged,
        Duration::ZERO,
        "RFC 10.3: the bootstrap allowance is attributed to the resolved domain once it is known; it still holds {:?}",
        view.bootstrap
    );
    let media = h
        .stats()
        .domains
        .into_iter()
        .find(|d| d.identity == DomainIdentity::Known(FakeFileSystem::domain_key(MEDIA)))
        .expect("the resolved domain was entered");
    assert!(
        media.charged > Duration::ZERO,
        "RFC 10.3 and 15.3: the resolved domain must carry the worker time the bootstrap scope advanced for it; \
         {MEDIA} charged {:?}",
        media.charged
    );
}

#[test]
fn a_domain_resolution_that_never_returns_keeps_its_slot_while_other_domains_progress() {
    let fs = mounted();
    fs.mkdir("mnt2");
    fs.mkdir("mnt2/inner");
    fs.create_file("mnt2/inner/deep", 1);
    fs.set_domain("mnt2", DomainId::new(9));
    fs.report_inline_domains(false);
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(5));
    fs.set_cost(CostScope::Domain(MEDIA), FakeOp::ResolveDomain, Duration::from_secs(36_000));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), crossing(DomainCrossing::Follow)).expect("open");
    h.run_jobs_until(h.now() + Duration::from_secs(600));

    let slots = h.stats().blocking_slots;
    assert!(
        slots.iter().any(|slot| slot.path == path("mnt") && slot.operation == JobOperation::DomainResolution),
        "RFC 10.3 and 13.5: topology discovery must not casually turn into an indefinite operation, and a stuck \
         resolution retains its physical slot until its call returns; the tree holds {slots:?}"
    );
    assert!(
        h.paths().contains(&"local/f".to_string()),
        "RFC 17.5: a stuck domain resolution must not stall the domains that are healthy; the tree holds {:?}",
        h.paths()
    );
    assert!(
        h.paths().contains(&"mnt2/inner/deep".to_string()),
        "RFC 10.3 and 13.5: the bootstrap scope is not quarantined by one stuck resolution, so a second mount \
         point resolves and lists while the first is stuck; the tree holds {:?}",
        h.paths()
    );
    assert!(
        !h.paths().contains(&"mnt/inner".to_string()),
        "the mount point whose domain never resolved must not be traversed on a guess; the tree holds {:?}",
        h.paths()
    );
}

#[test]
fn enumeration_reporting_a_child_domain_inline_runs_no_separate_resolution() {
    let fs = mounted();
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), crossing(DomainCrossing::Follow)).expect("open");
    h.run_until_idle();

    assert_eq!(
        fs.ops().iter().filter(|(op, _)| *op == FakeOp::ResolveDomain).count(),
        0,
        "RFC 10.3: enumeration MAY report a child's domain inline, in which case no separate resolution is needed"
    );
    assert_eq!(h.stats().domain_resolutions, 0);
    assert!(
        h.stats().crossings.iter().any(|event| event.path == path("mnt")),
        "the inline domain report did not produce a crossing decision"
    );
}

#[test]
fn bootstrap_cost_is_attributed_to_the_resolved_domain() {
    let fs = mounted();
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), crossing(DomainCrossing::Follow)).expect("open");

    let opening = h.governor();
    assert!(
        opening.bootstrap.granted > Duration::ZERO,
        "RFC 10.3: operations performed before a domain is known are charged to a bootstrap scope; the governor \
         reports {:?}",
        opening.bootstrap
    );

    h.run_until_idle();
    let view = h.governor();
    assert_eq!(
        view.bootstrap.charged,
        Duration::ZERO,
        "RFC 10.3: the bootstrap scope is attributed to the resolved domain once it is known; it still holds \
         {:?}",
        view.bootstrap
    );
    let charged: Duration = view.domains.values().map(|account| account.charged).sum();
    assert!(
        charged >= opening.bootstrap.granted,
        "RFC 10.3 and 15.3: the bootstrap allowance must land on a domain; the domains carry {charged:?} \
         against a bootstrap grant of {:?}",
        opening.bootstrap.granted
    );
}

#[test]
fn statistics_list_every_domain_entered_with_its_capabilities_and_declaration_source() {
    let fs = mounted();
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(5));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), crossing(DomainCrossing::Follow)).expect("open");
    h.run_until_idle();

    let domains = h.stats().domains;
    for domain in [DomainId::ROOT, MEDIA] {
        let key = FakeFileSystem::domain_key(domain);
        let entered = domains
            .iter()
            .find(|entered| entered.identity == DomainIdentity::Known(key.clone()))
            .unwrap_or_else(|| panic!("RFC 16: the statistics must list every storage domain the tree entered"));
        assert_eq!(
            entered.capabilities.sources.observation,
            DeclarationSource::Declared,
            "RFC 16: each domain is listed with the source of each declaration"
        );
        assert!(
            entered.charged > Duration::ZERO && entered.granted > Duration::ZERO,
            "RFC 16: per-domain worker time consumed and granted must be observable; {domain} reports granted \
             {:?} and charged {:?}",
            entered.granted,
            entered.charged
        );
    }
    assert!(
        h.stats().crossings.iter().any(|event| event.path == path("mnt") && event.parent != Some(event.child)),
        "RFC 16: domain-crossing decisions must be observable"
    );
}

#[test]
fn a_delta_installing_a_mount_point_carries_the_crossing_as_its_cause() {
    let fs = mounted();
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();

    let carried = h.events().iter().any(|event| match event {
        UpdateEvent::Delta(update) => {
            update.crossings.iter().any(|c| c.path == path("mnt") && c.mode == DomainCrossing::LoadOnDemand)
                && update.changes.iter().any(|change| *change.path() == path("mnt"))
        }
        _ => false,
    });
    assert!(
        carried,
        "RFC 14.3: a delta that installs a mount point as Excluded or Unloaded carries the crossing as its cause"
    );
}

struct FollowNamed(&'static str);

impl ScanPolicy for FollowNamed {
    fn revision(&self) -> PolicyRevision {
        PolicyRevision::new(0)
    }

    fn root_context(&self, _root: &EntryInfo) -> PolicyContext {
        PolicyContext::unit()
    }

    fn classify(&self, _parent: &PolicyContext, _path: &RelativePath, _info: &EntryInfo) -> ScanDecision {
        ScanDecision::Eligible { initially_loaded: true }
    }

    fn child_context(
        &self,
        parent: &PolicyContext,
        _path: &RelativePath,
        _listing: &DirectoryListing,
    ) -> PolicyContext {
        parent.clone()
    }

    fn crossing(
        &self,
        _parent: &PolicyContext,
        path: &RelativePath,
        child: &DomainCapabilities,
        configured: DomainCrossing,
    ) -> DomainCrossing {
        if path.to_string() == self.0 && child.topology == AccessTopology::Local {
            DomainCrossing::Follow
        } else {
            configured
        }
    }
}

#[test]
fn policy_refines_the_crossing_mode_per_crossing_from_the_child_domain_capabilities() {
    let fs = mounted();
    fs.mkdir("other");
    fs.create_file("other/f", 1);
    fs.set_domain("other", BIND);
    fs.set_capabilities(MEDIA, DomainCapabilities { topology: AccessTopology::Local, ..DomainCapabilities::inline() });
    fs.set_capabilities(BIND, DomainCapabilities { topology: AccessTopology::Remote, ..DomainCapabilities::inline() });
    let mut h = Harness::open(fs.clone(), Arc::new(FollowNamed("mnt")), Config::default()).expect("open");
    h.run_until_idle();

    assert_eq!(
        h.entry("mnt").and_then(|e| e.load_state()),
        Some(LoadState::Loaded),
        "RFC 14.3: policy receives the child domain's capabilities and MAY refine the mode per crossing"
    );
    assert_eq!(
        h.entry("other").and_then(|e| e.load_state()),
        Some(LoadState::Unloaded),
        "RFC 14.3: a crossing the policy does not refine keeps the configured mode"
    );
}

fn case_insensitive(space: u64) -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::with_capabilities(FsCapabilities {
        case: CaseSensitivity::Insensitive,
        watcher: WatcherKind::None,
    }));
    fs.set_identity_space(DomainId::ROOT, 0);
    fs.set_identity_space(BIND, 0);
    fs.set_identity_space(SUBVOLUME, space);
    fs.mkdir("Docs");
    fs.create_file("Docs/Readme.MD", 1);
    fs
}

fn rename_under_domain(domain: DomainId) -> (Option<tree_fucker::EntryId>, Option<tree_fucker::EntryId>) {
    let fs = case_insensitive(1);
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), crossing(DomainCrossing::Follow)).expect("open");
    h.run_until_idle();
    let before = h.entry("Docs/Readme.MD").map(|e| e.id);

    fs.remount("Docs", domain);
    fs.rename("Docs/Readme.MD", "Docs/README.md");
    let t = h.command(Command::Refresh(vec![path("Docs")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    (before, h.entry("Docs/README.md").map(|e| e.id))
}

#[test]
fn identities_from_different_identity_spaces_never_match_while_a_bind_mounts_do() {
    let (before, after) = rename_under_domain(BIND);
    assert!(before.is_some() && after.is_some());
    assert_eq!(
        before, after,
        "RFC 7.1 and 14.3: a bind mount and its origin share one identity space, so identities observed across \
         them remain comparable and the rename preserves the EntryId"
    );

    let (before, after) = rename_under_domain(SUBVOLUME);
    assert!(before.is_some() && after.is_some());
    assert_ne!(
        before, after,
        "RFC 7.1: identity comparisons are meaningful only between entries whose storage domains declare the \
         same identity space, so an identity from another space must never establish a rename"
    );
}

#[test]
fn an_advisory_identity_is_published_but_never_establishes_a_rename() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.set_capabilities(
        DomainId::ROOT,
        DomainCapabilities { identity_reliability: IdentityReliability::Advisory, ..DomainCapabilities::inline() },
    );
    fs.mkdir("dir");
    fs.create_file("dir/old", 1);
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();
    let before = h.entry("dir/old").expect("old entry");
    let advisory = before.identity.expect("the advisory identity is published as metadata");

    fs.rename("dir/old", "dir/new");
    let t = h.command(Command::Refresh(vec![path("dir")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    let after = h.entry("dir/new").expect("the moved child is represented under its new name");
    assert_eq!(after.identity, Some(advisory), "the advisory identity is still published on the replacement");
    assert_ne!(
        after.id, before.id,
        "RFC 7.1: an identity from a domain whose reliability is advisory MAY be published as metadata but MUST \
         NOT establish a rename, even when the observed identity is unchanged, so the move is a remove and an add"
    );
    assert!(h.entry("dir/old").is_none(), "the old name is gone");
}

#[test]
fn an_unmount_beneath_the_root_clears_the_crossing_and_the_mount_point_loads_again() {
    let fs = mounted();
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();
    assert_eq!(h.entry("mnt").and_then(|e| e.load_state()), Some(LoadState::Unloaded));

    fs.remount("mnt", DomainId::ROOT);
    for _ in 0..4 {
        h.run_round();
        h.run_until_idle();
    }

    assert_eq!(
        h.entry("mnt").and_then(|e| e.load_state()),
        Some(LoadState::Loaded),
        "RFC 14.3: crossing policy applies to a domain crossing, so a directory that no longer belongs to \
         another domain is an ordinary directory again"
    );
    assert!(h.paths().contains(&"mnt/inner/deep".to_string()));
}

#[test]
fn a_watch_registration_is_charged_to_the_domain_of_the_directory_it_watches() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    fs.mkdir("local");
    fs.create_file("local/f", 1);
    fs.mkdir("mnt");
    fs.mkdir("mnt/inner");
    fs.create_file("mnt/inner/deep", 1);
    fs.set_domain("mnt", MEDIA);
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), crossing(DomainCrossing::Follow)).expect("open");
    h.run_until_idle();
    fs.emit_watcher_failure("boom");
    h.advance(Duration::from_secs(60));

    assert!(
        fs.count_ops(FakeOp::Watch, "mnt") >= 2 && fs.count_ops(FakeOp::Watch, "mnt/inner") >= 2,
        "the watcher never restarted, so no standalone registration was admitted"
    );
    let view = h.governor();
    assert_eq!(
        view.bootstrap.grants, 0,
        "RFC 10.3 and 15.1 item 1: a watch registration runs against the domain of the directory it watches, so \
         no registration grant may be stranded in the bootstrap scope; it holds {:?}",
        view.bootstrap
    );

    let listings = u64::try_from(reads(&fs, "mnt") + reads(&fs, "mnt/inner")).unwrap_or(u64::MAX);
    let stats = h.stats();
    let media = stats
        .domains
        .iter()
        .find(|domain| domain.identity == DomainIdentity::Known(FakeFileSystem::domain_key(MEDIA)))
        .unwrap_or_else(|| panic!("the child domain was never entered"));
    let grants = view.domains.get(&media.id).map(|account| account.grants).unwrap_or_default();
    assert!(
        grants > listings,
        "RFC 11.4 and 15.1 item 1: the child domain performed {listings} listings and at least two standalone \
         watch registrations, so it must carry more than {listings} grants; it carries {grants}"
    );
}

fn two_unidentified_mounts() -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    for dir in ["near", "near/inner", "far", "far/inner"] {
        fs.mkdir(dir);
        fs.create_file(&format!("{dir}/f"), 1);
    }
    fs.set_domain("near", MEDIA);
    fs.set_domain("far", BIND);
    fs.report_unknown_domain_identity(MEDIA);
    fs.report_unknown_domain_identity(BIND);
    fs.set_capabilities(MEDIA, DomainCapabilities { topology: AccessTopology::Local, ..DomainCapabilities::inline() });
    fs.set_capabilities(BIND, DomainCapabilities { media: MediaHint::Rotational, ..DomainCapabilities::inline() });
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    fs
}

#[test]
fn two_mounts_without_identity_are_two_storage_domains() {
    let fs = two_unidentified_mounts();
    fs.set_cost(CostScope::path("near/inner"), FakeOp::ReadDir, Duration::from_secs(36_000));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), crossing(DomainCrossing::Follow)).expect("open");
    h.run_until_idle();

    let unknown: Vec<_> =
        h.stats().domains.into_iter().filter(|domain| domain.identity == DomainIdentity::Unknown).collect();
    assert_eq!(
        unknown.len(),
        2,
        "RFC 2 and 15.9: Unknown means the identity is unavailable, so two unidentified mounts are two storage \
         domains; the tree entered {unknown:?}"
    );
    let near = unknown
        .iter()
        .find(|domain| domain.entry_path == Some(path("near")))
        .unwrap_or_else(|| panic!("the near mount was never entered; the tree holds {unknown:?}"));
    let far = unknown
        .iter()
        .find(|domain| domain.entry_path == Some(path("far")))
        .unwrap_or_else(|| panic!("the far mount was never entered; the tree holds {unknown:?}"));
    assert_ne!(near.id, far.id, "two mounts without identity must not collapse onto one domain id");

    h.run_jobs_until(h.now() + Duration::from_secs(120));
    let health = h.health().resource_domains;
    assert_eq!(
        health.get(&near.id).copied(),
        Some(ResourceHealth::Throttled { cause: ThrottleCause::StuckWorker, resume: None }),
        "the near mount never went stuck, so the quarantine is untested; it reports {health:?}"
    );
    assert!(
        health.get(&far.id).copied().is_some_and(|health| health.cause() != Some(ThrottleCause::StuckWorker)),
        "RFC 13.5: one stuck worker quarantines its storage domain and no other; the tree reports {health:?}"
    );
    assert!(
        h.paths().contains(&"far/inner/f".to_string()),
        "the second unidentified mount stopped being read; the tree holds {:?}",
        h.paths()
    );
    let after: Vec<_> =
        h.stats().domains.into_iter().filter(|domain| domain.identity == DomainIdentity::Unknown).collect();
    assert_eq!(
        after.len(),
        2,
        "RFC 15.7: coordinator state per represented entry is bounded, so relisting an unidentified mount binds the \
         domain it already holds instead of minting another; the tree entered {after:?}"
    );
}

#[test]
fn each_unidentified_mount_gets_its_own_crossing_decision() {
    let fs = two_unidentified_mounts();
    let mut h = Harness::open(fs.clone(), Arc::new(FollowNamed("near")), Config::default()).expect("open");
    h.run_until_idle();

    assert_eq!(
        h.entry("near").and_then(|e| e.load_state()),
        Some(LoadState::Loaded),
        "RFC 14.3: policy receives the child domain's own capabilities and refines the mode per crossing"
    );
    assert_eq!(
        h.entry("far").and_then(|e| e.load_state()),
        Some(LoadState::Unloaded),
        "RFC 14.3: the second unidentified mount's own declared capabilities decide its crossing separately"
    );

    let unknown: Vec<_> =
        h.stats().domains.into_iter().filter(|domain| domain.identity == DomainIdentity::Unknown).collect();
    assert_eq!(
        unknown.len(),
        2,
        "RFC 2: each mount is its own storage domain, whichever crossing decision it received; the tree entered \
         {unknown:?}"
    );
    let followed = unknown
        .iter()
        .find(|domain| domain.entry_path == Some(path("near")))
        .unwrap_or_else(|| panic!("the followed mount was never entered; the tree holds {unknown:?}"));
    let held = unknown
        .iter()
        .find(|domain| domain.entry_path == Some(path("far")))
        .unwrap_or_else(|| panic!("the unloaded mount was never entered; the tree holds {unknown:?}"));
    assert_ne!(
        followed.id, held.id,
        "RFC 14.3: crossing policy operates on the mount instance, so a followed mount and an unloaded one are two \
         domains"
    );
}

#[test]
fn an_unidentified_mount_keeps_the_capabilities_it_declares() {
    let watcher = WatcherCapabilities {
        availability: WatcherAvailability::Available,
        scope: WatcherScope::PerDirectory,
        observes_external_writers: Answer::No,
        can_lose_events: Answer::Yes,
        signals_overflow: Answer::No,
        registration_gaps: Answer::Yes,
        polling_fallback_required: Answer::Yes,
    };
    let declared = DomainCapabilities {
        semantics: FilesystemSemantics::Smb,
        transport: TransportHint::Network,
        watcher,
        ..DomainCapabilities::inline()
    };
    let fs = mounted();
    fs.set_capabilities(MEDIA, declared.clone());
    fs.report_unknown_domain_identity(MEDIA);
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), crossing(DomainCrossing::Follow)).expect("open");
    h.run_until_idle();

    let stats = h.stats();
    let media = stats
        .domains
        .iter()
        .find(|domain| domain.identity == DomainIdentity::Unknown)
        .unwrap_or_else(|| panic!("the unidentified mount was never entered; the tree holds {:?}", stats.domains));
    assert_eq!(
        (media.capabilities.semantics.clone(), media.capabilities.transport),
        (FilesystemSemantics::Smb, TransportHint::Network),
        "RFC 10.3: capabilities are declared per storage domain, and an unavailable identity establishes nothing \
         about them; the domain reports {:?}",
        media.capabilities
    );
    assert_eq!(
        media.capabilities.watcher, watcher,
        "RFC 10.4: the watcher capabilities the adapter declared for the mount survive an unknown identity"
    );
    assert_eq!(
        media.watcher.registration_gaps,
        Answer::Yes,
        "RFC 10.4: a watcher with known registration gaps is reported as one; the domain reports {:?}",
        media.watcher
    );
}

fn cased(case: DomainCaseSensitivity) -> DomainCapabilities {
    DomainCapabilities { case, ..DomainCapabilities::inline() }
}

#[test]
fn a_case_insensitive_child_domain_folds_only_its_own_names() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.set_capabilities(DomainId::ROOT, cased(DomainCaseSensitivity::Sensitive));
    fs.set_capabilities(MEDIA, cased(DomainCaseSensitivity::Insensitive));
    fs.mkdir("top");
    fs.create_file("top/README.md", 1);
    fs.create_file("top/readme.md", 2);
    fs.mkdir("mnt");
    fs.create_file("mnt/README.md", 3);
    fs.create_file("mnt/readme.md", 4);
    fs.set_domain("mnt", MEDIA);
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), crossing(DomainCrossing::Follow)).expect("open");
    h.run_until_idle();

    let paths = h.paths();
    assert!(
        paths.contains(&"top/README.md".to_string()) && paths.contains(&"top/readme.md".to_string()),
        "RFC 10.3 and 14.1: a case-insensitive mount folds its own names and nothing else, so the case-sensitive \
         parent domain must keep both casings distinct; the tree holds {paths:?}"
    );
    assert_ne!(
        h.entry("top/README.md").map(|e| e.id),
        h.entry("top/readme.md").map(|e| e.id),
        "RFC 14.1: case comparison follows the configured semantics of the domain the containing directory belongs to"
    );

    let folded: Vec<&String> = paths.iter().filter(|p| p.starts_with("mnt/")).collect();
    assert_eq!(
        folded.len(),
        1,
        "RFC 10.3 and 14.1: beneath a case-insensitive mount the two casings are one child; the tree holds {folded:?}"
    );
    assert_eq!(
        h.entry("mnt/readme.md").map(|e| e.id),
        h.entry("mnt/README.MD").map(|e| e.id),
        "RFC 14.1: a lookup beneath the case-insensitive mount folds, whatever casing it is written in"
    );
    assert!(h.entry("mnt/readme.md").is_some());
}

#[test]
fn a_remount_that_changes_case_sensitivity_rekeys_the_subtree_without_losing_entries() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.set_capabilities(DomainId::ROOT, cased(DomainCaseSensitivity::Sensitive));
    fs.set_capabilities(MEDIA, cased(DomainCaseSensitivity::Sensitive));
    fs.set_capabilities(BIND, cased(DomainCaseSensitivity::Insensitive));
    fs.set_identity_space(MEDIA, 0);
    fs.set_identity_space(BIND, 0);
    fs.mkdir("mnt");
    fs.mkdir("mnt/Inner");
    fs.create_file("mnt/Inner/Leaf", 1);
    fs.create_file("mnt/Alpha", 2);
    fs.mkdir("mnt/alpha");
    fs.create_file("mnt/alpha/buried", 3);
    fs.set_domain("mnt", MEDIA);
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), crossing(DomainCrossing::Follow)).expect("open");
    h.run_until_idle();

    let before = h.paths();
    assert!(
        before.contains(&"mnt/Inner/Leaf".to_string())
            && before.contains(&"mnt/Alpha".to_string())
            && before.contains(&"mnt/alpha/buried".to_string()),
        "the sensitive mount lost a casing it was configured to keep; it holds {before:?}"
    );
    assert_ne!(
        h.entry("mnt/alpha").map(|e| e.id),
        h.entry("mnt/Alpha").map(|e| e.id),
        "the sensitive mount folded a lookup it was not configured to fold"
    );
    assert_eq!(h.snapshot().child_case(&path("mnt")), CaseSensitivity::Sensitive);
    let leaf = h.entry("mnt/Inner/Leaf").map(|e| e.id);

    fs.remount("mnt", BIND);
    for _ in 0..4 {
        h.run_round();
        h.run_until_idle();
    }

    assert_eq!(
        h.snapshot().child_case(&path("mnt")),
        CaseSensitivity::Insensitive,
        "RFC 10.3: a child name is keyed under the case sensitivity of the domain its containing directory \
         belongs to"
    );
    let after = h.paths();
    assert!(
        after.contains(&"mnt/Inner/Leaf".to_string()),
        "the re-key dropped a descendant that did not collide; the tree holds {after:?}"
    );
    assert_eq!(
        h.entry("mnt/alpha").map(|e| (e.path.to_string(), e.kind())),
        Some(("mnt/Alpha".to_string(), tree_fucker::EntryKind::File)),
        "RFC 11.5: the survivor of a re-key collision is the one the next listing would also keep, which the \
         collision order decides by name before kind; the tree holds {after:?}"
    );
    assert!(
        !after.contains(&"mnt/alpha/buried".to_string()),
        "a descendant of the entry the collision dropped survived without its parent; the tree holds {after:?}"
    );

    h.take_events();
    h.run_round();
    h.run_until_idle();
    let settled: Vec<tree_fucker::PathChange> = h
        .events()
        .iter()
        .filter_map(|event| match event {
            UpdateEvent::Delta(update) => Some(update.changes.clone()),
            _ => None,
        })
        .flatten()
        .filter(|change| change.path().starts_with(&path("mnt")))
        .collect();
    assert_eq!(
        settled,
        Vec::new(),
        "RFC 11.5: the re-key survivor must be the entry the next listing keeps, so a further round publishes \
         no change beneath the remounted directory"
    );
    assert_eq!(
        h.entry("mnt/inner/leaf").map(|e| e.id),
        leaf,
        "RFC 14.1: after the remount the subtree is keyed under the new domain's case semantics"
    );
    assert_eq!(
        h.entry("mnt/ALPHA").map(|e| e.id),
        h.entry("mnt/alpha").map(|e| e.id),
        "RFC 10.3: the re-keyed subtree folds under the remounted domain"
    );
    assert!(h.entry("mnt/alpha").is_some(), "the colliding casings folded away to nothing");
}

fn inconclusive_mount(child: DomainCapabilities) -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.set_capabilities(
        DomainId::ROOT,
        DomainCapabilities { topology: AccessTopology::Local, ..DomainCapabilities::inline() },
    );
    fs.set_capabilities(MEDIA, child);
    fs.report_unknown_domain_identity(MEDIA);
    fs.report_not_domain_root(MEDIA);
    fs.mkdir("local");
    fs.create_file("local/f", 1);
    fs.mkdir("mnt");
    fs.mkdir("mnt/inner");
    fs.create_file("mnt/inner/deep", 1);
    fs.set_domain("mnt", MEDIA);
    fs
}

#[test]
fn an_inconclusive_crossing_into_foreign_storage_is_not_traversed_by_default() {
    let fs =
        inconclusive_mount(DomainCapabilities { topology: AccessTopology::Remote, ..DomainCapabilities::inline() });
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();
    h.run_round();

    assert_eq!(
        (reads(&fs, "mnt"), reads(&fs, "mnt/inner")),
        (0, 0),
        "RFC 14.3: a tree rooted on a local filesystem MUST NOT traverse a network filesystem mounted beneath the \
         root unless the consumer asks for it, and an adapter that cannot prove the boundary does not make it a \
         consumer request"
    );
    assert_eq!(
        h.entry("mnt").and_then(|e| e.load_state()),
        Some(LoadState::Unloaded),
        "RFC 14.3: the default crossing mode represents the mount point as Unloaded"
    );
    assert!(
        h.stats().crossings.iter().any(|event| event.path == path("mnt") && event.mode == DomainCrossing::LoadOnDemand),
        "RFC 16: the crossing decision taken on an inconclusive boundary must be observable; the tree recorded {:?}",
        h.stats().crossings
    );
    assert!(h.paths().contains(&"local/f".to_string()), "the parent domain was traversed");
}

#[test]
fn an_inconclusive_boundary_with_the_parents_capabilities_is_the_same_domain() {
    let fs = inconclusive_mount(DomainCapabilities { topology: AccessTopology::Local, ..DomainCapabilities::inline() });
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();

    assert_eq!(
        h.entry("mnt").and_then(|e| e.load_state()),
        Some(LoadState::Loaded),
        "RFC 14.3: an inconclusive boundary whose declared capabilities match the parent's is the same storage, \
         so no crossing decision applies to it"
    );
    assert!(
        h.paths().contains(&"mnt/inner/deep".to_string()),
        "the subtree beneath an unproven, indistinguishable boundary was not traversed; the tree holds {:?}",
        h.paths()
    );
    assert!(
        !h.stats().crossings.iter().any(|event| event.path == path("mnt")),
        "RFC 14.3: only a crossing may be recorded as one; the tree recorded {:?}",
        h.stats().crossings
    );
}

#[test]
fn a_priority_path_survives_a_case_change_on_a_containing_directory() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.set_capabilities(DomainId::ROOT, cased(DomainCaseSensitivity::Sensitive));
    fs.set_capabilities(MEDIA, cased(DomainCaseSensitivity::Sensitive));
    fs.set_capabilities(BIND, cased(DomainCaseSensitivity::Insensitive));
    fs.set_identity_space(MEDIA, 0);
    fs.set_identity_space(BIND, 0);
    fs.mkdir("mnt");
    let watched: Vec<RelativePath> = (0..3)
        .map(|i| {
            fs.mkdir(&format!("mnt/W{i}"));
            fs.create_file(&format!("mnt/W{i}/f"), 1);
            path(&format!("mnt/W{i}"))
        })
        .collect();
    fs.mkdir("mnt/Plain");
    fs.create_file("mnt/Plain/f", 1);
    fs.set_domain("mnt", MEDIA);
    let config = Config { batch_size: 2, ..crossing(DomainCrossing::Follow) };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();

    let t = h.command(Command::SetPriority(watched));
    assert_eq!(h.result(t), Some(Ok(())));
    for _ in 0..2 {
        h.run_round();
    }
    assert!(
        fs.count_ops(FakeOp::ReadDir, "mnt/W0") > fs.count_ops(FakeOp::ReadDir, "mnt/Plain"),
        "the priority set was never serviced before the remount, so this test measures nothing"
    );

    fs.remount("mnt", BIND);
    for _ in 0..4 {
        h.run_round();
        h.run_until_idle();
    }
    assert_eq!(
        h.snapshot().child_case(&path("mnt")),
        CaseSensitivity::Insensitive,
        "the remount did not change the case sensitivity this test depends on"
    );

    let before = (fs.count_ops(FakeOp::ReadDir, "mnt/W0"), fs.count_ops(FakeOp::ReadDir, "mnt/Plain"));
    for _ in 0..2 {
        h.run_round();
    }
    let watched = fs.count_ops(FakeOp::ReadDir, "mnt/W0") - before.0;
    let plain = fs.count_ops(FakeOp::ReadDir, "mnt/Plain") - before.1;
    assert!(
        watched > plain,
        "RFC 11.3 and 14.1: a stored priority path must keep matching its directory after a case change on a \
         containing directory re-keys it; across two rounds after the remount the priority directory was listed \
         {watched} times against the sibling's {plain}"
    );
    assert_eq!(h.stats().priority_cursor.1, 3, "the priority set lost a path");
}

fn wide_listing_folds(children: usize) -> (u64, usize) {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("wide");
    for i in 0..children {
        fs.create_file(&format!("wide/f{i}"), 1);
    }
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();
    let before = h.stats().path_folds;
    let t = h.command(Command::Refresh(vec![path("wide")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    (
        h.stats().path_folds - before,
        h.snapshot().entries().filter(|e| e.path.starts_with(&path("wide")) && !e.path.is_root()).count() - 1,
    )
}

#[test]
fn relisting_a_directory_folds_its_own_path_and_never_one_path_per_child() {
    let (narrow, narrow_children) = wide_listing_folds(20);
    let (wide, wide_children) = wide_listing_folds(400);
    assert_eq!((narrow_children, wide_children), (20, 400), "the fixture did not represent every child");
    assert_eq!(
        narrow, wide,
        "a listing must derive every child key from the containing directory's single fold, so its cost in \
         path folds cannot grow with the child count; twenty children cost {narrow} folds and four hundred \
         cost {wide}"
    );
    assert!(wide < 16, "a listing that changes nothing must fold a handful of paths, not {wide}");
}

#[test]
fn per_domain_watch_accounting_matches_a_recomputed_scan() {
    let fs = Arc::new(FakeFileSystem::new(tree_fucker::WatcherKind::NonRecursive));
    fs.mkdir("local");
    fs.mkdir("local/inner");
    fs.mkdir("mnt");
    for i in 0..6 {
        fs.mkdir(&format!("mnt/d{i}"));
        fs.create_file(&format!("mnt/d{i}/f"), 1);
    }
    fs.set_domain("mnt", MEDIA);
    let config = Config { watcher_path_limit: 5, ..crossing(DomainCrossing::Follow) };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();

    let stats = h.stats();
    let watched: usize = stats.domains.iter().map(|domain| domain.paths_watched).sum();
    let capped: usize = stats.domains.iter().map(|domain| domain.paths_unwatched_by_cap).sum();
    assert_eq!(
        (watched, capped),
        (stats.paths_watched, stats.paths_unwatched_by_cap),
        "the per-domain watch accounts must sum to the tree's; the tree reports {stats:?}"
    );
    assert_eq!(stats.paths_watched, 5, "the cap did not bind, so the accounting was not exercised");
    assert!(stats.paths_unwatched_by_cap > 0, "nothing was turned away, so the capped account was not exercised");
    assert_eq!(
        stats.loaded_directories,
        h.snapshot().loaded_directories().count(),
        "RFC 16: the maintained loaded-directory count must equal a scan of the snapshot"
    );

    fs.remount("mnt", BIND);
    for _ in 0..4 {
        h.run_round();
        h.run_until_idle();
    }
    let stats = h.stats();
    let watched: usize = stats.domains.iter().map(|domain| domain.paths_watched).sum();
    assert_eq!(
        watched, stats.paths_watched,
        "a directory that changes storage domain must carry its watch account with it; the tree reports {:?}",
        stats.domains
    );
    assert_eq!(stats.loaded_directories, h.snapshot().loaded_directories().count());
}
