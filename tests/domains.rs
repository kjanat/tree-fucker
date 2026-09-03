use std::sync::Arc;
use std::time::Duration;

use tree_fucker::core::{Command, JobOperation};
use tree_fucker::fs::FsCapabilities;
use tree_fucker::policy::{PolicyContext, ScanDecision, ScanPolicy};
use tree_fucker::testing::{CostScope, DomainId, FakeFileSystem, FakeOp, Harness};
use tree_fucker::update::UpdateEvent;
use tree_fucker::{
    AccessTopology, CaseSensitivity, Config, DeclarationSource, DirectoryListing, DomainCapabilities, DomainCrossing,
    DomainIdentity, EntryInfo, LoadAll, LoadState, PolicyRevision, RelativePath, WatcherKind,
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

#[test]
fn two_domains_of_unknown_identity_share_one_record_that_declares_nothing() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("near");
    fs.create_file("near/f", 1);
    fs.mkdir("far");
    fs.create_file("far/f", 1);
    fs.set_domain("near", MEDIA);
    fs.set_domain("far", BIND);
    fs.report_unknown_domain_identity(MEDIA);
    fs.report_unknown_domain_identity(BIND);
    fs.set_capabilities(MEDIA, DomainCapabilities { topology: AccessTopology::Local, ..DomainCapabilities::inline() });
    fs.set_capabilities(BIND, DomainCapabilities { topology: AccessTopology::Remote, ..DomainCapabilities::inline() });
    let mut h = Harness::open(fs.clone(), Arc::new(FollowNamed("near")), Config::default()).expect("open");
    h.run_until_idle();

    let unknown: Vec<_> =
        h.stats().domains.into_iter().filter(|domain| domain.identity == DomainIdentity::Unknown).collect();
    assert_eq!(
        unknown.len(),
        1,
        "RFC 15.9: a domain whose identity is Unknown is accounted as its own domain per tree; the tree entered \
         {unknown:?}"
    );
    assert_eq!(
        unknown[0].capabilities,
        DomainCapabilities::default(),
        "RFC 10.3: Unknown is the required value for anything the adapter cannot establish, so one record shared \
         by several unidentified mounts declares nothing about either"
    );

    assert_eq!(
        h.entry("near").and_then(|e| e.load_state()),
        Some(LoadState::Loaded),
        "RFC 14.3: the crossing decision uses the child domain's own declared capabilities, not the shared record"
    );
    assert_eq!(
        h.entry("far").and_then(|e| e.load_state()),
        Some(LoadState::Unloaded),
        "RFC 14.3: the second unidentified mount's own declared capabilities decide its crossing separately"
    );
}
