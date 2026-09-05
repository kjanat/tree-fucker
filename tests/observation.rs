use std::sync::Arc;
use std::time::Duration;

use tree_fucker::core::{Command, JobOperation};
use tree_fucker::testing::DomainId;
use tree_fucker::testing::{CostScope, FailureMode, FakeFileSystem, FakeOp, Harness};
use tree_fucker::update::{ErrorCause, ResourceLimit, RoundResult, UpdateEvent};
use tree_fucker::{
    Config, DomainCapabilities, DomainCrossing, EntryKind, Error, FileIdentity, FileSystem, FsError, IdentitySource,
    KindSource, LoadAll, MetadataFields, MetadataSource, MetadataSources, PathChange, RelativePath, WatcherKind,
};

const PER_CHILD_IDENTITY: DomainId = DomainId::new(7);
const NO_IDENTITY: DomainId = DomainId::new(8);

fn path(p: &str) -> RelativePath {
    RelativePath::parse(p).expect("valid path")
}

fn sizes() -> MetadataFields {
    MetadataFields { size: true, ..MetadataFields::NONE }
}

fn per_child_sizes() -> DomainCapabilities {
    DomainCapabilities {
        metadata_sources: MetadataSources { size: MetadataSource::PerChildRead, ..MetadataSources::INLINE },
        ..DomainCapabilities::inline()
    }
}

fn sometimes_kinds() -> DomainCapabilities {
    DomainCapabilities { kind_source: KindSource::Sometimes, ..DomainCapabilities::inline() }
}

fn follow() -> Config {
    Config { domain_crossing: DomainCrossing::Follow, ..Default::default() }
}

fn populated() -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("a");
    fs.mkdir("a/b");
    fs.create_file("a/b/f1", 10);
    fs.create_file("a/f2", 20);
    fs.mkdir("c");
    fs.create_file("root.txt", 5);
    fs
}

fn published_causes(h: &Harness) -> Vec<ErrorCause> {
    h.events()
        .iter()
        .flat_map(|event| match event {
            UpdateEvent::Delta(update) => update.errors.clone(),
            UpdateEvent::Health { errors, .. } | UpdateEvent::Reset { errors, .. } => errors.clone(),
            UpdateEvent::Terminal { .. } => Vec::new(),
        })
        .map(|e| e.error)
        .collect()
}

fn per_child_metadata_operations(fs: &FakeFileSystem) -> Vec<(FakeOp, RelativePath)> {
    fs.ops()
        .into_iter()
        .filter(|(op, _)| matches!(op, FakeOp::Metadata | FakeOp::ResolveKind | FakeOp::Enrich))
        .collect()
}

#[test]
fn a_listing_with_metadata_none_performs_no_metadata_operation_on_an_inline_domain() {
    let fs = populated();
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    fs.clear_ops();
    h.run_until_idle();
    h.run_round();

    let reads = per_child_metadata_operations(&fs);
    assert!(
        reads.is_empty(),
        "RFC 10.1 with the RFC 9.2 tree default of metadata none: a listing must not perform a per-child \
         metadata read for what the enumeration primitive supplies; the scan performed {reads:?}"
    );
    assert_eq!(h.stats().metadata_operations, 0, "RFC 10.1: the adapter reported per-child metadata operations");
    assert_eq!(h.paths(), [".", "a", "a/b", "a/b/f1", "a/f2", "c", "root.txt"]);
    assert!(
        h.entry("a/f2").and_then(|e| e.identity).is_some(),
        "RFC 10.1: identity acquisition must not be modelled as metadata I/O where the domain supplies it inline"
    );
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(None));
}

#[test]
fn a_domain_reporting_unknown_kinds_resolves_them_in_the_session_and_charges_them_as_metadata_operations() {
    let fs = populated();
    fs.set_default_capabilities(sometimes_kinds());
    fs.report_unknown_kind("a/b");
    fs.report_unknown_kind("a/f2");
    fs.set_cost(CostScope::Everything, FakeOp::ResolveKind, Duration::from_millis(200));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    fs.clear_ops();
    let target = h.now() + Duration::from_secs(600);
    h.run_jobs_until(target);

    assert!(
        fs.count_ops(FakeOp::ResolveKind, "a/b") >= 1 && fs.count_ops(FakeOp::ResolveKind, "a/f2") >= 1,
        "RFC 10.1: an unknown kind is resolved with a metadata read inside the same session; the session \
         performed {:?}",
        per_child_metadata_operations(&fs)
    );
    assert_eq!(h.entry("a/b").map(|e| e.kind()), Some(EntryKind::Directory));
    assert_eq!(h.entry("a/f2").map(|e| e.kind()), Some(EntryKind::File));
    assert!(h.paths().contains(&"a/b/f1".to_string()), "the resolved directory was traversed");

    let stats = h.stats();
    assert!(
        stats.kind_resolutions >= 2 && stats.metadata_operations >= 2,
        "RFC 10.1 and 15.2: kind-resolution reads are counted and charged as metadata operations; the tree \
         counted {} resolutions and {} metadata operations",
        stats.kind_resolutions,
        stats.metadata_operations
    );
    assert!(
        stats.governor.charged >= Duration::from_millis(400),
        "RFC 15.2: the worker time of the kind-resolution reads is charged; the bucket was charged {:?}",
        stats.governor.charged
    );
}

#[test]
fn a_listing_with_an_unresolved_child_commits_nothing() {
    let fs = populated();
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();
    let before = h.paths();

    fs.set_default_capabilities(sometimes_kinds());
    fs.report_unknown_kind("a/late");
    fs.fail("a/late", FakeOp::ResolveKind, FailureMode::Always(FsError::Transient("no kind".into())));
    fs.add_silently("a/late", EntryKind::File);
    fs.remove_silently("a/f2");
    h.run_round();

    assert!(
        !h.paths().contains(&"a/late".to_string()),
        "RFC 10.1: an unresolved child must not be committed on a guess"
    );
    assert!(
        h.paths().contains(&"a/f2".to_string()),
        "RFC 10.1: a listing containing an unresolved child must not be used to prove that a name is absent"
    );
    assert_eq!(h.paths(), before, "RFC 10.1: a listing with an unresolved child commits nothing");
    assert!(
        h.stats().unresolved_listings >= 1,
        "RFC 10.1: the rejected listing was not reported as carrying an unresolved child"
    );
    assert!(
        h.stats().degraded_paths.contains(&path("a")) || h.health().reconciliation.is_degraded(),
        "RFC 13.1: the rejected listing leaves its path retryable and its round degraded"
    );
    assert!(
        h.events().iter().any(|event| match event {
            tree_fucker::update::UpdateEvent::Delta(update) =>
                update.errors.iter().any(|e| matches!(e.error, ErrorCause::UnresolvedKind(_))),
            tree_fucker::update::UpdateEvent::Health { errors, .. } =>
                errors.iter().any(|e| matches!(e.error, ErrorCause::UnresolvedKind(_))),
            _ => false,
        }),
        "RFC 10.1: the unresolved child was not reported"
    );

    fs.clear_failures();
    h.run_round();
    h.run_until_idle();
    assert!(h.paths().contains(&"a/late".to_string()), "RFC 10.1: resolution is not a failure threshold");
    assert!(!h.paths().contains(&"a/f2".to_string()));
}

#[test]
fn enabling_a_field_admits_enrichment_separately_from_the_listing() {
    let fs = populated();
    fs.set_default_capabilities(per_child_sizes());
    let config = Config { metadata_fields: sizes(), ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();

    let admissions = h.admissions();
    let listings: Vec<_> =
        admissions.iter().filter(|a| a.entry == path("a") && a.operation == JobOperation::Listing).collect();
    let enrichments: Vec<_> = admissions
        .iter()
        .filter(|a| a.entry == path("a") && matches!(a.operation, JobOperation::Enrichment { .. }))
        .collect();
    assert!(
        !listings.is_empty() && !enrichments.is_empty(),
        "RFC 10.1 and 15.1 item 1: enrichment is separately admitted; the admissions log holds {} listing \
         and {} enrichment grants for a",
        listings.len(),
        enrichments.len()
    );
    assert_ne!(
        listings[0].job, enrichments[0].job,
        "RFC 10.1: enrichment must be a separate job from the membership listing"
    );
    assert_eq!(
        enrichments[0].operation,
        JobOperation::Enrichment { fields: sizes() },
        "RFC 10.1: enrichment is requested only for the fields the configuration enables"
    );
    assert!(
        fs.count_ops(FakeOp::Enrich, "a/f2") >= 1,
        "RFC 10.1: a field the domain declares as a per-child read is obtained by enrichment"
    );
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(Some(20)));
    assert_eq!(h.entry("a/b/f1").map(|e| e.metadata.size), Some(Some(10)));
}

#[test]
fn a_failed_enrichment_leaves_the_membership_committed_and_reports_a_metadata_degradation() {
    let fs = populated();
    fs.set_default_capabilities(per_child_sizes());
    fs.fail("a", FakeOp::Enrich, FailureMode::Always(FsError::Transient("enrichment refused".into())));
    let config = Config { metadata_fields: sizes(), ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    h.run_round();

    assert_eq!(
        h.paths(),
        [".", "a", "a/b", "a/b/f1", "a/f2", "c", "root.txt"],
        "RFC 10.1: a failed enrichment must not prevent a structurally valid membership listing from committing"
    );
    assert_eq!(
        h.health().reconciliation.last_round,
        Some(RoundResult::Successful),
        "RFC 10.1 and 5.1: round success is a membership property, so a failed enrichment does not degrade the round"
    );
    let health = h.health();
    assert!(
        health.reconciliation.metadata_degraded_paths.contains(&path("a")),
        "RFC 10.1: a failed enrichment is reported as a metadata degradation of the affected path; the tree \
         reported {:?}",
        health.reconciliation.metadata_degraded_paths
    );
    assert!(
        !health.reconciliation.degraded_paths.contains(&path("a")),
        "RFC 10.1: a failed enrichment degrades only the metadata of the affected children"
    );
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(None));
    assert_eq!(
        h.entry("c").map(|e| e.load_state()),
        Some(Some(tree_fucker::LoadState::Loaded)),
        "RFC 10.1: the failure degrades only the affected path"
    );
    assert!(h.stats().enrichment_failures >= 1);
}

#[test]
fn a_baseline_round_refreshes_every_enabled_field_for_each_loaded_directory() {
    let fs = populated();
    fs.set_default_capabilities(per_child_sizes());
    let config = Config { metadata_fields: sizes(), ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(Some(20)));

    fs.set_size_silently("a/f2", 21);
    fs.set_size_silently("a/b/f1", 11);
    fs.set_size_silently("root.txt", 6);
    fs.clear_ops();
    h.run_round();
    h.run_until_idle();

    for directory in ["", "a", "a/b", "c"] {
        assert!(
            fs.count_ops(FakeOp::Enrich, directory) >= 1,
            "RFC 10.1: a baseline round refreshes every enabled field for each loaded directory and its \
             immediate children; {directory:?} received no enrichment"
        );
    }
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(Some(21)));
    assert_eq!(h.entry("a/b/f1").map(|e| e.metadata.size), Some(Some(11)));
    assert_eq!(h.entry("root.txt").map(|e| e.metadata.size), Some(Some(6)));
}

#[test]
fn an_inline_domain_needs_no_enrichment_job_for_the_same_configured_fields() {
    let fs = populated();
    let config = Config { metadata_fields: sizes(), ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    fs.clear_ops();
    h.run_until_idle();
    h.run_round();

    assert_eq!(
        per_child_metadata_operations(&fs),
        Vec::new(),
        "RFC 10.1: where the enumeration primitive supplies a field inline, the listing session performs the \
         refresh and no per-child operation is charged"
    );
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(Some(20)));
    assert_eq!(h.stats().enrichments, 0);
}

#[test]
fn a_domain_declares_per_item_whether_observation_costs_a_per_child_operation() {
    let fs = populated();
    let media = DomainId::new(2);
    fs.set_domain("a", media);
    fs.set_capabilities(
        media,
        DomainCapabilities {
            kind_source: KindSource::Sometimes,
            metadata_sources: MetadataSources::PER_CHILD_READ,
            ..DomainCapabilities::inline()
        },
    );

    let root = fs.capabilities_of(&path("c"));
    assert_eq!(root.kind_source, KindSource::Always);
    assert_eq!(root.metadata_sources.per_child_read(), MetadataFields::NONE);

    let child = fs.capabilities_of(&path("a/f2"));
    assert_eq!(child.kind_source, KindSource::Sometimes);
    assert_eq!(child.identity_source, IdentitySource::Inline);
    assert_eq!(
        child.metadata_sources.per_child_read(),
        MetadataFields::ALL,
        "RFC 10.1: on Unix every metadata field requires a per-child read while the inode is inline"
    );
    assert_eq!(child.metadata_sources.inline(), MetadataFields::NONE);
}

#[test]
fn a_listing_rejected_for_an_unresolved_child_reports_a_typed_error_and_no_filesystem_error() {
    let fs = populated();
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();
    h.take_events();

    fs.set_default_capabilities(sometimes_kinds());
    fs.report_unknown_kind("a/late");
    fs.fail("a/late", FakeOp::ResolveKind, FailureMode::Always(FsError::Transient("no kind".into())));
    fs.add_silently("a/late", EntryKind::File);
    let t = h.command(Command::Refresh(vec![path("a")]));
    h.run_until_idle();

    assert_eq!(
        h.result(t),
        Some(Err(Error::UnresolvedKind)),
        "RFC 13.1 and 10.1: a listing rejected for an unresolved child kind is a core-generated outcome, so its \
         command completes with that outcome"
    );
    let causes = published_causes(&h);
    assert!(
        causes.iter().any(|c| matches!(c, ErrorCause::UnresolvedKind(_))),
        "RFC 10.1: the unresolved child must be reported; the tree published {causes:?}"
    );
    assert!(
        !causes.iter().any(|c| matches!(c, ErrorCause::Fs(_))),
        "RFC 13.1: the core must not fabricate a filesystem error for an outcome it generated itself; it \
         published {causes:?}"
    );

    fs.clear_failures();
    h.run_round();
    h.run_until_idle();
    assert!(
        h.paths().contains(&"a/late".to_string()),
        "RFC 10.1: unknown-kind resolution is not a failure threshold, so the retry must converge"
    );
}

#[test]
fn a_domain_acquiring_identity_per_child_counts_one_operation_per_child_and_a_none_domain_counts_none() {
    let fs = populated();
    fs.create_file("c/g", 3);
    fs.set_domain("a", PER_CHILD_IDENTITY);
    fs.set_capabilities(
        PER_CHILD_IDENTITY,
        DomainCapabilities { identity_source: IdentitySource::PerChildRead, ..DomainCapabilities::inline() },
    );
    fs.set_domain("c", NO_IDENTITY);
    fs.set_capabilities(
        NO_IDENTITY,
        DomainCapabilities { identity_source: IdentitySource::None, ..DomainCapabilities::inline() },
    );
    let config = Config { operations_per_lease: 1, ..follow() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    fs.clear_ops();
    h.run_until_idle();

    assert!(
        h.entry("a/b").and_then(|e| e.identity).is_some() && h.entry("a/f2").and_then(|e| e.identity).is_some(),
        "RFC 10.1: a domain that supplies identity through a per-child read must still supply it"
    );
    assert_eq!(
        (fs.count_ops(FakeOp::ResolveIdentity, "a/b"), fs.count_ops(FakeOp::ResolveIdentity, "a/f2")),
        (1, 1),
        "RFC 10.1: obtaining identity on that domain costs one additional operation per child; the session \
         performed {:?}",
        fs.ops().iter().filter(|(op, _)| *op == FakeOp::ResolveIdentity).collect::<Vec<_>>()
    );

    assert!(
        h.entry("c/g").and_then(|e| e.identity).is_none(),
        "RFC 10.1: a domain declaring no identity source must supply none"
    );
    assert_eq!(
        fs.count_ops(FakeOp::ResolveIdentity, "c/g"),
        0,
        "RFC 10.1: a domain declaring no identity source performs no per-child identity operation"
    );

    let stats = h.stats();
    assert!(
        stats.identity_reads >= 2,
        "RFC 15.2: every per-child operation the session performs is counted; it counted {}",
        stats.identity_reads
    );
    assert!(
        stats.lease_grants > 0,
        "RFC 10.2: per-child identity reads hold lease, so a directory needing more of them than one lease \
         covers must take a further lease"
    );
    assert_eq!(
        stats.metadata_operations, 0,
        "RFC 10.1: identity acquisition is not modelled as metadata I/O; the tree counted {} metadata operations",
        stats.metadata_operations
    );
}

fn membership_changes(h: &Harness) -> Vec<PathChange> {
    h.events()
        .iter()
        .filter_map(|event| match event {
            UpdateEvent::Delta(update) => Some(update.changes.clone()),
            _ => None,
        })
        .flatten()
        .filter(|change| matches!(change, PathChange::Added { .. } | PathChange::Removed { .. }))
        .collect()
}

#[test]
fn a_mount_point_keeps_its_entry_when_its_own_identity_differs_from_its_directory_entry() {
    let fs = populated();
    fs.set_domain("a", DomainId::new(3));
    fs.report_own_identity("a", FileIdentity { device: 2, inode: 1 });
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), follow()).expect("open");
    h.run_until_idle();
    let mount = h.entry("a").expect("mount point");
    let inner = h.entry("a/b/f1").expect("inner file").id;
    let dirent = fs.metadata(fs.root(), &path("a")).expect("own metadata").identity;
    assert_ne!(mount.identity, dirent, "the fixture gives the mount point one identity in each domain");
    h.take_events();
    for _ in 0..3 {
        h.run_round();
    }
    let t = h.command(Command::Refresh(vec![path("a"), path("")]));
    h.run_until_idle();
    assert_eq!(h.result(t), Some(Ok(())));
    assert_eq!(
        h.entry("a").map(|e| e.id),
        Some(mount.id),
        "RFC 7.1 and 14.3: a mount point's identity in the containing filesystem and in the mounted filesystem are \
         two identity spaces, so the parent listing must not replace the entry on every round"
    );
    assert_eq!(h.entry("a").and_then(|e| e.identity), mount.identity, "the entry keeps one identity space");
    assert_eq!(h.entry("a/b/f1").map(|e| e.id), Some(inner), "the mounted subtree survived every parent listing");
    let churn: Vec<PathChange> = membership_changes(&h).into_iter().filter(|c| c.path() == &path("a")).collect();
    assert!(churn.is_empty(), "RFC 7.1: the mount point was removed and re-added: {churn:?}");
}

#[test]
fn a_failed_child_enrichment_degrades_only_that_child_and_the_rest_of_the_directory_is_enriched() {
    let fs = populated();
    fs.set_default_capabilities(per_child_sizes());
    fs.fail("a/f2", FakeOp::Enrich, FailureMode::Always(FsError::Transient("stat refused".into())));
    let config =
        Config { metadata_fields: sizes(), fixed_interval: Some(Duration::from_secs(3600)), ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    h.run_round();

    assert_eq!(h.paths(), [".", "a", "a/b", "a/b/f1", "a/f2", "c", "root.txt"], "membership is unaffected");
    assert_eq!(h.entry("a/b/f1").map(|e| e.metadata.size), Some(Some(10)), "the other children are enriched");
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(None), "the failed child carries no guessed value");
    let health = h.health();
    assert!(
        health.reconciliation.metadata_degraded_paths.contains(&path("a/f2")),
        "RFC 10.1: enrichment failure degrades the metadata of the affected children; the tree reported {:?}",
        health.reconciliation.metadata_degraded_paths
    );
    assert!(
        !health.reconciliation.metadata_degraded_paths.contains(&path("a")),
        "RFC 10.1: the directory whose other children were enriched is not degraded as a whole; {:?}",
        health.reconciliation.metadata_degraded_paths
    );
    assert!(health.reconciliation.degraded_paths.is_empty(), "RFC 10.1: metadata failure is never membership failure");
    assert_eq!(health.reconciliation.last_round, Some(RoundResult::Successful));
    let causes = published_causes(&h);
    assert!(
        causes.iter().any(|c| matches!(c, ErrorCause::Fs(FsError::Transient(_)))),
        "the failure is reported: {causes:?}"
    );

    fs.clear_failures();
    fs.clear_ops();
    h.run_jobs_until(h.now() + Duration::from_secs(120));
    assert_eq!(h.entry("a/f2").map(|e| e.metadata.size), Some(Some(20)), "RFC 10.1: enrichment is retryable work");
    assert!(fs.count_ops(FakeOp::Enrich, "a/f2") >= 1, "the failed child was read again");
    for untouched in ["a", "a/b"] {
        assert_eq!(
            fs.count_ops(FakeOp::Enrich, untouched),
            0,
            "RFC 10.1: the retry reads only the children whose enrichment failed; {untouched} was read again: {:?}",
            fs.ops()
        );
    }
    assert!(
        h.health().reconciliation.metadata_degraded_paths.is_empty(),
        "a successful enrichment clears the child's metadata degradation: {:?}",
        h.health().reconciliation.metadata_degraded_paths
    );
}

#[test]
fn enrichment_of_a_wide_directory_takes_one_lease_per_batch_of_children() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("wide");
    for i in 0..40 {
        fs.create_file(&format!("wide/f{i}"), 1);
    }
    fs.set_default_capabilities(per_child_sizes());
    fs.set_cost(CostScope::Everything, FakeOp::Enrich, Duration::from_millis(1));
    let config = Config { metadata_fields: sizes(), operations_per_lease: 8, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_jobs_until(h.now() + Duration::from_secs(600));

    for i in 0..40 {
        assert_eq!(
            h.entry(&format!("wide/f{i}")).map(|e| e.metadata.size),
            Some(Some(1)),
            "wide/f{i} was not enriched"
        );
    }
    let leases: Vec<_> = h
        .admissions()
        .into_iter()
        .filter(|a| a.entry == path("wide") && matches!(a.operation, JobOperation::Enrichment { .. }))
        .collect();
    let renewals = leases.iter().filter(|a| a.lease > 0).count();
    assert!(
        renewals >= 4,
        "RFC 10.2 and 15.3: forty children under an eight-operation lease are enriched in at least five governed \
         batches; the enrichment took {renewals} further lease grants ({} admissions)",
        leases.len()
    );
    let jobs: std::collections::BTreeSet<_> = leases.iter().map(|a| a.job).collect();
    assert!(!jobs.is_empty());
}

#[test]
fn only_unknown_kinds_receive_governed_lookups_and_those_consume_the_operations_lease() {
    fn run(unknown: bool) -> (Arc<FakeFileSystem>, Harness) {
        let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
        fs.mkdir("d");
        for i in 0..8 {
            fs.create_file(&format!("d/f{i}"), 1);
            if unknown && i % 2 == 0 {
                fs.report_unknown_kind(&format!("d/f{i}"));
            }
        }
        fs.set_default_capabilities(sometimes_kinds());
        let config = Config { operations_per_lease: 2, ..Default::default() };
        let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
        h.run_until_idle();
        (fs, h)
    }

    let (fs, h) = run(true);
    for i in 0..8 {
        let expected = usize::from(i % 2 == 0);
        assert_eq!(
            fs.count_ops(FakeOp::ResolveKind, &format!("d/f{i}")),
            expected,
            "RFC 10.1: only a child whose kind the enumeration did not supply receives a governed lookup"
        );
    }
    assert_eq!(h.stats().kind_resolutions, 4);
    assert!(
        h.stats().lease_grants >= 1,
        "RFC 10.2: four kind lookups under a two-operation lease must take further lease grants; the tree took {}",
        h.stats().lease_grants
    );
    assert_eq!(h.paths().len(), 10);

    let (_, control) = run(false);
    assert_eq!(control.stats().kind_resolutions, 0);
    assert_eq!(control.stats().lease_grants, 0, "without unknown kinds no per-child operation consumes the lease");
}

#[test]
fn a_permission_denied_directory_retries_once_per_baseline_round_and_not_between_rounds() {
    let fs = populated();
    let config = Config { fixed_interval: Some(Duration::from_secs(60)), ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    fs.fail("a", FakeOp::ReadDir, FailureMode::Always(FsError::PermissionDenied));
    h.run_round();
    assert!(h.health().reconciliation.degraded_paths.contains(&path("a")), "RFC 13.3: the path is degraded");
    assert!(h.paths().contains(&"a/b/f1".to_string()), "RFC 13.3: the last known representation is retained");
    let before = fs.count_ops(FakeOp::ReadDir, "a");
    h.advance(Duration::from_secs(30));
    assert_eq!(
        fs.count_ops(FakeOp::ReadDir, "a"),
        before,
        "RFC 13.1: a Loaded directory denied permission retries once per baseline round, never on a timer between rounds"
    );
    h.run_round();
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a"), before + 1, "RFC 13.1: exactly one attempt per round");
    h.run_round();
    assert_eq!(fs.count_ops(FakeOp::ReadDir, "a"), before + 2, "RFC 13.1: exactly one attempt per round");
    assert!(h.paths().contains(&"a/b/f1".to_string()));
}

#[test]
fn a_permanently_failing_directory_has_bounded_retry_admissions_over_an_hour() {
    let fs = populated();
    let config = Config { fixed_interval: Some(Duration::from_secs(300)), ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    fs.fail("a", FakeOp::ReadDir, FailureMode::Always(FsError::Transient("always".into())));
    let before = fs.count_ops(FakeOp::ReadDir, "a");
    h.run_jobs_until(h.now() + Duration::from_secs(3600));
    let attempts = fs.count_ops(FakeOp::ReadDir, "a") - before;
    assert!(attempts >= 5, "the failing directory was retried only {attempts} times, so nothing was bounded");
    assert!(
        attempts <= 40,
        "RFC 13.1 and 15.1 item 6: exponential backoff, the failure surcharge and one attempt per round bound a \
         permanently failing target; it was attempted {attempts} times in an hour"
    );
    assert!(h.paths().contains(&"a/b/f1".to_string()), "RFC 13.1: the snapshot is retained through every failure");
}

const RFC16_MEDIA: DomainId = DomainId::new(11);

fn rfc16_tree() -> Arc<FakeFileSystem> {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::Recursive));
    fs.mkdir("wide");
    for i in 0..3 {
        fs.create_file(&format!("wide/f{i}"), 1);
    }
    fs.mkdir("narrow");
    fs.create_file("narrow/f", 1);
    fs.mkdir("mnt");
    fs.mkdir("mnt/inner");
    fs.set_domain("mnt", RFC16_MEDIA);
    fs
}

#[test]
fn every_rfc_16_observability_item_is_present_in_stats_or_health() {
    let fs = rfc16_tree();
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(10));
    let config = Config { entries_per_directory: 3, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    h.command(Command::SetPriority(vec![path("narrow")]));
    h.run_round();
    let successful = h.stats();
    fs.add_silently("wide/f3", EntryKind::File);
    fs.add_silently("wide/f4", EntryKind::File);
    h.run_round();
    h.run_round();

    let stats = h.stats();
    let health = h.health();
    let listed = stats
        .domains
        .iter()
        .find(|domain| domain.listings > 0)
        .cloned()
        .expect("RFC 16: at least one storage domain was listed");

    let items: Vec<(&str, bool)> = vec![
        ("current snapshot version", stats.version.get() > 0),
        ("initial scan state", stats.initial_scan == health.initial_scan),
        ("current reconciliation generation", stats.reconciliation_generation.get() > 0),
        ("time and duration of the last successful round", successful.last_successful_round.is_some()),
        ("baseline cursor position", stats.baseline_cursor.0 <= stats.baseline_cursor.1),
        ("obligation counts, total", successful.obligations.total > 0),
        ("obligation counts, accepted", successful.obligations.accepted > 0),
        (
            "obligation counts, unsatisfied",
            stats.obligations.unsatisfied > 0 && stats.obligations.unsatisfied <= stats.obligations.total,
        ),
        ("obligation counts, removed", stats.obligations.removed <= stats.obligations.total),
        ("priority cursor progress", stats.priority_cursor.1 > 0),
        ("loaded entry count", stats.loaded_directories > 0),
        ("represented entry count", stats.represented_entries > 0),
        ("queued job count", stats.queued_jobs == 0),
        ("in-flight job count", stats.in_flight_jobs == 0),
        ("watcher backend", stats.watcher == WatcherKind::Recursive),
        ("watcher health", !health.watcher_domains.is_empty()),
        ("dropped watcher hint count", stats.dropped_hints == 0),
        ("coalesced watcher hint count", stats.coalesced_hints < u64::MAX),
        ("listing latency", stats.last_listing_duration.is_some() && listed.latency.samples > 0),
        ("listing failure counts", stats.listing_failures > 0),
        ("degraded paths", stats.degraded_paths.contains(&path("wide"))),
        ("storage domains entered", stats.domains.len() >= 2),
        (
            "declared capabilities and the source of each declaration",
            stats.domains.iter().all(|domain| {
                domain.capabilities.sources.topology == domain.capabilities.sources.topology
                    && domain.capabilities.topology == domain.capabilities.topology
            }),
        ),
        ("per-domain concurrency window", listed.window >= 1 && listed.window <= listed.ceiling),
        ("per-domain in-flight count", listed.in_flight == 0),
        ("per-domain worker time consumed", listed.charged > Duration::ZERO),
        ("per-domain worker time granted", listed.granted > Duration::ZERO),
        ("per-domain bucket level", listed.capacity > Duration::ZERO),
        ("per-domain debt", listed.level == Duration::ZERO || listed.debt == Duration::ZERO),
        ("throttled job count", stats.governor.denials < u64::MAX && listed.throttled_jobs < u64::MAX),
        ("total throttled duration", stats.governor.throttled_duration < Duration::MAX),
        ("effective background duty per domain", listed.effective_duty > 0.0),
        ("listing counts per domain", listed.listings > 0),
        ("metadata counts per domain", listed.metadata_operations < u64::MAX),
        ("enumeration counts per domain", listed.entries_enumerated > 0),
        (
            "per-domain latency summaries",
            listed.latency.samples > 0
                && listed.latency.minimum <= listed.latency.median
                && listed.latency.median <= listed.latency.tail
                && listed.latency.mean >= listed.latency.minimum,
        ),
        (
            "largest directories encountered",
            stats.largest_directories.first().map(|d| d.children)
                == stats.largest_directories.iter().map(|d| d.children).max()
                && stats.largest_directories.iter().any(|d| d.path == path("wide") && d.children > 3),
        ),
        ("accounted memory", stats.accounted_memory > 0),
        ("snapshot bytes", stats.snapshot_bytes > 0),
        (
            "stuck workers with their paths, operations, and start times",
            stats.stuck_workers.iter().all(|slot| slot.started <= h.now()),
        ),
        (
            "resource-limit events with cause and the configured limit",
            stats.resource_limits.iter().any(|event| {
                event.limited.limit == ResourceLimit::EntriesPerDirectory && event.limited.configured == 3
            }),
        ),
        ("domain-crossing decisions", stats.crossings.iter().any(|crossing| crossing.path == path("mnt"))),
    ];
    let missing: Vec<&str> = items.iter().filter(|(_, present)| !present).map(|(name, _)| *name).collect();
    assert!(missing.is_empty(), "RFC 16: the implementation exposes at least these items; missing {missing:?}");

    let mut stuck = Harness::open_with_host(
        {
            let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
            fs.mkdir("held");
            fs.set_cost(CostScope::path("held"), FakeOp::ReadDir, Duration::from_secs(36_000));
            fs
        },
        Arc::new(LoadAll),
        tree_fucker::HostConfig { stuck_threshold: Duration::from_secs(30), ..Default::default() },
        Config::default(),
    )
    .expect("open");
    stuck.run_jobs_until(tree_fucker::core::MonotonicTime::ZERO + Duration::from_secs(300));
    let slot = stuck
        .stats()
        .stuck_workers
        .first()
        .cloned()
        .expect("RFC 16: stuck workers are reported with their paths, operations, and start times");
    assert_eq!(slot.path, path("held"));
    assert_eq!(slot.operation, JobOperation::Listing);
    assert!(slot.started < stuck.now());
}

#[test]
fn an_enrichment_batch_never_carries_more_children_than_its_grant_permitted() {
    use std::collections::BTreeMap;

    use tree_fucker::JobId;
    use tree_fucker::testing::Dispatched;

    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("wide");
    for i in 0..40 {
        fs.create_file(&format!("wide/f{i}"), 1);
    }
    fs.set_default_capabilities(per_child_sizes());
    fs.set_cost(CostScope::Everything, FakeOp::Enrich, Duration::from_millis(1));
    let config = Config { metadata_fields: sizes(), ..Default::default() };
    let mut h = Harness::open(fs, Arc::new(LoadAll), config).expect("open");

    h.run_jobs_until(h.now() + Duration::from_secs(3600));

    let mut batches: BTreeMap<JobId, Vec<usize>> = BTreeMap::new();
    for dispatched in h.dispatches() {
        if let Dispatched::Enrichment { job, children, .. } = dispatched {
            batches.entry(job).or_default().push(children);
        }
    }
    let mut permitted: BTreeMap<JobId, Vec<u32>> = BTreeMap::new();
    for admission in h.admissions() {
        if matches!(admission.operation, JobOperation::Enrichment { .. }) {
            permitted.entry(admission.job).or_default().push(admission.operations);
        }
    }
    assert!(!batches.is_empty(), "the wide directory was never enriched, so nothing is fenced");
    for (job, sizes) in &batches {
        let grants = permitted.get(job).cloned().unwrap_or_default();
        assert!(
            sizes.len() <= grants.len(),
            "RFC 15.1 item 1: every enrichment batch runs under a grant; job {job:?} dispatched {} batches \
             against {} grants",
            sizes.len(),
            grants.len()
        );
        for (index, children) in sizes.iter().enumerate() {
            assert!(
                *children <= usize::try_from(grants[index]).unwrap_or(usize::MAX),
                "RFC 15.3: the enrichment batch carries the permitted count and the work MUST NOT perform more \
                 per-child operations than the grant permits; batch {index} of job {job:?} carried {children} \
                 children against {} permitted",
                grants[index]
            );
        }
    }
    for i in 0..40 {
        assert_eq!(
            h.entry(&format!("wide/f{i}")).map(|e| e.metadata.size),
            Some(Some(1)),
            "RFC 10.1: every observed child is enriched however many batches it takes; wide/f{i} was not"
        );
    }
}
