use std::sync::Arc;
use std::time::Duration;

use tree_fucker::core::{Command, JobOperation};
use tree_fucker::testing::DomainId;
use tree_fucker::testing::{CostScope, FailureMode, FakeFileSystem, FakeOp, Harness};
use tree_fucker::update::{ErrorCause, RoundResult, UpdateEvent};
use tree_fucker::{
    Config, EntryKind, Error, FieldSource, FsError, IdentitySource, KindSource, LoadAll, MetadataFields,
    MetadataSources, ObservationSources, RelativePath, WatcherKind,
};

const PER_CHILD_IDENTITY: DomainId = DomainId::new(7);
const NO_IDENTITY: DomainId = DomainId::new(8);

fn path(p: &str) -> RelativePath {
    RelativePath::parse(p).expect("valid path")
}

fn sizes() -> MetadataFields {
    MetadataFields { size: true, ..MetadataFields::NONE }
}

fn per_child_sizes() -> ObservationSources {
    ObservationSources {
        kind: KindSource::Always,
        identity: IdentitySource::Inline,
        metadata: MetadataSources { size: FieldSource::PerChildRead, ..MetadataSources::INLINE },
    }
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
    fs.set_default_sources(ObservationSources {
        kind: KindSource::Sometimes,
        identity: IdentitySource::Inline,
        metadata: MetadataSources::INLINE,
    });
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

    fs.set_default_sources(ObservationSources {
        kind: KindSource::Sometimes,
        identity: IdentitySource::Inline,
        metadata: MetadataSources::INLINE,
    });
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
    fs.set_default_sources(per_child_sizes());
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
    fs.set_default_sources(per_child_sizes());
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
    fs.set_default_sources(per_child_sizes());
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
    fs.set_sources(media, ObservationSources::UNIX);

    let root = fs.sources_of(&path("c"));
    assert_eq!(root, ObservationSources::INLINE);
    assert_eq!(root.metadata.per_child_read(), MetadataFields::NONE);

    let child = fs.sources_of(&path("a/f2"));
    assert_eq!(child.kind, KindSource::Sometimes);
    assert_eq!(child.identity, IdentitySource::Inline);
    assert_eq!(
        child.metadata.per_child_read(),
        MetadataFields::ALL,
        "RFC 10.1: on Unix every metadata field requires a per-child read while the inode is inline"
    );
    assert_eq!(child.metadata.inline(), MetadataFields::NONE);
}

#[test]
fn a_listing_rejected_for_an_unresolved_child_reports_a_typed_error_and_no_filesystem_error() {
    let fs = populated();
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    h.run_until_idle();
    h.take_events();

    fs.set_default_sources(ObservationSources {
        kind: KindSource::Sometimes,
        identity: IdentitySource::Inline,
        metadata: MetadataSources::INLINE,
    });
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
    fs.set_sources(
        PER_CHILD_IDENTITY,
        ObservationSources {
            kind: KindSource::Always,
            identity: IdentitySource::PerChildRead,
            metadata: MetadataSources::INLINE,
        },
    );
    fs.set_domain("c", NO_IDENTITY);
    fs.set_sources(
        NO_IDENTITY,
        ObservationSources {
            kind: KindSource::Always,
            identity: IdentitySource::None,
            metadata: MetadataSources::INLINE,
        },
    );
    let config = Config { operations_per_lease: 1, ..Default::default() };
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
