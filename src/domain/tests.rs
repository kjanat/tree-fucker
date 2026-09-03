use std::path::Path;

use super::{
    AccessTopology, Answer, Crossing, DeclarationSource, DeclaredProbe, DomainCapabilities, DomainCaseSensitivity,
    DomainIdentity, DomainKey, DomainProbe, FilesystemSemantics, IdentityReliability, IdentitySource, IdentitySpace,
    IdentitySpaceKey, KindSource, MediaHint, MetadataSource, TimestampGranularity, TransportHint, UnknownProbe,
    WatcherAvailability, WatcherScope,
};

fn space(id: u64) -> DomainCapabilities {
    DomainCapabilities {
        identity_space: IdentitySpace::Known(IdentitySpaceKey::declared(id)),
        identity_reliability: IdentityReliability::Stable,
        ..DomainCapabilities::default()
    }
}

fn declared(domain: u64, identity_space: u64) -> DeclaredProbe {
    DeclaredProbe::new(DomainIdentity::Known(DomainKey::declared(domain)), space(identity_space), true)
}

#[test]
fn every_capability_field_defaults_to_unknown() {
    let capabilities = DomainCapabilities::default();
    assert_eq!(capabilities.semantics, FilesystemSemantics::Unknown);
    assert_eq!(capabilities.topology, AccessTopology::Unknown);
    assert_eq!(capabilities.transport, TransportHint::Unknown);
    assert_eq!(capabilities.media, MediaHint::Unknown);
    assert_eq!(capabilities.case, DomainCaseSensitivity::Unknown);
    assert_eq!(capabilities.timestamp_granularity, TimestampGranularity::Unknown);
    assert_eq!(capabilities.identity_space, IdentitySpace::Unknown);
    assert_eq!(capabilities.identity_reliability, IdentityReliability::Unknown);
    assert_eq!(capabilities.kind_source, KindSource::Unknown);
    assert_eq!(capabilities.identity_source, IdentitySource::Unknown);
    assert_eq!(capabilities.metadata_sources.modified, MetadataSource::Unknown);
    assert_eq!(capabilities.metadata_sources.created, MetadataSource::Unknown);
    assert_eq!(capabilities.metadata_sources.size, MetadataSource::Unknown);
    assert_eq!(capabilities.metadata_sources.permissions, MetadataSource::Unknown);
    assert_eq!(capabilities.watcher.availability, WatcherAvailability::Unknown);
    assert_eq!(capabilities.watcher.scope, WatcherScope::Unknown);
    assert_eq!(capabilities.watcher.observes_external_writers, Answer::Unknown);
    assert_eq!(capabilities.watcher.can_lose_events, Answer::Unknown);
    assert_eq!(capabilities.watcher.signals_overflow, Answer::Unknown);
    assert_eq!(capabilities.watcher.registration_gaps, Answer::Unknown);
    assert_eq!(capabilities.watcher.polling_fallback_required, Answer::Unknown);
    assert_eq!(capabilities.sources.semantics, DeclarationSource::Unknown);
    assert_eq!(capabilities.sources.watcher, DeclarationSource::Unknown);
    assert!(!capabilities.identity_reliability.establishes_rename());
}

#[test]
fn an_unknown_probe_reports_unknown_for_every_domain() {
    let probe = UnknownProbe;
    let parent = probe.probe(Path::new("/"), None).expect("unknown probe");
    assert_eq!(parent.identity, DomainIdentity::Unknown);
    assert_eq!(parent.capabilities, DomainCapabilities::default());
    assert!(!parent.is_domain_root);
    assert_eq!(parent.crossed, Crossing::NotCrossed);

    let child = probe.probe(Path::new("/child"), Some(&parent)).expect("unknown probe");
    assert_eq!(child.crossed, Crossing::Inconclusive);
}

#[test]
fn a_declared_domain_crossing_is_proven_by_a_changed_declared_key() {
    let outer = declared(1, 1).probe(Path::new("/"), None).expect("declared probe");
    assert_eq!(outer.crossed, Crossing::NotCrossed);

    let same = declared(1, 1).probe(Path::new("/a"), Some(&outer)).expect("declared probe");
    assert_eq!(same.crossed, Crossing::NotCrossed);

    let other = declared(2, 2).probe(Path::new("/b"), Some(&outer)).expect("declared probe");
    assert_eq!(other.crossed, Crossing::Proven);

    let unknown = UnknownProbe.probe(Path::new("/c"), Some(&outer)).expect("unknown probe");
    assert_eq!(unknown.crossed, Crossing::Inconclusive);
}

#[test]
fn a_bind_mount_is_a_second_domain_that_shares_one_identity_space() {
    let origin = declared(1, 7).probe(Path::new("/origin"), None).expect("declared probe");
    let bind = declared(2, 7).probe(Path::new("/bind"), Some(&origin)).expect("declared probe");
    assert_eq!(bind.crossed, Crossing::Proven);
    assert_ne!(origin.identity, bind.identity);
    assert!(origin.capabilities.identities_comparable(&bind.capabilities));
}

#[test]
fn two_subvolumes_are_two_identity_spaces_whose_identities_never_compare() {
    let first = declared(1, 1).probe(Path::new("/first"), None).expect("declared probe");
    let second = declared(2, 2).probe(Path::new("/second"), Some(&first)).expect("declared probe");
    assert_eq!(second.crossed, Crossing::Proven);
    assert!(!first.capabilities.identities_comparable(&second.capabilities));
    assert!(!first.capabilities.identities_comparable(&DomainCapabilities::default()));
    assert!(!DomainCapabilities::default().identities_comparable(&DomainCapabilities::default()));
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;

    use super::super::{
        AccessTopology, Answer, Crossing, DeclarationSource, DomainCapabilities, DomainProbe, FilesystemSemantics,
        IdentitySpace, KindSource, LinuxProbe, ProbeError, ProbeResult, WatcherAvailability, WatcherScope,
    };

    fn probe(path: &str, parent: Option<&ProbeResult>) -> ProbeResult {
        LinuxProbe::new().probe(Path::new(path), parent).unwrap_or_else(|error| panic!("probe {path}: {error}"))
    }

    fn source_matches_value(capabilities: &DomainCapabilities) -> bool {
        let sources = &capabilities.sources;
        let known = [
            (capabilities.semantics != FilesystemSemantics::Unknown, sources.semantics),
            (capabilities.topology != AccessTopology::Unknown, sources.topology),
            (capabilities.identity_space != IdentitySpace::Unknown, sources.identity_space),
        ];
        known.iter().all(|(value, source)| *value == (*source != DeclarationSource::Unknown))
    }

    #[test]
    fn the_root_directory_resolves_a_filesystem_instance_and_an_identity_space() {
        let root = probe("/", None);
        assert!(root.identity.is_known());
        assert_eq!(root.crossed, Crossing::NotCrossed);
        assert_ne!(root.capabilities.semantics, FilesystemSemantics::Unknown);
        assert_eq!(root.capabilities.sources.semantics, DeclarationSource::Detected);
        assert_ne!(root.capabilities.identity_space, IdentitySpace::Unknown);
        assert_eq!(root.capabilities.sources.identity_space, DeclarationSource::Detected);
        assert!(source_matches_value(&root.capabilities));
    }

    #[test]
    fn proc_is_a_distinct_domain_reached_by_a_proven_crossing() {
        let root = probe("/", None);
        let proc = probe("/proc", Some(&root));
        assert_ne!(root.identity, proc.identity);
        assert_eq!(proc.crossed, Crossing::Proven);
        assert!(proc.is_domain_root);
        assert_eq!(proc.capabilities.semantics, FilesystemSemantics::Other("proc".to_owned()));
        assert_eq!(proc.capabilities.topology, AccessTopology::Virtual);
        assert!(source_matches_value(&proc.capabilities));
    }

    #[test]
    fn a_directory_within_one_domain_is_not_a_crossing() {
        let proc = probe("/proc", None);
        let inner = probe("/proc/sys", Some(&proc));
        assert_eq!(inner.identity, proc.identity);
        assert_eq!(inner.crossed, Crossing::NotCrossed);
        assert!(!inner.is_domain_root);
        assert_eq!(inner.capabilities.semantics, proc.capabilities.semantics);
    }

    #[test]
    fn sysfs_is_a_virtual_domain_of_its_own() {
        let root = probe("/", None);
        let sys = probe("/sys", Some(&root));
        assert_eq!(sys.capabilities.semantics, FilesystemSemantics::Other("sysfs".to_owned()));
        assert_eq!(sys.capabilities.topology, AccessTopology::Virtual);
        assert_eq!(sys.crossed, Crossing::Proven);
        assert!(sys.is_domain_root);
    }

    #[test]
    fn tmp_crosses_only_when_it_is_a_separate_mount() {
        if !Path::new("/tmp").is_dir() {
            return;
        }
        let root = probe("/", None);
        let tmp = probe("/tmp", Some(&root));
        if tmp.identity == root.identity {
            assert_eq!(tmp.crossed, Crossing::NotCrossed);
            assert!(!tmp.is_domain_root);
            assert_eq!(tmp.capabilities.semantics, root.capabilities.semantics);
        } else {
            assert_eq!(tmp.crossed, Crossing::Proven);
            assert!(tmp.is_domain_root);
        }
    }

    #[test]
    fn every_linux_domain_declares_inotify_watcher_capabilities() {
        let root = probe("/", None);
        assert_eq!(root.capabilities.watcher.availability, WatcherAvailability::Available);
        assert_eq!(root.capabilities.watcher.scope, WatcherScope::PerDirectory);
        assert_eq!(root.capabilities.watcher.can_lose_events, Answer::Yes);
        assert_eq!(root.capabilities.watcher.signals_overflow, Answer::Yes);
        assert_eq!(root.capabilities.sources.watcher, DeclarationSource::Declared);
        assert_eq!(root.capabilities.kind_source, KindSource::Sometimes);
    }

    #[test]
    fn a_non_directory_and_a_missing_path_are_classified() {
        let file = LinuxProbe::new().probe(Path::new("/proc/version"), None);
        assert_eq!(file, Err(ProbeError::NotDirectory));
        let missing = LinuxProbe::new().probe(Path::new("/proc/tree-fucker-absent"), None);
        assert_eq!(missing, Err(ProbeError::NotFound));
    }
}
