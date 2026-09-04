use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::unix::{at_mount_point, c_string, fsid_pair, open_directory};
use super::{
    AccessTopology, Answer, Crossing, DeclarationSource, DeclarationSources, DomainCapabilities, DomainCaseSensitivity,
    DomainIdentity, DomainKey, DomainProbe, FilesystemInstance, FilesystemInstanceKey, FilesystemSemantics,
    IdentityReliability, IdentitySource, IdentitySpace, IdentitySpaceKey, KindSource, MediaHint, MetadataSources,
    ProbeError, ProbeResult, TimestampGranularity, TransportHint, WatcherAvailability, WatcherCapabilities,
    WatcherScope,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FreeBsdProbe;

impl FreeBsdProbe {
    pub fn new() -> FreeBsdProbe {
        FreeBsdProbe
    }
}

impl DomainProbe for FreeBsdProbe {
    fn probe(&self, directory: &Path, parent: Option<&ProbeResult>) -> Result<ProbeResult, ProbeError> {
        let file = open_directory(directory)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() {
            return Err(ProbeError::NotDirectory);
        }

        let mut buffer = MaybeUninit::<libc::statfs>::uninit();
        let status = unsafe { libc::fstatfs(file.as_raw_fd(), buffer.as_mut_ptr()) };
        if status != 0 {
            return Err(ProbeError::from(std::io::Error::last_os_error()));
        }
        let stat = unsafe { buffer.assume_init() };
        let (first, second) = fsid_pair(stat.f_fsid);

        let identity = DomainIdentity::Known(DomainKey::fsid(first, second));
        let device = metadata.dev();
        let space = IdentitySpaceKey::unix_device(freebsd_major(device), freebsd_minor(device));
        let mount_point = c_string(&stat.f_mntonname);
        let local = stat.f_flags & libc::MNT_LOCAL != 0;
        let capabilities = capabilities_of(&c_string(&stat.f_fstypename), local, first, second, space);
        let crossed = crossing(parent, &identity, &capabilities.identity_space);
        let is_domain_root = at_mount_point(directory, &mount_point);

        Ok(ProbeResult { identity, capabilities, is_domain_root, crossed, directory_case: None })
    }
}

fn freebsd_major(device: u64) -> u64 {
    ((device >> 32) & 0xffff_ff00) | ((device >> 8) & 0xff)
}

fn freebsd_minor(device: u64) -> u64 {
    ((device >> 24) & 0xff00) | (device & 0xffff_00ff)
}

fn crossing(parent: Option<&ProbeResult>, identity: &DomainIdentity, space: &IdentitySpace) -> Crossing {
    let Some(parent) = parent else {
        return Crossing::NotCrossed;
    };
    let volumes = match (parent.identity.key(), identity.key()) {
        (Some(outer), Some(inner)) => Some(outer == inner),
        _ => None,
    };
    let devices = match (&parent.capabilities.identity_space, space) {
        (IdentitySpace::Known(outer), IdentitySpace::Known(inner)) => Some(outer == inner),
        _ => None,
    };
    match (volumes, devices) {
        (Some(false), _) | (_, Some(false)) => Crossing::Proven,
        (Some(true), Some(true)) => Crossing::NotCrossed,
        _ => Crossing::Inconclusive,
    }
}

fn capabilities_of(fs_type: &str, local: bool, first: i32, second: i32, space: IdentitySpaceKey) -> DomainCapabilities {
    let semantics = semantics_of(fs_type);
    let (topology, transport, media) = match fs_type {
        "tmpfs" => (AccessTopology::Local, TransportHint::Memory, MediaHint::Memory),
        "devfs" | "procfs" | "fdescfs" | "linprocfs" | "linsysfs" => {
            (AccessTopology::Virtual, TransportHint::Virtual, MediaHint::Unknown)
        }
        "fusefs" => (AccessTopology::Userspace, TransportHint::Unknown, MediaHint::Unknown),
        _ if local => (AccessTopology::Local, TransportHint::Unknown, MediaHint::Unknown),
        _ => (AccessTopology::Remote, TransportHint::Network, MediaHint::Unknown),
    };
    let case = case_of(fs_type);
    let reliability = reliability_of(fs_type, local);
    let external = match fs_type {
        "fusefs" => Answer::No,
        _ if local => Answer::Yes,
        _ => Answer::No,
    };
    DomainCapabilities {
        sources: DeclarationSources {
            filesystem: DeclarationSource::Detected,
            semantics: detected(semantics != FilesystemSemantics::Unknown),
            topology: DeclarationSource::Detected,
            transport: detected(transport != TransportHint::Unknown),
            media: detected(media != MediaHint::Unknown),
            case: declared(case != DomainCaseSensitivity::Unknown),
            timestamp_granularity: DeclarationSource::Unknown,
            identity_space: DeclarationSource::Detected,
            identity_reliability: declared(reliability != IdentityReliability::Unknown),
            observation: DeclarationSource::Declared,
            watcher: DeclarationSource::Declared,
        },
        filesystem: FilesystemInstance::Known(FilesystemInstanceKey::fsid(first, second)),
        semantics,
        topology,
        transport,
        media,
        case,
        timestamp_granularity: TimestampGranularity::Unknown,
        identity_space: IdentitySpace::Known(space),
        identity_reliability: reliability,
        kind_source: KindSource::Sometimes,
        identity_source: IdentitySource::Inline,
        metadata_sources: MetadataSources::PER_CHILD_READ,
        watcher: WatcherCapabilities {
            availability: WatcherAvailability::Available,
            scope: WatcherScope::PerDirectory,
            observes_external_writers: external,
            can_lose_events: Answer::Yes,
            signals_overflow: Answer::No,
            registration_gaps: Answer::Yes,
            polling_fallback_required: match external {
                Answer::Yes => Answer::No,
                Answer::No => Answer::Yes,
                Answer::Unknown => Answer::Unknown,
            },
        },
    }
}

fn detected(known: bool) -> DeclarationSource {
    if known { DeclarationSource::Detected } else { DeclarationSource::Unknown }
}

fn declared(known: bool) -> DeclarationSource {
    if known { DeclarationSource::Declared } else { DeclarationSource::Unknown }
}

fn semantics_of(fs_type: &str) -> FilesystemSemantics {
    match fs_type {
        "" => FilesystemSemantics::Unknown,
        "zfs" => FilesystemSemantics::Zfs,
        "ext2fs" => FilesystemSemantics::Ext4,
        "nfs" => FilesystemSemantics::Nfs,
        "smbfs" => FilesystemSemantics::Smb,
        "msdosfs" => FilesystemSemantics::Fat,
        "exfat" => FilesystemSemantics::ExFat,
        "ntfs" => FilesystemSemantics::Ntfs,
        "tmpfs" => FilesystemSemantics::Tmpfs,
        "fusefs" => FilesystemSemantics::Fuse,
        _ => FilesystemSemantics::Other(fs_type.to_owned()),
    }
}

fn case_of(fs_type: &str) -> DomainCaseSensitivity {
    match fs_type {
        "ufs" | "tmpfs" | "devfs" | "procfs" | "ext2fs" => DomainCaseSensitivity::Sensitive,
        "msdosfs" | "exfat" | "ntfs" => DomainCaseSensitivity::Insensitive,
        _ => DomainCaseSensitivity::Unknown,
    }
}

fn reliability_of(fs_type: &str, local: bool) -> IdentityReliability {
    match fs_type {
        "ufs" | "zfs" | "tmpfs" | "ext2fs" => IdentityReliability::Stable,
        "msdosfs" | "exfat" => IdentityReliability::None,
        "nfs" | "smbfs" | "fusefs" | "nullfs" | "unionfs" => IdentityReliability::Advisory,
        _ if local => IdentityReliability::Unknown,
        _ => IdentityReliability::Advisory,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(fs_type: &str, local: bool) -> DomainCapabilities {
        capabilities_of(fs_type, local, 1, 2, IdentitySpaceKey::unix_device(1, 2))
    }

    #[test]
    fn a_network_mount_is_remote_with_advisory_identity_and_no_view_of_external_writers() {
        let nfs = table("nfs", false);
        assert_eq!(nfs.semantics, FilesystemSemantics::Nfs);
        assert_eq!(nfs.topology, AccessTopology::Remote);
        assert_eq!(nfs.identity_reliability, IdentityReliability::Advisory);
        assert_eq!(nfs.watcher.observes_external_writers, Answer::No);
        assert_eq!(nfs.watcher.polling_fallback_required, Answer::Yes);
        assert_eq!(nfs.filesystem, FilesystemInstance::Known(FilesystemInstanceKey::fsid(1, 2)));
    }

    #[test]
    fn zfs_declares_stable_identity_and_unknown_case() {
        let zfs = table("zfs", true);
        assert_eq!(zfs.semantics, FilesystemSemantics::Zfs);
        assert_eq!(zfs.case, DomainCaseSensitivity::Unknown);
        assert_eq!(zfs.identity_reliability, IdentityReliability::Stable);
        assert_eq!(zfs.timestamp_granularity, TimestampGranularity::Unknown);
        assert_eq!(zfs.watcher.scope, WatcherScope::PerDirectory);
    }

    #[test]
    fn a_changed_fsid_or_device_proves_a_crossing() {
        let parent = ProbeResult {
            identity: DomainIdentity::Known(DomainKey::fsid(1, 2)),
            capabilities: table("ufs", true),
            ..ProbeResult::unknown()
        };
        let same = IdentitySpace::Known(IdentitySpaceKey::unix_device(1, 2));
        let other = IdentitySpace::Known(IdentitySpaceKey::unix_device(1, 3));
        assert_eq!(crossing(Some(&parent), &parent.identity, &same), Crossing::NotCrossed);
        assert_eq!(crossing(Some(&parent), &parent.identity, &other), Crossing::Proven);
        assert_eq!(crossing(Some(&parent), &DomainIdentity::Known(DomainKey::fsid(3, 4)), &same), Crossing::Proven);
        assert_eq!(crossing(Some(&parent), &DomainIdentity::Unknown, &IdentitySpace::Unknown), Crossing::Inconclusive);
    }
}
