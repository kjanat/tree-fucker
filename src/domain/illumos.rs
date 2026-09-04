use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::unix::{c_string, open_directory};
use super::{
    AccessTopology, Answer, Crossing, DeclarationSource, DeclarationSources, DomainCapabilities, DomainCaseSensitivity,
    DomainIdentity, DomainKey, DomainProbe, FilesystemInstance, FilesystemInstanceKey, FilesystemSemantics,
    IdentityReliability, IdentitySource, IdentitySpace, IdentitySpaceKey, KindSource, MediaHint, MetadataSources,
    ProbeError, ProbeResult, TimestampGranularity, TransportHint, WatcherAvailability, WatcherCapabilities,
    WatcherScope,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IllumosProbe;

impl IllumosProbe {
    pub fn new() -> IllumosProbe {
        IllumosProbe
    }
}

impl DomainProbe for IllumosProbe {
    fn probe(&self, directory: &Path, parent: Option<&ProbeResult>) -> Result<ProbeResult, ProbeError> {
        let file = open_directory(directory)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() {
            return Err(ProbeError::NotDirectory);
        }

        let mut buffer = MaybeUninit::<libc::statvfs>::uninit();
        let status = unsafe { libc::fstatvfs(file.as_raw_fd(), buffer.as_mut_ptr()) };
        if status != 0 {
            return Err(ProbeError::from(std::io::Error::last_os_error()));
        }
        let stat = unsafe { buffer.assume_init() };
        let fsid = stat.f_fsid;

        let identity = DomainIdentity::Known(DomainKey::statvfs_fsid(fsid));
        let device = metadata.dev();
        let space = IdentitySpaceKey::unix_device(device >> 32, device & 0xffff_ffff);
        let capabilities = capabilities_of(&c_string(&stat.f_basetype), fsid, space);
        let crossed = crossing(parent, &identity);
        let is_domain_root = mount_root(directory, fsid);

        Ok(ProbeResult { identity, capabilities, is_domain_root, crossed, directory_case: None })
    }
}

fn parent_fsid(directory: &Path) -> Option<u64> {
    let parent = directory.parent()?;
    let file = open_directory(parent).ok()?;
    let mut buffer = MaybeUninit::<libc::statvfs>::uninit();
    let status = unsafe { libc::fstatvfs(file.as_raw_fd(), buffer.as_mut_ptr()) };
    (status == 0).then(|| unsafe { buffer.assume_init() }.f_fsid)
}

fn mount_root(directory: &Path, own: u64) -> bool {
    is_mount_root(parent_fsid(directory), own)
}

fn is_mount_root(parent: Option<u64>, own: u64) -> bool {
    match parent {
        Some(parent) => parent != own,
        None => true,
    }
}

fn crossing(parent: Option<&ProbeResult>, identity: &DomainIdentity) -> Crossing {
    let Some(parent) = parent else {
        return Crossing::NotCrossed;
    };
    match (parent.identity.key(), identity.key()) {
        (Some(outer), Some(inner)) if outer == inner => Crossing::NotCrossed,
        (Some(_), Some(_)) => Crossing::Proven,
        _ => Crossing::Inconclusive,
    }
}

fn capabilities_of(base_type: &str, fsid: u64, space: IdentitySpaceKey) -> DomainCapabilities {
    let semantics = semantics_of(base_type);
    let (topology, transport, media) = match base_type {
        "tmpfs" => (AccessTopology::Local, TransportHint::Memory, MediaHint::Memory),
        "proc" | "devfs" | "dev" | "fd" | "ctfs" | "objfs" | "sharefs" | "mntfs" | "bootfs" => {
            (AccessTopology::Virtual, TransportHint::Virtual, MediaHint::Unknown)
        }
        "nfs" | "smbfs" | "autofs" => (AccessTopology::Remote, TransportHint::Network, MediaHint::Unknown),
        "ufs" | "pcfs" | "hsfs" | "udfs" => (AccessTopology::Local, TransportHint::Unknown, MediaHint::Unknown),
        _ => (AccessTopology::Unknown, TransportHint::Unknown, MediaHint::Unknown),
    };
    let case = match base_type {
        "ufs" | "tmpfs" | "proc" => DomainCaseSensitivity::Sensitive,
        "pcfs" => DomainCaseSensitivity::Insensitive,
        _ => DomainCaseSensitivity::Unknown,
    };
    let reliability = match base_type {
        "zfs" | "ufs" | "tmpfs" => IdentityReliability::Stable,
        "pcfs" => IdentityReliability::None,
        "nfs" | "smbfs" | "lofs" | "autofs" => IdentityReliability::Advisory,
        _ => IdentityReliability::Unknown,
    };
    let external = match topology {
        AccessTopology::Local | AccessTopology::Virtual => Answer::Yes,
        AccessTopology::Remote | AccessTopology::Userspace | AccessTopology::ProtocolNative => Answer::No,
        AccessTopology::Unknown => match base_type {
            "zfs" => Answer::Yes,
            _ => Answer::Unknown,
        },
    };
    DomainCapabilities {
        sources: DeclarationSources {
            filesystem: DeclarationSource::Detected,
            semantics: detected(semantics != FilesystemSemantics::Unknown),
            topology: detected(topology != AccessTopology::Unknown),
            transport: detected(transport != TransportHint::Unknown),
            media: detected(media != MediaHint::Unknown),
            case: declared(case != DomainCaseSensitivity::Unknown),
            timestamp_granularity: DeclarationSource::Unknown,
            identity_space: DeclarationSource::Detected,
            identity_reliability: declared(reliability != IdentityReliability::Unknown),
            observation: DeclarationSource::Declared,
            watcher: DeclarationSource::Declared,
        },
        filesystem: FilesystemInstance::Known(FilesystemInstanceKey::statvfs_fsid(fsid)),
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

fn semantics_of(base_type: &str) -> FilesystemSemantics {
    match base_type {
        "" => FilesystemSemantics::Unknown,
        "zfs" => FilesystemSemantics::Zfs,
        "nfs" => FilesystemSemantics::Nfs,
        "smbfs" => FilesystemSemantics::Smb,
        "pcfs" => FilesystemSemantics::Fat,
        "tmpfs" => FilesystemSemantics::Tmpfs,
        _ => FilesystemSemantics::Other(base_type.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_is_a_domain_root_when_its_filesystem_differs_from_its_parents() {
        assert!(is_mount_root(None, 7), "RFC 14.3: a directory with no parent to compare is a domain root");
        assert!(is_mount_root(Some(3), 7), "a directory whose statvfs fsid differs from its parent's is a mount root");
        assert!(
            !is_mount_root(Some(7), 7),
            "a directory sharing its parent's filesystem is an ordinary directory, not a domain root"
        );
    }

    #[test]
    fn event_ports_are_declared_one_shot_per_directory_watchers() {
        let zfs = capabilities_of("zfs", 7, IdentitySpaceKey::unix_device(1, 2));
        assert_eq!(zfs.semantics, FilesystemSemantics::Zfs);
        assert_eq!(zfs.watcher.scope, WatcherScope::PerDirectory);
        assert_eq!(zfs.watcher.registration_gaps, Answer::Yes);
        assert_eq!(zfs.case, DomainCaseSensitivity::Unknown);
        assert_eq!(zfs.filesystem, FilesystemInstance::Known(FilesystemInstanceKey::statvfs_fsid(7)));
        let nfs = capabilities_of("nfs", 8, IdentitySpaceKey::unix_device(1, 3));
        assert_eq!(nfs.topology, AccessTopology::Remote);
        assert_eq!(nfs.watcher.observes_external_writers, Answer::No);
        assert_eq!(nfs.identity_reliability, IdentityReliability::Advisory);
    }
}
