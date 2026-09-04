use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use super::unix::{at_mount_point, c_string, fsid_pair, open_directory};
use super::{
    AccessTopology, Answer, Crossing, DeclarationSource, DeclarationSources, DomainCapabilities, DomainCaseSensitivity,
    DomainIdentity, DomainKey, DomainProbe, FilesystemInstance, FilesystemInstanceKey, FilesystemSemantics,
    IdentityReliability, IdentitySource, IdentitySpace, IdentitySpaceKey, KindSource, MediaHint, MetadataSources,
    ProbeError, ProbeResult, TimestampGranularity, TransportHint, WatcherAvailability, WatcherCapabilities,
    WatcherScope,
};

const MNT_REMOVABLE: u32 = 0x200;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MacOsProbe;

impl MacOsProbe {
    pub fn new() -> MacOsProbe {
        MacOsProbe
    }
}

impl DomainProbe for MacOsProbe {
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
        let space = IdentitySpaceKey::unix_device(darwin_major(device), darwin_minor(device));
        let flags = stat.f_flags;
        let mount_point = c_string(&stat.f_mntonname);
        let volume = Volume {
            fs_type: c_string(&stat.f_fstypename),
            local: flags & u32::from_ne_bytes(libc::MNT_LOCAL.to_ne_bytes()) != 0,
            removable: flags & MNT_REMOVABLE != 0,
            capabilities: volume_capabilities(&mount_point),
            instance: FilesystemInstanceKey::fsid(first, second),
            space,
        };
        let capabilities = capabilities_of(&volume);
        let crossed = crossing(parent, &identity, &capabilities.identity_space);
        let is_domain_root = at_mount_point(directory, &mount_point);

        Ok(ProbeResult { identity, capabilities, is_domain_root, crossed, directory_case: None })
    }
}

fn darwin_major(device: u64) -> u64 {
    (device >> 24) & 0xff
}

fn darwin_minor(device: u64) -> u64 {
    device & 0x00ff_ffff
}

#[repr(C)]
struct VolumeCapabilitiesReply {
    length: u32,
    capabilities: libc::vol_capabilities_attr_t,
}

fn volume_capabilities(mount_point: &str) -> Option<libc::vol_capabilities_attr_t> {
    let path = CString::new(mount_point).ok()?;
    let mut list = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_CAPABILITIES,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut reply = MaybeUninit::<VolumeCapabilitiesReply>::uninit();
    let status = unsafe {
        libc::getattrlist(
            path.as_ptr(),
            (&raw mut list).cast(),
            reply.as_mut_ptr().cast(),
            size_of::<VolumeCapabilitiesReply>(),
            libc::FSOPT_NOFOLLOW,
        )
    };
    if status != 0 {
        return None;
    }
    let reply = unsafe { reply.assume_init() };
    (usize::try_from(reply.length).ok()? >= size_of::<VolumeCapabilitiesReply>()).then_some(reply.capabilities)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VolumeBit {
    Set,
    Clear,
    Unknown,
}

fn format_bit(capabilities: Option<&libc::vol_capabilities_attr_t>, bit: u32) -> VolumeBit {
    let Some(capabilities) = capabilities else {
        return VolumeBit::Unknown;
    };
    let valid = capabilities.valid.get(libc::VOL_CAPABILITIES_FORMAT).copied().unwrap_or(0);
    let set = capabilities.capabilities.get(libc::VOL_CAPABILITIES_FORMAT).copied().unwrap_or(0);
    if valid & bit == 0 {
        VolumeBit::Unknown
    } else if set & bit != 0 {
        VolumeBit::Set
    } else {
        VolumeBit::Clear
    }
}

struct Volume {
    fs_type: String,
    local: bool,
    removable: bool,
    capabilities: Option<libc::vol_capabilities_attr_t>,
    instance: FilesystemInstanceKey,
    space: IdentitySpaceKey,
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

fn capabilities_of(volume: &Volume) -> DomainCapabilities {
    let semantics = semantics_of(&volume.fs_type);
    let topology = if volume.local { AccessTopology::Local } else { AccessTopology::Remote };
    let granularity = granularity_of(&volume.fs_type);
    let case = match format_bit(volume.capabilities.as_ref(), libc::VOL_CAP_FMT_CASE_SENSITIVE) {
        VolumeBit::Set => DomainCaseSensitivity::Sensitive,
        VolumeBit::Clear => DomainCaseSensitivity::Insensitive,
        VolumeBit::Unknown => DomainCaseSensitivity::Unknown,
    };
    let reliability = match format_bit(volume.capabilities.as_ref(), libc::VOL_CAP_FMT_PERSISTENTOBJECTIDS) {
        VolumeBit::Set => IdentityReliability::Stable,
        VolumeBit::Clear => IdentityReliability::None,
        VolumeBit::Unknown => reliability_of(&volume.fs_type),
    };
    let reliability_source = match format_bit(volume.capabilities.as_ref(), libc::VOL_CAP_FMT_PERSISTENTOBJECTIDS) {
        VolumeBit::Set | VolumeBit::Clear => DeclarationSource::Detected,
        VolumeBit::Unknown => declared(reliability != IdentityReliability::Unknown),
    };
    let media = if volume.removable { MediaHint::Removable } else { MediaHint::Unknown };
    let external = if volume.local { Answer::Yes } else { Answer::No };
    DomainCapabilities {
        sources: DeclarationSources {
            filesystem: DeclarationSource::Detected,
            semantics: DeclarationSource::Detected,
            topology: DeclarationSource::Detected,
            transport: if volume.local { DeclarationSource::Unknown } else { DeclarationSource::Detected },
            media: detected(media != MediaHint::Unknown),
            case: detected(case != DomainCaseSensitivity::Unknown),
            timestamp_granularity: declared(granularity != TimestampGranularity::Unknown),
            identity_space: DeclarationSource::Detected,
            identity_reliability: reliability_source,
            observation: DeclarationSource::Declared,
            watcher: DeclarationSource::Declared,
        },
        filesystem: FilesystemInstance::Known(volume.instance.clone()),
        semantics,
        topology,
        transport: if volume.local { TransportHint::Unknown } else { TransportHint::Network },
        media,
        case,
        timestamp_granularity: granularity,
        identity_space: IdentitySpace::Known(volume.space.clone()),
        identity_reliability: reliability,
        kind_source: KindSource::Sometimes,
        identity_source: IdentitySource::Inline,
        metadata_sources: MetadataSources::PER_CHILD_READ,
        watcher: WatcherCapabilities {
            availability: WatcherAvailability::Available,
            scope: WatcherScope::Recursive,
            observes_external_writers: external,
            can_lose_events: Answer::Yes,
            signals_overflow: Answer::Yes,
            registration_gaps: Answer::Unknown,
            polling_fallback_required: if volume.local { Answer::No } else { Answer::Yes },
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
        "apfs" => FilesystemSemantics::Apfs,
        "hfs" => FilesystemSemantics::HfsPlus,
        "nfs" => FilesystemSemantics::Nfs,
        "smbfs" => FilesystemSemantics::Smb,
        "exfat" => FilesystemSemantics::ExFat,
        "msdos" => FilesystemSemantics::Fat,
        "ntfs" => FilesystemSemantics::Ntfs,
        _ => FilesystemSemantics::Other(fs_type.to_owned()),
    }
}

fn granularity_of(fs_type: &str) -> TimestampGranularity {
    match fs_type {
        "hfs" => TimestampGranularity::Resolution(Duration::from_secs(1)),
        "exfat" => TimestampGranularity::Resolution(Duration::from_millis(10)),
        "msdos" => TimestampGranularity::Resolution(Duration::from_secs(2)),
        _ => TimestampGranularity::Unknown,
    }
}

fn reliability_of(fs_type: &str) -> IdentityReliability {
    match fs_type {
        "apfs" | "hfs" => IdentityReliability::Stable,
        "exfat" | "msdos" => IdentityReliability::None,
        "nfs" | "smbfs" | "webdav" => IdentityReliability::Advisory,
        _ => IdentityReliability::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(fs_type: &str, local: bool, capabilities: Option<libc::vol_capabilities_attr_t>) -> Volume {
        Volume {
            fs_type: fs_type.to_owned(),
            local,
            removable: false,
            capabilities,
            instance: FilesystemInstanceKey::fsid(1, 2),
            space: IdentitySpaceKey::unix_device(1, 2),
        }
    }

    fn bits(valid: u32, set: u32) -> libc::vol_capabilities_attr_t {
        libc::vol_capabilities_attr_t { capabilities: [set, 0, 0, 0], valid: [valid, 0, 0, 0] }
    }

    #[test]
    fn a_volume_capability_bit_answers_only_where_its_valid_bit_is_set() {
        let unknown = capabilities_of(&volume("apfs", true, Some(bits(0, libc::VOL_CAP_FMT_CASE_SENSITIVE))));
        assert_eq!(unknown.case, DomainCaseSensitivity::Unknown, "RFC 14.3: a bit without its valid bit is Unknown");
        assert_eq!(unknown.sources.case, DeclarationSource::Unknown);
        let sensitive = capabilities_of(&volume(
            "apfs",
            true,
            Some(bits(libc::VOL_CAP_FMT_CASE_SENSITIVE, libc::VOL_CAP_FMT_CASE_SENSITIVE)),
        ));
        assert_eq!(sensitive.case, DomainCaseSensitivity::Sensitive);
        assert_eq!(sensitive.sources.case, DeclarationSource::Detected);
        let insensitive = capabilities_of(&volume("apfs", true, Some(bits(libc::VOL_CAP_FMT_CASE_SENSITIVE, 0))));
        assert_eq!(insensitive.case, DomainCaseSensitivity::Insensitive);
        assert_eq!(capabilities_of(&volume("apfs", true, None)).case, DomainCaseSensitivity::Unknown);
    }

    #[test]
    fn persistent_object_ids_decide_identity_reliability_ahead_of_the_type_table() {
        let none = capabilities_of(&volume("apfs", true, Some(bits(libc::VOL_CAP_FMT_PERSISTENTOBJECTIDS, 0))));
        assert_eq!(none.identity_reliability, IdentityReliability::None);
        assert_eq!(none.sources.identity_reliability, DeclarationSource::Detected);
        let table = capabilities_of(&volume("apfs", true, None));
        assert_eq!(table.identity_reliability, IdentityReliability::Stable);
        assert_eq!(table.sources.identity_reliability, DeclarationSource::Declared);
        assert_eq!(capabilities_of(&volume("smbfs", false, None)).identity_reliability, IdentityReliability::Advisory);
    }

    #[test]
    fn a_volume_that_is_not_local_declares_no_view_of_external_writers() {
        let remote = capabilities_of(&volume("smbfs", false, None));
        assert_eq!(remote.topology, AccessTopology::Remote);
        assert_eq!(remote.transport, TransportHint::Network);
        assert_eq!(remote.watcher.observes_external_writers, Answer::No);
        assert_eq!(remote.watcher.polling_fallback_required, Answer::Yes);
        let local = capabilities_of(&volume("apfs", true, None));
        assert_eq!(local.topology, AccessTopology::Local);
        assert_eq!(local.watcher.observes_external_writers, Answer::Yes);
        assert_eq!(local.filesystem, FilesystemInstance::Known(FilesystemInstanceKey::fsid(1, 2)));
    }

    #[test]
    fn a_changed_device_or_fsid_proves_a_crossing() {
        let parent = ProbeResult {
            identity: DomainIdentity::Known(DomainKey::fsid(1, 2)),
            capabilities: capabilities_of(&volume("apfs", true, None)),
            ..ProbeResult::unknown()
        };
        let same = IdentitySpace::Known(IdentitySpaceKey::unix_device(1, 2));
        let other = IdentitySpace::Known(IdentitySpaceKey::unix_device(1, 3));
        assert_eq!(crossing(Some(&parent), &parent.identity, &same), Crossing::NotCrossed);
        assert_eq!(
            crossing(Some(&parent), &parent.identity, &other),
            Crossing::Proven,
            "RFC 14.3: a firmlink changes st_dev without a mount-table entry"
        );
        let volume_changed = DomainIdentity::Known(DomainKey::fsid(9, 9));
        assert_eq!(crossing(Some(&parent), &volume_changed, &same), Crossing::Proven);
        assert_eq!(crossing(Some(&parent), &DomainIdentity::Unknown, &IdentitySpace::Unknown), Crossing::Inconclusive);
        assert_eq!(crossing(None, &volume_changed, &other), Crossing::NotCrossed);
    }
}
