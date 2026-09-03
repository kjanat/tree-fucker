use std::fs::File;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use super::{
    AccessTopology, Answer, Crossing, DeclarationSource, DeclarationSources, DomainCapabilities, DomainCaseSensitivity,
    DomainIdentity, DomainKey, DomainProbe, FilesystemSemantics, IdentityReliability, IdentitySource, IdentitySpace,
    IdentitySpaceKey, KindSource, MediaHint, MetadataSources, ProbeError, ProbeResult, TimestampGranularity,
    TransportHint, WatcherAvailability, WatcherCapabilities, WatcherScope,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MacOsProbe;

impl MacOsProbe {
    pub fn new() -> MacOsProbe {
        MacOsProbe
    }
}

impl DomainProbe for MacOsProbe {
    fn probe(&self, directory: &Path, parent: Option<&ProbeResult>) -> Result<ProbeResult, ProbeError> {
        let file = File::open(directory)?;
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
        let fsid: [i32; 2] = unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(stat.f_fsid) };

        let identity = DomainIdentity::Known(DomainKey::mac_fsid(fsid[0], fsid[1]));
        let device = metadata.dev();
        let space = IdentitySpaceKey::unix_device(darwin_major(device), darwin_minor(device));
        let local = stat.f_flags & u32::from_ne_bytes(libc::MNT_LOCAL.to_ne_bytes()) != 0;
        let capabilities = capabilities_of(c_string(&stat.f_fstypename), local, space);
        let crossed = crossing(parent, &identity, &capabilities.identity_space);
        let is_domain_root = at_mount_point(directory, &c_string(&stat.f_mntonname));

        Ok(ProbeResult { identity, capabilities, is_domain_root, crossed, directory_case: None })
    }
}

fn at_mount_point(directory: &Path, mount_point: &str) -> bool {
    match std::fs::canonicalize(directory) {
        Ok(resolved) => resolved == Path::new(mount_point),
        Err(_) => false,
    }
}

fn darwin_major(device: u64) -> u64 {
    (device >> 24) & 0xff
}

fn darwin_minor(device: u64) -> u64 {
    device & 0x00ff_ffff
}

fn c_string<const N: usize>(raw: &[libc::c_char; N]) -> String {
    let bytes: Vec<u8> = raw.iter().map(|value| u8::from_ne_bytes(value.to_ne_bytes())).collect();
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
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

fn capabilities_of(fs_type: String, local: bool, space: IdentitySpaceKey) -> DomainCapabilities {
    let semantics = semantics_of(&fs_type);
    let topology = if local { AccessTopology::Local } else { AccessTopology::Remote };
    let granularity = granularity_of(&fs_type);
    let reliability = reliability_of(&fs_type);
    let external = if local { Answer::Yes } else { Answer::No };
    DomainCapabilities {
        sources: DeclarationSources {
            semantics: DeclarationSource::Detected,
            topology: DeclarationSource::Detected,
            transport: DeclarationSource::Unknown,
            media: DeclarationSource::Unknown,
            case: DeclarationSource::Unknown,
            timestamp_granularity: if granularity == TimestampGranularity::Unknown {
                DeclarationSource::Unknown
            } else {
                DeclarationSource::Declared
            },
            identity_space: DeclarationSource::Detected,
            identity_reliability: if reliability == IdentityReliability::Unknown {
                DeclarationSource::Unknown
            } else {
                DeclarationSource::Declared
            },
            observation: DeclarationSource::Declared,
            watcher: DeclarationSource::Declared,
        },
        semantics,
        topology,
        transport: TransportHint::Unknown,
        media: MediaHint::Unknown,
        case: DomainCaseSensitivity::Unknown,
        timestamp_granularity: granularity,
        identity_space: IdentitySpace::Known(space),
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
            polling_fallback_required: if local { Answer::No } else { Answer::Yes },
        },
    }
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
