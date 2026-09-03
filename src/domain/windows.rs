use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ID_INFO, FILE_REMOTE_PROTOCOL_INFO, FileIdInfo, FileRemoteProtocolInfo, GetFileInformationByHandleEx,
    GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
};

use super::{
    AccessTopology, Answer, Crossing, DeclarationSource, DeclarationSources, DomainCapabilities, DomainCaseSensitivity,
    DomainIdentity, DomainKey, DomainProbe, FilesystemSemantics, IdentityReliability, IdentitySource, IdentitySpace,
    IdentitySpaceKey, KindSource, MediaHint, MetadataSource, MetadataSources, ProbeError, ProbeResult,
    TimestampGranularity, TransportHint, WatcherAvailability, WatcherCapabilities, WatcherScope,
};

const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_SHARE_ALL: u32 = 0x0000_0007;
const PATH_BUFFER: usize = 512;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowsProbe;

impl WindowsProbe {
    pub fn new() -> WindowsProbe {
        WindowsProbe
    }
}

impl DomainProbe for WindowsProbe {
    fn probe(&self, directory: &Path, parent: Option<&ProbeResult>) -> Result<ProbeResult, ProbeError> {
        let file = OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(directory)?;
        if !file.metadata()?.is_dir() {
            return Err(ProbeError::NotDirectory);
        }
        let handle: HANDLE = file.as_raw_handle();

        let mut ids = FILE_ID_INFO::default();
        let size = u32::try_from(size_of::<FILE_ID_INFO>())
            .map_err(|_| ProbeError::Unsupported("file id request size".to_owned()))?;
        let read = unsafe { GetFileInformationByHandleEx(handle, FileIdInfo, (&raw mut ids).cast(), size) };
        if read == 0 {
            return Err(ProbeError::from(std::io::Error::last_os_error()));
        }
        let serial = ids.VolumeSerialNumber;

        let mount_point = volume_path_name(directory);
        let identity = mount_point
            .as_deref()
            .and_then(volume_guid)
            .map_or(DomainIdentity::Unknown, |guid| DomainIdentity::Known(DomainKey::windows_volume_guid(guid)));
        let is_domain_root = mount_point.as_deref().is_some_and(|point| Path::new(point) == directory);
        let capabilities = capabilities_of(serial, remote(handle));
        let crossed = crossing(parent, serial);

        Ok(ProbeResult { identity, capabilities, is_domain_root, crossed })
    }
}

fn crossing(parent: Option<&ProbeResult>, serial: u64) -> Crossing {
    let Some(parent) = parent else {
        return Crossing::NotCrossed;
    };
    match &parent.capabilities.identity_space {
        IdentitySpace::Known(outer) if *outer == IdentitySpaceKey::windows_volume_serial(serial) => {
            Crossing::Inconclusive
        }
        IdentitySpace::Known(_) => Crossing::Proven,
        IdentitySpace::Unknown => Crossing::Inconclusive,
    }
}

fn remote(handle: HANDLE) -> bool {
    let Ok(size) = u32::try_from(size_of::<FILE_REMOTE_PROTOCOL_INFO>()) else {
        return false;
    };
    let mut protocol = FILE_REMOTE_PROTOCOL_INFO::default();
    let read =
        unsafe { GetFileInformationByHandleEx(handle, FileRemoteProtocolInfo, (&raw mut protocol).cast(), size) };
    read != 0
}

fn volume_path_name(directory: &Path) -> Option<String> {
    let mut buffer = vec![0u16; PATH_BUFFER];
    let target = wide(directory.as_os_str());
    let size = u32::try_from(buffer.len()).ok()?;
    let found = unsafe { GetVolumePathNameW(target.as_ptr(), buffer.as_mut_ptr(), size) };
    if found == 0 {
        return None;
    }
    Some(narrow(&buffer))
}

fn volume_guid(mount_point: &str) -> Option<String> {
    let point = wide(OsStr::new(mount_point));
    let mut name = vec![0u16; PATH_BUFFER];
    let size = u32::try_from(name.len()).ok()?;
    let named = unsafe { GetVolumeNameForVolumeMountPointW(point.as_ptr(), name.as_mut_ptr(), size) };
    if named == 0 {
        return None;
    }
    Some(narrow(&name))
}

fn wide(text: &OsStr) -> Vec<u16> {
    let mut units: Vec<u16> = text.encode_wide().collect();
    units.push(0);
    units
}

fn narrow(units: &[u16]) -> String {
    let end = units.iter().position(|unit| *unit == 0).unwrap_or(units.len());
    OsString::from_wide(&units[..end]).to_string_lossy().into_owned()
}

fn capabilities_of(serial: u64, remote: bool) -> DomainCapabilities {
    let topology = if remote { AccessTopology::Remote } else { AccessTopology::Unknown };
    DomainCapabilities {
        sources: DeclarationSources {
            semantics: DeclarationSource::Unknown,
            topology: if remote { DeclarationSource::Detected } else { DeclarationSource::Unknown },
            transport: DeclarationSource::Unknown,
            media: DeclarationSource::Unknown,
            case: DeclarationSource::Unknown,
            timestamp_granularity: DeclarationSource::Unknown,
            identity_space: DeclarationSource::Detected,
            identity_reliability: DeclarationSource::Unknown,
            observation: DeclarationSource::Declared,
            watcher: DeclarationSource::Declared,
        },
        semantics: FilesystemSemantics::Unknown,
        topology,
        transport: if remote { TransportHint::Network } else { TransportHint::Unknown },
        media: MediaHint::Unknown,
        case: DomainCaseSensitivity::Unknown,
        timestamp_granularity: TimestampGranularity::Unknown,
        identity_space: IdentitySpace::Known(IdentitySpaceKey::windows_volume_serial(serial)),
        identity_reliability: IdentityReliability::Unknown,
        kind_source: KindSource::Always,
        identity_source: IdentitySource::PerChildRead,
        metadata_sources: MetadataSources {
            modified: MetadataSource::Inline,
            created: MetadataSource::Inline,
            size: MetadataSource::Inline,
            permissions: MetadataSource::PerChildRead,
        },
        watcher: WatcherCapabilities {
            availability: WatcherAvailability::Available,
            scope: WatcherScope::Recursive,
            observes_external_writers: if remote { Answer::No } else { Answer::Unknown },
            can_lose_events: Answer::Yes,
            signals_overflow: Answer::Yes,
            registration_gaps: Answer::Unknown,
            polling_fallback_required: if remote { Answer::Yes } else { Answer::Unknown },
        },
    }
}
