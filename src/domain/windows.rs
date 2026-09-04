use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_CASE_SENSITIVE_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
    FILE_REMOTE_PROTOCOL_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileCaseSensitiveInfo, FileIdInfo,
    FileRemoteProtocolInfo, GetFileInformationByHandleEx, GetVolumeInformationByHandleW,
    GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
};
use windows_sys::Win32::System::SystemServices::{FILE_CS_FLAG_CASE_SENSITIVE_DIR, FILE_SUPPORTS_OPEN_BY_FILE_ID};

use super::{
    AccessTopology, Answer, Crossing, DeclarationSource, DeclarationSources, DomainCapabilities, DomainCaseSensitivity,
    DomainIdentity, DomainKey, DomainProbe, FilesystemInstance, FilesystemInstanceKey, FilesystemSemantics,
    IdentityReliability, IdentitySource, IdentitySpace, IdentitySpaceKey, KindSource, MediaHint, MetadataSource,
    MetadataSources, ProbeError, ProbeResult, TimestampGranularity, TransportHint, WatcherAvailability,
    WatcherCapabilities, WatcherScope,
};
use crate::entry::FileIdentity;
use crate::fs::FsError;
use crate::path::CaseSensitivity;

const FILE_SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const PATH_BUFFER: usize = 512;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowsProbe;

impl WindowsProbe {
    pub fn new() -> WindowsProbe {
        WindowsProbe
    }
}

fn open_object(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

fn file_id_info(handle: HANDLE) -> std::io::Result<FILE_ID_INFO> {
    let mut ids = FILE_ID_INFO::default();
    let size = u32::try_from(size_of::<FILE_ID_INFO>())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Unsupported, "file id request size"))?;
    let read = unsafe { GetFileInformationByHandleEx(handle, FileIdInfo, (&raw mut ids).cast(), size) };
    if read == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ids)
}

pub(crate) fn file_identity(path: &Path) -> Result<Option<FileIdentity>, FsError> {
    let file = open_object(path)?;
    let ids = file_id_info(file.as_raw_handle())?;
    let inode = u128::from_le_bytes(ids.FileId.Identifier);
    Ok((inode != 0).then_some(FileIdentity { device: ids.VolumeSerialNumber, inode }))
}

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

fn is_reparse_point(attributes: u32) -> bool {
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

impl DomainProbe for WindowsProbe {
    fn probe(&self, directory: &Path, parent: Option<&ProbeResult>) -> Result<ProbeResult, ProbeError> {
        use std::os::windows::fs::MetadataExt;
        let file = open_object(directory)?;
        let metadata = file.metadata()?;
        if is_reparse_point(metadata.file_attributes()) {
            return Err(ProbeError::NotDirectory);
        }
        if !metadata.is_dir() {
            return Err(ProbeError::NotDirectory);
        }
        let handle: HANDLE = file.as_raw_handle();

        let serial = file_id_info(handle)?.VolumeSerialNumber;
        let mount_point = volume_path_name(directory);
        let identity = mount_point
            .as_deref()
            .and_then(volume_guid)
            .map_or(DomainIdentity::Unknown, |guid| DomainIdentity::Known(DomainKey::windows_volume_guid(guid)));
        let is_domain_root = mount_point.as_deref().is_some_and(|point| Path::new(point) == directory);
        let volume = Volume {
            serial,
            remote: remote(handle),
            information: volume_information(handle),
            directory_case: directory_case(handle),
        };
        let capabilities = capabilities_of(&volume);
        let directory_case = volume.directory_case;
        let crossed = crossing(parent, serial);

        Ok(ProbeResult { identity, capabilities, is_domain_root, crossed, directory_case })
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

fn directory_case(handle: HANDLE) -> Option<CaseSensitivity> {
    let size = u32::try_from(size_of::<FILE_CASE_SENSITIVE_INFO>()).ok()?;
    let mut info = FILE_CASE_SENSITIVE_INFO::default();
    let read = unsafe { GetFileInformationByHandleEx(handle, FileCaseSensitiveInfo, (&raw mut info).cast(), size) };
    if read == 0 {
        return None;
    }
    Some(if info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0 {
        CaseSensitivity::Sensitive
    } else {
        CaseSensitivity::Insensitive
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VolumeInformation {
    name: String,
    flags: u32,
}

fn volume_information(handle: HANDLE) -> Option<VolumeInformation> {
    let mut name = vec![0u16; PATH_BUFFER];
    let size = u32::try_from(name.len()).ok()?;
    let mut serial: u32 = 0;
    let mut component_length: u32 = 0;
    let mut flags: u32 = 0;
    let read = unsafe {
        GetVolumeInformationByHandleW(
            handle,
            std::ptr::null_mut(),
            0,
            &raw mut serial,
            &raw mut component_length,
            &raw mut flags,
            name.as_mut_ptr(),
            size,
        )
    };
    if read == 0 {
        return None;
    }
    Some(VolumeInformation { name: narrow(&name), flags })
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

struct Volume {
    serial: u64,
    remote: bool,
    information: Option<VolumeInformation>,
    directory_case: Option<CaseSensitivity>,
}

fn semantics_of(name: &str) -> FilesystemSemantics {
    match name.to_ascii_uppercase().as_str() {
        "" => FilesystemSemantics::Unknown,
        "NTFS" => FilesystemSemantics::Ntfs,
        "REFS" => FilesystemSemantics::ReFs,
        "FAT" | "FAT12" | "FAT16" | "FAT32" => FilesystemSemantics::Fat,
        "EXFAT" => FilesystemSemantics::ExFat,
        _ => FilesystemSemantics::Other(name.to_owned()),
    }
}

fn capabilities_of(volume: &Volume) -> DomainCapabilities {
    let semantics = volume.information.as_ref().map_or(FilesystemSemantics::Unknown, |info| semantics_of(&info.name));
    let flags = volume.information.as_ref().map(|info| info.flags);
    let open_by_id = flags.map(|flags| flags & FILE_SUPPORTS_OPEN_BY_FILE_ID != 0);
    let reliability = match (&semantics, open_by_id, volume.remote) {
        (FilesystemSemantics::Ntfs | FilesystemSemantics::ReFs, Some(true), false) => IdentityReliability::Stable,
        (FilesystemSemantics::Fat | FilesystemSemantics::ExFat, _, _) => IdentityReliability::None,
        (_, Some(false), _) => IdentityReliability::None,
        (_, _, true) => IdentityReliability::Advisory,
        (_, _, false) => IdentityReliability::Unknown,
    };
    let identity_source = match open_by_id {
        Some(true) => IdentitySource::PerChildRead,
        Some(false) => IdentitySource::None,
        None => IdentitySource::Unknown,
    };
    let case = match (volume.directory_case, &semantics) {
        (Some(_), _) => DomainCaseSensitivity::PerDirectory { domain_default: CaseSensitivity::Insensitive },
        (None, FilesystemSemantics::Fat | FilesystemSemantics::ExFat) => DomainCaseSensitivity::Insensitive,
        (None, _) => DomainCaseSensitivity::Unknown,
    };
    let topology = if volume.remote { AccessTopology::Remote } else { AccessTopology::Unknown };
    DomainCapabilities {
        sources: DeclarationSources {
            filesystem: DeclarationSource::Detected,
            semantics: detected(semantics != FilesystemSemantics::Unknown),
            topology: detected(topology != AccessTopology::Unknown),
            transport: detected(volume.remote),
            media: DeclarationSource::Unknown,
            case: match (volume.directory_case, case) {
                (Some(_), _) => DeclarationSource::Detected,
                (None, DomainCaseSensitivity::Unknown) => DeclarationSource::Unknown,
                (None, _) => DeclarationSource::Declared,
            },
            timestamp_granularity: DeclarationSource::Unknown,
            identity_space: DeclarationSource::Detected,
            identity_reliability: match (open_by_id, reliability) {
                (_, IdentityReliability::Unknown) => DeclarationSource::Unknown,
                (Some(_), _) => DeclarationSource::Detected,
                (None, _) => DeclarationSource::Declared,
            },
            observation: DeclarationSource::Declared,
            watcher: DeclarationSource::Declared,
        },
        filesystem: FilesystemInstance::Known(FilesystemInstanceKey::windows_volume_serial(volume.serial)),
        semantics,
        topology,
        transport: if volume.remote { TransportHint::Network } else { TransportHint::Unknown },
        media: MediaHint::Unknown,
        case,
        timestamp_granularity: TimestampGranularity::Unknown,
        identity_space: IdentitySpace::Known(IdentitySpaceKey::windows_volume_serial(volume.serial)),
        identity_reliability: reliability,
        kind_source: KindSource::Always,
        identity_source,
        metadata_sources: MetadataSources {
            modified: MetadataSource::Inline,
            created: MetadataSource::Inline,
            size: MetadataSource::Inline,
            permissions: MetadataSource::PerChildRead,
        },
        watcher: WatcherCapabilities {
            availability: WatcherAvailability::Available,
            scope: WatcherScope::Recursive,
            observes_external_writers: if volume.remote { Answer::No } else { Answer::Unknown },
            can_lose_events: Answer::Yes,
            signals_overflow: Answer::Yes,
            registration_gaps: Answer::Unknown,
            polling_fallback_required: if volume.remote { Answer::Yes } else { Answer::Unknown },
        },
    }
}

fn detected(known: bool) -> DeclarationSource {
    if known { DeclarationSource::Detected } else { DeclarationSource::Unknown }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(name: Option<(&str, u32)>, remote: bool, directory_case: Option<CaseSensitivity>) -> Volume {
        Volume {
            serial: 7,
            remote,
            information: name.map(|(name, flags)| VolumeInformation { name: name.to_owned(), flags }),
            directory_case,
        }
    }

    #[test]
    fn a_serial_mismatch_proves_a_crossing_and_equality_is_inconclusive() {
        let parent =
            ProbeResult { capabilities: capabilities_of(&volume(None, false, None)), ..ProbeResult::unknown() };
        assert_eq!(
            crossing(Some(&parent), 7),
            Crossing::Inconclusive,
            "RFC 14.3: the serial is not required to be unique"
        );
        assert_eq!(crossing(Some(&parent), 8), Crossing::Proven);
        assert_eq!(crossing(None, 8), Crossing::NotCrossed);
        let unknown = ProbeResult::unknown();
        assert_eq!(crossing(Some(&unknown), 8), Crossing::Inconclusive);
    }

    #[test]
    fn ntfs_with_open_by_file_id_declares_stable_per_child_identity_and_per_directory_case() {
        use windows_sys::Win32::System::SystemServices::{FILE_CASE_PRESERVED_NAMES, FILE_CASE_SENSITIVE_SEARCH};
        let ntfs_flags = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES | FILE_SUPPORTS_OPEN_BY_FILE_ID;
        let ntfs = capabilities_of(&volume(Some(("NTFS", ntfs_flags)), false, Some(CaseSensitivity::Insensitive)));
        assert_eq!(ntfs.semantics, FilesystemSemantics::Ntfs);
        assert_eq!(ntfs.identity_reliability, IdentityReliability::Stable);
        assert_eq!(ntfs.identity_source, IdentitySource::PerChildRead);
        assert_eq!(
            ntfs.case,
            DomainCaseSensitivity::PerDirectory { domain_default: CaseSensitivity::Insensitive },
            "RFC 14.3: NTFS reports FILE_CASE_SENSITIVE_SEARCH set on every volume, but Windows lookup is \
             case-insensitive unless a directory opts in, so the per-directory default is Insensitive"
        );
        assert_eq!(ntfs.sources.case, DeclarationSource::Detected);
        assert_eq!(ntfs.filesystem, FilesystemInstance::Known(FilesystemInstanceKey::windows_volume_serial(7)));
        let refs = capabilities_of(&volume(Some(("ReFS", FILE_SUPPORTS_OPEN_BY_FILE_ID)), false, None));
        assert_eq!(refs.semantics, FilesystemSemantics::ReFs);
        assert!(is_reparse_point(FILE_ATTRIBUTE_REPARSE_POINT | 0x10), "RFC 14.2: a reparse point is never traversed");
        assert!(!is_reparse_point(0x10));
        assert_eq!(
            refs.identity_reliability,
            IdentityReliability::Stable,
            "RFC 14.3: ReFS MAY declare stable identity"
        );
    }

    #[test]
    fn a_volume_whose_management_calls_fail_declares_unknown_and_a_remote_one_advisory() {
        let unknown = capabilities_of(&volume(None, false, None));
        assert_eq!(unknown.semantics, FilesystemSemantics::Unknown);
        assert_eq!(unknown.case, DomainCaseSensitivity::Unknown);
        assert_eq!(unknown.identity_reliability, IdentityReliability::Unknown);
        assert_eq!(unknown.identity_source, IdentitySource::Unknown);
        assert_eq!(unknown.sources.semantics, DeclarationSource::Unknown);
        let remote = capabilities_of(&volume(None, true, None));
        assert_eq!(remote.topology, AccessTopology::Remote);
        assert_eq!(remote.identity_reliability, IdentityReliability::Advisory);
        assert_eq!(remote.watcher.observes_external_writers, Answer::No);
        assert_eq!(
            (remote.watcher.can_lose_events, remote.watcher.polling_fallback_required),
            (Answer::Yes, Answer::Yes),
            "RFC 10.4 and 14.3: ReadDirectoryChangesW over the network can lose events and requires polling fallback"
        );
        assert_eq!(unknown.watcher.can_lose_events, Answer::Yes, "RFC 10.4: the local watcher can also overflow");
        let fat = capabilities_of(&volume(Some(("FAT32", 0)), false, None));
        assert_eq!(fat.semantics, FilesystemSemantics::Fat);
        assert_eq!(fat.identity_reliability, IdentityReliability::None);
        assert_eq!(fat.case, DomainCaseSensitivity::Insensitive);
    }
}
