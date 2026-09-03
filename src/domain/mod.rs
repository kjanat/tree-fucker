mod declared;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

pub use declared::{DeclaredProbe, UnknownProbe};
#[cfg(target_os = "linux")]
pub use linux::LinuxProbe;
#[cfg(target_os = "macos")]
pub use macos::MacOsProbe;
#[cfg(windows)]
pub use windows::WindowsProbe;

use crate::entry::MetadataFields;
use crate::path::CaseSensitivity;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StorageDomainId(u64);

static NEXT_STORAGE_DOMAIN: AtomicU64 = AtomicU64::new(1);
static INTERNED_DOMAINS: Mutex<BTreeMap<DomainKey, StorageDomainId>> = Mutex::new(BTreeMap::new());

impl StorageDomainId {
    pub fn fresh() -> StorageDomainId {
        StorageDomainId(NEXT_STORAGE_DOMAIN.fetch_add(1, Ordering::Relaxed))
    }

    pub fn of(key: &DomainKey) -> StorageDomainId {
        let mut interned = match INTERNED_DOMAINS.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match interned.get(key) {
            Some(id) => *id,
            None => {
                let id = StorageDomainId(NEXT_STORAGE_DOMAIN.fetch_add(1, Ordering::Relaxed));
                interned.insert(key.clone(), id);
                id
            }
        }
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for StorageDomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "storage domain {}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum DomainCrossing {
    Follow,
    Exclude,
    #[default]
    LoadOnDemand,
}

impl fmt::Display for DomainCrossing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainCrossing::Follow => f.write_str("follow"),
            DomainCrossing::Exclude => f.write_str("exclude"),
            DomainCrossing::LoadOnDemand => f.write_str("load on demand"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainKey(Key);

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Key {
    Declared(u64),
    #[cfg(target_os = "linux")]
    LinuxUniqueMount(u64),
    #[cfg(target_os = "linux")]
    LinuxReusableMount(u64),
    #[cfg(target_os = "linux")]
    LinuxDevice {
        major: u32,
        minor: u32,
    },
    #[cfg(target_os = "macos")]
    MacFsid {
        first: i32,
        second: i32,
    },
    #[cfg(windows)]
    WindowsVolumeGuid(String),
}

impl DomainKey {
    pub fn declared(id: u64) -> DomainKey {
        DomainKey(Key::Declared(id))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn linux_unique_mount(id: u64) -> DomainKey {
        DomainKey(Key::LinuxUniqueMount(id))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn linux_reusable_mount(id: u64) -> DomainKey {
        DomainKey(Key::LinuxReusableMount(id))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn linux_device(major: u32, minor: u32) -> DomainKey {
        DomainKey(Key::LinuxDevice { major, minor })
    }

    #[cfg(target_os = "macos")]
    pub(super) fn mac_fsid(first: i32, second: i32) -> DomainKey {
        DomainKey(Key::MacFsid { first, second })
    }

    #[cfg(windows)]
    pub(super) fn windows_volume_guid(guid: String) -> DomainKey {
        DomainKey(Key::WindowsVolumeGuid(guid))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IdentitySpaceKey(SpaceKey);

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum SpaceKey {
    Declared(u64),
    #[cfg(unix)]
    UnixDevice {
        major: u64,
        minor: u64,
    },
    #[cfg(windows)]
    WindowsVolumeSerial(u64),
}

impl IdentitySpaceKey {
    pub fn declared(id: u64) -> IdentitySpaceKey {
        IdentitySpaceKey(SpaceKey::Declared(id))
    }

    #[cfg(unix)]
    pub(super) fn unix_device(major: u64, minor: u64) -> IdentitySpaceKey {
        IdentitySpaceKey(SpaceKey::UnixDevice { major, minor })
    }

    #[cfg(windows)]
    pub(super) fn windows_volume_serial(serial: u64) -> IdentitySpaceKey {
        IdentitySpaceKey(SpaceKey::WindowsVolumeSerial(serial))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum DomainIdentity {
    Known(DomainKey),
    #[default]
    Unknown,
}

impl DomainIdentity {
    pub fn key(&self) -> Option<&DomainKey> {
        match self {
            DomainIdentity::Known(key) => Some(key),
            DomainIdentity::Unknown => None,
        }
    }

    pub fn is_known(&self) -> bool {
        matches!(self, DomainIdentity::Known(_))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum FilesystemSemantics {
    Ext4,
    Btrfs,
    Xfs,
    Zfs,
    Apfs,
    HfsPlus,
    Ntfs,
    ReFs,
    ExFat,
    Fat,
    Nfs,
    Smb,
    Fuse,
    Tmpfs,
    Overlay,
    Other(String),
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum AccessTopology {
    Local,
    Remote,
    Userspace,
    Virtual,
    ProtocolNative,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TransportHint {
    Nvme,
    Sata,
    Sas,
    Usb,
    Sd,
    Iscsi,
    FibreChannel,
    Network,
    Virtual,
    Memory,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum MediaHint {
    Rotational,
    SolidState,
    Removable,
    Optical,
    Memory,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum DomainCaseSensitivity {
    Sensitive,
    Insensitive,
    PerDirectory {
        domain_default: CaseSensitivity,
    },
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TimestampGranularity {
    Resolution(Duration),
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum IdentitySpace {
    Known(IdentitySpaceKey),
    #[default]
    Unknown,
}

impl IdentitySpace {
    pub fn comparable_with(&self, other: &IdentitySpace) -> bool {
        match (self, other) {
            (IdentitySpace::Known(a), IdentitySpace::Known(b)) => a == b,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum IdentityReliability {
    None,
    Advisory,
    Stable,
    #[default]
    Unknown,
}

impl IdentityReliability {
    pub fn establishes_rename(self) -> bool {
        matches!(self, IdentityReliability::Stable)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum KindSource {
    Always,
    Sometimes,
    Never,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum IdentitySource {
    Inline,
    PerChildRead,
    None,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum MetadataSource {
    Inline,
    PerChildRead,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MetadataSources {
    pub modified: MetadataSource,
    pub created: MetadataSource,
    pub size: MetadataSource,
    pub permissions: MetadataSource,
}

impl MetadataSources {
    pub const INLINE: MetadataSources = MetadataSources {
        modified: MetadataSource::Inline,
        created: MetadataSource::Inline,
        size: MetadataSource::Inline,
        permissions: MetadataSource::Inline,
    };
    pub const PER_CHILD_READ: MetadataSources = MetadataSources {
        modified: MetadataSource::PerChildRead,
        created: MetadataSource::PerChildRead,
        size: MetadataSource::PerChildRead,
        permissions: MetadataSource::PerChildRead,
    };

    pub fn inline(self) -> MetadataFields {
        MetadataFields {
            modified: self.modified == MetadataSource::Inline,
            created: self.created == MetadataSource::Inline,
            size: self.size == MetadataSource::Inline,
            permissions: self.permissions == MetadataSource::Inline,
        }
    }

    pub fn per_child_read(self) -> MetadataFields {
        MetadataFields {
            modified: self.modified == MetadataSource::PerChildRead,
            created: self.created == MetadataSource::PerChildRead,
            size: self.size == MetadataSource::PerChildRead,
            permissions: self.permissions == MetadataSource::PerChildRead,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Answer {
    Yes,
    No,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum WatcherAvailability {
    Available,
    Unavailable,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum WatcherScope {
    Recursive,
    PerDirectory,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct WatcherCapabilities {
    pub availability: WatcherAvailability,
    pub scope: WatcherScope,
    pub observes_external_writers: Answer,
    pub can_lose_events: Answer,
    pub signals_overflow: Answer,
    pub registration_gaps: Answer,
    pub polling_fallback_required: Answer,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum DeclarationSource {
    Detected,
    Declared,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DeclarationSources {
    pub semantics: DeclarationSource,
    pub topology: DeclarationSource,
    pub transport: DeclarationSource,
    pub media: DeclarationSource,
    pub case: DeclarationSource,
    pub timestamp_granularity: DeclarationSource,
    pub identity_space: DeclarationSource,
    pub identity_reliability: DeclarationSource,
    pub observation: DeclarationSource,
    pub watcher: DeclarationSource,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DomainCapabilities {
    pub semantics: FilesystemSemantics,
    pub topology: AccessTopology,
    pub transport: TransportHint,
    pub media: MediaHint,
    pub case: DomainCaseSensitivity,
    pub timestamp_granularity: TimestampGranularity,
    pub identity_space: IdentitySpace,
    pub identity_reliability: IdentityReliability,
    pub kind_source: KindSource,
    pub identity_source: IdentitySource,
    pub metadata_sources: MetadataSources,
    pub watcher: WatcherCapabilities,
    pub sources: DeclarationSources,
}

impl DomainCapabilities {
    pub fn inline() -> DomainCapabilities {
        DomainCapabilities {
            identity_reliability: IdentityReliability::Stable,
            kind_source: KindSource::Always,
            identity_source: IdentitySource::Inline,
            metadata_sources: MetadataSources::INLINE,
            sources: DeclarationSources {
                identity_space: DeclarationSource::Declared,
                identity_reliability: DeclarationSource::Declared,
                observation: DeclarationSource::Declared,
                ..DeclarationSources::default()
            },
            ..DomainCapabilities::default()
        }
    }

    pub fn identities_comparable(&self, other: &DomainCapabilities) -> bool {
        self.identity_space.comparable_with(&other.identity_space)
    }

    pub fn establishes_rename(&self, other: &DomainCapabilities) -> bool {
        self.identity_reliability.establishes_rename()
            && other.identity_reliability.establishes_rename()
            && self.identities_comparable(other)
    }

    pub fn same_storage_as(&self, parent: &DomainCapabilities) -> bool {
        self.semantics == parent.semantics
            && self.topology == parent.topology
            && self.transport == parent.transport
            && self.media == parent.media
            && self.identity_space == parent.identity_space
    }

    pub fn foreign_beneath(&self, parent: &DomainCapabilities) -> bool {
        if parent.topology != AccessTopology::Local {
            return false;
        }
        matches!(
            self.topology,
            AccessTopology::Remote | AccessTopology::Userspace | AccessTopology::Virtual | AccessTopology::Unknown
        ) || self.media == MediaHint::Removable
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Crossing {
    Proven,
    Inconclusive,
    NotCrossed,
}

impl Crossing {
    pub fn stronger(self, other: Crossing) -> Crossing {
        match (self, other) {
            (Crossing::Proven, _) | (_, Crossing::Proven) => Crossing::Proven,
            (Crossing::NotCrossed, Crossing::NotCrossed) => Crossing::NotCrossed,
            _ => Crossing::Inconclusive,
        }
    }

    pub fn between(parent: Option<&ProbeResult>, identity: &DomainIdentity) -> Crossing {
        let Some(parent) = parent else {
            return Crossing::NotCrossed;
        };
        match (parent.identity.key(), identity.key()) {
            (Some(a), Some(b)) if a == b => Crossing::NotCrossed,
            (Some(_), Some(_)) => Crossing::Proven,
            _ => Crossing::Inconclusive,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    pub identity: DomainIdentity,
    pub capabilities: DomainCapabilities,
    pub is_domain_root: bool,
    pub crossed: Crossing,
    pub directory_case: Option<CaseSensitivity>,
}

impl ProbeResult {
    pub fn unknown() -> ProbeResult {
        ProbeResult {
            identity: DomainIdentity::Unknown,
            capabilities: DomainCapabilities::default(),
            is_domain_root: false,
            crossed: Crossing::Inconclusive,
            directory_case: None,
        }
    }

    pub fn case(&self) -> Option<CaseSensitivity> {
        match self.capabilities.case {
            DomainCaseSensitivity::Sensitive => Some(CaseSensitivity::Sensitive),
            DomainCaseSensitivity::Insensitive => Some(CaseSensitivity::Insensitive),
            DomainCaseSensitivity::PerDirectory { domain_default } => {
                Some(self.directory_case.unwrap_or(domain_default))
            }
            DomainCaseSensitivity::Unknown => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    NotFound,
    NotDirectory,
    PermissionDenied,
    Transient(String),
    Unsupported(String),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeError::NotFound => f.write_str("not found"),
            ProbeError::NotDirectory => f.write_str("not a directory"),
            ProbeError::PermissionDenied => f.write_str("permission denied"),
            ProbeError::Transient(m) => write!(f, "transient failure: {m}"),
            ProbeError::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl std::error::Error for ProbeError {}

impl From<std::io::Error> for ProbeError {
    fn from(err: std::io::Error) -> ProbeError {
        use std::io::ErrorKind;
        match err.kind() {
            ErrorKind::NotFound => ProbeError::NotFound,
            ErrorKind::NotADirectory => ProbeError::NotDirectory,
            ErrorKind::PermissionDenied => ProbeError::PermissionDenied,
            ErrorKind::Unsupported => ProbeError::Unsupported(err.to_string()),
            _ => ProbeError::Transient(err.to_string()),
        }
    }
}

pub trait DomainProbe: Send + Sync {
    fn probe(&self, directory: &Path, parent: Option<&ProbeResult>) -> Result<ProbeResult, ProbeError>;
}
