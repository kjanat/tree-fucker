//! This module identifies storage domains and probes their capabilities (RFC
//! §10.3, §14.3).
//!
//! A storage domain is a mount instance as traversal reaches it. A
//! [`DomainProbe`] reports the [`DomainIdentity`] and [`DomainCapabilities`]
//! of a directory. It also reports whether the step from the parent crossed
//! into another domain. The tree applies the configured [`DomainCrossing`]
//! mode at each crossing. Each platform exports its own probe.
//! [`DeclaredProbe`] returns fixed declarations, and [`UnknownProbe`]
//! answers Unknown for every field.

#[cfg(target_os = "freebsd")]
mod bsd;
mod declared;
#[cfg(any(target_os = "illumos", target_os = "solaris"))]
mod illumos;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(test)]
mod tests;
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "illumos", target_os = "solaris"))]
mod unix;
#[cfg(windows)]
mod windows;

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[cfg(target_os = "freebsd")]
pub use bsd::FreeBsdProbe;
pub use declared::{DeclaredProbe, UnknownProbe};
#[cfg(any(target_os = "illumos", target_os = "solaris"))]
pub use illumos::IllumosProbe;
#[cfg(target_os = "linux")]
pub use linux::LinuxProbe;
#[cfg(target_os = "macos")]
pub use macos::MacOsProbe;
#[cfg(windows)]
pub use windows::WindowsProbe;
#[cfg(windows)]
pub(crate) use windows::file_identity as windows_file_identity;

use crate::entry::MetadataFields;
use crate::path::CaseSensitivity;

/// `StorageDomainId` identifies one storage domain across the process.
///
/// Every tree in the process maps equal [`DomainKey`]s to one id. The
/// resource governor keys per-domain budgets and concurrency by this id
/// (RFC §15.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StorageDomainId(u64);

static NEXT_STORAGE_DOMAIN: AtomicU64 = AtomicU64::new(1);
static INTERNED_DOMAINS: Mutex<BTreeMap<DomainKey, StorageDomainId>> = Mutex::new(BTreeMap::new());

impl StorageDomainId {
    /// `fresh` allocates an unused id.
    ///
    /// Callers use it for a domain without a [`DomainKey`].
    pub fn fresh() -> StorageDomainId {
        StorageDomainId(NEXT_STORAGE_DOMAIN.fetch_add(1, Ordering::Relaxed))
    }

    /// `of` returns the interned id of `key` and allocates one on first use.
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

    /// `get` returns the raw value.
    pub fn get(self) -> u64 {
        self.0
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn unique_mount(self) -> Option<u64> {
        let interned = INTERNED_DOMAINS.lock().unwrap_or_else(|error| error.into_inner());
        interned.iter().find_map(|(key, id)| match (id == &self, &key.0) {
            (true, Key::LinuxUniqueMount(mount)) => Some(*mount),
            _ => None,
        })
    }
}

impl fmt::Display for StorageDomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "storage domain {}", self.0)
    }
}

/// `DomainCrossing` selects the tree's action where traversal enters another
/// storage domain (RFC §14.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum DomainCrossing {
    /// The tree traverses the child domain under its own capabilities, budgets
    /// and concurrency window. The tree goes all the way in.
    Follow,
    /// The tree represents the mount point as an Excluded directory and never
    /// reads its descendants.
    Exclude,
    /// The tree represents the mount point as an Unloaded directory until a
    /// `load` or a policy decision names it.
    ///
    /// `LoadOnDemand` is the default.
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

/// `DomainKey` names one storage domain from positive evidence (RFC §14.3).
///
/// Equal keys name the same domain, and [`StorageDomainId::of`] interns
/// them. Platform probes build keys from the Linux unique mount id, the
/// macOS and FreeBSD `f_fsid`, the illumos `statvfs` fsid, or the Windows
/// volume GUID path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainKey(Key);

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Key {
    Declared(u64),
    #[cfg(target_os = "linux")]
    LinuxUniqueMount(u64),
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    Fsid {
        first: i32,
        second: i32,
    },
    #[cfg(any(target_os = "illumos", target_os = "solaris"))]
    StatvfsFsid(u64),
    #[cfg(windows)]
    WindowsVolumeGuid(String),
}

impl DomainKey {
    /// `declared` builds a key from an adapter-declared value.
    ///
    /// Distinct values name distinct domains.
    pub fn declared(id: u64) -> DomainKey {
        DomainKey(Key::Declared(id))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn linux_unique_mount(id: u64) -> DomainKey {
        DomainKey(Key::LinuxUniqueMount(id))
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    pub(super) fn fsid(first: i32, second: i32) -> DomainKey {
        DomainKey(Key::Fsid { first, second })
    }

    #[cfg(any(target_os = "illumos", target_os = "solaris"))]
    pub(super) fn statvfs_fsid(id: u64) -> DomainKey {
        DomainKey(Key::StatvfsFsid(id))
    }

    #[cfg(windows)]
    pub(super) fn windows_volume_guid(guid: String) -> DomainKey {
        DomainKey(Key::WindowsVolumeGuid(guid))
    }
}

/// `WeakDomainKey` names a domain with a reusable platform key.
///
/// The platform can reuse the key after the domain disappears.
/// [`DomainIdentity::crossing_from`] compares two weak keys like two strong
/// ones. A weak key never interns into a [`StorageDomainId`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WeakDomainKey(WeakKey);

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum WeakKey {
    #[cfg(target_os = "linux")]
    LinuxReusableMount(u64),
    #[cfg(target_os = "linux")]
    LinuxDevice { major: u32, minor: u32 },
}

impl WeakDomainKey {
    /// `linux_reusable_mount` builds a key from a reusable Linux mount id.
    #[cfg(target_os = "linux")]
    pub fn linux_reusable_mount(id: u64) -> WeakDomainKey {
        WeakDomainKey(WeakKey::LinuxReusableMount(id))
    }

    /// `linux_device` builds a key from the device number of a Linux mount.
    #[cfg(target_os = "linux")]
    pub fn linux_device(major: u32, minor: u32) -> WeakDomainKey {
        WeakDomainKey(WeakKey::LinuxDevice { major, minor })
    }
}

/// `FilesystemInstanceKey` names the filesystem instance behind a domain.
///
/// The instance supplies the semantics of the domain. A bind mount and its
/// origin share one instance key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FilesystemInstanceKey(InstanceKey);

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum InstanceKey {
    Declared(u64),
    #[cfg(target_os = "linux")]
    LinuxSuperblock {
        major: u32,
        minor: u32,
    },
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    Fsid {
        first: i32,
        second: i32,
    },
    #[cfg(any(target_os = "illumos", target_os = "solaris"))]
    StatvfsFsid(u64),
    #[cfg(windows)]
    WindowsVolumeSerial(u64),
}

impl FilesystemInstanceKey {
    /// `declared` builds a key from an adapter-declared value.
    ///
    /// Distinct values name distinct instances.
    pub fn declared(id: u64) -> FilesystemInstanceKey {
        FilesystemInstanceKey(InstanceKey::Declared(id))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn linux_superblock(major: u32, minor: u32) -> FilesystemInstanceKey {
        FilesystemInstanceKey(InstanceKey::LinuxSuperblock { major, minor })
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    pub(super) fn fsid(first: i32, second: i32) -> FilesystemInstanceKey {
        FilesystemInstanceKey(InstanceKey::Fsid { first, second })
    }

    #[cfg(any(target_os = "illumos", target_os = "solaris"))]
    pub(super) fn statvfs_fsid(id: u64) -> FilesystemInstanceKey {
        FilesystemInstanceKey(InstanceKey::StatvfsFsid(id))
    }

    #[cfg(windows)]
    pub(super) fn windows_volume_serial(serial: u64) -> FilesystemInstanceKey {
        FilesystemInstanceKey(InstanceKey::WindowsVolumeSerial(serial))
    }
}

/// `FilesystemInstance` holds the filesystem instance behind a domain when the
/// platform exposes it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum FilesystemInstance {
    /// The probe identified the instance.
    Known(FilesystemInstanceKey),
    /// The probe could not identify the instance, and this variant is the
    /// default.
    #[default]
    Unknown,
}

impl FilesystemInstance {
    /// `same_as` reports whether both values name the same known instance.
    ///
    /// [`FilesystemInstance::Unknown`] never matches, even against itself.
    pub fn same_as(&self, other: &FilesystemInstance) -> bool {
        match (self, other) {
            (FilesystemInstance::Known(a), FilesystemInstance::Known(b)) => a == b,
            _ => false,
        }
    }
}

/// `IdentitySpaceKey` names a namespace for comparable file identities (RFC
/// §7.1).
///
/// A bind mount and its origin share one identity space. Each Btrfs
/// subvolume forms its own identity space.
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
    /// `declared` builds a key from an adapter-declared value.
    ///
    /// Distinct values name distinct spaces.
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

/// `DomainIdentity` holds the identity of a storage domain as a probe
/// established it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum DomainIdentity {
    /// The probe found a [`DomainKey`].
    Known(DomainKey),
    /// The probe found only a [`WeakDomainKey`].
    Weak(WeakDomainKey),
    /// The probe could not identify the domain, and this variant is the
    /// default.
    #[default]
    Unknown,
}

impl DomainIdentity {
    /// `key` returns the key of a [`DomainIdentity::Known`] identity.
    pub fn key(&self) -> Option<&DomainKey> {
        match self {
            DomainIdentity::Known(key) => Some(key),
            DomainIdentity::Weak(_) | DomainIdentity::Unknown => None,
        }
    }

    /// `weak` returns the key of a [`DomainIdentity::Weak`] identity.
    pub fn weak(&self) -> Option<&WeakDomainKey> {
        match self {
            DomainIdentity::Weak(key) => Some(key),
            DomainIdentity::Known(_) | DomainIdentity::Unknown => None,
        }
    }

    /// `is_known` reports whether this is a [`DomainIdentity::Known`] identity.
    pub fn is_known(&self) -> bool {
        matches!(self, DomainIdentity::Known(_))
    }

    /// `crossing_from` judges whether this identity lies in another domain than
    /// `outer`.
    ///
    /// The caller passes the identity of the parent as `outer`. Two keys of the
    /// same strength decide the verdict. Equal keys give
    /// [`Crossing::NotCrossed`], and different keys give [`Crossing::Proven`].
    /// Any other pair gives [`Crossing::Inconclusive`].
    pub fn crossing_from(&self, outer: &DomainIdentity) -> Crossing {
        let same = match (outer, self) {
            (DomainIdentity::Known(outer), DomainIdentity::Known(inner)) => outer == inner,
            (DomainIdentity::Weak(outer), DomainIdentity::Weak(inner)) => outer == inner,
            _ => return Crossing::Inconclusive,
        };
        match same {
            true => Crossing::NotCrossed,
            false => Crossing::Proven,
        }
    }
}

/// `FilesystemSemantics` names the filesystem type of a domain (RFC §10.3).
///
/// The type carries no performance claim.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum FilesystemSemantics {
    /// The domain uses Linux ext4.
    Ext4,
    /// The domain uses Btrfs, and each subvolume forms its own identity space.
    Btrfs,
    /// The domain uses XFS.
    Xfs,
    /// The domain uses ZFS.
    Zfs,
    /// The domain uses Apple APFS.
    Apfs,
    /// The domain uses Apple HFS+.
    HfsPlus,
    /// The domain uses Microsoft NTFS.
    Ntfs,
    /// The domain uses Microsoft ReFS.
    ReFs,
    /// The domain uses exFAT.
    ExFat,
    /// The domain uses FAT or VFAT.
    Fat,
    /// The domain is an NFS mount.
    Nfs,
    /// The domain is an SMB or CIFS mount.
    Smb,
    /// The domain is a FUSE filesystem.
    Fuse,
    /// The domain uses Linux tmpfs.
    Tmpfs,
    /// The domain uses Linux overlayfs.
    Overlay,
    /// The domain uses a type without its own variant, and the string holds the
    /// platform's type name.
    Other(String),
    /// The probe could not establish the type, and this variant is the default.
    #[default]
    Unknown,
}

/// `AccessTopology` states how the host reaches the storage of a domain (RFC
/// §10.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum AccessTopology {
    /// The storage is attached to this host, and memory-backed filesystems
    /// count as local.
    Local,
    /// The host reaches the storage over a network or a remote block protocol.
    Remote,
    /// A userspace process serves the filesystem.
    Userspace,
    /// The domain is a kernel pseudo filesystem or sits on a virtual device.
    Virtual,
    /// The adapter implements the protocol client itself.
    ProtocolNative,
    /// The probe could not establish the topology, and this variant is the
    /// default.
    #[default]
    Unknown,
}

/// `TransportHint` names the link to the storage of a domain (RFC §10.3).
///
/// The hint carries no performance claim.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TransportHint {
    /// The storage sits on NVMe.
    Nvme,
    /// The storage sits on SATA.
    Sata,
    /// The storage sits on SAS.
    Sas,
    /// The storage sits on USB.
    Usb,
    /// The storage sits on an SD or MMC card.
    Sd,
    /// The storage sits behind iSCSI.
    Iscsi,
    /// The storage sits behind Fibre Channel.
    FibreChannel,
    /// The storage sits behind a network filesystem protocol.
    Network,
    /// The storage is a virtual device or a pseudo filesystem.
    Virtual,
    /// The storage is host memory.
    Memory,
    /// The probe could not establish the transport, and this variant is the
    /// default.
    #[default]
    Unknown,
}

/// `MediaHint` names the storage medium of a domain (RFC §10.3).
///
/// The hint carries no performance claim.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum MediaHint {
    /// The medium is a spinning disk.
    Rotational,
    /// The medium is solid-state storage.
    SolidState,
    /// The medium is removable.
    Removable,
    /// The medium is an optical disc.
    Optical,
    /// The medium is host memory.
    Memory,
    /// The probe could not establish the medium, and this variant is the
    /// default.
    #[default]
    Unknown,
}

/// `DomainCaseSensitivity` gives the declared case rule of a domain's
/// directories (RFC §10.3, §14.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum DomainCaseSensitivity {
    /// Every directory compares names byte for byte.
    Sensitive,
    /// Every directory folds case.
    Insensitive,
    /// Each directory can carry its own rule, as on ext4, f2fs and NTFS.
    PerDirectory {
        /// `domain_default` applies when the probe cannot read the directory's
        /// own attribute.
        domain_default: CaseSensitivity,
    },
    /// The probe could not establish the rule, and this variant is the default.
    #[default]
    Unknown,
}

/// `TimestampGranularity` gives the declared timestamp resolution of a domain
/// (RFC §10.3).
///
/// No platform reports the resolution.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TimestampGranularity {
    /// Timestamps advance in steps of this duration.
    Resolution(Duration),
    /// The domain declares no resolution, and this variant is the default.
    #[default]
    Unknown,
}

/// `IdentitySpace` gives the declared identity space of a domain (RFC §7.1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum IdentitySpace {
    /// The domain's identities belong to this space.
    Known(IdentitySpaceKey),
    /// The domain declares no space, and this variant is the default.
    #[default]
    Unknown,
}

impl IdentitySpace {
    /// `comparable_with` reports whether both values name the same known space.
    ///
    /// [`IdentitySpace::Unknown`] never matches, even against itself.
    pub fn comparable_with(&self, other: &IdentitySpace) -> bool {
        match (self, other) {
            (IdentitySpace::Known(a), IdentitySpace::Known(b)) => a == b,
            _ => false,
        }
    }
}

/// `IdentityReliability` states how much the tree can trust a domain's file
/// identities (RFC §7.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum IdentityReliability {
    /// Identities carry no meaning on this domain.
    None,
    /// The tree may publish identities as metadata, and they must not establish
    /// a rename.
    Advisory,
    /// Identities are unambiguous and can establish a rename.
    Stable,
    /// The probe could not establish reliability, and this variant is the
    /// default.
    #[default]
    Unknown,
}

impl IdentityReliability {
    /// `establishes_rename` reports whether identities of this reliability can
    /// establish a rename.
    ///
    /// Only [`IdentityReliability::Stable`] identities establish a rename.
    pub fn establishes_rename(self) -> bool {
        matches!(self, IdentityReliability::Stable)
    }
}

/// `KindSource` states whether enumeration reports each child's kind (RFC
/// §10.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum KindSource {
    /// The enumeration reports every child's kind.
    Always,
    /// Some kinds arrive unknown, and the session resolves them with metadata
    /// reads.
    Sometimes,
    /// Every kind needs a metadata read.
    Never,
    /// The adapter could not establish the source, and this variant is the
    /// default.
    #[default]
    Unknown,
}

/// `IdentitySource` states where a child's identity comes from during a listing
/// (RFC §10.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum IdentitySource {
    /// The enumeration supplies the identity.
    Inline,
    /// Each identity costs one extra operation per child.
    PerChildRead,
    /// The domain supplies no identity.
    None,
    /// The adapter could not establish the source, and this variant is the
    /// default.
    #[default]
    Unknown,
}

/// `MetadataSource` states where one metadata field comes from during a listing
/// (RFC §10.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum MetadataSource {
    /// The enumeration supplies the value.
    Inline,
    /// Each value costs one extra operation per child.
    PerChildRead,
    /// The adapter could not establish the source, and this variant is the
    /// default.
    #[default]
    Unknown,
}

/// `MetadataSources` gives the [`MetadataSource`] of each
/// [`crate::entry::Metadata`] field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MetadataSources {
    /// `modified` gives the source of the modification time.
    pub modified: MetadataSource,
    /// `created` gives the source of the creation time.
    pub created: MetadataSource,
    /// `size` gives the source of the size.
    pub size: MetadataSource,
    /// `permissions` gives the source of the permission bits.
    pub permissions: MetadataSource,
}

impl MetadataSources {
    /// `INLINE` declares every field inline.
    pub const INLINE: MetadataSources = MetadataSources {
        modified: MetadataSource::Inline,
        created: MetadataSource::Inline,
        size: MetadataSource::Inline,
        permissions: MetadataSource::Inline,
    };
    /// `PER_CHILD_READ` declares a per-child read for every field.
    pub const PER_CHILD_READ: MetadataSources = MetadataSources {
        modified: MetadataSource::PerChildRead,
        created: MetadataSource::PerChildRead,
        size: MetadataSource::PerChildRead,
        permissions: MetadataSource::PerChildRead,
    };

    /// `inline` returns the inline fields.
    pub fn inline(self) -> MetadataFields {
        MetadataFields {
            modified: self.modified == MetadataSource::Inline,
            created: self.created == MetadataSource::Inline,
            size: self.size == MetadataSource::Inline,
            permissions: self.permissions == MetadataSource::Inline,
        }
    }

    /// `per_child_read` returns the fields with a per-child read source.
    ///
    /// A field with an Unknown source appears in neither this set nor
    /// [`MetadataSources::inline`].
    pub fn per_child_read(self) -> MetadataFields {
        MetadataFields {
            modified: self.modified == MetadataSource::PerChildRead,
            created: self.created == MetadataSource::PerChildRead,
            size: self.size == MetadataSource::PerChildRead,
            permissions: self.permissions == MetadataSource::PerChildRead,
        }
    }
}

/// `Answer` answers a capability question.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Answer {
    /// The capability holds.
    Yes,
    /// The capability is absent.
    No,
    /// The adapter could not establish an answer, and this variant is the
    /// default.
    #[default]
    Unknown,
}

/// `WatcherAvailability` states whether a watcher exists for a domain (RFC
/// §10.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum WatcherAvailability {
    /// A watcher can observe this domain.
    Available,
    /// No watcher can observe this domain, and reconciliation alone keeps it
    /// current.
    Unavailable,
    /// The adapter could not establish availability, and this variant is the
    /// default.
    #[default]
    Unknown,
}

/// `WatcherScope` states how far one watch registration reaches (RFC §10.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum WatcherScope {
    /// One registration covers a whole subtree.
    Recursive,
    /// Each directory needs its own registration.
    PerDirectory,
    /// The adapter could not establish the scope, and this variant is the
    /// default.
    #[default]
    Unknown,
}

/// `WatcherCapabilities` describes the declared watcher behaviour of one
/// storage domain (RFC §10.4).
///
/// These answers shape latency strategy only. Reconciliation stays required
/// for correctness whatever they say.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct WatcherCapabilities {
    /// `availability` states whether a watcher exists.
    pub availability: WatcherAvailability,
    /// `scope` states whether one registration covers a subtree.
    pub scope: WatcherScope,
    /// `observes_external_writers` states whether the watcher reports changes
    /// by writers outside this host.
    ///
    /// A watcher with the answer [`Answer::No`] serves only as latency
    /// assistance for local writes.
    pub observes_external_writers: Answer,
    /// `can_lose_events` states whether the watcher can lose events.
    pub can_lose_events: Answer,
    /// `signals_overflow` states whether the watcher signals overflow or a
    /// rescan requirement.
    pub signals_overflow: Answer,
    /// `registration_gaps` states whether registration has known windows that
    /// miss changes.
    pub registration_gaps: Answer,
    /// `polling_fallback_required` states whether polling must back up the
    /// watcher.
    pub polling_fallback_required: Answer,
}

/// `DeclarationSource` states how a probe established one capability field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum DeclarationSource {
    /// The probe read the value from the platform.
    Detected,
    /// The adapter supplied the value from a table, from configuration or from
    /// its own knowledge.
    Declared,
    /// The field holds its Unknown value, and this variant is the default.
    #[default]
    Unknown,
}

/// `DeclarationSources` gives the [`DeclarationSource`] of each field of
/// [`DomainCapabilities`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DeclarationSources {
    /// `filesystem` gives the source of [`DomainCapabilities::filesystem`].
    pub filesystem: DeclarationSource,
    /// `semantics` gives the source of [`DomainCapabilities::semantics`].
    pub semantics: DeclarationSource,
    /// `topology` gives the source of [`DomainCapabilities::topology`].
    pub topology: DeclarationSource,
    /// `transport` gives the source of [`DomainCapabilities::transport`].
    pub transport: DeclarationSource,
    /// `media` gives the source of [`DomainCapabilities::media`].
    pub media: DeclarationSource,
    /// `case` gives the source of [`DomainCapabilities::case`].
    pub case: DeclarationSource,
    /// `timestamp_granularity` gives the source of
    /// [`DomainCapabilities::timestamp_granularity`].
    pub timestamp_granularity: DeclarationSource,
    /// `identity_space` gives the source of
    /// [`DomainCapabilities::identity_space`].
    pub identity_space: DeclarationSource,
    /// `identity_reliability` gives the source of
    /// [`DomainCapabilities::identity_reliability`].
    pub identity_reliability: DeclarationSource,
    /// `observation` gives the shared source of the kind, identity and metadata
    /// source fields.
    pub observation: DeclarationSource,
    /// `watcher` gives the source of [`DomainCapabilities::watcher`].
    pub watcher: DeclarationSource,
}

/// `DomainCapabilities` holds the declared capabilities of one storage domain
/// (RFC §10.3).
///
/// Every field defaults to Unknown, and an adapter must report Unknown
/// wherever it cannot establish a field. No field implies performance.
/// [`DomainCapabilities::sources`] records how the probe established each
/// field.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DomainCapabilities {
    /// `filesystem` names the filesystem instance behind the domain.
    pub filesystem: FilesystemInstance,
    /// `semantics` names the filesystem type.
    pub semantics: FilesystemSemantics,
    /// `topology` states how the host reaches the storage.
    pub topology: AccessTopology,
    /// `transport` names the link to the storage.
    pub transport: TransportHint,
    /// `media` names the storage medium.
    pub media: MediaHint,
    /// `case` gives the case rule for the domain's directories.
    pub case: DomainCaseSensitivity,
    /// `timestamp_granularity` gives the timestamp resolution.
    pub timestamp_granularity: TimestampGranularity,
    /// `identity_space` names the namespace for comparable identities.
    pub identity_space: IdentitySpace,
    /// `identity_reliability` states how much the tree can trust identities.
    pub identity_reliability: IdentityReliability,
    /// `kind_source` states whether enumeration reports kinds.
    pub kind_source: KindSource,
    /// `identity_source` states where identities come from.
    pub identity_source: IdentitySource,
    /// `metadata_sources` states where each metadata field comes from.
    pub metadata_sources: MetadataSources,
    /// `watcher` describes the watcher behaviour.
    pub watcher: WatcherCapabilities,
    /// `sources` records how the probe established each field.
    pub sources: DeclarationSources,
}

impl DomainCapabilities {
    /// `inline` declares stable inline identity, inline kinds and inline
    /// metadata.
    ///
    /// Every other field stays Unknown, and so does the identity space.
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

    /// `identities_comparable` reports whether both domains declare the same
    /// known identity space.
    pub fn identities_comparable(&self, other: &DomainCapabilities) -> bool {
        self.identity_space.comparable_with(&other.identity_space)
    }

    /// `establishes_rename` reports whether identities from these two domains
    /// can establish a rename.
    ///
    /// Both domains must declare stable identity and the same known identity
    /// space (RFC §7.1).
    pub fn establishes_rename(&self, other: &DomainCapabilities) -> bool {
        self.identity_reliability.establishes_rename()
            && other.identity_reliability.establishes_rename()
            && self.identities_comparable(other)
    }

    /// `same_filesystem_as` reports whether both domains declare the same known
    /// filesystem instance.
    pub fn same_filesystem_as(&self, other: &DomainCapabilities) -> bool {
        self.filesystem.same_as(&other.filesystem)
    }

    /// `same_storage_as` reports whether every storage field of this domain
    /// equals the field of `parent`.
    ///
    /// The comparison covers filesystem instance, semantics, topology,
    /// transport, media and identity space. Here Unknown equals Unknown. Probe
    /// identities can leave a crossing inconclusive, and the tree then treats a
    /// mismatch as a crossing.
    pub fn same_storage_as(&self, parent: &DomainCapabilities) -> bool {
        self.filesystem == parent.filesystem
            && self.semantics == parent.semantics
            && self.topology == parent.topology
            && self.transport == parent.transport
            && self.media == parent.media
            && self.identity_space == parent.identity_space
    }

    /// `foreign_beneath` reports whether this domain is foreign beneath a local
    /// `parent` (RFC §14.3).
    ///
    /// The domain is foreign when `parent` is [`AccessTopology::Local`] and
    /// this domain is remote, userspace, virtual, of unknown topology, or
    /// on removable media. A tree must not traverse a foreign domain unless
    /// the consumer asks for it.
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

/// `Crossing` judges whether a directory lies in another storage domain than
/// its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Crossing {
    /// Evidence shows another domain.
    Proven,
    /// The available evidence cannot decide.
    Inconclusive,
    /// Evidence shows the same domain, or the directory has no parent.
    NotCrossed,
}

impl Crossing {
    /// `stronger` combines two verdicts on the same directory.
    ///
    /// [`Crossing::Proven`] wins over any verdict. Two [`Crossing::NotCrossed`]
    /// verdicts stay NotCrossed. Every other pair gives
    /// [`Crossing::Inconclusive`].
    pub fn stronger(self, other: Crossing) -> Crossing {
        match (self, other) {
            (Crossing::Proven, _) | (_, Crossing::Proven) => Crossing::Proven,
            (Crossing::NotCrossed, Crossing::NotCrossed) => Crossing::NotCrossed,
            _ => Crossing::Inconclusive,
        }
    }

    /// `between` judges `identity` against the identity in `parent`.
    ///
    /// Without a parent the verdict is [`Crossing::NotCrossed`]. Otherwise
    /// `between` follows [`DomainIdentity::crossing_from`].
    pub fn between(parent: Option<&ProbeResult>, identity: &DomainIdentity) -> Crossing {
        match parent {
            Some(parent) => identity.crossing_from(&parent.identity),
            None => Crossing::NotCrossed,
        }
    }
}

/// `ProbeResult` holds the report of a [`DomainProbe`] for one directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    /// `identity` holds the identity of the directory's domain.
    pub identity: DomainIdentity,
    /// `capabilities` holds the capabilities of that domain.
    pub capabilities: DomainCapabilities,
    /// `is_domain_root` states whether the directory is the root of its mount.
    ///
    /// The tree counts a domain root as a proven crossing.
    pub is_domain_root: bool,
    /// `crossed` holds the verdict against the parent result.
    pub crossed: Crossing,
    /// `directory_case` holds the case rule from the directory's own attribute
    /// when the platform carries one.
    pub directory_case: Option<CaseSensitivity>,
}

impl ProbeResult {
    /// `unknown` returns a result with Unknown identity and capabilities and an
    /// inconclusive crossing.
    pub fn unknown() -> ProbeResult {
        ProbeResult {
            identity: DomainIdentity::Unknown,
            capabilities: DomainCapabilities::default(),
            is_domain_root: false,
            crossed: Crossing::Inconclusive,
            directory_case: None,
        }
    }

    /// `case` returns the case rule for this directory's children.
    ///
    /// A uniform domain rule applies as declared. Under
    /// [`DomainCaseSensitivity::PerDirectory`] the directory's own attribute
    /// wins, and the domain default serves as fallback. Under an Unknown domain
    /// rule only the directory's attribute counts, and `None` means that no
    /// rule is known.
    pub fn case(&self) -> Option<CaseSensitivity> {
        match self.capabilities.case {
            DomainCaseSensitivity::Sensitive => Some(CaseSensitivity::Sensitive),
            DomainCaseSensitivity::Insensitive => Some(CaseSensitivity::Insensitive),
            DomainCaseSensitivity::PerDirectory { domain_default } => {
                Some(self.directory_case.unwrap_or(domain_default))
            }
            DomainCaseSensitivity::Unknown => self.directory_case,
        }
    }
}

/// `ProbeError` explains why a [`DomainProbe`] failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// The directory does not exist.
    NotFound,
    /// The path names a non-directory, and a symbolic link counts as one.
    NotDirectory,
    /// The platform refused access.
    PermissionDenied,
    /// Another I/O failure occurred, and the string carries its message. A
    /// retry can succeed.
    Transient(String),
    /// The platform lacks the operation, and the string carries the message.
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

/// A `DomainProbe` identifies the storage domain of a directory and declares
/// its capabilities (RFC §10.3).
///
/// An implementor must report Unknown wherever it cannot establish a field.
/// It must not follow a symbolic link at the probed path (RFC §14.2).
pub trait DomainProbe: Send + Sync {
    /// `probe` probes the directory at the absolute path `directory`.
    ///
    /// `parent` holds the result for the containing directory, or `None` for
    /// the tree root. The implementor sets [`ProbeResult::crossed`] relative to
    /// `parent`.
    ///
    /// # Errors
    ///
    /// `probe` returns [`ProbeError::NotDirectory`] when `directory` names a
    /// symbolic link or any other non-directory.
    fn probe(&self, directory: &Path, parent: Option<&ProbeResult>) -> Result<ProbeResult, ProbeError>;

    /// `probe_opened` probes a directory through an open descriptor.
    ///
    /// `opened` refers to the directory at `directory`. The default
    /// implementation calls [`DomainProbe::probe`] with `directory`.
    ///
    /// # Errors
    ///
    /// `probe_opened` fails like [`DomainProbe::probe`].
    #[cfg(unix)]
    fn probe_opened(
        &self,
        _opened: std::os::fd::BorrowedFd<'_>,
        directory: &Path,
        parent: Option<&ProbeResult>,
    ) -> Result<ProbeResult, ProbeError> {
        self.probe(directory, parent)
    }

    /// `probe_beneath` probes the child `name` of the open directory `beneath`
    /// (RFC §10.2).
    ///
    /// `directory` holds the full path of the child. An implementation can
    /// resolve `name` relative to `beneath`, and it must not follow a symbolic
    /// link there. The default implementation calls [`DomainProbe::probe`] with
    /// `directory`.
    ///
    /// # Errors
    ///
    /// `probe_beneath` fails like [`DomainProbe::probe`].
    #[cfg(unix)]
    fn probe_beneath(
        &self,
        _beneath: std::os::fd::BorrowedFd<'_>,
        _name: &std::ffi::OsStr,
        directory: &Path,
        parent: Option<&ProbeResult>,
    ) -> Result<ProbeResult, ProbeError> {
        self.probe(directory, parent)
    }
}
