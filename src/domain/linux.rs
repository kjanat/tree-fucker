use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use rustix::fs::{
    AtFlags, CWD, FileType, IFlags, Mode, OFlags, Statx, StatxAttributes, StatxFlags, ioctl_getflags, statx,
};
use rustix::io::Errno;

use super::{
    AccessTopology, Answer, Crossing, DeclarationSource, DeclarationSources, DomainCapabilities, DomainCaseSensitivity,
    DomainIdentity, DomainKey, DomainProbe, FilesystemInstance, FilesystemInstanceKey, FilesystemSemantics,
    IdentityReliability, IdentitySource, IdentitySpace, IdentitySpaceKey, KindSource, MediaHint, MetadataSources,
    ProbeError, ProbeResult, TimestampGranularity, TransportHint, WatcherAvailability, WatcherCapabilities,
    WatcherScope, WeakDomainKey,
};
use crate::path::CaseSensitivity;

const STATX_MNT_ID_UNIQUE: StatxFlags = StatxFlags::from_bits_retain(0x4000);
const FS_CASEFOLD_FL: IFlags = IFlags::from_bits_retain(0x4000_0000);
const MOUNTINFO: &str = "/proc/self/mountinfo";
const PROBE_MASK: StatxFlags = StatxFlags::TYPE.union(STATX_MNT_ID_UNIQUE).union(StatxFlags::MNT_ID);
const PROBE_FLAGS: AtFlags = AtFlags::NO_AUTOMOUNT.union(AtFlags::SYMLINK_NOFOLLOW).union(AtFlags::STATX_DONT_SYNC);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Declarations {
    timestamp_granularity: HashMap<String, TimestampGranularity>,
    case: HashMap<String, DomainCaseSensitivity>,
}

#[derive(Default)]
pub struct LinuxProbe {
    declarations: Declarations,
    instances: Mutex<HashMap<u64, DomainCapabilities>>,
}

impl LinuxProbe {
    pub fn new() -> LinuxProbe {
        LinuxProbe::default()
    }

    pub fn declare_timestamp_granularity(
        mut self,
        fs_type: impl Into<String>,
        granularity: TimestampGranularity,
    ) -> LinuxProbe {
        self.declarations.timestamp_granularity.insert(fs_type.into(), granularity);
        self
    }

    pub fn declare_case(mut self, fs_type: impl Into<String>, case: DomainCaseSensitivity) -> LinuxProbe {
        self.declarations.case.insert(fs_type.into(), case);
        self
    }

    fn cached(&self, mount: u64) -> Option<DomainCapabilities> {
        self.instances.lock().ok()?.get(&mount).cloned()
    }

    fn store(&self, mount: u64, capabilities: &DomainCapabilities) {
        if let Ok(mut cache) = self.instances.lock() {
            cache.insert(mount, capabilities.clone());
        }
    }

    fn capabilities(&self, mount: MountId, device: Device) -> DomainCapabilities {
        if let MountId::Unique(id) = mount
            && let Some(cached) = self.cached(id)
        {
            return cached;
        }
        let capabilities = capabilities_of(instance_of(mount, device).as_ref(), &self.declarations);
        if let MountId::Unique(id) = mount {
            self.store(id, &capabilities);
        }
        capabilities
    }
}

impl DomainProbe for LinuxProbe {
    fn probe(&self, directory: &Path, parent: Option<&ProbeResult>) -> Result<ProbeResult, ProbeError> {
        let stat = statx(CWD, directory, PROBE_FLAGS, PROBE_MASK).map_err(probe_error)?;
        self.assess(&stat, parent, || directory_case(directory))
    }

    fn probe_opened(
        &self,
        opened: BorrowedFd<'_>,
        _directory: &Path,
        parent: Option<&ProbeResult>,
    ) -> Result<ProbeResult, ProbeError> {
        let stat = statx(opened, c"", PROBE_FLAGS | AtFlags::EMPTY_PATH, PROBE_MASK).map_err(probe_error)?;
        self.assess(&stat, parent, || handle_case(opened))
    }

    fn probe_beneath(
        &self,
        beneath: BorrowedFd<'_>,
        name: &OsStr,
        _directory: &Path,
        parent: Option<&ProbeResult>,
    ) -> Result<ProbeResult, ProbeError> {
        let stat = statx(beneath, name, PROBE_FLAGS, PROBE_MASK).map_err(probe_error)?;
        self.assess(&stat, parent, || {
            let handle = rustix::fs::openat(beneath, name, CASE_FLAGS, Mode::empty()).ok()?;
            handle_case(handle.as_fd())
        })
    }
}

impl LinuxProbe {
    fn assess(
        &self,
        stat: &Statx,
        parent: Option<&ProbeResult>,
        case: impl FnOnce() -> Option<CaseSensitivity>,
    ) -> Result<ProbeResult, ProbeError> {
        if FileType::from_raw_mode(u32::from(stat.stx_mode)) != FileType::Directory {
            return Err(ProbeError::NotDirectory);
        }

        let mount = mount_id(stat.stx_mask, stat.stx_mnt_id);
        let device = Device { major: stat.stx_dev_major, minor: stat.stx_dev_minor };
        let at_mount_root = mount_root(stat);
        let identity = identity_of(mount, device);
        let crossed = crossing(parent, &identity, mount, at_mount_root);
        let is_domain_root = at_mount_root.unwrap_or(matches!(crossed, Crossing::Proven));

        let mut capabilities = self.capabilities(mount, device);
        let space = IdentitySpaceKey::unix_device(u64::from(device.major), u64::from(device.minor));
        capabilities.identity_space = IdentitySpace::Known(space);
        capabilities.sources.identity_space = DeclarationSource::Detected;
        if matches!(mount, MountId::Device) {
            capabilities.identity_reliability = IdentityReliability::Unknown;
            capabilities.sources.identity_reliability = DeclarationSource::Unknown;
        }

        let directory_case = match capabilities.case {
            DomainCaseSensitivity::PerDirectory { .. } => case(),
            _ => None,
        };

        Ok(ProbeResult { identity, capabilities, is_domain_root, crossed, directory_case })
    }
}

const CASE_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

fn directory_case(directory: &Path) -> Option<CaseSensitivity> {
    let handle = rustix::fs::open(directory, CASE_FLAGS, Mode::empty()).ok()?;
    handle_case(handle.as_fd())
}

fn handle_case(handle: BorrowedFd<'_>) -> Option<CaseSensitivity> {
    let flags = ioctl_getflags(handle).ok()?;
    Some(if flags.contains(FS_CASEFOLD_FL) { CaseSensitivity::Insensitive } else { CaseSensitivity::Sensitive })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Device {
    major: u32,
    minor: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MountId {
    Unique(u64),
    Reusable(u64),
    Device,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Instance {
    fs_type: String,
    source: Option<String>,
    device: Option<Device>,
}

fn mount_id(mask: u32, mnt_id: u64) -> MountId {
    if mask & STATX_MNT_ID_UNIQUE.bits() != 0 {
        MountId::Unique(mnt_id)
    } else if mask & StatxFlags::MNT_ID.bits() != 0 {
        MountId::Reusable(mnt_id)
    } else {
        MountId::Device
    }
}

fn mount_root(stat: &Statx) -> Option<bool> {
    mount_root_of(stat.stx_attributes_mask, stat.stx_attributes)
}

fn mount_root_of(supported: StatxAttributes, attributes: StatxAttributes) -> Option<bool> {
    supported.contains(StatxAttributes::MOUNT_ROOT).then(|| attributes.contains(StatxAttributes::MOUNT_ROOT))
}

fn identity_of(mount: MountId, device: Device) -> DomainIdentity {
    match mount {
        MountId::Unique(id) => DomainIdentity::Known(DomainKey::linux_unique_mount(id)),
        MountId::Reusable(id) => DomainIdentity::Weak(WeakDomainKey::linux_reusable_mount(id)),
        MountId::Device => DomainIdentity::Weak(WeakDomainKey::linux_device(device.major, device.minor)),
    }
}

fn crossing(
    parent: Option<&ProbeResult>,
    identity: &DomainIdentity,
    mount: MountId,
    at_mount_root: Option<bool>,
) -> Crossing {
    let Some(parent) = parent else {
        return Crossing::NotCrossed;
    };
    let proven_by_attribute = if at_mount_root == Some(true) { Crossing::Proven } else { Crossing::Inconclusive };
    if matches!(mount, MountId::Device) {
        return proven_by_attribute;
    }
    match identity.crossing_from(&parent.identity) {
        Crossing::Inconclusive => proven_by_attribute,
        verdict => verdict,
    }
}

fn probe_error(errno: Errno) -> ProbeError {
    if errno == Errno::NOENT {
        ProbeError::NotFound
    } else if errno == Errno::NOTDIR {
        ProbeError::NotDirectory
    } else if errno == Errno::ACCESS || errno == Errno::PERM {
        ProbeError::PermissionDenied
    } else if errno == Errno::NOSYS || errno == Errno::OPNOTSUPP {
        ProbeError::Unsupported(errno.to_string())
    } else {
        ProbeError::Transient(errno.to_string())
    }
}

fn instance_of(mount: MountId, device: Device) -> Option<Instance> {
    match mount {
        MountId::Unique(id) => statmount_instance(id).or_else(|| mountinfo_instance(None, device)),
        MountId::Reusable(id) => mountinfo_instance(Some(id), device),
        MountId::Device => mountinfo_instance(None, device),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backing {
    Block,
    Memory,
    Pseudo,
    Network,
    Userspace,
    MultiDevice,
    Overlay,
    Unknown,
}

fn backing_of(fs_type: &str) -> Backing {
    match fs_type {
        "ext2" | "ext3" | "ext4" | "xfs" | "f2fs" | "ntfs3" | "ntfs" | "exfat" | "vfat" | "msdos" | "iso9660"
        | "udf" | "jfs" | "reiserfs" => Backing::Block,
        "tmpfs" | "ramfs" | "devtmpfs" => Backing::Memory,
        "proc" | "sysfs" | "cgroup" | "cgroup2" | "devpts" | "securityfs" | "debugfs" | "tracefs" | "configfs"
        | "pstore" | "bpf" | "mqueue" | "hugetlbfs" | "autofs" | "efivarfs" | "binfmt_misc" | "fusectl"
        | "selinuxfs" | "nsfs" | "rpc_pipefs" => Backing::Pseudo,
        "nfs" | "nfs4" | "cifs" | "smb3" | "9p" | "ceph" | "afs" => Backing::Network,
        "overlay" => Backing::Overlay,
        "btrfs" | "zfs" | "bcachefs" => Backing::MultiDevice,
        _ if fs_type.starts_with("fuse") => Backing::Userspace,
        _ => Backing::Unknown,
    }
}

fn semantics_of(fs_type: &str) -> FilesystemSemantics {
    match fs_type {
        "" => FilesystemSemantics::Unknown,
        "ext4" => FilesystemSemantics::Ext4,
        "btrfs" => FilesystemSemantics::Btrfs,
        "xfs" => FilesystemSemantics::Xfs,
        "zfs" => FilesystemSemantics::Zfs,
        "ntfs3" | "ntfs" => FilesystemSemantics::Ntfs,
        "exfat" => FilesystemSemantics::ExFat,
        "vfat" | "msdos" => FilesystemSemantics::Fat,
        "nfs" | "nfs4" => FilesystemSemantics::Nfs,
        "cifs" | "smb3" => FilesystemSemantics::Smb,
        "tmpfs" => FilesystemSemantics::Tmpfs,
        "overlay" => FilesystemSemantics::Overlay,
        "fusectl" => FilesystemSemantics::Other(fs_type.to_owned()),
        _ if fs_type.starts_with("fuse") => FilesystemSemantics::Fuse,
        _ => FilesystemSemantics::Other(fs_type.to_owned()),
    }
}

fn case_of(fs_type: &str) -> DomainCaseSensitivity {
    match fs_type {
        "ext4" | "f2fs" => DomainCaseSensitivity::PerDirectory { domain_default: CaseSensitivity::Sensitive },
        "ext2" | "ext3" | "btrfs" | "bcachefs" | "tmpfs" | "ramfs" | "devtmpfs" | "proc" | "sysfs" | "cgroup2" => {
            DomainCaseSensitivity::Sensitive
        }
        "ntfs3" | "ntfs" | "exfat" | "vfat" | "msdos" => DomainCaseSensitivity::Insensitive,
        _ => DomainCaseSensitivity::Unknown,
    }
}

fn granularity_of(fs_type: &str) -> TimestampGranularity {
    match fs_type {
        "btrfs" | "xfs" | "f2fs" | "zfs" | "bcachefs" | "tmpfs" | "ramfs" | "devtmpfs" => {
            TimestampGranularity::Resolution(Duration::from_nanos(1))
        }
        "ext2" | "ext3" => TimestampGranularity::Resolution(Duration::from_secs(1)),
        "ntfs3" | "ntfs" => TimestampGranularity::Resolution(Duration::from_nanos(100)),
        "exfat" => TimestampGranularity::Resolution(Duration::from_millis(10)),
        "vfat" | "msdos" => TimestampGranularity::Resolution(Duration::from_secs(2)),
        _ => TimestampGranularity::Unknown,
    }
}

fn kind_source_of(fs_type: &str) -> KindSource {
    match fs_type {
        "ext4" | "btrfs" | "f2fs" | "bcachefs" | "zfs" | "tmpfs" | "ramfs" | "devtmpfs" | "proc" | "sysfs"
        | "cgroup2" => KindSource::Always,
        _ => KindSource::Sometimes,
    }
}

fn reliability_of(fs_type: &str, backing: Backing) -> IdentityReliability {
    match fs_type {
        "ext2" | "ext3" | "ext4" | "btrfs" | "xfs" | "f2fs" | "zfs" | "ntfs3" | "ntfs" | "tmpfs" | "ramfs"
        | "devtmpfs" => IdentityReliability::Stable,
        "exfat" | "vfat" | "msdos" => IdentityReliability::None,
        _ => match backing {
            Backing::Network | Backing::Userspace | Backing::Overlay | Backing::Pseudo => IdentityReliability::Advisory,
            _ => IdentityReliability::Unknown,
        },
    }
}

fn observes_external_writers(backing: Backing) -> Answer {
    match backing {
        Backing::Block | Backing::Memory | Backing::MultiDevice => Answer::Yes,
        Backing::Network | Backing::Userspace | Backing::Overlay | Backing::Pseudo => Answer::No,
        Backing::Unknown => Answer::Unknown,
    }
}

fn watcher_of(backing: Backing) -> WatcherCapabilities {
    let external = observes_external_writers(backing);
    let polling = match external {
        Answer::Yes => Answer::No,
        Answer::No => Answer::Yes,
        Answer::Unknown => Answer::Unknown,
    };
    WatcherCapabilities {
        availability: match backing {
            Backing::Pseudo => WatcherAvailability::Unavailable,
            _ => WatcherAvailability::Available,
        },
        scope: WatcherScope::PerDirectory,
        observes_external_writers: external,
        can_lose_events: Answer::Yes,
        signals_overflow: Answer::Yes,
        registration_gaps: Answer::Yes,
        polling_fallback_required: polling,
    }
}

fn topology_of(backing: Backing, source: Option<&str>) -> (AccessTopology, TransportHint, MediaHint) {
    match backing {
        Backing::Block => match block_hints(source) {
            Some((transport, media)) => (topology_for(transport), transport, media),
            None => (AccessTopology::Unknown, TransportHint::Unknown, MediaHint::Unknown),
        },
        Backing::Memory => (AccessTopology::Local, TransportHint::Memory, MediaHint::Memory),
        Backing::Pseudo => (AccessTopology::Virtual, TransportHint::Virtual, MediaHint::Unknown),
        Backing::Network => (AccessTopology::Remote, TransportHint::Network, MediaHint::Unknown),
        Backing::Userspace => (AccessTopology::Userspace, TransportHint::Unknown, MediaHint::Unknown),
        Backing::MultiDevice | Backing::Overlay | Backing::Unknown => {
            (AccessTopology::Unknown, TransportHint::Unknown, MediaHint::Unknown)
        }
    }
}

fn topology_for(transport: TransportHint) -> AccessTopology {
    match transport {
        TransportHint::Nvme | TransportHint::Sata | TransportHint::Sas | TransportHint::Usb | TransportHint::Sd => {
            AccessTopology::Local
        }
        TransportHint::Virtual => AccessTopology::Virtual,
        TransportHint::Iscsi | TransportHint::FibreChannel | TransportHint::Network => AccessTopology::Remote,
        TransportHint::Memory => AccessTopology::Local,
        TransportHint::Unknown => AccessTopology::Unknown,
    }
}

fn capabilities_of(instance: Option<&Instance>, declarations: &Declarations) -> DomainCapabilities {
    let fs_type = instance.map_or("", |instance| instance.fs_type.as_str());
    let backing = backing_of(fs_type);
    let semantics = semantics_of(fs_type);
    let (topology, transport, media) = topology_of(backing, instance.and_then(|i| i.source.as_deref()));
    let case = declarations.case.get(fs_type).copied().unwrap_or_else(|| case_of(fs_type));
    let granularity =
        declarations.timestamp_granularity.get(fs_type).copied().unwrap_or_else(|| granularity_of(fs_type));
    let reliability = reliability_of(fs_type, backing);
    let watcher = watcher_of(backing);
    let filesystem = match instance.and_then(|instance| instance.device) {
        Some(device) => FilesystemInstance::Known(FilesystemInstanceKey::linux_superblock(device.major, device.minor)),
        None => FilesystemInstance::Unknown,
    };
    DomainCapabilities {
        sources: DeclarationSources {
            filesystem: detected(filesystem != FilesystemInstance::Unknown),
            semantics: detected(semantics != FilesystemSemantics::Unknown),
            topology: detected(topology != AccessTopology::Unknown),
            transport: detected(transport != TransportHint::Unknown),
            media: detected(media != MediaHint::Unknown),
            case: declared(case != DomainCaseSensitivity::Unknown),
            timestamp_granularity: declared(granularity != TimestampGranularity::Unknown),
            identity_space: DeclarationSource::Unknown,
            identity_reliability: declared(reliability != IdentityReliability::Unknown),
            observation: DeclarationSource::Declared,
            watcher: DeclarationSource::Declared,
        },
        filesystem,
        semantics,
        topology,
        transport,
        media,
        case,
        timestamp_granularity: granularity,
        identity_space: IdentitySpace::Unknown,
        identity_reliability: reliability,
        kind_source: kind_source_of(fs_type),
        identity_source: IdentitySource::Inline,
        metadata_sources: MetadataSources::PER_CHILD_READ,
        watcher,
    }
}

fn detected(known: bool) -> DeclarationSource {
    if known { DeclarationSource::Detected } else { DeclarationSource::Unknown }
}

fn declared(known: bool) -> DeclarationSource {
    if known { DeclarationSource::Declared } else { DeclarationSource::Unknown }
}

fn block_hints(source: Option<&str>) -> Option<(TransportHint, MediaHint)> {
    let source = source?;
    if !source.starts_with('/') {
        return None;
    }
    let node = statx(CWD, source, AtFlags::empty(), StatxFlags::TYPE).ok()?;
    if FileType::from_raw_mode(u32::from(node.stx_mode)) != FileType::BlockDevice {
        return None;
    }
    let entry = PathBuf::from(format!("/sys/dev/block/{}:{}", node.stx_rdev_major, node.stx_rdev_minor));
    let device = fs::canonicalize(entry).ok()?;
    let disk = if device.join("queue").is_dir() { device } else { device.parent()?.to_path_buf() };
    Some((transport_of(&disk), media_of(&disk)))
}

fn media_of(disk: &Path) -> MediaHint {
    if sysfs_flag(&disk.join("removable")) == Some(true) {
        return MediaHint::Removable;
    }
    match sysfs_flag(&disk.join("queue/rotational")) {
        Some(true) => MediaHint::Rotational,
        Some(false) => MediaHint::SolidState,
        None => MediaHint::Unknown,
    }
}

fn sysfs_flag(path: &Path) -> Option<bool> {
    match fs::read_to_string(path).ok()?.trim() {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ChainNode {
    name: String,
    subsystem: Option<String>,
}

fn device_chain(disk: &Path) -> Vec<ChainNode> {
    let mut chain = Vec::new();
    let mut node = disk.to_path_buf();
    while node.starts_with("/sys/devices") {
        let name = node.file_name().and_then(|name| name.to_str()).unwrap_or_default().to_owned();
        chain.push(ChainNode { name, subsystem: subsystem_of(&node) });
        match node.parent() {
            Some(parent) => node = parent.to_path_buf(),
            None => break,
        }
    }
    chain
}

fn transport_of(disk: &Path) -> TransportHint {
    transport_from_chain(&device_chain(disk))
}

fn transport_from_chain(chain: &[ChainNode]) -> TransportHint {
    let mut scsi = false;
    let mut ata = false;
    let mut sas = false;
    let mut fibre_channel = false;
    let mut iscsi = false;
    for node in chain {
        if is_ata_host(&node.name) {
            ata = true;
        }
        match node.subsystem.as_deref() {
            Some("nvme") => return TransportHint::Nvme,
            Some("usb") => return TransportHint::Usb,
            Some("mmc") => return TransportHint::Sd,
            Some("virtio") => return TransportHint::Virtual,
            Some("iscsi_session" | "iscsi_host" | "iscsi_connection") => iscsi = true,
            Some("fc_host" | "fc_remote_ports" | "fc_transport") => fibre_channel = true,
            Some("sas_device" | "sas_end_device" | "sas_port" | "sas_phy" | "sas_expander" | "sas_host") => {
                sas = true;
            }
            Some("ata_port" | "ata_link" | "ata_device") => ata = true,
            Some("scsi") => scsi = true,
            _ => {}
        }
    }
    if iscsi {
        TransportHint::Iscsi
    } else if fibre_channel {
        TransportHint::FibreChannel
    } else if sas {
        TransportHint::Sas
    } else if scsi && ata {
        TransportHint::Sata
    } else {
        TransportHint::Unknown
    }
}

fn is_ata_host(name: &str) -> bool {
    match name.strip_prefix("ata") {
        Some(rest) => !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()),
        None => false,
    }
}

fn subsystem_of(node: &Path) -> Option<String> {
    let target = fs::read_link(node.join("subsystem")).ok()?;
    Some(target.file_name()?.to_str()?.to_owned())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn statmount_instance(mount: u64) -> Option<Instance> {
    const SYS_STATMOUNT: libc::c_long = 457;
    const REQUEST_SIZE: usize = 24;
    const REQUEST_FLAGS: libc::c_uint = 0;
    const REQUEST_MASK: u64 = 0x1 | 0x2 | 0x20 | 0x100 | 0x200;
    const MASK_SB_BASIC: u64 = 0x1;
    const MASK_FS_TYPE: u64 = 0x20;
    const MASK_FS_SUBTYPE: u64 = 0x100;
    const MASK_SB_SOURCE: u64 = 0x200;
    const OFFSET_MASK: usize = 8;
    const OFFSET_SB_DEV_MAJOR: usize = 16;
    const OFFSET_SB_DEV_MINOR: usize = 20;
    const OFFSET_FS_TYPE: usize = 36;
    const OFFSET_FS_SUBTYPE: usize = 120;
    const OFFSET_SB_SOURCE: usize = 124;
    const STRINGS: usize = 512;

    let mut request = [0u8; REQUEST_SIZE];
    request[0..4].copy_from_slice(&u32::try_from(REQUEST_SIZE).ok()?.to_ne_bytes());
    request[8..16].copy_from_slice(&mount.to_ne_bytes());
    request[16..24].copy_from_slice(&REQUEST_MASK.to_ne_bytes());

    let mut buffer = vec![0u8; 8192];
    let status =
        unsafe { libc::syscall(SYS_STATMOUNT, request.as_ptr(), buffer.as_mut_ptr(), buffer.len(), REQUEST_FLAGS) };
    if status != 0 {
        return None;
    }

    let mask = read_u64(&buffer, OFFSET_MASK)?;
    let strings = buffer.get(STRINGS..)?;
    let fs_type = if mask & MASK_FS_TYPE != 0 { string_at(strings, read_u32(&buffer, OFFSET_FS_TYPE)?) } else { None };
    let subtype =
        if mask & MASK_FS_SUBTYPE != 0 { string_at(strings, read_u32(&buffer, OFFSET_FS_SUBTYPE)?) } else { None };
    let source =
        if mask & MASK_SB_SOURCE != 0 { string_at(strings, read_u32(&buffer, OFFSET_SB_SOURCE)?) } else { None };
    let device = if mask & MASK_SB_BASIC != 0 {
        Some(Device { major: read_u32(&buffer, OFFSET_SB_DEV_MAJOR)?, minor: read_u32(&buffer, OFFSET_SB_DEV_MINOR)? })
    } else {
        None
    };

    let fs_type = match (fs_type?, subtype) {
        (base, Some(subtype)) if base == "fuse" => format!("fuse.{subtype}"),
        (base, _) => base,
    };
    Some(Instance { fs_type, source, device })
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn statmount_instance(_mount: u64) -> Option<Instance> {
    None
}

fn read_u32(buffer: &[u8], offset: usize) -> Option<u32> {
    let bytes = buffer.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_ne_bytes(bytes.try_into().ok()?))
}

fn read_u64(buffer: &[u8], offset: usize) -> Option<u64> {
    let bytes = buffer.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_ne_bytes(bytes.try_into().ok()?))
}

fn string_at(strings: &[u8], offset: u32) -> Option<String> {
    let rest = strings.get(usize::try_from(offset).ok()?..)?;
    let end = rest.iter().position(|byte| *byte == 0)?;
    Some(str::from_utf8(rest.get(..end)?).ok()?.to_owned())
}

fn mountinfo_instance(mount: Option<u64>, device: Device) -> Option<Instance> {
    let text = fs::read_to_string(MOUNTINFO).ok()?;
    if let Some(mount) = mount
        && let Some(line) = text.lines().find_map(|line| parse_mountinfo(line).filter(|entry| entry.mount == mount))
    {
        return Some(line.instance());
    }
    text.lines()
        .find_map(|line| parse_mountinfo(line).filter(|entry| entry.device == device))
        .map(|entry| entry.instance())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MountLine<'a> {
    mount: u64,
    device: Device,
    fs_type: &'a str,
    source: &'a str,
}

impl MountLine<'_> {
    fn instance(&self) -> Instance {
        Instance { fs_type: self.fs_type.to_owned(), source: Some(unescape(self.source)), device: Some(self.device) }
    }
}

fn parse_mountinfo(line: &str) -> Option<MountLine<'_>> {
    let mut fields = line.split(' ');
    let mount = fields.next()?.parse().ok()?;
    fields.next()?;
    let (major, minor) = fields.next()?.split_once(':')?;
    let device = Device { major: major.parse().ok()?, minor: minor.parse().ok()? };
    fields.next()?;
    fields.next()?;
    fields.next()?;
    loop {
        if fields.next()? == "-" {
            break;
        }
    }
    let fs_type = fields.next()?;
    let source = fields.next()?;
    Some(MountLine { mount, device, fs_type, source })
}

fn unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let escape = bytes
            .get(index)
            .filter(|byte| **byte == b'\\')
            .and_then(|_| bytes.get(index + 1..index + 4))
            .and_then(octal_byte);
        match escape {
            Some(byte) => {
                out.push(byte);
                index += 4;
            }
            None => {
                if let Some(byte) = bytes.get(index) {
                    out.push(*byte);
                }
                index += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_owned())
}

fn octal_byte(digits: &[u8]) -> Option<u8> {
    let mut value: u16 = 0;
    for digit in digits {
        let place = digit.checked_sub(b'0').filter(|place| *place < 8)?;
        value = value * 8 + u16::from(place);
    }
    u8::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = "36 35 98:0 /a /mnt/point rw,noatime master:1 - ext4 /dev/root rw,errors=continue";

    fn instance(fs_type: &str) -> Instance {
        Instance { fs_type: fs_type.to_owned(), source: None, device: None }
    }

    fn table(fs_type: &str) -> DomainCapabilities {
        capabilities_of(Some(&instance(fs_type)), &Declarations::default())
    }

    #[test]
    fn parses_a_mountinfo_line_past_its_optional_fields() {
        let entry = parse_mountinfo(LINE).expect("mountinfo line");
        assert_eq!(entry.mount, 36);
        assert_eq!(entry.device, Device { major: 98, minor: 0 });
        assert_eq!(entry.fs_type, "ext4");
        assert_eq!(
            entry.instance(),
            Instance {
                fs_type: "ext4".to_owned(),
                source: Some("/dev/root".to_owned()),
                device: Some(Device { major: 98, minor: 0 })
            }
        );
    }

    #[test]
    fn parses_a_mountinfo_line_without_optional_fields() {
        let line = "23 28 0:22 / /sys rw,nosuid - sysfs sysfs rw";
        let entry = parse_mountinfo(line).expect("mountinfo line");
        assert_eq!(entry.fs_type, "sysfs");
        assert_eq!(entry.source, "sysfs");
    }

    #[test]
    fn unescapes_octal_sequences_in_a_mount_source() {
        assert_eq!(unescape("/dev/disk\\040one"), "/dev/disk one");
        assert_eq!(unescape("/dev/plain"), "/dev/plain");
        assert_eq!(unescape("trailing\\04"), "trailing\\04");
        assert_eq!(unescape("\\134"), "\\");
    }

    #[test]
    fn classifies_filesystem_types_into_semantics_and_backing() {
        assert_eq!(semantics_of("ext4"), FilesystemSemantics::Ext4);
        assert_eq!(semantics_of("fuse.sshfs"), FilesystemSemantics::Fuse);
        assert_eq!(semantics_of("fusectl"), FilesystemSemantics::Other("fusectl".to_owned()));
        assert_eq!(semantics_of("proc"), FilesystemSemantics::Other("proc".to_owned()));
        assert_eq!(semantics_of(""), FilesystemSemantics::Unknown);
        assert_eq!(backing_of("nfs4"), Backing::Network);
        assert_eq!(backing_of("btrfs"), Backing::MultiDevice);
        assert_eq!(backing_of("fuse.sshfs"), Backing::Userspace);
        assert_eq!(backing_of("wobble"), Backing::Unknown);
    }

    #[test]
    fn a_filesystem_that_always_fills_the_directory_entry_type_declares_inline_kinds() {
        assert_eq!(table("ext4").kind_source, KindSource::Always);
        assert_eq!(table("btrfs").kind_source, KindSource::Always);
        assert_eq!(table("tmpfs").kind_source, KindSource::Always);
        assert_eq!(
            table("xfs").kind_source,
            KindSource::Sometimes,
            "RFC 10.1: an xfs formatted without ftype reports DT_UNKNOWN, so the table does not promise inline kinds"
        );
        assert_eq!(table("nfs4").kind_source, KindSource::Sometimes);
        assert_eq!(table("fuse.sshfs").kind_source, KindSource::Sometimes);
        assert_eq!(capabilities_of(None, &Declarations::default()).kind_source, KindSource::Sometimes);
    }

    #[test]
    fn a_domain_without_a_resolved_instance_declares_unknown_for_every_detected_field() {
        let capabilities = capabilities_of(None, &Declarations::default());
        assert_eq!(capabilities.filesystem, FilesystemInstance::Unknown);
        assert_eq!(capabilities.semantics, FilesystemSemantics::Unknown);
        assert_eq!(capabilities.topology, AccessTopology::Unknown);
        assert_eq!(capabilities.sources.filesystem, DeclarationSource::Unknown);
        assert_eq!(capabilities.sources.semantics, DeclarationSource::Unknown);
        assert_eq!(capabilities.sources.topology, DeclarationSource::Unknown);
        assert_eq!(capabilities.watcher.observes_external_writers, Answer::Unknown);
        assert_eq!(capabilities.identity_reliability, IdentityReliability::Unknown);
    }

    #[test]
    fn a_resolved_instance_names_the_superblock_it_supplies() {
        let resolved =
            Instance { fs_type: "btrfs".to_owned(), source: None, device: Some(Device { major: 0, minor: 29 }) };
        let capabilities = capabilities_of(Some(&resolved), &Declarations::default());
        assert_eq!(
            capabilities.filesystem,
            FilesystemInstance::Known(FilesystemInstanceKey::linux_superblock(0, 29)),
            "RFC 14.3: a domain records the underlying filesystem instance where the platform exposes it"
        );
        assert_eq!(capabilities.sources.filesystem, DeclarationSource::Detected);
    }

    #[test]
    fn a_network_domain_declares_that_it_cannot_observe_external_writers() {
        let resolved = Instance { fs_type: "nfs4".to_owned(), source: Some("server:/export".to_owned()), device: None };
        let capabilities = capabilities_of(Some(&resolved), &Declarations::default());
        assert_eq!(capabilities.semantics, FilesystemSemantics::Nfs);
        assert_eq!(capabilities.topology, AccessTopology::Remote);
        assert_eq!(capabilities.transport, TransportHint::Network);
        assert_eq!(capabilities.watcher.observes_external_writers, Answer::No);
        assert_eq!(capabilities.watcher.polling_fallback_required, Answer::Yes);
        assert_eq!(capabilities.identity_reliability, IdentityReliability::Advisory);
    }

    #[test]
    fn a_per_directory_case_attribute_is_declared_as_such() {
        let capabilities = table("ext4");
        assert_eq!(
            capabilities.case,
            DomainCaseSensitivity::PerDirectory { domain_default: CaseSensitivity::Sensitive }
        );
        assert_eq!(capabilities.sources.case, DeclarationSource::Declared);
        assert_eq!(
            capabilities.timestamp_granularity,
            TimestampGranularity::Unknown,
            "RFC 10.3: ext4 stores nanosecond timestamps only with 256-byte inodes, which no query reports, so the \
             table declares Unknown"
        );
        assert_eq!(capabilities.sources.timestamp_granularity, DeclarationSource::Unknown);
        assert_eq!(capabilities.identity_reliability, IdentityReliability::Stable);
    }

    #[test]
    fn a_declared_override_replaces_the_table_entry_for_one_filesystem_type() {
        let declarations = LinuxProbe::new()
            .declare_timestamp_granularity("ext4", TimestampGranularity::Resolution(Duration::from_nanos(1)))
            .declare_case("xfs", DomainCaseSensitivity::Insensitive)
            .declarations;
        let ext4 = capabilities_of(Some(&instance("ext4")), &declarations);
        assert_eq!(ext4.timestamp_granularity, TimestampGranularity::Resolution(Duration::from_nanos(1)));
        assert_eq!(ext4.sources.timestamp_granularity, DeclarationSource::Declared);
        let xfs = capabilities_of(Some(&instance("xfs")), &declarations);
        assert_eq!(xfs.case, DomainCaseSensitivity::Insensitive, "RFC 14.3: table-driven with a declared override");
        assert_eq!(capabilities_of(Some(&instance("ext3")), &declarations).case, DomainCaseSensitivity::Sensitive);
    }

    #[test]
    fn xfs_and_zfs_declare_unknown_case_because_the_format_can_be_insensitive() {
        for fs_type in ["xfs", "zfs"] {
            let capabilities = table(fs_type);
            assert_eq!(
                capabilities.case,
                DomainCaseSensitivity::Unknown,
                "RFC 10.3: {fs_type} can be formatted case-insensitive and exposes no query, so Unknown is required"
            );
            assert_eq!(capabilities.sources.case, DeclarationSource::Unknown);
            assert_eq!(capabilities.identity_reliability, IdentityReliability::Stable);
            assert_eq!(capabilities.timestamp_granularity, TimestampGranularity::Resolution(Duration::from_nanos(1)));
        }
        assert_eq!(table("zfs").topology, AccessTopology::Unknown);
    }

    #[test]
    fn a_pseudo_filesystem_declares_its_watcher_unavailable_and_requires_polling() {
        for fs_type in ["proc", "sysfs", "cgroup2"] {
            let watcher = table(fs_type).watcher;
            assert_eq!(
                watcher.availability,
                WatcherAvailability::Unavailable,
                "RFC 10.4: inotify cannot monitor a pseudo-filesystem such as {fs_type}, so the watcher is declared \
                 unavailable, never available with silent gaps"
            );
            assert_eq!(watcher.observes_external_writers, Answer::No, "{fs_type}");
            assert_eq!(watcher.polling_fallback_required, Answer::Yes, "{fs_type}");
        }
        assert_eq!(table("tmpfs").watcher.availability, WatcherAvailability::Available);
        assert_eq!(table("ext4").watcher.availability, WatcherAvailability::Available);
    }

    #[test]
    fn tmpfs_is_local_memory_storage_with_stable_identity() {
        let capabilities = table("tmpfs");
        assert_eq!(capabilities.semantics, FilesystemSemantics::Tmpfs);
        assert_eq!(
            (capabilities.topology, capabilities.transport, capabilities.media),
            (AccessTopology::Local, TransportHint::Memory, MediaHint::Memory)
        );
        assert_eq!(capabilities.case, DomainCaseSensitivity::Sensitive);
        assert_eq!(capabilities.identity_reliability, IdentityReliability::Stable);
        assert_eq!(capabilities.watcher.observes_external_writers, Answer::Yes);
    }

    #[test]
    fn overlay_declares_advisory_identity_and_no_view_of_external_writers() {
        let capabilities = table("overlay");
        assert_eq!(capabilities.semantics, FilesystemSemantics::Overlay);
        assert_eq!(capabilities.identity_reliability, IdentityReliability::Advisory);
        assert!(!capabilities.identity_reliability.establishes_rename());
        assert_eq!(capabilities.watcher.observes_external_writers, Answer::No);
        assert_eq!(capabilities.watcher.polling_fallback_required, Answer::Yes);
        assert_eq!(capabilities.topology, AccessTopology::Unknown);
    }

    #[test]
    fn fat_family_declares_no_identity_insensitive_names_and_coarse_timestamps() {
        for fs_type in ["vfat", "msdos", "exfat"] {
            let capabilities = table(fs_type);
            assert_eq!(capabilities.identity_reliability, IdentityReliability::None, "{fs_type}");
            assert_eq!(capabilities.case, DomainCaseSensitivity::Insensitive, "{fs_type}");
        }
        assert_eq!(table("vfat").timestamp_granularity, TimestampGranularity::Resolution(Duration::from_secs(2)));
        assert_eq!(table("exfat").timestamp_granularity, TimestampGranularity::Resolution(Duration::from_millis(10)));
        assert_eq!(table("exfat").semantics, FilesystemSemantics::ExFat);
        assert_eq!(table("msdos").semantics, FilesystemSemantics::Fat);
    }

    #[test]
    fn mounted_smb_and_ceph_are_remote_with_advisory_identity_and_server_decided_case() {
        for fs_type in ["cifs", "smb3", "ceph"] {
            let capabilities = table(fs_type);
            assert_eq!(capabilities.topology, AccessTopology::Remote, "{fs_type}");
            assert_eq!(capabilities.transport, TransportHint::Network, "{fs_type}");
            assert_eq!(capabilities.identity_reliability, IdentityReliability::Advisory, "{fs_type}");
            assert_eq!(capabilities.case, DomainCaseSensitivity::Unknown, "{fs_type}");
            assert_eq!(capabilities.watcher.observes_external_writers, Answer::No, "{fs_type}");
        }
        assert_eq!(table("cifs").semantics, FilesystemSemantics::Smb);
        assert_eq!(table("ceph").semantics, FilesystemSemantics::Other("ceph".to_owned()));
    }

    #[test]
    fn fuse_and_sshfs_declare_unknown_for_everything_the_daemon_decides() {
        for fs_type in ["fuse", "fuse.sshfs", "fuse.gvfsd-fuse"] {
            let capabilities = table(fs_type);
            assert_eq!(capabilities.semantics, FilesystemSemantics::Fuse, "{fs_type}");
            assert_eq!(capabilities.topology, AccessTopology::Userspace, "{fs_type}");
            assert_eq!(capabilities.transport, TransportHint::Unknown, "{fs_type}");
            assert_eq!(capabilities.case, DomainCaseSensitivity::Unknown, "{fs_type}");
            assert_eq!(capabilities.timestamp_granularity, TimestampGranularity::Unknown, "{fs_type}");
            assert_eq!(capabilities.identity_reliability, IdentityReliability::Advisory, "{fs_type}");
            assert_eq!(capabilities.watcher.observes_external_writers, Answer::No, "{fs_type}");
            assert_eq!(capabilities.watcher.polling_fallback_required, Answer::Yes, "{fs_type}");
        }
    }

    #[test]
    fn the_probe_asks_statx_for_kernel_local_facts_without_forcing_a_server_round_trip() {
        assert!(PROBE_FLAGS.contains(AtFlags::STATX_DONT_SYNC));
        assert!(PROBE_FLAGS.contains(AtFlags::NO_AUTOMOUNT));
        assert!(PROBE_FLAGS.contains(AtFlags::SYMLINK_NOFOLLOW));
        assert!(!PROBE_FLAGS.contains(AtFlags::STATX_FORCE_SYNC));
        assert_eq!(PROBE_MASK, StatxFlags::TYPE | STATX_MNT_ID_UNIQUE | StatxFlags::MNT_ID);
    }

    #[test]
    fn the_mount_identifier_prefers_the_unique_id_then_the_reusable_id_then_the_device() {
        assert_eq!(mount_id(STATX_MNT_ID_UNIQUE.bits() | StatxFlags::TYPE.bits(), 7), MountId::Unique(7));
        assert_eq!(mount_id(StatxFlags::MNT_ID.bits(), 7), MountId::Reusable(7));
        assert_eq!(mount_id(StatxFlags::TYPE.bits(), 7), MountId::Device);
    }

    #[test]
    fn only_a_unique_mount_identifier_becomes_a_process_stable_domain_key() {
        let device = Device { major: 8, minor: 1 };
        assert_eq!(
            identity_of(MountId::Unique(7), device),
            DomainIdentity::Known(DomainKey::linux_unique_mount(7)),
            "RFC 15.9: a unique mount identifier is unique for the lifetime of the process, so it names a storage \
             domain every tree in the process shares"
        );
        for weak in [identity_of(MountId::Reusable(7), device), identity_of(MountId::Device, device)] {
            assert!(
                !weak.is_known(),
                "RFC 15.9: a reusable mount identifier is recycled and a device number cannot tell two bind mounts \
                 apart, so neither may name a process-wide storage domain; the probe answered {weak:?}"
            );
            assert_eq!(weak.key(), None, "the weak evidence must not reach the process-wide key table");
        }
    }

    #[test]
    fn the_mount_root_attribute_is_read_only_where_the_kernel_supports_it() {
        assert_eq!(mount_root_of(StatxAttributes::empty(), StatxAttributes::MOUNT_ROOT), None);
        assert_eq!(mount_root_of(StatxAttributes::MOUNT_ROOT, StatxAttributes::MOUNT_ROOT), Some(true));
        assert_eq!(mount_root_of(StatxAttributes::MOUNT_ROOT, StatxAttributes::empty()), Some(false));
    }

    #[test]
    fn on_the_device_fallback_only_the_mount_root_attribute_proves_a_crossing() {
        let parent =
            ProbeResult { identity: DomainIdentity::Weak(WeakDomainKey::linux_device(8, 1)), ..ProbeResult::unknown() };
        let other = DomainIdentity::Weak(WeakDomainKey::linux_device(0, 40));
        assert_eq!(
            crossing(Some(&parent), &other, MountId::Device, Some(false)),
            Crossing::Inconclusive,
            "RFC 14.3: a changed st_dev alone is not a crossing, a Btrfs subvolume changes it within one mount"
        );
        assert_eq!(crossing(Some(&parent), &other, MountId::Device, None), Crossing::Inconclusive);
        assert_eq!(crossing(Some(&parent), &other, MountId::Device, Some(true)), Crossing::Proven);
        let same = DomainIdentity::Weak(WeakDomainKey::linux_device(8, 1));
        assert_eq!(
            crossing(Some(&parent), &same, MountId::Device, Some(true)),
            Crossing::Proven,
            "RFC 14.3: bind mounts share one st_dev, so an equal st_dev is not proof of the opposite"
        );
        let reusable = DomainIdentity::Weak(WeakDomainKey::linux_reusable_mount(3));
        let reusable_parent = ProbeResult { identity: reusable.clone(), ..ProbeResult::unknown() };
        assert_eq!(crossing(Some(&reusable_parent), &reusable, MountId::Reusable(3), None), Crossing::NotCrossed);
        let next = DomainIdentity::Weak(WeakDomainKey::linux_reusable_mount(4));
        assert_eq!(crossing(Some(&reusable_parent), &next, MountId::Reusable(4), None), Crossing::Proven);
        assert_eq!(crossing(None, &next, MountId::Reusable(4), Some(true)), Crossing::NotCrossed);
    }

    fn chain(nodes: &[(&str, Option<&str>)]) -> Vec<ChainNode> {
        nodes
            .iter()
            .map(|(name, subsystem)| ChainNode { name: (*name).to_owned(), subsystem: subsystem.map(str::to_owned) })
            .collect()
    }

    #[test]
    fn the_device_chain_classifies_iscsi_fibre_channel_sas_and_sata_transports() {
        let iscsi = chain(&[
            ("sda", Some("block")),
            ("2:0:0:0", Some("scsi")),
            ("target2:0:0", Some("scsi")),
            ("session1", Some("iscsi_session")),
            ("host2", Some("scsi")),
            ("platform", None),
        ]);
        assert_eq!(
            transport_from_chain(&iscsi),
            TransportHint::Iscsi,
            "RFC 10.3: an ext4 filesystem reached over iSCSI is topologically remote block storage"
        );
        assert_eq!(topology_for(TransportHint::Iscsi), AccessTopology::Remote);
        let fibre = chain(&[
            ("sdb", Some("block")),
            ("3:0:1:0", Some("scsi")),
            ("target3:0:1", Some("scsi")),
            ("rport-3:0-1", Some("fc_remote_ports")),
            ("host3", Some("scsi")),
            ("0000:03:00.0", Some("pci")),
        ]);
        assert_eq!(transport_from_chain(&fibre), TransportHint::FibreChannel);
        let sas = chain(&[
            ("sdc", Some("block")),
            ("4:0:2:0", Some("scsi")),
            ("target4:0:2", Some("scsi")),
            ("end_device-4:2", Some("sas_device")),
            ("port-4:2", Some("sas_port")),
            ("host4", Some("scsi")),
        ]);
        assert_eq!(transport_from_chain(&sas), TransportHint::Sas);
        let sata = chain(&[
            ("sdd", Some("block")),
            ("0:0:0:0", Some("scsi")),
            ("target0:0:0", Some("scsi")),
            ("host0", Some("scsi")),
            ("ata1", Some("ata_port")),
            ("0000:00:17.0", Some("pci")),
        ]);
        assert_eq!(transport_from_chain(&sata), TransportHint::Sata);
        let usb = chain(&[
            ("sde", Some("block")),
            ("5:0:0:0", Some("scsi")),
            ("host5", Some("scsi")),
            ("2-1:1.0", Some("usb")),
            ("usb2", Some("usb")),
        ]);
        assert_eq!(transport_from_chain(&usb), TransportHint::Usb);
        let bare = chain(&[("sdf", Some("block")), ("6:0:0:0", Some("scsi")), ("host6", Some("scsi"))]);
        assert_eq!(transport_from_chain(&bare), TransportHint::Unknown);
        assert_eq!(
            transport_from_chain(&chain(&[("nvme0n1", Some("block")), ("nvme0", Some("nvme"))])),
            TransportHint::Nvme
        );
    }

    fn mount_points() -> Vec<String> {
        let text = fs::read_to_string(MOUNTINFO).expect("mountinfo");
        text.lines().filter_map(|line| line.split(' ').nth(4).map(unescape)).collect()
    }

    #[test]
    fn statmount_and_mountinfo_agree_wherever_both_resolve_an_instance() {
        for path in mount_points() {
            let Ok(stat) = statx(CWD, path.as_str(), PROBE_FLAGS, PROBE_MASK) else {
                continue;
            };
            let MountId::Unique(mount) = mount_id(stat.stx_mask, stat.stx_mnt_id) else {
                continue;
            };
            let Some(direct) = statmount_instance(mount) else {
                continue;
            };
            let device = Device { major: stat.stx_dev_major, minor: stat.stx_dev_minor };
            let Some(fallback) = mountinfo_instance(None, device) else {
                continue;
            };
            assert_eq!(direct.fs_type, fallback.fs_type, "{path}");
            assert_eq!(
                direct.device, fallback.device,
                "RFC 14.3: statmount's superblock device and mountinfo's major:minor name one filesystem instance \
                 for {path}"
            );
        }
    }

    #[test]
    fn every_mounted_domain_reports_a_declaration_source_for_each_known_field() {
        for path in mount_points() {
            let Ok(result) = LinuxProbe::new().probe(Path::new(&path), None) else {
                continue;
            };
            let capabilities = &result.capabilities;
            let sources = &capabilities.sources;
            assert_eq!(
                capabilities.filesystem != FilesystemInstance::Unknown,
                sources.filesystem != DeclarationSource::Unknown,
                "{path}"
            );
            assert_eq!(
                capabilities.semantics != FilesystemSemantics::Unknown,
                sources.semantics != DeclarationSource::Unknown,
                "{path}"
            );
            assert_eq!(
                capabilities.topology != AccessTopology::Unknown,
                sources.topology != DeclarationSource::Unknown,
                "{path}"
            );
            assert_eq!(
                capabilities.transport != TransportHint::Unknown,
                sources.transport != DeclarationSource::Unknown,
                "{path}"
            );
            assert_eq!(capabilities.media != MediaHint::Unknown, sources.media != DeclarationSource::Unknown, "{path}");
            if capabilities.transport != TransportHint::Unknown {
                assert_ne!(capabilities.topology, AccessTopology::Unknown, "{path}");
            }
        }
    }

    #[test]
    fn two_mounts_of_one_btrfs_filesystem_share_the_instance_and_split_the_identity_space_per_subvolume() {
        let probe = LinuxProbe::new();
        let mut btrfs: Vec<(String, ProbeResult)> = Vec::new();
        for path in mount_points() {
            let Ok(result) = probe.probe(Path::new(&path), None) else {
                continue;
            };
            if result.capabilities.semantics == FilesystemSemantics::Btrfs {
                btrfs.push((path, result));
            }
        }
        let mut pairs = 0;
        for (index, (first_path, first)) in btrfs.iter().enumerate() {
            for (second_path, second) in btrfs.iter().skip(index + 1) {
                if !first.capabilities.same_filesystem_as(&second.capabilities) {
                    continue;
                }
                pairs += 1;
                assert_ne!(first.identity, second.identity, "{first_path} and {second_path} are two mounts");
                if first.capabilities.identity_space != second.capabilities.identity_space {
                    assert!(
                        !first.capabilities.identities_comparable(&second.capabilities),
                        "RFC 7.1: two subvolumes of one Btrfs filesystem are two identity spaces; {first_path} and \
                         {second_path}"
                    );
                }
            }
        }
        if btrfs.len() >= 2 {
            assert!(pairs > 0 || btrfs.iter().all(|(_, r)| r.capabilities.filesystem == FilesystemInstance::Unknown));
        }
    }

    #[test]
    fn recognises_an_ata_host_directory_name() {
        assert!(is_ata_host("ata1"));
        assert!(is_ata_host("ata12"));
        assert!(!is_ata_host("ata"));
        assert!(!is_ata_host("atax"));
        assert!(!is_ata_host("sata1"));
    }

    #[test]
    fn reads_a_nul_terminated_string_out_of_a_statmount_buffer() {
        let strings = b"btrfs\0/dev/nvme0n1p2\0";
        assert_eq!(string_at(strings, 0), Some("btrfs".to_owned()));
        assert_eq!(string_at(strings, 6), Some("/dev/nvme0n1p2".to_owned()));
        assert_eq!(string_at(strings, 99), None);
    }

    #[test]
    fn a_directorys_case_attribute_is_read_where_the_ioctl_succeeds() {
        let mut read = 0;
        for path in ["/", "/tmp", "/home"] {
            let Ok(handle) = fs::File::open(path) else {
                continue;
            };
            let Ok(flags) = ioctl_getflags(&handle) else {
                continue;
            };
            assert!(!flags.contains(FS_CASEFOLD_FL), "{path} is a casefolded directory on this host");
            assert_eq!(
                directory_case(Path::new(path)),
                Some(CaseSensitivity::Sensitive),
                "RFC 14.3: case sensitivity on ext4 and f2fs is a per-directory attribute, so a directory whose \
                 inode flags the adapter read answers the attribute it read for {path}"
            );
            read += 1;
        }
        assert!(read > 0, "the inode-flags ioctl succeeded on no directory, so nothing was read");
        assert_eq!(
            directory_case(Path::new("/proc")),
            None,
            "RFC 10.3: a directory whose inode flags the adapter cannot read answers Unknown, never a guess"
        );
    }

    #[test]
    fn a_probe_refines_case_only_on_a_per_directory_domain() {
        let probe = LinuxProbe::new();
        let Ok(mountinfo) = fs::read_to_string(MOUNTINFO) else {
            return;
        };
        let mut probed = 0;
        for line in mountinfo.lines() {
            let Some(target) = line.split(' ').nth(4) else {
                continue;
            };
            let Ok(result) = probe.probe(Path::new(target), None) else {
                continue;
            };
            probed += 1;
            match result.capabilities.case {
                DomainCaseSensitivity::PerDirectory { .. } => assert_eq!(
                    result.directory_case,
                    directory_case(Path::new(target)),
                    "RFC 10.3: a domain declaring PerDirectory carries the attribute the adapter read for {target}"
                ),
                declared => assert_eq!(
                    result.directory_case, None,
                    "RFC 10.3: case sensitivity is refined per directory only where the platform carries a \
                     per-directory attribute; {target} declares {declared:?}"
                ),
            }
        }
        assert!(probed > 0, "no mount on this host could be probed");
    }

    #[test]
    fn a_symbolic_link_to_a_directory_is_never_probed_as_the_directory_it_names() {
        let base = std::env::temp_dir().join(format!("tree-fucker-linux-probe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("target")).expect("target");
        let link = base.join("link");
        std::os::unix::fs::symlink(base.join("target"), &link).expect("symlink");
        assert_eq!(
            LinuxProbe::new().probe(&link, None),
            Err(ProbeError::NotDirectory),
            "RFC 14.2: symbolic links are entries and are never traversed, so the probe answers for the link itself"
        );
        assert_eq!(directory_case(&link), None);
        assert!(LinuxProbe::new().probe(&base.join("target"), None).is_ok());
        let _ = fs::remove_dir_all(&base);
    }
}
