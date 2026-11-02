//! Validate retained storage through the opened object, not its pathname.

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr::null_mut;

use windows_sys::Wdk::Storage::FileSystem::{FileFsDeviceInformation, NtQueryVolumeInformationFile};
use windows_sys::Wdk::System::SystemServices::{FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_DEVICE_DISK, FILE_TYPE_DISK, GetFileType, GetVolumeInformationByHandleW,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Ioctl::FILE_DEVICE_DISK_FILE_SYSTEM;
use windows_sys::Win32::System::SystemServices::{
    FILE_PERSISTENT_ACLS, FILE_READ_ONLY_VOLUME, FILE_SUPPORTS_OPEN_BY_FILE_ID,
};

fn require(device: &FILE_FS_DEVICE_INFORMATION, flags: u32, filesystem: &[u16]) -> io::Result<()> {
    let Some(end) = filesystem.iter().position(|&unit| unit == 0) else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unterminated Windows filesystem name"));
    };
    let name = String::from_utf16(&filesystem[..end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Windows filesystem name"))?;
    // A file object's device can be the disk filesystem rather than the
    // underlying disk. Both still require the explicit remote-device check.
    let failure = if !matches!(device.DeviceType, FILE_DEVICE_DISK | FILE_DEVICE_DISK_FILE_SYSTEM) {
        Some("coordination storage is not a disk device")
    } else if device.Characteristics & FILE_REMOTE_DEVICE != 0 {
        Some("coordination storage is remote")
    } else if flags & FILE_PERSISTENT_ACLS == 0 {
        Some("coordination storage does not support persistent ACLs")
    } else if flags & FILE_SUPPORTS_OPEN_BY_FILE_ID == 0 {
        Some("coordination storage does not support opening files by ID")
    } else if flags & FILE_READ_ONLY_VOLUME != 0 {
        Some("coordination storage is read-only")
    } else if !matches!(name.as_str(), "NTFS" | "ReFS") {
        Some("coordination storage requires NTFS or ReFS")
    } else {
        None
    };
    if let Some(reason) = failure {
        return Err(io::Error::new(io::ErrorKind::Unsupported, reason));
    }
    Ok(())
}

/// Callers supply a synchronous file or directory handle and keep it open for
/// the authority's lifetime. A failed locality query never implies local disk.
pub(crate) fn validate(file: &File) -> io::Result<()> {
    let handle = file.as_raw_handle();
    // SAFETY: the borrowed File owns a live handle for the complete query.
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "coordination storage is not a disk"));
    }
    let mut completion = IO_STATUS_BLOCK::default();
    let mut device = FILE_FS_DEVICE_INFORMATION::default();
    // SAFETY: synchronous handle, correctly aligned live output buffers, and
    // the SDK information class matching the supplied device structure.
    let status = unsafe {
        NtQueryVolumeInformationFile(
            handle,
            &mut completion,
            (&mut device as *mut FILE_FS_DEVICE_INFORMATION).cast(),
            size_of::<FILE_FS_DEVICE_INFORMATION>() as u32,
            FileFsDeviceInformation,
        )
    };
    if status != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("Windows coordination storage query failed: NTSTATUS {status:#x}"),
        ));
    }
    if completion.Information != size_of::<FILE_FS_DEVICE_INFORMATION>() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected Windows storage information size"));
    }
    let mut flags = 0;
    let mut name = [0u16; 32];
    // SAFETY: all requested outputs are live, correctly sized buffers. Other
    // outputs are explicitly omitted, and the handle is the same pinned object.
    if unsafe {
        GetVolumeInformationByHandleW(
            handle,
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            name.as_mut_ptr(),
            name.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    require(&device, flags, &name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED: u32 = FILE_PERSISTENT_ACLS | FILE_SUPPORTS_OPEN_BY_FILE_ID;

    fn name(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }

    #[test]
    fn storage_contract_rejects_remote_and_incomplete_capabilities() {
        let local = FILE_FS_DEVICE_INFORMATION { DeviceType: FILE_DEVICE_DISK, Characteristics: 0 };
        for filesystem in ["NTFS", "ReFS"] {
            require(&local, REQUIRED, &name(filesystem)).unwrap();
            let filesystem_device = FILE_FS_DEVICE_INFORMATION { DeviceType: FILE_DEVICE_DISK_FILE_SYSTEM, ..local };
            require(&filesystem_device, REQUIRED, &name(filesystem)).unwrap();
            assert!(
                require(
                    &FILE_FS_DEVICE_INFORMATION { Characteristics: FILE_REMOTE_DEVICE, ..filesystem_device },
                    REQUIRED,
                    &name(filesystem)
                )
                .is_err()
            );
        }
        for device in [
            FILE_FS_DEVICE_INFORMATION { Characteristics: FILE_REMOTE_DEVICE, ..local },
            FILE_FS_DEVICE_INFORMATION { DeviceType: 0, ..local },
        ] {
            assert!(require(&device, REQUIRED, &name("NTFS")).is_err());
        }
        for flags in [0, FILE_PERSISTENT_ACLS, FILE_SUPPORTS_OPEN_BY_FILE_ID, REQUIRED | FILE_READ_ONLY_VOLUME] {
            assert!(require(&local, flags, &name("NTFS")).is_err());
        }
        for filesystem in ["FAT32", "exFAT", "", "unknown"] {
            assert!(require(&local, REQUIRED, &name(filesystem)).is_err());
        }
        for malformed in [&[b'N' as u16][..], &[0xd800, 0]] {
            assert!(
                matches!(require(&local, REQUIRED, malformed), Err(error) if error.kind() == io::ErrorKind::InvalidData)
            );
        }
    }

    #[test]
    fn native_retained_storage_is_checked_through_the_open_handle() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("retained");
        let file = File::create(&path).unwrap();
        validate(&file).unwrap();
        std::fs::rename(&path, directory.path().join("renamed")).unwrap();
        validate(&file).unwrap();
        let duplicate = file.try_clone().unwrap();
        drop(file);
        validate(&duplicate).unwrap();
    }
}
