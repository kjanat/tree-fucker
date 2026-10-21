//! Pinned Windows directory traversal and single-component relative opens.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, Prefix};
use std::ptr::{null, null_mut};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError, UNICODE_STRING};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

fn component(name: &OsStr) -> io::Result<Vec<u16>> {
    let units: Vec<_> = name.encode_wide().collect();
    if units.is_empty()
        || units.len() > (u16::MAX as usize / 2)
        || units.iter().any(|&unit| unit < 32 || b"/\\:*?\"<>|".contains(&(unit as u8)) && unit <= 127)
        || matches!(units.last(), Some(32 | 46))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "coordination requires one unambiguous path component",
        ));
    }
    Ok(units)
}

/// Open one child against a live directory handle. A creation descriptor is
/// supplied only for OPEN_IF; neither disposition truncates an existing file.
pub(crate) fn open(
    parent: &File,
    name: &OsStr,
    access: u32,
    share: u32,
    directory: bool,
    creation: Option<&SECURITY_ATTRIBUTES>,
) -> io::Result<File> {
    let mut units = component(name)?;
    let length = (units.len() * 2) as u16;
    let mut name = UNICODE_STRING { Length: length, MaximumLength: length, Buffer: units.as_mut_ptr() };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &mut name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: creation.map_or(null(), |attributes| attributes.lpSecurityDescriptor.cast()),
        SecurityQualityOfService: null_mut(),
    };
    let mut completion = IO_STATUS_BLOCK::default();
    let mut handle = null_mut();
    // SAFETY: the parent and all descriptor/name buffers remain live for this
    // synchronous call. The name is a single relative component; neither an
    // alternate stream nor an object-manager/drive namespace can be supplied.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut completion,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            if creation.is_some() { FILE_OPEN_IF } else { FILE_OPEN },
            FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_OPEN_REPARSE_POINT
                | if directory { FILE_DIRECTORY_FILE } else { FILE_NON_DIRECTORY_FILE },
            null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: the conversion takes a scalar NTSTATUS and owns no memory.
        return Err(io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32));
    }
    if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Windows relative open returned no handle"));
    }
    // SAFETY: successful synchronous creation transfers one owned handle.
    let file = unsafe { File::from_raw_handle(handle) };
    if directory {
        super::handles::directory_identity(&file)?;
    } else {
        super::handles::identity(&file)?;
    }
    Ok(file)
}

/// Ancestors stay open without delete sharing until the directory is dropped.
/// Child operations use the final handle, never reconstruct an absolute path.
pub(crate) struct Directory {
    file: File,
    _ancestors: Vec<File>,
}

impl Directory {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let mut parts = path.components();
        let Some(Component::Prefix(prefix)) = parts.next() else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "coordination requires an absolute drive path"));
        };
        if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
            || parts.next() != Some(Component::RootDir)
        {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "coordination requires an absolute drive path"));
        }
        // Resolve the drive root once. Every remaining component is resolved
        // against its pinned parent, including when a DOS device map changes.
        let mut root = prefix.as_os_str().to_os_string();
        root.push("\\");
        let access = FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE;
        let mut file = OpenOptions::new()
            .access_mode(access)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(root)?;
        super::handles::directory_identity(&file)?;
        let mut ancestors = Vec::new();
        super::storage::validate(&file)?;
        for part in parts {
            let Component::Normal(name) = part else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "coordination path contains traversal"));
            };
            let child = open(&file, name, access, FILE_SHARE_READ | FILE_SHARE_WRITE, true, None)?;
            ancestors.push(file);
            file = child;
        }
        super::storage::validate(&file)?;
        Ok(Self { file, _ancestors: ancestors })
    }

    pub(crate) fn handle(&self) -> &File {
        &self.file
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};

    use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};

    use super::*;

    #[test]
    fn relative_names_reject_traversal_streams_and_ambiguous_components() {
        for bad in ["", ".", "..", "../state", "a\\state", "state:stream", "state.", "state ", "C:", "a\0b", "*"] {
            assert!(component(OsStr::new(bad)).is_err(), "accepted {bad:?}");
        }
        for good in ["state", "owner-4095", "scope.authority.lock", "é", "字"] {
            component(OsStr::new(good)).unwrap();
        }
    }

    #[test]
    fn relative_opens_pin_ancestors_and_reopen_the_same_child() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("parent");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("state"), b"retained").unwrap();
        let directory = Directory::open(&nested).unwrap();
        assert!(std::fs::rename(root.path(), root.path().with_extension("moved")).is_err());
        assert!(std::fs::rename(&nested, root.path().join("replaced")).is_err());
        let first =
            open(directory.handle(), OsStr::new("state"), FILE_GENERIC_READ, FILE_SHARE_READ, false, None).unwrap();
        let second =
            open(directory.handle(), OsStr::new("state"), FILE_GENERIC_READ, FILE_SHARE_READ, false, None).unwrap();
        assert_eq!(super::super::handles::identity(&first).unwrap(), super::super::handles::identity(&second).unwrap());
        assert!(
            open(directory.handle(), OsStr::new("state:alternate"), FILE_GENERIC_READ, FILE_SHARE_READ, false, None)
                .is_err()
        );
        drop((first, second, directory));
        std::fs::rename(&nested, root.path().join("replaced")).unwrap();
    }

    #[test]
    fn relative_creation_preserves_existing_contents_and_sharing() {
        let root = tempfile::tempdir().unwrap();
        let directory = Directory::open(root.path()).unwrap();
        // This lower-level test exercises create disposition and sharing. The
        // Principal supplies and validates the protected descriptor separately.
        let creation = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, ..Default::default() };
        let name = OsStr::new("retained");
        let access = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
        let mut first = open(directory.handle(), name, access, 0, false, Some(&creation)).unwrap();
        first.write_all(b"retained debt").unwrap();
        let expected = super::super::handles::identity(&first).unwrap();
        let duplicate = first.try_clone().unwrap();
        drop(first);
        let attribute_pin = open(
            directory.handle(),
            name,
            FILE_READ_ATTRIBUTES | windows_sys::Win32::Storage::FileSystem::READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            false,
            None,
        )
        .unwrap();
        assert_eq!(super::super::handles::identity(&attribute_pin).unwrap(), expected);
        let conflict = open(directory.handle(), name, access, 0, false, Some(&creation)).unwrap_err();
        assert_eq!(conflict.raw_os_error(), Some(windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION as i32));
        drop(duplicate);
        let mut reopened = open(directory.handle(), name, access, 0, false, Some(&creation)).unwrap();
        assert_eq!(super::super::handles::identity(&reopened).unwrap(), expected);
        reopened.seek(SeekFrom::Start(0)).unwrap();
        let mut contents = String::new();
        reopened.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "retained debt");
        drop((reopened, attribute_pin));
        assert!(open(directory.handle(), name, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, true, None).is_err());
    }

    #[test]
    fn relative_traversal_rejects_a_real_directory_junction() {
        use windows_sys::Win32::System::IO::DeviceIoControl;
        use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
        use windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT;

        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let link = root.path().join("redirect");
        std::fs::create_dir_all(target.join("nested")).unwrap();
        std::fs::create_dir(&link).unwrap();
        let target = target.canonicalize().unwrap();
        let mut name: Vec<_> = target.as_os_str().encode_wide().collect();
        assert!(name.starts_with(&[92, 92, 63, 92]), "canonical target must use a verbatim drive path");
        // Convert the Win32 verbatim prefix to the NT substitute-name prefix.
        name[1] = b'?' as u16;
        let length: u16 = (name.len() * 2).try_into().unwrap();
        let mut bytes = vec![0u8; 16 + usize::from(length) + 4];
        bytes[..4].copy_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
        let data_length: u16 = (bytes.len() - 8).try_into().unwrap();
        bytes[4..6].copy_from_slice(&data_length.to_le_bytes());
        bytes[10..12].copy_from_slice(&length.to_le_bytes());
        bytes[12..14].copy_from_slice(&(length + 2).to_le_bytes());
        for (output, unit) in bytes[16..16 + usize::from(length)].as_chunks_mut::<2>().0.iter_mut().zip(name) {
            output.copy_from_slice(&unit.to_le_bytes());
        }
        let junction = OpenOptions::new()
            .access_mode(FILE_GENERIC_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&link)
            .unwrap();
        let mut returned = 0;
        // SAFETY: the live synchronous directory handle receives a complete
        // mount-point reparse buffer; both byte lengths include their headers.
        let success = unsafe {
            DeviceIoControl(
                junction.as_raw_handle(),
                FSCTL_SET_REPARSE_POINT,
                bytes.as_ptr().cast(),
                bytes.len() as u32,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        assert_ne!(success, 0, "junction creation failed: {}", io::Error::last_os_error());
        drop(junction);
        assert!(link.join("nested").is_dir(), "fixture must actually redirect to the target");
        assert!(Directory::open(&link).is_err());
        assert!(Directory::open(&link.join("nested")).is_err());
        let parent = Directory::open(root.path()).unwrap();
        assert!(
            open(
                parent.handle(),
                OsStr::new("redirect"),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                true,
                None
            )
            .is_err()
        );
        drop(parent);
        std::fs::remove_dir(&link).unwrap();
        assert!(target.join("nested").is_dir());
    }
}
