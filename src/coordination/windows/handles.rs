//! Windows file ownership and nonblocking bookkeeping primitives.
//!
//! The enclosing authority must pin and validate the parent directory, storage,
//! and security descriptor. These primitives never unlink or truncate a slot.
//! Recovery must hold the bookkeeping lock through the journal commit and keep
//! the returned owner handle until that commit completes.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ID_INFO,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, FileIdInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFileType, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    READ_CONTROL, UnlockFileEx,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

use super::security::Principal;

/// Preserve the complete volume serial and 128-bit file identity. In
/// particular, do not truncate a ReFS identity to the older 64-bit index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub volume: u64,
    pub file: [u8; 16],
}

pub(crate) fn identity(file: &File) -> io::Result<Identity> {
    object_identity(file, false)
}

pub(crate) fn directory_identity(file: &File) -> io::Result<Identity> {
    object_identity(file, true)
}

fn object_identity(file: &File, directory: bool) -> io::Result<Identity> {
    let handle = file.as_raw_handle();
    let mut attributes = BY_HANDLE_FILE_INFORMATION::default();
    let mut id = FILE_ID_INFO::default();
    // SAFETY: the file owns a live handle and both output buffers have the
    // exact layout and size requested by their respective Windows APIs.
    unsafe {
        if GetFileType(handle) != FILE_TYPE_DISK {
            return Err(io::Error::other("coordination object is not a disk file"));
        }
        if GetFileInformationByHandle(handle, &mut attributes) == 0 {
            return Err(io::Error::last_os_error());
        }
        if attributes.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
            || (!directory && attributes.nNumberOfLinks != 1)
        {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "coordination object has an invalid type or link"));
        }
        if GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&mut id as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    if id.FileId.Identifier == [0; 16] {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "coordination object has no file identity"));
    }
    Ok(Identity { volume: id.VolumeSerialNumber, file: id.FileId.Identifier })
}

pub(crate) fn recover_at(
    parent: &File,
    name: &OsStr,
    expected: Identity,
    principal: &Principal,
) -> io::Result<Option<File>> {
    principal.check()?;
    let pin = super::relative::open(
        parent,
        name,
        FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        false,
        None,
    )?;
    principal.validate(&pin, false)?;
    if identity(&pin)? != expected {
        return Err(io::Error::other("coordination owner file was replaced"));
    }
    match principal.open_at(parent, name, false, 0, false) {
        Ok(owner) => {
            if identity(&owner)? != expected {
                return Err(io::Error::other("coordination owner file changed during recovery"));
            }
            Ok(Some(owner))
        }
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => Ok(None),
        Err(error) => Err(error),
    }
}

/// A byte-range lock belongs to bookkeeping, never physical operation lifetime.
/// The byte is beyond the anchor header so validation can still read the
/// header.
pub(crate) struct Bookkeeping<'a> {
    file: &'a File,
    held: bool,
}

impl<'a> Bookkeeping<'a> {
    fn range() -> OVERLAPPED {
        let mut range = OVERLAPPED::default();
        range.Anonymous.Anonymous.Offset = 4096;
        range
    }

    /// A conflicting independent open fails immediately, including an open in
    /// the same process. The owner of the journal also holds a local mutex.
    pub(crate) fn try_lock(file: &'a File) -> io::Result<Self> {
        let mut range = Self::range();
        // SAFETY: synchronous live file handle and initialized OVERLAPPED;
        // FAIL_IMMEDIATELY ensures the OS cannot retain the stack buffer.
        if unsafe {
            LockFileEx(file.as_raw_handle(), LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &mut range)
        } == 0
        {
            let error = io::Error::last_os_error();
            return Err(if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
                io::Error::from(io::ErrorKind::WouldBlock)
            } else {
                error
            });
        }
        Ok(Self { file, held: true })
    }

    fn release(&mut self) -> io::Result<()> {
        self.held = false;
        let mut range = Self::range();
        // SAFETY: the borrowed file still owns the same live handle and range.
        if unsafe { UnlockFileEx(self.file.as_raw_handle(), 0, 1, 0, &mut range) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The authority must fence its connection if explicit release fails.
    pub(crate) fn unlock(mut self) -> io::Result<()> {
        self.release()
    }
}

impl Drop for Bookkeeping<'_> {
    fn drop(&mut self) {
        if self.held {
            let _ = self.release();
        }
    }
}
