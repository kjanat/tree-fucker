use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::ProbeError;

pub(super) fn open_directory(directory: &Path) -> Result<File, ProbeError> {
    match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY).open(directory) {
        Ok(file) => Ok(file),
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) || err.raw_os_error() == Some(libc::EMLINK) => {
            Err(ProbeError::NotDirectory)
        }
        Err(err) => Err(ProbeError::from(err)),
    }
}

pub(super) fn c_string<const N: usize>(raw: &[libc::c_char; N]) -> String {
    let bytes: Vec<u8> = raw.iter().map(|value| u8::from_ne_bytes(value.to_ne_bytes())).collect();
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) fn fsid_pair(fsid: libc::fsid_t) -> (i32, i32) {
    let pair: [i32; 2] = unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(fsid) };
    (pair[0], pair[1])
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(super) fn at_mount_point(directory: &Path, mount_point: &str) -> bool {
    match std::fs::canonicalize(directory) {
        Ok(resolved) => resolved == Path::new(mount_point),
        Err(_) => false,
    }
}
