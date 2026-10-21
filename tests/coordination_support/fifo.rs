use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub fn create(path: &Path) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: the NUL-terminated path remains live throughout the call.
    if unsafe { libc::mkfifo(path.as_ptr(), 0o600) } == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}
