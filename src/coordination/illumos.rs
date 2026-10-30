//! illumos coordination on zone-local retained tmpfs storage.
//!
//! Discovery uses an administrator-created sticky directory at
//! `/var/run/tree-fucker`, which must reside on tmpfs. The kernel's monotonic
//! epoch and the retained storage share a boot lifetime. Root and zone
//! incarnation qualify the scope. Native flock uses open-file-description
//! ownership.

use std::fs::{self, File};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;

pub use super::unix::{AccessCounters, Client, Completion, Diagnostics, Error, Prepared, Scope};

pub(super) const MAGIC: &[u8; 8] = b"TFILL001";
pub(super) const RENDEZVOUS: &str = "/var/run/tree-fucker";

unsafe extern "C" {
    fn getzoneid() -> libc::zoneid_t;
    fn zone_getattr(id: libc::zoneid_t, attr: libc::c_int, buf: *mut libc::c_void, size: usize) -> libc::ssize_t;
}

pub(super) fn namespaces() -> Result<[[u8; 16]; 3], Error> {
    // SAFETY: getzoneid takes no pointers and returns this process's zone ID.
    let id = unsafe { getzoneid() };
    if id < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // sys/zone.h: unlike zoneid_t, ZONE_ATTR_UNIQID identifies the zone's
    // incarnation and is not reused when a zone is shut down and recreated.
    const ZONE_ATTR_UNIQID: libc::c_int = 5;
    let mut incarnation = 0_u64;
    // SAFETY: the native attribute is uint64_t; its output buffer remains
    // writable for the call. Validate the returned native size before use.
    let length = unsafe { zone_getattr(id, ZONE_ATTR_UNIQID, (&mut incarnation as *mut u64).cast(), size_of::<u64>()) };
    if length < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if length as usize != size_of::<u64>() {
        return Err(Error::Incompatible);
    }
    let mut zone = [0; 16];
    zone[..4].copy_from_slice(b"zone");
    zone[4..8].copy_from_slice(&(id as u32).to_le_bytes());
    zone[8..].copy_from_slice(&incarnation.to_le_bytes());
    Ok([super::unix::identity(&fs::metadata("/")?), zone, *b"illumos-monotime"])
}

pub(super) fn is_tmpfs(file: &File) -> Result<bool, Error> {
    let mut stat = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: the descriptor is live and the output allocation has the exact
    // native statvfs ABI size and alignment.
    if unsafe { libc::fstatvfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: a successful fstatvfs initializes the entire result.
    let stat = unsafe { stat.assume_init() };
    Ok(stat.f_basetype[..5].iter().copied().map(|byte| byte as u8).eq(*b"tmpfs") && stat.f_basetype[5] == 0)
}
