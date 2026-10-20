//! FreeBSD retained tmpfs coordination.
//!
//! Discovery uses an administrator-mounted tmpfs at `/var/run/tree-fucker`.
//! Explicit scopes must also reside on tmpfs. The filesystem root and effective
//! user qualify the scope, including compatible jail views. Capability mode
//! cannot provide the namespace access required for validation.
//! Retained state cannot survive a reboot into a different monotonic epoch.

use std::fs::{self, File};
use std::io;

pub use super::unix::{AccessCounters, Client, Completion, Diagnostics, Error, Prepared, Scope};

pub(super) const MAGIC: &[u8; 8] = b"TFBSD001";
pub(super) const RENDEZVOUS: &str = "/var/run/tree-fucker";

pub(super) fn namespaces() -> Result<[[u8; 16]; 3], Error> {
    let mut capability_mode = 0;
    // SAFETY: the kernel writes one unsigned integer to a live writable value.
    if unsafe { libc::cap_getmode(&mut capability_mode) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if capability_mode != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "coordination requires namespace access").into());
    }
    // Jails with the same filesystem root and effective user share the same
    // retained files and kernel monotonic clock. Their separate jail IDs must
    // not manufacture independent allowances. A different root is incompatible
    // even when it exposes the original retained files through another path.
    Ok([super::unix::identity(&fs::metadata("/")?), *b"freebsd-root-ns\0", *b"freebsd-monotime"])
}

pub(super) fn is_tmpfs(file: &File) -> Result<bool, Error> {
    let stat = rustix::fs::fstatfs(file)?;
    Ok(stat.f_fstypename[..5].iter().copied().map(|byte| byte as u8).eq(*b"tmpfs") && stat.f_fstypename[5] == 0)
}
