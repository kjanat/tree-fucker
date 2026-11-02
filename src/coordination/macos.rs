//! macOS coordination on administrator-mounted tmpfs storage.
//!
//! Discovery uses `/var/run/tree-fucker`. The retained mount and kernel
//! monotonic clock share a boot lifetime; closing the final application does
//! not remove accounting. Filesystem root identity and effective user qualify
//! the scope. Sandbox denial is handled through the ordinary access checks.

use std::fs::{self, File};

pub use super::unix::{AccessCounters, Client, Completion, Diagnostics, Error, Prepared, Scope};

pub(super) const MAGIC: &[u8; 8] = b"TFMAC001";
pub(super) const RENDEZVOUS: &str = "/var/run/tree-fucker";

pub(super) fn namespaces() -> Result<[[u8; 16]; 3], Error> {
    Ok([super::unix::identity(&fs::metadata("/")?), *b"darwin-root-ns\0\0", *b"darwin-monotime\0"])
}

pub(super) fn is_tmpfs(file: &File) -> Result<bool, Error> {
    let stat = rustix::fs::fstatfs(file)?;
    Ok(stat.f_fstypename[..5].iter().copied().map(|byte| byte as u8).eq(*b"tmpfs") && stat.f_fstypename[5] == 0)
}
