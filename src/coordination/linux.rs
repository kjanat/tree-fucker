//! Linux coordination on private tmpfs storage under `/dev/shm`.
//!
//! The scope is qualified by user, IPC, and time namespaces. Accounting lasts
//! for the retained tmpfs mount, independently of participant lifetimes.

use std::fs::{self, File};

pub use super::unix::{AccessCounters, Client, Completion, Diagnostics, Error, Prepared, Scope};

pub(super) const MAGIC: &[u8; 8] = b"TFLINUX1";
pub(super) const RENDEZVOUS: &str = "/dev/shm";

pub(super) fn namespaces() -> Result<[[u8; 16]; 3], Error> {
    Ok([
        super::unix::identity(&fs::metadata("/proc/thread-self/ns/user")?),
        super::unix::identity(&fs::metadata("/proc/thread-self/ns/ipc")?),
        super::unix::identity(&fs::metadata("/proc/thread-self/ns/time")?),
    ])
}

pub(super) fn is_tmpfs(file: &File) -> Result<bool, Error> {
    // statfs uses different signedness on Linux architectures/ABIs.
    Ok(i128::from(rustix::fs::fstatfs(file)?.f_type) == i128::from(libc::TMPFS_MAGIC))
}
