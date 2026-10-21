//! Daemonless coordination protocol.
//!
//! The ownership ledger, admission authority, and recoverable journal are
//! platform-independent. Native interprocess synchronization and an installed
//! backend are separate integration layers. A backend must hold its exclusive
//! bookkeeping lock across each journal transaction before returning an
//! admission decision or authorizing target-filesystem work.

pub mod authority;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
mod client;
#[cfg(target_os = "freebsd")]
pub mod freebsd;
#[cfg(target_os = "illumos")]
pub mod illumos;
pub mod journal;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
mod native_error;
mod policy;
pub mod protocol;
pub(crate) use policy::Selection;
pub use policy::{Error, Mode, Options, Rendezvous, ScopeIdentity, ScopeInfo, State, Status};
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos"))]
pub(crate) mod unix;
mod wire;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos"))]
pub(crate) use unix as native;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub(crate) use windows as native;
