#[cfg(target_os = "freebsd")]
pub use tree_fucker::coordination::freebsd as native;
#[cfg(target_os = "linux")]
pub use tree_fucker::coordination::linux as native;

#[cfg(target_os = "linux")]
pub const RENDEZVOUS: &str = "/dev/shm";
#[cfg(target_os = "freebsd")]
pub const RENDEZVOUS: &str = "/var/run/tree-fucker";

#[cfg(target_os = "illumos")]
pub use tree_fucker::coordination::illumos as native;
#[cfg(target_os = "illumos")]
pub const RENDEZVOUS: &str = "/var/run/tree-fucker";

#[cfg(target_os = "macos")]
pub use tree_fucker::coordination::macos as native;
#[cfg(target_os = "macos")]
pub const RENDEZVOUS: &str = "/var/run/tree-fucker";

#[cfg(windows)]
pub use tree_fucker::coordination::windows as native;
