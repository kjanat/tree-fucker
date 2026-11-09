use std::path::PathBuf;

use super::{authority, protocol};

/// `Mode` selects how a governor coordinates admission with other processes.
///
/// The application chooses a mode before any filesystem work and passes it to
/// [`HostGovernor::configured`](crate::HostGovernor::configured) or
/// [`HostGovernor::install_with_coordination`](crate::HostGovernor::install_with_coordination).
/// coordination.md specifies the policy in "Failure modes and API policy".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// The governor admits work under process-local policy alone and performs
    /// no native discovery.
    #[default]
    ProcessOnly,
    /// The governor joins the shared scope, and it falls back to process-only
    /// policy when the platform has no backend or the rendezvous is
    /// unavailable before join.
    ///
    /// Every other failure, and any failure during or after join, is an error.
    Auto(Options),
    /// The governor requires shared protection, and every discovery or join
    /// failure is an error.
    Required(Options),
}

/// `Options` names the shared scope and the limits a governor joins it with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// `scope` names the rendezvous where the governor opens the shared
    /// authority.
    pub scope: Rendezvous,
    /// `limits` holds the authoritative limits, and all participants must
    /// agree on them.
    ///
    /// The first participant records them in the authority, and a later
    /// participant with different limits receives [`Error::Incompatible`].
    pub limits: authority::Config,
}

/// `Rendezvous` tells the backend where to find the shared authority.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Rendezvous {
    /// The backend derives the platform's private scope location for the
    /// effective user and namespace.
    ///
    /// coordination-platforms.md specifies the location on each platform.
    #[default]
    Discover,
    /// The backend opens the scope at this absolute directory.
    ///
    /// Every cooperating participant must name the same directory, and the
    /// directory must satisfy the platform's storage requirements.
    Directory(PathBuf),
}

/// `Error` reports a coordination configuration or connection failure.
///
/// Only [`Error::UnsupportedPlatform`] and [`Error::Unavailable`] before join
/// let [`Mode::Auto`] fall back to process-only policy. A failure during or
/// after join never permits fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The target platform has no native shared backend.
    UnsupportedPlatform,
    /// The shared limits fail validation, and the message names the cause.
    InvalidConfig(String),
    /// The rendezvous does not exist, denies access, or uses unsupported
    /// storage, and the message names the cause.
    Unavailable(String),
    /// Another connection holds the bookkeeping lock, and the caller may retry
    /// joining the same authority.
    Busy,
    /// The scope location fails the platform's storage, ownership, or
    /// permission requirements.
    InvalidScope,
    /// The retained authority records a different configuration, generation,
    /// or scope identity.
    Incompatible,
    /// The participant, operation, or domain table is full, and the message
    /// names the table.
    Capacity(String),
    /// Another native failure occurred, and the message describes it.
    Failed(String),
}

impl Error {
    pub(crate) fn permits_fallback(&self) -> bool {
        matches!(self, Self::UnsupportedPlatform | Self::Unavailable(_))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPlatform => f.write_str("native shared coordination is unavailable on this platform"),
            Self::InvalidConfig(message) => write!(f, "invalid coordination configuration: {message}"),
            Self::Unavailable(message) => write!(f, "coordination is unavailable: {message}"),
            Self::Busy => f.write_str("coordination is busy; retry joining the same authority"),
            Self::InvalidScope => {
                f.write_str("coordination scope does not meet native storage and ownership requirements")
            }
            Self::Incompatible => f.write_str("coordination configuration or scope is incompatible"),
            Self::Capacity(message) | Self::Failed(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows))]
impl From<super::native::Error> for Error {
    fn from(error: super::native::Error) -> Self {
        use super::native::Error as Native;
        match error {
            Native::Busy => Self::Busy,
            Native::InvalidScope => Self::InvalidScope,
            Native::Incompatible => Self::Incompatible,
            Native::Authority(authority::Error::InvalidConfig) => Self::InvalidConfig(error.to_string()),
            Native::Authority(
                authority::Error::DomainCapacity
                | authority::Error::Protocol(protocol::Error::ParticipantCapacity | protocol::Error::OperationCapacity),
            ) => Self::Capacity(error.to_string()),
            Native::Io(ref io)
                if matches!(
                    io.kind(),
                    std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::PermissionDenied
                        | std::io::ErrorKind::Unsupported
                ) =>
            {
                Self::Unavailable(error.to_string())
            }
            _ => Self::Failed(error.to_string()),
        }
    }
}

/// `ScopeInfo` describes the shared scope that a governor joined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeInfo {
    /// `directory` names the directory where the governor opened the scope.
    pub directory: PathBuf,
    /// `generation` identifies the retained authority that owns the scope's
    /// accounting.
    pub generation: protocol::Generation,
    /// `participant` identifies the governor's participant incarnation within
    /// the authority.
    pub participant: protocol::Participant,
    /// `limits` holds the limits that the authority enforces for every
    /// participant.
    pub limits: authority::Config,
    /// `identity` records the security, namespace, and clock boundary of the
    /// scope.
    pub identity: ScopeIdentity,
}

/// `ScopeIdentity` records the platform boundary that qualifies a shared scope.
///
/// Participants join one authority only when every component matches.
/// coordination-platforms.md specifies each platform's boundary.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeIdentity {
    /// The Windows backend qualifies the scope by user, boot clock, and scope
    /// directory.
    Windows {
        /// `user` holds the effective user's SID.
        user: String,
        /// `clock` encodes the boot-entry GUID, kernel boot sequence, and
        /// performance-counter frequency.
        clock: [u8; 32],
        /// `volume` holds the volume serial number of the scope directory.
        volume: u64,
        /// `root` holds the 128-bit file ID of the scope directory.
        root: [u8; 16],
    },
    /// The Linux backend qualifies the scope by the caller's user, IPC, and
    /// time namespaces.
    Linux {
        /// `user` holds the device and inode of the user namespace.
        user: [u8; 16],
        /// `ipc` holds the device and inode of the IPC namespace.
        ipc: [u8; 16],
        /// `time` holds the device and inode of the time namespace.
        time: [u8; 16],
    },
    /// The macOS backend qualifies the scope by filesystem root and kernel
    /// monotonic clock.
    MacOs {
        /// `root` holds the device and inode of the filesystem root.
        root: [u8; 16],
        /// `clock` holds a fixed tag that names the Darwin kernel monotonic
        /// clock.
        clock: [u8; 16],
    },
    /// The FreeBSD backend qualifies the scope by filesystem root and kernel
    /// monotonic clock.
    ///
    /// Jails with the same root share one scope.
    FreeBsd {
        /// `root` holds the device and inode of the filesystem root.
        root: [u8; 16],
        /// `clock` holds a fixed tag that names the FreeBSD kernel monotonic
        /// clock.
        clock: [u8; 16],
    },
    /// The illumos backend qualifies the scope by filesystem root, zone, and
    /// kernel monotonic clock.
    Illumos {
        /// `root` holds the device and inode of the filesystem root.
        root: [u8; 16],
        /// `zone` holds the numeric zone ID and the kernel's zone incarnation.
        zone: [u8; 16],
        /// `clock` holds a fixed tag that names the illumos kernel monotonic
        /// clock.
        clock: [u8; 16],
    },
}

/// `State` reports the coordination policy that a governor applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// The governor admits work under process-local policy alone.
    ProcessOnly,
    /// [`Mode::Auto`] could not join the shared scope, and the governor fell
    /// back to process-local policy.
    Fallback {
        /// `reason` explains why the governor fell back.
        reason: Error,
    },
    /// The governor joined a shared scope, and every admission needs both
    /// authorities.
    Shared {
        /// `scope` describes the joined scope.
        scope: Box<ScopeInfo>,
        /// `failure` describes the failure that fenced shared admission.
        ///
        /// The governor admits no new shared work while `failure` is `Some`.
        failure: Option<String>,
        /// `pending_settlements` counts the settlements and cancellations that
        /// wait for the bookkeeping lock.
        ///
        /// It is `None` when the governor cannot read connection diagnostics.
        pending_settlements: Option<usize>,
        /// `bookkeeping_active` is `Some(true)` while a bookkeeping thread
        /// drains deferred settlements.
        ///
        /// It is `None` when the governor cannot read connection diagnostics.
        bookkeeping_active: Option<bool>,
    },
}

/// `Status` pairs the requested coordination mode with the effective state.
///
/// [`HostGovernor::coordination_status`](crate::HostGovernor::coordination_status)
/// returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// `requested` holds the mode that the application requested.
    pub requested: Mode,
    /// `state` holds the state that the governor applies.
    pub state: State,
}

pub(crate) struct Selection {
    pub mode: Mode,
    pub fallback: Option<Error>,
}
