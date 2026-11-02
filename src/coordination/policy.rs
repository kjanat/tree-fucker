use std::path::PathBuf;

use super::{authority, protocol};

/// How an application selects shared coordination before doing filesystem work.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    ProcessOnly,
    /// Use process-only policy if native coordination is unavailable before
    /// join.
    Auto(Options),
    /// Require shared protection; every discovery or join failure is an error.
    Required(Options),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub scope: Rendezvous,
    /// All participants must agree on these authoritative limits.
    pub limits: authority::Config,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Rendezvous {
    #[default]
    Discover,
    Directory(PathBuf),
}

/// An actionable configuration or connection failure, without fallback after
/// join.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedPlatform,
    InvalidConfig(String),
    Unavailable(String),
    Busy,
    InvalidScope,
    Incompatible,
    Capacity(String),
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeInfo {
    pub directory: PathBuf,
    pub generation: protocol::Generation,
    pub participant: protocol::Participant,
    pub limits: authority::Config,
    pub identity: ScopeIdentity,
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeIdentity {
    Windows { user: String, clock: [u8; 32], volume: u64, root: [u8; 16] },
    Linux { user: [u8; 16], ipc: [u8; 16], time: [u8; 16] },
    MacOs { root: [u8; 16], clock: [u8; 16] },
    FreeBsd { root: [u8; 16], clock: [u8; 16] },
    Illumos { root: [u8; 16], zone: [u8; 16], clock: [u8; 16] },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    ProcessOnly,
    Fallback {
        reason: Error,
    },
    Shared {
        scope: Box<ScopeInfo>,
        failure: Option<String>,
        pending_settlements: Option<usize>,
        bookkeeping_active: Option<bool>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub requested: Mode,
    pub state: State,
}

pub(crate) struct Selection {
    pub mode: Mode,
    pub fallback: Option<Error>,
}
