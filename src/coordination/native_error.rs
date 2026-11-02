use std::io;

use super::{authority, journal};

/// Failure never authorizes process-only fallback after joining.
#[derive(Debug)]
pub enum Error {
    Busy,
    Io(io::Error),
    Journal(journal::Error),
    Authority(authority::Error),
    InvalidScope,
    Replaced,
    Incompatible,
    Forked,
    Failed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => f.write_str("coordination lock is busy; retry outside the filesystem worker"),
            Self::Io(error) => error.fmt(f),
            Self::Journal(error) => error.fmt(f),
            Self::Authority(error) => error.fmt(f),
            Self::InvalidScope => {
                f.write_str("coordination scope does not meet native storage and ownership requirements")
            }
            Self::Replaced => f.write_str("coordination authority or owner file was removed or replaced"),
            Self::Incompatible => f.write_str("coordination scope configuration or namespace is incompatible"),
            Self::Forked => f.write_str("inherited coordination handles cannot be used after fork"),
            Self::Failed => f.write_str("coordination handle is fenced after an uncertain storage failure"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(unix)]
impl From<rustix::io::Errno> for Error {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}

impl From<journal::Error> for Error {
    fn from(error: journal::Error) -> Self {
        Self::Journal(error)
    }
}

impl From<authority::Error> for Error {
    fn from(error: authority::Error) -> Self {
        Self::Authority(error)
    }
}
