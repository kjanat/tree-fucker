use std::io;

use super::{authority, journal};

/// `Error` reports a failure of a native coordination connection.
///
/// A failure after joining never authorizes process-only fallback. An I/O,
/// journal, replacement, or fencing failure during an access fences the
/// connection, and later calls return [`Error::Failed`].
#[derive(Debug)]
pub enum Error {
    /// Another thread or process holds the connection mutex or the bookkeeping
    /// lock.
    ///
    /// The caller may retry later outside the filesystem worker.
    Busy,
    /// An operating-system call on the scope's files failed.
    Io(io::Error),
    /// The connection could not read, recover, or publish the retained journal.
    Journal(journal::Error),
    /// The shared authority rejected the requested transition.
    Authority(authority::Error),
    /// The scope location or one of its files fails the platform's storage,
    /// ownership, or permission requirements.
    InvalidScope,
    /// The scope directory, anchor, state file, or an owner file was removed
    /// or replaced after the connection pinned it.
    Replaced,
    /// The retained authority records a different configuration, generation,
    /// or scope identity, or the caller's security context changed.
    Incompatible,
    /// A child process called the API through a handle that it inherited
    /// across `fork`.
    Forked,
    /// An earlier uncertain storage failure fenced this connection, and the
    /// connection refuses further work.
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
