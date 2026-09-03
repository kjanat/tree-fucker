use std::collections::BTreeSet;
use std::fmt;

use crate::fs::FsError;
use crate::path::{PathError, RelativePath};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidConfig(String),
    InvalidPath(PathError),
    NotFound,
    NotDirectory,
    NotLoaded,
    PolicyDenied,
    LimitExceeded,
    PathLimit,
    Capacity,
    RootUnavailable,
    Shutdown,
    TreeTerminated,
    WatcherRegistrationFailed,
    WorkerLost,
    Stuck,
    InitialScanDegraded(BTreeSet<RelativePath>),
    Io(FsError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidConfig(m) => write!(f, "invalid config: {m}"),
            Error::InvalidPath(e) => write!(f, "invalid path: {e}"),
            Error::NotFound => f.write_str("not found"),
            Error::NotDirectory => f.write_str("not a directory"),
            Error::NotLoaded => f.write_str("not loaded"),
            Error::PolicyDenied => f.write_str("denied by policy"),
            Error::LimitExceeded => f.write_str("configured entry limit exceeded"),
            Error::PathLimit => f.write_str("too many paths in command"),
            Error::Capacity => f.write_str("command capacity exhausted"),
            Error::RootUnavailable => f.write_str("root unavailable"),
            Error::Shutdown => f.write_str("tree is shut down"),
            Error::TreeTerminated => f.write_str("tree terminated"),
            Error::WatcherRegistrationFailed => f.write_str("watcher registration failed"),
            Error::WorkerLost => f.write_str("filesystem worker lost"),
            Error::Stuck => f.write_str("filesystem worker stuck"),
            Error::InitialScanDegraded(paths) => {
                write!(f, "initial scan degraded for {} paths", paths.len())
            }
            Error::Io(e) => write!(f, "filesystem error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<PathError> for Error {
    fn from(err: PathError) -> Self {
        Error::InvalidPath(err)
    }
}

impl From<FsError> for Error {
    fn from(err: FsError) -> Self {
        match err {
            FsError::NotFound => Error::NotFound,
            FsError::NotDirectory => Error::NotDirectory,
            other => Error::Io(other),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
