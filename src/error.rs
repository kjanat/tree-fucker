//! This module defines the crate error of opening, commands, and scans.
//!
//! An [`Error`] fails a call. The update stream reports recoverable failures
//! as [`crate::update::RecoverableError`] values instead.

use std::collections::BTreeSet;
use std::fmt;

use crate::fs::FsError;
use crate::path::{PathError, RelativePath};
use crate::update::ResourceLimited;

/// `Error` reports the failure of an open, a command, or a scan.
///
/// [`crate::tree::Tree::open`], every [`crate::tree::TreeHandle`] command,
/// and [`crate::scan::Scan`] return it. Command outcomes follow RFC §9 and
/// §9.1. A command failure before acceptance changes no tree state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// `InvalidConfig` carries the reason for a failed configuration check.
    InvalidConfig(String),
    /// `InvalidPath` means a path failed normalization into a [`RelativePath`].
    InvalidPath(PathError),
    /// `NotFound` means the root or a command target is absent.
    NotFound,
    /// `NotDirectory` means the root or a command target is a non-directory.
    NotDirectory,
    /// `NotLoaded` means a refresh walk met an Unloaded directory (RFC §9.1).
    NotLoaded,
    /// `PolicyDenied` means policy excludes the command target (RFC §9.1).
    PolicyDenied,
    /// `ResourceLimited` means a required read hit a limit (RFC §13.1).
    ResourceLimited(ResourceLimited),
    /// `PathLimit` means a command named too many paths (RFC §9.2).
    PathLimit,
    /// `Capacity` means the pending command capacity is exhausted (RFC §13.6).
    Capacity,
    /// `RootUnavailable` means the root is unavailable (RFC §13.2).
    RootUnavailable,
    /// `Shutdown` means the tree shut down or a scan read followed exhaustion.
    Shutdown,
    /// `TreeTerminated` means a Fatal failure terminated the tree (RFC §13.1).
    TreeTerminated,
    /// `WatcherRegistrationFailed` means a required registration failed.
    ///
    /// The RequireWatcher mode makes registration required (RFC §11.1).
    WatcherRegistrationFailed,
    /// `WorkerLost` means a worker ended without its result (RFC §13.5).
    WorkerLost,
    /// `Stuck` means a stuck worker blocks a required read (RFC §13.5).
    ///
    /// The read itself is stuck, or a stuck worker quarantines its domain.
    Stuck,
    /// `InvalidListing` means a listing has an unsafe child name (RFC §14.1).
    InvalidListing,
    /// `UnresolvedKind` means a listed child has an unknown kind (RFC §10.1).
    UnresolvedKind,
    /// `AncestorNotDirectory` means a target ancestor is a non-directory.
    AncestorNotDirectory,
    /// `InitialScanDegraded` lists the unsatisfied initial paths (RFC §11.1).
    InitialScanDegraded(BTreeSet<RelativePath>),
    /// `Cancelled` means the token of a one-shot scan cancelled it.
    Cancelled,
    /// `Coordination` carries the failure reason of the shared authority.
    Coordination(String),
    /// `Io` carries a non-structural failure from the filesystem adapter.
    ///
    /// The payload is Transient, PermissionDenied, Unsupported, or Fatal.
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
            Error::ResourceLimited(limited) => write!(f, "{limited}"),
            Error::PathLimit => f.write_str("too many paths in command"),
            Error::Capacity => f.write_str("command capacity exhausted"),
            Error::RootUnavailable => f.write_str("root unavailable"),
            Error::Shutdown => f.write_str("tree is shut down"),
            Error::TreeTerminated => f.write_str("tree terminated"),
            Error::WatcherRegistrationFailed => f.write_str("watcher registration failed"),
            Error::WorkerLost => f.write_str("filesystem worker lost"),
            Error::Stuck => f.write_str("filesystem worker stuck"),
            Error::InvalidListing => f.write_str("listing has an unrepresentable child name"),
            Error::UnresolvedKind => f.write_str("listing has a child whose kind is unresolved"),
            Error::AncestorNotDirectory => f.write_str("an ancestor is not a directory"),
            Error::InitialScanDegraded(paths) => {
                write!(f, "initial scan degraded for {} paths", paths.len())
            }
            Error::Cancelled => f.write_str("cancelled"),
            Error::Coordination(message) => write!(f, "coordination failed: {message}"),
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

/// `Result` pairs a value type with the crate [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
