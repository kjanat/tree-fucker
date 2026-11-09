//! [tree-fucker] maintains an immutable, diffable representation of a
//! filesystem tree, specified by [the tree-fucker RFC][RFC]
//! ([plain text][RFC-TXT]).
//!
//! A [`Tree`] keeps one filesystem subtree as a sequence of immutable
//! [`Snapshot`]s. Reconciliation lists loaded directories directly from the
//! filesystem, and watcher events only reduce latency. A per-host
//! [`HostGovernor`] admits every filesystem call and gives each storage domain
//! its own budget.
//!
//! # Start here
//!
//! 1. Pick a [`FileSystem`]. [`std_fs::StdFileSystem`] wraps the standard
//!    library; [`testing::FakeFileSystem`] is deterministic for tests.
#![cfg_attr(feature = "tokio", doc = " 2. Pick a [`Runtime`]. The `tokio` feature provides [`runtime::TokioRuntime`].")]
#![cfg_attr(
    not(feature = "tokio"),
    doc = " 2. Pick a [`Runtime`]. The `tokio` feature provides `runtime::TokioRuntime`."
)]
//! 3. Choose a [`ScanPolicy`] such as [`LoadAll`] or [`LoadDepth`], and a
//!    [`Config`].
//! 4. Call [`Tree::open`]. It returns a [`TreeHandle`] for commands and queries
//!    and an [`UpdateStream`] of [`UpdateEvent`]s.
//! 5. Read [`TreeHandle::snapshot`], [`TreeHandle::health`] and
//!    [`TreeHandle::stats`] at any time. Await
//!    [`TreeHandle::initial_scan_complete`] to wait for the first full listing.
//! 6. Call [`TreeHandle::shutdown`] to stop. The tree keeps running after every
//!    handle is dropped. A slow consumer receives [`UpdateEvent::Reset`] under
//!    the default [`LagMode::Reset`].
//!
//! [`Scan`] is the one-shot form. It walks a tree under the governor, yields
//! [`ScanEvent`]s and retains no tree.
//!
//! # Modules
//!
//! - [`tree`] holds the live tree, its handle and its update stream.
//! - [`update`] holds the events, [`Health`] and the errors the stream emits.
//! - [`snapshot`], [`entry`], [`path`] and [`ids`] hold the immutable data
//!   model.
//! - [`fs`] defines the filesystem boundary, and [`std_fs`] adapts `std::fs` to
//!   it.
//! - [`policy`] decides which directories a tree loads and how deep.
//! - [`config`] holds the tuning values, and [`core`] holds the deterministic
//!   coordinator.
//! - [`domain`] holds storage-domain identity and capabilities.
//! - [`coordination`] shares admission across the processes of one host.
//! - [`scan`] holds the one-shot governed walk.
//! - [`runtime`] abstracts the async runtime.
//! - [`testing`] holds fakes and a harness for consumers' tests.
//!
//! [RFC]: https://tree-fucker.kjanat.dev/
//! [RFC-TXT]: https://tree-fucker.kjanat.dev/tree-fucker.txt
//! [tree-fucker]: https://github.com/kjanat/tree-fucker
#![doc(
    html_logo_url = "https://tree-fucker.kjanat.dev/fucker/stickfigure.svg",
    html_favicon_url = "https://tree-fucker.kjanat.dev/fucker/stickfigure.svg"
)]

pub mod config;
pub mod coordination;
pub mod core;
pub mod domain;
pub mod entry;
pub mod error;
pub mod fs;
pub mod ids;
pub mod path;
pub mod policy;
pub mod runtime;
pub mod scan;
pub mod snapshot;
pub mod std_fs;
pub mod testing;
pub mod tree;
pub mod update;

#[doc(inline)]
pub use core::{
    Admitted, DegradedCause, HostGovernor, HostGovernorError, PreparedAdmission, Reported, Stats, host_governor,
};

#[doc(inline)]
pub use config::{ClassWeights, Config, HostConfig, LagMode, WatchRegistrationFailure};
#[doc(inline)]
pub use domain::{
    AccessTopology, Answer, Crossing, DeclarationSource, DeclarationSources, DomainCapabilities, DomainCaseSensitivity,
    DomainCrossing, DomainIdentity, DomainKey, DomainProbe, FilesystemInstance, FilesystemInstanceKey,
    FilesystemSemantics, IdentityReliability, IdentitySource, IdentitySpace, IdentitySpaceKey, KindSource, MediaHint,
    MetadataSource, MetadataSources, ProbeError, ProbeResult, StorageDomainId, TimestampGranularity, TransportHint,
    WatcherAvailability, WatcherCapabilities, WatcherScope, WeakDomainKey,
};
#[doc(inline)]
pub use entry::{Entry, EntryKind, FileIdentity, LoadState, Metadata, MetadataFields, Shape};
#[doc(inline)]
pub use error::{Error, Result};
#[doc(inline)]
pub use fs::{
    Anchor, CancellationToken, Ceilings, Continuation, DirEntry, DirectoryListing, Enrichment, EnrichmentBatch,
    EntryInfo, FileSystem, FsCapabilities, FsError, HintKind, Lease, ListingAt, ListingSession, Observation,
    ObservedKind, SessionCost, SessionOutcome, SessionState, SessionStep, WatcherEvent, WatcherKind, WatcherSink,
    entry_bytes, list_directory,
};
#[doc(inline)]
pub use ids::{
    CommandId, EntryId, JobId, PolicyRevision, ReconciliationGeneration, RootIncarnation, Sequence, SnapshotVersion,
    WatchId, WatchReleaseId, WatchRequestId,
};
#[doc(inline)]
pub use path::{CaseSensitivity, PathError, PathKey, RelativePath};
#[doc(inline)]
pub use policy::{LoadAll, LoadDepth, PathPredicate, PolicyContext, ScanDecision, ScanPolicy};
#[doc(inline)]
pub use runtime::{BoxFuture, BoxTaskHandle, Runtime, TaskHandle};
#[doc(inline)]
pub use scan::{
    AnchorPolicy, Clock, Descent, ListingExecutor, Scan, ScanEntry, ScanEvent, ScanFailure, ScanOptions, ScanPath,
    ScanStats, SystemClock,
};
#[doc(inline)]
pub use snapshot::Snapshot;
#[doc(inline)]
pub use tree::{Tree, TreeHandle, UpdateStream};
#[doc(inline)]
pub use update::{
    ErrorCause, Health, InitialScanState, Operation, PathChange, ReconciliationHealth, RecoverableError,
    ResourceHealth, ResourceLimit, ResourceLimitEvent, ResourceLimited, RootAvailability, RoundResult, ShutdownState,
    StreamError, ThrottleCause, Update, UpdateEvent, WatcherHealth,
};
