//! tree-fucker maintains an immutable, diffable representation of a filesystem
//! tree, specified by `rfc/tree-fucker.txt`.

pub mod config;
pub mod core;
pub mod domain;
pub mod entry;
pub mod error;
pub mod fs;
pub mod ids;
pub mod path;
pub mod policy;
pub mod runtime;
pub mod snapshot;
pub mod std_fs;
pub mod testing;
pub mod tree;
pub mod update;

pub use core::{HostGovernor, HostGovernorError, Stats, host_governor};

pub use config::{ClassWeights, Config, HostConfig, LagMode, WatchRegistrationFailure};
pub use domain::{
    AccessTopology, Answer, Crossing, DeclarationSource, DeclarationSources, DomainCapabilities, DomainCaseSensitivity,
    DomainCrossing, DomainIdentity, DomainKey, DomainProbe, FilesystemSemantics, IdentityReliability, IdentitySource,
    IdentitySpace, IdentitySpaceKey, KindSource, MediaHint, MetadataSource, MetadataSources, ProbeError, ProbeResult,
    StorageDomainId, TimestampGranularity, TransportHint, WatcherAvailability, WatcherCapabilities, WatcherScope,
};
pub use entry::{Entry, EntryKind, FileIdentity, LoadState, Metadata, MetadataFields, Shape};
pub use error::{Error, Result};
pub use fs::{
    CancellationToken, Ceilings, Continuation, DirEntry, DirectoryListing, Enrichment, EntryInfo, FileSystem,
    FsCapabilities, FsError, HintKind, Lease, ListingSession, Observation, ObservedKind, SessionCost, SessionOutcome,
    SessionState, SessionStep, WatcherEvent, WatcherKind, WatcherSink, entry_bytes, list_directory,
};
pub use ids::{
    CommandId, EntryId, JobId, PolicyRevision, ReconciliationGeneration, RootIncarnation, Sequence, SnapshotVersion,
    WatchId,
};
pub use path::{CaseSensitivity, PathError, PathKey, RelativePath};
pub use policy::{LoadAll, LoadDepth, PathPredicate, PolicyContext, ScanDecision, ScanPolicy};
pub use runtime::{BoxFuture, BoxTaskHandle, Runtime, TaskHandle};
pub use snapshot::Snapshot;
pub use tree::{Tree, TreeHandle, UpdateStream};
pub use update::{
    ErrorCause, Health, InitialScanState, Operation, PathChange, ReconciliationHealth, RecoverableError,
    ResourceHealth, ResourceLimit, ResourceLimitEvent, ResourceLimited, RootAvailability, RoundResult, ShutdownState,
    StreamError, ThrottleCause, Update, UpdateEvent, WatcherHealth,
};
