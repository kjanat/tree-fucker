//! This module provides the one-shot, governed directory walk.
//!
//! A [`Scan`] observes a tree once and yields each observation as a
//! [`ScanEvent`] (RFC §9.3). It shares the host governor with every
//! [`crate::tree::Tree`] in the process. It keeps no snapshot, watcher, or
//! command state.

use std::collections::{HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

mod anchors;
mod executor;
pub use executor::ListingExecutor;

use crate::config::Config;
use crate::coordination::protocol::Work as GovernedWork;
use crate::core::{
    GrantId, HostGovernor, MonotonicTime, Reported, Reservation, TreeNumber, WorkOrigin, host_governor,
    requires_crossing_decision,
};
use crate::domain::{DomainCrossing, IdentitySource, KindSource, ProbeResult, StorageDomainId};
use crate::entry::{EntryKind, FileIdentity, Metadata, MetadataFields};
use crate::error::{Error, Result};
use crate::fs::{
    Anchor, CancellationToken, Ceilings, Continuation, DirEntry, EnrichmentBatch, EntryInfo, FileSystem, FsError,
    Lease, ListingAt, ListingSession, ObservedKind, SessionCost, SessionOutcome, entry_bytes,
};
use crate::ids::JobId;
use crate::path::{RelativePath, validate_name};
use crate::policy::{PolicyContext, ScanDecision, ScanPolicy};
use crate::update::{ResourceLimit, ResourceLimited, ThrottleCause};

fn failed_listing(continuation: &Continuation) -> bool {
    matches!(continuation, Continuation::Finished(outcome) if !matches!(outcome, SessionOutcome::Complete(_)))
}

const LONGEST_WAIT: Duration = Duration::from_secs(1);

/// `Clock` supplies time and waiting to a one-shot scan.
///
/// [`Scan::open`] uses [`SystemClock`]. Tests pass another clock to
/// [`Scan::open_outside_host_governor`] to control time.
pub trait Clock: Send + Sync {
    /// `now` returns the current monotonic time.
    ///
    /// Implementations must never return a smaller value than before.
    fn now(&self) -> Instant;

    /// `sleep` blocks the calling thread for `duration`.
    ///
    /// A simulated clock may advance its time instead.
    fn sleep(&self, duration: Duration);

    /// `wait_for_change` blocks until the governor changes or `timeout` passes.
    ///
    /// The governor changes when its change counter moves past `seen`. The
    /// default implementation calls [`HostGovernor::wait_for_change`].
    fn wait_for_change(&self, governor: &HostGovernor, seen: u64, timeout: Duration) {
        governor.wait_for_change(seen, timeout);
    }
}

/// `SystemClock` uses [`Instant::now`] and [`std::thread::sleep`].
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// `AnchorPolicy` decides whether a scan may yield unanchored non-root entries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AnchorPolicy {
    /// `Optional` lets a listing at the anchor limit run without an anchor.
    #[default]
    Optional,
    /// `Required` turns an unanchored listing into a limited Unlisted event.
    Required,
}

/// `ScanOptions` holds the limits and choices of one [`Scan`].
///
/// The default takes its values from [`Config::default`] and retains no
/// anchors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanOptions {
    /// `crossing` sets the default crossing mode (RFC §14.3).
    ///
    /// The policy may refine the mode per crossing. Follow lists the child
    /// domain. Exclude and LoadOnDemand both yield a [`ScanEvent::Boundary`].
    pub crossing: DomainCrossing,
    /// `fields` selects the metadata fields to report.
    ///
    /// When a listing omits a field, enrichment reads it.
    pub fields: MetadataFields,
    /// `entries_per_directory` sets the entry ceiling of one listing.
    pub entries_per_directory: usize,
    /// `entries_per_lease` sets the entry count of one listing lease.
    pub entries_per_lease: usize,
    /// `operations_per_lease` caps per-child operations per lease or batch.
    pub operations_per_lease: usize,
    /// `ceiling` caps the worker time of the whole scan (RFC §15.4).
    ///
    /// The whole scan counts as one command.
    pub ceiling: Duration,
    /// `anchors` caps the anchor slots in use at once.
    ///
    /// Zero disables anchors.
    pub anchors: usize,
    /// `anchor_policy` decides the fate of a listing without an anchor.
    pub anchor_policy: AnchorPolicy,
    /// `streaming` makes the scan yield bounded chunks before a listing ends.
    ///
    /// Streaming requires a chunk-capable policy and filesystem session.
    pub streaming: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        let config = Config::default();
        ScanOptions {
            crossing: config.domain_crossing,
            fields: config.metadata_fields,
            entries_per_directory: config.entries_per_directory,
            entries_per_lease: config.entries_per_lease,
            operations_per_lease: config.operations_per_lease,
            ceiling: config.foreground_ceiling_per_command,
            anchors: 0,
            anchor_policy: AnchorPolicy::Optional,
            streaming: false,
        }
    }
}

impl ScanOptions {
    /// `validate` checks the counts and the ceiling.
    ///
    /// The entry, lease, and operation counts must be at least one, and the
    /// ceiling must be nonzero.
    /// `validate` returns the reason for the first failed check.
    /// [`Scan::open`] runs this check and reports a failure as
    /// [`Error::InvalidConfig`].
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.entries_per_directory == 0 {
            return Err("entries_per_directory must be at least 1".into());
        }
        if self.entries_per_lease == 0 {
            return Err("entries_per_lease must be at least 1".into());
        }
        if self.operations_per_lease == 0 {
            return Err("operations_per_lease must be at least 1".into());
        }
        if self.ceiling.is_zero() {
            return Err("ceiling must be greater than zero".into());
        }
        Ok(())
    }
}

/// `Descent` tells the consumer how the scan treats an entry (RFC §9.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Descent {
    /// `Leaf` marks a non-directory.
    Leaf,
    /// `Descending` marks a directory, and policy selects it for listing.
    Descending,
    /// `Withheld` marks a directory, and policy blocks its listing.
    ///
    /// Policy excludes the directory or leaves it unloaded.
    Withheld,
    /// `Unresolved` marks an entry of unknown kind without traversal.
    Unresolved,
}

/// `ScanPath` locates a scan entry relative to the scan root.
///
/// It stores the parent directory and the name separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanPath {
    directory: Option<RelativePath>,
    name: OsString,
}

impl ScanPath {
    /// `root` returns the path of the scan root.
    pub fn root() -> ScanPath {
        ScanPath { directory: None, name: OsString::new() }
    }

    /// `is_root` reports whether this path names the scan root.
    pub fn is_root(&self) -> bool {
        self.directory.is_none()
    }

    /// `directory` returns the parent directory, or `None` for the root.
    pub fn directory(&self) -> Option<&RelativePath> {
        self.directory.as_ref()
    }

    /// `name` returns the final component, or `None` for the root.
    pub fn name(&self) -> Option<&OsStr> {
        self.directory.as_ref().map(|_| self.name.as_os_str())
    }

    /// `depth` returns the number of components.
    ///
    /// The root has depth zero.
    pub fn depth(&self) -> usize {
        self.directory.as_ref().map_or(0, |directory| directory.depth() + 1)
    }

    /// `path` builds the joined [`RelativePath`].
    pub fn path(&self) -> RelativePath {
        match &self.directory {
            Some(directory) => directory.joined(&self.name),
            None => RelativePath::root(),
        }
    }

    /// `under` builds the native path of this entry beneath `root`.
    pub fn under(&self, root: &Path) -> PathBuf {
        match &self.directory {
            Some(directory) => directory.under(root).join(&self.name),
            None => root.to_path_buf(),
        }
    }
}

impl std::fmt::Display for ScanPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.directory {
            Some(directory) if directory.is_root() => write!(f, "{}", self.name.to_string_lossy()),
            Some(directory) => write!(f, "{directory}/{}", self.name.to_string_lossy()),
            None => f.write_str("."),
        }
    }
}

/// `ScanEntry` describes one observed entry of a scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanEntry {
    /// `path` locates the entry relative to the scan root.
    pub path: ScanPath,
    /// `kind` gives the kind from the listing.
    pub kind: ObservedKind,
    /// `identity` holds the file identity, or `None` without domain support.
    pub identity: Option<FileIdentity>,
    /// `metadata` holds the obtained subset of the requested fields.
    pub metadata: Metadata,
    /// `fields` names the fields in `metadata`.
    pub fields: MetadataFields,
    /// `metadata_error` holds the enrichment failure of this entry, if any.
    pub metadata_error: Option<FsError>,
    /// `domain` names the storage domain of the parent listing.
    pub domain: StorageDomainId,
    /// `descent` tells how the scan treats this entry.
    pub descent: Descent,
    /// `anchor` holds the anchor of the parent listing, if the scan kept one.
    pub anchor: Option<Anchor>,
}

/// `ScanFailure` names the reason for a [`ScanEvent::Unlisted`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanFailure {
    /// `Fs` means domain resolution or listing failed with a classified error.
    Fs(FsError),
    /// `ResourceLimited` means the listing reached a configured limit.
    ///
    /// The limit can be the entry ceiling or the anchor limit.
    ResourceLimited(ResourceLimited),
    /// `Quarantined` means a stuck worker quarantines the domain (RFC §13.5).
    Quarantined(StorageDomainId),
    /// `InvalidName` carries an unsafe child name.
    ///
    /// The scan skips that child.
    InvalidName(OsString),
}

impl std::fmt::Display for ScanFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanFailure::Fs(error) => write!(f, "{error}"),
            ScanFailure::ResourceLimited(limited) => write!(f, "{limited}"),
            ScanFailure::Quarantined(domain) => write!(f, "{domain} is quarantined behind a stuck worker"),
            ScanFailure::InvalidName(name) => write!(f, "unrepresentable child name {name:?}"),
        }
    }
}

/// `ScanEvent` is one item of a scan (RFC §9.3).
///
/// A directory's Entry precedes its Boundary or Unlisted event and every
/// event of its descendants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanEvent {
    /// `Entry` carries one observed entry.
    Entry(ScanEntry),
    /// `Boundary` reports a domain crossing, and the scan stops there.
    Boundary {
        /// `path` locates the first directory of the child domain.
        path: RelativePath,
        /// `mode` gives the applied crossing mode, Exclude or LoadOnDemand.
        mode: DomainCrossing,
        /// `domain` names the storage domain of the child.
        domain: StorageDomainId,
    },
    /// `Unlisted` reports a failed resolution or listing, or a skipped child.
    ///
    /// The scan continues with the siblings of `path`.
    Unlisted {
        /// `path` locates the affected directory.
        path: RelativePath,
        /// `failure` names the reason for the failure.
        failure: ScanFailure,
    },
}

/// `ScanStats` counts the work of one scan.
///
/// The host governor stays authoritative for physical occupancy and cost.
/// These counters exclude abandoned results (RFC §9.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// `grants` counts the governor grants of the scan.
    pub grants: u64,
    /// `listings` counts the listing operations of the adapter.
    pub listings: u64,
    /// `leases` counts the completed listing leases.
    pub leases: u64,
    /// `resolutions` counts the storage-domain resolutions.
    pub resolutions: u64,
    /// `enrichments` counts the enrichment batches.
    pub enrichments: u64,
    /// `metadata_operations` counts metadata operations.
    ///
    /// The count includes kind resolutions and [`Scan::read`] calls.
    pub metadata_operations: u64,
    /// `entries_enumerated` counts the enumerated directory entries.
    ///
    /// The count includes skipped entries.
    pub entries_enumerated: u64,
    /// `entries` counts the Entry events, with the root included.
    pub entries: u64,
    /// `boundaries` counts the Boundary events.
    pub boundaries: u64,
    /// `unlisted` counts the Unlisted events.
    pub unlisted: u64,
    /// `admitted` sums the worker time of the governor grants of this scan.
    pub admitted: Duration,
    /// `throttled` sums the time of the scan in admission waits.
    pub throttled: Duration,
    /// `buffered_bytes` counts the bytes of currently retained listings.
    pub buffered_bytes: u64,
    /// `peak_buffered_bytes` records the maximum of `buffered_bytes`.
    pub peak_buffered_bytes: u64,
    /// `anchors_live` counts the reserved anchor slots.
    ///
    /// The count includes active and detached cursors and retained
    /// observations.
    pub anchors_live: usize,
    /// `anchors_peak` records the maximum of simultaneously reserved slots.
    pub anchors_peak: usize,
    /// `anchors_withheld` counts the listings at a full anchor limit.
    pub anchors_withheld: u64,
}

#[derive(Debug)]
struct Located {
    domain: StorageDomainId,
    probe: ProbeResult,
}

enum Site {
    Located(Arc<Located>),
    Probed { probe: Box<ProbeResult>, parent: Arc<Located> },
    Beneath(Arc<Located>),
}

struct Target {
    path: RelativePath,
    context: PolicyContext,
    site: Site,
    beneath: Option<Anchor>,
}

struct Frame {
    path: RelativePath,
    context: PolicyContext,
    located: Arc<Located>,
    anchor: Option<Anchor>,
    children: std::vec::IntoIter<DirEntry>,
    supplied: MetadataFields,
    enriched: HashMap<OsString, std::result::Result<Metadata, FsError>>,
    bytes: u64,
}

enum Node {
    List(Target),
    Resume(Box<Listing>),
    Children(Box<Frame>),
}

struct Listing {
    path: RelativePath,
    context: PolicyContext,
    located: Arc<Located>,
    id: GrantId,
    carried: Option<Granted>,
    session: Box<dyn ListingSession>,
    lease: u32,
    needs_operations: bool,
    // Bytes already emitted are no longer live, but remain part of the
    // whole-directory observation used to admit later full listings.
    emitted_bytes: u64,
}

struct Need {
    work: GovernedWork,
    reads: u32,
    operations: u32,
    lease: u32,
    domain: Option<StorageDomainId>,
    listing: bool,
}

struct Held {
    id: GrantId,
    governor: HostGovernor,
    clock: Arc<dyn Clock>,
    base: Instant,
}

impl Held {
    fn failed(&self) {
        let now = MonotonicTime(self.clock.now().saturating_duration_since(self.base));
        self.governor.record_grant_failure(self.id, now);
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let now = MonotonicTime(self.clock.now().saturating_duration_since(self.base));
        if std::thread::panicking() {
            self.governor.record_grant_failure(self.id, now);
        }
        self.governor.release(self.id, now);
    }
}

struct Granted {
    held: Held,
    operations: u32,
}

enum Admission {
    Granted(Granted),
    Quarantined(StorageDomainId),
}

/// `Scan` walks a directory tree once, synchronously and governed (RFC §9.3).
///
/// A scan iterates depth first, and it goes deep. It lists a directory,
/// yields its children in enumeration order, and lists a child directory
/// before the next sibling. The root is the first event. [`ScanPolicy`] selects
/// the directories for listing. The scan never traverses symbolic links.
///
/// By default each filesystem operation runs on the calling thread after
/// the host governor grants it. [`Scan::with_listing_executor`] moves
/// listing leases to a bounded worker pool. Every operation draws on the
/// foreground allowance. The whole scan counts as one command against
/// [`ScanOptions::ceiling`]. Throttling delays a scan and never truncates
/// it.
///
/// Iteration ends with `None` after the last event. A scan can also end
/// with one error item followed by `None`.
///
/// - Cancellation ends it with [`Error::Cancelled`].
/// - A Fatal adapter failure ends it with [`Error::Io`].
/// - The ceiling or the memory limit ends it with [`Error::ResourceLimited`].
/// - A lost worker ends it with [`Error::WorkerLost`].
/// - A failed shared authority ends it with [`Error::Coordination`].
/// - A streaming scan ends with [`Error::InvalidConfig`] when a listing session
///   lacks chunk support.
///
/// Earlier events stay valid after the error.
///
/// A default scan holds no grant between events. The consumer can stop at
/// any event and drop the scan, and the drop releases its accounted memory.
pub struct Scan {
    filesystem: Arc<dyn FileSystem>,
    root: PathBuf,
    policy: Arc<dyn ScanPolicy>,
    options: ScanOptions,
    governor: HostGovernor,
    clock: Arc<dyn Clock>,
    base: Instant,
    number: TreeNumber,
    next_job: u64,
    cancel: CancellationToken,
    stack: Vec<Node>,
    pending: VecDeque<ScanEvent>,
    terminal: Option<Error>,
    finished: bool,
    live_anchors: Arc<AtomicUsize>,
    in_flight_bytes: u64,
    reported: (u64, u64),
    stats: ScanStats,
    bootstrap_charged: Duration,
    listing_executor: Option<ListingExecutor>,
    accounting: Option<Arc<ScanAccounting>>,
}

struct ScanAccounting {
    governor: HostGovernor,
    number: TreeNumber,
}

impl Drop for ScanAccounting {
    fn drop(&mut self) {
        self.governor.forget_tree(self.number);
    }
}

// Kept separate from the scan's tree number: dropping the logical scan must not
// forget the bounded buffer still owned by an uninterruptible listing.
struct ListingResources {
    grant: Option<Granted>,
    governor: HostGovernor,
    number: TreeNumber,
    _scan: Arc<ScanAccounting>,
}

impl Drop for ListingResources {
    fn drop(&mut self) {
        // Settle physical occupancy before the last scan-accounting owner
        // drops.
        drop(self.grant.take());
        self.governor.forget_tree(self.number);
    }
}

fn costs_per_child(probe: &ProbeResult) -> bool {
    probe.capabilities.kind_source != KindSource::Always
        || probe.capabilities.identity_source == IdentitySource::PerChildRead
}

fn fatal(error: &FsError) -> Option<Error> {
    match error {
        FsError::Fatal(message) => Some(Error::Io(FsError::Fatal(message.clone()))),
        _ => None,
    }
}

fn nanos(value: Duration) -> u64 {
    u64::try_from(value.as_nanos()).unwrap_or(u64::MAX)
}

impl Scan {
    /// `open` opens a scan at `root` under the process-wide host governor.
    ///
    /// `open` canonicalizes the root, reads its metadata, and resolves its
    /// storage domain under bootstrap grants. The root is the first event.
    ///
    /// # Errors
    ///
    /// - `open` returns [`Error::InvalidConfig`] for invalid `options` or host
    ///   limits. It also returns it when `options.streaming` is set and
    ///   `policy` lacks chunk support.
    /// - It returns [`Error::NotFound`] or [`Error::NotDirectory`] for an
    ///   absent or non-directory root.
    /// - It returns [`Error::Io`] when the adapter fails a root read.
    /// - It returns [`Error::ResourceLimited`] when bootstrap reaches the
    ///   ceiling.
    /// - It returns [`Error::Coordination`] when the shared authority fails.
    pub fn open(
        filesystem: Arc<dyn FileSystem>,
        root: PathBuf,
        policy: Arc<dyn ScanPolicy>,
        options: ScanOptions,
    ) -> Result<Scan> {
        Scan::open_under(filesystem, root, policy, options, host_governor(), Arc::new(SystemClock))
    }

    /// `open_outside_host_governor` opens a scan under the given `governor`.
    ///
    /// The scan reads time from `clock`. This function is the named opt-out
    /// of RFC §9.3 and §15.9. The process-wide governor states a bound for
    /// the process, and work of this scan falls outside it. Its errors match
    /// [`Scan::open`].
    pub fn open_outside_host_governor(
        filesystem: Arc<dyn FileSystem>,
        root: PathBuf,
        policy: Arc<dyn ScanPolicy>,
        options: ScanOptions,
        governor: HostGovernor,
        clock: Arc<dyn Clock>,
    ) -> Result<Scan> {
        Scan::open_under(filesystem, root, policy, options, governor, clock)
    }

    fn open_under(
        filesystem: Arc<dyn FileSystem>,
        root: PathBuf,
        policy: Arc<dyn ScanPolicy>,
        options: ScanOptions,
        governor: HostGovernor,
        clock: Arc<dyn Clock>,
    ) -> Result<Scan> {
        options.validate().map_err(Error::InvalidConfig)?;
        if options.streaming && !policy.supports_chunks() {
            return Err(Error::InvalidConfig("streaming requires a chunk-capable scan policy".into()));
        }
        governor.limits().validate().map_err(Error::InvalidConfig)?;
        let base = governor.base(clock.now());
        let number = governor.next_tree();
        let mut scan = Scan {
            filesystem,
            root,
            policy,
            options,
            governor,
            clock,
            base,
            number,
            next_job: 0,
            cancel: CancellationToken::new(),
            stack: Vec::new(),
            pending: VecDeque::new(),
            terminal: None,
            finished: false,
            live_anchors: Arc::new(AtomicUsize::new(0)),
            in_flight_bytes: 0,
            reported: (0, 0),
            stats: ScanStats::default(),
            bootstrap_charged: Duration::ZERO,
            listing_executor: None,
            accounting: None,
        };
        let given = scan.root.clone();
        let (canonical, _) = scan.bootstrap(GovernedWork::Bootstrap, |fs| fs.canonicalize(&given))?;
        scan.root = canonical;
        let root = scan.root.clone();
        let (info, _) = scan.bootstrap(GovernedWork::Bootstrap, |fs| fs.metadata(&root, &RelativePath::root()))?;
        if info.kind != EntryKind::Directory {
            return Err(Error::NotDirectory);
        }
        let (probe, grant) =
            scan.bootstrap(GovernedWork::DomainDiscovery, |fs| fs.resolve_domain(&root, &RelativePath::root(), None))?;
        scan.stats.resolutions += 1;
        let domain = scan.bind(&probe, None);
        let now = scan.now();
        scan.governor.attribute(grant.id, domain, now);
        drop(grant);
        let context = scan.policy.root_context(&info);
        let path = RelativePath::root();
        let descent = match scan.policy.classify(&context, &path, &info) {
            ScanDecision::Eligible { initially_loaded: true } => Descent::Descending,
            ScanDecision::Eligible { initially_loaded: false } | ScanDecision::Excluded => Descent::Withheld,
        };
        let fields = scan.options.fields;
        scan.stats.entries += 1;
        scan.pending.push_back(ScanEvent::Entry(ScanEntry {
            path: ScanPath::root(),
            kind: ObservedKind::Resolved(EntryKind::Directory),
            identity: info.identity,
            metadata: info.metadata.project(fields),
            fields,
            metadata_error: None,
            domain,
            descent,
            anchor: None,
        }));
        if descent == Descent::Descending {
            let located = Arc::new(Located { domain, probe });
            scan.stack.push(Node::List(Target { path, context, site: Site::Located(located), beneath: None }));
        }
        Ok(scan)
    }

    /// `root` returns the canonical root path.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// `cancellation` returns the cancel token of this scan.
    ///
    /// Any thread can cancel the scan through the token. The next check then
    /// yields [`Error::Cancelled`]. Listing sessions poll the token between
    /// chunks, and a call inside the kernel runs to completion.
    pub fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// `read` performs one lazy, adapter-specific read under the scan governor.
    ///
    /// The consumer calls `read` before the scan reaches its end. The callback
    /// receives the original observation, including its retained anchor. The
    /// callback must perform at most one physical read and must not reacquire
    /// this scan. Scan accounting excludes raw reads outside this method. The
    /// callback runs inline, and cancellation cannot interrupt a kernel call.
    pub fn read<T>(
        &mut self,
        entry: &ScanEntry,
        read: impl FnOnce(&ScanEntry) -> std::result::Result<T, FsError>,
    ) -> Result<T> {
        if self.finished {
            return Err(Error::Shutdown);
        }
        // Keep governor charges authoritative even if a consumer catches a
        // panic from its callback and continues using the scan.
        self.accounting
            .get_or_insert_with(|| Arc::new(ScanAccounting { governor: self.governor.clone(), number: self.number }));
        let id = self.next_grant();
        let need = Need {
            work: GovernedWork::LazyRead,
            reads: 1,
            operations: 0,
            lease: 0,
            domain: Some(entry.domain),
            listing: false,
        };
        let granted = match self.admit(id, &entry.path.path(), need)? {
            Admission::Granted(granted) => granted,
            Admission::Quarantined(_) => return Err(Error::Stuck),
        };
        self.stats.metadata_operations += 1;
        let result = read(entry);
        if result.is_err() {
            granted.held.failed();
        }
        self.settle(granted, Some(Reported { blocking: None, operations: 1 }), Some(entry.domain));
        if result.is_ok() {
            self.record_success(Some(entry.domain));
        }
        result.map_err(Error::from)
    }

    /// `with_listing_executor` moves later listing leases to `executor`.
    ///
    /// The executor is a bounded, reusable worker pool. Bootstrap, domain
    /// resolution, and enrichment stay inline. When a listing passes the
    /// governor's stuck threshold, the scan reports it as unlisted. Its
    /// worker, grant, and buffer allowance stay held until the physical call
    /// completes. Healthy domains continue only while both pool and governor
    /// capacity remain.
    pub fn with_listing_executor(mut self, executor: ListingExecutor) -> Self {
        self.accounting
            .get_or_insert_with(|| Arc::new(ScanAccounting { governor: self.governor.clone(), number: self.number }));
        self.listing_executor = Some(executor);
        self
    }

    /// `stats` returns the current counters.
    pub fn stats(&self) -> ScanStats {
        ScanStats {
            admitted: self.admitted_cost(),
            anchors_live: self.live_anchors.load(Ordering::SeqCst),
            ..self.stats.clone()
        }
    }

    fn admitted_cost(&self) -> Duration {
        if self.accounting.is_some() {
            self.stats.admitted.max(self.bootstrap_charged.saturating_add(self.governor.charged_by_tree(self.number)))
        } else {
            self.stats.admitted
        }
    }

    fn now(&self) -> MonotonicTime {
        MonotonicTime(self.clock.now().saturating_duration_since(self.base))
    }

    fn next_grant(&mut self) -> GrantId {
        self.next_job += 1;
        GrantId::Job(self.number, JobId::new(self.next_job))
    }

    fn check_cancelled(&self) -> Result<()> {
        match self.cancel.is_cancelled() {
            true => Err(Error::Cancelled),
            false => Ok(()),
        }
    }

    fn limited(&self, limit: ResourceLimit, configured: u64, observed: u64, domain: Option<StorageDomainId>) -> Error {
        Error::ResourceLimited(ResourceLimited { limit, configured, observed, domain })
    }

    fn ceiling_reached(&self) -> Error {
        self.limited(ResourceLimit::CommandWorkerTime, nanos(self.options.ceiling), nanos(self.admitted_cost()), None)
    }

    fn wait(&mut self, seen: u64, now: MonotonicTime) {
        let started = self.clock.now();
        match self.governor.resume_at(now) {
            Some(at) if at > now => self.clock.sleep(at.since(now).min(LONGEST_WAIT)),
            _ => self.clock.wait_for_change(&self.governor, seen, LONGEST_WAIT),
        }
        self.stats.throttled += self.clock.now().saturating_duration_since(started);
    }

    fn admit(&mut self, id: GrantId, path: &RelativePath, need: Need) -> Result<Admission> {
        let admitted = loop {
            self.check_cancelled()?;
            if let Some(error) = self.governor.coordination_error() {
                return Err(Error::Coordination(error));
            }
            self.governor.account_and_quarantine(self.now());
            let remaining = self.options.ceiling.saturating_sub(self.admitted_cost());
            if remaining.is_zero() {
                return Err(self.ceiling_reached());
            }
            let seen = self.governor.changes();
            let now = self.now();
            let reservation = Reservation {
                id,
                path: path.clone(),
                reads: need.reads,
                registrations: 0,
                operations: need.operations,
                ceiling: Some(remaining),
                lease: need.lease,
                domain: need.domain,
                origin: WorkOrigin::Foreground,
                listing: need.listing,
            };
            let cause = match self.governor.try_admit_work(reservation, need.work, now) {
                Ok(admitted) => break admitted,
                Err(cause) => cause,
            };
            match (cause, need.domain) {
                (ThrottleCause::StuckWorker, Some(domain)) => return Ok(Admission::Quarantined(domain)),
                (ThrottleCause::CommandCeiling { required }, _) => {
                    return Err(self.limited(
                        ResourceLimit::CommandWorkerTime,
                        nanos(self.options.ceiling),
                        nanos(self.admitted_cost().saturating_add(required)),
                        need.domain,
                    ));
                }
                (ThrottleCause::ForegroundCeiling, _)
                    if remaining < self.governor.cost_of(need.domain, need.reads + need.operations.min(1)) =>
                {
                    return Err(self.ceiling_reached());
                }
                (ThrottleCause::Memory, _) if self.alone_over_memory(need.domain, need.listing) => {
                    let ceiling = self.governor.memory_ceiling();
                    return Err(self.limited(
                        ResourceLimit::AccountedMemory,
                        ceiling,
                        self.stats.buffered_bytes.saturating_add(self.in_flight_bytes),
                        need.domain,
                    ));
                }
                _ => self.wait(seen, now),
            }
        };
        self.stats.admitted += admitted.cost;
        if id.tree().is_none() {
            self.bootstrap_charged += admitted.cost;
        }
        self.stats.grants += 1;
        let held = Held { id, governor: self.governor.clone(), clock: self.clock.clone(), base: self.base };
        let started = self.start_prepared(id, need.domain);
        if !matches!(started, Ok(None)) {
            // Refund only a still-reversible hold. Already committed local
            // admissions and physical work remain charged.
            let refund = self.governor.prepared_cost_of(id);
            self.stats.admitted -= refund;
            if id.tree().is_none() {
                self.bootstrap_charged -= refund;
            }
        }
        match started? {
            Some(domain) => Ok(Admission::Quarantined(domain)),
            None => Ok(Admission::Granted(Granted { held, operations: admitted.operations })),
        }
    }

    fn start_prepared(&mut self, id: GrantId, domain: Option<StorageDomainId>) -> Result<Option<StorageDomainId>> {
        loop {
            self.check_cancelled()?;
            if let Some(error) = self.governor.coordination_error() {
                return Err(Error::Coordination(error));
            }
            let seen = self.governor.changes();
            let now = self.now();
            self.governor.account_and_quarantine(now);
            if self.accounting.is_some() {
                // This grant's reservation is already charged and may fill
                // the ceiling exactly. Abort only if continuing physical
                // work has pushed the command beyond its admitted budget.
                if self.admitted_cost() > self.options.ceiling {
                    return Err(self.ceiling_reached());
                }
            }
            if let Some(domain) = domain
                && self.governor.quarantined(Some(domain))
            {
                return Ok(Some(domain));
            }
            match (self.governor.try_start(id, now), domain) {
                (Ok(()), _) => return Ok(None),
                (Err(ThrottleCause::StuckWorker), Some(domain)) => return Ok(Some(domain)),
                (Err(_), _) => self.wait(seen, now),
            }
        }
    }

    fn alone_over_memory(&self, domain: Option<StorageDomainId>, listing: bool) -> bool {
        let own = self.stats.buffered_bytes.saturating_add(self.in_flight_bytes);
        let expected = match listing {
            true => self.governor.bytes_estimate(domain),
            false => 0,
        };
        own > 0
            && self.governor.accounted_memory_excluding(self.number).saturating_add(expected)
                <= self.governor.memory_ceiling()
    }

    fn settle(&mut self, granted: Granted, reported: Option<Reported>, domain: Option<StorageDomainId>) {
        let now = self.now();
        let id = granted.held.id;
        if let Some(domain) = domain {
            self.governor.attribute(id, domain, now);
        }
        if let Some(reported) = reported {
            self.governor.report(id, reported, now);
        }
        self.stats.admitted += self.governor.overshoot_of(id);
        drop(granted);
    }

    fn record_success(&self, domain: Option<StorageDomainId>) {
        self.governor.record_outcome(domain, false, self.now());
    }

    fn bootstrap<T>(
        &mut self,
        work_kind: GovernedWork,
        work: impl FnOnce(&dyn FileSystem) -> std::result::Result<T, FsError>,
    ) -> Result<(T, Held)> {
        let id = GrantId::Bootstrap(self.governor.next_bootstrap());
        let need = Need { work: work_kind, reads: 1, operations: 0, lease: 0, domain: None, listing: false };
        let granted = match self.admit(id, &RelativePath::root(), need)? {
            Admission::Granted(granted) => granted,
            Admission::Quarantined(_) => return Err(Error::Stuck),
        };
        let outcome = work(self.filesystem.as_ref());
        if outcome.is_err() {
            granted.held.failed();
        }
        self.governor.account(self.now());
        let overshoot = self.governor.overshoot_of(id);
        self.stats.admitted += overshoot;
        self.bootstrap_charged += overshoot;
        outcome.map(|value| (value, granted.held)).map_err(Error::from)
    }

    fn bind(&self, probe: &ProbeResult, parent: Option<&Located>) -> StorageDomainId {
        let id = match probe.identity.key() {
            Some(key) => StorageDomainId::of(key),
            None => match parent {
                Some(parent) if !requires_crossing_decision(Some(&parent.probe), probe) => parent.domain,
                _ => StorageDomainId::fresh(),
            },
        };
        let now = self.now();
        self.governor.register_domain(id, &probe.capabilities, now);
        id
    }

    fn report_memory(&mut self) {
        let reported = (self.stats.buffered_bytes, self.in_flight_bytes);
        if self.reported == reported {
            return;
        }
        self.reported = reported;
        self.governor.report_memory(self.number, reported.0, reported.1);
    }

    fn unlisted(&mut self, path: RelativePath, failure: ScanFailure) {
        self.stats.unlisted += 1;
        self.pending.push_back(ScanEvent::Unlisted { path, failure });
    }

    fn maximum_operations(&self) -> u32 {
        u32::try_from(self.options.operations_per_lease).unwrap_or(u32::MAX).max(1)
    }

    fn anchor_room(&self) -> bool {
        self.live_anchors.load(Ordering::SeqCst) < self.options.anchors
    }

    fn locate(
        &mut self,
        id: GrantId,
        path: &RelativePath,
        context: &PolicyContext,
        site: Site,
        beneath: Option<&Anchor>,
        listing_allowed: bool,
    ) -> Result<Option<(Arc<Located>, Option<Granted>)>> {
        let (probe, parent, mut granted) = match site {
            Site::Located(located) => return Ok(Some((located, None))),
            Site::Probed { probe, parent } => (*probe, parent, None),
            Site::Beneath(parent) => {
                let separate = self.listing_executor.is_some() || !listing_allowed;
                let operations = if separate { 0 } else { self.lease_operations(&parent.probe, false) };
                let need = Need {
                    work: GovernedWork::DomainDiscovery,
                    reads: if separate { 1 } else { 2 },
                    operations,
                    lease: 0,
                    domain: Some(parent.domain),
                    listing: !separate,
                };
                let granted = match self.admit(id, path, need)? {
                    Admission::Granted(granted) => granted,
                    Admission::Quarantined(domain) => {
                        self.unlisted(path.clone(), ScanFailure::Quarantined(domain));
                        return Ok(None);
                    }
                };
                let resolved = self.filesystem.resolve_domain_beneath(&self.root, path, beneath, Some(&parent.probe));
                self.stats.resolutions += 1;
                match resolved {
                    Ok(probe) => (probe, parent, Some(granted)),
                    Err(error) => {
                        granted.held.failed();
                        self.settle(granted, Some(Reported { blocking: None, operations: 1 }), Some(parent.domain));
                        if let Some(fatal) = fatal(&error) {
                            return Err(fatal);
                        }
                        self.unlisted(path.clone(), ScanFailure::Fs(error));
                        return Ok(None);
                    }
                }
            }
        };
        let domain = self.bind(&probe, Some(&parent));
        if requires_crossing_decision(Some(&parent.probe), &probe) {
            let mode = self.policy.crossing(context, path, &probe.capabilities, self.options.crossing);
            if mode != DomainCrossing::Follow {
                if let Some(granted) = granted {
                    self.settle(granted, Some(Reported { blocking: None, operations: 1 }), Some(domain));
                    self.record_success(Some(domain));
                }
                self.stats.boundaries += 1;
                self.pending.push_back(ScanEvent::Boundary { path: path.clone(), mode, domain });
                return Ok(None);
            }
        }
        if domain != parent.domain
            && let Some(discovery) = granted.take()
        {
            // Discovery was authorized against the parent. Its permission
            // cannot cover listing a newly resolved domain: settle it before
            // resume_listing acquires a grant against the destination.
            self.settle(discovery, Some(Reported { blocking: None, operations: 1 }), Some(domain));
            self.record_success(Some(domain));
        }
        Ok(Some((Arc::new(Located { domain, probe }), granted)))
    }

    fn lease_operations(&self, probe: &ProbeResult, needs_operations: bool) -> u32 {
        match needs_operations || costs_per_child(probe) {
            true => self.maximum_operations(),
            false => 0,
        }
    }

    fn count(&mut self, cost: &SessionCost) {
        self.stats.leases += 1;
        self.stats.listings += u64::from(cost.listing_operations);
        self.stats.metadata_operations += u64::from(cost.metadata_operations);
        self.stats.entries_enumerated += cost.entries_enumerated;
    }

    fn resume_on_worker(
        &mut self,
        worker: executor::Worker,
        granted: Granted,
        session: Box<dyn ListingSession>,
        lease: Lease,
        domain: StorageDomainId,
    ) -> Result<Option<(Continuation, SessionCost, ListingResources)>> {
        let id = granted.held.id;
        let mut memory = ListingResources {
            grant: Some(granted),
            governor: self.governor.clone(),
            number: self.governor.next_tree(),
            _scan: self.accounting.as_ref().expect("executor accounting").clone(),
        };
        let bytes = self.listing_bytes();
        self.governor.try_reserve_scan_memory(self.number, memory.number, bytes).map_err(|mut limited| {
            limited.domain = Some(domain);
            Error::ResourceLimited(limited)
        })?;
        let cancel = self.cancel.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        worker.run(move || {
            if cancel.is_cancelled() {
                return;
            }
            let (continuation, cost) = session.resume(lease);
            if failed_listing(&continuation) {
                memory.grant.as_ref().expect("physical grant").held.failed();
            }
            let held = &memory.grant.as_ref().expect("physical grant").held;
            let now = MonotonicTime(held.clock.now().saturating_duration_since(held.base));
            let governor = &held.governor;
            governor.report(
                id,
                Reported {
                    blocking: cost.blocking,
                    operations: cost.listing_operations.saturating_add(cost.per_child_operations()),
                },
                now,
            );
            let overshoot = governor.overshoot_of(id);
            drop(memory.grant.take());
            // On cancellation/timeout the receiver is gone: the returned
            // session and its buffer are dropped here, after the
            // physical call completes.
            let _ = sender.send((continuation, cost, overshoot, memory));
        })?;
        self.in_flight_bytes = 0;
        self.report_memory();
        loop {
            self.check_cancelled()?;
            match receiver.recv_timeout(executor::CHECK_INTERVAL) {
                Ok((continuation, cost, overshoot, memory)) => {
                    self.governor
                        .try_return_scan_memory(memory.number, self.number, cost.bytes)
                        .map_err(Error::ResourceLimited)?;
                    self.in_flight_bytes = cost.bytes;
                    self.reported = (self.stats.buffered_bytes, cost.bytes);
                    self.stats.admitted += overshoot;
                    return Ok(Some((continuation, cost, memory)));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    self.check_cancelled()?;
                    return Err(Error::WorkerLost);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
            let now = self.now();
            self.governor.account_and_quarantine(now);
            if self.admitted_cost() >= self.options.ceiling {
                return Err(self.ceiling_reached());
            }
            if self.governor.stuck_grants().iter().any(|grant| grant.id == id) {
                return Ok(None);
            }
        }
    }

    fn listing_bytes(&self) -> u64 {
        let limits = self.governor.limits();
        let allowance = if self.listing_executor.is_some() {
            // A detached call can retain its whole allowance. Leave room for
            // other physical slots instead of reserving the host's entire pool.
            (limits.in_flight_listing_bytes / limits.maximum_in_flight as u64).max(1)
        } else {
            limits.in_flight_listing_bytes
        };
        allowance.min(limits.accounted_memory_ceiling.saturating_sub(self.stats.buffered_bytes))
    }

    fn list(&mut self, target: Target) -> Result<()> {
        let Target { path, context, site, beneath } = target;
        let anchored = self.anchor_room();
        let listing_allowed = anchored || self.options.anchor_policy == AnchorPolicy::Optional;
        let id = self.next_grant();
        let Some((located, mut carried)) = self.locate(id, &path, &context, site, beneath.as_ref(), listing_allowed)?
        else {
            return Ok(());
        };
        let domain = located.domain;
        // Domain resolution remains inline. Do not hold its physical grant
        // while waiting for an executor slot, or charge worker queue
        // time as filesystem work.
        if (self.listing_executor.is_some() || !listing_allowed)
            && let Some(granted) = carried.take()
        {
            self.settle(granted, Some(Reported { blocking: None, operations: 1 }), Some(domain));
        }
        if !anchored && self.options.anchors > 0 {
            self.stats.anchors_withheld += 1;
        }
        if !listing_allowed {
            self.unlisted(
                path,
                ScanFailure::ResourceLimited(ResourceLimited {
                    limit: ResourceLimit::Anchors,
                    configured: self.options.anchors as u64,
                    observed: self.live_anchors.load(Ordering::SeqCst) as u64 + 1,
                    domain: Some(domain),
                }),
            );
            return Ok(());
        }
        let ceilings = Ceilings { entries: self.options.entries_per_directory, bytes: self.listing_bytes() };
        if ceilings.bytes == 0 {
            return Err(self.limited(
                ResourceLimit::AccountedMemory,
                self.governor.memory_ceiling(),
                self.stats.buffered_bytes.saturating_add(1),
                Some(domain),
            ));
        }
        // Reserve before session construction, which may already create an
        // anchor. The session wrapper retains this slot through detachment.
        let slot = anchored.then(|| {
            let (slot, live) = crate::fs::AnchorSlot::reserve(&self.live_anchors);
            self.stats.anchors_peak = self.stats.anchors_peak.max(live);
            slot
        });
        let at = ListingAt { beneath: beneath.as_ref(), anchored };
        let session: Box<dyn ListingSession> =
            self.filesystem.open_listing_at(&self.root, &path, at, ceilings, self.cancel.clone());
        let session = anchors::track(session, slot);
        if self.options.streaming && !session.supports_chunks() {
            return Err(Error::InvalidConfig("streaming requires a chunk-capable listing session".into()));
        }
        self.resume_listing(Listing {
            path,
            context,
            located,
            id,
            carried,
            session,
            lease: 0,
            needs_operations: false,
            emitted_bytes: 0,
        })
    }

    fn resume_listing(&mut self, listing: Listing) -> Result<()> {
        let Listing {
            path,
            context,
            located,
            id,
            mut carried,
            mut session,
            mut lease,
            mut needs_operations,
            mut emitted_bytes,
        } = listing;
        let domain = located.domain;
        let outcome = loop {
            let worker = if let Some(executor) = &self.listing_executor {
                match executor.acquire(&self.cancel, || {
                    self.governor.account_and_quarantine(self.now());
                    if self.admitted_cost() >= self.options.ceiling {
                        return Err(self.ceiling_reached());
                    }
                    if self.governor.quarantined(Some(domain)) { Err(Error::Stuck) } else { Ok(()) }
                }) {
                    Ok(worker) => Some(worker),
                    Err(Error::Stuck) => {
                        self.in_flight_bytes = 0;
                        self.report_memory();
                        self.unlisted(path, ScanFailure::Quarantined(domain));
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            } else {
                None
            };
            let resolution = u32::from(carried.is_some());
            let granted = match carried.take() {
                Some(granted) => granted,
                None => {
                    let operations = self.lease_operations(&located.probe, needs_operations);
                    let need = Need {
                        work: GovernedWork::Listing,
                        reads: 1,
                        operations,
                        lease,
                        domain: Some(domain),
                        listing: true,
                    };
                    match self.admit(id, &path, need) {
                        Ok(Admission::Granted(granted)) => granted,
                        Ok(Admission::Quarantined(quarantined)) => {
                            self.in_flight_bytes = 0;
                            self.report_memory();
                            self.unlisted(path, ScanFailure::Quarantined(quarantined));
                            return Ok(());
                        }
                        Err(error) => {
                            self.in_flight_bytes = 0;
                            return Err(error);
                        }
                    }
                }
            };
            let permitted = usize::try_from(granted.operations).unwrap_or(usize::MAX);
            let lease_budget = Lease { entries: self.options.entries_per_lease, operations: permitted };
            let (continuation, cost, memory) = if let Some(worker) = worker {
                match self.resume_on_worker(worker, granted, session, lease_budget, domain)? {
                    Some((continuation, cost, memory)) => (continuation, cost, Some(memory)),
                    None => {
                        self.unlisted(path, ScanFailure::Quarantined(domain));
                        return Ok(());
                    }
                }
            } else {
                let (continuation, cost) = session.resume(lease_budget);
                if failed_listing(&continuation) {
                    granted.held.failed();
                }
                let operations = cost.listing_operations.saturating_add(cost.per_child_operations()) + resolution;
                self.settle(granted, Some(Reported { blocking: cost.blocking, operations }), Some(domain));
                (continuation, cost, None)
            };
            self.count(&cost);
            self.in_flight_bytes = cost.bytes;
            self.report_memory();
            drop(memory);
            match continuation {
                Continuation::Suspended(mut next) => {
                    needs_operations = cost.entries_enumerated == 0 || cost.per_child_operations() > 0;
                    lease += 1;
                    if self.options.streaming
                        && let Some(chunk) = next.take_chunk()
                    {
                        emitted_bytes = emitted_bytes.saturating_add(cost.bytes);
                        self.in_flight_bytes = 0;
                        let resume = Node::Resume(Box::new(Listing {
                            path: path.clone(),
                            context: context.clone(),
                            located: located.clone(),
                            id,
                            carried: None,
                            session: next,
                            lease,
                            needs_operations,
                            emitted_bytes,
                        }));
                        let before = self.stack.len();
                        self.accept_listing(path, context, located, chunk)?;
                        if self.stack.len() > before {
                            self.stack.insert(before, resume);
                        }
                        return Ok(());
                    }
                    session = next;
                }
                Continuation::Finished(outcome) => break (outcome, emitted_bytes.saturating_add(cost.bytes)),
            }
        };
        let (outcome, bytes) = outcome;
        self.in_flight_bytes = 0;
        let now = self.now();
        self.governor.record_bytes(Some(domain), bytes, now);
        match outcome {
            SessionOutcome::Complete(listing) => self.accept_listing(path, context, located, listing)?,
            SessionOutcome::Cancelled => {
                self.report_memory();
                return Err(Error::Cancelled);
            }
            SessionOutcome::ResourceLimited(mut limited) => {
                self.report_memory();
                limited.domain = Some(domain);
                self.unlisted(path, ScanFailure::ResourceLimited(limited));
            }
            SessionOutcome::Failed(error) => {
                self.report_memory();
                if let Some(fatal) = fatal(&error) {
                    return Err(fatal);
                }
                self.unlisted(path, ScanFailure::Fs(error));
            }
        }
        Ok(())
    }

    fn accept_listing(
        &mut self,
        path: RelativePath,
        context: PolicyContext,
        located: Arc<Located>,
        mut listing: crate::fs::DirectoryListing,
    ) -> Result<()> {
        let domain = located.domain;
        self.record_success(Some(domain));
        let anchor = listing.anchor.take();
        if anchor.is_none() && self.options.anchor_policy == AnchorPolicy::Required {
            self.report_memory();
            self.unlisted(
                path,
                ScanFailure::ResourceLimited(ResourceLimited {
                    limit: ResourceLimit::Anchors,
                    configured: 0,
                    observed: 1,
                    domain: Some(domain),
                }),
            );
            return Ok(());
        }
        let child_context = self.policy.child_context(&context, &path, &listing);
        let supplied = listing.supplied_fields.intersect(self.options.fields);
        let missing = self.options.fields.without(listing.supplied_fields);
        let bytes = listing.entries.iter().map(|entry| entry_bytes(&entry.name)).sum::<u64>();
        let retained = self.stats.buffered_bytes.saturating_add(bytes);
        self.governor.try_retain_scan_memory(self.number, retained).map_err(Error::ResourceLimited)?;
        self.stats.buffered_bytes = retained;
        self.stats.peak_buffered_bytes = self.stats.peak_buffered_bytes.max(retained);
        self.reported = (retained, 0);
        let enriched = match missing.any() && !listing.entries.is_empty() {
            true => {
                let names = listing.entries.iter().map(|entry| entry.name.clone()).collect();
                self.enrich(&path, domain, names, missing)?
            }
            false => HashMap::new(),
        };
        self.stack.push(Node::Children(Box::new(Frame {
            path,
            context: child_context,
            located,
            anchor,
            children: listing.entries.into_iter(),
            supplied,
            enriched,
            bytes,
        })));
        Ok(())
    }

    fn enrich(
        &mut self,
        path: &RelativePath,
        domain: StorageDomainId,
        names: Vec<OsString>,
        fields: MetadataFields,
    ) -> Result<HashMap<OsString, std::result::Result<Metadata, FsError>>> {
        let mut results = HashMap::with_capacity(names.len());
        let id = self.next_grant();
        let mut cursor = 0;
        let mut lease = 0;
        while cursor < names.len() {
            let remaining = u32::try_from(names.len() - cursor).unwrap_or(u32::MAX);
            let operations = self.maximum_operations().min(remaining);
            let need = Need {
                work: GovernedWork::Enrichment,
                reads: 1,
                operations,
                lease,
                domain: Some(domain),
                listing: false,
            };
            let granted = match self.admit(id, path, need)? {
                Admission::Granted(granted) => granted,
                Admission::Quarantined(quarantined) => {
                    let error = FsError::Transient(format!("{quarantined} is quarantined behind a stuck worker"));
                    for name in &names[cursor..] {
                        results.insert(name.clone(), Err(error.clone()));
                    }
                    break;
                }
            };
            let take = usize::try_from(granted.operations).unwrap_or(usize::MAX).clamp(1, names.len() - cursor);
            let batch = EnrichmentBatch { fields, directory: false, children: names[cursor..cursor + take].to_vec() };
            let enriched = self.filesystem.enrich(&self.root, path, &batch);
            self.stats.enrichments += 1;
            match enriched {
                Ok(enrichment) => {
                    let failed = !enrichment.failed.is_empty() || enrichment.children.len() != batch.children.len();
                    if failed {
                        granted.held.failed();
                    }
                    let reported = Reported { blocking: None, operations: enrichment.metadata_operations };
                    self.settle(granted, Some(reported), Some(domain));
                    if !failed {
                        self.record_success(Some(domain));
                    }
                    self.stats.metadata_operations += u64::from(enrichment.metadata_operations);
                    for (name, metadata) in enrichment.children {
                        results.insert(name, Ok(metadata));
                    }
                    for (name, error) in enrichment.failed {
                        if let Some(fatal) = fatal(&error) {
                            return Err(fatal);
                        }
                        results.insert(name, Err(error));
                    }
                    for name in batch.children {
                        results.entry(name).or_insert(Err(FsError::NotFound));
                    }
                }
                Err(error) => {
                    granted.held.failed();
                    self.settle(granted, None, Some(domain));
                    if let Some(fatal) = fatal(&error) {
                        return Err(fatal);
                    }
                    for name in batch.children {
                        results.insert(name, Err(error.clone()));
                    }
                }
            }
            cursor += take;
            lease += 1;
        }
        Ok(results)
    }

    fn child(&mut self, frame: &mut Frame, child: DirEntry) -> (ScanEvent, Option<Target>) {
        let DirEntry { name, info, domain } = child;
        if validate_name(&name).is_err() {
            self.stats.unlisted += 1;
            let event = ScanEvent::Unlisted { path: frame.path.clone(), failure: ScanFailure::InvalidName(name) };
            return (event, None);
        }
        let mut metadata = info.metadata.project(frame.supplied);
        let mut fields = frame.supplied;
        let mut metadata_error = None;
        let enriched = match frame.enriched.is_empty() {
            true => None,
            false => frame.enriched.remove(&name),
        };
        match enriched {
            Some(Ok(supplied)) => {
                let missing = self.options.fields.without(frame.supplied);
                metadata = metadata.merged(supplied, missing);
                fields = self.options.fields;
            }
            Some(Err(error)) => metadata_error = Some(error),
            None => {}
        }
        let (descent, target) = match info.kind {
            ObservedKind::Unresolved => (Descent::Unresolved, None),
            ObservedKind::Resolved(EntryKind::Directory) => {
                let observed = EntryInfo { kind: EntryKind::Directory, metadata, identity: info.identity };
                let path = frame.path.joined(&name);
                match self.policy.classify(&frame.context, &path, &observed) {
                    ScanDecision::Eligible { initially_loaded: true } => {
                        let site = match domain {
                            Some(probe) => Site::Probed { probe, parent: frame.located.clone() },
                            None => Site::Beneath(frame.located.clone()),
                        };
                        let target =
                            Target { path, context: frame.context.clone(), site, beneath: frame.anchor.clone() };
                        (Descent::Descending, Some(target))
                    }
                    ScanDecision::Eligible { initially_loaded: false } | ScanDecision::Excluded => {
                        (Descent::Withheld, None)
                    }
                }
            }
            ObservedKind::Resolved(_) => (Descent::Leaf, None),
        };
        self.stats.entries += 1;
        let entry = ScanEntry {
            path: ScanPath { directory: Some(frame.path.clone()), name },
            kind: info.kind,
            identity: info.identity,
            metadata,
            fields,
            metadata_error,
            domain: frame.located.domain,
            descent,
            anchor: frame.anchor.clone(),
        };
        (ScanEvent::Entry(entry), target)
    }

    fn release_frame(&mut self, frame: &Frame) {
        self.stats.buffered_bytes = self.stats.buffered_bytes.saturating_sub(frame.bytes);
        self.report_memory();
    }

    fn step(&mut self) -> Result<Option<ScanEvent>> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Ok(Some(event));
            }
            self.check_cancelled()?;
            let Some(node) = self.stack.pop() else {
                return Ok(None);
            };
            match node {
                Node::List(target) => self.list(target)?,
                Node::Resume(listing) => self.resume_listing(*listing)?,
                Node::Children(mut frame) => match frame.children.next() {
                    Some(child) => {
                        let (event, target) = self.child(&mut frame, child);
                        self.stack.push(Node::Children(frame));
                        if let Some(target) = target {
                            self.stack.push(Node::List(target));
                        }
                        return Ok(Some(event));
                    }
                    None => self.release_frame(&frame),
                },
            }
        }
    }

    fn finish(&mut self) {
        self.finished = true;
        self.stack.clear();
        self.stats.buffered_bytes = 0;
        self.in_flight_bytes = 0;
        if self.accounting.is_some() {
            self.cancel.cancel();
            self.report_memory();
        } else {
            self.governor.forget_tree(self.number);
        }
    }
}

impl Iterator for Scan {
    type Item = Result<ScanEvent>;

    fn next(&mut self) -> Option<Result<ScanEvent>> {
        if let Some(event) = self.pending.pop_front() {
            return Some(Ok(event));
        }
        if let Some(error) = self.terminal.take() {
            return Some(Err(error));
        }
        if self.finished {
            return None;
        }
        match self.step() {
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => {
                self.finish();
                None
            }
            Err(error) => {
                self.finish();
                match self.pending.pop_front() {
                    Some(event) => {
                        self.terminal = Some(error);
                        Some(Ok(event))
                    }
                    None => Some(Err(error)),
                }
            }
        }
    }
}

impl Drop for Scan {
    fn drop(&mut self) {
        if self.accounting.is_some() {
            self.cancel.cancel();
            self.governor.report_memory(self.number, 0, 0);
        } else {
            self.governor.forget_tree(self.number);
        }
    }
}
