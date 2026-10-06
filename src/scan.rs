use std::collections::{HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::config::Config;
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

const LONGEST_WAIT: Duration = Duration::from_secs(1);

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn sleep(&self, duration: Duration);

    fn wait_for_change(&self, governor: &HostGovernor, seen: u64, timeout: Duration) {
        governor.wait_for_change(seen, timeout);
    }
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanOptions {
    pub crossing: DomainCrossing,
    pub fields: MetadataFields,
    pub entries_per_directory: usize,
    pub entries_per_lease: usize,
    pub operations_per_lease: usize,
    pub ceiling: Duration,
    pub anchors: usize,
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
        }
    }
}

impl ScanOptions {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Descent {
    Leaf,
    Descending,
    Withheld,
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanPath {
    directory: Option<RelativePath>,
    name: OsString,
}

impl ScanPath {
    pub fn root() -> ScanPath {
        ScanPath { directory: None, name: OsString::new() }
    }

    pub fn is_root(&self) -> bool {
        self.directory.is_none()
    }

    pub fn directory(&self) -> Option<&RelativePath> {
        self.directory.as_ref()
    }

    pub fn name(&self) -> Option<&OsStr> {
        self.directory.as_ref().map(|_| self.name.as_os_str())
    }

    pub fn depth(&self) -> usize {
        self.directory.as_ref().map_or(0, |directory| directory.depth() + 1)
    }

    pub fn path(&self) -> RelativePath {
        match &self.directory {
            Some(directory) => directory.joined(&self.name),
            None => RelativePath::root(),
        }
    }

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanEntry {
    pub path: ScanPath,
    pub kind: ObservedKind,
    pub identity: Option<FileIdentity>,
    pub metadata: Metadata,
    pub fields: MetadataFields,
    pub metadata_error: Option<FsError>,
    pub domain: StorageDomainId,
    pub descent: Descent,
    pub anchor: Option<Anchor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanFailure {
    Fs(FsError),
    ResourceLimited(ResourceLimited),
    Quarantined(StorageDomainId),
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanEvent {
    Entry(ScanEntry),
    Boundary { path: RelativePath, mode: DomainCrossing, domain: StorageDomainId },
    Unlisted { path: RelativePath, failure: ScanFailure },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanStats {
    pub grants: u64,
    pub listings: u64,
    pub leases: u64,
    pub resolutions: u64,
    pub enrichments: u64,
    pub metadata_operations: u64,
    pub entries_enumerated: u64,
    pub entries: u64,
    pub boundaries: u64,
    pub unlisted: u64,
    pub admitted: Duration,
    pub throttled: Duration,
    pub buffered_bytes: u64,
    pub peak_buffered_bytes: u64,
    pub anchors_live: usize,
    pub anchors_peak: usize,
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
    Children(Box<Frame>),
}

struct Need {
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

impl Drop for Held {
    fn drop(&mut self) {
        let now = MonotonicTime(self.clock.now().saturating_duration_since(self.base));
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
    pub fn open(
        filesystem: Arc<dyn FileSystem>,
        root: PathBuf,
        policy: Arc<dyn ScanPolicy>,
        options: ScanOptions,
    ) -> Result<Scan> {
        Scan::open_under(filesystem, root, policy, options, host_governor(), Arc::new(SystemClock))
    }

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
        };
        let given = scan.root.clone();
        let (canonical, _) = scan.bootstrap(|fs| fs.canonicalize(&given))?;
        scan.root = canonical;
        let root = scan.root.clone();
        let (info, _) = scan.bootstrap(|fs| fs.metadata(&root, &RelativePath::root()))?;
        if info.kind != EntryKind::Directory {
            return Err(Error::NotDirectory);
        }
        let (probe, grant) = scan.bootstrap(|fs| fs.resolve_domain(&root, &RelativePath::root(), None))?;
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

    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn stats(&self) -> ScanStats {
        ScanStats { anchors_live: self.live_anchors.load(Ordering::SeqCst), ..self.stats.clone() }
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
        self.limited(ResourceLimit::CommandWorkerTime, nanos(self.options.ceiling), nanos(self.stats.admitted), None)
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
            let remaining = self.options.ceiling.saturating_sub(self.stats.admitted);
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
            let cause = match self.governor.try_admit(reservation, now) {
                Ok(admitted) => break admitted,
                Err(cause) => cause,
            };
            match (cause, need.domain) {
                (ThrottleCause::StuckWorker, Some(domain)) => return Ok(Admission::Quarantined(domain)),
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
        self.stats.grants += 1;
        let held = Held { id, governor: self.governor.clone(), clock: self.clock.clone(), base: self.base };
        loop {
            self.check_cancelled()?;
            let seen = self.governor.changes();
            let now = self.now();
            if self.governor.try_start(id, now).is_ok() {
                break;
            }
            let started = self.clock.now();
            self.clock.wait_for_change(&self.governor, seen, LONGEST_WAIT);
            self.stats.throttled += self.clock.now().saturating_duration_since(started);
        }
        Ok(Admission::Granted(Granted { held, operations: admitted.operations }))
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

    fn record(&self, domain: Option<StorageDomainId>, failed: bool) {
        let now = self.now();
        if failed {
            self.governor.charge_surcharge(domain, WorkOrigin::Foreground, now);
        }
        self.governor.record_outcome(domain, failed, now);
    }

    fn bootstrap<T>(
        &mut self,
        work: impl FnOnce(&dyn FileSystem) -> std::result::Result<T, FsError>,
    ) -> Result<(T, Held)> {
        let id = GrantId::Bootstrap(self.governor.next_bootstrap());
        let need = Need { reads: 1, operations: 0, lease: 0, domain: None, listing: false };
        let granted = match self.admit(id, &RelativePath::root(), need)? {
            Admission::Granted(granted) => granted,
            Admission::Quarantined(_) => return Err(Error::Stuck),
        };
        let outcome = work(self.filesystem.as_ref());
        self.stats.admitted += self.governor.overshoot_of(id);
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

    fn anchor_room(&mut self) -> bool {
        if self.options.anchors == 0 {
            return false;
        }
        let room = self.live_anchors.load(Ordering::SeqCst) < self.options.anchors;
        if !room {
            self.stats.anchors_withheld += 1;
        }
        room
    }

    fn locate(
        &mut self,
        id: GrantId,
        path: &RelativePath,
        context: &PolicyContext,
        site: Site,
        beneath: Option<&Anchor>,
    ) -> Result<Option<(Arc<Located>, Option<Granted>)>> {
        let (probe, parent, granted) = match site {
            Site::Located(located) => return Ok(Some((located, None))),
            Site::Probed { probe, parent } => (*probe, parent, None),
            Site::Beneath(parent) => {
                let operations = self.lease_operations(&parent.probe, false);
                let need = Need { reads: 2, operations, lease: 0, domain: Some(parent.domain), listing: true };
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
                        self.settle(granted, Some(Reported { blocking: None, operations: 1 }), Some(parent.domain));
                        self.record(Some(parent.domain), true);
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
                    self.record(Some(domain), false);
                }
                self.stats.boundaries += 1;
                self.pending.push_back(ScanEvent::Boundary { path: path.clone(), mode, domain });
                return Ok(None);
            }
        }
        Ok(Some((Arc::new(Located { domain, probe }), granted)))
    }

    fn lease_operations(&self, probe: &ProbeResult, starved: bool) -> u32 {
        match starved || costs_per_child(probe) {
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

    fn list(&mut self, target: Target) -> Result<()> {
        let Target { path, context, site, beneath } = target;
        let id = self.next_grant();
        let Some((located, mut carried)) = self.locate(id, &path, &context, site, beneath.as_ref())? else {
            return Ok(());
        };
        let domain = located.domain;
        let anchored = self.anchor_room();
        let ceilings = Ceilings {
            entries: self.options.entries_per_directory,
            bytes: self.governor.limits().in_flight_listing_bytes,
        };
        let at = ListingAt { beneath: beneath.as_ref(), anchored };
        let mut session: Box<dyn ListingSession> =
            self.filesystem.open_listing_at(&self.root, &path, at, ceilings, self.cancel.clone());
        let mut lease = 0;
        let mut starved = false;
        let outcome = loop {
            let resolution = u32::from(carried.is_some());
            let granted = match carried.take() {
                Some(granted) => granted,
                None => {
                    let operations = self.lease_operations(&located.probe, starved);
                    let need = Need { reads: 1, operations, lease, domain: Some(domain), listing: true };
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
            let (continuation, cost) =
                session.resume(Lease { entries: self.options.entries_per_lease, operations: permitted });
            self.count(&cost);
            let operations = cost.listing_operations.saturating_add(cost.per_child_operations()) + resolution;
            self.settle(granted, Some(Reported { blocking: cost.blocking, operations }), Some(domain));
            self.in_flight_bytes = cost.bytes;
            self.report_memory();
            match continuation {
                Continuation::Suspended(next) => {
                    starved = cost.entries_enumerated == 0;
                    lease += 1;
                    session = next;
                }
                Continuation::Finished(outcome) => break (outcome, cost.bytes),
            }
        };
        let (outcome, bytes) = outcome;
        self.in_flight_bytes = 0;
        let now = self.now();
        self.governor.record_bytes(Some(domain), bytes, now);
        match outcome {
            SessionOutcome::Complete(mut listing) => {
                self.record(Some(domain), false);
                let anchor = listing.anchor.take();
                if let Some(anchor) = &anchor {
                    anchor.count_in(&self.live_anchors);
                    let live = self.live_anchors.load(Ordering::SeqCst);
                    self.stats.anchors_peak = self.stats.anchors_peak.max(live);
                }
                let child_context = self.policy.child_context(&context, &path, &listing);
                let supplied = listing.supplied_fields.intersect(self.options.fields);
                let missing = self.options.fields.without(listing.supplied_fields);
                let enriched = match missing.any() && !listing.entries.is_empty() {
                    true => {
                        let names = listing.entries.iter().map(|entry| entry.name.clone()).collect();
                        self.enrich(&path, domain, names, missing)?
                    }
                    false => HashMap::new(),
                };
                let bytes = listing.entries.iter().map(|entry| entry_bytes(&entry.name)).sum::<u64>();
                self.stats.buffered_bytes = self.stats.buffered_bytes.saturating_add(bytes);
                self.stats.peak_buffered_bytes = self.stats.peak_buffered_bytes.max(self.stats.buffered_bytes);
                self.report_memory();
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
            }
            SessionOutcome::Cancelled => {
                self.record(Some(domain), true);
                self.report_memory();
                return Err(Error::Cancelled);
            }
            SessionOutcome::ResourceLimited(mut limited) => {
                self.record(Some(domain), true);
                self.report_memory();
                limited.domain = Some(domain);
                self.unlisted(path, ScanFailure::ResourceLimited(limited));
            }
            SessionOutcome::Failed(error) => {
                self.record(Some(domain), true);
                self.report_memory();
                if let Some(fatal) = fatal(&error) {
                    return Err(fatal);
                }
                self.unlisted(path, ScanFailure::Fs(error));
            }
        }
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
            let need = Need { reads: 1, operations, lease, domain: Some(domain), listing: false };
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
                    let reported = Reported { blocking: None, operations: enrichment.metadata_operations };
                    self.settle(granted, Some(reported), Some(domain));
                    self.record(Some(domain), false);
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
                    self.settle(granted, None, Some(domain));
                    self.record(Some(domain), true);
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
        self.governor.forget_tree(self.number);
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
        self.governor.forget_tree(self.number);
    }
}
