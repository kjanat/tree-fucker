use std::any::Any;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::domain::{DomainCapabilities, DomainCrossing};
use crate::entry::EntryKind;
use crate::fs::{DirectoryListing, EntryInfo};
use crate::ids::PolicyRevision;
use crate::path::RelativePath;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScanDecision {
    Excluded,
    Eligible { initially_loaded: bool },
}

#[derive(Clone)]
pub struct PolicyContext {
    fingerprint: u64,
    value: Arc<dyn Any + Send + Sync>,
}

impl PolicyContext {
    pub fn new<T: Any + Send + Sync>(fingerprint: u64, value: T) -> PolicyContext {
        PolicyContext { fingerprint, value: Arc::new(value) }
    }

    pub fn unit() -> PolicyContext {
        PolicyContext::new(0, ())
    }

    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    pub fn get<T: Any>(&self) -> Option<&T> {
        self.value.downcast_ref::<T>()
    }

    pub fn same_as(&self, other: &PolicyContext) -> bool {
        self.fingerprint == other.fingerprint
    }
}

impl fmt::Debug for PolicyContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PolicyContext({})", self.fingerprint)
    }
}

pub trait ScanPolicy: Send + Sync {
    fn revision(&self) -> PolicyRevision;
    fn root_context(&self, root: &EntryInfo) -> PolicyContext;
    fn classify(&self, parent: &PolicyContext, path: &RelativePath, info: &EntryInfo) -> ScanDecision;
    fn child_context(&self, parent: &PolicyContext, path: &RelativePath, listing: &DirectoryListing) -> PolicyContext;

    fn crossing(
        &self,
        _parent: &PolicyContext,
        _path: &RelativePath,
        _child: &DomainCapabilities,
        configured: DomainCrossing,
    ) -> DomainCrossing {
        configured
    }

    fn watcher_path_limit(
        &self,
        _parent: &PolicyContext,
        _path: &RelativePath,
        _domain: &DomainCapabilities,
        configured: usize,
    ) -> usize {
        configured
    }
}

pub struct PathPredicate<F> {
    revision: AtomicU64,
    predicate: F,
}

impl<F> PathPredicate<F>
where
    F: Fn(&RelativePath, EntryKind) -> ScanDecision + Send + Sync,
{
    pub fn new(predicate: F) -> PathPredicate<F> {
        PathPredicate { revision: AtomicU64::new(0), predicate }
    }

    pub fn bump_revision(&self) {
        self.revision.fetch_add(1, Ordering::SeqCst);
    }
}

impl<F> ScanPolicy for PathPredicate<F>
where
    F: Fn(&RelativePath, EntryKind) -> ScanDecision + Send + Sync,
{
    fn revision(&self) -> PolicyRevision {
        PolicyRevision::new(self.revision.load(Ordering::SeqCst))
    }

    fn root_context(&self, _root: &EntryInfo) -> PolicyContext {
        PolicyContext::unit()
    }

    fn classify(&self, _parent: &PolicyContext, path: &RelativePath, info: &EntryInfo) -> ScanDecision {
        (self.predicate)(path, info.kind)
    }

    fn child_context(
        &self,
        parent: &PolicyContext,
        _path: &RelativePath,
        _listing: &DirectoryListing,
    ) -> PolicyContext {
        parent.clone()
    }
}

pub struct LoadAll;

impl ScanPolicy for LoadAll {
    fn revision(&self) -> PolicyRevision {
        PolicyRevision::new(0)
    }

    fn root_context(&self, _root: &EntryInfo) -> PolicyContext {
        PolicyContext::unit()
    }

    fn classify(&self, _parent: &PolicyContext, _path: &RelativePath, _info: &EntryInfo) -> ScanDecision {
        ScanDecision::Eligible { initially_loaded: true }
    }

    fn child_context(
        &self,
        parent: &PolicyContext,
        _path: &RelativePath,
        _listing: &DirectoryListing,
    ) -> PolicyContext {
        parent.clone()
    }
}

pub struct LoadDepth {
    pub depth: usize,
}

impl ScanPolicy for LoadDepth {
    fn revision(&self) -> PolicyRevision {
        PolicyRevision::new(0)
    }

    fn root_context(&self, _root: &EntryInfo) -> PolicyContext {
        PolicyContext::unit()
    }

    fn classify(&self, _parent: &PolicyContext, path: &RelativePath, _info: &EntryInfo) -> ScanDecision {
        ScanDecision::Eligible { initially_loaded: path.depth() < self.depth }
    }

    fn child_context(
        &self,
        parent: &PolicyContext,
        _path: &RelativePath,
        _listing: &DirectoryListing,
    ) -> PolicyContext {
        parent.clone()
    }
}
