//! This module defines the scan descent policy.
//!
//! A [`ScanPolicy`] classifies every entry as excluded or eligible, decides
//! which directories start loaded, and derives traversal context from parent
//! to child (RFC §8). [`LoadAll`], [`LoadDepth`], and [`PathPredicate`] cover
//! policies that need no context.

use std::any::Any;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::domain::{DomainCapabilities, DomainCrossing};
use crate::entry::EntryKind;
use crate::fs::{DirectoryListing, EntryInfo};
use crate::ids::PolicyRevision;
use crate::path::RelativePath;

/// A [`ScanPolicy`] returns one `ScanDecision` for each entry (RFC §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScanDecision {
    /// The entry is excluded. Exclusion overrides every explicit load request.
    Excluded,
    /// The tree represents the entry.
    Eligible {
        /// `initially_loaded` makes a directory start loaded, and `load` and
        /// `unload` override it per path.
        initially_loaded: bool,
    },
}

/// The policy owns `PolicyContext`, and the core treats it as opaque,
/// revisioned traversal context (RFC §8).
///
/// The core compares contexts by fingerprint alone. A policy must give
/// distinct fingerprints to contexts that classify any entry differently. A
/// changed fingerprint increments the affected policy-context generation.
#[derive(Clone)]
pub struct PolicyContext {
    fingerprint: u64,
    value: Arc<dyn Any + Send + Sync>,
}

impl PolicyContext {
    /// `new` wraps `value` with the fingerprint that identifies it.
    pub fn new<T: Any + Send + Sync>(fingerprint: u64, value: T) -> PolicyContext {
        PolicyContext { fingerprint, value: Arc::new(value) }
    }

    /// `unit` builds a context with fingerprint 0 and a unit value.
    pub fn unit() -> PolicyContext {
        PolicyContext::new(0, ())
    }

    /// `get` returns the wrapped value when it has type `T`.
    pub fn get<T: Any>(&self) -> Option<&T> {
        self.value.downcast_ref::<T>()
    }

    /// `same_as` reports whether both contexts carry the same fingerprint.
    pub fn same_as(&self, other: &PolicyContext) -> bool {
        self.fingerprint == other.fingerprint
    }
}

impl fmt::Debug for PolicyContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PolicyContext({})", self.fingerprint)
    }
}

/// A `ScanPolicy` decides exclusion and initial loading during descent (RFC
/// §8).
pub trait ScanPolicy: Send + Sync {
    /// `supports_chunks` returns true only when `child_context` works without a
    /// complete listing.
    ///
    /// A streaming [`crate::scan::Scan`] requires it (RFC §9.3).
    fn supports_chunks(&self) -> bool {
        false
    }

    /// `revision` returns the current policy revision.
    ///
    /// If the core dispatched a listing under an older revision, that listing
    /// cannot commit after policy invalidation. Scans ignore revisions (RFC
    /// §9.3).
    fn revision(&self) -> PolicyRevision;

    /// `root_context` derives the root's context from its entry info.
    fn root_context(&self, root: &EntryInfo) -> PolicyContext;

    /// `classify` classifies the entry at `path` under its parent's context.
    fn classify(&self, parent: &PolicyContext, path: &RelativePath, info: &EntryInfo) -> ScanDecision;

    /// `child_context` derives the children's context from the listing of the
    /// directory at `path`.
    fn child_context(&self, parent: &PolicyContext, path: &RelativePath, listing: &DirectoryListing) -> PolicyContext;

    /// `crossing` chooses the crossing mode for a child directory in another
    /// storage domain.
    ///
    /// The caller passes the configured mode as `configured` (RFC §14.3). The
    /// default returns it.
    fn crossing(
        &self,
        _parent: &PolicyContext,
        _path: &RelativePath,
        _child: &DomainCapabilities,
        configured: DomainCrossing,
    ) -> DomainCrossing {
        configured
    }

    /// `watcher_path_limit` limits the watched paths in the storage domain of
    /// the directory at `path`.
    ///
    /// The core applies the smaller of this value and `configured`. The
    /// default returns `configured`.
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

/// `PathPredicate` builds a context-free policy from a closure over path and
/// kind.
///
/// After the closure's answers change, the caller calls
/// [`PathPredicate::bump_revision`] and names the affected roots with
/// [`crate::tree::TreeHandle::invalidate_policy`].
pub struct PathPredicate<F> {
    revision: AtomicU64,
    predicate: F,
}

impl<F> PathPredicate<F>
where
    F: Fn(&RelativePath, EntryKind) -> ScanDecision + Send + Sync,
{
    /// `new` wraps `predicate` at revision 0.
    pub fn new(predicate: F) -> PathPredicate<F> {
        PathPredicate { revision: AtomicU64::new(0), predicate }
    }

    /// `bump_revision` increments the policy revision.
    pub fn bump_revision(&self) {
        self.revision.fetch_add(1, Ordering::SeqCst);
    }
}

impl<F> ScanPolicy for PathPredicate<F>
where
    F: Fn(&RelativePath, EntryKind) -> ScanDecision + Send + Sync,
{
    fn supports_chunks(&self) -> bool {
        true
    }

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

/// `LoadAll` represents and loads every entry.
pub struct LoadAll;

impl ScanPolicy for LoadAll {
    fn supports_chunks(&self) -> bool {
        true
    }

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

/// `LoadDepth` represents every entry and loads directories down to a depth.
///
/// An entry starts loaded when its path has fewer than `depth` components.
/// The root has zero components.
pub struct LoadDepth {
    /// `depth` sets the component count at which directories stop loading
    /// initially.
    pub depth: usize,
}

impl ScanPolicy for LoadDepth {
    fn supports_chunks(&self) -> bool {
        true
    }

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
