use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tree_fucker::*;

pub fn delay() -> Duration {
    static DELAY: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *DELAY.get_or_init(|| {
        Duration::from_micros(
            std::env::var("BENCH_LISTING_DELAY_US").map_or(0, |s| s.parse().expect("delay in microseconds")),
        )
    })
}

pub struct Delayed(pub std_fs::StdFileSystem);
struct Session {
    inner: Box<dyn ListingSession>,
    first: bool,
}
impl ListingSession for Session {
    fn resume(self: Box<Self>, lease: Lease) -> (Continuation, SessionCost) {
        if self.first {
            std::thread::sleep(delay());
        }
        let (next, mut cost) = self.inner.resume(lease);
        if self.first {
            cost.blocking = cost.blocking.map(|cost| cost + delay());
        }
        let next = match next {
            Continuation::Suspended(inner) => Continuation::Suspended(Box::new(Session { inner, first: false })),
            done => done,
        };
        (next, cost)
    }
    fn take_chunk(&mut self) -> Option<DirectoryListing> {
        self.inner.take_chunk()
    }
    fn supports_chunks(&self) -> bool {
        self.inner.supports_chunks()
    }
}
impl FileSystem for Delayed {
    fn capabilities(&self) -> FsCapabilities {
        self.0.capabilities()
    }
    fn canonicalize(&self, root: &Path) -> std::result::Result<PathBuf, FsError> {
        self.0.canonicalize(root)
    }
    fn metadata(&self, root: &Path, path: &RelativePath) -> std::result::Result<EntryInfo, FsError> {
        self.0.metadata(root, path)
    }
    fn resolve_domain(
        &self,
        root: &Path,
        path: &RelativePath,
        parent: Option<&ProbeResult>,
    ) -> std::result::Result<ProbeResult, FsError> {
        self.0.resolve_domain(root, path, parent)
    }
    fn resolve_domain_beneath(
        &self,
        root: &Path,
        path: &RelativePath,
        anchor: Option<&Anchor>,
        parent: Option<&ProbeResult>,
    ) -> std::result::Result<ProbeResult, FsError> {
        self.0.resolve_domain_beneath(root, path, anchor, parent)
    }
    fn open_listing(
        &self,
        root: &Path,
        path: &RelativePath,
        ceilings: Ceilings,
        cancel: CancellationToken,
    ) -> Box<dyn ListingSession> {
        Box::new(Session { inner: self.0.open_listing(root, path, ceilings, cancel), first: true })
    }
    fn open_listing_at(
        &self,
        root: &Path,
        path: &RelativePath,
        at: ListingAt<'_>,
        ceilings: Ceilings,
        cancel: CancellationToken,
    ) -> Box<dyn ListingSession> {
        Box::new(Session { inner: self.0.open_listing_at(root, path, at, ceilings, cancel), first: true })
    }
    fn enrich(
        &self,
        root: &Path,
        path: &RelativePath,
        batch: &EnrichmentBatch,
    ) -> std::result::Result<Enrichment, FsError> {
        self.0.enrich(root, path, batch)
    }
    fn watch(
        &self,
        root: &Path,
        path: &RelativePath,
        recursive: bool,
        sink: Arc<dyn WatcherSink>,
    ) -> std::result::Result<WatchId, FsError> {
        self.0.watch(root, path, recursive, sink)
    }
    fn unwatch(&self, watch: WatchId) {
        self.0.unwatch(watch);
    }
}
