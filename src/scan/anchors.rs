use std::sync::Arc;

use crate::fs::{AnchorSlot, Continuation, DirectoryListing, Lease, ListingSession, SessionCost, SessionOutcome};

pub(super) fn track(session: Box<dyn ListingSession>, slot: Option<Arc<AnchorSlot>>) -> Box<dyn ListingSession> {
    match slot {
        Some(slot) => Box::new(AnchoredSession { inner: session, slot }),
        None => session,
    }
}

// Reserve from construction through physical cursor disposal. Returned anchors
// share that same reservation, so chunks and retained rows never double count.
struct AnchoredSession {
    inner: Box<dyn ListingSession>,
    slot: Arc<AnchorSlot>,
}

fn retain(listing: &DirectoryListing, slot: &Arc<AnchorSlot>) {
    if let Some(anchor) = &listing.anchor {
        anchor.retain_slot(slot);
    }
}

impl ListingSession for AnchoredSession {
    fn resume(self: Box<Self>, lease: Lease) -> (Continuation, SessionCost) {
        let Self { inner, slot } = *self;
        let (continuation, cost) = inner.resume(lease);
        let continuation = match continuation {
            Continuation::Suspended(inner) => Continuation::Suspended(Box::new(Self { inner, slot })),
            Continuation::Finished(SessionOutcome::Complete(listing)) => {
                retain(&listing, &slot);
                Continuation::Finished(SessionOutcome::Complete(listing))
            }
            other => other,
        };
        (continuation, cost)
    }

    fn supports_chunks(&self) -> bool {
        self.inner.supports_chunks()
    }

    fn take_chunk(&mut self) -> Option<DirectoryListing> {
        let listing = self.inner.take_chunk()?;
        retain(&listing, &self.slot);
        Some(listing)
    }
}
