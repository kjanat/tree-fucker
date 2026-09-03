use super::governor::GrantId;
use super::types::*;
use super::{Coordinator, Output};
use crate::entry::{LoadState, Shape};
use crate::fs::{HintKind, WatcherEvent};
use crate::path::RelativePath;
use crate::update::{ErrorCause, Operation, WatcherHealth};

impl Coordinator {
    pub(super) fn on_watcher(&mut self, event: WatcherEvent) {
        match event {
            WatcherEvent::Hint { paths, kind } => {
                for path in paths {
                    self.on_hint(path, kind);
                }
            }
            WatcherEvent::Overflow => self.coverage_invalidate(),
            WatcherEvent::Dropped { count } => {
                self.dropped_hints += count;
                self.coverage_invalidate();
            }
            WatcherEvent::Failed { message } => {
                self.watcher_health = WatcherHealth::Degraded { backend: self.caps.watcher, reason: message.clone() };
                self.push_error(RelativePath::root(), Operation::Watcher, ErrorCause::WatcherLost(message));
                self.unwatch_all();
                self.coverage_invalidate();
                let delay = self.backoff(self.watcher_restart_attempts);
                self.watcher_restart_due = Some(self.now + delay);
            }
        }
    }

    pub(super) fn coverage_invalidate(&mut self) {
        self.min_recon = self.recon_seq.next();
        self.recon_seq = self.min_recon;
    }

    fn on_hint(&mut self, path: RelativePath, kind: HintKind) {
        let RootState::Available { .. } = self.root else {
            return;
        };
        let watcher_pending = self.pending.values().filter(|p| p.reasons.watcher).count();
        if watcher_pending >= self.config.watcher_path_limit {
            self.dropped_hints += 1;
            self.coverage_invalidate();
            return;
        }
        let entry = self.snapshot.get(&path).cloned();
        let mut targets: Vec<(crate::ids::EntryId, RelativePath, ReadNeed)> = Vec::new();
        match (entry, kind) {
            (Some(e), HintKind::Modify | HintKind::Metadata) => {
                let need = if e.is_loaded() { ReadNeed::Listing } else { ReadNeed::Metadata };
                targets.push((e.id, e.path, need));
            }
            (Some(e), HintKind::Create | HintKind::Remove | HintKind::Rename | HintKind::Unknown) => {
                match self.parent_of(e.id).and_then(|p| self.snapshot.get_by_id(p).cloned()) {
                    Some(parent) => {
                        let need = if parent.is_loaded() { ReadNeed::Listing } else { ReadNeed::Metadata };
                        targets.push((parent.id, parent.path, need));
                        if kind == HintKind::Unknown && e.is_loaded() {
                            targets.push((e.id, e.path, ReadNeed::Listing));
                        }
                    }
                    None => targets.push((e.id, e.path, ReadNeed::Listing)),
                }
            }
            (None, _) => {
                let mut cursor = path.parent();
                while let Some(candidate) = cursor {
                    if let Some(ancestor) = self.snapshot.get(&candidate).cloned() {
                        if let Shape::Directory(LoadState::Loaded) = ancestor.shape {
                            targets.push((ancestor.id, ancestor.path, ReadNeed::Listing));
                        }
                        break;
                    }
                    cursor = candidate.parent();
                }
            }
        }
        for (id, target_path, need) in targets {
            self.bump_epoch(id);
            self.request(id, target_path, need, Reasons::watcher(), Vec::new());
        }
    }

    pub(super) fn restart_watcher(&mut self) {
        let RootState::Available { id: root_id, .. } = self.root else {
            return;
        };
        let targets: Vec<(crate::ids::EntryId, RelativePath, bool)> = if self.caps.watcher.is_per_directory() {
            self.snapshot
                .loaded_directories()
                .filter(|e| !matches!(self.dir_state(e.id).map(|d| d.watch), Some(WatchState::Registered(_))))
                .map(|e| (e.id, e.path.clone(), false))
                .collect()
        } else {
            vec![(root_id, RelativePath::root(), true)]
        };
        let mut deferred = false;
        for (id, path, recursive) in targets {
            let request = self.next_watch_request();
            let now = self.now;
            let reservation = super::governor::Reservation {
                id: GrantId::WatchRegistration(request),
                path: path.clone(),
                reads: 0,
                registrations: 1,
                lease: 0,
                domain: self.domain_of(id),
            };
            if self.governor.try_admit(reservation, now).is_err() {
                deferred = true;
                break;
            }
            self.registrations.insert(request, RegistrationTarget::Standalone(id));
            self.outputs.push(Output::RegisterWatch { request, path, recursive });
        }
        if deferred {
            self.watcher_restart_due = Some(self.now + self.config.minimum_period);
        }
    }
}
