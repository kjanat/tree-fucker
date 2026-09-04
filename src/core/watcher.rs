use super::types::*;
use super::{Coordinator, Output, WatchDecision};
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
            WatcherEvent::Failed { message, path } => self.on_watcher_failed(message, path),
        }
    }

    fn on_watcher_failed(&mut self, message: String, path: Option<RelativePath>) {
        let scope = path.as_ref().and_then(|path| self.snapshot.get(path)).map(|entry| entry.id);
        let reported = path.unwrap_or_else(RelativePath::root);
        match scope {
            Some(entry) => {
                self.degrade_domain_watcher(entry, message.clone());
                self.unwatch_domain(entry);
            }
            None => {
                self.watcher_health = WatcherHealth::Degraded { backend: self.caps.watcher, reason: message.clone() };
                let domains: Vec<crate::domain::StorageDomainId> = self.domain_records.keys().copied().collect();
                for domain in domains {
                    self.watcher_degraded.insert(domain, message.clone());
                }
                self.unwatch_all();
            }
        }
        self.push_error(reported, Operation::Watcher, ErrorCause::WatcherLost(message));
        self.coverage_invalidate();
        let delay = self.backoff(self.watcher_restart_attempts);
        self.watcher_restart_due = Some(self.now + delay);
    }

    fn unwatch_domain(&mut self, entry: crate::ids::EntryId) {
        let Some(domain) = self.domain_of(entry) else {
            return;
        };
        let held: Vec<crate::ids::EntryId> =
            self.entries.watched_ids().filter(|id| self.domain_of(*id) == Some(domain)).collect();
        for id in held {
            let Some(WatchState::Registered(watch)) = self.dir_state(id).map(|d| d.watch()) else {
                continue;
            };
            let domain = self.domain_of(id);
            self.emit_unwatch(watch, domain);
            self.watches.retain(|held| *held != watch);
            self.entries.set_watch(id, WatchState::NotRegistered, domain);
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
        let RootState::Available { .. } = self.root else {
            return;
        };
        let candidates: Vec<crate::ids::EntryId> = self.snapshot.loaded_directories().map(|e| e.id).collect();
        if self.register_watches(candidates) {
            self.watcher_restart_due = Some(self.now + self.config.minimum_period);
        }
    }

    pub(super) fn retry_capped_watches(&mut self) {
        let RootState::Available { .. } = self.root else {
            return;
        };
        if !self.entries.any_capped() || !self.tree_watch_capacity() {
            return;
        }
        let candidates: Vec<crate::ids::EntryId> = self.entries.capped_ids().take(self.config.batch_size).collect();
        self.register_watches(candidates);
    }

    fn register_watches(&mut self, candidates: Vec<crate::ids::EntryId>) -> bool {
        for id in candidates {
            let Some(path) = self.snapshot.get_by_id(id).map(|e| e.path.clone()) else {
                continue;
            };
            match self.watch_decision(id) {
                WatchDecision::NotNeeded => continue,
                WatchDecision::Capped => {
                    let domain = self.domain_of(id);
                    self.entries.set_watch(id, WatchState::Capped, domain);
                    continue;
                }
                WatchDecision::Register(scope) => {
                    let domain = self.domain_of(id);
                    if self.governor.may_start(domain).is_err() {
                        return true;
                    }
                    let request = self.next_watch_request();
                    let now = self.now;
                    let reservation = super::governor::Reservation {
                        id: self.registration_grant(request),
                        path: path.clone(),
                        reads: 0,
                        registrations: 1,
                        lease: 0,
                        domain,
                        origin: WorkOrigin::Background,
                        listing: false,
                    };
                    if self.governor.try_admit(reservation, now).is_err() {
                        return true;
                    }
                    self.governor.start(self.registration_grant(request), now);
                    self.hold_watch_path(id);
                    self.blocking_slots.insert(
                        super::SlotOwner::WatchRegistration(request),
                        Occupancy {
                            path: path.clone(),
                            operation: super::JobOperation::WatchRegistration,
                            started: now,
                        },
                    );
                    self.registrations.insert(request, RegistrationTarget::Standalone(id));
                    self.outputs.push(Output::RegisterWatch { request, path, recursive: scope.is_recursive() });
                }
            }
        }
        false
    }
}
