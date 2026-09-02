use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::sync::Arc;

use super::types::*;
use super::{Coordinator, Output};
use crate::entry::{Entry, EntryKind, LoadState, Shape};
use crate::error::Error;
use crate::fs::{DirEntry, DirectoryListing, EntryInfo};
use crate::ids::*;
use crate::path::{PathKey, RelativePath};
use crate::policy::{PolicyContext, ScanDecision};
use crate::snapshot::{SnapshotBuilder, new_entry};
use crate::update::{ErrorCause, Operation, PathChange};

pub(super) struct Observed<'a> {
    pub path: &'a RelativePath,
    pub info: EntryInfo,
}

#[derive(Default)]
pub(super) struct Effects {
    pub new_loading: Vec<(EntryId, RelativePath, Reasons)>,
    pub removed: Vec<Arc<Entry>>,
    pub unloaded: Vec<EntryId>,
    pub excluded: Vec<EntryId>,
    pub loaded: Vec<EntryId>,
    pub contexts: Vec<(EntryId, PolicyContext)>,
    pub kind_changed: Vec<EntryId>,
}

impl Coordinator {
    pub(super) fn commit_listing(&mut self, job: &ActiveJob, listing: DirectoryListing) -> Result<(), ()> {
        let Some(dir_id) = job.entry else {
            return Ok(());
        };
        let Some(dir) = self.snapshot.get_by_id(dir_id).cloned() else {
            return Ok(());
        };
        let fields = self.config.metadata_fields;
        let case = self.caps.case;
        let dir_key = self.snapshot.key(&dir.path);
        let mut seen: HashSet<PathKey> = HashSet::new();
        let mut children: Vec<(OsString, PathKey, EntryInfo)> = Vec::with_capacity(listing.entries.len());
        for DirEntry { name, info } in &listing.entries {
            let key = match dir_key.child(name, case) {
                Ok(key) => key,
                Err(_) => {
                    self.push_error(dir.path.clone(), Operation::Listing, ErrorCause::InvalidName(name.clone()));
                    continue;
                }
            };
            if !seen.insert(key.clone()) {
                self.push_error(dir.path.clone(), Operation::Listing, ErrorCause::DuplicateName(name.clone()));
                continue;
            }
            children.push((name.clone(), key, *info));
        }
        if children.len() > self.config.entries_per_directory {
            return Err(());
        }
        let mut builder = self.snapshot.builder();
        let mut effects = Effects::default();
        let was_loading = dir.shape == Shape::Directory(LoadState::Loading);
        let new_metadata = listing.directory.metadata.project(fields);
        if was_loading || dir.metadata != new_metadata || dir.identity != listing.directory.identity {
            let _ = builder.update(dir_id, |e| {
                e.metadata = new_metadata;
                e.identity = listing.directory.identity;
                if was_loading {
                    e.shape = Shape::Directory(LoadState::Loaded);
                }
            });
        }
        if was_loading {
            effects.loaded.push(dir_id);
        }
        let parent_ctx = self.parent_context(dir_id).unwrap_or_else(PolicyContext::unit);
        let ctx = self.policy.child_context(&parent_ctx, &dir.path, &listing);
        let ctx_changed =
            self.dir_state(dir_id).and_then(|d| d.context.as_ref()).map(|c| !c.same_as(&ctx)).unwrap_or(true);
        if ctx_changed {
            effects.contexts.push((dir_id, ctx.clone()));
        }
        let inherit = Reasons { initial_scan: job.reasons.initial_scan, ..Default::default() };
        let existing: HashMap<PathKey, Arc<Entry>> =
            builder.children(dir_id).into_iter().map(|e| (e.path.key(case), e)).collect();
        let mut seen_ids: HashSet<EntryId> = HashSet::new();
        for (name, key, info) in children {
            let Ok(path) = dir.path.join(&name) else {
                continue;
            };
            match existing.get(&key) {
                Some(old) => {
                    seen_ids.insert(old.id);
                    let replaced = self.caps.stable_identity
                        && old.identity.is_some()
                        && info.identity.is_some()
                        && old.identity != info.identity;
                    if replaced {
                        effects.removed.extend(builder.remove_subtree(old.id));
                        self.insert_new(&mut builder, &mut effects, path, info, &ctx, inherit);
                    } else {
                        let observed = Observed { path: &path, info };
                        self.reconcile_existing(&mut builder, &mut effects, old, observed, &ctx, inherit);
                    }
                }
                None => self.insert_new(&mut builder, &mut effects, path, info, &ctx, inherit),
            }
        }
        for old in existing.values() {
            if !seen_ids.contains(&old.id) {
                effects.removed.extend(builder.remove_subtree(old.id));
            }
        }
        if ctx_changed {
            self.reevaluate_descendants(&mut builder, &mut effects, dir_id, &ctx, false, inherit);
        }
        if builder.len() > self.config.represented_entries {
            return Err(());
        }
        self.commit(builder, effects, Some(job));
        Ok(())
    }

    fn insert_new(
        &mut self,
        builder: &mut SnapshotBuilder,
        effects: &mut Effects,
        path: RelativePath,
        info: EntryInfo,
        ctx: &PolicyContext,
        inherit: Reasons,
    ) {
        let decision = self.policy.classify(ctx, &path, &info);
        let shape = match info.kind {
            EntryKind::Directory => match decision {
                ScanDecision::Excluded => Shape::Directory(LoadState::Excluded),
                ScanDecision::Eligible { initially_loaded: true } => Shape::Directory(LoadState::Loading),
                ScanDecision::Eligible { initially_loaded: false } => Shape::Directory(LoadState::Unloaded),
            },
            other => {
                if decision == ScanDecision::Excluded {
                    return;
                }
                Shape::from_kind(other, LoadState::Unloaded)
            }
        };
        let id = self.next_entry_id();
        let mut entry = new_entry(id, path.clone(), shape);
        entry.metadata = info.metadata.project(self.config.metadata_fields);
        entry.identity = info.identity;
        if builder.insert(entry).is_ok() && shape == Shape::Directory(LoadState::Loading) {
            effects.new_loading.push((id, path, inherit));
        }
    }

    fn reconcile_existing(
        &mut self,
        builder: &mut SnapshotBuilder,
        effects: &mut Effects,
        old: &Entry,
        observed: Observed<'_>,
        ctx: &PolicyContext,
        inherit: Reasons,
    ) {
        let Observed { path, info } = observed;
        let metadata = info.metadata.project(self.config.metadata_fields);
        if old.kind() != info.kind {
            self.change_kind(builder, effects, old, info, ctx, inherit);
            return;
        }
        if old.path != *path {
            let _ = builder.rename_subtree(old.id, path.clone());
        }
        let metadata_changed = old.metadata != metadata || old.identity != info.identity;
        if metadata_changed {
            let _ = builder.update(old.id, |e| {
                e.metadata = metadata;
                e.identity = info.identity;
            });
        }
        let decision = self.policy.classify(ctx, path, &info);
        let current = Entry { metadata, identity: info.identity, ..old.clone() };
        self.apply_decision(builder, effects, &current, decision, inherit);
    }

    fn change_kind(
        &mut self,
        builder: &mut SnapshotBuilder,
        effects: &mut Effects,
        old: &Entry,
        info: EntryInfo,
        ctx: &PolicyContext,
        inherit: Reasons,
    ) {
        let decision = self.policy.classify(ctx, &old.path, &info);
        if old.is_directory() {
            for child in builder.child_ids(old.id) {
                effects.removed.extend(builder.remove_subtree(child));
            }
        }
        let shape = match info.kind {
            EntryKind::Directory => match decision {
                ScanDecision::Excluded => Shape::Directory(LoadState::Excluded),
                ScanDecision::Eligible { initially_loaded: true } => Shape::Directory(LoadState::Loading),
                ScanDecision::Eligible { initially_loaded: false } => Shape::Directory(LoadState::Unloaded),
            },
            other => {
                if decision == ScanDecision::Excluded {
                    effects.removed.extend(builder.remove_subtree(old.id));
                    return;
                }
                Shape::from_kind(other, LoadState::Unloaded)
            }
        };
        let metadata = info.metadata.project(self.config.metadata_fields);
        let _ = builder.update(old.id, |e| {
            e.shape = shape;
            e.metadata = metadata;
            e.identity = info.identity;
            e.generation = e.generation.next();
        });
        effects.kind_changed.push(old.id);
        if shape == Shape::Directory(LoadState::Loading) {
            effects.new_loading.push((old.id, old.path.clone(), inherit));
        }
    }

    fn apply_decision(
        &self,
        builder: &mut SnapshotBuilder,
        effects: &mut Effects,
        entry: &Entry,
        decision: ScanDecision,
        inherit: Reasons,
    ) {
        match entry.shape {
            Shape::Directory(current) => {
                if entry.path.is_root() {
                    return;
                }
                let override_load = self.dir_state(entry.id).and_then(|d| d.override_load);
                let target = match decision {
                    ScanDecision::Excluded => {
                        if current == LoadState::Excluded {
                            None
                        } else {
                            Some(LoadState::Excluded)
                        }
                    }
                    ScanDecision::Eligible { initially_loaded } => {
                        let desired = if current == LoadState::Excluded {
                            initially_loaded
                        } else {
                            override_load.unwrap_or(initially_loaded)
                        };
                        match (current, desired) {
                            (LoadState::Excluded, true) | (LoadState::Unloaded, true) => Some(LoadState::Loading),
                            (LoadState::Excluded, false) => Some(LoadState::Unloaded),
                            (LoadState::Loaded, false) | (LoadState::Loading, false) => Some(LoadState::Unloaded),
                            _ => None,
                        }
                    }
                };
                let Some(new_state) = target else { return };
                if matches!(current, LoadState::Loaded | LoadState::Loading) {
                    for child in builder.child_ids(entry.id) {
                        effects.removed.extend(builder.remove_subtree(child));
                    }
                }
                let _ = builder.update(entry.id, |e| e.shape = Shape::Directory(new_state));
                match new_state {
                    LoadState::Loading => effects.new_loading.push((entry.id, entry.path.clone(), inherit)),
                    LoadState::Unloaded => effects.unloaded.push(entry.id),
                    LoadState::Excluded => {
                        effects.unloaded.push(entry.id);
                        effects.excluded.push(entry.id);
                    }
                    LoadState::Loaded => {}
                }
            }
            _ => {
                if decision == ScanDecision::Excluded {
                    effects.removed.extend(builder.remove_subtree(entry.id));
                }
            }
        }
    }

    pub(super) fn listing_view(builder: &SnapshotBuilder, dir: &Entry) -> DirectoryListing {
        let entries = builder
            .children(dir.id)
            .into_iter()
            .filter_map(|child| {
                let name = child.path.file_name()?.to_os_string();
                Some(DirEntry {
                    name,
                    info: EntryInfo { kind: child.kind(), metadata: child.metadata, identity: child.identity },
                })
            })
            .collect();
        DirectoryListing {
            directory: EntryInfo { kind: dir.kind(), metadata: dir.metadata, identity: dir.identity },
            entries,
        }
    }

    pub(super) fn reevaluate_descendants(
        &mut self,
        builder: &mut SnapshotBuilder,
        effects: &mut Effects,
        dir_id: EntryId,
        ctx: &PolicyContext,
        force: bool,
        inherit: Reasons,
    ) {
        let mut stack: Vec<(EntryId, PolicyContext)> = vec![(dir_id, ctx.clone())];
        while let Some((parent, parent_ctx)) = stack.pop() {
            for child in builder.children(parent) {
                if child.shape != Shape::Directory(LoadState::Loaded) {
                    continue;
                }
                let view = Self::listing_view(builder, &child);
                let child_ctx = self.policy.child_context(&parent_ctx, &child.path, &view);
                let changed = self
                    .dir_state(child.id)
                    .and_then(|d| d.context.as_ref())
                    .map(|c| !c.same_as(&child_ctx))
                    .unwrap_or(true);
                if changed {
                    effects.contexts.push((child.id, child_ctx.clone()));
                }
                if !changed && !force {
                    continue;
                }
                for grandchild in builder.children(child.id) {
                    let info = EntryInfo {
                        kind: grandchild.kind(),
                        metadata: grandchild.metadata,
                        identity: grandchild.identity,
                    };
                    let decision = self.policy.classify(&child_ctx, &grandchild.path, &info);
                    self.apply_decision(builder, effects, &grandchild, decision, inherit);
                }
                stack.push((child.id, child_ctx));
            }
        }
    }

    pub(super) fn reevaluate_root_of_policy(
        &mut self,
        builder: &mut SnapshotBuilder,
        effects: &mut Effects,
        entry: &Entry,
    ) {
        let inherit = Reasons::default();
        if !entry.path.is_root() {
            let parent_ctx = self.parent_context(entry.id).unwrap_or_else(PolicyContext::unit);
            let info = EntryInfo { kind: entry.kind(), metadata: entry.metadata, identity: entry.identity };
            let decision = self.policy.classify(&parent_ctx, &entry.path, &info);
            self.apply_decision(builder, effects, entry, decision, inherit);
        }
        let still_loaded = builder.get(entry.id).map(|e| e.is_loaded()).unwrap_or(false);
        if still_loaded {
            let ctx = self.context_for_children(entry.id).unwrap_or_else(PolicyContext::unit);
            for child in builder.children(entry.id) {
                let info = EntryInfo { kind: child.kind(), metadata: child.metadata, identity: child.identity };
                let decision = self.policy.classify(&ctx, &child.path, &info);
                self.apply_decision(builder, effects, &child, decision, inherit);
            }
            self.reevaluate_descendants(builder, effects, entry.id, &ctx, true, inherit);
        }
    }

    pub(super) fn commit_metadata(&mut self, job: &ActiveJob, info: EntryInfo) -> JobOutcome {
        let Some(id) = job.entry else {
            return JobOutcome::Accepted;
        };
        let Some(entry) = self.snapshot.get_by_id(id).cloned() else {
            return JobOutcome::Stale;
        };
        let metadata = info.metadata.project(self.config.metadata_fields);
        let mut builder = self.snapshot.builder();
        let mut effects = Effects::default();
        let parent_ctx = self.parent_context(id).unwrap_or_else(PolicyContext::unit);
        let inherit = Reasons::default();
        if entry.kind() != info.kind {
            if entry.path.is_root() {
                self.root_lost();
                return JobOutcome::Removed;
            }
            let was_directory = entry.is_directory();
            self.change_kind(&mut builder, &mut effects, &entry, info, &parent_ctx, inherit);
            self.commit(builder, effects, Some(job));
            return if was_directory { JobOutcome::Removed } else { JobOutcome::Accepted };
        }
        let changed = entry.metadata != metadata || entry.identity != info.identity;
        if changed {
            let _ = builder.update(id, |e| {
                e.metadata = metadata;
                e.identity = info.identity;
            });
            if !entry.path.is_root() {
                let current = Entry { metadata, identity: info.identity, ..entry.clone() };
                let decision = self.policy.classify(&parent_ctx, &entry.path, &info);
                self.apply_decision(&mut builder, &mut effects, &current, decision, inherit);
            }
        }
        self.commit(builder, effects, Some(job));
        JobOutcome::Accepted
    }

    pub(super) fn remove_entry(&mut self, id: EntryId, job: Option<&ActiveJob>) {
        let mut builder = self.snapshot.builder();
        let mut effects = Effects::default();
        effects.removed.extend(builder.remove_subtree(id));
        self.commit(builder, effects, job);
    }

    pub(super) fn commit(&mut self, builder: SnapshotBuilder, effects: Effects, job: Option<&ActiveJob>) {
        let touched: Vec<EntryId> = builder.touched().collect();
        let previous = self.snapshot.version();
        let changes: Vec<PathChange> = if touched.is_empty() {
            Vec::new()
        } else {
            let (snapshot, produced) = builder.finish(previous.next());
            self.snapshot = snapshot;
            produced
        };
        let current_job = job.map(|j| j.id);
        let removed_ids: HashSet<EntryId> = effects.removed.iter().map(|e| e.id).collect();
        for removed in &effects.removed {
            self.drop_entry_state(removed.id, current_job);
            self.commands_entry_removed(removed.id, &removed.path, job);
        }
        for id in &effects.unloaded {
            if removed_ids.contains(id) {
                continue;
            }
            let excluded = effects.excluded.contains(id);
            self.invalidate_directory_work(*id, current_job);
            if let Some(dir) = self.dir_state_mut(*id) {
                dir.load_generation = dir.load_generation.next();
                dir.context = None;
                dir.last_covered = None;
                if excluded {
                    dir.override_load = None;
                }
            }
            self.set_obligation(*id, ObligationState::Removed);
            if let Some((_, state)) = self.initial_scan.obligations.get_mut(id)
                && *state == ScanObligation::Pending
            {
                *state = ScanObligation::Removed;
            }
            self.commands_entry_unloaded(*id, excluded);
        }
        for id in &effects.kind_changed {
            if removed_ids.contains(id) {
                continue;
            }
            let now_directory = self.snapshot.get_by_id(*id).map(|e| e.is_directory()).unwrap_or(false);
            self.invalidate_directory_work(*id, current_job);
            let state = self.entry_state_mut(*id);
            if now_directory {
                if state.dir.is_none() {
                    state.dir = Some(DirState::default());
                }
            } else {
                state.dir = None;
            }
            self.set_obligation(*id, ObligationState::Removed);
            if let Some((_, state)) = self.initial_scan.obligations.get_mut(id)
                && *state == ScanObligation::Pending
            {
                *state = ScanObligation::Removed;
            }
            self.commands_kind_changed(*id, job);
        }
        for id in &effects.loaded {
            let previous_generation = self.dir_state(*id).map(|d| d.load_generation);
            if let Some(dir) = self.dir_state_mut(*id) {
                dir.load_generation = dir.load_generation.next();
            }
            if let Some((generation, state)) = self.initial_scan.obligations.get_mut(id)
                && *state == ScanObligation::Pending
                && Some(*generation) == previous_generation
            {
                *state = ScanObligation::Accepted;
            }
        }
        for (id, ctx) in effects.contexts {
            if removed_ids.contains(&id) {
                continue;
            }
            if let Some(dir) = self.dir_state_mut(id) {
                dir.context = Some(ctx);
                dir.context_generation = dir.context_generation.next();
            }
        }
        for id in &touched {
            if self.snapshot.contains_id(*id) && !self.entries.contains_key(id) {
                let is_dir = self.snapshot.get_by_id(*id).map(|e| e.is_directory()).unwrap_or(false);
                self.entries.insert(*id, if is_dir { EntryState::directory() } else { EntryState::default() });
            }
        }
        for (id, path, reasons) in effects.new_loading {
            if removed_ids.contains(&id) {
                continue;
            }
            let state = self.entry_state_mut(id);
            if state.dir.is_none() {
                state.dir = Some(DirState::default());
            }
            if let Some(dir) = state.dir.as_mut() {
                dir.load_generation = dir.load_generation.next();
                dir.context = None;
            }
            let load_generation = self.dir_state(id).map(|d| d.load_generation).unwrap_or_default();
            if reasons.initial_scan {
                self.initial_scan.obligations.insert(id, (load_generation, ScanObligation::Pending));
            }
            let mut request_reasons = Reasons::control();
            request_reasons.merge(reasons);
            self.request(id, path, ReadNeed::Listing, request_reasons, Vec::new());
        }
        for change in &changes {
            let membership_parents: Vec<RelativePath> = match change {
                PathChange::Added { path, .. } | PathChange::Removed { path, .. } => {
                    path.parent().into_iter().collect()
                }
                PathChange::Renamed { old_path, new_path, .. } => {
                    old_path.parent().into_iter().chain(new_path.parent()).collect()
                }
                PathChange::KindChanged { .. }
                | PathChange::LoadStateChanged { .. }
                | PathChange::MetadataChanged { .. } => Vec::new(),
            };
            for parent_path in membership_parents {
                if let Some(parent) = self.snapshot.get(&parent_path).map(|p| p.id)
                    && let Some(dir) = self.dir_state_mut(parent)
                {
                    dir.child_state = dir.child_state.next();
                }
            }
            let owner_paths: Vec<RelativePath> = match change {
                PathChange::Renamed { old_path, new_path, .. } => {
                    old_path.parent().into_iter().chain(new_path.parent()).collect()
                }
                other => other.path().parent().into_iter().collect(),
            };
            for owner_path in owner_paths {
                if let Some(owner) = self.snapshot.get(&owner_path).map(|p| p.id) {
                    let state = self.entry_state_mut(owner);
                    state.state_generation = state.state_generation.next();
                }
            }
            if !matches!(change, PathChange::Added { .. } | PathChange::Removed { .. }) {
                let state = self.entry_state_mut(change.id());
                state.state_generation = state.state_generation.next();
            }
        }
        if self.snapshot.version() != previous {
            self.publish_delta(previous, changes);
        }
    }

    fn invalidate_directory_work(&mut self, id: EntryId, except: Option<JobId>) {
        if let Some(job_id) = self.active_by_entry.get(&id).copied()
            && Some(job_id) != except
        {
            self.cancel_job(job_id);
        }
        self.pending.remove(&id);
        if let Some(state) = self.entries.get_mut(&id) {
            state.retry = None;
            state.degraded = None;
            if let Some(dir) = state.dir.as_mut()
                && let WatchState::Registered(watch) = dir.watch
                && self.caps.watcher.is_per_directory()
            {
                self.outputs.push(Output::Unwatch(watch));
                self.watches.retain(|w| *w != watch);
                dir.watch = WatchState::NotRegistered;
            }
        }
    }

    fn drop_entry_state(&mut self, id: EntryId, except: Option<JobId>) {
        if let Some(job_id) = self.active_by_entry.get(&id).copied() {
            if Some(job_id) != except {
                self.cancel_job(job_id);
            } else {
                self.active_by_entry.remove(&id);
            }
        }
        self.pending.remove(&id);
        if let Some(state) = self.entries.remove(&id)
            && let Some(dir) = state.dir
            && let WatchState::Registered(watch) = dir.watch
            && self.caps.watcher.is_per_directory()
        {
            self.outputs.push(Output::Unwatch(watch));
            self.watches.retain(|w| *w != watch);
        }
        self.set_obligation(id, ObligationState::Removed);
        if let Some((_, state)) = self.initial_scan.obligations.get_mut(&id)
            && *state == ScanObligation::Pending
        {
            *state = ScanObligation::Removed;
        }
    }

    pub(super) fn root_lost(&mut self) {
        let RootState::Available { incarnation, id } = self.root else {
            return;
        };
        let mut builder = self.snapshot.builder();
        builder.remove_subtree(id);
        let previous = self.snapshot.version();
        let (snapshot, changes) = builder.finish(previous.next());
        self.snapshot = snapshot;
        self.root = RootState::Unavailable { last: incarnation };
        self.entries.clear();
        self.pending.clear();
        self.round = None;
        self.cancel_all_jobs();
        self.unwatch_all();
        let ids: Vec<CommandId> = self.commands.keys().copied().collect();
        for cmd in ids {
            self.finish_command(cmd, Err(Error::RootUnavailable));
        }
        let waiters = std::mem::take(&mut self.initial_scan.waiters);
        for cmd in waiters {
            self.outputs.push(Output::CommandFinished { id: cmd, result: Err(Error::RootUnavailable) });
        }
        self.initial_scan = InitialScan::new();
        self.probe_attempts = 0;
        self.publish_delta(previous, changes);
        if self.config.root_reappearance_monitoring {
            self.schedule_probe(false);
        }
    }

    pub(super) fn root_recovered(&mut self, info: EntryInfo) {
        let previous = self.snapshot.version();
        self.install_root(info);
        let changes = self
            .snapshot
            .root()
            .map(|root| vec![PathChange::Added { id: root.id, path: root.path.clone(), kind: root.kind() }])
            .unwrap_or_default();
        let root_id = self.root.id();
        let recovering: Vec<CommandId> = self
			.commands
			.values()
			.filter(|c| matches!(&c.state, CommandState::Refresh { remaining } if remaining.iter().any(|t| matches!(t, RefreshTarget::RootRecovery))))
			.map(|c| c.id)
			.collect();
        if let Some(root_id) = root_id
            && let Some(request) = self.pending.get_mut(&root_id)
        {
            for cmd in recovering {
                if !request.barriers.contains(&cmd) {
                    request.barriers.push(cmd);
                }
            }
        }
        self.publish_delta(previous, changes);
    }
}
