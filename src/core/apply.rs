use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
use std::sync::Arc;

use super::types::*;
use super::{Coordinator, CrossingEvent, Output};
use crate::domain::{Crossing, DomainCapabilities, DomainCrossing, ProbeResult};
use crate::entry::{Entry, EntryKind, LoadState, Metadata, MetadataFields, Shape};
use crate::error::Error;
use crate::fs::{DirEntry, DirectoryListing, Enrichment, EntryInfo, Observation};
use crate::ids::*;
use crate::path::{PathKey, RelativePath};
use crate::policy::{PolicyContext, ScanDecision};
use crate::snapshot::{SnapshotBuilder, new_entry};
use crate::update::{ErrorCause, Operation, PathChange, ResourceLimit, ResourceLimitEvent, ResourceLimited};

pub(super) struct Observed<'a> {
    pub path: &'a RelativePath,
    pub info: EntryInfo,
}

pub(super) struct Candidate<'a> {
    pub key: PathKey,
    pub path: RelativePath,
    pub info: EntryInfo,
    pub domain: Option<&'a ProbeResult>,
}

pub(super) struct Classification<'a> {
    pub ctx: &'a PolicyContext,
    pub inherit: Reasons,
    pub fields: MetadataFields,
    pub parent_domain: Option<&'a ProbeResult>,
}

fn crossed(parent: Option<&ProbeResult>, child: &ProbeResult) -> Crossing {
    let mount_root = if child.is_domain_root { Crossing::Proven } else { Crossing::NotCrossed };
    child.crossed.stronger(Crossing::between(parent, &child.identity)).stronger(mount_root)
}

fn requires_crossing_decision(parent: Option<&ProbeResult>, child: &ProbeResult) -> bool {
    match crossed(parent, child) {
        Crossing::Proven => true,
        Crossing::NotCrossed => false,
        Crossing::Inconclusive => match parent {
            Some(parent) => {
                !child.capabilities.same_storage_as(&parent.capabilities)
                    || child.capabilities.foreign_beneath(&parent.capabilities)
            }
            None => false,
        },
    }
}

enum IdentityMatch {
    Unavailable,
    Same,
    Different,
}

enum ChildBinding {
    Retained,
    Renamed,
    Replaced,
}

struct Chosen {
    name: OsString,
    path: RelativePath,
    info: EntryInfo,
    domain: Option<Box<ProbeResult>>,
}

fn collision_key(candidate: &Chosen) -> crate::entry::CollisionKey<'_> {
    crate::entry::collision_key(&candidate.name, candidate.info.kind, &candidate.info.metadata, candidate.info.identity)
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
    pub domains: Vec<(EntryId, DomainBinding)>,
    pub crossings: Vec<(EntryId, Option<CrossingEvent>)>,
}

impl Coordinator {
    pub(super) fn commit_listing(
        &mut self,
        job: &ActiveJob,
        listing: DirectoryListing,
    ) -> Result<(), ListingRejection> {
        let Some(dir_id) = job.entry() else {
            return Ok(());
        };
        let Some(dir) = self.snapshot.get_by_id(dir_id).cloned() else {
            return Ok(());
        };
        let fields = self.config.metadata_fields;
        let observed_fields = fields.intersect(listing.supplied_fields);
        let mut builder = self.snapshot.builder();
        let mut effects = Effects::default();
        effects.removed.extend(builder.set_child_case(dir_id, listing.domain.case()));
        let Some((dir_key, case)) = builder.directory_key(dir_id) else {
            return Ok(());
        };
        let mut order: Vec<PathKey> = Vec::with_capacity(listing.entries.len());
        let mut chosen: BTreeMap<PathKey, Chosen> = BTreeMap::new();
        let mut malformed: Vec<ErrorCause> = Vec::new();
        let mut duplicates: Vec<OsString> = Vec::new();
        let mut unresolved: Vec<OsString> = Vec::new();
        for DirEntry { name, info, domain } in &listing.entries {
            let Some(info) = info.info() else {
                unresolved.push(name.clone());
                continue;
            };
            let (path, key) = match (dir.path.join(name), dir_key.child(name, case)) {
                (Ok(path), Ok(key)) => (path, key),
                _ => {
                    malformed.push(ErrorCause::InvalidName(name.clone()));
                    continue;
                }
            };
            let candidate = Chosen { name: name.clone(), path, info, domain: domain.clone() };
            match chosen.get_mut(&key) {
                Some(kept) => {
                    if collision_key(&candidate) < collision_key(kept) {
                        duplicates.push(std::mem::replace(kept, candidate).name);
                    } else {
                        duplicates.push(candidate.name);
                    }
                }
                None => {
                    order.push(key.clone());
                    chosen.insert(key, candidate);
                }
            }
        }
        if !unresolved.is_empty() {
            self.unresolved_listings += 1;
            unresolved.sort();
            for name in unresolved {
                self.push_error(dir.path.clone(), Operation::Listing, ErrorCause::UnresolvedKind(name));
            }
            return Err(ListingRejection::UnresolvedChild);
        }
        if !malformed.is_empty() {
            for cause in malformed {
                self.push_error(dir.path.clone(), Operation::Listing, cause);
            }
            return Err(ListingRejection::MalformedNames);
        }
        if order.len() > self.config.entries_per_directory {
            let limited = self.limited(
                ResourceLimit::EntriesPerDirectory,
                u64::try_from(self.config.entries_per_directory).unwrap_or(u64::MAX),
                u64::try_from(order.len()).unwrap_or(u64::MAX),
                dir_id,
            );
            self.record_resource_limit(ResourceLimitEvent { path: dir.path.clone(), limited });
            return Err(ListingRejection::ResourceLimited(limited));
        }
        let children: Vec<(RelativePath, PathKey, EntryInfo, Option<Box<ProbeResult>>)> = order
            .into_iter()
            .filter_map(|key| chosen.remove(&key).map(|kept| (kept.path, key, kept.info, kept.domain)))
            .collect();
        let previous_domain =
            self.dir_state(dir_id).and_then(|d| d.domain.as_ref()).map(|b| b.probe.capabilities.clone());
        let binding = self.bind_domain(&listing.domain);
        effects.domains.push((dir_id, binding));
        let own_domain = listing.domain.as_ref();
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
        let classification =
            Classification { ctx: &ctx, inherit, fields: observed_fields, parent_domain: Some(own_domain) };
        let existing: BTreeMap<PathKey, Arc<Entry>> = builder
            .children(dir_id)
            .into_iter()
            .filter_map(|e| Some((dir_key.descend(e.path.file_name()?, case), e)))
            .collect();
        let mut seen_ids: HashSet<EntryId, crate::ids::IdHashing> = HashSet::default();
        for (path, key, info, child_domain) in children {
            let Some(old) = existing.get(&key) else {
                let candidate = Candidate { key, path, info, domain: child_domain.as_deref() };
                self.insert_new(&mut builder, &mut effects, candidate, &classification);
                continue;
            };
            seen_ids.insert(old.id);
            let bound = match self.bind_child(previous_domain.as_ref(), &own_domain.capabilities, old, &path, &info) {
                ChildBinding::Retained => true,
                ChildBinding::Renamed => builder.rename_subtree(old.id, path.clone()).is_ok(),
                ChildBinding::Replaced => false,
            };
            if bound {
                self.rebind_child_domain(
                    &mut builder,
                    &mut effects,
                    old.id,
                    &path,
                    child_domain.as_deref(),
                    own_domain,
                );
                let observed = Observed { path: &path, info };
                self.reconcile_existing(&mut builder, &mut effects, old, observed, &classification);
            } else {
                effects.removed.extend(builder.remove_subtree(old.id));
                let candidate = Candidate { key, path, info, domain: child_domain.as_deref() };
                self.insert_new(&mut builder, &mut effects, candidate, &classification);
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
        if let Some(limited) = self.exceeded_representation(&builder, dir_id) {
            self.record_resource_limit(ResourceLimitEvent { path: dir.path.clone(), limited });
            return Err(ListingRejection::ResourceLimited(limited));
        }
        duplicates.sort();
        for name in duplicates {
            self.push_error(dir.path.clone(), Operation::Listing, ErrorCause::DuplicateName(name));
        }
        self.commit(builder, effects, Some(job));
        self.request_enrichment(dir_id, fields.without(listing.supplied_fields), job.reasons);
        Ok(())
    }

    pub(super) fn exceeded_representation(
        &self,
        builder: &crate::snapshot::SnapshotBuilder,
        dir: EntryId,
    ) -> Option<ResourceLimited> {
        if builder.len() > self.config.represented_entries {
            return Some(self.limited(
                ResourceLimit::RepresentedEntries,
                u64::try_from(self.config.represented_entries).unwrap_or(u64::MAX),
                u64::try_from(builder.len()).unwrap_or(u64::MAX),
                dir,
            ));
        }
        if builder.bytes() > self.config.snapshot_bytes {
            return Some(self.limited(ResourceLimit::SnapshotBytes, self.config.snapshot_bytes, builder.bytes(), dir));
        }
        let projected = self.projected_memory(builder.bytes());
        let ceiling = self.memory_ceiling();
        if projected > ceiling {
            return Some(self.limited(ResourceLimit::AccountedMemory, ceiling, projected, dir));
        }
        None
    }

    pub(super) fn request_enrichment(&mut self, dir: EntryId, fields: MetadataFields, origin: Reasons) {
        if !fields.any() {
            self.pending_enrichment.remove(&dir);
            return;
        }
        let Some(entry) = self.snapshot.get_by_id(dir) else {
            return;
        };
        if !entry.is_loaded() {
            return;
        }
        let path = entry.path.clone();
        let mut reasons = origin;
        reasons.baseline = false;
        reasons.initial_scan = false;
        match self.pending_enrichment.get_mut(&dir) {
            Some(existing) => {
                existing.path = path;
                existing.fields = fields;
                existing.reasons.merge(reasons);
                existing.due = None;
            }
            None => {
                self.pending_enrichment
                    .insert(dir, EnrichmentRequest { path, fields, reasons, attempts: 0, due: None });
            }
        }
    }

    pub(super) fn commit_enrichment(
        &mut self,
        job: &ActiveJob,
        fields: MetadataFields,
        read: Enrichment,
    ) -> JobOutcome {
        let Some(dir_id) = job.entry() else {
            return JobOutcome::Accepted;
        };
        let Some(dir) = self.snapshot.get_by_id(dir_id).cloned() else {
            return JobOutcome::Stale;
        };
        self.metadata_operations += u64::from(read.metadata_operations);
        self.enrichments += 1;
        let supplied = fields.intersect(read.supplied_fields);
        let mut builder = self.snapshot.builder();
        let mut effects = Effects::default();
        let Some((dir_key, case)) = builder.directory_key(dir_id) else {
            return JobOutcome::Stale;
        };
        if let Some(metadata) = read.directory {
            let merged = dir.metadata.merged(metadata, supplied);
            if merged != dir.metadata {
                let _ = builder.update(dir_id, |e| e.metadata = merged);
            }
        }
        let by_key: HashMap<PathKey, Metadata> = read
            .children
            .into_iter()
            .filter_map(|(name, metadata)| Some((dir_key.child(&name, case).ok()?, metadata)))
            .collect();
        let ctx = self.context_for_children(dir_id).unwrap_or_else(PolicyContext::unit);
        let children: Vec<Arc<Entry>> = builder.children(dir_id);
        for child in children {
            let Some(key) = child.path.file_name().map(|name| dir_key.descend(name, case)) else {
                continue;
            };
            let Some(metadata) = by_key.get(&key).copied() else {
                continue;
            };
            let merged = child.metadata.merged(metadata, supplied);
            if merged == child.metadata {
                continue;
            }
            let _ = builder.update(child.id, |e| e.metadata = merged);
            let info = EntryInfo { kind: child.kind(), metadata: merged, identity: child.identity };
            let current = Entry { metadata: merged, ..(*child).clone() };
            let decision = self.policy.classify(&ctx, &child.path, &info);
            self.apply_decision(&mut builder, &mut effects, &current, decision, Reasons::default());
        }
        self.commit(builder, effects, Some(job));
        self.entries.set_metadata_degraded(dir_id, None);
        JobOutcome::Accepted
    }

    fn identity_match(
        &self,
        previous: Option<&DomainCapabilities>,
        incoming: &DomainCapabilities,
        old: &Entry,
        info: &EntryInfo,
    ) -> IdentityMatch {
        let Some(previous) = previous else {
            return IdentityMatch::Unavailable;
        };
        if !previous.establishes_rename(incoming) {
            return IdentityMatch::Unavailable;
        }
        match (old.identity, info.identity) {
            (Some(previous), Some(observed)) if previous == observed => IdentityMatch::Same,
            (Some(_), Some(_)) => IdentityMatch::Different,
            _ => IdentityMatch::Unavailable,
        }
    }

    fn bind_child(
        &self,
        previous: Option<&DomainCapabilities>,
        incoming: &DomainCapabilities,
        old: &Entry,
        path: &RelativePath,
        info: &EntryInfo,
    ) -> ChildBinding {
        match (old.path == *path, self.identity_match(previous, incoming, old, info)) {
            (_, IdentityMatch::Different) => ChildBinding::Replaced,
            (true, _) => ChildBinding::Retained,
            (false, IdentityMatch::Same) => ChildBinding::Renamed,
            (false, IdentityMatch::Unavailable) => ChildBinding::Replaced,
        }
    }

    fn insert_new(
        &mut self,
        builder: &mut SnapshotBuilder,
        effects: &mut Effects,
        candidate: Candidate<'_>,
        classification: &Classification<'_>,
    ) {
        let Candidate { key, path, info, domain } = candidate;
        let Classification { ctx, inherit, fields, parent_domain } = *classification;
        let decision = self.policy.classify(ctx, &path, &info);
        let crossing = match (info.kind, domain) {
            (EntryKind::Directory, Some(probe)) => requires_crossing_decision(parent_domain, probe)
                .then(|| self.policy.crossing(ctx, &path, &probe.capabilities, self.config.domain_crossing)),
            _ => None,
        };
        let shape = match info.kind {
            EntryKind::Directory => match (crossing, decision) {
                (_, ScanDecision::Excluded) | (Some(DomainCrossing::Exclude), _) => {
                    Shape::Directory(LoadState::Excluded)
                }
                (Some(DomainCrossing::LoadOnDemand), _) => Shape::Directory(LoadState::Unloaded),
                (_, ScanDecision::Eligible { initially_loaded: true }) => Shape::Directory(LoadState::Loading),
                (_, ScanDecision::Eligible { initially_loaded: false }) => Shape::Directory(LoadState::Unloaded),
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
        entry.metadata = info.metadata.project(fields);
        entry.identity = info.identity;
        if builder.insert_at(key, entry).is_err() {
            return;
        }
        if let (EntryKind::Directory, Some(probe)) = (info.kind, domain) {
            effects.removed.extend(builder.set_child_case(id, probe.case()));
            let binding = self.bind_domain(probe);
            let child = binding.id;
            effects.domains.push((id, binding));
            if let Some(mode) = crossing {
                let parent = parent_domain.map(|probe| self.bind_domain(probe).id);
                effects.crossings.push((id, Some(CrossingEvent { path: path.clone(), parent, child, mode })));
            }
        }
        if shape == Shape::Directory(LoadState::Loading) {
            effects.new_loading.push((id, path, inherit));
        }
    }

    fn reconcile_existing(
        &mut self,
        builder: &mut SnapshotBuilder,
        effects: &mut Effects,
        old: &Entry,
        observed: Observed<'_>,
        classification: &Classification<'_>,
    ) {
        let Classification { ctx, inherit, fields, .. } = *classification;
        let Observed { path, info } = observed;
        let metadata = old.metadata.merged(info.metadata, fields);
        let current = Entry { path: path.clone(), metadata, identity: info.identity, ..old.clone() };
        if old.kind() != info.kind {
            self.change_kind(builder, effects, &current, info, classification);
            return;
        }
        let metadata_changed = old.metadata != metadata || old.identity != info.identity;
        if metadata_changed {
            let _ = builder.update(old.id, |e| {
                e.metadata = metadata;
                e.identity = info.identity;
            });
        }
        let decision = self.policy.classify(ctx, path, &info);
        self.apply_decision(builder, effects, &current, decision, inherit);
    }

    fn change_kind(
        &mut self,
        builder: &mut SnapshotBuilder,
        effects: &mut Effects,
        old: &Entry,
        info: EntryInfo,
        classification: &Classification<'_>,
    ) {
        let Classification { ctx, inherit, fields, .. } = *classification;
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
        let metadata = old.metadata.merged(info.metadata, fields);
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
                let crossing = self.dir_state(entry.id).and_then(|d| d.crossing);
                let decision = match crossing {
                    Some(DomainCrossing::Exclude) => ScanDecision::Excluded,
                    Some(DomainCrossing::LoadOnDemand) if override_load != Some(true) => match decision {
                        ScanDecision::Excluded => ScanDecision::Excluded,
                        ScanDecision::Eligible { .. } => ScanDecision::Eligible { initially_loaded: false },
                    },
                    _ => decision,
                };
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

    pub(super) fn listing_view(
        builder: &SnapshotBuilder,
        dir: &Entry,
        supplied_fields: MetadataFields,
        domain: ProbeResult,
    ) -> DirectoryListing {
        let entries = builder
            .children(dir.id)
            .into_iter()
            .filter_map(|child| {
                let name = child.path.file_name()?.to_os_string();
                let info = EntryInfo { kind: child.kind(), metadata: child.metadata, identity: child.identity };
                Some(DirEntry::new(name, Observation::resolved(info)))
            })
            .collect();
        DirectoryListing {
            directory: EntryInfo { kind: dir.kind(), metadata: dir.metadata, identity: dir.identity },
            entries,
            supplied_fields,
            domain: Box::new(domain),
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
                let domain = self
                    .dir_state(child.id)
                    .and_then(|d| d.domain.as_ref())
                    .map(|binding| binding.probe.clone())
                    .unwrap_or_else(ProbeResult::unknown);
                let view = Self::listing_view(builder, &child, self.config.metadata_fields, domain);
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
        let Some(id) = job.entry() else {
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
            let classification =
                Classification { ctx: &parent_ctx, inherit, fields: self.config.metadata_fields, parent_domain: None };
            self.change_kind(&mut builder, &mut effects, &entry, info, &classification);
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
        self.path_folds += u64::try_from(builder.folds()).unwrap_or(u64::MAX);
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
                if excluded {
                    dir.override_load = None;
                }
            }
            self.entries.mark_unloaded(*id);
            self.set_obligation(*id, ObligationState::Removed);
            self.initial_scan.resolve_removed(*id);
            self.commands_entry_unloaded(*id, excluded);
        }
        for id in &effects.kind_changed {
            if removed_ids.contains(id) {
                continue;
            }
            let now_directory = self.snapshot.get_by_id(*id).map(|e| e.is_directory()).unwrap_or(false);
            self.invalidate_directory_work(*id, current_job);
            self.entries.set_directory(*id, now_directory);
            self.set_obligation(*id, ObligationState::Removed);
            self.initial_scan.resolve_removed(*id);
            self.commands_kind_changed(*id, job);
        }
        for id in &effects.loaded {
            let previous_generation = self.dir_state(*id).map(|d| d.load_generation);
            if let Some(dir) = self.dir_state_mut(*id) {
                dir.load_generation = dir.load_generation.next();
            }
            self.entries.mark_loaded(*id);
            if let Some(generation) = previous_generation {
                self.initial_scan.resolve_accepted(*id, generation);
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
            if self.snapshot.contains_id(*id) && !self.entries.contains(*id) {
                let is_dir = self.snapshot.get_by_id(*id).map(|e| e.is_directory()).unwrap_or(false);
                self.entries.insert(*id, if is_dir { EntryState::directory() } else { EntryState::default() });
            }
        }
        for (id, binding) in effects.domains {
            if removed_ids.contains(&id) {
                continue;
            }
            self.entries.set_directory(id, true);
            let domain = binding.id;
            if let Some(dir) = self.dir_state_mut(id) {
                dir.domain = Some(binding);
            }
            self.entries.rebind_watch_domain(id, Some(domain));
        }
        let mut crossing_events: Vec<CrossingEvent> = Vec::new();
        for (id, event) in effects.crossings {
            if removed_ids.contains(&id) {
                continue;
            }
            if let Some(dir) = self.dir_state_mut(id) {
                dir.crossing = event.as_ref().map(|event| event.mode);
            }
            if let Some(event) = event {
                self.record_crossing(event.clone());
                crossing_events.push(event);
            }
        }
        for (id, path, reasons) in effects.new_loading {
            if removed_ids.contains(&id) {
                continue;
            }
            self.entries.set_directory(id, true);
            if let Some(dir) = self.dir_state_mut(id) {
                dir.load_generation = dir.load_generation.next();
                dir.context = None;
            }
            let load_generation = self.dir_state(id).map(|d| d.load_generation).unwrap_or_default();
            if reasons.initial_scan {
                self.initial_scan.record_pending(id, load_generation);
            }
            let mut request_reasons = Reasons::control();
            request_reasons.merge(reasons);
            let resolved = self.dir_state(id).map(|d| d.domain.is_some()).unwrap_or(false) || path.is_root();
            if !resolved {
                self.request_domain(id, path.clone(), request_reasons);
            }
            self.request(id, path, ReadNeed::Listing, request_reasons, Vec::new());
        }
        let mut parents: HashMap<RelativePath, Option<EntryId>> = HashMap::new();
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
                let parent = match parents.get(&parent_path) {
                    Some(known) => *known,
                    None => {
                        let resolved = self.snapshot.get(&parent_path).map(|p| p.id);
                        parents.insert(parent_path, resolved);
                        resolved
                    }
                };
                if let Some(parent) = parent
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
                let owner = match parents.get(&owner_path) {
                    Some(known) => *known,
                    None => {
                        let resolved = self.snapshot.get(&owner_path).map(|p| p.id);
                        parents.insert(owner_path, resolved);
                        resolved
                    }
                };
                if let Some(owner) = owner {
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
            self.publish_delta(previous, changes, crossing_events);
        }
    }

    fn rebind_child_domain(
        &mut self,
        builder: &mut SnapshotBuilder,
        effects: &mut Effects,
        child: EntryId,
        path: &RelativePath,
        domain: Option<&ProbeResult>,
        parent: &ProbeResult,
    ) {
        let Some(probe) = domain else {
            return;
        };
        let unchanged = self
            .dir_state(child)
            .and_then(|d| d.domain.as_ref())
            .map(|binding| binding.probe == *probe)
            .unwrap_or(false);
        if unchanged {
            return;
        }
        effects.removed.extend(builder.set_child_case(child, probe.case()));
        let binding = self.bind_domain(probe);
        let id = binding.id;
        effects.domains.push((child, binding));
        if requires_crossing_decision(Some(parent), probe) {
            let mode = self.crossing_mode(child, path, &probe.capabilities);
            let parent_domain = self.bind_domain(parent).id;
            effects.crossings.push((
                child,
                Some(CrossingEvent { path: path.clone(), parent: Some(parent_domain), child: id, mode }),
            ));
        } else {
            effects.crossings.push((child, None));
        }
    }

    pub(super) fn request_domain(&mut self, entry: EntryId, path: RelativePath, reasons: Reasons) {
        match self.pending_domain.get_mut(&entry) {
            Some(existing) => {
                existing.path = path;
                existing.reasons.merge(reasons);
                existing.due = None;
            }
            None => {
                self.pending_domain.insert(entry, DomainRequest { path, reasons, attempts: 0, due: None });
            }
        }
    }

    pub(super) fn commit_domain(&mut self, job: &ActiveJob, probe: ProbeResult) -> JobOutcome {
        let Some(id) = job.entry() else {
            return JobOutcome::Accepted;
        };
        let Some(entry) = self.snapshot.get_by_id(id).cloned() else {
            return JobOutcome::Stale;
        };
        self.domain_resolutions += 1;
        let parent_probe = self.parent_domain_probe(id);
        let parent_domain = self.parent_of(id).and_then(|parent| self.domain_of(parent));
        let proven = requires_crossing_decision(parent_probe.as_ref(), &probe);
        let binding = self.bind_domain(&probe);
        let child = binding.id;
        let override_load = self.dir_state(id).and_then(|d| d.override_load);
        let mut builder = self.snapshot.builder();
        let mut effects = Effects::default();
        effects.removed.extend(builder.set_child_case(id, probe.case()));
        effects.domains.push((id, binding));
        if proven && entry.is_directory() {
            let mode = if override_load == Some(true) {
                DomainCrossing::Follow
            } else {
                self.crossing_mode(id, &entry.path, &probe.capabilities)
            };
            effects
                .crossings
                .push((id, Some(CrossingEvent { path: entry.path.clone(), parent: parent_domain, child, mode })));
            let target = match mode {
                DomainCrossing::Follow => None,
                DomainCrossing::Exclude => Some(LoadState::Excluded),
                DomainCrossing::LoadOnDemand => Some(LoadState::Unloaded),
            };
            if let Some(target) = target {
                for grandchild in builder.child_ids(id) {
                    effects.removed.extend(builder.remove_subtree(grandchild));
                }
                let _ = builder.update(id, |e| e.shape = Shape::Directory(target));
                effects.unloaded.push(id);
                if target == LoadState::Excluded {
                    effects.excluded.push(id);
                }
            }
        }
        self.commit(builder, effects, Some(job));
        JobOutcome::Accepted
    }

    fn invalidate_directory_work(&mut self, id: EntryId, except: Option<JobId>) {
        if let Some(job_id) = self.active_by_entry.get(&id).copied()
            && Some(job_id) != except
        {
            self.cancel_job(job_id);
        }
        self.pending.remove(&id);
        self.pending_enrichment.remove(&id);
        self.pending_domain.remove(&id);
        self.entries.clear_retry(id);
        self.entries.set_degraded(id, None);
        self.entries.set_metadata_degraded(id, None);
        if let Some(WatchState::Registered(watch)) = self.dir_state(id).map(|dir| dir.watch())
            && self.watcher_of(id).scope == crate::domain::WatcherScope::PerDirectory
        {
            let domain = self.domain_of(id);
            self.emit_unwatch(watch, domain);
            self.watches.retain(|w| *w != watch);
            self.entries.set_watch(id, WatchState::NotRegistered, domain);
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
        self.pending_enrichment.remove(&id);
        self.pending_domain.remove(&id);
        let per_directory = self.watcher_of(id).scope == crate::domain::WatcherScope::PerDirectory;
        let domain = self.domain_of(id);
        let released = match self.entries.remove(id) {
            Some(state) => match (state.dir().map(|dir| dir.watch()), per_directory) {
                (Some(WatchState::Registered(watch)), true) => Some(watch),
                _ => None,
            },
            None => None,
        };
        if let Some(watch) = released {
            self.emit_unwatch(watch, domain);
            self.watches.retain(|w| *w != watch);
        }
        self.set_obligation(id, ObligationState::Removed);
        self.initial_scan.resolve_removed(id);
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
        self.pending_enrichment.clear();
        self.pending_domain.clear();
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
        self.publish_delta(previous, changes, Vec::new());
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
        self.publish_delta(previous, changes, Vec::new());
    }
}
