use std::cmp::Reverse;
use std::ffi::OsStr;
use std::fmt;
use std::ops::Bound;
use std::sync::Arc;

use imbl::OrdMap;

use crate::entry::{Entry, Shape};
use crate::ids::{EntryGeneration, EntryId, IdHashing, IdMap, SharedIdMap, SnapshotVersion};
use crate::path::{CaseSensitivity, PathKey, RelativePath};
use crate::update::PathChange;

#[derive(Clone)]
pub struct Snapshot {
    inner: Arc<Inner>,
}

struct Inner {
    version: SnapshotVersion,
    case: CaseSensitivity,
    bytes: u64,
    child_case: SharedIdMap<EntryId, CaseSensitivity>,
    by_path: OrdMap<PathKey, Arc<Entry>>,
    by_id: SharedIdMap<EntryId, PathKey>,
    children: SharedIdMap<EntryId, OrdMap<PathKey, EntryId>>,
}

fn survivor(candidate: &Arc<Entry>, kept: &Arc<Entry>) -> EntryId {
    let empty = OsStr::new("");
    let candidate_key = crate::entry::collision_key(
        candidate.path.file_name().unwrap_or(empty),
        candidate.kind(),
        &candidate.metadata,
        candidate.identity,
    );
    let kept_key =
        crate::entry::collision_key(kept.path.file_name().unwrap_or(empty), kept.kind(), &kept.metadata, kept.identity);
    if candidate_key < kept_key { candidate.id } else { kept.id }
}

fn fold(
    path: &RelativePath,
    default: CaseSensitivity,
    by_path: &OrdMap<PathKey, Arc<Entry>>,
    child_case: &SharedIdMap<EntryId, CaseSensitivity>,
) -> (PathKey, CaseSensitivity) {
    if child_case.is_empty() {
        return (path.key(default), default);
    }
    let mut key = PathKey::root();
    let mut case = default;
    let declared = |key: &PathKey| by_path.get(key).and_then(|entry| child_case.get(&entry.id)).copied();
    if let Some(root) = declared(&key) {
        case = root;
    }
    for name in path.components() {
        key = key.descend(name, case);
        if let Some(next) = declared(&key) {
            case = next;
        }
    }
    (key, case)
}

impl Snapshot {
    pub fn empty(version: SnapshotVersion, case: CaseSensitivity) -> Snapshot {
        Snapshot {
            inner: Arc::new(Inner {
                version,
                case,
                bytes: 0,
                child_case: SharedIdMap::with_hasher(IdHashing),
                by_path: OrdMap::new(),
                by_id: SharedIdMap::with_hasher(IdHashing),
                children: SharedIdMap::with_hasher(IdHashing),
            }),
        }
    }

    pub fn version(&self) -> SnapshotVersion {
        self.inner.version
    }

    pub fn len(&self) -> usize {
        self.inner.by_path.len()
    }

    pub fn bytes(&self) -> u64 {
        self.inner.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.inner.by_path.is_empty()
    }

    pub fn key(&self, path: &RelativePath) -> PathKey {
        self.fold(path).0
    }

    pub fn child_case(&self, path: &RelativePath) -> CaseSensitivity {
        self.fold(path).1
    }

    fn fold(&self, path: &RelativePath) -> (PathKey, CaseSensitivity) {
        fold(path, self.inner.case, &self.inner.by_path, &self.inner.child_case)
    }

    pub fn root(&self) -> Option<&Entry> {
        self.get(&RelativePath::root())
    }

    pub fn get(&self, path: &RelativePath) -> Option<&Entry> {
        self.get_key(&self.key(path))
    }

    pub fn get_key(&self, key: &PathKey) -> Option<&Entry> {
        self.inner.by_path.get(key).map(|e| e.as_ref())
    }

    pub fn parent_id(&self, id: EntryId) -> Option<EntryId> {
        let key = self.inner.by_id.get(&id)?;
        let parent = key.parent()?;
        self.inner.by_path.get(&parent).map(|entry| entry.id)
    }

    pub fn get_by_id(&self, id: EntryId) -> Option<&Entry> {
        let key = self.inner.by_id.get(&id)?;
        self.get_key(key)
    }

    pub fn contains_id(&self, id: EntryId) -> bool {
        self.inner.by_id.contains_key(&id)
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> + '_ {
        self.inner.by_path.values().map(|e| e.as_ref())
    }

    pub fn children(&self, id: EntryId) -> impl Iterator<Item = &Entry> + '_ {
        self.inner.children.get(&id).into_iter().flat_map(|c| c.values()).filter_map(|child| self.get_by_id(*child))
    }

    pub fn child_ids(&self, id: EntryId) -> Vec<EntryId> {
        self.inner.children.get(&id).map(|c| c.values().copied().collect()).unwrap_or_default()
    }

    pub fn child_by_name(&self, id: EntryId, name: &OsStr) -> Option<&Entry> {
        let parent = self.get_by_id(id)?;
        let (parent_key, case) = self.fold(&parent.path);
        let key = parent_key.child(name, case).ok()?;
        let child_id = self.inner.children.get(&id)?.get(&key)?;
        self.get_by_id(*child_id)
    }

    pub fn child_count(&self, id: EntryId) -> usize {
        self.inner.children.get(&id).map(|c| c.len()).unwrap_or(0)
    }

    pub fn descendants(&self, id: EntryId) -> impl Iterator<Item = &Entry> + '_ {
        let prefix = self.inner.by_id.get(&id).cloned();
        let start = prefix.clone();
        self.inner
            .by_path
            .range((start.map(Bound::Excluded).unwrap_or(Bound::Unbounded), Bound::Unbounded))
            .take_while(move |(key, _)| match &prefix {
                Some(prefix) => key.starts_with(prefix),
                None => false,
            })
            .map(|(_, entry)| entry.as_ref())
    }

    pub fn loaded_directories(&self) -> impl Iterator<Item = &Entry> + '_ {
        self.entries().filter(|e| e.is_loaded())
    }

    pub fn builder(&self) -> SnapshotBuilder {
        SnapshotBuilder {
            bytes: self.inner.bytes,
            case: self.inner.case,
            folds: 0,
            child_case: self.inner.child_case.clone(),
            by_path: self.inner.by_path.clone(),
            by_id: self.inner.by_id.clone(),
            children: self.inner.children.clone(),
            before: IdMap::default(),
        }
    }
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot").field("version", &self.inner.version).field("entries", &self.len()).finish()
    }
}

pub struct SnapshotBuilder {
    case: CaseSensitivity,
    bytes: u64,
    folds: usize,
    child_case: SharedIdMap<EntryId, CaseSensitivity>,
    by_path: OrdMap<PathKey, Arc<Entry>>,
    by_id: SharedIdMap<EntryId, PathKey>,
    children: SharedIdMap<EntryId, OrdMap<PathKey, EntryId>>,
    before: IdMap<EntryId, Option<Arc<Entry>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    MissingParent(RelativePath),
    DuplicatePath(RelativePath),
    DuplicateId(EntryId),
    UnknownEntry(EntryId),
}

impl SnapshotBuilder {
    fn put(&mut self, key: PathKey, entry: Arc<Entry>) {
        self.bytes = self.bytes.saturating_add(crate::entry::entry_bytes(&entry));
        if let Some(previous) = self.by_path.insert(key, entry) {
            self.bytes = self.bytes.saturating_sub(crate::entry::entry_bytes(&previous));
        }
    }

    fn take(&mut self, key: &PathKey) -> Option<Arc<Entry>> {
        let removed = self.by_path.remove(key)?;
        self.bytes = self.bytes.saturating_sub(crate::entry::entry_bytes(&removed));
        Some(removed)
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    fn fold(&mut self, path: &RelativePath) -> (PathKey, CaseSensitivity) {
        self.folds += 1;
        fold(path, self.case, &self.by_path, &self.child_case)
    }

    pub fn folds(&self) -> usize {
        self.folds
    }

    pub fn key(&mut self, path: &RelativePath) -> PathKey {
        self.fold(path).0
    }

    pub fn directory_key(&mut self, id: EntryId) -> Option<(PathKey, CaseSensitivity)> {
        let path = self.get(id)?.path.clone();
        Some(self.fold(&path))
    }

    pub fn child_case(&mut self, id: EntryId) -> CaseSensitivity {
        match self.get(id).map(|entry| entry.path.clone()) {
            Some(path) => self.fold(&path).1,
            None => self.case,
        }
    }

    pub fn set_child_case(&mut self, id: EntryId, case: Option<CaseSensitivity>) -> Vec<Arc<Entry>> {
        if self.child_case.get(&id).copied() == case {
            return Vec::new();
        }
        let Some(path) = self.get(id).map(|entry| entry.path.clone()) else {
            return Vec::new();
        };
        let before = self.fold(&path).1;
        match case {
            Some(case) => self.child_case.insert(id, case),
            None => self.child_case.remove(&id),
        };
        if self.fold(&path).1 == before {
            return Vec::new();
        }
        self.rekey_subtree(id)
    }

    fn rekey_subtree(&mut self, root: EntryId) -> Vec<Arc<Entry>> {
        let mut order: Vec<EntryId> = Vec::new();
        let mut stack = vec![root];
        while let Some(current) = stack.pop() {
            let kids = self.child_ids(current);
            self.children.remove(&current);
            order.extend(kids.iter().copied());
            stack.extend(kids);
        }
        for id in &order {
            self.remember(*id);
        }
        let mut moved: Vec<Arc<Entry>> = Vec::new();
        for id in &order {
            if let Some(key) = self.by_id.remove(id)
                && let Some(entry) = self.take(&key)
            {
                moved.push(entry);
            }
        }
        let mut collided: Vec<RelativePath> = Vec::new();
        let mut dropped: Vec<Arc<Entry>> = Vec::new();
        for entry in moved {
            if collided.iter().any(|prefix| entry.path.starts_with(prefix)) {
                self.child_case.remove(&entry.id);
                dropped.push(entry);
                continue;
            }
            let key = self.fold(&entry.path).0;
            if let Some(incumbent) = self.by_path.get(&key).cloned() {
                if survivor(&entry, &incumbent) != entry.id {
                    collided.push(entry.path.clone());
                    self.child_case.remove(&entry.id);
                    dropped.push(entry);
                    continue;
                }
                self.evict(&key, &incumbent);
                collided.push(incumbent.path.clone());
                dropped.push(incumbent);
            }
            self.by_id.insert(entry.id, key.clone());
            self.put(key.clone(), entry.clone());
            if let Some(parent_key) = key.parent()
                && let Some(parent) = self.by_path.get(&parent_key).map(|p| p.id)
            {
                self.children.entry(parent).or_default().insert(key, entry.id);
            }
        }
        dropped
    }

    fn evict(&mut self, key: &PathKey, entry: &Arc<Entry>) {
        self.by_id.remove(&entry.id);
        self.take(key);
        self.children.remove(&entry.id);
        self.child_case.remove(&entry.id);
        if let Some(parent_key) = key.parent()
            && let Some(parent) = self.by_path.get(&parent_key).map(|p| p.id)
            && let Some(siblings) = self.children.get_mut(&parent)
        {
            siblings.remove(key);
        }
    }

    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }

    pub fn get(&self, id: EntryId) -> Option<&Entry> {
        let key = self.by_id.get(&id)?;
        self.by_path.get(key).map(|e| e.as_ref())
    }

    pub fn child_ids(&self, id: EntryId) -> Vec<EntryId> {
        self.children.get(&id).map(|c| c.values().copied().collect()).unwrap_or_default()
    }

    pub fn children(&self, id: EntryId) -> Vec<Arc<Entry>> {
        self.child_ids(id)
            .into_iter()
            .filter_map(|c| self.by_id.get(&c).and_then(|k| self.by_path.get(k)).cloned())
            .collect()
    }

    fn remember(&mut self, id: EntryId) {
        if !self.before.contains_key(&id) {
            let current = self.by_id.get(&id).and_then(|k| self.by_path.get(k)).cloned();
            self.before.insert(id, current);
        }
    }

    pub fn insert(&mut self, entry: Entry) -> Result<(), BuildError> {
        let key = self.key(&entry.path);
        self.insert_at(key, entry)
    }

    pub fn insert_at(&mut self, key: PathKey, entry: Entry) -> Result<(), BuildError> {
        if self.by_path.contains_key(&key) {
            return Err(BuildError::DuplicatePath(entry.path.clone()));
        }
        if self.by_id.contains_key(&entry.id) {
            return Err(BuildError::DuplicateId(entry.id));
        }
        let parent_id = match key.parent() {
            Some(parent_key) => match self.by_path.get(&parent_key) {
                Some(parent) => Some(parent.id),
                None => return Err(BuildError::MissingParent(entry.path.clone())),
            },
            None => None,
        };
        self.remember(entry.id);
        let id = entry.id;
        self.by_id.insert(id, key.clone());
        self.put(key.clone(), Arc::new(entry));
        if let Some(parent_id) = parent_id {
            self.children.entry(parent_id).or_default().insert(key, id);
        }
        Ok(())
    }

    pub fn update(&mut self, id: EntryId, change: impl FnOnce(&mut Entry)) -> Result<(), BuildError> {
        let key = self.by_id.get(&id).cloned().ok_or(BuildError::UnknownEntry(id))?;
        self.remember(id);
        let mut entry = self.by_path.get(&key).map(|e| e.as_ref().clone()).ok_or(BuildError::UnknownEntry(id))?;
        change(&mut entry);
        entry.path = self.by_path.get(&key).map(|e| e.path.clone()).unwrap_or(entry.path);
        entry.id = id;
        self.put(key, Arc::new(entry));
        Ok(())
    }

    pub fn remove_subtree(&mut self, id: EntryId) -> Vec<Arc<Entry>> {
        let mut removed = Vec::new();
        let mut stack = vec![id];
        while let Some(current) = stack.pop() {
            if let Some(children) = self.children.remove(&current) {
                stack.extend(children.values().copied());
            }
            self.remember(current);
            self.child_case.remove(&current);
            if let Some(key) = self.by_id.remove(&current)
                && let Some(entry) = self.take(&key)
            {
                if let Some(parent_key) = key.parent()
                    && let Some(parent) = self.by_path.get(&parent_key).map(|p| p.id)
                    && let Some(siblings) = self.children.get_mut(&parent)
                {
                    siblings.remove(&key);
                }
                removed.push(entry);
            }
        }
        removed
    }

    pub fn rename_subtree(&mut self, id: EntryId, new_path: RelativePath) -> Result<Vec<EntryId>, BuildError> {
        let old_key = self.by_id.get(&id).cloned().ok_or(BuildError::UnknownEntry(id))?;
        let new_key = self.key(&new_path);
        if new_key != old_key && self.by_path.contains_key(&new_key) {
            return Err(BuildError::DuplicatePath(new_path));
        }
        let new_parent = match new_key.parent() {
            Some(parent_key) => {
                Some(self.by_path.get(&parent_key).map(|p| p.id).ok_or(BuildError::MissingParent(new_path.clone()))?)
            }
            None => None,
        };
        let old_path = self.by_path.get(&old_key).map(|e| e.path.clone()).ok_or(BuildError::UnknownEntry(id))?;
        let mut moved = Vec::new();
        let mut stack = vec![id];
        let mut collected: Vec<Arc<Entry>> = Vec::new();
        while let Some(current) = stack.pop() {
            if let Some(children) = self.children.get(&current) {
                stack.extend(children.values().copied());
            }
            if let Some(entry) = self.by_id.get(&current).and_then(|k| self.by_path.get(k)).cloned() {
                collected.push(entry);
            }
        }
        if let Some(parent_key) = old_key.parent()
            && let Some(parent) = self.by_path.get(&parent_key).map(|p| p.id)
            && let Some(siblings) = self.children.get_mut(&parent)
        {
            siblings.remove(&old_key);
        }
        for entry in &collected {
            self.remember(entry.id);
            if let Some(key) = self.by_id.remove(&entry.id) {
                self.take(&key);
            }
        }
        for entry in collected {
            let rebased = entry.path.rebase(&old_path, &new_path).ok_or(BuildError::UnknownEntry(entry.id))?;
            let key = self.key(&rebased);
            let mut updated = entry.as_ref().clone();
            updated.path = rebased;
            updated.generation = updated.generation.next();
            self.by_id.insert(updated.id, key.clone());
            self.put(key.clone(), Arc::new(updated));
            moved.push(entry.id);
            if let Some(parent_key) = key.parent()
                && let Some(parent) = self.by_path.get(&parent_key).map(|p| p.id)
            {
                self.children.entry(parent).or_default().insert(key, entry.id);
            }
        }
        if let Some(parent) = new_parent {
            self.children.entry(parent).or_default().insert(new_key, id);
        }
        Ok(moved)
    }

    pub fn touched(&self) -> impl Iterator<Item = EntryId> + '_ {
        self.before.keys().copied()
    }

    pub fn finish(self, version: SnapshotVersion) -> (Snapshot, Vec<PathChange>) {
        let sort_key = |path: &RelativePath| fold(path, self.case, &self.by_path, &self.child_case).0;
        let mut changes: Vec<(SortKey, PathChange)> = Vec::new();
        for (id, before) in &self.before {
            let after = self.by_id.get(id).and_then(|k| self.by_path.get(k)).cloned();
            match (before, after) {
                (None, None) => {}
                (None, Some(after)) => {
                    let key = sort_key(&after.path);
                    changes.push((
                        SortKey::added(key, *id),
                        PathChange::Added { id: *id, path: after.path.clone(), kind: after.kind() },
                    ));
                }
                (Some(before), None) => {
                    let key = sort_key(&before.path);
                    changes.push((
                        SortKey::removed(key, *id),
                        PathChange::Removed { id: *id, path: before.path.clone(), kind: before.kind() },
                    ));
                }
                (Some(before), Some(after)) => {
                    let new_key = sort_key(&after.path);
                    if before.path != after.path {
                        changes.push((
                            SortKey::renamed(sort_key(&before.path), new_key.clone(), *id),
                            PathChange::Renamed {
                                id: *id,
                                old_path: before.path.clone(),
                                new_path: after.path.clone(),
                            },
                        ));
                    }
                    if before.kind() != after.kind() {
                        changes.push((
                            SortKey::flat(2, new_key.clone(), *id),
                            PathChange::KindChanged {
                                id: *id,
                                path: after.path.clone(),
                                old: before.kind(),
                                new: after.kind(),
                            },
                        ));
                    } else if let (Shape::Directory(old), Shape::Directory(new)) = (before.shape, after.shape)
                        && old != new
                    {
                        changes.push((
                            SortKey::flat(3, new_key.clone(), *id),
                            PathChange::LoadStateChanged { id: *id, path: after.path.clone(), old, new },
                        ));
                    }
                    if before.metadata != after.metadata {
                        changes.push((
                            SortKey::flat(5, new_key, *id),
                            PathChange::MetadataChanged {
                                id: *id,
                                path: after.path.clone(),
                                old: before.metadata,
                                new: after.metadata,
                            },
                        ));
                    }
                }
            }
        }
        changes.sort_by(|a, b| a.0.cmp(&b.0));
        let snapshot = Snapshot {
            inner: Arc::new(Inner {
                version,
                case: self.case,
                bytes: self.bytes,
                child_case: self.child_case,
                by_path: self.by_path,
                by_id: self.by_id,
                children: self.children,
            }),
        };
        (snapshot, changes.into_iter().map(|(_, c)| c).collect())
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct SortKey {
    phase: u8,
    depth: Reverse<usize>,
    shallow: usize,
    first: PathKey,
    second: Option<PathKey>,
    id: EntryId,
}

impl SortKey {
    fn removed(key: PathKey, id: EntryId) -> SortKey {
        SortKey { phase: 0, depth: Reverse(key.depth()), shallow: 0, first: key, second: None, id }
    }

    fn renamed(old: PathKey, new: PathKey, id: EntryId) -> SortKey {
        SortKey { phase: 1, depth: Reverse(0), shallow: 0, first: old, second: Some(new), id }
    }

    fn flat(phase: u8, key: PathKey, id: EntryId) -> SortKey {
        SortKey { phase, depth: Reverse(0), shallow: 0, first: key, second: None, id }
    }

    fn added(key: PathKey, id: EntryId) -> SortKey {
        SortKey { phase: 4, depth: Reverse(0), shallow: key.depth(), first: key, second: None, id }
    }
}

pub fn new_entry(id: EntryId, path: RelativePath, shape: Shape) -> Entry {
    Entry { id, path, shape, metadata: Default::default(), identity: None, generation: EntryGeneration::new(0) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{EntryKind, LoadState};

    fn path(p: &str) -> RelativePath {
        RelativePath::parse(p).expect("valid path")
    }

    #[test]
    fn builds_and_diffs_in_canonical_order() {
        let base = Snapshot::empty(SnapshotVersion::new(0), CaseSensitivity::Sensitive);
        let mut b = base.builder();
        b.insert(new_entry(EntryId::new(1), path(""), Shape::Directory(LoadState::Loaded))).expect("root");
        b.insert(new_entry(EntryId::new(2), path("a"), Shape::Directory(LoadState::Loaded))).expect("a");
        b.insert(new_entry(EntryId::new(3), path("a/b"), Shape::File)).expect("a/b");
        b.insert(new_entry(EntryId::new(4), path("c"), Shape::File)).expect("c");
        let (s1, changes) = b.finish(SnapshotVersion::new(1));
        let kinds: Vec<(u8, String)> = changes.iter().map(|c| (c.phase(), c.path().to_string())).collect();
        assert_eq!(kinds, [(4, ".".into()), (4, "a".into()), (4, "c".into()), (4, "a/b".into())]);
        assert_eq!(s1.len(), 4);
        assert_eq!(s1.child_count(EntryId::new(1)), 2);

        let mut b = s1.builder();
        let removed = b.remove_subtree(EntryId::new(2));
        assert_eq!(removed.len(), 2);
        b.update(EntryId::new(4), |e| e.metadata.size = Some(3)).expect("update");
        b.insert(new_entry(EntryId::new(5), path("d"), Shape::Directory(LoadState::Unloaded))).expect("d");
        let (s2, changes) = b.finish(SnapshotVersion::new(2));
        let rendered: Vec<(u8, String)> = changes.iter().map(|c| (c.phase(), c.path().to_string())).collect();
        assert_eq!(rendered, [(0, "a/b".into()), (0, "a".into()), (4, "d".into()), (5, "c".into())]);
        assert_eq!(s2.len(), 3);
        assert_eq!(s1.len(), 4);
        assert!(matches!(changes[3], PathChange::MetadataChanged { .. }));
        assert_eq!(s2.get(&path("d")).map(|e| e.kind()), Some(EntryKind::Directory));
    }

    #[test]
    fn rename_onto_an_occupied_path_is_rejected_without_moving_anything() {
        let base = Snapshot::empty(SnapshotVersion::new(0), CaseSensitivity::Sensitive);
        let mut b = base.builder();
        b.insert(new_entry(EntryId::new(1), path(""), Shape::Directory(LoadState::Loaded))).expect("root");
        b.insert(new_entry(EntryId::new(2), path("a"), Shape::Directory(LoadState::Loaded))).expect("a");
        b.insert(new_entry(EntryId::new(3), path("a/b"), Shape::File)).expect("a/b");
        b.insert(new_entry(EntryId::new(4), path("z"), Shape::File)).expect("z");
        let (s1, _) = b.finish(SnapshotVersion::new(1));
        let mut b = s1.builder();
        assert_eq!(b.rename_subtree(EntryId::new(2), path("z")), Err(BuildError::DuplicatePath(path("z"))));
        assert_eq!(b.get(EntryId::new(2)).map(|e| e.path.clone()), Some(path("a")));
        assert_eq!(b.get(EntryId::new(3)).map(|e| e.path.clone()), Some(path("a/b")));
        assert_eq!(b.rename_subtree(EntryId::new(9), path("y")), Err(BuildError::UnknownEntry(EntryId::new(9))));
    }

    #[test]
    fn rename_rebases_descendants() {
        let base = Snapshot::empty(SnapshotVersion::new(0), CaseSensitivity::Sensitive);
        let mut b = base.builder();
        b.insert(new_entry(EntryId::new(1), path(""), Shape::Directory(LoadState::Loaded))).expect("root");
        b.insert(new_entry(EntryId::new(2), path("a"), Shape::Directory(LoadState::Loaded))).expect("a");
        b.insert(new_entry(EntryId::new(3), path("a/b"), Shape::File)).expect("a/b");
        let (s1, _) = b.finish(SnapshotVersion::new(1));
        let mut b = s1.builder();
        b.rename_subtree(EntryId::new(2), path("z")).expect("rename");
        let (s2, changes) = b.finish(SnapshotVersion::new(2));
        assert!(s2.get(&path("z/b")).is_some());
        assert!(s2.get(&path("a")).is_none());
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().all(|c| matches!(c, PathChange::Renamed { .. })));
        assert_eq!(s2.child_count(EntryId::new(1)), 1);
        let descendants: Vec<String> = s2.descendants(EntryId::new(1)).map(|e| e.path.to_string()).collect();
        assert_eq!(descendants, ["z", "z/b"]);
    }
}
