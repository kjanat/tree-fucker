use std::collections::HashMap;

use super::types::*;
use super::{Command, Coordinator, Output, TerminalOutcome};
use crate::entry::{LoadState, Shape};
use crate::error::Error;
use crate::ids::*;
use crate::path::RelativePath;
use crate::update::{ShutdownState, UpdateEvent};

enum WalkStep {
    Done,
    Continue(EntryId),
    Fail(Error),
}

enum Resolved {
    Read { entry: EntryId, need: ReadNeed },
    Walk { ancestor: EntryId },
    Fail(Error),
}

impl Coordinator {
    pub(super) fn on_command(&mut self, id: CommandId, command: Command) {
        if self.shutdown != ShutdownState::Running {
            self.outputs.push(Output::CommandFinished { id, result: Err(Error::Shutdown) });
            return;
        }
        match command {
            Command::Shutdown => self.do_shutdown(id),
            Command::SetPriority(paths) => {
                if paths.len() > self.config.priority_set_limit {
                    self.outputs.push(Output::CommandFinished { id, result: Err(Error::PathLimit) });
                    return;
                }
                self.priority = PrioritySet { paths: paths.into_iter().collect(), cursor: 0 };
                self.outputs.push(Output::CommandFinished { id, result: Ok(()) });
            }
            Command::InitialScanComplete => {
                if self.commands.len() + self.initial_scan.waiters.len() >= self.config.command_capacity {
                    self.outputs.push(Output::CommandFinished { id, result: Err(Error::Capacity) });
                    return;
                }
                match self.root {
                    RootState::Unavailable { .. } => {
                        self.outputs.push(Output::CommandFinished { id, result: Err(Error::RootUnavailable) });
                    }
                    RootState::Available { .. } => {
                        self.initial_scan.waiters.push(id);
                        self.check_initial_scan();
                    }
                }
            }
            Command::Refresh(paths) => {
                if let Err(err) = self.admission_checks(paths.len()) {
                    self.outputs.push(Output::CommandFinished { id, result: Err(err) });
                    return;
                }
                let barrier = self.next_seq();
                self.accept_refresh(id, barrier, paths);
            }
            Command::Load(path) => {
                if let Err(err) = self.admission_checks(1) {
                    self.outputs.push(Output::CommandFinished { id, result: Err(err) });
                    return;
                }
                let barrier = self.next_seq();
                self.accept_load(id, barrier, path);
            }
            Command::Unload(path) => {
                if let Err(err) = self.admission_checks(1) {
                    self.outputs.push(Output::CommandFinished { id, result: Err(err) });
                    return;
                }
                let _barrier = self.next_seq();
                let result = self.accept_unload(path);
                self.outputs.push(Output::CommandFinished { id, result });
            }
            Command::InvalidatePolicy(roots) => {
                if let Err(err) = self.admission_checks(roots.len()) {
                    self.outputs.push(Output::CommandFinished { id, result: Err(err) });
                    return;
                }
                let barrier = self.next_seq();
                self.accept_invalidate_policy(id, barrier, roots);
            }
        }
    }

    fn admission_checks(&self, paths: usize) -> Result<(), Error> {
        if self.commands.len() + self.initial_scan.waiters.len() >= self.config.command_capacity {
            return Err(Error::Capacity);
        }
        if paths > self.config.paths_per_command {
            return Err(Error::PathLimit);
        }
        Ok(())
    }

    fn resolve_refresh(&self, path: &RelativePath) -> Resolved {
        if let Some(entry) = self.snapshot.get(path) {
            let need = match entry.shape {
                Shape::Directory(LoadState::Loaded | LoadState::Loading) => ReadNeed::Listing,
                _ => ReadNeed::Metadata,
            };
            return Resolved::Read { entry: entry.id, need };
        }
        let mut cursor = path.parent();
        while let Some(candidate) = cursor {
            if let Some(ancestor) = self.snapshot.get(&candidate) {
                return match ancestor.shape {
                    Shape::Directory(LoadState::Loaded | LoadState::Loading) => {
                        Resolved::Walk { ancestor: ancestor.id }
                    }
                    Shape::Directory(LoadState::Unloaded) => Resolved::Fail(Error::NotLoaded),
                    Shape::Directory(LoadState::Excluded) => Resolved::Fail(Error::PolicyDenied),
                    _ => Resolved::Fail(Error::NotDirectory),
                };
            }
            cursor = candidate.parent();
        }
        Resolved::Fail(Error::RootUnavailable)
    }

    fn accept_refresh(&mut self, id: CommandId, barrier: Sequence, paths: Vec<RelativePath>) {
        if let RootState::Unavailable { .. } = self.root {
            if paths.iter().all(|p| p.is_root()) && !paths.is_empty() {
                self.commands.insert(
                    id,
                    PendingCommand {
                        id,
                        barrier,
                        state: CommandState::Refresh { remaining: vec![RefreshTarget::RootRecovery] },
                    },
                );
                self.schedule_probe(false);
                if let Some(probe) = self.root_probe.as_mut() {
                    probe.not_before = None;
                }
            } else {
                self.outputs.push(Output::CommandFinished { id, result: Err(Error::RootUnavailable) });
            }
            return;
        }
        let mut remaining: Vec<RefreshTarget> = Vec::new();
        let mut requests: Vec<(EntryId, RelativePath, ReadNeed)> = Vec::new();
        for path in paths {
            match self.resolve_refresh(&path) {
                Resolved::Read { entry, need } => {
                    if !remaining.iter().any(|t| matches!(t, RefreshTarget::Read { entry: e } if *e == entry)) {
                        remaining.push(RefreshTarget::Read { entry });
                        let target_path = self.snapshot.get_by_id(entry).map(|e| e.path.clone()).unwrap_or(path);
                        requests.push((entry, target_path, need));
                    }
                }
                Resolved::Walk { ancestor } => {
                    remaining.push(RefreshTarget::Walk { ancestor, target: path });
                    let target_path =
                        self.snapshot.get_by_id(ancestor).map(|e| e.path.clone()).unwrap_or_default_root();
                    requests.push((ancestor, target_path, ReadNeed::Listing));
                }
                Resolved::Fail(err) => {
                    self.outputs.push(Output::CommandFinished { id, result: Err(err) });
                    return;
                }
            }
        }
        if remaining.is_empty() {
            self.outputs.push(Output::CommandFinished { id, result: Ok(()) });
            return;
        }
        self.commands.insert(id, PendingCommand { id, barrier, state: CommandState::Refresh { remaining } });
        for (entry, path, need) in requests {
            self.bump_epoch(entry);
            self.request(entry, path, need, Reasons::refresh(), vec![id]);
        }
    }

    fn accept_load(&mut self, id: CommandId, barrier: Sequence, path: RelativePath) {
        if let RootState::Unavailable { .. } = self.root {
            self.outputs.push(Output::CommandFinished { id, result: Err(Error::RootUnavailable) });
            return;
        }
        let Some(entry) = self.snapshot.get(&path).cloned() else {
            self.outputs.push(Output::CommandFinished { id, result: Err(Error::NotFound) });
            return;
        };
        let state = match entry.shape {
            Shape::Directory(state) => state,
            _ => {
                self.outputs.push(Output::CommandFinished { id, result: Err(Error::NotDirectory) });
                return;
            }
        };
        match state {
            LoadState::Excluded => {
                self.outputs.push(Output::CommandFinished { id, result: Err(Error::PolicyDenied) });
                return;
            }
            LoadState::Unloaded => {
                let mut builder = self.snapshot.builder();
                let mut effects = super::apply::Effects::default();
                let _ = builder.update(entry.id, |e| e.shape = Shape::Directory(LoadState::Loading));
                effects.new_loading.push((entry.id, entry.path.clone(), Reasons::default()));
                if let Some(dir) = self.dir_state_mut(entry.id) {
                    dir.override_load = Some(true);
                }
                self.commit(builder, effects, None);
            }
            LoadState::Loading | LoadState::Loaded => {
                if let Some(dir) = self.dir_state_mut(entry.id) {
                    dir.override_load = Some(true);
                }
            }
        }
        self.commands.insert(id, PendingCommand { id, barrier, state: CommandState::Load { entry: entry.id } });
        self.bump_epoch(entry.id);
        self.request(entry.id, entry.path.clone(), ReadNeed::Listing, Reasons::control(), vec![id]);
    }

    fn accept_unload(&mut self, path: RelativePath) -> Result<(), Error> {
        if let RootState::Unavailable { .. } = self.root {
            return Err(Error::RootUnavailable);
        }
        let Some(entry) = self.snapshot.get(&path).cloned() else {
            return Ok(());
        };
        let state = match entry.shape {
            Shape::Directory(state) => state,
            _ => return Err(Error::NotDirectory),
        };
        match state {
            LoadState::Unloaded | LoadState::Excluded => Ok(()),
            LoadState::Loading | LoadState::Loaded => {
                let mut builder = self.snapshot.builder();
                let mut effects = super::apply::Effects::default();
                for child in builder.child_ids(entry.id) {
                    effects.removed.extend(builder.remove_subtree(child));
                }
                let _ = builder.update(entry.id, |e| e.shape = Shape::Directory(LoadState::Unloaded));
                effects.unloaded.push(entry.id);
                if let Some(dir) = self.dir_state_mut(entry.id) {
                    dir.override_load = Some(false);
                }
                self.commit(builder, effects, None);
                Ok(())
            }
        }
    }

    fn accept_invalidate_policy(&mut self, id: CommandId, barrier: Sequence, roots: Vec<RelativePath>) {
        if let RootState::Unavailable { .. } = self.root {
            self.outputs.push(Output::CommandFinished { id, result: Err(Error::RootUnavailable) });
            return;
        }
        self.policy_fence = self.policy_fence.next();
        let mut builder = self.snapshot.builder();
        let mut effects = super::apply::Effects::default();
        let mut targets: Vec<crate::entry::Entry> =
            roots.iter().filter_map(|p| self.snapshot.get(p).cloned()).collect();
        targets.sort_by_key(|a| self.snapshot.key(&a.path));
        targets.dedup_by(|a, b| a.id == b.id);
        let mut covered: Vec<RelativePath> = Vec::new();
        for target in targets {
            if covered.iter().any(|c| target.path.starts_with(c)) {
                continue;
            }
            if builder.get(target.id).is_none() {
                continue;
            }
            self.reevaluate_root_of_policy(&mut builder, &mut effects, &target);
            covered.push(target.path.clone());
        }
        let new_loading: Vec<EntryId> = effects.new_loading.iter().map(|(e, _, _)| *e).collect();
        self.commit(builder, effects, None);
        let mut remaining: HashMap<EntryId, LoadGeneration> = HashMap::new();
        for entry in new_loading {
            if let Some(dir) = self.dir_state(entry) {
                remaining.insert(entry, dir.load_generation);
            }
            if let Some(request) = self.pending.get_mut(&entry) {
                request.barriers.push(id);
            }
        }
        if remaining.is_empty() {
            self.outputs.push(Output::CommandFinished { id, result: Ok(()) });
            return;
        }
        self.commands.insert(id, PendingCommand { id, barrier, state: CommandState::InvalidatePolicy { remaining } });
    }

    fn do_shutdown(&mut self, id: CommandId) {
        self.shutdown = ShutdownState::ShuttingDown;
        let ids: Vec<CommandId> = self.commands.keys().copied().collect();
        for cmd in ids {
            self.finish_command(cmd, Err(Error::Shutdown));
        }
        let waiters = std::mem::take(&mut self.initial_scan.waiters);
        for cmd in waiters {
            self.outputs.push(Output::CommandFinished { id: cmd, result: Err(Error::Shutdown) });
        }
        self.cancel_all_jobs();
        self.unwatch_all();
        self.pending.clear();
        self.root_probe = None;
        self.shutdown = ShutdownState::Stopped;
        let health = self.compute_health();
        self.outputs.push(Output::Publish(Box::new(UpdateEvent::Terminal { health })));
        self.outputs.push(Output::CommandFinished { id, result: Ok(()) });
        self.outputs.push(Output::Stopped(TerminalOutcome::ShutDown));
    }

    pub(super) fn finish_command(&mut self, id: CommandId, result: Result<(), Error>) {
        if self.commands.remove(&id).is_some() {
            self.outputs.push(Output::CommandFinished { id, result });
        }
    }

    pub(super) fn check_initial_scan(&mut self) {
        let RootState::Available { .. } = self.root else {
            return;
        };
        if self.initial_scan.foreground_done && self.initial_scan.waiters.is_empty() {
            return;
        }
        let settled = !self.initial_scan.any_pending() && !self.traversal_in_progress();
        if !settled {
            return;
        }
        self.initial_scan.foreground_done = true;
        let waiters = std::mem::take(&mut self.initial_scan.waiters);
        if waiters.is_empty() {
            return;
        }
        let result = if self.initial_scan.any_unsatisfied() {
            Err(Error::InitialScanDegraded(self.initial_scan.failed_paths()))
        } else {
            Ok(())
        };
        for id in waiters {
            self.outputs.push(Output::CommandFinished { id, result: result.clone() });
        }
    }

    fn walk_step(&self, ancestor: EntryId, target: &RelativePath) -> WalkStep {
        let Some(ancestor_entry) = self.snapshot.get_by_id(ancestor) else {
            return WalkStep::Done;
        };
        let depth = ancestor_entry.path.depth();
        let Some(name) = target.components().get(depth) else {
            return WalkStep::Done;
        };
        let Some(child) = self.snapshot.child_by_name(ancestor, name) else {
            return WalkStep::Done;
        };
        if child.path.depth() >= target.depth() {
            return WalkStep::Done;
        }
        match child.shape {
            Shape::Directory(LoadState::Loaded | LoadState::Loading) => WalkStep::Continue(child.id),
            Shape::Directory(LoadState::Unloaded) => WalkStep::Fail(Error::NotLoaded),
            Shape::Directory(LoadState::Excluded) => WalkStep::Fail(Error::PolicyDenied),
            _ => WalkStep::Fail(Error::NotDirectory),
        }
    }

    pub(super) fn command_satisfied(&mut self, id: CommandId, entry: EntryId, job: &ActiveJob) {
        let Some(mut command) = self.commands.remove(&id) else {
            return;
        };
        let is_root = self.snapshot.get_by_id(entry).map(|e| e.path.is_root()).unwrap_or(false);
        let mut result: Option<Result<(), Error>> = None;
        let mut follow_ups: Vec<EntryId> = Vec::new();
        match &mut command.state {
            CommandState::Refresh { remaining } => {
                let mut kept: Vec<RefreshTarget> = Vec::new();
                for target in remaining.drain(..) {
                    match target {
                        RefreshTarget::Read { entry: e } if e == entry => {}
                        RefreshTarget::RootRecovery if is_root => {}
                        RefreshTarget::Walk { ancestor, target } if ancestor == entry => {
                            match self.walk_step(ancestor, &target) {
                                WalkStep::Done => {}
                                WalkStep::Continue(child) => {
                                    follow_ups.push(child);
                                    kept.push(RefreshTarget::Walk { ancestor: child, target });
                                }
                                WalkStep::Fail(err) => {
                                    result = Some(Err(err));
                                }
                            }
                        }
                        other => kept.push(other),
                    }
                }
                *remaining = kept;
                if result.is_none() && remaining.is_empty() {
                    result = Some(Ok(()));
                }
            }
            CommandState::Load { entry: e } => {
                if *e == entry && self.snapshot.get_by_id(entry).map(|x| x.is_loaded()).unwrap_or(false) {
                    result = Some(Ok(()));
                }
            }
            CommandState::InvalidatePolicy { remaining } => {
                if remaining.get(&entry).copied() == job.target.load_generation() {
                    remaining.remove(&entry);
                }
                if remaining.is_empty() {
                    result = Some(Ok(()));
                }
            }
        }
        match result {
            Some(result) => self.outputs.push(Output::CommandFinished { id, result }),
            None => {
                self.commands.insert(id, command);
                for child in follow_ups {
                    if let Some(path) = self.snapshot.get_by_id(child).map(|e| e.path.clone()) {
                        self.bump_epoch(child);
                        self.request(child, path, ReadNeed::Listing, Reasons::refresh(), vec![id]);
                    }
                }
            }
        }
    }

    pub(super) fn commands_entry_removed(&mut self, entry: EntryId, path: &RelativePath, job: Option<&ActiveJob>) {
        let ids: Vec<CommandId> = self.commands.keys().copied().collect();
        for id in ids {
            let Some(mut command) = self.commands.remove(&id) else {
                continue;
            };
            let post_barrier = job.map(|j| j.dispatch > command.barrier).unwrap_or(false);
            let mut result: Option<Result<(), Error>> = None;
            let mut requests: Vec<(EntryId, ReadNeed, Option<RefreshTarget>)> = Vec::new();
            match &mut command.state {
                CommandState::Refresh { remaining } => {
                    let mut kept = Vec::new();
                    for target in remaining.drain(..) {
                        let affected = match &target {
                            RefreshTarget::Read { entry: e } => *e == entry,
                            RefreshTarget::Walk { ancestor, .. } => *ancestor == entry,
                            RefreshTarget::RootRecovery => false,
                        };
                        if !affected {
                            kept.push(target);
                            continue;
                        }
                        if post_barrier {
                            continue;
                        }
                        let original = match &target {
                            RefreshTarget::Walk { target, .. } => target.clone(),
                            _ => path.clone(),
                        };
                        match self.resolve_refresh(&original) {
                            Resolved::Read { entry: e, need } => {
                                requests.push((e, need, None));
                                kept.push(RefreshTarget::Read { entry: e });
                            }
                            Resolved::Walk { ancestor } => {
                                requests.push((ancestor, ReadNeed::Listing, None));
                                kept.push(RefreshTarget::Walk { ancestor, target: original });
                            }
                            Resolved::Fail(err) => result = Some(Err(err)),
                        }
                    }
                    *remaining = kept;
                    if result.is_none() && remaining.is_empty() {
                        result = Some(Ok(()));
                    }
                }
                CommandState::Load { entry: e } => {
                    if *e == entry {
                        result = Some(Err(Error::NotFound));
                    }
                }
                CommandState::InvalidatePolicy { remaining } => {
                    remaining.remove(&entry);
                    if remaining.is_empty() {
                        result = Some(Ok(()));
                    }
                }
            }
            match result {
                Some(result) => self.outputs.push(Output::CommandFinished { id, result }),
                None => {
                    self.commands.insert(id, command);
                    for (target, need, _) in requests {
                        if let Some(target_path) = self.snapshot.get_by_id(target).map(|e| e.path.clone()) {
                            self.bump_epoch(target);
                            self.request(target, target_path, need, Reasons::refresh(), vec![id]);
                        }
                    }
                }
            }
        }
    }

    pub(super) fn commands_entry_unloaded(&mut self, entry: EntryId, excluded: bool) {
        let ids: Vec<CommandId> = self.commands.keys().copied().collect();
        for id in ids {
            let Some(mut command) = self.commands.remove(&id) else {
                continue;
            };
            let mut result: Option<Result<(), Error>> = None;
            let mut rerequest = false;
            match &mut command.state {
                CommandState::Load { entry: e } => {
                    if *e == entry {
                        result = Some(Err(if excluded { Error::PolicyDenied } else { Error::NotLoaded }));
                    }
                }
                CommandState::Refresh { remaining } => {
                    for target in remaining.iter_mut() {
                        match target {
                            RefreshTarget::Read { entry: e } if *e == entry => rerequest = true,
                            RefreshTarget::Walk { ancestor, .. } if *ancestor == entry => {
                                result = Some(Err(if excluded { Error::PolicyDenied } else { Error::NotLoaded }));
                            }
                            _ => {}
                        }
                    }
                }
                CommandState::InvalidatePolicy { remaining } => {
                    remaining.remove(&entry);
                    if remaining.is_empty() {
                        result = Some(Ok(()));
                    }
                }
            }
            match result {
                Some(result) => self.outputs.push(Output::CommandFinished { id, result }),
                None => {
                    self.commands.insert(id, command);
                    if rerequest && let Some(target_path) = self.snapshot.get_by_id(entry).map(|e| e.path.clone()) {
                        self.bump_epoch(entry);
                        self.request(entry, target_path, ReadNeed::Metadata, Reasons::refresh(), vec![id]);
                    }
                }
            }
        }
    }

    pub(super) fn commands_kind_changed(&mut self, entry: EntryId, job: Option<&ActiveJob>) {
        let ids: Vec<CommandId> = self.commands.keys().copied().collect();
        for id in ids {
            let Some(mut command) = self.commands.remove(&id) else {
                continue;
            };
            let post_barrier = job.map(|j| j.dispatch > command.barrier).unwrap_or(false);
            let mut result: Option<Result<(), Error>> = None;
            let mut rerequest = false;
            match &mut command.state {
                CommandState::Load { entry: e } => {
                    if *e == entry {
                        result = Some(Err(Error::NotDirectory));
                    }
                }
                CommandState::Refresh { remaining } => {
                    let mut kept = Vec::new();
                    for target in remaining.drain(..) {
                        match &target {
                            RefreshTarget::Read { entry: e } if *e == entry => {
                                if post_barrier {
                                    continue;
                                }
                                rerequest = true;
                                kept.push(target);
                            }
                            RefreshTarget::Walk { ancestor, .. } if *ancestor == entry => {
                                result = Some(Err(Error::NotDirectory));
                            }
                            _ => kept.push(target),
                        }
                    }
                    *remaining = kept;
                    if result.is_none() && remaining.is_empty() {
                        result = Some(Ok(()));
                    }
                }
                CommandState::InvalidatePolicy { remaining } => {
                    remaining.remove(&entry);
                    if remaining.is_empty() {
                        result = Some(Ok(()));
                    }
                }
            }
            match result {
                Some(result) => self.outputs.push(Output::CommandFinished { id, result }),
                None => {
                    self.commands.insert(id, command);
                    if rerequest && let Some(current) = self.snapshot.get_by_id(entry).cloned() {
                        let need = match current.shape {
                            Shape::Directory(LoadState::Loaded | LoadState::Loading) => ReadNeed::Listing,
                            _ => ReadNeed::Metadata,
                        };
                        self.bump_epoch(entry);
                        self.request(entry, current.path, need, Reasons::refresh(), vec![id]);
                    }
                }
            }
        }
    }
}

trait OrRoot {
    fn unwrap_or_default_root(self) -> RelativePath;
}

impl OrRoot for Option<RelativePath> {
    fn unwrap_or_default_root(self) -> RelativePath {
        self.unwrap_or_else(RelativePath::root)
    }
}
