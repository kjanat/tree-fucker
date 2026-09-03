use super::governor::GrantId;
use super::types::*;
use super::{Coordinator, JobOperation, JobResult, Output, WorkerLoss};
use crate::config::WatchRegistrationFailure;
use crate::entry::{EntryKind, LoadState, Shape};
use crate::error::Error;
use crate::fs::FsError;
use crate::ids::*;
use crate::update::{ErrorCause, Operation, WatcherHealth};

impl Coordinator {
    pub(super) fn on_job_completed(&mut self, id: JobId, result: JobResult) {
        let Some(job) = self.jobs.get(&id).cloned() else {
            return;
        };
        let Some(started) = job.phase.started() else {
            return;
        };
        let Some(entry) = job.entry() else {
            self.on_probe_result(job, result);
            return;
        };
        let fatal = match &result {
            JobResult::Listing(Err(FsError::Fatal(m))) | JobResult::Metadata(Err(FsError::Fatal(m))) => Some(m.clone()),
            _ => None,
        };
        if let Some(message) = fatal {
            self.finish_job(id, JobOutcome::Cancelled);
            self.terminate(FsError::Fatal(message));
            return;
        }
        if !self.guards_valid(&job) {
            self.stale_results += 1;
            self.finish_job(id, JobOutcome::Stale);
            return;
        }
        if job.need == ReadNeed::Listing {
            self.last_listing_duration = Some(self.now.since(started));
        }
        let is_root = self.snapshot.get_by_id(entry).map(|e| e.path.is_root()).unwrap_or(false);
        match (job.need, job.phase, result) {
            (ReadNeed::Listing, JobPhase::Running(_), JobResult::Listing(Ok(listing))) => {
                self.listings += 1;
                self.last_listing_children = Some(listing.entries.len());
                match self.commit_listing(&job, listing) {
                    Ok(()) => self.finish_job(id, JobOutcome::Accepted),
                    Err(rejection) => {
                        self.listing_failures += 1;
                        let outcome = match rejection {
                            ListingRejection::LimitExceeded => JobOutcome::LimitExceeded,
                            ListingRejection::MalformedNames => {
                                JobOutcome::Failed(FsError::Transient("listing has an unusable child name".into()))
                            }
                        };
                        self.finish_job(id, outcome)
                    }
                }
            }
            (ReadNeed::Listing, JobPhase::Running(_), JobResult::Listing(Err(FsError::NotFound))) => {
                self.listing_failures += 1;
                self.on_not_found(&job);
            }
            (ReadNeed::Listing, JobPhase::Running(_), JobResult::Listing(Err(FsError::NotDirectory))) => {
                if is_root {
                    self.root_lost();
                    self.finish_job(id, JobOutcome::Removed);
                    return;
                }
                if let Some(job) = self.jobs.get_mut(&id) {
                    job.phase = JobPhase::Confirming(started);
                }
                self.dispatch_job(id, JobOperation::Metadata);
            }
            (ReadNeed::Listing, JobPhase::Confirming(_), JobResult::Metadata(Ok(info))) => {
                if info.kind == EntryKind::Directory {
                    self.stale_results += 1;
                    self.finish_job(id, JobOutcome::Stale);
                } else {
                    let outcome = self.commit_metadata(&job, info);
                    self.finish_job(id, outcome);
                }
            }
            (ReadNeed::Listing, JobPhase::Confirming(_), JobResult::Metadata(Err(FsError::NotFound))) => {
                self.on_not_found(&job)
            }
            (ReadNeed::Listing, JobPhase::Confirming(_), JobResult::Metadata(Err(FsError::NotDirectory))) => {
                self.listing_failures += 1;
                self.resolve_ancestor(entry);
                self.finish_job(id, JobOutcome::Failed(FsError::Transient("ancestor is not a directory".into())));
            }
            (ReadNeed::Listing, _, JobResult::Listing(Err(FsError::Fatal(m))))
            | (ReadNeed::Listing, _, JobResult::Metadata(Err(FsError::Fatal(m))))
            | (ReadNeed::Metadata, _, JobResult::Metadata(Err(FsError::Fatal(m)))) => {
                self.terminate(FsError::Fatal(m));
            }
            (ReadNeed::Listing, _, JobResult::Listing(Err(err)))
            | (ReadNeed::Listing, _, JobResult::Metadata(Err(err))) => {
                self.listing_failures += 1;
                self.finish_job(id, JobOutcome::Failed(err));
            }
            (ReadNeed::Metadata, _, JobResult::Metadata(Ok(info))) => {
                let outcome = self.commit_metadata(&job, info);
                self.finish_job(id, outcome);
            }
            (ReadNeed::Metadata, _, JobResult::Metadata(Err(FsError::NotFound))) => self.on_not_found(&job),
            (ReadNeed::Metadata, _, JobResult::Metadata(Err(FsError::NotDirectory))) => {
                if is_root {
                    self.root_lost();
                    self.finish_job(id, JobOutcome::Removed);
                    return;
                }
                self.resolve_ancestor(entry);
                self.finish_job(id, JobOutcome::Failed(FsError::Transient("ancestor is not a directory".into())));
            }
            (ReadNeed::Metadata, _, JobResult::Metadata(Err(err))) => self.finish_job(id, JobOutcome::Failed(err)),
            (_, _, _) => {
                self.finish_job(id, JobOutcome::Failed(FsError::Transient("unexpected job result kind".into())))
            }
        }
    }

    pub(super) fn on_worker_lost(&mut self, loss: WorkerLoss) {
        match loss {
            WorkerLoss::Job(id) => self.on_job_lost(id),
            WorkerLoss::WatchRegistration(request) => self.on_watch_registered(request, Err(ErrorCause::WorkerLost)),
        }
    }

    fn on_job_lost(&mut self, id: JobId) {
        let Some(job) = self.jobs.get(&id).cloned() else {
            return;
        };
        if job.phase.started().is_none() {
            return;
        }
        self.lost_workers += 1;
        match job.entry() {
            Some(_) => self.finish_job(id, JobOutcome::WorkerLost),
            None => {
                self.push_error(crate::path::RelativePath::root(), Operation::RootProbe, ErrorCause::WorkerLost);
                self.finish_job(id, JobOutcome::Cancelled);
                self.schedule_probe(true);
            }
        }
    }

    fn resolve_ancestor(&mut self, entry: EntryId) {
        let Some(parent) = self.parent_of(entry) else {
            return;
        };
        let Some(parent_entry) = self.snapshot.get_by_id(parent).cloned() else {
            return;
        };
        let need = match parent_entry.shape {
            Shape::Directory(LoadState::Loaded | LoadState::Loading) => ReadNeed::Listing,
            _ => ReadNeed::Metadata,
        };
        self.bump_epoch(parent);
        self.request(parent, parent_entry.path, need, Reasons::control(), Vec::new());
    }

    fn on_not_found(&mut self, job: &ActiveJob) {
        let Some(entry) = job.entry() else { return };
        let is_root = self.snapshot.get_by_id(entry).map(|e| e.path.is_root()).unwrap_or(false);
        if is_root {
            self.root_lost();
        } else {
            self.remove_entry(entry, Some(job));
        }
        self.finish_job(job.id, JobOutcome::Removed);
    }

    fn on_probe_result(&mut self, job: ActiveJob, result: JobResult) {
        if let JobResult::Metadata(Err(FsError::Fatal(message))) = result {
            self.finish_job(job.id, JobOutcome::Cancelled);
            self.terminate(FsError::Fatal(message));
            return;
        }
        if !self.guards_valid(&job) {
            self.finish_job(job.id, JobOutcome::Stale);
            return;
        }
        match result {
            JobResult::Metadata(Ok(info)) if info.kind == EntryKind::Directory => {
                self.finish_job(job.id, JobOutcome::Accepted);
                self.root_recovered(info);
            }
            JobResult::Metadata(Ok(_)) | JobResult::Metadata(Err(FsError::NotFound | FsError::NotDirectory)) => {
                self.finish_job(job.id, JobOutcome::Accepted);
                self.schedule_probe(true);
            }
            JobResult::Metadata(Err(err)) => {
                self.push_error(crate::path::RelativePath::root(), Operation::RootProbe, err);
                self.finish_job(job.id, JobOutcome::Accepted);
                self.schedule_probe(true);
            }
            JobResult::Listing(_) => {
                self.finish_job(job.id, JobOutcome::Accepted);
                self.schedule_probe(true);
            }
        }
    }

    pub(super) fn schedule_probe(&mut self, after_failure: bool) {
        if self.root_probe.is_some() || self.probe_job.is_some() {
            return;
        }
        if after_failure {
            self.probe_attempts = self.probe_attempts.saturating_add(1);
            if !self.config.root_reappearance_monitoring {
                let ids: Vec<CommandId> = self
					.commands
					.values()
					.filter(|c| matches!(&c.state, CommandState::Refresh { remaining } if remaining.iter().any(|t| matches!(t, RefreshTarget::RootRecovery))))
					.map(|c| c.id)
					.collect();
                for id in ids {
                    self.finish_command(id, Err(Error::NotFound));
                }
                return;
            }
        }
        let not_before = if after_failure { Some(self.now + self.backoff(self.probe_attempts)) } else { None };
        self.root_probe = Some(RootProbe {
            request: PendingRequest {
                path: crate::path::RelativePath::root(),
                need: ReadNeed::Metadata,
                reasons: Reasons::control(),
                barriers: Vec::new(),
                designate_for_round: None,
            },
            not_before,
        });
    }

    pub(super) fn finish_job(&mut self, id: JobId, outcome: JobOutcome) {
        let Some(job) = self.jobs.remove(&id) else {
            return;
        };
        if job.phase.started().is_none() {
            let now = self.now;
            self.governor.release(GrantId::Job(id), now);
        }
        match job.entry() {
            Some(entry) => {
                if self.active_by_entry.get(&entry) == Some(&id) {
                    self.active_by_entry.remove(&entry);
                }
            }
            None => {
                if self.probe_job == Some(id) {
                    self.probe_job = None;
                }
            }
        }
        if let JobPhase::Registering(request) = job.phase {
            self.abandon_registration(request);
        }
        self.queue_order.retain(|q| *q != id);
        if let Some(entry) = job.entry() {
            self.settle_obligations(&job, &outcome);
            self.settle_commands(&job, &outcome);
            self.settle_retry(entry, &job, &outcome);
        }
        self.job_terminal(id);
    }

    fn settle_obligations(&mut self, job: &ActiveJob, outcome: &JobOutcome) {
        let Some(entry) = job.entry() else { return };
        let round_generation = self.round.as_ref().map(|r| r.generation);
        match outcome {
            JobOutcome::Accepted => {
                if job.designated || (job.recon.is_some() && job.recon == round_generation) {
                    self.set_obligation(entry, ObligationState::Accepted);
                }
            }
            JobOutcome::Removed => self.set_obligation(entry, ObligationState::Removed),
            JobOutcome::Failed(_)
            | JobOutcome::LimitExceeded
            | JobOutcome::WatcherRegistrationFailed
            | JobOutcome::Stale
            | JobOutcome::Cancelled
            | JobOutcome::WorkerLost
            | JobOutcome::Stuck => {
                if job.designated {
                    self.set_obligation(entry, ObligationState::Unsatisfied);
                }
            }
        }
        if job.reasons.initial_scan {
            match outcome {
                JobOutcome::Failed(_)
                | JobOutcome::LimitExceeded
                | JobOutcome::WatcherRegistrationFailed
                | JobOutcome::Stuck => {
                    self.initial_scan.resolve_unsatisfied(entry, job.path.clone());
                }
                JobOutcome::Accepted
                | JobOutcome::Removed
                | JobOutcome::Stale
                | JobOutcome::Cancelled
                | JobOutcome::WorkerLost => {}
            }
        }
    }

    fn settle_commands(&mut self, job: &ActiveJob, outcome: &JobOutcome) {
        let Some(entry) = job.entry() else { return };
        let attached: Vec<CommandId> = job
            .barriers
            .iter()
            .copied()
            .filter(|c| self.commands.get(c).map(|cmd| job.dispatch > cmd.barrier).unwrap_or(false))
            .collect();
        match outcome {
            JobOutcome::Accepted => {
                for cmd in attached {
                    self.command_satisfied(cmd, entry, job);
                }
            }
            JobOutcome::Removed => {}
            JobOutcome::Failed(err) => {
                for cmd in attached {
                    self.finish_command(cmd, Err(Error::Io(err.clone())));
                }
            }
            JobOutcome::LimitExceeded => {
                for cmd in attached {
                    self.finish_command(cmd, Err(Error::LimitExceeded));
                }
            }
            JobOutcome::WatcherRegistrationFailed => {
                for cmd in attached {
                    self.finish_command(cmd, Err(Error::WatcherRegistrationFailed));
                }
            }
            JobOutcome::Stuck => {
                for cmd in attached {
                    self.finish_command(cmd, Err(Error::Stuck));
                }
            }
            JobOutcome::Stale | JobOutcome::Cancelled | JobOutcome::WorkerLost => {}
        }
    }

    fn retry_phase(need: ReadNeed) -> RetryPhase {
        match need {
            ReadNeed::Listing => RetryPhase::Listing,
            ReadNeed::Metadata => RetryPhase::Metadata,
        }
    }

    fn merge_retry(
        &mut self,
        entry: EntryId,
        phase: RetryPhase,
        attempts: u32,
        timing: RetryTiming,
        reasons: Reasons,
        barriers: &[CommandId],
    ) {
        let mut record = RetryRecord { phase, attempts, due: None, reasons, barriers: Vec::new() };
        let existing = self.entries.take_retry(entry);
        let retained = match existing {
            Some(existing) => {
                record.phase = record.phase.max(existing.phase);
                record.reasons.merge(existing.reasons);
                existing.barriers
            }
            None => Vec::new(),
        };
        let timing = match record.phase {
            RetryPhase::WatchRegistrationThenListing => RetryTiming::Backoff,
            RetryPhase::Listing | RetryPhase::Metadata => timing,
        };
        record.due = match timing {
            RetryTiming::Backoff => Some(self.now + self.backoff(record.attempts)),
            RetryTiming::Untimed => None,
        };
        for barrier in barriers.iter().copied().chain(retained) {
            if self.commands.contains_key(&barrier) && !record.barriers.contains(&barrier) {
                record.barriers.push(barrier);
            }
        }
        self.entries.set_retry(entry, record);
    }

    fn settle_retry(&mut self, entry: EntryId, job: &ActiveJob, outcome: &JobOutcome) {
        let represented = self.snapshot.get_by_id(entry).cloned();
        match outcome {
            JobOutcome::Accepted | JobOutcome::Removed => {
                let clear = match (self.entries.retry(entry).map(|r| r.phase), job.need) {
                    (Some(_), ReadNeed::Listing) => true,
                    (Some(phase), ReadNeed::Metadata) => phase == RetryPhase::Metadata,
                    (None, _) => false,
                };
                if clear {
                    self.entries.clear_retry(entry);
                }
                let Some(state) = self.entries.get_mut(entry) else {
                    return;
                };
                state.transient_failures = 0;
                let recovered = job.need == ReadNeed::Listing || state.retry().is_none();
                if recovered {
                    self.entries.set_degraded(entry, None);
                }
            }
            JobOutcome::Failed(err) => {
                self.push_error(
                    job.path.clone(),
                    if job.need == ReadNeed::Listing { Operation::Listing } else { Operation::Metadata },
                    err.clone(),
                );
                let Some(current) = represented else { return };
                let loaded = current.is_loaded();
                let cause = match err {
                    FsError::Transient(_) => DegradedCause::Transient,
                    FsError::PermissionDenied => DegradedCause::PermissionDenied,
                    FsError::Unsupported(_) => DegradedCause::Unsupported,
                    _ => DegradedCause::Transient,
                };
                let threshold = self.config.transient_degrade_threshold;
                let attempts = self.entries.retry(entry).map(|r| r.attempts + 1).unwrap_or(1);
                let timing = if matches!(err, FsError::Transient(_)) || !loaded {
                    RetryTiming::Backoff
                } else {
                    RetryTiming::Untimed
                };
                let state = self.entry_state_mut(entry);
                let degraded = match cause {
                    DegradedCause::Transient => {
                        state.transient_failures += 1;
                        (state.transient_failures >= threshold).then_some(DegradedCause::Transient)
                    }
                    other => Some(other),
                };
                if degraded.is_some() {
                    self.entries.set_degraded(entry, degraded);
                }
                self.merge_retry(
                    entry,
                    Self::retry_phase(job.need),
                    attempts,
                    timing,
                    job.reasons.for_retry(),
                    &job.barriers,
                );
            }
            JobOutcome::LimitExceeded => {
                self.push_error(job.path.clone(), Operation::Listing, crate::update::ErrorCause::LimitExceeded);
                let Some(current) = represented else { return };
                let loaded = current.is_loaded();
                let attempts = self.entries.retry(entry).map(|r| r.attempts + 1).unwrap_or(1);
                let timing = if loaded { RetryTiming::Untimed } else { RetryTiming::Backoff };
                self.merge_retry(entry, RetryPhase::Listing, attempts, timing, job.reasons.for_retry(), &job.barriers);
                self.entries.set_degraded(entry, Some(DegradedCause::LimitExceeded));
            }
            JobOutcome::WatcherRegistrationFailed => {
                let attempts = self.entries.retry(entry).map(|r| r.attempts + 1).unwrap_or(1);
                self.merge_retry(
                    entry,
                    RetryPhase::WatchRegistrationThenListing,
                    attempts,
                    RetryTiming::Backoff,
                    job.reasons.for_retry(),
                    &job.barriers,
                );
                self.entries.set_degraded(entry, Some(DegradedCause::WatcherRegistration));
            }
            JobOutcome::Stuck => {
                self.push_error(
                    job.path.clone(),
                    if job.need == ReadNeed::Listing { Operation::Listing } else { Operation::Metadata },
                    ErrorCause::WorkerStuck,
                );
                let Some(current) = represented else { return };
                if !Self::still_required(&current, job.need) {
                    return;
                }
                let attempts = self.entries.retry(entry).map(|r| r.attempts + 1).unwrap_or(1);
                self.merge_retry(
                    entry,
                    Self::retry_phase(job.need),
                    attempts,
                    RetryTiming::Backoff,
                    job.reasons.for_retry(),
                    &job.barriers,
                );
            }
            JobOutcome::WorkerLost => {
                self.push_error(
                    job.path.clone(),
                    if job.need == ReadNeed::Listing { Operation::Listing } else { Operation::Metadata },
                    ErrorCause::WorkerLost,
                );
                let Some(current) = represented else { return };
                if !Self::still_required(&current, job.need) {
                    return;
                }
                let attempts = self.entries.retry(entry).map(|r| r.attempts + 1).unwrap_or(1);
                self.merge_retry(
                    entry,
                    Self::retry_phase(job.need),
                    attempts,
                    RetryTiming::Backoff,
                    job.reasons.for_retry(),
                    &job.barriers,
                );
            }
            JobOutcome::Stale | JobOutcome::Cancelled => {
                let Some(current) = represented else { return };
                if !Self::still_required(&current, job.need) {
                    return;
                }
                let mut reasons = job.reasons;
                reasons.baseline = false;
                self.request_with(
                    entry,
                    PendingRequest {
                        path: current.path.clone(),
                        need: job.need,
                        reasons,
                        barriers: job.barriers.clone(),
                        designate_for_round: None,
                    },
                );
            }
        }
    }

    fn still_required(current: &crate::entry::Entry, need: ReadNeed) -> bool {
        match need {
            ReadNeed::Listing => matches!(current.shape, Shape::Directory(LoadState::Loaded | LoadState::Loading)),
            ReadNeed::Metadata => true,
        }
    }

    fn abandon_registration(&mut self, request: WatchRequestId) {
        if let Some(target) = self.registrations.get_mut(&request) {
            *target = RegistrationTarget::Abandoned;
        }
    }

    pub(super) fn release_watch(&mut self, result: Result<WatchId, ErrorCause>) {
        if let Ok(watch) = result {
            self.outputs.push(Output::Unwatch(watch));
        }
    }

    pub(super) fn on_watch_registered(&mut self, request: WatchRequestId, result: Result<WatchId, ErrorCause>) {
        let target = self.registrations.remove(&request).unwrap_or(RegistrationTarget::Abandoned);
        match target {
            RegistrationTarget::Abandoned => self.release_watch(result),
            RegistrationTarget::Job(job_id) => {
                let Some(job) = self.jobs.get(&job_id).cloned() else {
                    self.release_watch(result);
                    return;
                };
                if job.phase != JobPhase::Registering(request) {
                    self.release_watch(result);
                    return;
                }
                let Some(entry) = job.entry() else {
                    self.release_watch(result);
                    return;
                };
                let is_root = job.path.is_root();
                match result {
                    Ok(watch) => {
                        self.watches.push(watch);
                        if let Some(dir) = self.dir_state_mut(entry) {
                            dir.watch = WatchState::Registered(watch);
                        }
                        self.entries.advance_watch_phase(entry);
                        if is_root {
                            self.watcher_health = WatcherHealth::Healthy { backend: self.caps.watcher };
                            if self.open_gate == OpenGate::Pending {
                                self.open_gate = OpenGate::Ready;
                            }
                        }
                        self.requeue_after_registration(job_id);
                    }
                    Err(err) => {
                        self.push_error(job.path.clone(), Operation::WatchRegistration, err.clone());
                        if let Some(dir) = self.dir_state_mut(entry) {
                            dir.watch = WatchState::Failed;
                        }
                        self.watcher_health = WatcherHealth::Degraded {
                            backend: self.caps.watcher,
                            reason: format!("registration failed for {}: {err}", job.path),
                        };
                        match self.config.watch_registration_failure {
                            WatchRegistrationFailure::ReconcileOnly => {
                                if is_root && self.open_gate == OpenGate::Pending {
                                    self.open_gate = OpenGate::Ready;
                                }
                                self.requeue_after_registration(job_id);
                            }
                            WatchRegistrationFailure::RequireWatcher => {
                                if is_root && self.open_gate == OpenGate::Pending {
                                    self.open_gate = OpenGate::Failed(Error::WatcherRegistrationFailed);
                                }
                                self.finish_job(job_id, JobOutcome::WatcherRegistrationFailed);
                            }
                        }
                    }
                }
            }
            RegistrationTarget::Standalone(entry) => match result {
                Ok(watch) => {
                    let is_root = self.snapshot.get_by_id(entry).map(|e| e.path.is_root()).unwrap_or(false);
                    match self.dir_state_mut(entry) {
                        Some(dir) => dir.watch = WatchState::Registered(watch),
                        None => {
                            self.outputs.push(Output::Unwatch(watch));
                            return;
                        }
                    }
                    self.watches.push(watch);
                    self.entries.advance_watch_phase(entry);
                    if is_root || self.caps.watcher.is_per_directory() {
                        self.watcher_health = WatcherHealth::Healthy { backend: self.caps.watcher };
                        self.watcher_restart_attempts = 0;
                        self.coverage_invalidate();
                    }
                }
                Err(err) => {
                    let path = self
                        .snapshot
                        .get_by_id(entry)
                        .map(|e| e.path.clone())
                        .unwrap_or_else(crate::path::RelativePath::root);
                    self.push_error(path, Operation::WatchRegistration, err.clone());
                    if let Some(dir) = self.dir_state_mut(entry) {
                        dir.watch = WatchState::Failed;
                    }
                    self.watcher_health = WatcherHealth::Degraded {
                        backend: self.caps.watcher,
                        reason: format!("restart failed: {err}"),
                    };
                    self.watcher_restart_attempts = self.watcher_restart_attempts.saturating_add(1);
                    let delay = self.backoff(self.watcher_restart_attempts);
                    self.watcher_restart_due = Some(self.now + delay);
                }
            },
        }
    }

    fn requeue_after_registration(&mut self, job_id: JobId) {
        if let Some(job) = self.jobs.get_mut(&job_id) {
            job.phase = JobPhase::Queued;
        }
        self.queue_order.push_back(job_id);
    }
}
