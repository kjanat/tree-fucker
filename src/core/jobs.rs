use super::types::*;
use super::{Coordinator, JobOperation, JobResult, JobSpec, Output};
use crate::config::WatchRegistrationFailure;
use crate::entry::{EntryKind, LoadState, Shape};
use crate::error::Error;
use crate::fs::FsError;
use crate::ids::*;
use crate::update::{Operation, WatcherHealth};

impl Coordinator {
    pub(super) fn on_job_completed(&mut self, id: JobId, result: JobResult) {
        let Some(job) = self.jobs.get(&id).cloned() else {
            return;
        };
        if !matches!(job.phase, JobPhase::Running | JobPhase::Confirming) {
            return;
        }
        let Some(entry) = job.entry else {
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
        if job.need == ReadNeed::Listing
            && let Some(started) = job.started
        {
            self.last_listing_duration = Some(self.now.since(started));
        }
        let is_root = self.snapshot.get_by_id(entry).map(|e| e.path.is_root()).unwrap_or(false);
        match (job.need, job.phase, result) {
            (ReadNeed::Listing, JobPhase::Running, JobResult::Listing(Ok(listing))) => {
                self.listings += 1;
                self.last_listing_children = Some(listing.entries.len());
                match self.commit_listing(&job, listing) {
                    Ok(()) => self.finish_job(id, JobOutcome::Accepted),
                    Err(()) => {
                        self.listing_failures += 1;
                        self.finish_job(id, JobOutcome::LimitExceeded)
                    }
                }
            }
            (ReadNeed::Listing, JobPhase::Running, JobResult::Listing(Err(FsError::NotFound))) => {
                self.listing_failures += 1;
                self.on_not_found(&job);
            }
            (ReadNeed::Listing, JobPhase::Running, JobResult::Listing(Err(FsError::NotDirectory))) => {
                if is_root {
                    self.root_lost();
                    self.finish_job(id, JobOutcome::Removed);
                    return;
                }
                if let Some(job) = self.jobs.get_mut(&id) {
                    job.phase = JobPhase::Confirming;
                }
                self.outputs.push(Output::StartJob(JobSpec {
                    id,
                    path: job.path.clone(),
                    operation: JobOperation::Metadata,
                }));
            }
            (ReadNeed::Listing, JobPhase::Confirming, JobResult::Metadata(Ok(info))) => {
                if info.kind == EntryKind::Directory {
                    self.stale_results += 1;
                    self.finish_job(id, JobOutcome::Stale);
                } else {
                    let outcome = self.commit_metadata(&job, info);
                    self.finish_job(id, outcome);
                }
            }
            (ReadNeed::Listing, JobPhase::Confirming, JobResult::Metadata(Err(FsError::NotFound))) => {
                self.on_not_found(&job)
            }
            (ReadNeed::Listing, JobPhase::Confirming, JobResult::Metadata(Err(FsError::NotDirectory))) => {
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
        let Some(entry) = job.entry else { return };
        let is_root = self.snapshot.get_by_id(entry).map(|e| e.path.is_root()).unwrap_or(false);
        if is_root {
            self.root_lost();
        } else {
            self.remove_entry(entry, Some(job));
        }
        self.finish_job(job.id, JobOutcome::Removed);
    }

    fn on_probe_result(&mut self, job: ActiveJob, result: JobResult) {
        if !self.guards_valid(&job) {
            self.finish_job(job.id, JobOutcome::Stale);
            return;
        }
        match result {
            JobResult::Metadata(Ok(info)) if info.kind == EntryKind::Directory => {
                self.finish_job(job.id, JobOutcome::Accepted);
                self.root_recovered(info);
            }
            JobResult::Metadata(Err(FsError::Fatal(m))) => {
                self.finish_job(job.id, JobOutcome::Accepted);
                self.terminate(FsError::Fatal(m));
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
        self.root_probe = Some(PendingRequest {
            path: crate::path::RelativePath::root(),
            need: ReadNeed::Metadata,
            reasons: Reasons::control(),
            barriers: Vec::new(),
            designate_for_round: None,
            not_before,
        });
    }

    pub(super) fn finish_job(&mut self, id: JobId, outcome: JobOutcome) {
        let Some(job) = self.jobs.remove(&id) else {
            return;
        };
        match job.entry {
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
            self.registrations.remove(&request);
        }
        self.queue_order.retain(|q| *q != id);
        if let Some(entry) = job.entry {
            self.settle_obligations(&job, &outcome);
            self.settle_commands(&job, &outcome);
            self.settle_retry(entry, &job, &outcome);
        }
        self.job_terminal(id);
    }

    fn settle_obligations(&mut self, job: &ActiveJob, outcome: &JobOutcome) {
        let Some(entry) = job.entry else { return };
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
            | JobOutcome::Cancelled => {
                if job.designated {
                    self.set_obligation(entry, ObligationState::Unsatisfied);
                }
            }
        }
        if job.reasons.initial_scan {
            match outcome {
                JobOutcome::Failed(_) | JobOutcome::LimitExceeded | JobOutcome::WatcherRegistrationFailed => {
                    if let Some((_, state)) = self.initial_scan.obligations.get_mut(&entry)
                        && *state == ScanObligation::Pending
                    {
                        *state = ScanObligation::Unsatisfied;
                        self.initial_scan.failed.insert(job.path.clone());
                    }
                }
                _ => {}
            }
        }
    }

    fn settle_commands(&mut self, job: &ActiveJob, outcome: &JobOutcome) {
        let Some(entry) = job.entry else { return };
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
            JobOutcome::Stale | JobOutcome::Cancelled => {}
        }
    }

    fn settle_retry(&mut self, entry: EntryId, job: &ActiveJob, outcome: &JobOutcome) {
        let represented = self.snapshot.get_by_id(entry).cloned();
        match outcome {
            JobOutcome::Accepted | JobOutcome::Removed => {
                let state = self.entry_state_mut(entry);
                state.transient_failures = 0;
                let clear = match (&state.retry, job.need) {
                    (Some(_), ReadNeed::Listing) => true,
                    (Some(record), ReadNeed::Metadata) => record.phase == RetryPhase::Metadata,
                    (None, _) => false,
                };
                if clear {
                    state.retry = None;
                }
                if job.need == ReadNeed::Listing || state.retry.is_none() {
                    state.degraded = None;
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
                let attempts =
                    self.entry_state(entry).and_then(|s| s.retry.as_ref()).map(|r| r.attempts + 1).unwrap_or(1);
                let timed = matches!(err, FsError::Transient(_)) || !loaded;
                let due = if timed { Some(self.now + self.backoff(attempts)) } else { None };
                let state = self.entry_state_mut(entry);
                match cause {
                    DegradedCause::Transient => {
                        state.transient_failures += 1;
                        if state.transient_failures >= threshold {
                            state.degraded = Some(DegradedCause::Transient);
                        }
                    }
                    other => state.degraded = Some(other),
                }
                let mut reasons = job.reasons;
                reasons.baseline = false;
                reasons.priority = false;
                state.retry = Some(RetryRecord {
                    phase: if job.need == ReadNeed::Listing { RetryPhase::Listing } else { RetryPhase::Metadata },
                    attempts,
                    due,
                    reasons,
                    barriers: Vec::new(),
                });
            }
            JobOutcome::LimitExceeded => {
                self.push_error(job.path.clone(), Operation::Listing, crate::update::ErrorCause::LimitExceeded);
                let Some(current) = represented else { return };
                let loaded = current.is_loaded();
                let attempts =
                    self.entry_state(entry).and_then(|s| s.retry.as_ref()).map(|r| r.attempts + 1).unwrap_or(1);
                let due = if loaded { None } else { Some(self.now + self.backoff(attempts)) };
                let mut reasons = job.reasons;
                reasons.baseline = false;
                reasons.priority = false;
                let state = self.entry_state_mut(entry);
                state.degraded = Some(DegradedCause::LimitExceeded);
                state.retry =
                    Some(RetryRecord { phase: RetryPhase::Listing, attempts, due, reasons, barriers: Vec::new() });
            }
            JobOutcome::WatcherRegistrationFailed => {
                let attempts =
                    self.entry_state(entry).and_then(|s| s.retry.as_ref()).map(|r| r.attempts + 1).unwrap_or(1);
                let due = Some(self.now + self.backoff(attempts));
                let mut reasons = job.reasons;
                reasons.baseline = false;
                reasons.priority = false;
                let state = self.entry_state_mut(entry);
                state.degraded = Some(DegradedCause::WatcherRegistration);
                state.retry = Some(RetryRecord {
                    phase: RetryPhase::WatchRegistrationThenListing,
                    attempts,
                    due,
                    reasons,
                    barriers: Vec::new(),
                });
            }
            JobOutcome::Stale | JobOutcome::Cancelled => {
                let Some(current) = represented else { return };
                let still_required = match job.need {
                    ReadNeed::Listing => {
                        matches!(current.shape, Shape::Directory(LoadState::Loaded | LoadState::Loading))
                    }
                    ReadNeed::Metadata => true,
                };
                if !still_required {
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
                        not_before: None,
                    },
                );
            }
        }
    }

    pub(super) fn on_watch_registered(&mut self, request: WatchRequestId, result: Result<WatchId, FsError>) {
        let Some(target) = self.registrations.remove(&request) else {
            return;
        };
        match target {
            RegistrationTarget::Job(job_id) => {
                let Some(job) = self.jobs.get(&job_id).cloned() else {
                    if let Ok(watch) = result {
                        self.outputs.push(Output::Unwatch(watch));
                    }
                    return;
                };
                if job.phase != JobPhase::Registering(request) {
                    return;
                }
                let Some(entry) = job.entry else { return };
                let is_root = job.path.is_root();
                match result {
                    Ok(watch) => {
                        self.watches.push(watch);
                        if let Some(dir) = self.dir_state_mut(entry) {
                            dir.watch = WatchState::Registered(watch);
                        }
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
                    self.watches.push(watch);
                    let is_root = self.snapshot.get_by_id(entry).map(|e| e.path.is_root()).unwrap_or(false);
                    if let Some(dir) = self.dir_state_mut(entry) {
                        dir.watch = WatchState::Registered(watch);
                    } else {
                        self.outputs.push(Output::Unwatch(watch));
                        return;
                    }
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
