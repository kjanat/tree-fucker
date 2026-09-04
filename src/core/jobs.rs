use super::types::*;
use super::{Coordinator, JobResult, Output, Work, WorkerLoss};
use crate::config::WatchRegistrationFailure;
use crate::entry::{EntryKind, LoadState, Shape};
use crate::error::Error;
use crate::fs::{FsError, SessionOutcome, SessionState, SessionStep};
use crate::ids::*;
use crate::update::{ErrorCause, Operation, ResourceLimitEvent, ResourceLimited, WatcherHealth};

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
            JobResult::Listing(SessionStep {
                state: SessionState::Finished(SessionOutcome::Failed(FsError::Fatal(m))),
                ..
            })
            | JobResult::Metadata(Err(FsError::Fatal(m)))
            | JobResult::Domain(Err(FsError::Fatal(m)))
            | JobResult::Enrichment(Err(FsError::Fatal(m))) => Some(m.clone()),
            _ => None,
        };
        if let Some(message) = fatal {
            self.finish_job(id, JobOutcome::Cancelled);
            self.terminate(FsError::Fatal(message));
            return;
        }
        if let JobResult::Listing(step) = &result {
            let cost = step.cost;
            let suspended = step.state == SessionState::Suspended;
            self.record_session_cost(id, &cost);
            if let Some(job) = self.jobs.get_mut(&id) {
                job.session_open = suspended;
            }
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
            (ReadNeed::Listing, JobPhase::Running(_), JobResult::Listing(step)) => match step.state {
                SessionState::Suspended => self.suspend_job(id),
                SessionState::Finished(SessionOutcome::Complete(listing)) => {
                    self.listings += 1;
                    self.last_listing_children = Some(listing.entries.len());
                    self.record_directory_size(&job.path, listing.entries.len());
                    match self.commit_listing(&job, listing) {
                        Ok(()) => self.finish_job(id, JobOutcome::Accepted),
                        Err(rejection) => {
                            self.listing_failures += 1;
                            self.finish_job(id, JobOutcome::Rejected(rejection))
                        }
                    }
                }
                SessionState::Finished(SessionOutcome::Cancelled) => {
                    self.cancelled_sessions += 1;
                    self.finish_job(id, JobOutcome::Cancelled);
                }
                SessionState::Finished(SessionOutcome::ResourceLimited(reported)) => {
                    self.listing_failures += 1;
                    let limited = ResourceLimited { domain: self.domain_of(entry), ..reported };
                    self.record_directory_size(&job.path, usize::try_from(limited.observed).unwrap_or(usize::MAX));
                    self.record_resource_limit(ResourceLimitEvent { path: job.path.clone(), limited });
                    self.finish_job(id, JobOutcome::Rejected(ListingRejection::ResourceLimited(limited)));
                }
                SessionState::Finished(SessionOutcome::Failed(FsError::NotFound)) => {
                    self.listing_failures += 1;
                    self.on_not_found(&job);
                }
                SessionState::Finished(SessionOutcome::Failed(FsError::NotDirectory)) => {
                    if is_root {
                        self.root_lost();
                        self.finish_job(id, JobOutcome::Removed);
                        return;
                    }
                    if let Some(job) = self.jobs.get_mut(&id) {
                        job.phase = JobPhase::Confirming(started);
                    }
                    self.dispatch_job(id, Work::Metadata);
                }
                SessionState::Finished(SessionOutcome::Failed(err)) => {
                    self.listing_failures += 1;
                    self.finish_job(id, JobOutcome::Failed(err));
                }
            },
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
                self.finish_job(id, JobOutcome::AncestorNotDirectory);
            }
            (ReadNeed::Listing, _, JobResult::Metadata(Err(err))) => {
                self.listing_failures += 1;
                self.finish_job(id, JobOutcome::Failed(err));
            }
            (ReadNeed::Metadata, _, JobResult::Metadata(Ok(info))) => {
                let outcome = self.commit_metadata(&job, info);
                self.finish_job(id, outcome);
            }
            (ReadNeed::Domain, _, JobResult::Domain(Ok(probe))) => {
                let outcome = self.commit_domain(&job, probe);
                self.finish_job(id, outcome);
            }
            (ReadNeed::Domain, _, JobResult::Domain(Err(FsError::NotFound))) => self.on_not_found(&job),
            (ReadNeed::Domain, _, JobResult::Domain(Err(err))) => self.finish_job(id, JobOutcome::Failed(err)),
            (ReadNeed::Enrichment(fields), _, JobResult::Enrichment(Ok(read))) => {
                let outcome = self.commit_enrichment(&job, fields, read);
                self.finish_job(id, outcome);
            }
            (ReadNeed::Enrichment(_), _, JobResult::Enrichment(Err(err))) => {
                self.finish_job(id, JobOutcome::Failed(err))
            }
            (ReadNeed::Metadata, _, JobResult::Metadata(Err(FsError::NotFound))) => self.on_not_found(&job),
            (ReadNeed::Metadata, _, JobResult::Metadata(Err(FsError::NotDirectory))) => {
                if is_root {
                    self.root_lost();
                    self.finish_job(id, JobOutcome::Removed);
                    return;
                }
                self.resolve_ancestor(entry);
                self.finish_job(id, JobOutcome::AncestorNotDirectory);
            }
            (ReadNeed::Metadata, _, JobResult::Metadata(Err(err))) => self.finish_job(id, JobOutcome::Failed(err)),
            (_, _, _) => self.finish_job(id, JobOutcome::ResultMismatch),
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
            JobResult::Listing(_) | JobResult::Enrichment(_) | JobResult::Domain(_) => {
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
        job.cancel.cancel();
        self.settle_domain_cost(&job, &outcome);
        self.release_session_bytes(id);
        if job.session_open || (outcome == JobOutcome::Cancelled && job.phase.started().is_some()) {
            self.outputs.push(Output::CancelJob(id));
        }
        if job.phase.started().is_none() {
            let now = self.now;
            self.governor.release(self.job_grant(id), now);
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
        if let JobPhase::Registering(request, _) = job.phase {
            self.abandon_registration(request);
            if let Some(entry) = job.entry() {
                let domain = self.domain_of(entry);
                self.entries.set_watch(entry, WatchState::NotRegistered, domain);
            }
        }
        self.queue_order.retain(|q| *q != id);
        if let Some(entry) = job.entry() {
            match job.need.kind() {
                None => match job.need {
                    ReadNeed::Enrichment(fields) => self.settle_enrichment(entry, &job, fields, &outcome),
                    ReadNeed::Domain => self.settle_domain(entry, &job, &outcome),
                    ReadNeed::Metadata | ReadNeed::Listing => {}
                },
                Some(kind) => {
                    self.settle_obligations(&job, &outcome);
                    self.settle_commands(&job, &outcome);
                    self.settle_retry(entry, &job, kind, &outcome);
                }
            }
        }
        self.job_terminal(id);
    }

    fn settle_domain_cost(&mut self, job: &ActiveJob, outcome: &JobOutcome) {
        let domain = job.domain;
        let now = self.now;
        if job.phase.started().is_some()
            && job.need == ReadNeed::Metadata
            && let Some(entry) = job.entry()
        {
            self.record_domain_metadata(entry, 1);
        }
        let surcharged = matches!(
            outcome,
            JobOutcome::Failed(_)
                | JobOutcome::Rejected(_)
                | JobOutcome::Cancelled
                | JobOutcome::WorkerLost
                | JobOutcome::Stuck
        );
        if surcharged {
            self.governor.charge_surcharge(domain, now);
        }
        match outcome {
            JobOutcome::Accepted => self.governor.record_outcome(domain, false, now),
            JobOutcome::Failed(_)
            | JobOutcome::Rejected(_)
            | JobOutcome::AncestorNotDirectory
            | JobOutcome::WorkerLost
            | JobOutcome::Stuck => self.governor.record_outcome(domain, true, now),
            JobOutcome::Removed
            | JobOutcome::ResultMismatch
            | JobOutcome::WatcherRegistrationFailed
            | JobOutcome::Stale
            | JobOutcome::Cancelled => {}
        }
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
            | JobOutcome::Rejected(_)
            | JobOutcome::AncestorNotDirectory
            | JobOutcome::ResultMismatch
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
                | JobOutcome::Rejected(_)
                | JobOutcome::AncestorNotDirectory
                | JobOutcome::WatcherRegistrationFailed
                | JobOutcome::Stuck => {
                    self.initial_scan.resolve_unsatisfied(entry, job.path.clone());
                }
                JobOutcome::Accepted
                | JobOutcome::Removed
                | JobOutcome::ResultMismatch
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
            JobOutcome::Rejected(rejection) => {
                let error = match rejection {
                    ListingRejection::MalformedNames => Error::InvalidListing,
                    ListingRejection::UnresolvedChild => Error::UnresolvedKind,
                    ListingRejection::ResourceLimited(limited) => Error::ResourceLimited(*limited),
                };
                for cmd in attached {
                    self.finish_command(cmd, Err(error.clone()));
                }
            }
            JobOutcome::AncestorNotDirectory => {
                for cmd in attached {
                    self.finish_command(cmd, Err(Error::AncestorNotDirectory));
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
            JobOutcome::Stale | JobOutcome::Cancelled | JobOutcome::WorkerLost | JobOutcome::ResultMismatch => {}
        }
    }

    fn retry_phase(kind: ReadKind) -> RetryPhase {
        match kind {
            ReadKind::Listing => RetryPhase::Listing,
            ReadKind::Metadata => RetryPhase::Metadata,
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

    fn settle_retry(&mut self, entry: EntryId, job: &ActiveJob, kind: ReadKind, outcome: &JobOutcome) {
        let represented = self.snapshot.get_by_id(entry).cloned();
        match outcome {
            JobOutcome::Accepted | JobOutcome::Removed => {
                let clear = match (self.entries.retry(entry).map(|r| r.phase), kind) {
                    (Some(_), ReadKind::Listing) => true,
                    (Some(phase), ReadKind::Metadata) => phase == RetryPhase::Metadata,
                    (None, _) => false,
                };
                if clear {
                    self.entries.clear_retry(entry);
                }
                let Some(state) = self.entries.get_mut(entry) else {
                    return;
                };
                state.transient_failures = 0;
                let recovered = kind == ReadKind::Listing || state.retry().is_none();
                if recovered {
                    self.entries.set_degraded(entry, None);
                }
            }
            JobOutcome::Failed(err) => {
                self.push_error(job.path.clone(), kind.operation(), err.clone());
                let Some(current) = represented else { return };
                let loaded = current.is_loaded();
                let cause = match err {
                    FsError::PermissionDenied => DegradedCause::PermissionDenied,
                    FsError::Unsupported(_) => DegradedCause::Unsupported,
                    FsError::Transient(_) | FsError::NotFound | FsError::NotDirectory | FsError::Fatal(_) => {
                        DegradedCause::Transient
                    }
                };
                let timing = if cause == DegradedCause::Transient || !loaded {
                    RetryTiming::Backoff
                } else {
                    RetryTiming::Untimed
                };
                self.degrade_and_retry(entry, job, kind, cause, timing);
            }
            JobOutcome::Rejected(rejection) => {
                let (cause, timing) = match rejection {
                    ListingRejection::MalformedNames | ListingRejection::UnresolvedChild => {
                        (DegradedCause::Transient, RetryTiming::Backoff)
                    }
                    ListingRejection::ResourceLimited(limited) => {
                        self.push_error(job.path.clone(), kind.operation(), ErrorCause::ResourceLimited(*limited));
                        let loaded = represented.as_ref().map(|current| current.is_loaded()).unwrap_or(false);
                        let timing = if loaded { RetryTiming::Untimed } else { RetryTiming::Backoff };
                        (DegradedCause::ResourceLimited, timing)
                    }
                };
                if represented.is_none() {
                    return;
                }
                self.degrade_and_retry(entry, job, kind, cause, timing);
            }
            JobOutcome::AncestorNotDirectory => {
                self.push_error(job.path.clone(), kind.operation(), ErrorCause::Fs(FsError::NotDirectory));
                if represented.is_none() {
                    return;
                }
                self.degrade_and_retry(entry, job, kind, DegradedCause::Transient, RetryTiming::Backoff);
            }
            JobOutcome::ResultMismatch => {
                self.push_error(job.path.clone(), kind.operation(), ErrorCause::ResultMismatch);
                let Some(current) = represented else { return };
                if !kind.still_required(&current) {
                    return;
                }
                let attempts = self.entries.retry(entry).map(|r| r.attempts + 1).unwrap_or(1);
                self.merge_retry(
                    entry,
                    Self::retry_phase(kind),
                    attempts,
                    RetryTiming::Backoff,
                    job.reasons.for_retry(),
                    &job.barriers,
                );
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
                self.push_error(job.path.clone(), kind.operation(), ErrorCause::WorkerStuck);
                let Some(current) = represented else { return };
                if !kind.still_required(&current) {
                    return;
                }
                let attempts = self.entries.retry(entry).map(|r| r.attempts + 1).unwrap_or(1);
                self.merge_retry(
                    entry,
                    Self::retry_phase(kind),
                    attempts,
                    RetryTiming::Backoff,
                    job.reasons.for_retry(),
                    &job.barriers,
                );
            }
            JobOutcome::WorkerLost => {
                self.push_error(job.path.clone(), kind.operation(), ErrorCause::WorkerLost);
                let Some(current) = represented else { return };
                if !kind.still_required(&current) {
                    return;
                }
                let attempts = self.entries.retry(entry).map(|r| r.attempts + 1).unwrap_or(1);
                self.merge_retry(
                    entry,
                    Self::retry_phase(kind),
                    attempts,
                    RetryTiming::Backoff,
                    job.reasons.for_retry(),
                    &job.barriers,
                );
            }
            JobOutcome::Stale | JobOutcome::Cancelled => {
                let Some(current) = represented else { return };
                if !kind.still_required(&current) {
                    return;
                }
                let mut reasons = job.reasons;
                reasons.baseline = false;
                self.request_with(
                    entry,
                    PendingRequest {
                        path: current.path.clone(),
                        need: kind.need(),
                        reasons,
                        barriers: job.barriers.clone(),
                        designate_for_round: None,
                    },
                );
            }
        }
    }

    fn degrade_and_retry(
        &mut self,
        entry: EntryId,
        job: &ActiveJob,
        kind: ReadKind,
        cause: DegradedCause,
        timing: RetryTiming,
    ) {
        let threshold = self.config.transient_degrade_threshold;
        let attempts = self.entries.retry(entry).map(|r| r.attempts + 1).unwrap_or(1);
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
        self.merge_retry(entry, Self::retry_phase(kind), attempts, timing, job.reasons.for_retry(), &job.barriers);
    }

    fn settle_enrichment(
        &mut self,
        entry: EntryId,
        job: &ActiveJob,
        fields: crate::entry::MetadataFields,
        outcome: &JobOutcome,
    ) {
        match outcome {
            JobOutcome::Accepted => {}
            JobOutcome::Removed | JobOutcome::Cancelled => {
                self.pending_enrichment.remove(&entry);
            }
            JobOutcome::Stale => {
                let reasons = job.reasons;
                self.request_enrichment(entry, fields, reasons);
            }
            JobOutcome::Failed(err) => {
                self.enrichment_failures += 1;
                self.push_error(job.path.clone(), Operation::Metadata, err.clone());
                self.retry_enrichment(entry, job, fields);
            }
            JobOutcome::WatcherRegistrationFailed
            | JobOutcome::WorkerLost
            | JobOutcome::Stuck
            | JobOutcome::Rejected(_)
            | JobOutcome::AncestorNotDirectory
            | JobOutcome::ResultMismatch => {
                self.enrichment_failures += 1;
                self.retry_enrichment(entry, job, fields);
            }
        }
    }

    fn settle_domain(&mut self, entry: EntryId, job: &ActiveJob, outcome: &JobOutcome) {
        match outcome {
            JobOutcome::Accepted | JobOutcome::Removed => {
                self.pending_domain.remove(&entry);
            }
            JobOutcome::Stale | JobOutcome::Cancelled => {
                if self.snapshot.contains_id(entry) {
                    self.request_domain(entry, job.path.clone(), job.reasons);
                }
            }
            JobOutcome::Failed(err) => {
                self.push_error(job.path.clone(), Operation::DomainResolution, err.clone());
                self.retry_domain(entry, job);
            }
            JobOutcome::Rejected(ListingRejection::ResourceLimited(limited)) => {
                self.push_error(job.path.clone(), Operation::DomainResolution, ErrorCause::ResourceLimited(*limited));
                self.retry_domain(entry, job);
            }
            JobOutcome::Rejected(ListingRejection::MalformedNames | ListingRejection::UnresolvedChild)
            | JobOutcome::WatcherRegistrationFailed => self.retry_domain(entry, job),
            JobOutcome::AncestorNotDirectory => {
                self.push_error(job.path.clone(), Operation::DomainResolution, ErrorCause::Fs(FsError::NotDirectory));
                self.retry_domain(entry, job);
            }
            JobOutcome::ResultMismatch => {
                self.push_error(job.path.clone(), Operation::DomainResolution, ErrorCause::ResultMismatch);
                self.retry_domain(entry, job);
            }
            JobOutcome::WorkerLost => {
                self.push_error(job.path.clone(), Operation::DomainResolution, ErrorCause::WorkerLost);
                self.retry_domain(entry, job);
            }
            JobOutcome::Stuck => {
                self.push_error(job.path.clone(), Operation::DomainResolution, ErrorCause::WorkerStuck);
                self.retry_domain(entry, job);
            }
        }
    }

    fn retry_domain(&mut self, entry: EntryId, job: &ActiveJob) {
        let Some(current) = self.snapshot.get_by_id(entry).cloned() else {
            return;
        };
        if !current.is_directory() {
            self.pending_domain.remove(&entry);
            return;
        }
        let attempts = self.pending_domain.get(&entry).map(|r| r.attempts + 1).unwrap_or(1);
        let due = self.now + self.backoff(attempts);
        let mut reasons = job.reasons;
        reasons.retry = true;
        self.pending_domain
            .insert(entry, DomainRequest { path: current.path.clone(), reasons, attempts, due: Some(due) });
    }

    fn retry_enrichment(&mut self, entry: EntryId, job: &ActiveJob, fields: crate::entry::MetadataFields) {
        let Some(current) = self.snapshot.get_by_id(entry).cloned() else {
            return;
        };
        if !current.is_loaded() {
            self.pending_enrichment.remove(&entry);
            return;
        }
        self.entries.set_metadata_degraded(entry, Some(DegradedCause::Enrichment));
        let attempts = self.pending_enrichment.get(&entry).map(|r| r.attempts + 1).unwrap_or(1);
        let due = self.now + self.backoff(attempts);
        let mut reasons = job.reasons;
        reasons.retry = true;
        self.pending_enrichment
            .insert(entry, EnrichmentRequest { path: current.path.clone(), fields, reasons, attempts, due: Some(due) });
    }

    fn abandon_registration(&mut self, request: WatchRequestId) {
        if let Some(target) = self.registrations.get_mut(&request) {
            *target = target.abandon();
        }
    }

    pub(super) fn release_watch(&mut self, result: Result<WatchId, ErrorCause>) {
        if let Ok(watch) = result {
            self.emit_unwatch(watch, None);
        }
    }

    pub(super) fn on_watch_registered(&mut self, request: WatchRequestId, result: Result<WatchId, ErrorCause>) {
        let Some(target) = self.registrations.remove(&request) else {
            self.release_watch(result);
            return;
        };
        match target {
            RegistrationTarget::AbandonedStandalone => self.release_watch(result),
            RegistrationTarget::AbandonedJob(job_id) => {
                self.release_registration_slot(job_id);
                self.release_watch(result);
            }
            RegistrationTarget::Job(job_id) => {
                let Some(job) = self.jobs.get(&job_id).cloned() else {
                    self.release_registration_slot(job_id);
                    self.release_watch(result);
                    return;
                };
                if !matches!(job.phase, JobPhase::Registering(held, _) if held == request) {
                    self.release_watch(result);
                    return;
                }
                let Some(entry) = job.entry() else {
                    self.release_registration_slot(job_id);
                    self.release_watch(result);
                    return;
                };
                let is_root = job.path.is_root();
                match result {
                    Ok(watch) => {
                        self.watches.push(watch);
                        let domain = self.domain_of(entry);
                        self.entries.set_watch(entry, WatchState::Registered(watch), domain);
                        self.recover_domain_watcher(entry);
                        self.entries.advance_watch_phase(entry);
                        if is_root {
                            self.watcher_health = WatcherHealth::Healthy { backend: self.caps.watcher };
                            if self.open_gate == OpenGate::Pending {
                                self.open_gate = OpenGate::Ready;
                            }
                        }
                        self.continue_after_registration(job_id);
                    }
                    Err(err) => {
                        self.push_error(job.path.clone(), Operation::WatchRegistration, err.clone());
                        let domain = self.domain_of(entry);
                        self.entries.set_watch(entry, WatchState::Failed, domain);
                        let reason = format!("registration failed for {}: {err}", job.path);
                        self.degrade_domain_watcher(entry, reason.clone());
                        self.watcher_health = WatcherHealth::Degraded { backend: self.caps.watcher, reason };
                        match self.config.watch_registration_failure_mode {
                            WatchRegistrationFailure::ReconcileOnly => {
                                if is_root && self.open_gate == OpenGate::Pending {
                                    self.open_gate = OpenGate::Ready;
                                }
                                self.continue_after_registration(job_id);
                            }
                            WatchRegistrationFailure::RequireWatcher => {
                                if is_root && self.open_gate == OpenGate::Pending {
                                    self.open_gate = OpenGate::Failed(Error::WatcherRegistrationFailed);
                                }
                                self.release_registration_slot(job_id);
                                if let Some(job) = self.jobs.get_mut(&job_id) {
                                    job.phase = JobPhase::Queued;
                                }
                                self.finish_job(job_id, JobOutcome::WatcherRegistrationFailed);
                            }
                        }
                    }
                }
            }
            RegistrationTarget::Standalone(entry) => match result {
                Ok(watch) => {
                    if self.dir_state(entry).is_none() {
                        let domain = self.domain_of(entry);
                        self.emit_unwatch(watch, domain);
                        return;
                    }
                    let is_root = self.snapshot.get_by_id(entry).map(|e| e.path.is_root()).unwrap_or(false);
                    let domain = self.domain_of(entry);
                    self.entries.set_watch(entry, WatchState::Registered(watch), domain);
                    self.recover_domain_watcher(entry);
                    self.watches.push(watch);
                    self.entries.advance_watch_phase(entry);
                    if is_root || self.watcher_of(entry).scope == crate::domain::WatcherScope::PerDirectory {
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
                    let domain = self.domain_of(entry);
                    self.entries.set_watch(entry, WatchState::Failed, domain);
                    let reason = format!("restart failed: {err}");
                    self.degrade_domain_watcher(entry, reason.clone());
                    self.watcher_health = WatcherHealth::Degraded { backend: self.caps.watcher, reason };
                    self.watcher_restart_attempts = self.watcher_restart_attempts.saturating_add(1);
                    let delay = self.backoff(self.watcher_restart_attempts);
                    self.watcher_restart_due = Some(self.now + delay);
                }
            },
        }
    }
}
