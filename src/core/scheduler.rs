use std::collections::{BTreeSet, HashSet};
use std::time::Duration;

use super::governor::{GrantId, Reservation};
use super::types::*;
use super::{Coordinator, JobSpec, ListingWork, Output, WatchDecision, WatchScope, Work};
use crate::domain::StorageDomainId;
use crate::entry::{LoadState, Shape};
use crate::fs::{CancellationToken, Lease};
use crate::ids::*;
use crate::update::{RoundResult, ShutdownState};

impl Coordinator {
    pub(super) fn maybe_dispatch(&mut self) {
        if self.shutdown != ShutdownState::Running || self.batch.is_some() {
            return;
        }
        let periodic = self.baseline_due;
        self.retry_capped_watches();
        self.materialize_retries();
        self.materialize_enrichment();
        self.materialize_domain_requests();
        if periodic {
            self.ensure_round();
            self.materialize_priority();
        }
        let baseline_ready = periodic && self.round.as_ref().map(|r| !r.wrapped()).unwrap_or(false);
        let expedited = self.ready_expedited();
        let expedited_ready = !expedited.is_empty() || self.probe_ready();
        let b = self.config.batch_size;
        let reservation = self.config.baseline_reservation();
        let (baseline_slots, expedited_slots) = match (baseline_ready, expedited_ready) {
            (true, true) => (reservation, b - reservation),
            (true, false) => (b, 0),
            (false, true) => (0, b),
            (false, false) => (0, 0),
        };
        let mut members: HashSet<JobId> = HashSet::new();
        let contended = baseline_slots > 0 && expedited_slots > 0;
        let baseline_first = !contended || self.dispatch_rotation.is_multiple_of(2);
        if contended {
            self.dispatch_rotation = self.dispatch_rotation.wrapping_add(1);
        }
        let mut granting = true;
        if baseline_first && baseline_slots > 0 {
            granting = self.admit_baseline(baseline_slots, &mut members);
        }
        if granting && expedited_slots > 0 {
            granting = self.admit_expedited(expedited_slots, expedited, &mut members);
        }
        if granting && !baseline_first && baseline_slots > 0 {
            self.admit_baseline(baseline_slots, &mut members);
        }
        if periodic {
            self.baseline_due = false;
        }
        if members.is_empty() {
            if periodic {
                self.complete_periodic();
            }
            return;
        }
        self.batch = Some(Batch { members, periodic });
    }

    fn try_grant(&mut self, entry: Option<EntryId>, need: ReadNeed, path: &RelativePathOwned) -> Option<JobGrant> {
        self.try_grant_on(entry, need, path).ok()
    }

    fn try_grant_on(
        &mut self,
        entry: Option<EntryId>,
        need: ReadNeed,
        path: &RelativePathOwned,
    ) -> Result<JobGrant, Denied> {
        let id = self.next_job_id;
        let decision = match entry {
            Some(entry) => self.registration_decision(entry, need),
            None => WatchDecision::NotNeeded,
        };
        let registration = match (decision, entry) {
            (WatchDecision::Register(scope), _) => Some(scope),
            (WatchDecision::Capped, Some(entry)) => {
                let domain = self.domain_of(entry);
                self.entries.set_watch(entry, WatchState::Capped, domain);
                None
            }
            (WatchDecision::Capped, None) | (WatchDecision::NotNeeded, _) => None,
        };
        let domain = entry.and_then(|e| self.domain_of(e));
        let now = self.now;
        let reservation = Reservation {
            id: GrantId::Job(id),
            path: path.clone(),
            reads: 1,
            registrations: u32::from(registration.is_some()),
            lease: 0,
            domain,
        };
        match self.governor.try_admit(reservation, now) {
            Ok(_) => {
                self.next_job_id = id.next();
                Ok(JobGrant { id, registration, domain })
            }
            Err(_) => match self.governor.global_exhausted(domain) {
                true => Err(Denied::Globally),
                false => Err(Denied::OnDomain(domain)),
            },
        }
    }

    pub(super) fn resume_sessions(&mut self) {
        if self.shutdown != ShutdownState::Running {
            return;
        }
        let mut suspended: Vec<JobId> =
            self.jobs.iter().filter(|(_, job)| job.phase == JobPhase::Suspended).map(|(id, _)| *id).collect();
        suspended.sort();
        for id in suspended {
            let Some(job) = self.jobs.get(&id).cloned() else {
                continue;
            };
            if !self.guards_valid(&job) {
                self.stale_results += 1;
                self.finish_job(id, JobOutcome::Stale);
                continue;
            }
            let now = self.now;
            let lease = job.leases;
            let domain = job.domain;
            let reservation =
                Reservation { id: GrantId::Job(id), path: job.path.clone(), reads: 1, registrations: 0, lease, domain };
            if self.governor.try_admit(reservation, now).is_err() {
                continue;
            }
            if let Some(job) = self.jobs.get_mut(&id) {
                job.phase = JobPhase::Queued;
                job.leases = job.leases.saturating_add(1);
            }
            self.queue_order.push_back(id);
        }
    }

    pub(super) fn suspend_job(&mut self, id: JobId) {
        if let Some(job) = self.jobs.get_mut(&id) {
            job.phase = JobPhase::Suspended;
        }
    }

    fn work_for(&self, job: &ActiveJob) -> Work {
        match job.need {
            ReadNeed::Listing => Work::Listing(ListingWork {
                lease: Lease { entries: self.config.entries_per_lease, operations: self.config.operations_per_lease },
                ceiling: self.config.entries_per_directory,
                cancel: job.cancel.clone(),
                resume: job.session_open,
            }),
            ReadNeed::Metadata => Work::Metadata,
            ReadNeed::Domain => Work::ResolveDomain {
                parent: job.entry().and_then(|entry| self.parent_domain_probe(entry)).map(Box::new),
            },
            ReadNeed::Enrichment(fields) => Work::Enrichment { fields },
        }
    }

    fn probe_ready(&self) -> bool {
        self.probe_job.is_none() && self.root_probe.as_ref().map(|p| p.ready(self.now)).unwrap_or(false)
    }

    fn ready_expedited(&self) -> Vec<Ready> {
        let mut domains: Vec<(crate::path::PathKey, EntryId)> = self
            .pending_domain
            .iter()
            .filter(|(id, request)| {
                !self.active_by_entry.contains_key(id) && self.snapshot.contains_id(**id) && request.ready(self.now)
            })
            .map(|(id, request)| (self.snapshot.key(&request.path), *id))
            .collect();
        domains.sort();
        let mut reads: Vec<(crate::path::PathKey, EntryId)> = self
            .pending
            .iter()
            .filter(|(id, _)| {
                !self.active_by_entry.contains_key(id)
                    && self.snapshot.contains_id(**id)
                    && !self.pending_domain.contains_key(id)
            })
            .map(|(id, request)| (self.snapshot.key(&request.path), *id))
            .collect();
        reads.sort();
        let mut enrichments: Vec<(crate::path::PathKey, EntryId)> = self
            .pending_enrichment
            .iter()
            .filter(|(id, request)| {
                !self.active_by_entry.contains_key(id)
                    && !self.pending.contains_key(id)
                    && self.snapshot.get_by_id(**id).map(|e| e.is_loaded()).unwrap_or(false)
                    && request.ready(self.now)
            })
            .map(|(id, request)| (self.snapshot.key(&request.path), *id))
            .collect();
        enrichments.sort();
        domains
            .into_iter()
            .map(|(_, id)| Ready::Domain(id))
            .chain(reads.into_iter().map(|(_, id)| Ready::Read(id)))
            .chain(enrichments.into_iter().map(|(_, id)| Ready::Enrich(id)))
            .collect()
    }

    fn materialize_domain_requests(&mut self) {
        let now = self.now;
        for request in self.pending_domain.values_mut() {
            if request.due.is_some_and(|at| at <= now) {
                request.due = None;
            }
        }
    }

    fn materialize_retries(&mut self) {
        for id in self.entries.retries_due(self.now) {
            let Some(entry) = self.snapshot.get_by_id(id).cloned() else {
                self.entries.clear_retry(id);
                continue;
            };
            self.entries.disarm_retry(id);
            let Some(record) = self.entries.retry(id) else {
                continue;
            };
            let phase = record.phase;
            let reasons = record.admission_reasons();
            let kind = phase.required_kind();
            let barriers = record.barriers.clone();
            if !kind.still_required(&entry) {
                self.entries.clear_retry(id);
                continue;
            }
            self.request(id, entry.path.clone(), kind.need(), reasons, barriers);
        }
    }

    fn materialize_enrichment(&mut self) {
        let now = self.now;
        for request in self.pending_enrichment.values_mut() {
            if request.due.is_some_and(|at| at <= now) {
                request.due = None;
            }
        }
    }

    fn materialize_priority(&mut self) {
        if self.priority.paths.is_empty() {
            return;
        }
        let loaded: Vec<EntryId> = self
            .priority
            .paths
            .iter()
            .filter_map(|path| self.snapshot.get(path).filter(|e| e.is_loaded()).map(|e| e.id))
            .collect();
        if loaded.is_empty() {
            return;
        }
        let start = self.priority.cursor % loaded.len();
        let take = self.config.batch_size.min(loaded.len());
        for offset in 0..take {
            let id = &loaded[(start + offset) % loaded.len()];
            if self.active_by_entry.contains_key(id) {
                continue;
            }
            let path = match self.snapshot.get_by_id(*id) {
                Some(e) => e.path.clone(),
                None => continue,
            };
            self.request(*id, path, ReadNeed::Listing, Reasons::priority(), Vec::new());
        }
        self.priority.cursor = (start + take) % loaded.len();
    }

    fn ensure_round(&mut self) {
        if self.round.is_some() {
            return;
        }
        let RootState::Available { .. } = self.root else {
            return;
        };
        let mut loaded: Vec<(crate::path::PathKey, EntryId, RelativePathOwned)> =
            self.snapshot.loaded_directories().map(|e| (self.snapshot.key(&e.path), e.id, e.path.clone())).collect();
        loaded.sort_by(|a, b| a.0.cmp(&b.0));
        if loaded.is_empty() {
            if self.last_round_result != Some(RoundResult::Successful) {
                self.last_round_result = Some(RoundResult::Successful);
            }
            self.last_round = Some((self.now, Duration::ZERO));
            return;
        }
        let generation = self.recon_seq.next().max(self.min_recon);
        self.recon_seq = generation;
        let barrier = self.next_seq();
        let mut obligations = Vec::with_capacity(loaded.len());
        let mut index = std::collections::HashMap::new();
        for (i, (_, id, path)) in loaded.into_iter().enumerate() {
            let load_generation = self.dir_state(id).map(|d| d.load_generation).unwrap_or_default();
            obligations.push(Obligation { entry: id, load_generation, path, state: ObligationState::Pending });
            index.insert(id, i);
        }
        self.round = Some(Round { generation, barrier, obligations, index, cursor: 0, started: self.now });
    }

    fn admit_baseline(&mut self, slots: usize, members: &mut HashSet<JobId>) -> bool {
        let mut remaining = slots;
        let mut denied: BTreeSet<Option<StorageDomainId>> = BTreeSet::new();
        let mut index = match self.round.as_ref() {
            Some(round) => round.cursor,
            None => return true,
        };
        loop {
            if remaining == 0 {
                break;
            }
            let Some(round) = self.round.as_ref() else {
                break;
            };
            if index >= round.obligations.len() {
                break;
            }
            let at_cursor = index == round.cursor;
            let obligation = round.obligations[index].clone();
            let generation = round.generation;
            let barrier = round.barrier;
            index += 1;
            if obligation.state != ObligationState::Pending {
                if at_cursor {
                    self.advance_cursor();
                }
                continue;
            }
            let dir_ok = self
                .dir_state(obligation.entry)
                .map(|d| d.load_generation == obligation.load_generation)
                .unwrap_or(false)
                && self.snapshot.get_by_id(obligation.entry).map(|e| e.is_loaded()).unwrap_or(false);
            if !dir_ok {
                self.set_obligation(obligation.entry, ObligationState::Removed);
                if at_cursor {
                    self.advance_cursor();
                }
                continue;
            }
            if let Some(job_id) = self.active_by_entry.get(&obligation.entry).copied() {
                let designatable = self
                    .jobs
                    .get(&job_id)
                    .map(|j| {
                        j.dispatch > barrier
                            && j.need == ReadNeed::Listing
                            && j.target.load_generation() == Some(obligation.load_generation)
                    })
                    .unwrap_or(false);
                if designatable {
                    if let Some(job) = self.jobs.get_mut(&job_id) {
                        job.designated = true;
                        job.recon = Some(generation);
                        job.reasons.baseline = true;
                    }
                    self.set_obligation(obligation.entry, ObligationState::Designated(job_id));
                } else {
                    let path = obligation.path.clone();
                    self.request_with(
                        obligation.entry,
                        PendingRequest {
                            path,
                            need: ReadNeed::Listing,
                            reasons: Reasons::default(),
                            barriers: Vec::new(),
                            designate_for_round: Some(generation),
                        },
                    );
                }
                if at_cursor {
                    self.advance_cursor();
                }
                continue;
            }
            let domain = self.domain_of(obligation.entry);
            if self.governor.quarantined(domain) {
                self.set_obligation(obligation.entry, ObligationState::Unsatisfied);
                if at_cursor {
                    self.advance_cursor();
                }
                continue;
            }
            if denied.contains(&domain) {
                continue;
            }
            let grant = match self.try_grant_on(Some(obligation.entry), ReadNeed::Listing, &obligation.path) {
                Ok(grant) => grant,
                Err(Denied::Globally) => return false,
                Err(Denied::OnDomain(domain)) => {
                    denied.insert(domain);
                    continue;
                }
            };
            let mut request = self.pending.remove(&obligation.entry).unwrap_or(PendingRequest {
                path: obligation.path.clone(),
                need: ReadNeed::Listing,
                reasons: Reasons::default(),
                barriers: Vec::new(),
                designate_for_round: None,
            });
            request.need = ReadNeed::Listing;
            request.reasons.baseline = true;
            request.designate_for_round = Some(generation);
            let job_id = self.admit(grant, Some(obligation.entry), request);
            members.insert(job_id);
            remaining -= 1;
            if at_cursor {
                self.advance_cursor();
            }
        }
        true
    }

    fn advance_cursor(&mut self) {
        if let Some(round) = self.round.as_mut() {
            round.cursor += 1;
        }
    }

    pub(super) fn set_obligation(&mut self, entry: EntryId, state: ObligationState) {
        if let Some(round) = self.round.as_mut()
            && let Some(obligation) = round.obligation_mut(entry)
            && !obligation.state.is_terminal()
        {
            obligation.state = state;
        }
    }

    fn admit_expedited(&mut self, slots: usize, ready: Vec<Ready>, members: &mut HashSet<JobId>) -> bool {
        let mut by_class: [Vec<Ready>; 5] = Default::default();
        for candidate in ready {
            let id = candidate.entry();
            if members.iter().any(|j| self.jobs.get(j).map(|job| job.entry() == Some(id)).unwrap_or(false)) {
                continue;
            }
            let reasons = match candidate {
                Ready::Read(id) => self.pending.get(&id).map(|request| request.reasons),
                Ready::Domain(id) => self.pending_domain.get(&id).map(|request| request.reasons),
                Ready::Enrich(id) => self.pending_enrichment.get(&id).map(|request| request.reasons),
            };
            let Some(reasons) = reasons else {
                continue;
            };
            let class = reasons.expedited_class();
            let slot = EXPEDITED_CLASSES.iter().position(|c| *c == class).unwrap_or(0);
            by_class[slot].push(candidate);
        }
        let mut probe_pending = self.probe_ready();
        let weights = [
            self.config.class_weights.control,
            self.config.class_weights.refresh,
            self.config.class_weights.watcher,
            self.config.class_weights.retry,
            self.config.class_weights.priority,
        ];
        let mut counts: [usize; 5] = [0; 5];
        for (i, list) in by_class.iter().enumerate() {
            counts[i] = list.len();
        }
        if probe_pending {
            counts[0] += 1;
        }
        let weight_sum: u64 = (0..5).filter(|i| counts[*i] > 0).map(|i| u64::from(weights[i])).sum();
        if weight_sum == 0 {
            return true;
        }
        let mut quota: [usize; 5] = [0; 5];
        let mut assigned = 0usize;
        for i in 0..5 {
            if counts[i] == 0 {
                continue;
            }
            let slots = u64::try_from(slots).unwrap_or(u64::MAX);
            let share = usize::try_from(slots.saturating_mul(u64::from(weights[i])) / weight_sum).unwrap_or(usize::MAX);
            quota[i] = share.min(counts[i]);
            assigned += quota[i];
        }
        let mut leftover = slots.saturating_sub(assigned);
        let rotation = self.class_rotation;
        let mut progress = true;
        while leftover > 0 && progress {
            progress = false;
            for step in 0..5 {
                let i = (rotation + step) % 5;
                if quota[i] < counts[i] && leftover > 0 {
                    quota[i] += 1;
                    leftover -= 1;
                    progress = true;
                }
            }
        }
        self.class_rotation = (rotation + 1) % 5;
        let mut denied: BTreeSet<Option<StorageDomainId>> = BTreeSet::new();
        for i in 0..5 {
            let mut take = quota[i];
            if i == 0
                && probe_pending
                && take > 0
                && let Some(probe) = self.root_probe.take()
            {
                match self.try_grant(None, probe.request.need, &probe.request.path) {
                    Some(grant) => {
                        let job_id = self.admit(grant, None, probe.request);
                        members.insert(job_id);
                        take -= 1;
                        probe_pending = false;
                    }
                    None => {
                        self.root_probe = Some(probe);
                        return false;
                    }
                }
            }
            for candidate in by_class[i].clone().into_iter().take(take) {
                let request = match candidate {
                    Ready::Read(id) => self.pending.get(&id).cloned(),
                    Ready::Domain(id) => self.pending_domain.get(&id).map(|request| PendingRequest {
                        path: request.path.clone(),
                        need: ReadNeed::Domain,
                        reasons: request.reasons,
                        barriers: Vec::new(),
                        designate_for_round: None,
                    }),
                    Ready::Enrich(id) => self.pending_enrichment.get(&id).map(|request| PendingRequest {
                        path: request.path.clone(),
                        need: ReadNeed::Enrichment(request.fields),
                        reasons: request.reasons,
                        barriers: Vec::new(),
                        designate_for_round: None,
                    }),
                };
                let Some(request) = request else {
                    continue;
                };
                let id = candidate.entry();
                if denied.contains(&self.domain_of(id)) {
                    continue;
                }
                let grant = match self.try_grant_on(Some(id), request.need, &request.path) {
                    Ok(grant) => grant,
                    Err(Denied::Globally) => return false,
                    Err(Denied::OnDomain(domain)) => {
                        denied.insert(domain);
                        continue;
                    }
                };
                match candidate {
                    Ready::Read(id) => {
                        self.pending.remove(&id);
                    }
                    Ready::Domain(id) => {
                        self.pending_domain.remove(&id);
                    }
                    Ready::Enrich(id) => {
                        self.pending_enrichment.remove(&id);
                    }
                }
                let job_id = self.admit(grant, Some(id), request);
                members.insert(job_id);
            }
        }
        true
    }

    fn admit(&mut self, grant: JobGrant, entry: Option<EntryId>, request: PendingRequest) -> JobId {
        let id = grant.id;
        let dispatch = self.next_seq();
        let mut reasons = request.reasons;
        let mut barriers = request.barriers;
        if let Some(entry_id) = entry {
            if let Some(kind) = request.need.kind() {
                self.merge_retry_record(entry_id, kind, &mut reasons, &mut barriers);
            }
            if reasons.initial_scan {
                self.initial_scan.revive(entry_id);
            }
        }
        let mut designated = false;
        let mut recon = None;
        if let (Some(entry_id), Some(round)) = (entry, self.round.as_ref())
            && request.need == ReadNeed::Listing
            && dispatch > round.barrier
            && let Some(obligation) = round.index.get(&entry_id).and_then(|i| round.obligations.get(*i))
        {
            let load_ok =
                self.dir_state(entry_id).map(|d| d.load_generation == obligation.load_generation).unwrap_or(false);
            if load_ok && matches!(obligation.state, ObligationState::Pending | ObligationState::Designated(_)) {
                recon = Some(round.generation);
                if request.designate_for_round == Some(round.generation) && obligation.state == ObligationState::Pending
                {
                    designated = true;
                }
            }
        }
        if designated {
            reasons.baseline = true;
        }
        let target = match entry {
            Some(entry_id) => JobTarget::Entry { id: entry_id, guards: self.capture_guards(entry_id, request.need) },
            None => JobTarget::RootProbe { expected_unavailable: self.root.incarnation() },
        };
        let phase = match (grant.registration, entry) {
            (Some(scope), Some(entry_id)) => {
                let req = self.next_watch_request();
                self.registrations.insert(req, RegistrationTarget::Job(id));
                let recursive = scope.is_recursive();
                self.hold_watch_path(entry_id);
                self.outputs.push(Output::RegisterWatch { request: req, path: request.path.clone(), recursive });
                JobPhase::Registering(req)
            }
            (Some(_), None) | (None, _) => JobPhase::Queued,
        };
        let job = ActiveJob {
            id,
            target,
            path: request.path,
            domain: grant.domain,
            need: request.need,
            phase,
            dispatch,
            recon,
            reasons,
            barriers,
            designated,
            cancel: CancellationToken::new(),
            leases: 1,
            session_open: false,
        };
        if let Some(entry_id) = entry {
            self.active_by_entry.insert(entry_id, id);
            self.entry_state_mut(entry_id).latest_dispatch = Some(dispatch);
            if designated {
                self.set_obligation(entry_id, ObligationState::Designated(id));
            }
        } else {
            self.probe_job = Some(id);
        }
        if phase == JobPhase::Queued {
            self.queue_order.push_back(id);
        }
        self.jobs.insert(id, job);
        id
    }

    fn merge_retry_record(&self, entry: EntryId, kind: ReadKind, reasons: &mut Reasons, barriers: &mut Vec<CommandId>) {
        let Some(record) = self.entries.retry(entry) else {
            return;
        };
        if kind < record.phase.required_kind() {
            return;
        }
        reasons.merge(record.reasons);
        for barrier in &record.barriers {
            if !barriers.contains(barrier) {
                barriers.push(*barrier);
            }
        }
    }

    fn registration_decision(&self, entry: EntryId, need: ReadNeed) -> WatchDecision {
        if need != ReadNeed::Listing {
            return WatchDecision::NotNeeded;
        }
        if self.snapshot.get_by_id(entry).map(|e| e.shape) != Some(Shape::Directory(LoadState::Loading)) {
            return WatchDecision::NotNeeded;
        }
        self.watch_decision(entry)
    }

    pub(super) fn capture_guards(&self, entry: EntryId, need: ReadNeed) -> Guards {
        let e = self.snapshot.get_by_id(entry);
        let parent = self.parent_of(entry);
        let state = self.entries.get(entry);
        Guards {
            incarnation: self.root.incarnation(),
            entry_generation: e.map(|e| e.generation).unwrap_or_default(),
            load_generation: state.and_then(|s| s.dir()).map(|d| d.load_generation),
            policy_revision: self.policy.revision(),
            policy_fence: self.policy_fence,
            parent_context: parent.and_then(|p| self.dir_state(p)).map(|d| d.context_generation),
            child_state: if need.observes_children() {
                state.and_then(|s| s.dir()).map(|d| d.child_state)
            } else {
                None
            },
            parent_child_state: parent.and_then(|p| self.dir_state(p)).map(|d| d.child_state),
            entry_state: state.map(|s| s.state_generation).unwrap_or_default(),
            change_epoch: state.map(|s| s.change_epoch).unwrap_or_default(),
        }
    }

    pub(super) fn guards_valid(&self, job: &ActiveJob) -> bool {
        match job.target {
            JobTarget::Entry { id, guards } => {
                if guards.incarnation != self.root.incarnation() {
                    return false;
                }
                if !self.snapshot.contains_id(id) {
                    return false;
                }
                let current = self.capture_guards(id, job.need);
                current == guards && self.entries.get(id).and_then(|s| s.latest_dispatch) == Some(job.dispatch)
            }
            JobTarget::RootProbe { expected_unavailable } => match self.root {
                RootState::Unavailable { last } => expected_unavailable == last,
                RootState::Available { .. } => false,
            },
        }
    }

    pub(super) fn start_queued(&mut self) {
        if self.shutdown != ShutdownState::Running {
            return;
        }
        let mut deferred: Vec<JobId> = Vec::new();
        loop {
            if self.blocking_slots.len() >= self.config.max_in_flight {
                break;
            }
            let Some(id) = self.queue_order.pop_front() else {
                break;
            };
            let Some(job) = self.jobs.get(&id) else {
                continue;
            };
            if job.phase != JobPhase::Queued {
                continue;
            }
            if !self.guards_valid(job) {
                self.cancel_job(id);
                continue;
            }
            let domain = job.domain;
            if self.governor.may_start(domain, self.blocking_slots.len()).is_err() {
                deferred.push(id);
                continue;
            }
            let Some(job) = self.jobs.get(&id) else {
                continue;
            };
            let work = self.work_for(job);
            let now = self.now;
            if let Some(job) = self.jobs.get_mut(&id) {
                job.phase = JobPhase::Running(now);
            }
            self.governor.start(GrantId::Job(id), now);
            self.dispatch_job(id, work);
        }
        for id in deferred.into_iter().rev() {
            self.queue_order.push_front(id);
        }
    }

    pub(super) fn dispatch_job(&mut self, id: JobId, work: Work) {
        let Some(job) = self.jobs.get(&id) else {
            return;
        };
        let Some(started) = job.phase.started() else {
            return;
        };
        let path = job.path.clone();
        let spec = JobSpec { id, path: path.clone(), work };
        let operation = spec.operation();
        self.blocking_slots.insert(id, Occupancy { path, operation, started });
        self.outputs.push(Output::StartJob(spec));
    }

    pub(super) fn job_terminal(&mut self, id: JobId) {
        let Some(batch) = self.batch.as_mut() else {
            return;
        };
        batch.members.remove(&id);
        if batch.members.is_empty() {
            let periodic = batch.periodic;
            self.batch = None;
            if periodic {
                self.complete_periodic();
            }
        }
    }

    pub(super) fn complete_periodic(&mut self) {
        let interval = self.config.fixed_interval.unwrap_or(self.config.minimum_period);
        self.periodic_due = self.now + interval;
    }

    pub(super) fn check_round_end(&mut self) {
        let Some(round) = self.round.as_ref() else {
            return;
        };
        if !round.wrapped() || !round.all_terminal() {
            return;
        }
        let unsatisfied: std::collections::BTreeSet<RelativePathOwned> = round
            .obligations
            .iter()
            .filter(|o| o.state == ObligationState::Unsatisfied)
            .map(|o| o.path.clone())
            .collect();
        let generation = round.generation;
        let started = round.started;
        let accepted: Vec<EntryId> =
            round.obligations.iter().filter(|o| o.state == ObligationState::Accepted).map(|o| o.entry).collect();
        for entry in accepted {
            self.entries.mark_covered(entry, generation);
        }
        self.last_round = Some((started, self.now.since(started)));
        self.last_round_result =
            Some(if unsatisfied.is_empty() { RoundResult::Successful } else { RoundResult::Degraded { unsatisfied } });
        self.round = None;
    }

    pub(super) fn cancel_job(&mut self, id: JobId) {
        self.finish_job(id, JobOutcome::Cancelled);
    }
}

type RelativePathOwned = crate::path::RelativePath;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Denied {
    Globally,
    OnDomain(Option<StorageDomainId>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct JobGrant {
    pub id: JobId,
    pub registration: Option<WatchScope>,
    pub domain: Option<StorageDomainId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ready {
    Read(EntryId),
    Domain(EntryId),
    Enrich(EntryId),
}

impl Ready {
    fn entry(self) -> EntryId {
        match self {
            Ready::Read(id) | Ready::Domain(id) | Ready::Enrich(id) => id,
        }
    }
}
