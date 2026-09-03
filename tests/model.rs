use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tree_fucker::core::JobOperation;
use tree_fucker::testing::{CostScope, DomainId, FailureMode, FakeFileSystem, FakeOp, Harness};
use tree_fucker::update::RoundResult;
use tree_fucker::{
    Config, DomainCapabilities, DomainCrossing, EntryKind, FileSystem, FsError, KindSource, LoadAll, MetadataFields,
    MetadataSource, MetadataSources, RelativePath, WatcherKind,
};

const BACKGROUND_DUTY_GLOBAL: f64 = 0.02;
const BACKGROUND_BURST_GLOBAL: Duration = Duration::from_millis(500);
const MAXIMUM_PERIOD: Duration = Duration::from_secs(300);
const INITIAL_COST_ESTIMATE: Duration = Duration::from_millis(20);
const DEFAULT_CHUNK: usize = 1024;

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            None
        } else {
            let index = usize::try_from(self.next()).unwrap_or(usize::MAX) % items.len();
            items.get(index)
        }
    }
}

fn reachable(fs: &FakeFileSystem, name: &str) -> Option<EntryKind> {
    fs.metadata(fs.root(), &FakeFileSystem::path(name)).ok().map(|i| i.kind)
}

fn directories(fs: &FakeFileSystem, names: &[String]) -> Vec<String> {
    let mut dirs = vec![String::new()];
    for name in names {
        if reachable(fs, name) == Some(EntryKind::Directory) {
            dirs.push(name.clone());
        }
    }
    dirs
}

fn envelope(duty: f64, burst: Duration, window: Duration) -> Duration {
    Duration::from_secs_f64(window.as_secs_f64() * duty) + burst
}

fn settle(h: &mut Harness) {
    for _ in 0..200 {
        let target = h.now() + Duration::from_secs(60);
        h.run_jobs_until(target);
        if h.health().reconciliation.last_round == Some(RoundResult::Successful) && h.pending_jobs().is_empty() {
            return;
        }
    }
}

struct Run {
    harness: Harness,
    fs: Arc<FakeFileSystem>,
    known: Vec<String>,
    phase_ops: Vec<(FakeOp, RelativePath)>,
    phase_admissions: Vec<tree_fucker::testing::Admission>,
}

fn chunked() -> Config {
    Config { entries_per_lease: 2, operations_per_lease: 2, ..Default::default() }
}

fn random_history(seed: u64) -> Run {
    random_history_with(seed, Config::default(), DEFAULT_CHUNK)
}

fn random_history_with(seed: u64, config: Config, chunk: usize) -> Run {
    let mut rng = Lcg(seed);
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.set_cost(CostScope::Everything, FakeOp::ReadDir, Duration::from_millis(5 + seed * 3));
    fs.set_cost(CostScope::Everything, FakeOp::Metadata, Duration::from_millis(1 + seed));
    let mut known: Vec<String> = Vec::new();
    for i in 0..6 {
        let name = format!("d{i}");
        fs.mkdir(&name);
        fs.set_cost(CostScope::path(&name), FakeOp::ReadDir, Duration::from_millis(1 + rng.next() % 40));
        known.push(name.clone());
        let file = format!("{name}/f");
        fs.create_file(&file, 1);
        known.push(file);
    }
    fs.set_chunk_size(chunk);
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    fs.clear_ops();
    settle(&mut h);
    for step in 0..40 {
        let dirs = directories(&fs, &known);
        let dir = rng.pick(&dirs).cloned().unwrap_or_default();
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        match rng.next() % 5 {
            0 => {
                let name = format!("{prefix}n{step}");
                fs.add_silently(&name, EntryKind::File);
                known.push(name);
            }
            1 => {
                let name = format!("{prefix}sub{step}");
                fs.add_silently(&name, EntryKind::Directory);
                fs.set_cost(CostScope::path(&name), FakeOp::ReadDir, Duration::from_millis(1 + rng.next() % 40));
                known.push(name);
            }
            2 => {
                if let Some(victim) = rng.pick(&known).cloned() {
                    fs.remove_silently(&victim);
                }
            }
            3 => {
                if let Some(target) = rng.pick(&known).cloned()
                    && reachable(&fs, &target).is_some()
                {
                    fs.set_size_silently(&target, u64::try_from(step).unwrap_or(u64::MAX));
                }
            }
            _ => {
                if step % 7 == 0 {
                    let target = h.now() + Duration::from_secs(30);
                    h.run_jobs_until(target);
                }
            }
        }
    }
    h.run_until_idle();
    let admitted_before = h.admissions().len();
    fs.clear_ops();
    settle(&mut h);
    let phase_ops = fs.ops();
    let phase_admissions = h.admissions().split_off(admitted_before);
    Run { harness: h, fs, known, phase_ops, phase_admissions }
}

#[test]
fn random_operations_with_random_costs_converge_on_the_filesystem() {
    for seed in 1..12u64 {
        let run = random_history(seed);
        assert_eq!(run.harness.health().reconciliation.last_round, Some(RoundResult::Successful), "seed {seed}");
        let mut expected: Vec<String> = Vec::new();
        for name in &run.known {
            if reachable(&run.fs, name).is_some() {
                expected.push(name.clone());
            }
        }
        expected.push(".".into());
        expected.sort();
        expected.dedup();
        let mut actual = run.harness.paths();
        actual.sort();
        assert_eq!(actual, expected, "seed {seed}");
    }
}

#[test]
fn every_filesystem_operation_in_a_random_history_holds_a_logged_admission() {
    for seed in 1..12u64 {
        let run = random_history(seed);
        let mut granted: BTreeMap<RelativePath, usize> = BTreeMap::new();
        for admission in &run.phase_admissions {
            *granted.entry(admission.entry.clone()).or_default() += 1;
        }
        let mut performed: BTreeMap<RelativePath, usize> = BTreeMap::new();
        for (op, target) in &run.phase_ops {
            if *op == FakeOp::Watch {
                continue;
            }
            *performed.entry(target.clone()).or_default() += 1;
        }
        for (target, count) in &performed {
            let grants = granted.get(target).copied().unwrap_or(0);
            assert!(
                grants >= *count,
                "RFC 15.1 item 1: seed {seed}: {count} filesystem operations ran for {target} against \
                 {grants} logged admissions"
            );
        }
    }
}

#[test]
fn reserved_worker_time_over_every_window_of_a_random_history_stays_within_the_envelope() {
    let budget = envelope(BACKGROUND_DUTY_GLOBAL, BACKGROUND_BURST_GLOBAL, MAXIMUM_PERIOD);
    let mut worst = Duration::ZERO;
    let mut worst_seed = 0;
    let mut worst_shape = "whole listings";
    for seed in 1..12u64 {
        for (shape, config, chunk) in
            [("whole listings", Config::default(), DEFAULT_CHUNK), ("chunked listings", chunked(), 1)]
        {
            let run = random_history_with(seed, config, chunk);
            let (_, seed_worst) = run.harness.worst_reserved_window(MAXIMUM_PERIOD);
            if seed_worst > worst {
                worst = seed_worst;
                worst_seed = seed;
                worst_shape = shape;
            }
        }
    }
    assert!(
        worst <= budget,
        "RFC 15.3 with the RFC 9.2 host defaults: seed {worst_seed} over {worst_shape} reserved {worst:?} of \
         worker time at admission over a {MAXIMUM_PERIOD:?} window, above the rate times window plus burst \
         budget of {budget:?}"
    );
}

#[test]
fn chunked_listings_in_a_random_history_converge_and_hold_a_lease_for_every_operation() {
    for seed in 1..8u64 {
        let run = random_history_with(seed, chunked(), 1);
        assert_eq!(
            run.harness.health().reconciliation.last_round,
            Some(RoundResult::Successful),
            "RFC 5.2 and 10.2: chunked, leased listings must still converge; seed {seed}"
        );
        let mut expected: Vec<String> = Vec::new();
        for name in &run.known {
            if reachable(&run.fs, name).is_some() {
                expected.push(name.clone());
            }
        }
        expected.push(".".into());
        expected.sort();
        expected.dedup();
        let mut actual = run.harness.paths();
        actual.sort();
        assert_eq!(actual, expected, "seed {seed}");

        let mut granted: BTreeMap<RelativePath, usize> = BTreeMap::new();
        for admission in &run.phase_admissions {
            *granted.entry(admission.entry.clone()).or_default() += 1;
        }
        let mut performed: BTreeMap<RelativePath, usize> = BTreeMap::new();
        for (op, target) in &run.phase_ops {
            if *op == FakeOp::Watch {
                continue;
            }
            *performed.entry(target.clone()).or_default() += 1;
        }
        for (target, count) in &performed {
            let grants = granted.get(target).copied().unwrap_or(0);
            assert!(
                grants >= *count,
                "RFC 15.1 item 1 and 10.2: seed {seed}: {count} filesystem operations ran for {target} against \
                 {grants} logged grants, so an operation ran without a grant or a lease"
            );
        }
        assert!(
            run.harness.stats().lease_grants > 0,
            "seed {seed} took no further lease, so the chunked property was never tested"
        );
    }
}

#[test]
fn actual_occupancy_of_a_random_history_is_charged_in_full() {
    for seed in 1..12u64 {
        let run = random_history(seed);
        let occupied = run.harness.charged_work();
        let charged = run.harness.governor().charged;
        assert!(
            charged >= occupied,
            "RFC 15.3: seed {seed}: workers occupied {occupied:?} of blocking time against {charged:?} \
             charged to the background bucket"
        );
    }
}

#[test]
fn an_underestimated_listing_charges_its_overshoot_as_debt() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("slow");
    fs.set_cost(CostScope::path("slow"), FakeOp::ReadDir, Duration::from_secs(30));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    let target = h.now() + Duration::from_secs(60);
    h.run_jobs_until(target);

    let view = h.governor();
    assert!(
        view.charged >= Duration::from_secs(30),
        "RFC 15.2: a listing that occupied 30s against a {INITIAL_COST_ESTIMATE:?} estimate must be charged \
         its occupancy in full; the bucket was charged {:?}",
        view.charged
    );
    assert!(
        view.debt > Duration::from_secs(25),
        "RFC 15.3: the overshoot beyond the reservation must appear as debt; the bucket reports {:?}",
        view.debt
    );
}

#[test]
fn a_bucket_in_debt_admits_nothing_until_the_debt_is_repaid() {
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.mkdir("slow");
    fs.mkdir("quick");
    fs.set_cost(CostScope::path("slow"), FakeOp::ReadDir, Duration::from_secs(30));
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), Config::default()).expect("open");
    let target = h.now() + Duration::from_secs(60);
    h.run_jobs_until(target);
    assert!(h.governor().debt > Duration::ZERO, "the slow listing left no debt to observe");

    let indebted_at = h.now();
    let repaid_at = h.governor().next_admissible.expect("a bucket in debt names its refill time");
    assert!(repaid_at > indebted_at, "a bucket in debt reported an immediate refill time");
    let target = repaid_at.saturating_sub(indebted_at) / 2;
    let target = indebted_at + target;
    h.run_jobs_until(target);
    let admitted: Vec<_> = h.admissions().into_iter().filter(|a| a.at > indebted_at && a.at <= target).collect();
    assert!(
        admitted.is_empty(),
        "RFC 15.3: no further admission may occur while the bucket is in debt; {} jobs were admitted between \
         {indebted_at:?} and {target:?}",
        admitted.len()
    );

    let target = repaid_at + Duration::from_secs(60);
    h.run_jobs_until(target);
    let admitted: Vec<_> = h.admissions().into_iter().filter(|a| a.at > indebted_at).collect();
    assert!(
        !admitted.is_empty(),
        "RFC 5.2: convergence must resume once the bucket refills; nothing was admitted by {target:?}"
    );

    assert!(h.governor().denials > 0, "the history recorded no denial, so contiguity was never tested");
    let mut ids: Vec<u64> = h.admissions().iter().map(|a| a.job.get()).collect();
    ids.sort_unstable();
    ids.dedup();
    let expected: Vec<u64> = (1..=u64::try_from(ids.len()).unwrap_or(u64::MAX)).collect();
    assert_eq!(
        ids, expected,
        "RFC 15.3: governor denial is not an admission outcome, so a denied job must consume no JobId; the          admitted ids have holes"
    );
}

#[test]
fn random_silent_mutations_converge_after_successful_round() {
    for seed in 1..12u64 {
        let mut rng = Lcg(seed);
        let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
        let mut known: Vec<String> = Vec::new();
        for i in 0..6 {
            let name = format!("d{i}");
            fs.mkdir(&name);
            known.push(name.clone());
            let file = format!("{name}/f");
            fs.create_file(&file, 1);
            known.push(file);
        }
        let config =
            Config { metadata_fields: MetadataFields { size: true, ..MetadataFields::NONE }, ..Default::default() };
        let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
        h.run_until_idle();
        for step in 0..40 {
            let dirs = directories(&fs, &known);
            let dir = rng.pick(&dirs).cloned().unwrap_or_default();
            let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
            match rng.next() % 5 {
                0 => {
                    let name = format!("{prefix}n{step}");
                    fs.add_silently(&name, EntryKind::File);
                    known.push(name);
                }
                1 => {
                    let name = format!("{prefix}sub{step}");
                    fs.add_silently(&name, EntryKind::Directory);
                    known.push(name);
                }
                2 => {
                    if let Some(victim) = rng.pick(&known).cloned() {
                        fs.remove_silently(&victim);
                    }
                }
                3 => {
                    if let Some(target) = rng.pick(&known).cloned()
                        && reachable(&fs, &target).is_some()
                    {
                        fs.set_size_silently(&target, u64::try_from(step).unwrap_or(u64::MAX));
                    }
                }
                _ => {
                    if step % 7 == 0 {
                        h.run_round();
                    }
                }
            }
        }
        for _ in 0..50 {
            h.run_round();
            if h.health().reconciliation.last_round == Some(RoundResult::Successful) && h.pending_jobs().is_empty() {
                break;
            }
        }
        h.run_round();
        assert_eq!(h.health().reconciliation.last_round, Some(RoundResult::Successful), "seed {seed}");
        let mut expected: Vec<String> = Vec::new();
        for name in &known {
            if reachable(&fs, name).is_some() {
                expected.push(name.clone());
            }
        }
        expected.push(".".into());
        expected.sort();
        expected.dedup();
        let mut actual = h.paths();
        actual.sort();
        assert_eq!(actual, expected, "seed {seed}");
        for name in &known {
            if let Some(entry) = h.entry(name) {
                let info = fs.metadata(fs.root(), &FakeFileSystem::path(name)).expect("exists");
                assert_eq!(entry.metadata.size, info.metadata.size, "size of {name} seed {seed}");
                assert_eq!(entry.kind(), info.kind, "kind of {name} seed {seed}");
            }
        }
    }
}

fn enrichment_history(seed: u64) -> (Harness, Arc<FakeFileSystem>, Vec<String>) {
    let mut rng = Lcg(seed);
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    fs.set_default_capabilities(DomainCapabilities {
        kind_source: KindSource::Sometimes,
        metadata_sources: MetadataSources { size: MetadataSource::PerChildRead, ..MetadataSources::INLINE },
        ..DomainCapabilities::inline()
    });
    let mut known: Vec<String> = Vec::new();
    for i in 0..6 {
        let name = format!("d{i}");
        fs.mkdir(&name);
        known.push(name.clone());
        let file = format!("{name}/f");
        fs.create_file(&file, 1);
        known.push(file);
    }
    let config =
        Config { metadata_fields: MetadataFields { size: true, ..MetadataFields::NONE }, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    for step in 0..40 {
        let dirs = directories(&fs, &known);
        let dir = rng.pick(&dirs).cloned().unwrap_or_default();
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        match rng.next() % 6 {
            0 => {
                let name = format!("{prefix}n{step}");
                fs.add_silently(&name, EntryKind::File);
                known.push(name);
            }
            1 => {
                let name = format!("{prefix}sub{step}");
                fs.add_silently(&name, EntryKind::Directory);
                known.push(name);
            }
            2 => {
                if let Some(victim) = rng.pick(&known).cloned() {
                    fs.remove_silently(&victim);
                }
            }
            3 => {
                if let Some(target) = rng.pick(&known).cloned() {
                    fs.fail(&target, FakeOp::Enrich, FailureMode::Times(2, FsError::Transient("enrich".into())));
                }
            }
            4 => {
                if let Some(target) = rng.pick(&known).cloned()
                    && reachable(&fs, &target).is_some()
                {
                    fs.report_unknown_kind(&target);
                }
            }
            _ => {
                if step % 13 == 0 {
                    h.run_round();
                }
            }
        }
    }
    (h, fs, known)
}

#[test]
fn enrichment_never_changes_membership_and_is_never_required_for_round_success() {
    for seed in 1..6u64 {
        let (mut h, fs, known) = enrichment_history(seed);
        fs.clear_failures();
        for _ in 0..50 {
            h.run_round();
            if h.health().reconciliation.last_round == Some(RoundResult::Successful) && h.pending_jobs().is_empty() {
                break;
            }
        }
        h.run_round();
        assert_eq!(
            h.health().reconciliation.last_round,
            Some(RoundResult::Successful),
            "RFC 10.1 and 5.1: round success is a membership property, so a pending or failed enrichment must \
             never keep a round from succeeding; seed {seed}"
        );

        let mut expected: Vec<String> = Vec::new();
        for name in &known {
            if reachable(&fs, name).is_some() {
                expected.push(name.clone());
            }
        }
        expected.push(".".into());
        expected.sort();
        expected.dedup();
        let mut actual = h.paths();
        actual.sort();
        assert_eq!(actual, expected, "seed {seed}");

        let membership = h.paths();
        h.run_until_idle();
        assert_eq!(
            h.paths(),
            membership,
            "RFC 10.1: enrichment is separately admitted metadata work and must never change membership; seed {seed}"
        );
        assert!(h.stats().enrichments > 0, "seed {seed} exercised no enrichment, so the property was never tested");
    }
}

fn domained_history(seed: u64) -> (Harness, Arc<FakeFileSystem>, Vec<String>) {
    let mut rng = Lcg(seed);
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::None));
    let mut known: Vec<String> = Vec::new();
    for i in 0..6 {
        let name = format!("d{i}");
        fs.mkdir(&name);
        known.push(name.clone());
        let file = format!("{name}/f");
        fs.create_file(&file, 1);
        known.push(file);
    }
    for (index, domain) in [(1u64, DomainId::new(11)), (3, DomainId::new(13)), (5, DomainId::new(15))] {
        fs.set_domain(&format!("d{index}"), domain);
        fs.set_cost(CostScope::Domain(domain), FakeOp::ReadDir, Duration::from_millis(1 + index * 4));
        fs.set_identity_space(domain, index);
    }
    fs.report_inline_domains(seed.is_multiple_of(2));
    let config = Config { domain_crossing: DomainCrossing::Follow, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    for step in 0..40 {
        let dirs = directories(&fs, &known);
        let dir = rng.pick(&dirs).cloned().unwrap_or_default();
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        match rng.next() % 5 {
            0 => {
                let name = format!("{prefix}n{step}");
                fs.add_silently(&name, EntryKind::File);
                known.push(name);
            }
            1 => {
                let name = format!("{prefix}sub{step}");
                fs.add_silently(&name, EntryKind::Directory);
                known.push(name);
            }
            2 => {
                if let Some(victim) = rng.pick(&known).cloned() {
                    fs.remove_silently(&victim);
                }
            }
            3 => {
                if reachable(&fs, "d3") == Some(EntryKind::Directory) && step % 11 == 0 {
                    fs.remount("d3", DomainId::new(23));
                }
            }
            _ => {
                if step % 7 == 0 {
                    h.run_round();
                }
            }
        }
    }
    for _ in 0..50 {
        h.run_round();
        if h.health().reconciliation.last_round == Some(RoundResult::Successful) && h.pending_jobs().is_empty() {
            break;
        }
    }
    h.run_round();
    (h, fs, known)
}

#[test]
fn a_random_history_over_several_domains_converges_and_every_operation_carries_a_domain() {
    for seed in 1..6u64 {
        let (h, fs, known) = domained_history(seed);
        assert_eq!(
            h.health().reconciliation.last_round,
            Some(RoundResult::Successful),
            "RFC 5.2 and 14.3: a tree spanning several storage domains must still converge; seed {seed}"
        );
        let mut expected: Vec<String> = Vec::new();
        for name in &known {
            if reachable(&fs, name).is_some() {
                expected.push(name.clone());
            }
        }
        expected.push(".".into());
        expected.sort();
        expected.dedup();
        let mut actual = h.paths();
        actual.sort();
        assert_eq!(actual, expected, "seed {seed}");

        for admission in h.admissions() {
            assert!(
                admission.domain.is_some()
                    || admission.operation == JobOperation::DomainResolution
                    || admission.entry.is_root(),
                "RFC 11.4: every job captures its storage domain; seed {seed} admitted {:?} for {} without one",
                admission.operation,
                admission.entry
            );
        }
        let domains = h.stats().domains;
        assert!(
            domains.len() >= 4,
            "seed {seed} entered {} domains, too few to exercise several domains in one tree",
            domains.len()
        );
        assert!(
            domains.iter().all(|domain| domain.granted > Duration::ZERO),
            "RFC 16: every domain entered must report the worker time granted against it; seed {seed} reports \
             {domains:?}"
        );
    }
}

fn watched_history(seed: u64, limit: usize) -> (Harness, Arc<FakeFileSystem>, Vec<String>, usize) {
    let mut rng = Lcg(seed);
    let fs = Arc::new(FakeFileSystem::new(WatcherKind::NonRecursive));
    let mut known: Vec<String> = Vec::new();
    for i in 0..6 {
        let name = format!("d{i}");
        fs.mkdir(&name);
        known.push(name.clone());
        let file = format!("{name}/f");
        fs.create_file(&file, 1);
        known.push(file);
    }
    for (index, domain) in [(1u64, DomainId::new(31)), (4, DomainId::new(34))] {
        fs.set_domain(&format!("d{index}"), domain);
        fs.set_identity_space(domain, index);
    }
    let config = Config { watcher_path_limit: limit, domain_crossing: DomainCrossing::Follow, ..Default::default() };
    let mut h = Harness::open(fs.clone(), Arc::new(LoadAll), config).expect("open");
    h.run_until_idle();
    let mut worst = h.stats().paths_watched;
    for step in 0..40 {
        let dirs = directories(&fs, &known);
        let dir = rng.pick(&dirs).cloned().unwrap_or_default();
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        match rng.next() % 6 {
            0 => {
                let name = format!("{prefix}sub{step}");
                fs.mkdir(&name);
                known.push(name);
            }
            1 => {
                let name = format!("{prefix}n{step}");
                fs.create_file(&name, 1);
                known.push(name);
            }
            2 => {
                if let Some(victim) = rng.pick(&known).cloned() {
                    fs.remove(&victim);
                }
            }
            3 => {
                if step % 9 == 0 {
                    fs.emit_watcher_failure("backend restarted");
                }
            }
            4 => {
                if step % 5 == 0 {
                    fs.emit_watcher_failure_under("d1", "mount watcher gone");
                }
            }
            _ => {
                h.run_round();
            }
        }
        h.run_until_idle();
        worst = worst.max(h.stats().paths_watched);
    }
    for _ in 0..50 {
        h.run_round();
        h.run_until_idle();
        worst = worst.max(h.stats().paths_watched);
        if h.health().reconciliation.last_round == Some(RoundResult::Successful) && h.pending_jobs().is_empty() {
            break;
        }
    }
    (h, fs, known, worst)
}

#[test]
fn watch_registrations_in_a_random_history_never_exceed_the_cap_and_every_one_holds_a_grant() {
    for seed in 1..8u64 {
        let limit = 3 + usize::try_from(seed % 4).unwrap_or(0);
        let (h, fs, known, worst) = watched_history(seed, limit);
        assert!(
            worst <= limit,
            "RFC 9.2 and 10.4: the configured watcher path limit bounds the registered watch paths per tree; \
             seed {seed} held {worst} of a limit of {limit}"
        );
        let performed =
            u64::try_from(fs.ops().iter().filter(|(op, _)| *op == FakeOp::Watch).count()).unwrap_or(u64::MAX);
        let granted = h.governor().watch_registration_grants;
        assert!(performed > 0, "seed {seed} registered no watch, so the property was never tested");
        assert!(
            granted >= performed,
            "RFC 15.1 item 1: seed {seed} performed {performed} watch registrations against {granted} governor \
             grants"
        );

        let stats = h.stats();
        assert!(
            stats.paths_watched <= limit && stats.paths_watched <= stats.watcher_path_limit,
            "RFC 10.4: seed {seed} settled holding {} watch paths under a limit of {limit}",
            stats.paths_watched
        );
        for domain in &stats.domains {
            assert!(
                domain.paths_watched <= limit,
                "RFC 10.4: seed {seed}: domain {} holds {} watch paths, above the tree cap of {limit}",
                domain.id,
                domain.paths_watched
            );
        }

        let mut expected: Vec<String> = Vec::new();
        for name in &known {
            if reachable(&fs, name).is_some() {
                expected.push(name.clone());
            }
        }
        expected.push(".".into());
        expected.sort();
        expected.dedup();
        let mut actual = h.paths();
        actual.sort();
        assert_eq!(
            actual, expected,
            "RFC 5.2 and 10.4: a tree whose watcher cap leaves directories unwatched must still converge; seed {seed}"
        );
    }
}
