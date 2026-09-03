use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tree_fucker::testing::{CostScope, FakeFileSystem, FakeOp, Harness};
use tree_fucker::update::RoundResult;
use tree_fucker::{EntryKind, FileSystem, LoadAll, RelativePath, WatcherKind};

const BACKGROUND_DUTY_GLOBAL: f64 = 0.02;
const BACKGROUND_BURST_GLOBAL: Duration = Duration::from_millis(500);
const MAXIMUM_PERIOD: Duration = Duration::from_secs(300);

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
            let index = (self.next() as usize) % items.len();
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

fn worst_window(h: &Harness, window: Duration) -> Duration {
    let charges = h.charges();
    let mut worst = Duration::ZERO;
    let mut oldest = 0;
    let mut total = Duration::ZERO;
    for index in 0..charges.len() {
        let end = charges[index].at;
        total += charges[index].cost;
        while charges[oldest].at.0 + window <= end.0 {
            total -= charges[oldest].cost;
            oldest += 1;
        }
        worst = worst.max(total);
    }
    worst
}

fn settle(h: &mut Harness) {
    for _ in 0..50 {
        let target = h.now() + Duration::from_secs(60);
        h.run_jobs_until(target);
        if h.health().reconciliation.last_round == Some(RoundResult::Successful) && h.pending_jobs().is_empty() {
            return;
        }
    }
}

#[test]
fn random_operations_with_random_costs_converge_and_stay_within_budget() {
    let mut worst = Duration::ZERO;
    let mut worst_seed = 0;
    for seed in 1..12u64 {
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
        let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
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
                        fs.set_size_silently(&target, step as u64);
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

        let mut granted: BTreeMap<RelativePath, usize> = BTreeMap::new();
        for admission in phase_admissions {
            *granted.entry(admission.entry).or_default() += 1;
        }
        let mut performed: BTreeMap<RelativePath, usize> = BTreeMap::new();
        for (op, target) in phase_ops {
            if op == FakeOp::Watch {
                continue;
            }
            *performed.entry(target).or_default() += 1;
        }
        for (target, count) in &performed {
            let grants = granted.get(target).copied().unwrap_or(0);
            assert!(
                grants >= *count,
                "RFC 15.1 item 1: seed {seed}: {count} filesystem operations ran for {target} against \
                 {grants} logged admissions"
            );
        }

        let seed_worst = worst_window(&h, MAXIMUM_PERIOD);
        if seed_worst > worst {
            worst = seed_worst;
            worst_seed = seed;
        }
    }

    let budget =
        Duration::from_secs_f64(MAXIMUM_PERIOD.as_secs_f64() * BACKGROUND_DUTY_GLOBAL) + BACKGROUND_BURST_GLOBAL;
    assert!(
        worst <= budget,
        "RFC 15.3 with the RFC 9.2 host defaults: seed {worst_seed} charged {worst:?} of worker time over a \
         {MAXIMUM_PERIOD:?} window, above the rate times window plus burst budget of {budget:?}"
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
        let mut h = Harness::open_default(fs.clone(), Arc::new(LoadAll));
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
                        fs.set_size_silently(&target, step as u64);
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
