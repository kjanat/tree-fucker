use std::sync::Arc;

use tree_fucker::testing::{FakeFileSystem, Harness};
use tree_fucker::update::RoundResult;
use tree_fucker::{EntryKind, FileSystem, LoadAll, WatcherKind};

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
