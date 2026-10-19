use std::hint::black_box;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

// Kept local to each repository so its probes never require the sibling
// checkout.
pub fn inventory(root: &Path, size: bool) -> Vec<PathBuf> {
    let mut rows = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                stack.push(entry.path());
            }
            if !size || (kind.is_file() && entry.metadata().unwrap().len() > 1_000_000) {
                rows.push(entry.path());
            }
        }
    }
    rows.sort();
    rows
}

pub fn std_count(root: &Path) -> usize {
    let mut count = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            count += 1;
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            }
            black_box(entry);
        }
    }
    count
}

pub fn main(allocations: bool) {
    let mut args: Vec<_> = std::env::args_os()
        .skip(1)
        // Cargo passes this flag to harness-free benchmark executables too.
        .filter(|arg| arg != "--bench")
        .collect();
    if args.is_empty() || args[0] == "--help" {
        println!(
            "Usage: ROOT MODE [RUNS=15] [WARMUPS=2]\n       --fixture FILES MODE [RUNS=15] [WARMUPS=2]\n       --test\nUse MODE=all to run every mode.\nModes: {}\nResults are TSV on stdout; diagnostics on stderr. Output goes to the OS null device. Allocation executable reports allocations separately; its timings are not comparable.",
            super::MODES.join(", ")
        );
        return;
    }
    let smoke = args[0] == "--test";
    let generated = args[0] == "--fixture";
    let files = if generated {
        assert!((3..=5).contains(&args.len()), "see --help");
        let files: usize = args[1].to_str().unwrap().parse().unwrap();
        assert!(files > 0, "FILES must be positive");
        args.remove(1);
        files
    } else {
        100
    };
    assert!(if smoke { args.len() == 1 } else { (2..=4).contains(&args.len()) }, "see --help");
    let fixture = if smoke || generated {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/benchmarks");
        std::fs::create_dir_all(&base).unwrap();
        let fixture = tempfile::Builder::new().prefix("layers-").tempdir_in(base).unwrap();
        for i in 0..files {
            let dir = fixture.path().join(format!("group-{}", i % 10));
            std::fs::create_dir_all(&dir).unwrap();
            let file = std::fs::File::create(dir.join(format!("quoted-'ü-{i}.rs"))).unwrap();
            file.set_len(if i % 7 == 0 { 1_000_001 } else { 64 }).unwrap();
        }
        std::fs::create_dir(fixture.path().join(".hidden")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("group-0", fixture.path().join("link-dir")).unwrap();
            std::os::unix::fs::symlink("missing", fixture.path().join("dangling")).unwrap();
        }
        Some(fixture)
    } else {
        None
    };
    let root = if let Some(fixture) = &fixture { fixture.path() } else { Path::new(&args[0]) }.canonicalize().unwrap();
    assert!(root.is_dir());
    let modes: Vec<&str> =
        if smoke || args[1] == "all" { super::MODES.to_vec() } else { vec![args[1].to_str().unwrap()] };
    let runs: usize = args.get(2).map_or(if smoke { 1 } else { 15 }, |s| s.to_str().unwrap().parse().unwrap());
    let warmups: usize = args.get(3).map_or(if smoke { 0 } else { 2 }, |s| s.to_str().unwrap().parse().unwrap());
    assert!(runs > 0, "RUNS must be positive");
    let _governor = tree_fucker::HostGovernor::install(tree_fucker::HostConfig {
        foreground_duty: 1.0,
        domain_foreground_duty: 1.0,
        ..Default::default()
    })
    .unwrap();
    eprintln!("root={} runs={runs} warmups={warmups} allocations={allocations}", root.display());
    println!("mode\trows\tmedian_ms\tmin_ms\tmax_ms\tallocations\treallocations\tbytes_allocated");
    for mode in modes {
        assert!(super::MODES.contains(&mode), "unknown mode: {mode}");
        let expected = inventory(&root, mode.contains("size"));
        // Verify full path multisets before timing, not merely equal row
        // counts.
        let mut verified = Vec::new();
        super::measure(&root, mode, &mut |path| verified.push(path.to_path_buf()), true);
        verified.sort();
        assert_eq!(verified, expected, "path mismatch: {mode}");
        let mut times = Vec::with_capacity(runs);
        let mut totals = [0usize; 3];
        for iteration in 0..warmups + runs {
            let region = stats_alloc::Region::new(&stats_alloc::INSTRUMENTED_SYSTEM);
            let start = Instant::now();
            let count = super::measure(&root, mode, &mut |_| {}, false);
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            let stats = region.change();
            assert_eq!(count, expected.len(), "row count changed during timing");
            if iteration >= warmups {
                times.push(elapsed);
                totals[0] += stats.allocations;
                totals[1] += stats.reallocations;
                totals[2] += stats.bytes_allocated;
            }
        }
        assert_eq!(inventory(&root, mode.contains("size")), expected, "tree changed during measurement");
        times.sort_by(f64::total_cmp);
        let median = (times[(runs - 1) / 2] + times[runs / 2]) / 2.0;
        println!(
            "{mode}\t{}\t{median:.3}\t{:.3}\t{:.3}\t{}\t{}\t{}",
            expected.len(),
            times[0],
            times[runs - 1],
            totals[0] / runs,
            totals[1] / runs,
            totals[2] / runs
        );
        std::io::stdout().flush().unwrap();
    }
}
