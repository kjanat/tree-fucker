mod delayed;
mod driver;
#[cfg(target_os = "linux")]
#[path = "../../benchmarks/baselines/fsql/row.rs"]
mod fsql_baseline_row;
#[cfg(target_os = "linux")]
#[path = "../../benchmarks/baselines/fsql/walk.rs"]
mod fsql_walk_baseline;
mod persistent;
mod raw;
use std::path::Path;
pub const MODES: &[&str] = &[
    "std-count",
    "scan-count",
    "scan-bounded",
    "scan-streaming",
    "scan-anchors",
    "scan-paths",
    "scan-stats",
    "tree-initial",
    #[cfg(target_os = "linux")]
    "fsql-walk-baseline",
];
pub fn measure(
    root: &Path,
    mode: &str,
    visit: &mut dyn FnMut(&Path),
    verify: bool,
) -> (usize, Option<std::time::Duration>) {
    if mode == "std-count" {
        if verify {
            for path in driver::inventory(root, false) {
                visit(&path);
            }
        }
        (driver::std_count(root), None)
    } else if mode == "tree-initial" {
        persistent::scan(root, visit, verify)
    } else if mode == "fsql-walk-baseline" {
        #[cfg(target_os = "linux")]
        {
            let start = std::time::Instant::now();
            let mut first = None;
            let mut count = 0;
            for entry in fsql_walk_baseline::Walker::new(root, fsql_walk_baseline::WalkOptions::default()).unwrap() {
                let entry = entry.unwrap();
                if entry.depth() == 0 {
                    continue;
                }
                first.get_or_insert_with(|| start.elapsed());
                if verify {
                    visit(entry.path());
                }
                std::hint::black_box(entry);
                count += 1;
            }
            (count, first)
        }
        #[cfg(not(target_os = "linux"))]
        unreachable!("fsql walker baseline requires Linux")
    } else {
        raw::scan(root, mode, visit, verify)
    }
}
pub fn main(allocations: bool) {
    driver::main(allocations);
}
