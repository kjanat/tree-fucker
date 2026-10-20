mod driver;
mod raw;
use std::path::Path;
pub const MODES: &[&str] = &["std-count", "scan-count", "scan-bounded", "scan-anchors", "scan-paths", "scan-stats"];
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
    } else {
        raw::scan(root, mode, visit, verify)
    }
}
pub fn main(allocations: bool) {
    driver::main(allocations);
}
