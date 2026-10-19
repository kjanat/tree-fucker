use std::hint::black_box;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tree_fucker::scan::{Scan, ScanEvent, ScanOptions};

pub fn scan(root: &Path, mode: &str, visit: &mut dyn FnMut(&Path), verify: bool) -> usize {
    let mut scan = Scan::open(
        Arc::new(tree_fucker::std_fs::StdFileSystem::new()),
        root.to_path_buf(),
        Arc::new(tree_fucker::LoadAll),
        ScanOptions {
            anchors: if mode == "scan-anchors" { 1024 } else { 0 },
            crossing: tree_fucker::domain::DomainCrossing::Follow,
            ceiling: Duration::MAX,
            ..Default::default()
        },
    )
    .unwrap();
    let mut count = 0;
    for event in scan.by_ref() {
        match event.unwrap() {
            ScanEvent::Entry(entry) => {
                if !entry.path.is_root() {
                    if verify || mode == "scan-paths" {
                        let path = entry.path.under(root);
                        visit(&path);
                        black_box(path);
                    }
                    count += 1;
                }
                black_box(entry);
            }
            ScanEvent::Unlisted { failure, .. } => panic!("unlisted: {failure:?}"),
            ScanEvent::Boundary { .. } => panic!("unexpected domain boundary"),
        }
    }
    if mode == "scan-stats" {
        eprintln!("{:?}", scan.stats());
    }
    count
}
