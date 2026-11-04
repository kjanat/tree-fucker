use std::{path::PathBuf, sync::Arc};

use tree_fucker::{DomainCrossing, LoadAll, Scan, ScanEvent, ScanOptions, std_fs::StdFileSystem};

fn main() -> tree_fucker::Result<()> {
    let options = ScanOptions { crossing: DomainCrossing::Exclude, ..ScanOptions::default() };
    let scan = Scan::open(Arc::new(StdFileSystem::new()), PathBuf::from("."), Arc::new(LoadAll), options)?;
    for event in scan {
        match event? {
            ScanEvent::Entry(entry) => println!("{}", entry.path),
            ScanEvent::Boundary { path, mode, .. } => println!("{path}: mount not followed ({mode})"),
            ScanEvent::Unlisted { path, failure } => eprintln!("{path}: {failure}"),
        }
    }
    Ok(())
}
