#![cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos"))]

use std::sync::Arc;

use tree_fucker::coordination::{self, Mode, Options, Rendezvous, State};
use tree_fucker::{HostConfig, HostGovernor, HostGovernorError, LoadAll, Scan, ScanOptions};

#[test]
fn installing_required_coordination_protects_default_scan_constructors() {
    let root =
        tempfile::Builder::new().prefix("tree-fucker-install-").tempdir_in(coordination_support::RENDEZVOUS).unwrap();
    let config = HostConfig::default();
    let options = Options {
        scope: Rendezvous::Directory(root.path().join("scope")),
        limits: coordination::authority::Config::from_host(&config, 8, 32, 16).unwrap(),
    };
    let installed = HostGovernor::install_with_coordination(config, Mode::Required(options.clone())).unwrap();
    let State::Shared { scope, .. } = installed.coordination_status().state else { panic!("shared mode") };
    assert_eq!(tree_fucker::host_governor().coordination_status(), installed.coordination_status());
    let tree = root.path().join("input");
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("leaf"), b"data").unwrap();
    let scan = Scan::open(
        Arc::new(tree_fucker::std_fs::StdFileSystem::new()),
        tree,
        Arc::new(LoadAll),
        ScanOptions::default(),
    )
    .unwrap();
    assert!(scan.collect::<tree_fucker::Result<Vec<_>>>().unwrap().len() >= 2);
    let authority = coordination_support::native::Scope::open(&scope.directory, options.limits).unwrap();
    assert!(authority.view().unwrap().charged_ns > 0);
    let untouched = root.path().join("unused");
    assert!(matches!(
        HostGovernor::install_with_coordination(
            config,
            Mode::Required(Options { scope: Rendezvous::Directory(untouched.clone()), ..options })
        ),
        Err(HostGovernorError::AlreadyInstalled)
    ));
    assert!(!untouched.exists());
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos"))]
mod coordination_support;
