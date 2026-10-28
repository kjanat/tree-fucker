//! Power-transition fixtures. Dedicated CI controllers invoke ignored entries.
#![cfg(any(windows, target_os = "macos"))]

mod coordination_support;

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;
use std::time::Duration;

use coordination_support::native::{Completion, Scope};
use tree_fucker::HostConfig;
use tree_fucker::coordination::authority::{Authority, Config, Origin, Request};
use tree_fucker::coordination::journal::Journal;
use tree_fucker::coordination::protocol::Work;

fn root() -> PathBuf {
    let root = PathBuf::from(std::env::var_os("TF_POWER_ROOT").expect("dedicated power-test root"));
    #[cfg(target_os = "macos")]
    assert!(root.starts_with(coordination_support::RENDEZVOUS));
    root
}

fn config() -> Config {
    Config::from_host(&HostConfig::default(), 4, 8, 4).unwrap()
}

fn request() -> Request {
    Request {
        work: Work::LazyRead,
        origin: Origin::Foreground,
        domain: None,
        required: 1,
        desired: 0,
        ceiling_ns: u64::MAX,
    }
}

fn snapshot(root: &Path) -> Authority {
    let anchor = OpenOptions::new().read(true).write(true).open(root.join("scope.authority.lock")).unwrap();
    anchor.lock().unwrap();
    let state = OpenOptions::new().read(true).write(true).open(root.join("scope/authority.state")).unwrap();
    let mut journal = Journal::open(state).unwrap();
    let authority = journal.load().unwrap();
    journal.into_inner().sync_all().unwrap();
    anchor.sync_all().unwrap();
    authority
}

fn persist(path: &Path, bytes: &[u8]) {
    let mut file = File::create(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[cfg(windows)]
#[test]
#[ignore = "reboots the disposable Windows guest; run through the CI controller"]
fn windows_before_reboot() {
    let root = root();
    fs::create_dir_all(&root).unwrap();
    assert!(!root.join("before.state").exists(), "fixture requires a fresh guest");
    let scope = Scope::open(root.join("scope"), config()).unwrap();
    let client = scope.join().unwrap();
    let mut prepared = client.prepare(request()).unwrap();
    prepared
        .try_run(|_| -> Completion<()> {
            // Keep an authorized owner alive until the kernel ends this
            // process. The post-boot check must recover it without
            // resetting its charge.
            let state = snapshot(&root);
            assert_eq!(state.view().physical, 1);
            assert!(state.view().charged_ns > 0);
            persist(&root.join("before.state"), &state.encode().unwrap());
            persist(&root.join("before.epoch"), &scope.diagnostics().unwrap().clock);
            persist(&root.join("ready"), b"ready\n");
            assert!(Command::new("shutdown.exe").args(["/r", "/t", "0", "/f"]).status().unwrap().success());
            std::thread::sleep(Duration::from_secs(120));
            panic!("Windows did not reboot");
        })
        .unwrap();
}

#[cfg(windows)]
#[test]
#[ignore = "second phase on the same guest and disk after a real reboot"]
fn windows_after_reboot() {
    let root = root();
    let before = Authority::decode(&fs::read(root.join("before.state")).unwrap()).unwrap();
    assert_eq!(snapshot(&root), before, "boot must retain the committed journal");
    let old_epoch = fs::read(root.join("before.epoch")).unwrap();
    let scope = Scope::open(root.join("scope"), config()).unwrap();
    let identity = scope.diagnostics().unwrap();
    assert_ne!(identity.clock.as_slice(), old_epoch, "the test must cross a real boot epoch");
    assert_eq!(identity.generation, before.ledger().generation());
    assert_eq!(snapshot(&root).view(), before.view(), "migration must not refill or erase debt");
    let recovered = scope.view().unwrap();
    assert_eq!((recovered.physical, recovered.prepared, recovered.participants), (0, 0, 0));
    assert!(recovered.charged_ns >= before.view().charged_ns);
    let other = Scope::open(root.join("scope"), config()).unwrap();
    assert_eq!(other.diagnostics().unwrap().clock_offset_ns, identity.clock_offset_ns);
    drop((scope, other));
    std::thread::sleep(Duration::from_millis(20));
    let reopened = Scope::open(root.join("scope"), config()).unwrap();
    assert_eq!(reopened.diagnostics().unwrap().clock_offset_ns, identity.clock_offset_ns);
    assert_eq!(reopened.diagnostics().unwrap().generation, identity.generation);
    persist(&root.join("verified"), b"real reboot, retained accounting, recovered owner, stable mapping\n");
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "holds live ownership while the dedicated CI controller sleeps and wakes macOS"]
fn macos_sleep_wake() {
    let root = root();
    fs::create_dir_all(&root).unwrap();
    let scope = Scope::open(root.join("scope"), config()).unwrap();
    let client = scope.join().unwrap();
    let mut prepared = client.prepare(request()).unwrap();
    prepared
        .try_run(|_| {
            let before = snapshot(&root);
            assert_eq!(before.view().physical, 1);
            persist(&root.join("ready"), b"ready\n");
            let deadline = std::time::Instant::now() + Duration::from_secs(180);
            while !root.join("woke").exists() {
                assert!(std::time::Instant::now() < deadline, "controller did not verify sleep/wake");
                std::thread::sleep(Duration::from_millis(50));
            }
            assert_eq!(snapshot(&root), before, "sleep alone must not mutate retained accounting");
            let view = scope.view().unwrap();
            assert_eq!(view.physical, 1, "sleep does not establish owner exit");
            assert!(view.charged_ns >= before.view().charged_ns);
            let peer = Scope::open(root.join("scope"), config()).unwrap();
            assert_eq!(peer.diagnostics().unwrap().generation, before.ledger().generation());
            assert_eq!(peer.view().unwrap().physical, 1);
            Completion { value: (), operations: 1, failed: false }
        })
        .unwrap();
    assert_eq!(scope.view().unwrap().physical, 0);
    persist(&root.join("verified"), b"sleep/wake retains ownership and accounting\n");
}
