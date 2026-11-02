use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

use tree_fucker::coordination::authority::{self, Origin, Request};
use tree_fucker::coordination::freebsd::{Completion, Error, Scope};
use tree_fucker::coordination::protocol::{self, Work};
use tree_fucker::coordination::{Mode, Options, Rendezvous};
use tree_fucker::{HostConfig, HostGovernor};

fn config() -> authority::Config {
    authority::Config::from_host(
        &HostConfig {
            maximum_in_flight: 1,
            per_domain_concurrency: 1,
            foreground_duty: 1.0,
            foreground_burst: Duration::from_secs(30),
            ..HostConfig::default()
        },
        8,
        16,
        16,
    )
    .unwrap()
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

fn enter(root: &Path) -> i32 {
    let path = std::ffi::CString::new(root.as_os_str().as_bytes()).unwrap();
    let name = std::ffi::CString::new(format!("tree-fucker-scope-{}", std::process::id())).unwrap();
    let mut jail = libc::jail {
        version: libc::JAIL_API_VERSION,
        path: path.as_ptr().cast_mut(),
        hostname: c"coordination-test".as_ptr().cast_mut(),
        jailname: name.as_ptr().cast_mut(),
        ip4s: 0,
        ip6s: 0,
        ip4: std::ptr::null_mut(),
        ip6: std::ptr::null_mut(),
    };
    // SAFETY: the strings outlive this call; address lists have zero length.
    // Only this dedicated fixture process enters the nonpersistent jail.
    let id = unsafe { libc::jail(&mut jail) };
    assert!(id > 0, "{}", std::io::Error::last_os_error());
    id
}

struct Owner(Child);
impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires root to launch two independent jails; run explicitly in native CI"]
fn privileged_same_root_jails_share_physical_ownership_and_retained_debt() {
    let root = super::fixture();
    let scope = Scope::open(root.path().join("scope"), config()).unwrap();
    let gate = root.path().join("gate");
    rustix::fs::mkfifoat(rustix::fs::CWD, &gate, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR).unwrap();
    let mut release = fs::OpenOptions::new().read(true).write(true).open(&gate).unwrap();
    let mut owner = Owner(super::child("jails::held_jail_fixture", root.path()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(15);
    while !root.path().join("entered").exists() {
        assert!(owner.0.try_wait().unwrap().is_none(), "owner exited before physical entry");
        assert!(Instant::now() < deadline, "jailed owner did not enter its filesystem call");
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(scope.view().unwrap().physical, 1);
    assert!(super::child("jails::contending_jail_fixture", root.path()).status().unwrap().success());
    assert_ne!(fs::read(root.path().join("entered")).unwrap(), fs::read(root.path().join("contender")).unwrap());
    assert_eq!(scope.view().unwrap().physical, 1);
    release.write_all(&[1]).unwrap();
    assert!(owner.0.wait().unwrap().success());
    let before = scope.view().unwrap();
    assert_eq!((before.prepared, before.physical, before.participants), (0, 0, 0));
    assert!(before.charged_ns > 0);
    drop(scope);
    assert_eq!(Scope::open(root.path().join("scope"), config()).unwrap().view().unwrap().charged_ns, before.charged_ns);
}

#[test]
#[ignore = "jailed physical owner fixture"]
fn held_jail_fixture() {
    let root = PathBuf::from(std::env::var_os("TF_FREEBSD_FIXTURE").unwrap());
    let jail = enter(Path::new("/"));
    let scope = Scope::open(root.join("scope"), config()).unwrap();
    let client = scope.join().unwrap();
    client
        .prepare(request())
        .unwrap()
        .try_run(|_| {
            let mut gate = File::open(root.join("gate")).unwrap();
            fs::write(root.join("entered"), jail.to_le_bytes()).unwrap();
            gate.read_exact(&mut [0]).unwrap();
            Completion { value: (), operations: 1, failed: false }
        })
        .unwrap();
}

#[test]
#[ignore = "independent jailed admission contender"]
fn contending_jail_fixture() {
    let root = PathBuf::from(std::env::var_os("TF_FREEBSD_FIXTURE").unwrap());
    let jail = enter(Path::new("/"));
    let scope = Scope::open(root.join("scope"), config()).unwrap();
    let client = scope.join().unwrap();
    let mut prepared = client.prepare(request()).unwrap();
    assert!(matches!(
        prepared.try_run::<()>(|_| panic!("second jail dispatched beyond the common ceiling")),
        Err(Error::Authority(authority::Error::Protocol(protocol::Error::PhysicalCapacity)))
    ));
    fs::write(root.join("contender"), jail.to_le_bytes()).unwrap();
}

#[test]
#[ignore = "requires root to enter a jail with a different filesystem root"]
fn privileged_different_root_view_rejects_the_same_retained_authority() {
    let root = super::fixture();
    let scope = Scope::open(root.path().join("scope"), config()).unwrap();
    let before = fs::read(root.path().join("scope/authority.state")).unwrap();
    assert!(super::child("jails::different_root_fixture", root.path()).status().unwrap().success());
    assert_eq!(fs::read(root.path().join("scope/authority.state")).unwrap(), before);
    assert_eq!(scope.view().unwrap().charged_ns, 0);
}

#[test]
#[ignore = "different filesystem root fixture"]
fn different_root_fixture() {
    let root = PathBuf::from(std::env::var_os("TF_FREEBSD_FIXTURE").unwrap());
    enter(&root);
    assert!(matches!(Scope::open("/scope", config()), Err(Error::Incompatible)));
    let options = Options { scope: Rendezvous::Directory("/scope".into()), limits: config() };
    assert!(matches!(
        HostGovernor::configured(&HostConfig::default(), Mode::Auto(options)),
        Err(tree_fucker::HostGovernorError::Coordination(tree_fucker::coordination::Error::Incompatible))
    ));
    // An explicitly separate scope in this root is usable and retains debt.
    let scope = Scope::open("/local", config()).unwrap();
    fs::write("/input", b"jailed read").unwrap();
    read_once(&scope, Path::new("/input"));
    let charged = scope.view().unwrap().charged_ns;
    assert!(charged > 0);
    drop(scope);
    assert_eq!(Scope::open("/local", config()).unwrap().view().unwrap().charged_ns, charged);
}

/// Perform real work and leave only the caller's scope handle alive.
pub(super) fn read_once(scope: &std::sync::Arc<Scope>, input: &Path) {
    let client = scope.join().unwrap();
    client
        .prepare(request())
        .unwrap()
        .try_run(|_| {
            assert_eq!(fs::read(input).unwrap(), b"jailed read");
            Completion { value: (), operations: 1, failed: false }
        })
        .unwrap();
}
