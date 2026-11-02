#![cfg(target_os = "macos")]

use std::ffi::{CStr, CString};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use tree_fucker::coordination::macos::Scope;
use tree_fucker::coordination::{self, Mode, Options, Rendezvous, State};
use tree_fucker::core::{GrantId, MonotonicTime, Reservation, WorkOrigin};
use tree_fucker::{HostConfig, HostGovernor, RelativePath, ThrottleCause};

#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_init(profile: *const libc::c_char, flags: u64, error: *mut *mut libc::c_char) -> libc::c_int;
    fn sandbox_free_error(error: *mut libc::c_char);
}

fn limits() -> coordination::authority::Config {
    coordination::authority::Config::from_host(&HostConfig::default(), 8, 16, 16).unwrap()
}

fn reservation(host: &HostGovernor) -> Reservation {
    Reservation {
        id: GrantId::Bootstrap(host.next_bootstrap()),
        path: RelativePath::root(),
        reads: 1,
        registrations: 0,
        operations: 0,
        ceiling: None,
        lease: 0,
        domain: None,
        origin: WorkOrigin::Foreground,
        listing: false,
    }
}

#[test]
fn sandbox_denial_fences_joined_governance_and_reports_prejoin_fallback() {
    let root = tempfile::Builder::new().prefix("tree-fucker-sandbox-").tempdir_in("/var/run/tree-fucker").unwrap();
    assert!(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "sandbox_fixture", "--ignored", "--nocapture"])
            .env("TF_MACOS_FIXTURE", root.path())
            .stdin(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::read(root.path().join("scope/authority.state")).unwrap(),
        fs::read(root.path().join("before")).unwrap()
    );
    let scope = Scope::open(root.path().join("scope"), limits()).unwrap();
    let view = scope.view().unwrap();
    assert_eq!((view.prepared, view.physical, view.participants, view.charged_ns), (0, 0, 0, 0));
}

#[test]
#[ignore = "sandbox entry affects only this dedicated subprocess"]
fn sandbox_fixture() {
    let root = fs::canonicalize(PathBuf::from(std::env::var_os("TF_MACOS_FIXTURE").unwrap())).unwrap();
    let options = Options { scope: Rendezvous::Directory(root.join("scope")), limits: limits() };
    let host = HostGovernor::configured(&HostConfig::default(), Mode::Auto(options.clone())).unwrap();
    assert!(matches!(host.coordination_status().state, State::Shared { failure: None, .. }));
    fs::write(root.join("before"), fs::read(root.join("scope/authority.state")).unwrap()).unwrap();

    let denied = root.join("scope").to_str().unwrap().replace('\\', "\\\\").replace('"', "\\\"");
    let profile =
        CString::new(format!("(version 1)(allow default)(deny file-read* file-write* (subpath \"{denied}\"))"))
            .unwrap();
    let mut error = std::ptr::null_mut();
    // SAFETY: the profile is NUL-terminated and the output pointer is writable.
    // Only this fixture process receives the irreversible sandbox restriction.
    let result = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error) };
    let message = if error.is_null() {
        String::new()
    } else {
        // SAFETY: sandbox_init owns this NUL-terminated error allocation until
        // sandbox_free_error releases it; copy the text before freeing it.
        let message = unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned();
        unsafe { sandbox_free_error(error) };
        message
    };
    assert_eq!(result, 0, "sandbox_init: {message}");

    let fallback = HostGovernor::configured(&HostConfig::default(), Mode::Auto(options.clone())).unwrap();
    assert!(matches!(
        fallback.coordination_status().state,
        State::Fallback { reason: coordination::Error::Unavailable(_) }
    ));
    assert!(HostGovernor::configured(&HostConfig::default(), Mode::Required(options)).is_err());
    assert_eq!(host.try_admit(reservation(&host), MonotonicTime::ZERO), Err(ThrottleCause::CoordinationFailed));
    assert!(matches!(host.coordination_status().state, State::Shared { failure: Some(_), .. }));
    assert_eq!(host.view(MonotonicTime::ZERO).charged, Duration::ZERO);
}

#[test]
#[ignore = "requires root to change the fixture process's filesystem root"]
fn privileged_root_transition_fences_existing_and_reopened_authorities() {
    let root = tempfile::Builder::new().prefix("tree-fucker-chroot-").tempdir_in("/var/run/tree-fucker").unwrap();
    assert!(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "root_transition_fixture", "--ignored", "--nocapture"])
            .env("TF_MACOS_FIXTURE", root.path())
            .stdin(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::read(root.path().join("scope/authority.state")).unwrap(),
        fs::read(root.path().join("before")).unwrap()
    );
    assert_eq!(Scope::open(root.path().join("scope"), limits()).unwrap().view().unwrap().charged_ns, 0);
}

#[test]
#[ignore = "root transition affects only this dedicated subprocess"]
fn root_transition_fixture() {
    use std::os::unix::ffi::OsStrExt;

    let root = PathBuf::from(std::env::var_os("TF_MACOS_FIXTURE").unwrap());
    let options = Options { scope: Rendezvous::Directory(root.join("scope")), limits: limits() };
    let host = HostGovernor::configured(&HostConfig::default(), Mode::Auto(options)).unwrap();
    fs::write(root.join("before"), fs::read(root.join("scope/authority.state")).unwrap()).unwrap();
    let root = CString::new(root.as_os_str().as_bytes()).unwrap();
    // SAFETY: the path is NUL-terminated; only this fixture changes its root.
    assert_eq!(unsafe { libc::chroot(root.as_ptr()) }, 0, "{}", std::io::Error::last_os_error());
    std::env::set_current_dir("/").unwrap();
    assert_eq!(host.try_admit(reservation(&host), MonotonicTime::ZERO), Err(ThrottleCause::CoordinationFailed));
    assert!(matches!(host.coordination_status().state, State::Shared { failure: Some(_), .. }));
    assert_eq!(host.view(MonotonicTime::ZERO).charged, Duration::ZERO);
    let options = Options { scope: Rendezvous::Directory("/scope".into()), limits: limits() };
    assert!(matches!(
        HostGovernor::configured(&HostConfig::default(), Mode::Auto(options)),
        Err(tree_fucker::HostGovernorError::Coordination(coordination::Error::Incompatible))
    ));

    // A separately requested authority works in the new root without /dev.
    let scope = Scope::open("/local", limits()).unwrap();
    let client = scope.join().unwrap();
    fs::write("/input", b"root-local read").unwrap();
    client
        .prepare(coordination::authority::Request {
            work: coordination::protocol::Work::LazyRead,
            origin: coordination::authority::Origin::Foreground,
            domain: None,
            required: 1,
            desired: 0,
            ceiling_ns: u64::MAX,
        })
        .unwrap()
        .try_run(|_| {
            assert_eq!(fs::read("/input").unwrap(), b"root-local read");
            coordination::macos::Completion { value: (), operations: 1, failed: false }
        })
        .unwrap();
    let charged = scope.view().unwrap().charged_ns;
    assert!(charged > 0);
    drop(client);
    drop(scope);
    assert_eq!(Scope::open("/local", limits()).unwrap().view().unwrap().charged_ns, charged);
}
