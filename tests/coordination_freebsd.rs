#![cfg(target_os = "freebsd")]

use std::path::PathBuf;
use std::process::{Command, Stdio};

use tree_fucker::coordination::freebsd::{Error, Scope};
use tree_fucker::coordination::{self, Mode, Options, Rendezvous, State};
use tree_fucker::core::{GrantId, MonotonicTime, Reservation, WorkOrigin};
use tree_fucker::{HostConfig, HostGovernor, RelativePath, ThrottleCause};

#[path = "coordination_freebsd/jails.rs"]
mod jails;

fn limits() -> coordination::authority::Config {
    coordination::authority::Config::from_host(&HostConfig::default(), 8, 16, 16).unwrap()
}

fn fixture() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("tree-fucker-freebsd-").tempdir_in("/var/run/tree-fucker").unwrap()
}

fn child(name: &str, root: &std::path::Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", name, "--ignored", "--nocapture"]);
    command.env("TF_FREEBSD_FIXTURE", root).stdin(Stdio::null());
    command
}

#[test]
fn capability_mode_rejects_prejoin_and_fences_an_existing_governor() {
    let root = fixture();
    assert!(child("capability_fixture", root.path()).status().unwrap().success());
    // Kernel descriptor retirement, not a capability-mode error or timeout,
    // establishes that the child can no longer own its reservations.
    let scope = Scope::open(root.path().join("scope"), limits()).unwrap();
    for _ in 0..8 {
        if scope.view().unwrap().participants == 0 {
            return;
        }
    }
    panic!("exited capability-mode participant was not recovered");
}

#[test]
#[ignore = "capability-mode subprocess fixture"]
fn capability_fixture() {
    let root = PathBuf::from(std::env::var_os("TF_FREEBSD_FIXTURE").unwrap());
    let options = Options { scope: Rendezvous::Directory(root.join("scope")), limits: limits() };
    let host = HostGovernor::configured(&HostConfig::default(), Mode::Required(options.clone())).unwrap();
    assert!(matches!(host.coordination_status().state, State::Shared { failure: None, .. }));
    // SAFETY: this intentionally restricts only this dedicated test process.
    assert_eq!(unsafe { libc::cap_enter() }, 0);
    assert!(matches!(
        Scope::open(root.join("scope"), limits()),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied
    ));
    let fallback = HostGovernor::configured(&HostConfig::default(), Mode::Auto(options.clone())).unwrap();
    assert!(matches!(
        fallback.coordination_status().state,
        State::Fallback { reason: coordination::Error::Unavailable(_) }
    ));
    assert!(HostGovernor::configured(&HostConfig::default(), Mode::Required(options)).is_err());
    let reservation = Reservation {
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
    };
    assert_eq!(host.try_admit(reservation, MonotonicTime::ZERO), Err(ThrottleCause::CoordinationFailed));
    assert!(matches!(host.coordination_status().state, State::Shared { failure: Some(_), .. }));
    assert_eq!(host.view(MonotonicTime::ZERO).charged, std::time::Duration::ZERO);
}

#[test]
#[ignore = "requires root and permission to create a jail; run explicitly in native CI"]
fn privileged_same_root_jail_transition_preserves_the_authority() {
    let root = fixture();
    let host = Scope::open(root.path().join("scope"), limits()).unwrap();
    assert!(child("jail_transition_fixture", root.path()).status().unwrap().success());
    assert!(host.view().unwrap().charged_ns > 0);
}

#[test]
#[ignore = "jail transition subprocess fixture"]
fn jail_transition_fixture() {
    let root = PathBuf::from(std::env::var_os("TF_FREEBSD_FIXTURE").unwrap());
    let options = Options { scope: Rendezvous::Directory(root.join("scope")), limits: limits() };
    let host = HostGovernor::configured(&HostConfig::default(), Mode::Required(options.clone())).unwrap();
    let generation = match host.coordination_status().state {
        State::Shared { scope, .. } => scope.generation,
        other => panic!("expected shared authority: {other:?}"),
    };
    std::fs::write(root.join("input"), b"jailed read").unwrap();
    let scope = Scope::open(root.join("scope"), limits()).unwrap();
    jails::read_once(&scope, &root.join("input"));
    let charged_before_entry = scope.view().unwrap().charged_ns;
    assert!(charged_before_entry > 0);
    drop(scope);
    let name = std::ffi::CString::new(format!("tree-fucker-test-{}", std::process::id())).unwrap();
    let mut jail = libc::jail {
        version: libc::JAIL_API_VERSION,
        path: c"/".as_ptr().cast_mut(),
        hostname: c"coordination-test".as_ptr().cast_mut(),
        jailname: name.as_ptr().cast_mut(),
        ip4s: 0,
        ip6s: 0,
        ip4: std::ptr::null_mut(),
        ip6: std::ptr::null_mut(),
    };
    // SAFETY: all C strings and zero-length address lists remain live for this
    // call. Only this dedicated subprocess enters the new, nonpersistent jail.
    let mut host = Some(host);
    if unsafe { libc::jail(&mut jail) } < 0 {
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        // The default FreeBSD policy rejects jail entry with the scope's
        // directory descriptors open. Prove that closing them permits entry.
        assert!(matches!(host.as_ref().unwrap().coordination_status().state, State::Shared { failure: None, .. }));
        drop(host.take());
        // SAFETY: same live jail parameters, still only this fixture process.
        assert!(unsafe { libc::jail(&mut jail) } >= 0, "{}", std::io::Error::last_os_error());
    }
    let joined = HostGovernor::configured(&HostConfig::default(), Mode::Auto(options)).unwrap();
    assert!(matches!(joined.coordination_status().state, State::Shared { failure: None, .. }));
    if let Some(host) = host {
        assert!(matches!(host.coordination_status().state, State::Shared { failure: None, .. }));
    }
    let scope = Scope::open(root.join("scope"), limits()).unwrap();
    assert_eq!(scope.diagnostics().unwrap().generation, generation);
    assert_eq!(scope.view().unwrap().charged_ns, charged_before_entry);
    jails::read_once(&scope, &root.join("input"));
    let charged = scope.view().unwrap().charged_ns;
    assert!(charged > charged_before_entry);
    drop(scope);
    drop(joined);
    let reopened = Scope::open(root.join("scope"), limits()).unwrap();
    assert_eq!(reopened.diagnostics().unwrap().generation, generation);
    assert_eq!(reopened.view().unwrap().charged_ns, charged);
}

#[test]
#[ignore = "requires root to launch a different effective user; run explicitly in native CI"]
fn privileged_uid_isolation_allows_unprivileged_host_work() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = fixture();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
    assert!(child("different_uid_fixture", root.path()).status().unwrap().success());
    let metadata = std::fs::metadata(root.path().join("scope")).unwrap();
    assert_eq!(metadata.uid(), 65534);
    assert_eq!(metadata.mode() & 0o7777, 0o700);
    // Even host root does not silently join another effective user's budget.
    assert!(matches!(Scope::open(root.path().join("scope"), limits()), Err(Error::InvalidScope)));
}

#[test]
#[ignore = "unprivileged subprocess fixture"]
fn different_uid_fixture() {
    let root = PathBuf::from(std::env::var_os("TF_FREEBSD_FIXTURE").unwrap());
    // SAFETY: privilege changes affect only this dedicated fixture process;
    // no groups are supplied to the zero-length supplementary group list.
    unsafe {
        assert_eq!(libc::setgroups(0, std::ptr::null()), 0);
        assert_eq!(libc::setgid(65534), 0);
        assert_eq!(libc::setuid(65534), 0);
    }
    let scope = Scope::open(root.join("scope"), limits()).unwrap();
    let client = scope.join().unwrap();
    let request = coordination::authority::Request {
        work: coordination::protocol::Work::LazyRead,
        origin: coordination::authority::Origin::Foreground,
        domain: None,
        required: 1,
        desired: 0,
        ceiling_ns: u64::MAX,
    };
    std::fs::write(root.join("input"), b"unprivileged read").unwrap();
    client
        .prepare(request)
        .unwrap()
        .try_run(|_| {
            assert_eq!(std::fs::read(root.join("input")).unwrap(), b"unprivileged read");
            coordination::freebsd::Completion { value: (), operations: 1, failed: false }
        })
        .unwrap();
    let before = scope.view().unwrap();
    assert_eq!(before.physical, 0);
    assert!(before.charged_ns > 0);
    drop(client);
    drop(scope);
    assert_eq!(Scope::open(root.join("scope"), limits()).unwrap().view().unwrap().charged_ns, before.charged_ns);
}
