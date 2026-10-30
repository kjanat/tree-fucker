#![cfg(target_os = "illumos")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tree_fucker::coordination::illumos::{Completion, Error, Scope};
use tree_fucker::coordination::{self, Mode, Options, Rendezvous, State};
use tree_fucker::core::{GrantId, MonotonicTime, Reservation, WorkOrigin};
use tree_fucker::{HostConfig, HostGovernor, RelativePath, ThrottleCause};

unsafe extern "C" {
    fn getzoneidbyname(name: *const libc::c_char) -> libc::zoneid_t;
    fn zone_enter(id: libc::zoneid_t) -> libc::c_int;
}

fn limits() -> coordination::authority::Config {
    coordination::authority::Config::from_host(&HostConfig::default(), 8, 16, 16).unwrap()
}

struct Mount(Option<PathBuf>);

impl Mount {
    fn close(&mut self) -> std::io::Result<()> {
        let Some(path) = self.0.as_ref() else { return Ok(()) };
        if !Command::new("umount").arg(path).status()?.success() {
            return Err(std::io::Error::other(format!("failed to unmount zone fixture {}", path.display())));
        }
        let path = self.0.take().unwrap();
        fs::remove_dir(path)
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("{error}");
        }
    }
}

#[test]
#[ignore = "requires the running tree-fucker-coordination zone; provision with benchmarks/omnios_vm.py"]
fn privileged_zone_scope_and_live_handle_transition() {
    // SAFETY: the name is a static NUL-terminated string.
    let zone = unsafe { getzoneidbyname(c"tree-fucker-coordination".as_ptr()) };
    assert!(zone > 0, "the dedicated acceptance zone must be running");
    let root = tempfile::Builder::new().prefix("tree-fucker-zone-").tempdir_in("/var/run/tree-fucker").unwrap();
    let scope = Scope::open(root.path().join("scope"), limits()).unwrap();
    let parent_zone = scope.diagnostics().unwrap().namespaces[1];
    fs::write(root.path().join("parent-zone"), parent_zone).unwrap();

    let guest = format!("/var/run/tree-fucker-zone-{}", std::process::id());
    let mount = Path::new("/zones/tree-fucker-coordination/root").join(guest.trim_start_matches('/'));
    fs::create_dir(&mount).unwrap();
    assert!(Command::new("mount").args(["-F", "lofs"]).arg(root.path()).arg(&mount).status().unwrap().success());
    let mut mount = Mount(Some(mount));
    // A separate process contract permits zone_enter without changing the
    // parent harness's contract or moving unrelated processes into the zone.
    let result = Command::new("ctrun")
        .args(["-l", "child"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "zone_transition_fixture", "--ignored", "--nocapture"])
        .env("TF_ILLUMOS_FIXTURE", root.path())
        .env("TF_ILLUMOS_GUEST_FIXTURE", guest)
        .env("TF_ILLUMOS_ZONE", zone.to_string())
        .status()
        .unwrap();
    assert!(result.success());
    assert_eq!(scope.view().unwrap().charged_ns, 0);
    mount.close().unwrap();
}

#[test]
#[ignore = "zone transition subprocess fixture"]
fn zone_transition_fixture() {
    let root = PathBuf::from(std::env::var_os("TF_ILLUMOS_FIXTURE").unwrap());
    let guest = PathBuf::from(std::env::var_os("TF_ILLUMOS_GUEST_FIXTURE").unwrap());
    let zone: libc::zoneid_t = std::env::var("TF_ILLUMOS_ZONE").unwrap().parse().unwrap();
    let options = Options { scope: Rendezvous::Directory(root.join("scope")), limits: limits() };
    let host = HostGovernor::configured(&HostConfig::default(), Mode::Auto(options)).unwrap();
    assert!(matches!(host.coordination_status().state, State::Shared { failure: None, .. }));
    let state = fs::read(root.join("scope/authority.state")).unwrap();
    // SAFETY: only this dedicated process enters the prepared test zone.
    assert_eq!(unsafe { zone_enter(zone) }, 0, "{}", std::io::Error::last_os_error());
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
    // The LOFS view exposes the exact global authority; rejection must not
    // create a replacement ledger or reset its accounting.
    assert!(matches!(Scope::open(guest.join("scope"), limits()), Err(Error::Incompatible)));
    assert_eq!(fs::read(guest.join("scope/authority.state")).unwrap(), state);

    let zone_root = tempfile::Builder::new().prefix("tree-fucker-local-").tempdir_in("/var/run/tree-fucker").unwrap();
    let scope = Scope::open(zone_root.path().join("scope"), limits()).unwrap();
    let identity = scope.diagnostics().unwrap().namespaces[1];
    assert_eq!(u32::from_le_bytes(identity[4..8].try_into().unwrap()), zone as u32);
    assert_ne!(identity.as_slice(), fs::read(guest.join("parent-zone")).unwrap());
    verify_local_work(zone_root.path(), scope);
}

#[test]
#[ignore = "requires root to launch a different effective user; run explicitly in native CI"]
fn privileged_uid_isolation_allows_unprivileged_work() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = tempfile::Builder::new().prefix("tree-fucker-user-").tempdir_in("/var/run/tree-fucker").unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o1777)).unwrap();
    assert!(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "different_uid_fixture", "--ignored", "--nocapture"])
            .env("TF_ILLUMOS_FIXTURE", root.path())
            .status()
            .unwrap()
            .success()
    );
    let metadata = fs::metadata(root.path().join("scope")).unwrap();
    assert_eq!(metadata.uid(), 65534);
    assert_eq!(metadata.mode() & 0o7777, 0o700);
    assert!(matches!(Scope::open(root.path().join("scope"), limits()), Err(Error::InvalidScope)));
}

#[test]
#[ignore = "unprivileged subprocess fixture"]
fn different_uid_fixture() {
    let root = PathBuf::from(std::env::var_os("TF_ILLUMOS_FIXTURE").unwrap());
    // SAFETY: privilege changes affect only this dedicated fixture process.
    // No supplementary groups are supplied to the zero-length group list.
    unsafe {
        assert_eq!(libc::setgroups(0, std::ptr::null()), 0);
        assert_eq!(libc::setgid(65534), 0);
        assert_eq!(libc::setuid(65534), 0);
    }
    let scope = Scope::open(root.join("scope"), limits()).unwrap();
    verify_local_work(&root, scope);
}

fn verify_local_work(root: &Path, scope: std::sync::Arc<Scope>) {
    fs::write(root.join("input"), b"scope-local work").unwrap();
    let client = scope.join().unwrap();
    let request = coordination::authority::Request {
        work: coordination::protocol::Work::LazyRead,
        origin: coordination::authority::Origin::Foreground,
        domain: None,
        required: 1,
        desired: 0,
        ceiling_ns: u64::MAX,
    };
    client
        .prepare(request)
        .unwrap()
        .try_run(|_| {
            assert_eq!(fs::read(root.join("input")).unwrap(), b"scope-local work");
            Completion { value: (), operations: 1, failed: false }
        })
        .unwrap();
    let before = scope.view().unwrap();
    assert_eq!(before.physical, 0);
    assert!(before.charged_ns > 0);
    drop(client);
    drop(scope);
    assert_eq!(Scope::open(root.join("scope"), limits()).unwrap().view().unwrap().charged_ns, before.charged_ns);
}
