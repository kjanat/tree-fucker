#![cfg(target_os = "linux")]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use tree_fucker::coordination::authority::{Config, Origin, Request};
use tree_fucker::coordination::linux::{Completion, Error, Scope};
use tree_fucker::coordination::protocol::Work;
use tree_fucker::coordination::{self, Mode, Options, Rendezvous};
use tree_fucker::core::{GrantId, MonotonicTime, Reservation, WorkOrigin};
use tree_fucker::{HostConfig, HostGovernor, HostGovernorError, RelativePath, ThrottleCause};

fn config() -> Config {
    Config::from_host(&HostConfig::default(), 8, 16, 16).unwrap()
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

fn fixture_command(test: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", test, "--ignored", "--nocapture"]);
    command.stdin(Stdio::null());
    command
}

#[test]
#[ignore = "requires Linux user, IPC, and time namespace creation; run explicitly in native CI"]
fn namespace_histories() {
    for scenario in ["ipc-thread", "user", "ipc", "time", "time-for-children"] {
        // Namespace capabilities belong only to this new user namespace. The
        // fixture never changes the host's credentials, namespaces, or clocks.
        let status = Command::new("unshare")
            .args(["--user", "--map-root-user", "--ipc"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "namespace_fixture", "--ignored", "--nocapture"])
            .env("TF_NAMESPACE_SCENARIO", scenario)
            .stdin(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "namespace history failed: {scenario}");
    }
}

#[test]
#[ignore = "isolated user-namespace fixture launched by namespace_histories"]
fn namespace_fixture() {
    let root = tempfile::Builder::new().prefix("tree-fucker-namespaces-").tempdir_in("/dev/shm").unwrap();
    let scope = Scope::open(root.path().join("scope"), config()).unwrap();
    let scenario = std::env::var("TF_NAMESPACE_SCENARIO").unwrap();
    if scenario == "ipc-thread" {
        thread_transition(root.path(), scope);
        return;
    }
    let client = scope.join().unwrap();
    let mut prepared = client.prepare(request()).unwrap();
    prepared
        .try_run(|_| {
            fs::write(root.path().join("physical-input"), b"owned work").unwrap();
            assert_eq!(fs::read(root.path().join("physical-input")).unwrap(), b"owned work");
            let mut before = fs::read(root.path().join("scope/authority.state")).unwrap();
            let status = if scenario == "time-for-children" {
                let identity = scope.diagnostics().unwrap().namespaces;
                // CLONE_NEWTIME selects a namespace for future children; it
                // does not change this thread's active clock or
                // current time namespace.
                assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWTIME) }, 0, "{}", std::io::Error::last_os_error());
                assert_eq!(scope.diagnostics().unwrap().namespaces, identity);
                assert_eq!(scope.view().unwrap().physical, 1);
                before = fs::read(root.path().join("scope/authority.state")).unwrap();
                fixture_command("incompatible_namespace_fixture")
                    .env("TF_NAMESPACE_ROOT", root.path())
                    .status()
                    .unwrap()
            } else {
                let mut command = Command::new("unshare");
                match scenario.as_str() {
                    "user" => {
                        command.args(["--user", "--map-root-user"]);
                    }
                    "ipc" => {
                        command.arg("--ipc");
                    }
                    "time" => {
                        command.args(["--time", "--monotonic", "3600", "--fork"]);
                    }
                    _ => panic!("unknown namespace scenario"),
                }
                command
                    .arg(std::env::current_exe().unwrap())
                    .args(["--exact", "incompatible_namespace_fixture", "--ignored", "--nocapture"])
                    .env("TF_NAMESPACE_ROOT", root.path())
                    .env("TF_NAMESPACE_SCENARIO", &scenario)
                    .env("TF_NAMESPACE_PARENT_CLOCK", monotonic_ns().to_string())
                    .stdin(Stdio::null())
                    .status()
                    .unwrap()
            };
            assert!(status.success());
            assert_eq!(
                fs::read(root.path().join("scope/authority.state")).unwrap(),
                before,
                "a rejected namespace must not advance the authority clock or mutate ownership"
            );
            assert_eq!(scope.view().unwrap().physical, 1);
            Completion { value: (), operations: 1, failed: false }
        })
        .unwrap();
    let view = scope.view().unwrap();
    assert_eq!(view.physical, 0);
    assert!(view.charged_ns > 0);
}

#[test]
#[ignore = "incompatible namespace subprocess fixture"]
fn incompatible_namespace_fixture() {
    let root = PathBuf::from(std::env::var_os("TF_NAMESPACE_ROOT").unwrap());
    if std::env::var("TF_NAMESPACE_SCENARIO").as_deref() == Ok("time") {
        let parent: u64 = std::env::var("TF_NAMESPACE_PARENT_CLOCK").unwrap().parse().unwrap();
        assert!(monotonic_ns() - parent >= 3_600_000_000_000, "fixture did not change the monotonic epoch");
    }
    assert!(matches!(Scope::open(root.join("scope"), config()), Err(Error::Incompatible)));
    let options = Options { scope: Rendezvous::Directory(root.join("scope")), limits: config() };
    for mode in [Mode::Auto(options.clone()), Mode::Required(options)] {
        assert!(matches!(
            HostGovernor::configured(&HostConfig::default(), mode),
            Err(HostGovernorError::Coordination(coordination::Error::Incompatible))
        ));
    }
}

fn monotonic_ns() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
}

fn thread_transition(root: &Path, scope: std::sync::Arc<Scope>) {
    let original = File::open("/proc/thread-self/ns/ipc").unwrap();
    let gate_path = root.join("gate");
    rustix::fs::mkfifoat(rustix::fs::CWD, &gate_path, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR).unwrap();
    let mut gate = OpenOptions::new().read(true).write(true).open(&gate_path).unwrap();
    let observer = Scope::open(root.join("scope"), config()).unwrap();
    let client = scope.join().unwrap();
    let worker_client = client.clone();
    let host = HostGovernor::configured(
        &HostConfig::default(),
        Mode::Auto(Options { scope: Rendezvous::Directory(root.join("scope")), limits: config() }),
    )
    .unwrap();
    let (started, ready) = mpsc::channel();
    let root = root.to_path_buf();
    let worker = std::thread::spawn(move || {
        worker_client
            .prepare(request())
            .unwrap()
            .try_run(|_| {
                // Only this worker enters another IPC namespace. The
                // thread-group leader stays in the old one,
                // exercising /proc/thread-self.
                assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWIPC) }, 0, "{}", std::io::Error::last_os_error());
                assert!(matches!(scope.view(), Err(Error::Incompatible)));
                assert!(matches!(worker_client.prepare(request()), Err(Error::Incompatible)));
                assert!(matches!(Scope::open(root.join("scope"), config()), Err(Error::Incompatible)));
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
                let status = host.coordination_status();
                assert!(matches!(status.requested, Mode::Auto(_)));
                assert!(matches!(status.state, coordination::State::Shared { failure: Some(_), .. }));
                assert_eq!(host.view(MonotonicTime::ZERO).charged, Duration::ZERO);
                started.send(()).unwrap();
                File::open(gate_path).unwrap().read_exact(&mut [0]).unwrap();
                assert_eq!(
                    unsafe { libc::setns(original.as_raw_fd(), libc::CLONE_NEWIPC) },
                    0,
                    "{}",
                    std::io::Error::last_os_error()
                );
                Completion { value: (), operations: 1, failed: false }
            })
            .unwrap();
    });
    ready.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(observer.view().unwrap().physical, 1);
    gate.write_all(&[1]).unwrap();
    worker.join().unwrap();
    let view = observer.view().unwrap();
    assert_eq!(view.physical, 0);
    assert!(view.charged_ns > 0);
}
