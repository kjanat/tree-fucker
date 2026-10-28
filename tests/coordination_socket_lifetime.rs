//! Native lifetime acceptance for a Solaris owner-slot candidate.
//! A bound datagram endpoint needs no accept loop or queued probe messages.
#![cfg(unix)]

#[path = "coordination_support/fifo.rs"]
mod native_fifo;

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn identity(path: &Path) -> (u64, u64) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (metadata.dev(), metadata.ino())
}

#[track_caller]
fn alive(path: &Path) -> bool {
    let probe = UnixDatagram::unbound().unwrap();
    probe.set_nonblocking(true).unwrap();
    match probe.connect(path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => false,
        // OmniOS and Solaris 11.4 return this for a retained pathname after its last
        // endpoint description closes. The histories below verify the live,
        // duplicated, inherited, and final-close cases independently.
        #[cfg(any(target_os = "illumos", target_os = "solaris"))]
        Err(error) if error.raw_os_error() == Some(libc::EDESTADDRREQ) => false,
        Err(error) => panic!("socket lifetime is unknown: {error}"),
    }
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !predicate() {
        assert!(Instant::now() < deadline, "socket lifetime transition did not complete");
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn datagram_probes_do_not_queue_messages_or_release_duplicated_ownership() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("owner");
    let owner = UnixDatagram::bind(&path).unwrap();
    owner.set_nonblocking(true).unwrap();
    let retained = identity(&path);
    for _ in 0..1024 {
        assert!(alive(&path));
    }
    assert_eq!(owner.recv(&mut [0]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    let duplicate = owner.try_clone().unwrap();
    drop(owner);
    assert!(alive(&path));
    drop(duplicate);
    wait_until(|| !alive(&path));
    // Closing the endpoint leaves the evidence pathname and inode intact.
    assert_eq!(identity(&path), retained);
}

#[test]
fn connected_probe_does_not_keep_a_closed_owner_discoverable() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("owner");
    let owner = UnixDatagram::bind(&path).unwrap();
    let probe = UnixDatagram::unbound().unwrap();
    probe.connect(&path).unwrap();
    drop(owner);
    wait_until(|| !alive(&path));
    drop(probe);
}

struct Fixture {
    child: Child,
    gate: File,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = self.gate.write_all(&[1]);
    }
}

#[test]
fn inherited_datagram_owner_survives_original_process_death() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("owner");
    let gate = root.path().join("gate");
    native_fifo::create(&gate).unwrap();
    let gate = OpenOptions::new().read(true).write(true).open(gate).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "inherited_socket_fixture", "--ignored", "--nocapture"])
        .env("TF_SOCKET_FIXTURE", root.path())
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let mut fixture = Fixture { child, gate };
    wait_until(|| {
        assert!(fixture.child.try_wait().unwrap().is_none(), "owner fixture exited before fork");
        root.path().join("forked").exists()
    });
    let retained = identity(&path);
    fixture.child.kill().unwrap();
    assert!(!fixture.child.wait().unwrap().success());
    for _ in 0..64 {
        assert!(alive(&path), "original process death does not retire the inherited endpoint");
    }
    fixture.gate.write_all(&[1]).unwrap();
    wait_until(|| !alive(&path));
    assert_eq!(identity(&path), retained);
}

#[test]
#[ignore = "forked endpoint fixture launched by the lifetime acceptance test"]
fn inherited_socket_fixture() {
    let root = std::env::var_os("TF_SOCKET_FIXTURE").unwrap();
    let root = Path::new(&root);
    let _owner = UnixDatagram::bind(root.join("owner")).unwrap();
    let mut gate = File::open(root.join("gate")).unwrap();
    // SAFETY: the child only reads an inherited descriptor and calls _exit.
    // It never accesses inherited Rust locks, allocation, or destructors.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let mut byte = 0_u8;
        unsafe {
            libc::read(gate.as_raw_fd(), (&mut byte as *mut u8).cast(), 1);
            libc::_exit(0);
        }
    }
    fs::write(root.join("forked"), []).unwrap();
    // The acceptance parent kills this original process before releasing the
    // descendant, so both processes retain an endpoint until then.
    gate.read_exact(&mut [0]).unwrap();
}
