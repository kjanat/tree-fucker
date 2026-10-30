use tree_fucker::coordination::{self, Mode, Options, Rendezvous, State};
use tree_fucker::{HostConfig, HostGovernor, HostGovernorError};

fn options() -> Options {
    Options {
        scope: Rendezvous::Discover,
        limits: coordination::authority::Config::from_host(&HostConfig::default(), 8, 32, 16).unwrap(),
    }
}

#[test]
fn process_only_is_the_default_and_remains_observable() {
    let host = HostGovernor::configured(&HostConfig::default(), Mode::default()).unwrap();
    assert_eq!(
        host.coordination_status(),
        coordination::Status { requested: Mode::ProcessOnly, state: State::ProcessOnly }
    );
    assert_eq!(HostGovernor::independent(&HostConfig::default()).coordination_status(), host.coordination_status());
}

#[test]
fn auto_never_hides_invalid_configuration() {
    let mut options = options();
    options.limits.ownership.physical = 0;
    assert!(matches!(
        HostGovernor::configured(&HostConfig::default(), Mode::Auto(options)),
        Err(HostGovernorError::Coordination(coordination::Error::InvalidConfig(_)))
    ));
}

#[test]
#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos", windows)))]
fn unavailable_native_backend_has_explicit_required_and_auto_outcomes() {
    let host = HostGovernor::configured(&HostConfig::default(), Mode::Auto(options())).unwrap();
    assert!(matches!(
        host.coordination_status().state,
        State::Fallback { reason: coordination::Error::UnsupportedPlatform }
    ));
    assert!(matches!(
        HostGovernor::configured(&HostConfig::default(), Mode::Required(options())),
        Err(HostGovernorError::Coordination(coordination::Error::UnsupportedPlatform))
    ));
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos"))]
mod native {
    use coordination_support::native::Scope;

    use super::*;

    fn fixture() -> (tempfile::TempDir, Options) {
        let root = tempfile::Builder::new()
            .prefix("tree-fucker-policy-")
            .tempdir_in(coordination_support::RENDEZVOUS)
            .unwrap();
        let options = Options { scope: Rendezvous::Directory(root.path().join("scope")), ..options() };
        (root, options)
    }

    #[test]
    fn unavailable_prejoin_scope_is_reported_in_auto_and_rejected_in_required() {
        let (root, mut options) = fixture();
        options.scope = Rendezvous::Directory(root.path().join("missing/scope"));
        let host = HostGovernor::configured(&HostConfig::default(), Mode::Auto(options.clone())).unwrap();
        assert_eq!(host.coordination_status().requested, Mode::Auto(options.clone()));
        assert!(matches!(
            host.coordination_status().state,
            State::Fallback { reason: coordination::Error::Unavailable(_) }
        ));
        assert!(matches!(
            HostGovernor::configured(&HostConfig::default(), Mode::Required(options)),
            Err(HostGovernorError::Coordination(coordination::Error::Unavailable(_)))
        ));
        assert!(!root.path().join("missing").exists());
    }

    #[test]
    fn auto_keeps_the_shared_identity_after_a_postjoin_failure() {
        use tree_fucker::core::{GrantId, MonotonicTime, Reservation, WorkOrigin};
        let (root, options) = fixture();
        let host = HostGovernor::configured(&HostConfig::default(), Mode::Auto(options.clone())).unwrap();
        let State::Shared { scope, failure: None, .. } = host.coordination_status().state else {
            panic!("shared mode")
        };
        assert_eq!(scope.limits, options.limits);
        std::fs::rename(root.path().join("scope"), root.path().join("old")).unwrap();
        let reservation = Reservation {
            id: GrantId::Bootstrap(host.next_bootstrap()),
            path: tree_fucker::RelativePath::root(),
            reads: 1,
            registrations: 0,
            operations: 0,
            ceiling: None,
            lease: 0,
            domain: None,
            origin: WorkOrigin::Foreground,
            listing: false,
        };
        assert_eq!(
            host.try_admit(reservation, MonotonicTime::ZERO),
            Err(tree_fucker::ThrottleCause::CoordinationFailed)
        );
        let status = host.coordination_status();
        assert_eq!(status.requested, Mode::Auto(options));
        let State::Shared { scope: after, failure: Some(_), .. } = status.state else { panic!("failed shared mode") };
        assert_eq!(scope, after);
        assert_eq!(host.view(MonotonicTime::ZERO).charged, std::time::Duration::ZERO);
    }

    #[test]
    fn busy_incompatible_full_and_corrupt_authorities_do_not_enable_auto_fallback() {
        use std::io::{Seek, SeekFrom, Write};

        use rustix::fs::{FlockOperation, flock};
        let (root, mut options) = fixture();
        options.limits.ownership.participants = 1;
        let scope = Scope::open(root.path().join("scope"), options.limits).unwrap();
        let client = scope.join().unwrap();
        assert!(matches!(
            HostGovernor::configured(&HostConfig::default(), Mode::Auto(options.clone())),
            Err(HostGovernorError::Coordination(coordination::Error::Capacity(_)))
        ));
        let lock =
            std::fs::OpenOptions::new().read(true).write(true).open(root.path().join("scope.authority.lock")).unwrap();
        flock(&lock, FlockOperation::LockExclusive).unwrap();
        assert!(matches!(
            HostGovernor::configured(&HostConfig::default(), Mode::Auto(options.clone())),
            Err(HostGovernorError::Coordination(coordination::Error::Busy))
        ));
        flock(&lock, FlockOperation::Unlock).unwrap();
        let mut incompatible = options.clone();
        incompatible.limits.domains += 1;
        assert!(matches!(
            HostGovernor::configured(&HostConfig::default(), Mode::Auto(incompatible)),
            Err(HostGovernorError::Coordination(coordination::Error::Incompatible))
        ));
        drop(client);
        let mut state =
            std::fs::OpenOptions::new().write(true).open(root.path().join("scope/authority.state")).unwrap();
        state.seek(SeekFrom::Start(0)).unwrap();
        state.write_all(b"corrupt!").unwrap();
        assert!(matches!(
            HostGovernor::configured(&HostConfig::default(), Mode::Auto(options)),
            Err(HostGovernorError::Coordination(coordination::Error::Failed(_)))
        ));
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "macos"))]
mod coordination_support;
