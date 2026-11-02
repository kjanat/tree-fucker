//! Entry point for actual RDP-session processes in the disposable guest.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;
use std::time::Instant;

use tree_fucker::coordination::authority::{self, Budget};
use tree_fucker::coordination::protocol::{self, Limits};
use tree_fucker::coordination::windows::Error;
use tree_fucker::coordination::{self, Mode, Options, Rendezvous, State};
use tree_fucker::{HostGovernor, HostGovernorError};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_STATISTICS, TokenElevation,
    TokenIsAppContainer, TokenSessionId, TokenStatistics,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::*;

fn limits() -> Config {
    let budget = Budget { refill_ns_per_second: 1_000_000_000, burst_ns: 3_600_000_000_000 };
    Config {
        ownership: Limits { participants: 8, operations: 32, physical: 2 },
        domains: 8,
        background: budget,
        foreground: budget,
        domain_background: budget,
        domain_foreground: budget,
        bootstrap_ns: 3_600_000_000_000,
        per_domain_physical: 2,
        initial_estimate_ns: 1_000_000,
        stuck_after_ns: 3_600_000_000_000,
        failure_surcharge_ns: 1_000_000,
    }
}

fn retry<T>(mut call: impl FnMut() -> Result<T, Error>) -> T {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match call() {
            Ok(value) => return value,
            Err(Error::Busy) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Err(error) => panic!("session coordination failed: {error}"),
        }
    }
}

fn token_value<T: Default>(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> T {
    let mut value = T::default();
    let mut length = 0;
    // SAFETY: each caller pairs the class with its fixed Windows output type.
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                class,
                (&mut value as *mut T).cast(),
                size_of::<T>() as u32,
                &mut length,
            )
        },
        0
    );
    assert_eq!(length as usize, size_of::<T>());
    value
}

fn caller_report() -> String {
    let mut token = null_mut();
    // SAFETY: current process pseudo-handle and a newly owned token handle.
    assert_ne!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }, 0);
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let session: u32 = token_value(&token, TokenSessionId);
    let statistics: TOKEN_STATISTICS = token_value(&token, TokenStatistics);
    let elevation: TOKEN_ELEVATION = token_value(&token, TokenElevation);
    let appcontainer: u32 = token_value(&token, TokenIsAppContainer);
    assert_ne!(session, 0, "session fixtures must run in real interactive sessions");
    let expected = u32::from(std::env::var("TF_SESSION_CONTEXT").unwrap() == "appcontainer");
    assert_eq!(appcontainer, expected, "the fixture must use the requested real token class");
    format!(
        "session={session}\nlogon={}:{}\nelevated={}\nappcontainer={appcontainer}\n",
        statistics.AuthenticationId.HighPart, statistics.AuthenticationId.LowPart, elevation.TokenIsElevated,
    )
}

fn report(root: &Path, name: &str, scope: &Scope) {
    let caller = caller_report();
    let diagnostics = scope.diagnostics().unwrap();
    let view = retry(|| scope.view());
    let contents = format!(
        "{caller}user={}\ngeneration={:?}\npath={}\nphysical={}\nprepared={}\ncharged={}\nsurcharged={}\n",
        diagnostics.user,
        diagnostics.generation,
        diagnostics.path.display(),
        view.physical,
        view.prepared,
        view.charged_ns,
        view.surcharged_ns,
    );
    // The controller observes the ready marker only after the complete report.
    fs::write(root.join(format!("{name}.report")), contents).unwrap();
    fs::write(root.join(format!("{name}.ready")), []).unwrap();
}

#[test]
#[ignore = "launched with a real interactive user token by the disposable guest controller"]
fn interactive_session_fixture() {
    let root = PathBuf::from(std::env::var_os("TF_SESSION_ROOT").unwrap());
    let name = std::env::var("TF_SESSION_NAME").unwrap();
    assert!(name.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'));
    let mode = std::env::var("TF_SESSION_MODE").unwrap();
    let location = std::env::var_os("TF_SESSION_SCOPE").unwrap();
    let rendezvous = if location == "discover" { Rendezvous::Discover } else { Rendezvous::Directory(location.into()) };
    if mode == "denied" {
        let options = Options { scope: rendezvous, limits: limits() };
        let automatic = HostGovernor::configured(&HostConfig::default(), Mode::Auto(options.clone())).unwrap();
        assert!(matches!(
            automatic.coordination_status().state,
            State::Fallback { reason: coordination::Error::Unavailable(_) }
        ));
        assert!(matches!(
            HostGovernor::configured(&HostConfig::default(), Mode::Required(options)),
            Err(HostGovernorError::Coordination(coordination::Error::Unavailable(_)))
        ));
        fs::write(root.join(format!("{name}.report")), caller_report() + "unavailable=true\n").unwrap();
        fs::write(root.join(format!("{name}.ready")), []).unwrap();
        return;
    }
    let scope = retry(|| match &rendezvous {
        Rendezvous::Discover => Scope::discover(limits()),
        Rendezvous::Directory(path) => Scope::open(path, limits()),
    });
    if mode == "observe" {
        report(&root, &name, &scope);
        return;
    }
    let client = retry(|| scope.join());
    let mut prepared = retry(|| client.prepare(request()));
    if mode == "probe" {
        let result =
            prepared.try_run(|_| -> Completion<()> { panic!("a third session process exceeded the shared ceiling") });
        assert!(matches!(result, Err(Error::Authority(authority::Error::Protocol(protocol::Error::PhysicalCapacity)))));
        drop(prepared);
        report(&root, &name, &scope);
        return;
    }
    assert_eq!(mode, "hold");
    retry(|| {
        prepared.try_run(|_| {
            let data = root.join(format!("{name}.data"));
            fs::write(&data, b"interactive session filesystem work").unwrap();
            assert_eq!(fs::read(&data).unwrap(), b"interactive session filesystem work");
            report(&root, &name, &scope);
            let deadline = Instant::now() + Duration::from_secs(180);
            while !root.join(format!("{name}.release")).exists() {
                assert!(Instant::now() < deadline, "guest controller did not release the session owner");
                std::thread::sleep(Duration::from_millis(10));
            }
            Completion { value: (), operations: 1, failed: false }
        })
    });
}
