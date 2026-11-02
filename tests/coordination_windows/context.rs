use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::ptr::null_mut;

use tree_fucker::coordination::{self, Mode, Options, Rendezvous, State};
use tree_fucker::{HostGovernor, HostGovernorError};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
    SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC};

use super::*;

struct Allocation(*mut c_void);

impl Drop for Allocation {
    fn drop(&mut self) {
        // SAFETY: these descriptors are returned by APIs requiring LocalFree.
        unsafe { LocalFree(self.0) };
    }
}

struct ChangedDacl {
    file: File,
    original: Allocation,
}

fn set_dacl(file: &File, descriptor: &Allocation) {
    let mut acl = null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    // SAFETY: the descriptor owns the ACL throughout the synchronous call;
    // the file was opened with WRITE_DAC and remains live.
    unsafe {
        assert_ne!(GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted), 0);
        assert_ne!(present, 0);
        assert_eq!(
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null_mut(),
            ),
            0
        );
    }
}

impl ChangedDacl {
    fn new(path: &Path, dacl: &str) -> Self {
        let file = OpenOptions::new()
            .access_mode(WRITE_DAC | READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)
            .unwrap();
        let mut original = null_mut();
        // SAFETY: a live readable-security handle and owned output descriptor.
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut original,
                )
            },
            0
        );
        let guard = Self { file, original: Allocation(original) };
        let text: Vec<_> = dacl.encode_utf16().chain([0]).collect();
        let mut descriptor = null_mut();
        // SAFETY: NUL-terminated SDDL and an output allocation owned below.
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            },
            0
        );
        set_dacl(&guard.file, &Allocation(descriptor));
        guard
    }
}

impl Drop for ChangedDacl {
    fn drop(&mut self) {
        set_dacl(&self.file, &self.original);
    }
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

#[test]
fn native_policy_distinguishes_denied_and_broadened_acl() {
    let principal = Principal::current().unwrap();
    for broad in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("scope");
        let config = authority().config();
        let scope = Scope::open(&path, config).unwrap();
        let generation = scope.diagnostics().unwrap().generation;
        let client = scope.join().unwrap();
        client.prepare(request()).unwrap().try_run(|_| Completion { value: (), operations: 1, failed: false }).unwrap();
        let charged = scope.view().unwrap().charged_ns;
        drop((client, scope));
        let dacl = if broad { format!("D:P(A;;FA;;;{})(A;;FR;;;WD)", principal.sid) } else { "D:P".into() };
        let changed = ChangedDacl::new(&path.join("authority.state"), &dacl);
        let options = Options { scope: Rendezvous::Directory(path.clone()), limits: config };
        let automatic = HostGovernor::configured(&HostConfig::default(), Mode::Auto(options.clone()));
        let required = HostGovernor::configured(&HostConfig::default(), Mode::Required(options));
        if broad {
            assert!(matches!(automatic, Err(HostGovernorError::Coordination(coordination::Error::Failed(_)))));
            assert!(matches!(required, Err(HostGovernorError::Coordination(coordination::Error::Failed(_)))));
        } else {
            assert!(matches!(
                automatic.unwrap().coordination_status().state,
                State::Fallback { reason: coordination::Error::Unavailable(_) }
            ));
            assert!(matches!(required, Err(HostGovernorError::Coordination(coordination::Error::Unavailable(_)))));
        }
        drop(changed);
        let reopened = Scope::open(&path, config).unwrap();
        assert_eq!(reopened.diagnostics().unwrap().generation, generation);
        assert_eq!(reopened.view().unwrap().charged_ns, charged);
    }
}

#[test]
fn acl_change_after_join_fences_admission_and_preserves_ownership() {
    use tree_fucker::core::{GrantId, MonotonicTime, Reservation, WorkOrigin};

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("scope");
    let config = authority().config();
    let scope = Scope::open(&path, config).unwrap();
    let options = Options { scope: Rendezvous::Directory(path.clone()), limits: config };
    let host = HostGovernor::configured(&HostConfig::default(), Mode::Auto(options.clone())).unwrap();
    let State::Shared { scope: identity_before, failure: None, .. } = host.coordination_status().state else {
        panic!("shared mode")
    };
    let client = scope.join().unwrap();
    let prepared = client.prepare(request()).unwrap();
    let mut running = client.prepare(request()).unwrap();
    let mut charged_before = 0;
    let result = running.try_run(|_| {
        let before = scope.view().unwrap();
        assert_eq!((before.prepared, before.physical), (1, 1));
        charged_before = before.charged_ns;
        let principal = Principal::current().unwrap();
        let changed =
            ChangedDacl::new(&path.join("authority.state"), &format!("D:P(A;;FA;;;{})(A;;FR;;;WD)", principal.sid));
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
        assert!(scope.view().is_err());
        assert!(scope.diagnostics().unwrap().failed);
        // Reading the published journal avoids repairing or recovering anything
        // while its original physical owner is still active.
        let retained =
            Journal::open(OpenOptions::new().read(true).write(true).open(path.join("authority.state")).unwrap())
                .unwrap()
                .load()
                .unwrap()
                .view();
        assert_eq!((retained.prepared, retained.physical), (1, 1));
        assert!(retained.charged_ns >= charged_before);
        drop(changed);
        let fresh = Scope::open(&path, config).unwrap();
        let retained = fresh.view().unwrap();
        assert_eq!((retained.prepared, retained.physical), (1, 1));
        Completion { value: (), operations: 1, failed: false }
    });
    assert!(result.is_err(), "a fenced connection cannot publish success");
    let status = host.coordination_status();
    assert_eq!(status.requested, Mode::Auto(options));
    let State::Shared { scope: identity_after, failure: Some(_), .. } = status.state else {
        panic!("failed shared mode")
    };
    assert_eq!(identity_after, identity_before);
    drop((running, prepared, client, scope, host));
    let fresh = Scope::open(&path, config).unwrap();
    let recovered = fresh.view().unwrap();
    assert_eq!((recovered.prepared, recovered.physical, recovered.participants), (0, 0, 0));
    assert!(recovered.charged_ns >= charged_before);
    assert_eq!(recovered.surcharged_ns, u128::from(config.failure_surcharge_ns));
    let replay = fresh.view().unwrap();
    assert_eq!((replay.charged_ns, replay.surcharged_ns), (recovered.charged_ns, recovered.surcharged_ns));
}

#[test]
fn token_identity_and_revision_changes_retain_outstanding_liabilities() {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Foundation::{GetLastError, LUID};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, DuplicateTokenEx, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, RevertToSelf,
        SE_PRIVILEGE_ENABLED, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
        TOKEN_PRIVILEGES, TOKEN_QUERY, TokenImpersonation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, SetThreadToken};

    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            // SAFETY: restores only this dedicated test thread's token.
            assert_ne!(unsafe { RevertToSelf() }, 0);
        }
    }
    std::thread::spawn(|| {
        for change_revision in [false, true] {
            let mut source = null_mut();
            let mut duplicate = null_mut();
            // SAFETY: live output slots and independently owned token handles.
            let duplicate = unsafe {
                assert_ne!(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut source), 0);
                let source = OwnedHandle::from_raw_handle(source);
                assert_ne!(
                    DuplicateTokenEx(
                        source.as_raw_handle(),
                        TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_PRIVILEGES,
                        std::ptr::null(),
                        SecurityImpersonation,
                        TokenImpersonation,
                        &mut duplicate,
                    ),
                    0
                );
                OwnedHandle::from_raw_handle(duplicate)
            };
            let mut revert = None;
            if change_revision {
                // SAFETY: null selects the current dedicated test thread.
                assert_ne!(unsafe { SetThreadToken(std::ptr::null(), duplicate.as_raw_handle()) }, 0);
                revert = Some(Revert);
            }
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("scope");
            let config = authority().config();
            let scope = Scope::open(&path, config).unwrap();
            let generation = scope.diagnostics().unwrap().generation;
            let client = scope.join().unwrap();
            let prepared = client.prepare(request()).unwrap();
            let mut running = client.prepare(request()).unwrap();
            let mut charged_before = 0;
            let result = running.try_run(|_| {
                let before = scope.view().unwrap();
                assert_eq!((before.prepared, before.physical), (1, 1));
                charged_before = before.charged_ns;
                let principal = Principal::current().unwrap();
                if change_revision {
                    let name: Vec<_> = "SeChangeNotifyPrivilege".encode_utf16().chain([0]).collect();
                    let mut luid = LUID::default();
                    // SAFETY: a live terminated privilege name and output LUID.
                    assert_ne!(unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) }, 0);
                    // Mutate only our duplicate. Toggling both ways guarantees
                    // a ModifiedId change even if it started disabled.
                    for attributes in [0, SE_PRIVILEGE_ENABLED] {
                        let privileges = TOKEN_PRIVILEGES {
                            PrivilegeCount: 1,
                            Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: attributes }],
                        };
                        // SAFETY: the token grants ADJUST_PRIVILEGES, and the
                        // fixed structure contains exactly the advertised
                        // entry.
                        assert_ne!(
                            unsafe {
                                AdjustTokenPrivileges(
                                    duplicate.as_raw_handle(),
                                    0,
                                    &privileges,
                                    0,
                                    null_mut(),
                                    null_mut(),
                                )
                            },
                            0
                        );
                        assert_eq!(unsafe { GetLastError() }, 0, "the duplicate must hold the named privilege");
                    }
                } else {
                    // SAFETY: switches only this test thread to its duplicate.
                    assert_ne!(unsafe { SetThreadToken(std::ptr::null(), duplicate.as_raw_handle()) }, 0);
                    revert = Some(Revert);
                }
                assert!(principal.check().is_err());
                assert!(matches!(scope.view(), Err(tree_fucker::coordination::windows::Error::Incompatible)));
                assert!(matches!(
                    client.prepare(request()),
                    Err(tree_fucker::coordination::windows::Error::Incompatible)
                ));
                let fresh = Scope::open(&path, config).unwrap();
                assert_eq!(fresh.diagnostics().unwrap().generation, generation);
                let retained = fresh.view().unwrap();
                assert_eq!((retained.prepared, retained.physical), (1, 1));
                assert!(retained.charged_ns >= charged_before);
                Completion { value: (), operations: 1, failed: false }
            });
            assert!(result.is_err(), "completion on a changed token must be fenced");
            drop((running, prepared, client, scope));
            let fresh = Scope::open(&path, config).unwrap();
            let recovered = fresh.view().unwrap();
            assert_eq!((recovered.participants, recovered.prepared, recovered.physical), (0, 0, 0));
            assert!(recovered.charged_ns >= charged_before);
            assert_eq!(recovered.surcharged_ns, u128::from(config.failure_surcharge_ns));
            let replay = fresh.view().unwrap();
            assert_eq!((replay.charged_ns, replay.surcharged_ns), (recovered.charged_ns, recovered.surcharged_ns));
            drop(fresh);
            drop(revert);
        }
    })
    .join()
    .unwrap();
}
