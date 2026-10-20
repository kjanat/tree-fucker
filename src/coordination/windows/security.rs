//! Effective-caller checks and private Windows coordination objects.

use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{ERROR_NO_TOKEN, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, GetAce, GetLengthSid,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation,
    IsValidAcl, IsValidSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED,
    SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER, TokenIsAppContainer,
    TokenSessionId, TokenStatistics, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_TRAVERSE, READ_CONTROL,
};
#[cfg(test)]
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken};

fn invalid(reason: &'static str) -> io::Error {
    // Unsafe existing state is not simple unavailability: Auto selection must
    // not turn a malformed/broadened authority into an independent budget.
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: every instance owns an allocation returned by a Windows API
        // whose contract requires LocalFree.
        unsafe {
            LocalFree(self.0);
        }
    }
}

// The SID pointers passed here come from validated Windows output structures.
unsafe fn sid_text(sid: PSID) -> io::Result<String> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(invalid("coordination security descriptor contains an invalid SID"));
    }
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _allocation = Local(text.cast());
    let mut length = 0;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| invalid("Windows returned an invalid SID string"))
}

fn effective_token(access: u32) -> io::Result<OwnedHandle> {
    let mut token = null_mut();
    // SAFETY: pseudo-handles refer to this process/thread. The successful call
    // transfers a real token handle to OwnedHandle. OpenAsSelf controls access
    // to the token, not which effective token is queried.
    unsafe {
        if OpenThreadToken(GetCurrentThread(), access, 1, &mut token) == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
                return Err(error);
            }
            if OpenProcessToken(GetCurrentProcess(), access, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(OwnedHandle::from_raw_handle(token))
    }
}

fn token_value<T: Default>(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<T> {
    let mut value = T::default();
    let mut length = 0;
    // SAFETY: callers pair each fixed-size token class with its Windows output
    // type. The buffer is live, aligned, and its exact size is supplied.
    if unsafe { GetTokenInformation(token, class, (&mut value as *mut T).cast(), size_of::<T>() as u32, &mut length) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<T>() {
        return Err(io::Error::other("unexpected token information length"));
    }
    Ok(value)
}

/// Session and authentication identify a live handle's caller context. Scope
/// discovery must use the user identity, not the authentication ID: another
/// login must reopen retained accounting instead of creating a fresh budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Principal {
    pub sid: String,
    pub sid_bytes: [u8; 68],
    pub session: u32,
    pub authentication: [u32; 2],
    token: [u32; 2],
    revision: [u32; 2],
}

impl Principal {
    pub(crate) fn local_data_directory(&self) -> io::Result<PathBuf> {
        use std::os::windows::ffi::OsStringExt;

        use windows_sys::Win32::Security::{TOKEN_DUPLICATE, TOKEN_IMPERSONATE};
        use windows_sys::Win32::System::Com::CoTaskMemFree;
        use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath};

        self.check()?;
        let token = effective_token(TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE)?;
        let mut path = null_mut();
        // SAFETY: the effective token remains live; the API owns the returned
        // NUL-terminated allocation until CoTaskMemFree below.
        let result = unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, token.as_raw_handle(), &mut path) };
        if result < 0 {
            // SAFETY: the API requires freeing its output even on failure;
            // CoTaskMemFree accepts a null pointer.
            unsafe {
                CoTaskMemFree(path.cast());
            }
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Windows local application-data discovery failed: HRESULT {result:#x}"),
            ));
        }
        if path.is_null() {
            return Err(invalid("Windows returned no local application-data path"));
        }
        let mut length = 0;
        // SAFETY: a successful API call returns a NUL-terminated wide string.
        let value = unsafe {
            while *path.add(length) != 0 {
                length += 1;
            }
            let value = std::ffi::OsString::from_wide(std::slice::from_raw_parts(path, length));
            CoTaskMemFree(path.cast());
            value
        };
        self.check()?;
        Ok(PathBuf::from(value))
    }

    pub(crate) fn current() -> io::Result<Self> {
        let token = effective_token(TOKEN_QUERY)?;
        let handle = token.as_raw_handle();
        if token_value::<u32>(handle, TokenIsAppContainer)? != 0 {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "coordination is unavailable in an AppContainer"));
        }
        // TOKEN_USER contains an embedded SID pointer. A fixed aligned buffer
        // covers its header plus SECURITY_MAX_SID_SIZE on both architectures.
        let mut user = [0usize; 32];
        let mut length = 0;
        // SAFETY: aligned live output buffer; Windows returns a SID within it.
        let (sid, sid_bytes) = unsafe {
            if GetTokenInformation(handle, TokenUser, user.as_mut_ptr().cast(), size_of_val(&user) as u32, &mut length)
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            if (length as usize) < size_of::<TOKEN_USER>() {
                return Err(io::Error::other("truncated token user"));
            }
            let sid = (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid;
            let text = sid_text(sid)?;
            let length = GetLengthSid(sid) as usize;
            let mut bytes = [0; 68];
            if length > bytes.len() {
                return Err(invalid("Windows returned an oversized SID"));
            }
            bytes[..length].copy_from_slice(std::slice::from_raw_parts(sid.cast::<u8>(), length));
            (text, bytes)
        };
        let statistics: TOKEN_STATISTICS = token_value(handle, TokenStatistics)?;
        Ok(Self {
            sid,
            sid_bytes,
            session: token_value(handle, TokenSessionId)?,
            authentication: [statistics.AuthenticationId.LowPart, statistics.AuthenticationId.HighPart as u32],
            token: [statistics.TokenId.LowPart, statistics.TokenId.HighPart as u32],
            revision: [statistics.ModifiedId.LowPart, statistics.ModifiedId.HighPart as u32],
        })
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        if Self::current()? != *self {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "coordination caller context changed"));
        }
        Ok(())
    }

    pub(crate) fn validate(&self, file: &File, directory: bool) -> io::Result<()> {
        super::storage::validate(file)?;
        let mut descriptor = null_mut();
        // SAFETY: live handle and owned output allocation. Components remain
        // inside the allocation until Descriptor is dropped.
        let result = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        Descriptor(Local(descriptor)).validate(self, directory)
    }

    #[cfg(test)]
    pub(crate) fn open_file(&self, path: &Path, create: bool, share: u32) -> io::Result<File> {
        let parent = path.parent().ok_or_else(|| invalid("coordination file has no parent"))?;
        let name = path.file_name().ok_or_else(|| invalid("coordination file has no name"))?;
        let parent = super::relative::Directory::open(parent)?;
        self.open_at(parent.handle(), name, create, share, false)
    }

    #[cfg(test)]
    pub(crate) fn directory(&self, path: &Path, create: bool) -> io::Result<File> {
        let parent = path.parent().ok_or_else(|| invalid("coordination directory has no parent"))?;
        let name = path.file_name().ok_or_else(|| invalid("coordination directory has no name"))?;
        let parent = super::relative::Directory::open(parent)?;
        self.open_at(parent.handle(), name, create, FILE_SHARE_READ | FILE_SHARE_WRITE, true)
    }

    /// Scope callers retain the parent pin across all journal transactions.
    pub(crate) fn open_at(
        &self,
        parent: &File,
        name: &OsStr,
        create: bool,
        share: u32,
        directory: bool,
    ) -> io::Result<File> {
        self.check()?;
        let descriptor = Descriptor::private(self, directory)?;
        let attributes = descriptor.attributes();
        let access = if directory {
            READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE
        } else {
            FILE_GENERIC_READ | FILE_GENERIC_WRITE
        };
        let file = super::relative::open(parent, name, access, share, directory, create.then_some(&attributes))?;
        self.validate(&file, directory)?;
        Ok(file)
    }
}

struct Descriptor(Local);

impl Descriptor {
    fn parse(text: &str) -> io::Result<Self> {
        let text: Vec<_> = text.encode_utf16().chain([0]).collect();
        let mut descriptor = null_mut();
        // SAFETY: a live NUL-terminated string and an owned LocalFree
        // allocation.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(Local(descriptor)))
    }

    fn private(principal: &Principal, directory: bool) -> io::Result<Self> {
        let flags = if directory { "OICI" } else { "" };
        Self::parse(&format!("O:{}D:P(A;{flags};FA;;;{})", principal.sid, principal.sid))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: 0,
        }
    }

    fn validate(&self, principal: &Principal, directory: bool) -> io::Result<()> {
        let mut control = 0;
        let mut revision = 0;
        let mut owner = null_mut();
        let mut defaulted = 0;
        let mut present = 0;
        let mut acl: *mut ACL = null_mut();
        // SAFETY: descriptor is a valid Windows-produced allocation. Component
        // pointers are borrowed only while it remains alive. IsValidAcl and
        // GetAce validate the variable-size access entry before dereferencing.
        unsafe {
            if GetSecurityDescriptorControl(self.0.0, &mut control, &mut revision) == 0
                || GetSecurityDescriptorOwner(self.0.0, &mut owner, &mut defaulted) == 0
                || GetSecurityDescriptorDacl(self.0.0, &mut present, &mut acl, &mut defaulted) == 0
            {
                return Err(io::Error::last_os_error());
            }
            if control & SE_DACL_PROTECTED == 0 {
                return Err(invalid("coordination DACL is not protected from inherited permissions"));
            }
            if sid_text(owner)? != principal.sid {
                return Err(invalid("coordination object belongs to another principal"));
            }
            if present == 0 || acl.is_null() || IsValidAcl(acl) == 0 || (*acl).AceCount != 1 {
                return Err(invalid("coordination DACL must contain exactly one explicit owner entry"));
            }
            let mut entry = null_mut();
            if GetAce(acl, 0, &mut entry) == 0 {
                return Err(io::Error::last_os_error());
            }
            let header = &*entry.cast::<ACE_HEADER>();
            let flags = if directory { OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE } else { 0 };
            if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
                || u32::from(header.AceFlags) != flags
                || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
            {
                return Err(invalid("coordination access entry has an invalid type, inheritance, or size"));
            }
            let ace = &*entry.cast::<ACCESS_ALLOWED_ACE>();
            if ace.Mask != FILE_ALL_ACCESS {
                return Err(invalid("coordination access entry must grant the owner full file access"));
            }
            let sid = (&ace.SidStart as *const u32).cast_mut().cast();
            if sid_text(sid)? != principal.sid
                || GetLengthSid(sid) as usize + std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart)
                    != usize::from(ace.Header.AceSize)
            {
                return Err(invalid("coordination access entry does not name the exact owner SID"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
    use windows_sys::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;

    #[test]
    fn native_discovery_is_stable_for_the_effective_user() {
        let first = Principal::current().unwrap();
        let path = first.local_data_directory().unwrap();
        assert!(path.is_absolute() && path.is_dir());
        let second = Principal::current().unwrap();
        assert_eq!(first.sid_bytes, second.sid_bytes);
        assert_eq!(path, second.local_data_directory().unwrap());
    }

    #[test]
    fn impersonation_fences_captured_context_even_with_the_same_user_sid() {
        use windows_sys::Win32::Security::{
            DuplicateTokenEx, RevertToSelf, SecurityImpersonation, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
            TokenImpersonation,
        };
        use windows_sys::Win32::System::Threading::SetThreadToken;

        std::thread::spawn(|| {
            let principal = Principal::current().unwrap();
            let mut source = null_mut();
            let mut duplicate = null_mut();
            // SAFETY: current process pseudo-handle, live output slots, and
            // individually owned token handles closed by OwnedHandle.
            unsafe {
                assert_ne!(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut source), 0);
                let source = OwnedHandle::from_raw_handle(source);
                assert_ne!(
                    DuplicateTokenEx(
                        source.as_raw_handle(),
                        TOKEN_QUERY | TOKEN_IMPERSONATE,
                        std::ptr::null(),
                        SecurityImpersonation,
                        TokenImpersonation,
                        &mut duplicate
                    ),
                    0
                );
            }
            // SAFETY: the successful duplication returned a new owned handle.
            let duplicate = unsafe { OwnedHandle::from_raw_handle(duplicate) };
            struct Revert;
            impl Drop for Revert {
                fn drop(&mut self) {
                    // SAFETY: this guard restores its test thread's original
                    // process token before any subsequent filesystem cleanup.
                    assert_ne!(unsafe { RevertToSelf() }, 0);
                }
            }
            // SAFETY: null selects only the current dedicated test thread.
            assert_ne!(unsafe { SetThreadToken(std::ptr::null(), duplicate.as_raw_handle()) }, 0);
            let revert = Revert;
            assert_eq!(Principal::current().unwrap().sid, principal.sid);
            assert!(principal.check().is_err(), "a different token must fence the old connection");
            drop(revert);
            principal.check().unwrap();
        })
        .join()
        .unwrap();
    }

    use super::*;

    #[test]
    fn private_descriptors_reject_missing_null_broad_and_inherited_access() {
        let principal = Principal::current().unwrap();
        for directory in [false, true] {
            Descriptor::private(&principal, directory).unwrap().validate(&principal, directory).unwrap();
        }
        for dacl in [
            String::new(),
            "D:NO_ACCESS_CONTROL".into(),
            "D:P".into(),
            format!("D:(A;;FA;;;{})", principal.sid),
            "D:P(A;;FA;;;WD)".into(),
            format!("D:P(A;;FA;;;{})(A;;FR;;;WD)", principal.sid),
            format!("D:P(A;;FR;;;{})", principal.sid),
            format!("D:P(A;IO;FA;;;{})", principal.sid),
            format!("D:P(D;;FA;;;{})", principal.sid),
        ] {
            let descriptor = Descriptor::parse(&format!("O:{}{dacl}", principal.sid)).unwrap();
            assert!(
                matches!(descriptor.validate(&principal, false), Err(error) if error.kind() == io::ErrorKind::InvalidData),
                "a non-private DACL must fail without permitting unavailable-mode fallback: {dacl}"
            );
        }
        let wrong_owner = Descriptor::parse(&format!("O:WDD:P(A;;FA;;;{})", principal.sid)).unwrap();
        assert!(wrong_owner.validate(&principal, false).is_err());
    }

    #[test]
    fn private_objects_survive_reopen_and_reject_acl_mutation_without_repair() {
        let root = tempfile::tempdir().unwrap();
        let principal = Principal::current().unwrap();
        let path = root.path().join("private");
        let directory = principal.directory(&path, true).unwrap();
        let file_path = path.join("state");
        let file = principal.open_file(&file_path, true, FILE_SHARE_READ | FILE_SHARE_WRITE).unwrap();
        principal.validate(&file, false).unwrap();
        drop(file);
        principal.open_file(&file_path, false, FILE_SHARE_READ | FILE_SHARE_WRITE).unwrap();
        drop(directory);
        principal.directory(&path, false).unwrap();

        // Widen the ACL through an explicitly opened WRITE_DAC handle. The
        // coordination path must reject it, not silently repair shared state.
        let writable = OpenOptions::new()
            .access_mode(windows_sys::Win32::Storage::FileSystem::WRITE_DAC | READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&file_path)
            .unwrap();
        let broad =
            Descriptor::parse(&format!("O:{}D:P(A;;FA;;;{})(A;;FR;;;WD)", principal.sid, principal.sid)).unwrap();
        let mut acl = null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        // SAFETY: live validated descriptor, output pointers, and WRITE_DAC
        // handle.
        unsafe {
            assert_ne!(GetSecurityDescriptorDacl(broad.0.0, &mut present, &mut acl, &mut defaulted), 0);
            assert_eq!(
                SetSecurityInfo(
                    writable.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    acl,
                    null_mut()
                ),
                0
            );
        }
        assert!(principal.open_file(&file_path, false, FILE_SHARE_READ | FILE_SHARE_WRITE).is_err());
        assert!(principal.validate(&writable, false).is_err(), "opening must not rewrite an unsafe ACL");
        assert!(principal.directory(root.path(), true).is_err(), "an existing shared parent is not a private scope");
    }
}
