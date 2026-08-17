use std::ffi::c_void;
use std::io;
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{addr_of, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    AddAccessAllowedAceEx, CopySid, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid,
    GetAce, GetAclInformation, GetLengthSid, GetTokenInformation, INHERIT_ONLY_ACE, InitializeAcl,
    IsValidSid, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const MUTATING_RIGHTS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

pub(crate) fn path_acl_is_trusted(path: &Path, system_scope: bool) -> io::Result<bool> {
    let path = wide_path(path);
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: all output pointers are valid for the duration of the call and
    // `path` is a terminated Windows path. The returned descriptor is released
    // with `LocalFree` below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _descriptor = LocalDescriptor(descriptor);
    if owner.is_null() || dacl.is_null() {
        return Ok(false);
    }

    let sids = TrustedSids::load()?;
    if !sids.is_trusted(owner, system_scope) {
        return Ok(false);
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` belongs to the live security descriptor and the output
    // buffer has exactly the declared structure size.
    if unsafe {
        GetAclInformation(
            dacl,
            &mut information as *mut _ as *mut c_void,
            size_of_val(&information) as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    for index in 0..information.AceCount {
        let mut raw_ace = null_mut();
        // SAFETY: the ACL was returned by Windows and `index` is below its
        // reported ACE count.
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = unsafe { &*(raw_ace as *const ACE_HEADER) };
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        match u32::from(header.AceType) {
            ACCESS_ALLOWED_ACE_TYPE => {
                if usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
                    return Ok(false);
                }
                let ace = unsafe { &*(raw_ace as *const ACCESS_ALLOWED_ACE) };
                if ace.Mask & MUTATING_RIGHTS != 0 {
                    let sid = addr_of!(ace.SidStart) as PSID;
                    if unsafe { IsValidSid(sid) } == 0 || !sids.is_trusted(sid, system_scope) {
                        return Ok(false);
                    }
                }
            }
            ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_COMPOUND_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                // Conditional and object-specific allow ACEs require a full
                // token access check to interpret. Refuse them rather than
                // accidentally treating an untrusted write grant as safe.
                return Ok(false);
            }
            _ => {}
        }
    }
    Ok(true)
}

pub(crate) fn make_path_private(path: &Path) -> io::Result<()> {
    let sids = TrustedSids::load()?;
    let principals = [sids.current(), sids.system(), sids.administrators()];
    set_path_dacl(path, &principals)
}

fn set_path_dacl(path: &Path, principals: &[PSID]) -> io::Result<()> {
    let acl_bytes = size_of::<ACL>()
        + principals
            .iter()
            .map(|sid| {
                size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>()
                    + unsafe { GetLengthSid(*sid) as usize }
            })
            .sum::<usize>();
    let mut storage = vec![0_u32; acl_bytes.div_ceil(size_of::<u32>())];
    let acl = storage.as_mut_ptr() as *mut ACL;
    // SAFETY: `storage` is aligned, writable, and at least `acl_bytes` long.
    if unsafe { InitializeAcl(acl, acl_bytes as u32, ACL_REVISION) } == 0 {
        return Err(io::Error::last_os_error());
    }
    for sid in principals.iter().copied() {
        // SAFETY: the ACL was initialized with enough capacity for every ACE,
        // and every SID comes from a validated Windows API.
        if unsafe { AddAccessAllowedAceEx(acl, ACL_REVISION, 0, FILE_ALL_ACCESS, sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let path = wide_path(path);
    // SAFETY: `path` and `acl` remain live for the call. Passing null owner,
    // group, and SACL pointers updates only the protected DACL.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null_mut(),
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

struct TrustedSids {
    token_user: Vec<usize>,
    system: Vec<u32>,
    administrators: Vec<u32>,
    trusted_installer: Vec<u32>,
}

impl TrustedSids {
    fn load() -> io::Result<Self> {
        let mut token: HANDLE = null_mut();
        // SAFETY: `token` is a valid output pointer and the pseudo process
        // handle is always valid in the current process.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(token);
        let mut token_bytes = 0;
        // The size-probe call is expected to fail while setting `token_bytes`.
        unsafe {
            GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut token_bytes);
        }
        if token_bytes < size_of::<TOKEN_USER>() as u32 {
            return Err(io::Error::last_os_error());
        }
        let mut token_user = vec![0_usize; (token_bytes as usize).div_ceil(size_of::<usize>())];
        // SAFETY: the buffer is aligned and at least `token_bytes` long.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                token_user.as_mut_ptr() as *mut c_void,
                token_bytes,
                &mut token_bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let current = unsafe { (*(token_user.as_ptr() as *const TOKEN_USER)).User.Sid };
        if unsafe { IsValidSid(current) } == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            token_user,
            system: well_known_sid(WinLocalSystemSid)?,
            administrators: well_known_sid(WinBuiltinAdministratorsSid)?,
            trusted_installer: string_sid(
                "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            )?,
        })
    }

    fn current(&self) -> PSID {
        unsafe { (*(self.token_user.as_ptr() as *const TOKEN_USER)).User.Sid }
    }

    fn system(&self) -> PSID {
        self.system.as_ptr() as PSID
    }

    fn administrators(&self) -> PSID {
        self.administrators.as_ptr() as PSID
    }

    fn trusted_installer(&self) -> PSID {
        self.trusted_installer.as_ptr() as PSID
    }

    fn is_trusted(&self, sid: PSID, system_scope: bool) -> bool {
        let equal = |candidate| unsafe { EqualSid(sid, candidate) != 0 };
        equal(self.system())
            || equal(self.administrators())
            || equal(self.trusted_installer())
            || (!system_scope && equal(self.current()))
    }
}

fn string_sid(value: &str) -> io::Result<Vec<u32>> {
    let wide: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
    let mut allocated: PSID = null_mut();
    // SAFETY: `wide` is terminated and `allocated` is a valid output pointer.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut allocated) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let allocated = LocalSid(allocated);
    let size = unsafe { GetLengthSid(allocated.0) };
    let mut sid = vec![0_u32; (size as usize).div_ceil(size_of::<u32>())];
    // SAFETY: the destination is at least `size` bytes and both SIDs are valid.
    if unsafe { CopySid(size, sid.as_mut_ptr() as PSID, allocated.0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sid)
}

fn well_known_sid(kind: i32) -> io::Result<Vec<u32>> {
    let mut size = SECURITY_MAX_SID_SIZE;
    let mut sid = vec![0_u32; (size as usize).div_ceil(size_of::<u32>())];
    // SAFETY: the output buffer is `SECURITY_MAX_SID_SIZE` bytes long.
    if unsafe { CreateWellKnownSid(kind, null_mut(), sid.as_mut_ptr() as PSID, &mut size) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(sid)
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct LocalDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

struct LocalSid(PSID);

impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_acl_is_accepted_for_the_current_user() {
        let directory = tempfile::tempdir().unwrap();
        make_path_private(directory.path()).unwrap();
        assert!(path_acl_is_trusted(directory.path(), false).unwrap());
    }

    #[test]
    fn writable_acl_for_an_untrusted_principal_is_rejected() {
        use windows_sys::Win32::Security::WinWorldSid;

        let directory = tempfile::tempdir().unwrap();
        let sids = TrustedSids::load().unwrap();
        let world = well_known_sid(WinWorldSid).unwrap();
        set_path_dacl(
            directory.path(),
            &[
                sids.current(),
                sids.system(),
                sids.administrators(),
                world.as_ptr() as PSID,
            ],
        )
        .unwrap();
        assert!(!path_acl_is_trusted(directory.path(), false).unwrap());
    }
}
