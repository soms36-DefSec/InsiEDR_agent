use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Enables a specified Windows privilege (e.g. "SeDebugPrivilege", "SeSecurityPrivilege", "SeBackupPrivilege")
/// for the current process token.
pub fn enable_privilege(privilege_name: &str) -> Result<(), String> {
    let wide_name: Vec<u16> = privilege_name.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .map_err(|e| format!("OpenProcessToken failed: {e}"))?;

        let mut luid = LUID::default();
        let lookup_ok = LookupPrivilegeValueW(
            PCWSTR::null(),
            PCWSTR::from_raw(wide_name.as_ptr()),
            &mut luid,
        );

        if lookup_ok.is_err() {
            let _ = CloseHandle(token);
            return Err(format!("LookupPrivilegeValueW failed for {privilege_name}: {:?}", GetLastError()));
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let adjust_res = AdjustTokenPrivileges(
            token,
            false,
            Some(&tp),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        );

        let _ = CloseHandle(token);

        adjust_res.map_err(|e| format!("AdjustTokenPrivileges failed for {privilege_name}: {e}"))?;
        Ok(())
    }
}

/// Automatically enables all standard enterprise EDR privileges required for full kernel and process visibility.
pub fn enable_core_edr_privileges() {
    let _ = enable_privilege("SeDebugPrivilege");
    let _ = enable_privilege("SeSecurityPrivilege");
    let _ = enable_privilege("SeBackupPrivilege");
    let _ = enable_privilege("SeRestorePrivilege");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_privilege() {
        // Will succeed or return error gracefully without panicking
        let _ = enable_privilege("SeDebugPrivilege");
    }
}
