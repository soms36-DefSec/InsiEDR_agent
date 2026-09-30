use windows::core::PCWSTR;
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, SetServiceObjectSecurity,
    SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS,
};

/// Hardens the Windows Service DACL to prevent unauthorized stoppage or modification
/// even by users in the local Administrators group.
pub fn harden_service_dacl(service_name: &str) -> Result<(), String> {
    let wide_name: Vec<u16> = service_name.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let scm = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
            .map_err(|e| format!("Failed to open SCManager: {e}"))?;

        let service = OpenServiceW(
            scm,
            PCWSTR::from_raw(wide_name.as_ptr()),
            SERVICE_ALL_ACCESS,
        )
        .map_err(|e| {
            let _ = CloseServiceHandle(scm);
            format!("Failed to open service {service_name}: {e}")
        })?;

        // SDDL string granting full control only to LocalSystem (SY) and Builtin Admins (BA) read-only/query
        let sddl = "D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPLORC;;;BA)(A;;CCLCSWRPWPDTLORC;;;SY)";
        let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();

        let mut sec_desc: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        let conv_res = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(wide_sddl.as_ptr()),
            1, // SDDL_REVISION_1
            &mut sec_desc,
            None,
        );

        if conv_res.is_ok() && !sec_desc.0.is_null() {
            let info = OBJECT_SECURITY_INFORMATION(DACL_SECURITY_INFORMATION.0);
            let set_res = SetServiceObjectSecurity(service, info, sec_desc);
            let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(sec_desc.0 as _));
            let _ = CloseServiceHandle(service);
            let _ = CloseServiceHandle(scm);

            if let Err(e) = set_res {
                Err(format!("SetServiceObjectSecurity failed: {e}"))
            } else {
                Ok(())
            }
        } else {
            let _ = CloseServiceHandle(service);
            let _ = CloseServiceHandle(scm);
            Err("ConvertStringSecurityDescriptor failed".into())
        }
    }
}
