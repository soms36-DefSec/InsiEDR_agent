use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

pub const CRITICAL_SYSTEM_PROCESSES: &[&str] = &[
    "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "fontdrvhost.exe"
];

fn get_process_name(pid: u32) -> Option<String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    let len = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let exe_name = String::from_utf16_lossy(&entry.szExeFile[..len]).to_lowercase();
                    let _ = CloseHandle(snapshot);
                    return Some(exe_name);
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    None
}

/// Terminates a target process by PID using native Win32 TerminateProcess API.
/// Strictly guards against terminating critical Windows kernel/subsystem processes.
pub fn terminate_process_by_pid(pid: u32) -> Result<(), String> {
    if pid <= 4 {
        return Err(format!("Refusing to terminate critical system PID {pid}"));
    }
    if pid == std::process::id() {
        return Err("Refusing to terminate agent self process".to_string());
    }

    if let Some(name) = get_process_name(pid) {
        if CRITICAL_SYSTEM_PROCESSES.iter().any(|&c| name.eq_ignore_ascii_case(c)) {
            return Err(format!("Refusing to terminate critical Windows system process '{name}' (PID {pid})"));
        }
    }

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
            .map_err(|e| format!("Failed to open process PID {pid}: win32 error {e}"))?;

        let res = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);

        res.map_err(|e| format!("TerminateProcess failed for PID {pid}: win32 error {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prevent_critical_pid_termination() {
        assert!(terminate_process_by_pid(0).is_err());
        assert!(terminate_process_by_pid(4).is_err());
        assert!(terminate_process_by_pid(std::process::id()).is_err());
    }

    #[test]
    fn test_critical_system_process_list() {
        assert!(CRITICAL_SYSTEM_PROCESSES.contains(&"csrss.exe"));
        assert!(CRITICAL_SYSTEM_PROCESSES.contains(&"lsass.exe"));
        assert!(CRITICAL_SYSTEM_PROCESSES.contains(&"wininit.exe"));
    }
}
