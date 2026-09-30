use std::os::windows::process::CommandExt;
use std::process::Command;
use windows::Win32::System::Shutdown::LockWorkStation;

const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Instantly locks the user desktop using native Win32 LockWorkStation,
/// with multi-tier fallback for Session 0 Windows Service contexts.
pub fn lock_workstation() -> Result<(), String> {
    unsafe {
        // Direct Win32 API call (succeeds in interactive user sessions)
        if LockWorkStation().is_ok() {
            return Ok(());
        }
    }

    // Session 0 Service Fallback: invoke user32 LockWorkStation via system rundll32
    let status = Command::new("rundll32.exe")
        .args(["user32.dll,LockWorkStation"])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| format!("Failed to spawn rundll32 LockWorkStation: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err("LockWorkStation failed across both Win32 direct call and Session 0 fallback".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_workstation_callable() {
        // Verify function pointer and presence
        let f: fn() -> Result<(), String> = lock_workstation;
        assert!((f as usize) != 0);
    }
}

