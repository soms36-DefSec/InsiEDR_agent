use std::mem;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectCpuRateControlInformation, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
    JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
};
use windows::Win32::System::Threading::GetCurrentProcess;

/// Sets a hard CPU usage cap (in basis points: 300 = 3.00%) using Windows Job Objects.
/// Guarantees the EDR sensor never impacts employee PC responsiveness.
pub fn set_cpu_rate_cap(max_rate_basis_points: u32) -> Result<(), String> {
    if max_rate_basis_points == 0 || max_rate_basis_points > 10_000 {
        return Err("CPU rate cap must be between 1 and 10000 basis points (0.01% - 100.0%)".to_string());
    }

    unsafe {
        let job = CreateJobObjectW(None, None)
            .map_err(|e| format!("CreateJobObjectW failed: {e}"))?;

        let mut cpu_rate: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = mem::zeroed();
        cpu_rate.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        cpu_rate.Anonymous.CpuRate = max_rate_basis_points; // e.g. 300 = 3%

        if let Err(e) = SetInformationJobObject(
            job,
            JobObjectCpuRateControlInformation,
            &cpu_rate as *const _ as *const std::ffi::c_void,
            mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
        ) {
            let _ = CloseHandle(job);
            return Err(format!("SetInformationJobObject failed: {e}"));
        }

        if let Err(e) = AssignProcessToJobObject(job, GetCurrentProcess()) {
            let _ = CloseHandle(job);
            return Err(format!("AssignProcessToJobObject failed: {e}"));
        }

        // Job object handle remains active for the process lifetime
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_governor_rate_validation() {
        assert!(set_cpu_rate_cap(0).is_err());
        assert!(set_cpu_rate_cap(10_001).is_err());
    }
}
