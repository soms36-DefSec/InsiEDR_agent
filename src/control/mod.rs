pub mod isolate;
pub mod terminate;
pub mod lock;
pub mod rollback;

use crate::protocol::heartbeat::RemoteTask;

pub fn execute_remote_task(task: &RemoteTask, server_ip: &str) -> (i32, String) {
    match task.command.as_str() {
        "isolate_host" => {
            match isolate::isolate_host(server_ip) {
                Ok(_) => (0, "Host isolated successfully. Windows firewall containment active.".to_string()),
                Err(e) => (1, format!("Failed to isolate host: {e}")),
            }
        }
        "unisolate_host" => {
            match isolate::unisolate_host() {
                Ok(_) => (0, "Host isolation removed. Normal network connectivity restored.".to_string()),
                Err(e) => (1, format!("Failed to unisolate host: {e}")),
            }
        }
        "lock_workstation" => {
            match lock::lock_workstation() {
                Ok(_) => (0, "Workstation locked successfully.".to_string()),
                Err(e) => (1, format!("Failed to lock workstation: {e}")),
            }
        }
        "kill_process" => {
            if let Some(pid) = task.params.get("pid").and_then(|p| p.as_u64()) {
                match terminate::terminate_process_by_pid(pid as u32) {
                    Ok(_) => (0, format!("Process PID {pid} terminated successfully.")),
                    Err(e) => (1, format!("Failed to terminate PID {pid}: {e}")),
                }
            } else {
                (2, "Missing or invalid 'pid' parameter in kill_process command".to_string())
            }
        }
        "create_shadow" => {
            let volume = task.params.get("volume").and_then(|v| v.as_str()).unwrap_or("C:");
            match rollback::create_vss_snapshot(volume) {
                Ok(dev) => (0, format!("Volume Shadow Copy created successfully: {dev}")),
                Err(e) => (1, format!("Failed to create shadow copy: {e}")),
            }
        }
        "rollback_directory" => {
            if let Some(path) = task.params.get("path").and_then(|p| p.as_str()) {
                let snap = task.params.get("snapshot").and_then(|s| s.as_str());
                match rollback::rollback_directory(path, snap) {
                    Ok(report) => (0, format!("Rollback completed: {} files restored ({} bytes)", report.files_restored, report.bytes_restored)),
                    Err(e) => (1, format!("Rollback failed: {e}")),
                }
            } else {
                (2, "Missing 'path' parameter in rollback_directory command".to_string())
            }
        }
        other => (3, format!("Unknown or unsupported remote command: '{other}'")),
    }
}
