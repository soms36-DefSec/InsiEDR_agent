use super::Collector;
use crate::etw::EtwCollectorHub;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

pub struct ProcessWatcherCollector;

impl ProcessWatcherCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Collector for ProcessWatcherCollector {
    fn name(&self) -> &'static str {
        "process-watcher"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339();
        let tunneling_names = ["ngrok", "ssh", "plink", "localtunnel", "chisel", "frpc"];
        let hub = EtwCollectorHub::global();

        let mut processes = Vec::new();
        let mut temp_exe_count = 0;
        let mut tunneling_count = 0;
        let mut admin_process_count = 0;
        let etw_active = hub.is_active();

        if etw_active {
            let (starts, stops, images) = hub.drain_process_events();
            for start in &starts {
                let img_lower = start.image_name.to_lowercase();
                let cmd_lower = start.command_line.to_lowercase();

                if img_lower.contains("\\temp\\") || img_lower.contains("\\tmp\\") {
                    temp_exe_count += 1;
                }

                for tool in &tunneling_names {
                    if img_lower.contains(tool) || cmd_lower.contains(tool) {
                        tunneling_count += 1;
                    }
                }

                if let Some(ref sid) = start.user_sid {
                    // S-1-5-18 (Local System) or S-1-5-32-544 (Administrators)
                    if sid.contains("S-1-5-18") || sid.contains("S-1-5-32-544") {
                        admin_process_count += 1;
                    }
                }

                processes.push(json!({
                    "pid": start.pid,
                    "ppid": start.parent_pid,
                    "name": start.image_name,
                    "cmd": start.command_line,
                    "user_sid": start.user_sid,
                    "source": "etw-kernel-realtime"
                }));
            }

            // If no new events drained in this cycle, also perform a lightweight snapshot
            // so we never report 0 active processes
            if processes.is_empty() {
                unsafe {
                    if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
                        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

                        if Process32FirstW(snapshot, &mut entry).is_ok() {
                            loop {
                                let len = entry
                                    .szExeFile
                                    .iter()
                                    .position(|&c| c == 0)
                                    .unwrap_or(entry.szExeFile.len());
                                let exe_name = String::from_utf16_lossy(&entry.szExeFile[..len]).to_lowercase();

                                for tool in &tunneling_names {
                                    if exe_name.contains(tool) {
                                        tunneling_count += 1;
                                    }
                                }

                                processes.push(json!({
                                    "pid": entry.th32ProcessID,
                                    "ppid": entry.th32ParentProcessID,
                                    "name": exe_name,
                                    "source": "snapshot-baseline"
                                }));

                                if Process32NextW(snapshot, &mut entry).is_err() {
                                    break;
                                }
                            }
                        }
                        let _ = CloseHandle(snapshot);
                    }
                }
            }

            let total = processes.len();
            CollectorResult::success(
                self.name(),
                now,
                json!({
                    "daily_unique_process_count": total,
                    "executables_from_temp_folder": temp_exe_count,
                    "admin_process_count": admin_process_count,
                    "tunneling_process_count": tunneling_count,
                    "process_count": total,
                    "etw_realtime_active": true,
                    "etw_lifecycle_events": {
                        "started_count": starts.len(),
                        "stopped_count": stops.len(),
                        "image_loads_count": images.len()
                    }
                }),
                QualityFlags {
                    exact: true,
                    partial: false,
                    elevated: true,
                    heuristic: false,
                },
            )
        } else {
            // Snapshot Fallback
            unsafe {
                if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    let mut entry: PROCESSENTRY32W = std::mem::zeroed();
                    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

                    if Process32FirstW(snapshot, &mut entry).is_ok() {
                        loop {
                            let len = entry
                                .szExeFile
                                .iter()
                                .position(|&c| c == 0)
                                .unwrap_or(entry.szExeFile.len());
                            let exe_name = String::from_utf16_lossy(&entry.szExeFile[..len]).to_lowercase();

                            for tool in &tunneling_names {
                                if exe_name.contains(tool) {
                                    tunneling_count += 1;
                                }
                            }

                            processes.push(json!({
                                "pid": entry.th32ProcessID,
                                "ppid": entry.th32ParentProcessID,
                                "name": exe_name,
                                "source": "snapshot-fallback"
                            }));

                            if Process32NextW(snapshot, &mut entry).is_err() {
                                break;
                            }
                        }
                    }
                    let _ = CloseHandle(snapshot);
                }
            }

            let total = processes.len();
            CollectorResult::success(
                self.name(),
                now,
                json!({
                    "daily_unique_process_count": total,
                    "executables_from_temp_folder": temp_exe_count,
                    "admin_process_count": 0,
                    "tunneling_process_count": tunneling_count,
                    "process_count": total,
                    "etw_realtime_active": false
                }),
                QualityFlags {
                    exact: true,
                    partial: false,
                    elevated: false,
                    heuristic: false,
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_watcher_collector_runs() {
        let collector = ProcessWatcherCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "process-watcher");
        assert!(res.success);
        assert!(res.metrics.get("process_count").is_some());
    }
}
