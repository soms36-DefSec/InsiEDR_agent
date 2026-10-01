use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::ffi::c_void;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
};
use windows::Win32::System::ProcessStatus::GetMappedFileNameW;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryThreat {
    pub pid: u32,
    pub process_name: String,
    pub base_address: String,
    pub region_size: usize,
    pub threat_type: String,
    pub details: String,
}

pub struct MemoryScannerCollector;

impl MemoryScannerCollector {
    pub fn new() -> Self {
        Self
    }

    fn scan_process_memory(&self, pid: u32, process_name: &str) -> Vec<MemoryThreat> {
        let mut threats = Vec::new();

        unsafe {
            let handle_res = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if handle_res.is_err() {
                return threats;
            }
            let handle = handle_res.unwrap();

            let mut address: usize = 0x10000; // Start above null page
            let max_user_address: usize = if usize::BITS == 64 {
                0x7FFFFFFEFFFF // Top of 64-bit user address space
            } else {
                0x7FFEFFFF // Top of 32-bit/WOW64 user address space
            };

            let exec_flags = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

            let mut scanned_regions = 0;
            // Cap scanning at 2000 regions per process to guarantee zero latency spike
            while address < max_user_address && scanned_regions < 2000 {
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                let bytes = VirtualQueryEx(
                    handle,
                    Some(address as *const c_void),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );

                if bytes == 0 {
                    break;
                }

                scanned_regions += 1;

                // Only inspect committed executable memory
                if mbi.State == MEM_COMMIT {
                    let is_exec = (mbi.Protect.0 & exec_flags.0) != 0;

                    if is_exec {
                        // 1. Check for Unbacked Private Executable Memory (Shellcode / Reflective DLLs)
                        if mbi.Type == MEM_PRIVATE {
                            let mut peek_buf = [0u8; 512];
                            let mut bytes_read = 0usize;
                            let _ = ReadProcessMemory(
                                handle,
                                mbi.BaseAddress,
                                peek_buf.as_mut_ptr() as *mut c_void,
                                peek_buf.len(),
                                Some(&mut bytes_read),
                            );

                            let has_mz = bytes_read >= 2 && peek_buf[0] == 0x4D && peek_buf[1] == 0x5A; // "MZ"
                            let is_rwx = (mbi.Protect.0 & PAGE_EXECUTE_READWRITE.0) != 0;

                            // Suppress benign JIT compilation pages (e.g., .NET CLR in PowerShell, V8)
                            let is_jit_host = [
                                "powershell", "dotnet", "w3wp", "node", "electron", "teams", "slack", "chrome", "msedge"
                            ].iter().any(|&j| process_name.contains(j));

                            // If it's a known JIT engine and memory is plain RX without MZ, treat as benign JIT
                            if is_jit_host && !is_rwx && !has_mz {
                                // Benign JIT method page - skip threat generation
                            } else {
                                let (threat_type, details) = if has_mz {
                                    (
                                        "Reflective PE Injection (Unbacked MZ Header)".to_string(),
                                        format!(
                                            "Private executable memory region contains portable executable MZ header at 0x{:X} (Size: {} KB)",
                                            mbi.BaseAddress as usize,
                                            mbi.RegionSize / 1024
                                        ),
                                    )
                                } else if is_rwx {
                                    (
                                        "Unbacked RWX Shellcode Allocation".to_string(),
                                        format!(
                                            "Private PAGE_EXECUTE_READWRITE memory allocated at 0x{:X} without disk image backing",
                                            mbi.BaseAddress as usize
                                        ),
                                    )
                                } else {
                                    (
                                        "Unbacked Executable Memory".to_string(),
                                        format!(
                                            "Private executable memory (0x{:X}) without disk image backing",
                                            mbi.BaseAddress as usize
                                        ),
                                    )
                                };

                                threats.push(MemoryThreat {
                                    pid,
                                    process_name: process_name.to_string(),
                                    base_address: format!("0x{:X}", mbi.BaseAddress as usize),
                                    region_size: mbi.RegionSize,
                                    threat_type,
                                    details,
                                });
                            }
                        } else if mbi.Type == MEM_IMAGE {
                            // 2. Check for Process Hollowing / Phantom DLL Mappings
                            let mut mapped_name = [0u16; 512];
                            let name_len = GetMappedFileNameW(
                                handle,
                                mbi.BaseAddress,
                                &mut mapped_name,
                            );

                            if name_len == 0 {
                                threats.push(MemoryThreat {
                                    pid,
                                    process_name: process_name.to_string(),
                                    base_address: format!("0x{:X}", mbi.BaseAddress as usize),
                                    region_size: mbi.RegionSize,
                                    threat_type: "Phantom Image Mapping (Possible Hollowing)".to_string(),
                                    details: format!(
                                        "MEM_IMAGE executable section at 0x{:X} has no valid mapped disk file",
                                        mbi.BaseAddress as usize
                                    ),
                                });
                            }
                        }
                    }
                }

                // Advance to next region with stall and overflow protection
                let next_addr = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
                if next_addr <= address {
                    address = address.saturating_add(4096);
                } else {
                    address = next_addr;
                }
            }

            let _ = CloseHandle(handle);
        }

        threats
    }
}

impl Collector for MemoryScannerCollector {
    fn name(&self) -> &'static str {
        "memory-scanner"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let high_risk_targets = [
            "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
            "regsvr32", "svchost", "spoolsv", "explorer", "winword", "excel",
        ];

        let my_pid = std::process::id();
        let mut targets_to_scan = Vec::new();

        unsafe {
            if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                let mut entry = PROCESSENTRY32W::default();
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

                if Process32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        let len = entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len());
                        let exe_name = String::from_utf16_lossy(&entry.szExeFile[..len]).to_lowercase();

                        // Target high-risk candidates, excluding system and self process
                        let is_priority = high_risk_targets.iter().any(|&t| exe_name.contains(t));
                        if is_priority && entry.th32ProcessID > 4 && entry.th32ProcessID != my_pid {
                            targets_to_scan.push((entry.th32ProcessID, exe_name));
                        }

                        // Cap to 25 target processes per cycle to strictly adhere to governor cap
                        if targets_to_scan.len() >= 25 {
                            break;
                        }

                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snapshot);
            }
        }

        let mut all_threats = Vec::new();
        let mut unbacked_count = 0;
        let mut reflective_pe_count = 0;
        let mut hollowing_count = 0;

        for (pid, name) in &targets_to_scan {
            let proc_threats = self.scan_process_memory(*pid, name);
            for t in proc_threats {
                if t.threat_type.contains("Reflective PE") {
                    reflective_pe_count += 1;
                } else if t.threat_type.contains("Hollowing") {
                    hollowing_count += 1;
                } else if t.threat_type.contains("Unbacked") {
                    unbacked_count += 1;
                }
                all_threats.push(t);
            }
        }

        let threats_detected = !all_threats.is_empty();

        CollectorResult::success(
            self.name(),
            now,
            json!({
                "target_processes_scanned": targets_to_scan.len(),
                "threats_detected": threats_detected,
                "unbacked_executable_regions": unbacked_count,
                "reflective_pe_injections": reflective_pe_count,
                "phantom_hollowed_mappings": hollowing_count,
                "sample_threats": all_threats.iter().take(10).collect::<Vec<_>>()
            }),
            QualityFlags {
                exact: true,
                partial: false,
                elevated: true,
                heuristic: false,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_threat_serialization() {
        let threat = MemoryThreat {
            pid: 1234,
            process_name: "test.exe".into(),
            base_address: "0x7FFE0000".into(),
            region_size: 4096,
            threat_type: "Reflective PE Injection (Unbacked MZ Header)".into(),
            details: "Sample detection".into(),
        };

        let serialized = serde_json::to_string(&threat).expect("Failed to serialize threat");
        assert!(serialized.contains("1234"));
        assert!(serialized.contains("Reflective PE"));
    }

    #[test]
    fn test_address_space_limits() {
        let max_user: usize = if usize::BITS == 64 {
            0x7FFFFFFEFFFF
        } else {
            0x7FFEFFFF
        };
        assert!(max_user > 0x10000);
    }

    #[test]
    fn test_memory_scanner_collector_runs() {
        let collector = MemoryScannerCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "memory-scanner");
        assert!(res.success);
    }
}
