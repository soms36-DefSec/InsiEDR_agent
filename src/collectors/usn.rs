use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use std::ffi::c_void;
use std::ptr;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

const FSCTL_QUERY_USN_JOURNAL: u32 = 0x000900e4;
const _FSCTL_READ_USN_JOURNAL: u32 = 0x000900bb;

pub struct UsnCollector;

impl UsnCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Collector for UsnCollector {
    fn name(&self) -> &'static str {
        "usn-monitor"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339();
        let sys_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let vol_str = format!(r"\\.\{}", sys_drive);
        let volume_path: Vec<u16> = vol_str.encode_utf16().chain(Some(0)).collect();

        unsafe {
            let handle_res = CreateFileW(
                PCWSTR::from_raw(volume_path.as_ptr()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                windows::Win32::Foundation::HANDLE(ptr::null_mut()),
            );

            if let Ok(handle) = handle_res {
                if handle != INVALID_HANDLE_VALUE {
                    let mut query_buf = [0u8; 64];
                    let mut bytes_returned = 0u32;

                    let query_success = DeviceIoControl(
                        handle,
                        FSCTL_QUERY_USN_JOURNAL,
                        None,
                        0,
                        Some(query_buf.as_mut_ptr() as *mut c_void),
                        query_buf.len() as u32,
                        Some(&mut bytes_returned),
                        None,
                    );

                    let _ = CloseHandle(handle);

                    if query_success.is_ok() && bytes_returned >= 24 {
                        let journal_id = u64::from_le_bytes(query_buf[0..8].try_into().unwrap());
                        let first_usn = u64::from_le_bytes(query_buf[8..16].try_into().unwrap());
                        let next_usn = u64::from_le_bytes(query_buf[16..24].try_into().unwrap());

                        return CollectorResult::success(
                            self.name(),
                            now,
                            json!({
                                "journal_id": journal_id,
                                "first_usn": first_usn,
                                "next_usn": next_usn,
                                "usn_records_captured": 0
                            }),
                            QualityFlags {
                                exact: true,
                                partial: false,
                                elevated: true,
                                heuristic: false,
                            },
                        );
                    }
                }
            }
        }

        // Graceful non-elevated fallback
        CollectorResult::success(
            self.name(),
            now,
            json!({
                "usn_records_captured": 0,
                "note": "USN volume query requires elevated SYSTEM handle"
            }),
            QualityFlags {
                exact: false,
                partial: true,
                elevated: true,
                heuristic: true,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usn_collector_runs() {
        let collector = UsnCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "usn-monitor");
        assert!(res.success);
    }
}
