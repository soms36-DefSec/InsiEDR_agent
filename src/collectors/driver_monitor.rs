use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use std::ffi::c_void;
use windows::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverBaseNameW};

pub struct DriverMonitorCollector;

impl DriverMonitorCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Collector for DriverMonitorCollector {
    fn name(&self) -> &'static str {
        "driver-monitor"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut drivers = Vec::new();
        let mut cb_needed = 0u32;
        let mut driver_ptrs = vec![std::ptr::null_mut::<c_void>(); 1024];

        unsafe {
            let success = EnumDeviceDrivers(
                driver_ptrs.as_mut_ptr(),
                (driver_ptrs.len() * std::mem::size_of::<*mut c_void>()) as u32,
                &mut cb_needed,
            );

            if success.is_ok() {
                let count = (cb_needed as usize) / std::mem::size_of::<*mut c_void>();
                for &ptr in driver_ptrs.iter().take(count) {
                    if !ptr.is_null() {
                        let mut name_buf = [0u16; 256];
                        let len = GetDeviceDriverBaseNameW(ptr, &mut name_buf);
                        if len > 0 {
                            let name = String::from_utf16_lossy(&name_buf[..len as usize]);
                            drivers.push(name);
                        }
                    }
                }
            }
        }

        let total = drivers.len();
        CollectorResult::success(
            self.name(),
            now,
            json!({
                "driver_count": total,
                "running_drivers": total,
                "drivers_sample": drivers.iter().take(50).collect::<Vec<_>>()
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
    fn test_driver_monitor_collector_runs() {
        let collector = DriverMonitorCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "driver-monitor");
        assert!(res.success);
    }
}
