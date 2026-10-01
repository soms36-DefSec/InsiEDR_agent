use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use std::mem;
use windows::Win32::System::SystemInformation::GetTickCount64;
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

pub struct ActivityCollector;

impl ActivityCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ActivityCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for ActivityCollector {
    fn name(&self) -> &'static str {
        "activity-monitor"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut lii: LASTINPUTINFO = unsafe { mem::zeroed() };
        lii.cbSize = mem::size_of::<LASTINPUTINFO>() as u32;

        let success = unsafe { GetLastInputInfo(&mut lii).as_bool() };
        if success {
            let tick_count = unsafe { GetTickCount64() };
            let idle_ms = tick_count.saturating_sub(lii.dwTime as u64);
            let idle_seconds = (idle_ms as f64) / 1000.0;

            CollectorResult::success(
                self.name(),
                now,
                json!({
                    "user_idle_seconds": (idle_seconds * 100.0).round() / 100.0,
                    "is_user_active": idle_seconds < 300.0,
                    "last_input_tick": lii.dwTime
                }),
                QualityFlags {
                    exact: true,
                    partial: false,
                    elevated: false,
                    heuristic: false,
                },
            )
        } else {
            CollectorResult::failed(
                self.name(),
                now,
                "Win32Error",
                "GetLastInputInfo failed",
                QualityFlags::default(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activity_collector_runs() {
        let collector = ActivityCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "activity-monitor");
        assert!(res.success || res.status == "failed");
    }
}
