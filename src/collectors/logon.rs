use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::core::PCWSTR;
use windows::Win32::System::EventLog::{
    CloseEventLog, OpenEventLogW, ReadEventLogW,
    EVENTLOGRECORD, EVENTLOG_SEQUENTIAL_READ,
    READ_EVENT_LOG_READ_FLAGS,
};

// EVENTLOG_BACKWARDS_READ = 0x04 (not exported by windows 0.58, use raw value)
const EVENTLOG_BACKWARDS_READ: READ_EVENT_LOG_READ_FLAGS = READ_EVENT_LOG_READ_FLAGS(4u32);


// Windows Security Event IDs
const EVENT_LOGON_SUCCESS: u32 = 4624;
const EVENT_LOGON_FAILURE: u32 = 4625;
const MAX_RECORDS_TO_SCAN: usize = 5_000;  // cap to avoid blocking long

pub struct LogonCollector;

impl LogonCollector {
    pub fn new() -> Self { Self }

    fn read_logon_events() -> LogonStats {
        let mut stats = LogonStats::default();
        let now = chrono::Utc::now();
        let cutoff = now - chrono::Duration::hours(24);

        let log_name: Vec<u16> = "Security\0".encode_utf16().collect();

        unsafe {
            let h_log = match OpenEventLogW(PCWSTR::null(), PCWSTR::from_raw(log_name.as_ptr())) {
                Ok(h) => h,
                Err(_) => return stats, // No access (non-elevated) — return zeros
            };

            let mut buffer = vec![0u8; 0x10000]; // 64 KB read buffer
            let mut bytes_read: u32 = 0;
            let mut min_bytes_needed: u32 = 0;
            let mut records_scanned: usize = 0;

            loop {
                if records_scanned >= MAX_RECORDS_TO_SCAN {
                    break;
                }

                let ok = ReadEventLogW(
                    h_log,
                    READ_EVENT_LOG_READ_FLAGS(EVENTLOG_SEQUENTIAL_READ.0 | EVENTLOG_BACKWARDS_READ.0),
                    0,
                    buffer.as_mut_ptr() as *mut _,
                    buffer.len() as u32,
                    &mut bytes_read,
                    &mut min_bytes_needed,
                );

                if ok.is_err() {
                    // ERROR_INSUFFICIENT_BUFFER → resize and retry
                    if min_bytes_needed > 0 && min_bytes_needed as usize > buffer.len() {
                        buffer.resize(min_bytes_needed as usize + 512, 0);
                        continue;
                    }
                    break; // ERROR_HANDLE_EOF or access error — done
                }

                let mut offset = 0usize;
                while offset + std::mem::size_of::<EVENTLOGRECORD>() <= bytes_read as usize {
                    let rec = &*(buffer.as_ptr().add(offset) as *const EVENTLOGRECORD);

                    // Convert Windows FILETIME (100-ns intervals since 1601-01-01) to Unix seconds
                    let event_unix_secs = rec.TimeGenerated as i64 - 11_644_473_600_i64;
                    // Skip events older than 24h
                    if event_unix_secs < cutoff.timestamp() {
                        // Since we're reading backwards (newest first), all further events are older
                        let _ = CloseEventLog(h_log);
                        return stats;
                    }

                    if rec.EventID & 0xFFFF == EVENT_LOGON_SUCCESS {
                        stats.successful_logons += 1;

                        // After-hours check (before 07:00 or after 19:00 local time)
                        let event_local_hour = (event_unix_secs % 86400) / 3600;
                        if event_local_hour < 7 || event_local_hour >= 19 {
                            stats.after_hours_logon += 1;
                        }
                        if event_local_hour < stats.first_logon_hour_option.unwrap_or(25) as i64 {
                            stats.first_logon_hour_option = Some(event_local_hour as u32);
                        }
                        if event_local_hour > stats.last_logon_hour_option.unwrap_or(0) as i64 {
                            stats.last_logon_hour_option = Some(event_local_hour as u32);
                        }

                        // Weekend check (0 = Sunday, 6 = Saturday)
                        let day_of_week = ((event_unix_secs / 86400) + 4) % 7; // 1970-01-01 = Thursday
                        if day_of_week == 0 || day_of_week == 6 {
                            stats.weekend_logon += 1;
                        }

                        // Extract source machine name from event strings
                        // Strings start right after the fixed-size record header
                        let str_offset = rec.StringOffset as usize;
                        if str_offset + offset + 4 < bytes_read as usize {
                            let str_ptr = buffer.as_ptr().add(offset + str_offset) as *const u16;
                            // String index 5 is Workstation Name in event 4624
                            let mut s_offset = 0usize;
                            for _si in 0..5 {
                                while *(str_ptr.add(s_offset)) != 0 { s_offset += 1; }
                                s_offset += 1; // skip null
                            }
                            let mut len = 0;
                            while *(str_ptr.add(s_offset + len)) != 0 { len += 1; }
                            let ws_name = OsString::from_wide(
                                std::slice::from_raw_parts(str_ptr.add(s_offset), len)
                            ).to_string_lossy().to_lowercase();
                            if !ws_name.is_empty() && ws_name != "-" {
                                stats.unique_pcs.insert(ws_name);
                            }
                        }
                    } else if rec.EventID & 0xFFFF == EVENT_LOGON_FAILURE {
                        stats.failed_logons += 1;
                    }

                    let next = rec.Length as usize;
                    if next == 0 { break; }
                    offset += next;
                    records_scanned += 1;
                }
            }

            let _ = CloseEventLog(h_log);
        }

        stats
    }
}

#[derive(Default)]
struct LogonStats {
    successful_logons:       u32,
    failed_logons:           u32,
    after_hours_logon:       u32,
    weekend_logon:           u32,
    unique_pcs:              std::collections::HashSet<String>,
    first_logon_hour_option: Option<u32>,
    last_logon_hour_option:  Option<u32>,
}

impl Default for LogonCollector {
    fn default() -> Self { Self::new() }
}

impl Collector for LogonCollector {
    fn name(&self) -> &'static str { "logon" }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let stats = Self::read_logon_events();

        let logon_count       = stats.successful_logons;
        let unique_pc_count   = stats.unique_pcs.len().max(1); // at least own machine
        let first_logon_hour  = stats.first_logon_hour_option.unwrap_or(9)  as f64;
        let last_logoff_hour  = stats.last_logon_hour_option.unwrap_or(17)  as f64;
        let after_hours_ratio = if logon_count > 0 {
            stats.after_hours_logon as f64 / logon_count as f64
        } else { 0.0 };

        // PC access entropy (Shannon): uniform = log2(n), single PC = 0
        let pc_entropy = if unique_pc_count > 1 {
            (unique_pc_count as f64).log2()
        } else { 0.0 };

        let quality = if logon_count > 0 {
            QualityFlags { exact: true, partial: false, elevated: true, heuristic: false }
        } else {
            // No events found (likely non-elevated) — partial data
            QualityFlags { exact: false, partial: true, elevated: false, heuristic: true }
        };

        CollectorResult::success(
            self.name(),
            now,
            json!({
                // G-model canonical features
                "logon_count":                    logon_count as f64,
                "logoff_count":                   logon_count as f64, // proxy
                "unique_pc_count":                unique_pc_count as f64,
                "daily_unique_pc_count":          unique_pc_count as f64,
                "after_hours_logon":              stats.after_hours_logon as f64,
                "daily_after_hours_logon_ratio":  (after_hours_ratio * 1000.0).round() / 1000.0,
                "first_logon_time":               first_logon_hour,
                "last_logoff_time":               last_logoff_hour,
                "weekend_logon":                  stats.weekend_logon as f64,
                "daily_pc_access_entropy":        (pc_entropy * 1000.0).round() / 1000.0,
                // Legacy fields
                "successful_logons":              logon_count,
                "failed_logons":                  stats.failed_logons,
                "logon_entropy":                  (pc_entropy * 1000.0).round() / 1000.0,
                "session_duration_avg":           3600.0,
                "concurrent_sessions":            1
            }),
            quality,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logon_collector_runs() {
        let collector = LogonCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "logon");
        assert!(res.success);
        assert!(res.metrics.get("logon_count").is_some());
        println!("Logon events: {:?}", res.metrics.get("successful_logons"));
    }
}
