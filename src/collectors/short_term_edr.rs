use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use windows::core::PCWSTR;
use windows::Win32::System::EventLog::{
    CloseEventLog, OpenEventLogW, ReadEventLogW,
    EVENTLOGRECORD, EVENTLOG_SEQUENTIAL_READ,
    READ_EVENT_LOG_READ_FLAGS,
};

// EVENTLOG_BACKWARDS_READ = 0x04 (not exported by windows 0.58)
const EVENTLOG_BACKWARDS_READ: READ_EVENT_LOG_READ_FLAGS = READ_EVENT_LOG_READ_FLAGS(4u32);


// Windows Security Event IDs for authentication
const EVENT_LOGON_SUCCESS: u32 = 4624;
const EVENT_LOGON_FAILURE: u32 = 4625;

const WINDOW_300S:  i64 = 300;
const WINDOW_3600S: i64 = 3600;
const MAX_SCAN:     usize = 3_000;

pub struct ShortTermEdrCollector;

impl ShortTermEdrCollector {
    pub fn new() -> Self { Self }

    fn compute_sliding_window() -> EdrWindowStats {
        let mut stats = EdrWindowStats::default();
        let now_unix = chrono::Utc::now().timestamp();
        let cutoff   = now_unix - WINDOW_3600S;

        let log_name: Vec<u16> = "Security\0".encode_utf16().collect();

        unsafe {
            let h_log = match OpenEventLogW(PCWSTR::null(), PCWSTR::from_raw(log_name.as_ptr())) {
                Ok(h) => h,
                Err(_) => return stats,
            };

            let mut buffer  = vec![0u8; 0x10000];
            let mut bytes_read: u32 = 0;
            let mut min_needed: u32 = 0;
            let mut scanned = 0usize;

            // Sliding window accumulators
            let mut auth_300  = 0u32;
            let mut auth_3600 = 0u32;
            let mut fail_300  = 0u32;
            let mut fail_3600 = 0u32;
            let mut off_hours = 0u32;
            let mut unique_ws_300: std::collections::HashSet<u32> = std::collections::HashSet::new();

            loop {
                if scanned >= MAX_SCAN { break; }

                let ok = ReadEventLogW(
                    h_log,
                    READ_EVENT_LOG_READ_FLAGS(EVENTLOG_SEQUENTIAL_READ.0 | EVENTLOG_BACKWARDS_READ.0),
                    0,
                    buffer.as_mut_ptr() as *mut _,
                    buffer.len() as u32,
                    &mut bytes_read,
                    &mut min_needed,
                );

                if ok.is_err() {
                    if min_needed as usize > buffer.len() {
                        buffer.resize(min_needed as usize + 512, 0);
                        continue;
                    }
                    break;
                }

                let mut offset = 0usize;
                while offset + std::mem::size_of::<EVENTLOGRECORD>() <= bytes_read as usize {
                    let rec = &*(buffer.as_ptr().add(offset) as *const EVENTLOGRECORD);

                    let event_unix = rec.TimeGenerated as i64 - 11_644_473_600_i64;
                    if event_unix < cutoff {
                        let _ = CloseEventLog(h_log);
                        stats.auth_300  = auth_300;
                        stats.auth_3600 = auth_3600;
                        stats.fail_300  = fail_300;
                        stats.fail_3600 = fail_3600;
                        stats.off_hours = off_hours;
                        stats.unique_ws_300 = unique_ws_300.len() as u32;
                        return stats;
                    }

                    let event_id = rec.EventID & 0xFFFF;
                    let age_secs = now_unix - event_unix;

                    if event_id == EVENT_LOGON_SUCCESS {
                        if age_secs <= WINDOW_3600S { auth_3600 += 1; }
                        if age_secs <= WINDOW_300S  {
                            auth_300 += 1;
                            // Use EventRecordID as a proxy for workstation identity within window
                            unique_ws_300.insert(rec.RecordNumber);
                        }
                        let hour = (event_unix % 86400) / 3600;
                        if hour < 7 || hour >= 19 { off_hours += 1; }
                    } else if event_id == EVENT_LOGON_FAILURE {
                        if age_secs <= WINDOW_3600S { fail_3600 += 1; }
                        if age_secs <= WINDOW_300S  { fail_300  += 1; }
                    }

                    let next = rec.Length as usize;
                    if next == 0 { break; }
                    offset += next;
                    scanned += 1;
                }
            }

            let _ = CloseEventLog(h_log);
            stats.auth_300       = auth_300;
            stats.auth_3600      = auth_3600;
            stats.fail_300       = fail_300;
            stats.fail_3600      = fail_3600;
            stats.off_hours      = off_hours;
            stats.unique_ws_300  = unique_ws_300.len() as u32;
        }

        stats
    }
}

#[derive(Default)]
struct EdrWindowStats {
    auth_300:      u32,   // successful logons in last 5 min
    auth_3600:     u32,   // successful logons in last 1 hr
    fail_300:      u32,   // failed logons in last 5 min
    fail_3600:     u32,   // failed logons in last 1 hr
    off_hours:     u32,   // auth events outside 07:00-19:00
    unique_ws_300: u32,   // proxy for unique workstations in last 5 min
}

impl Default for ShortTermEdrCollector {
    fn default() -> Self { Self::new() }
}

impl Collector for ShortTermEdrCollector {
    fn name(&self) -> &'static str { "short-Term_EDR_Feature" }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let w   = Self::compute_sliding_window();

        // Derived rate features
        let auth_per_min_300  = w.auth_300  as f64 / (WINDOW_300S  as f64 / 60.0);
        let auth_per_min_3600 = w.auth_3600 as f64 / (WINDOW_3600S as f64 / 60.0);
        let fail_ratio_300    = if w.auth_300 + w.fail_300 > 0 {
            w.fail_300 as f64 / (w.auth_300 + w.fail_300) as f64
        } else { 0.0 };

        // Velocity Z-score: how many std-devs above zero is auth_per_min_300?
        // Baseline assumption: 0.05 auths/min typical, std ~0.1
        let baseline_mean = 0.05_f64;
        let baseline_std  = 0.10_f64;
        let velocity_zscore = if baseline_std > 0.0 {
            (auth_per_min_300 - baseline_mean) / baseline_std
        } else { 0.0 };

        let quality = if w.auth_300 + w.auth_3600 + w.fail_300 > 0 {
            QualityFlags { exact: true, partial: false, elevated: true, heuristic: false }
        } else {
            QualityFlags { exact: false, partial: true, elevated: false, heuristic: true }
        };

        CollectorResult::success(
            self.name(),
            now,
            json!({
                // LANL-compatible canonical fields
                "edr_auth_event_count_window":            w.auth_300,
                "edr_failed_auth_ratio_window":           (fail_ratio_300 * 1000.0).round() / 1000.0,
                "edr_auth_events_per_minute_window":      (auth_per_min_300 * 1000.0).round() / 1000.0,
                "edr_failed_auth_events_per_minute_window": (w.fail_300 as f64 / (WINDOW_300S as f64 / 60.0) * 1000.0).round() / 1000.0,
                "edr_unique_logon_type_count_window":     w.unique_ws_300.max(1),
                // High-resolution windows
                "auth_rate_300s":                         (auth_per_min_300  * 10000.0).round() / 10000.0,
                "auth_fail_rate_300s":                    (fail_ratio_300    * 10000.0).round() / 10000.0,
                "auth_rate_3600s":                        (auth_per_min_3600 * 10000.0).round() / 10000.0,
                "unique_workstations_300s":               w.unique_ws_300,
                "off_hours_auth_count":                   w.off_hours,
                "logon_velocity_zscore":                  (velocity_zscore * 100.0).round() / 100.0
            }),
            quality,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_term_edr_collector_runs() {
        let collector = ShortTermEdrCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "short-Term_EDR_Feature");
        assert!(res.success);
        assert!(res.metrics.get("edr_auth_events_per_minute_window").is_some());
        println!("Auth 300s: {:?}", res.metrics.get("edr_auth_event_count_window"));
    }
}
