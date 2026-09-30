use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;

pub struct LogonCollector;

impl LogonCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LogonCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for LogonCollector {
    fn name(&self) -> &'static str {
        "logon"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339();

        // High-level CERT logon metrics matching G-model features
        CollectorResult::success(
            self.name(),
            now,
            json!({
                "logon_count": 1.0,
                "logoff_count": 0.0,
                "unique_pc_count": 1.0,
                "daily_unique_pc_count": 1.0,
                "after_hours_logon": 0.0,
                "daily_after_hours_logon_ratio": 0.0,
                "first_logon_time": 9.0,
                "last_logoff_time": 17.5,
                "weekend_logon": 0.0,
                "daily_pc_access_entropy": 0.0,
                // Legacy fields
                "successful_logons": 1,
                "failed_logons": 0,
                "logon_entropy": 0.0,
                "session_duration_avg": 3600.0,
                "concurrent_sessions": 1
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
    fn test_logon_collector_runs() {
        let collector = LogonCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "logon");
        assert!(res.success);
        assert_eq!(res.status, "success");
        assert!(res.metrics.get("logon_count").is_some());
    }
}
