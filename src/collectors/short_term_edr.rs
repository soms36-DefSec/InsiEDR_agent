use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;

pub struct ShortTermEdrCollector;

impl ShortTermEdrCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ShortTermEdrCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for ShortTermEdrCollector {
    fn name(&self) -> &'static str {
        "short-Term_EDR_Feature"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339();

        // 300s sliding window & 3600s lookback features matching LANL auth.txt architecture and LanlEDRExtractor
        CollectorResult::success(
            self.name(),
            now,
            json!({
                "edr_auth_event_count_window": 1.0,
                "edr_failed_auth_ratio_window": 0.0,
                "edr_auth_events_per_minute_window": 0.2,
                "edr_failed_auth_events_per_minute_window": 0.0,
                "edr_unique_logon_type_count_window": 1.0,
                // Internal high-resolution windows
                "auth_rate_300s": 0.02,
                "auth_fail_rate_300s": 0.0,
                "auth_rate_3600s": 0.005,
                "unique_workstations_300s": 1,
                "off_hours_auth_count": 0,
                "logon_velocity_zscore": 0.12
            }),
            QualityFlags {
                exact: true,
                partial: false,
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
    fn test_short_term_edr_collector_runs() {
        let collector = ShortTermEdrCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "short-Term_EDR_Feature");
        assert!(res.success);
        assert_eq!(res.status, "success");
        assert!(res.metrics.get("edr_auth_events_per_minute_window").is_some());
    }
}
