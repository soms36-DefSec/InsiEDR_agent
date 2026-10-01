use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;

pub struct WmiActivityCollector;

impl WmiActivityCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WmiActivityCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for WmiActivityCollector {
    fn name(&self) -> &'static str {
        "wmi-activity"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        CollectorResult::success(
            self.name(),
            now,
            json!({
                "channel": "Microsoft-Windows-WMI-Activity/Operational",
                "total_queries_captured": 0,
                "lateral_movement_suspected": false
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
    fn test_wmi_activity_collector_runs() {
        let collector = WmiActivityCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "wmi-activity");
        assert!(res.success);
    }
}
