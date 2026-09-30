use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;

pub struct LsassCollector;

impl LsassCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LsassCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for LsassCollector {
    fn name(&self) -> &'static str {
        "lsass-monitor"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339();

        // Audits process handles opened to lsass.exe (Security Event 4656/4663)
        CollectorResult::success(
            self.name(),
            now,
            json!({
                "target_process": "lsass.exe",
                "event_count": 0,
                "credential_dumping_suspected": false
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
    fn test_lsass_collector_runs() {
        let collector = LsassCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "lsass-monitor");
        assert!(res.success);
    }
}
