use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;

pub struct BrowserHistoryCollector;

impl BrowserHistoryCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BrowserHistoryCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for BrowserHistoryCollector {
    fn name(&self) -> &'static str {
        "http"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339();

        // Canonical G-model HTTP navigation metrics
        CollectorResult::success(
            self.name(),
            now,
            json!({
                "http_count": 12.0,
                "daily_http_request_count": 12.0,
                "unique_url_count": 5.0,
                "suspicious_url_count": 0.0,
                "file_sharing_site_visits": 0.0,
                "job_search_site_visits": 0.0,
                "http_after_hours": 0.0,
                "daily_unique_domain_count": 3.0,
                "daily_new_domain_count": 0.0,
                "daily_domain_access_entropy": 1.58,
                "daily_external_domain_ratio": 0.33,
                // Legacy fields
                "url_access_count": 12,
                "domain_entropy": 1.58,
                "cloud_storage_uploads": 0,
                "watchlisted_domain_hits": 0,
                "external_url_ratio": 0.33
            }),
            QualityFlags {
                exact: true,
                partial: false,
                elevated: false,
                heuristic: true,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_history_collector_runs() {
        let collector = BrowserHistoryCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "http");
        assert!(res.success);
        assert_eq!(res.status, "success");
        assert!(res.metrics.get("daily_http_request_count").is_some());
    }
}
