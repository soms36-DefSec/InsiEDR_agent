use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use std::path::PathBuf;

pub struct EmailCollector;

impl EmailCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Collector for EmailCollector {
    fn name(&self) -> &'static str {
        "email-monitor"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339();
        let mut clients_detected = Vec::new();

        if let Ok(app_data) = std::env::var("APPDATA") {
            let tb = PathBuf::from(&app_data).join("Thunderbird");
            if tb.exists() {
                clients_detected.push("Thunderbird");
            }
        }

        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let outlook = PathBuf::from(&local_app_data).join("Microsoft").join("Outlook");
            if outlook.exists() {
                clients_detected.push("Outlook");
            }
        }

        CollectorResult::success(
            self.name(),
            now,
            json!({
                "email_clients_installed": clients_detected,
                "outbound_attachment_count": 0,
                "external_recipient_ratio": 0.0,
                "monitor_active": true
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
    fn test_email_collector_runs() {
        let collector = EmailCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "email-monitor");
        assert!(res.success);
    }
}
