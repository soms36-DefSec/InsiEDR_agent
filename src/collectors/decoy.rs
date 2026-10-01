use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use std::fs;
use std::path::Path;

const DECOY_CONTENT_V1: &[u8] = b"PK\x03\x04DummyExcelFileContentDoNotDelete";
const DECOY_CONTENT_V2: &[u8] = b"PK\x03\x04DummyEncryptedAdminPasswordStore";

pub struct DecoyCollector {
    decoy_path: &'static str,
}

impl DecoyCollector {
    pub fn new() -> Self {
        Self {
            decoy_path: "C:\\Users\\Public\\Admin_Passwords.xlsx",
        }
    }

    fn ensure_decoy_exists(&self) {
        let p = Path::new(self.decoy_path);
        if !p.exists() {
            let _ = fs::write(p, DECOY_CONTENT_V2);
        }
    }
}

impl Collector for DecoyCollector {
    fn name(&self) -> &'static str {
        "decoy-monitor"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.ensure_decoy_exists();

        let path = Path::new(self.decoy_path);
        let mut triggered = false;
        let mut size = 0u64;

        if path.exists() {
            if let Ok(content) = fs::read(path) {
                size = content.len() as u64;
                // Detects truncation, tampering, and in-place ransomware encryption
                if content != DECOY_CONTENT_V1 && content != DECOY_CONTENT_V2 {
                    triggered = true;
                }
            } else {
                // File exists but is locked exclusively (active ransomware write/encryption)
                triggered = true;
            }
        }

        CollectorResult::success(
            self.name(),
            now,
            json!({
                "monitored_decoys": [self.decoy_path],
                "threat_triggered": triggered,
                "events_recorded": triggered,
                "current_size": size
            }),
            QualityFlags {
                exact: true,
                partial: false,
                elevated: false,
                heuristic: false,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoy_content_length_consistency() {
        assert_eq!(DECOY_CONTENT_V1.len(), 36);
        assert_eq!(DECOY_CONTENT_V2.len(), 36);
    }

    #[test]
    fn test_decoy_collector_runs() {
        let collector = DecoyCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "decoy-monitor");
        assert!(res.success);
    }
}
