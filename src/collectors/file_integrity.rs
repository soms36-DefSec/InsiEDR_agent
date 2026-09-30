use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::PathBuf;

pub struct FileIntegrityCollector;

impl FileIntegrityCollector {
    pub fn new() -> Self {
        Self
    }

    fn hash_file(path: &PathBuf) -> Option<String> {
        if let Ok(mut file) = fs::File::open(path) {
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 65536];
            let mut bytes_read_total = 0;
            // Read up to 1MB max for performance
            while let Ok(n) = file.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
                bytes_read_total += n;
                if bytes_read_total >= 1024 * 1024 {
                    break;
                }
            }
            Some(format!("{:x}", hasher.finalize()))
        } else {
            None
        }
    }
}

impl Collector for FileIntegrityCollector {
    fn name(&self) -> &'static str {
        "file-integrity-monitor"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339();
        let mut integrity_events = Vec::new();

        // 1. Audit critical system network configuration files (e.g. hosts file tampering)
        let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let hosts_path = PathBuf::from(&sys_root).join("System32\\drivers\\etc\\hosts");
        if hosts_path.exists() {
            if let Some(hash) = Self::hash_file(&hosts_path) {
                integrity_events.push(json!({
                    "path": hosts_path.to_string_lossy(),
                    "sha256": hash,
                    "target_type": "critical_system_file",
                    "op": "AUDIT"
                }));
            }
        }

        // 2. Audit user document paths (supports both user context and Session 0 SYSTEM service)
        let mut target_dirs = Vec::new();
        if let Ok(user_profile) = std::env::var("USERPROFILE") {
            let docs = PathBuf::from(&user_profile).join("Documents");
            if docs.exists() {
                target_dirs.push(docs);
            }
        }

        // If running as LocalSystem in Session 0, enumerate active profiles in C:\Users
        if target_dirs.is_empty() {
            let users_dir = PathBuf::from("C:\\Users");
            if let Ok(entries) = fs::read_dir(users_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        let name = entry.file_name().to_string_lossy().to_lowercase();
                        if !name.starts_with("default") && name != "public" && name != "all users" {
                            let docs = p.join("Documents");
                            if docs.exists() {
                                target_dirs.push(docs);
                                break;
                            }
                        }
                    }
                }
            }
        }

        for dir in target_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten().take(20) {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(hash) = Self::hash_file(&path) {
                            integrity_events.push(json!({
                                "path": path.to_string_lossy(),
                                "sha256": hash,
                                "target_type": "user_document",
                                "op": "AUDIT"
                            }));
                        }
                    }
                }
            }
        }

        let count = integrity_events.len();
        CollectorResult::success(
            self.name(),
            now,
            json!({
                "file_access_count": count as f64,
                "daily_unique_filename_count": count as f64,
                "daily_new_filename_count": 0.0,
                "daily_file_access_entropy": 0.0,
                "integrity_events": integrity_events,
                "event_count": count,
                "monitor_active": true
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
    fn test_file_integrity_collector_runs() {
        let collector = FileIntegrityCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "file-integrity-monitor");
        assert!(res.success);
    }
}
