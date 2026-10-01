use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use rusqlite::{Connection, OpenFlags};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

pub struct BrowserHistoryCollector;

impl BrowserHistoryCollector {
    pub fn new() -> Self { Self }

    /// Returns candidate Chrome / Edge history database paths for the current user.
    fn candidate_db_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let local_app_data = match std::env::var("LOCALAPPDATA") {
            Ok(p) => PathBuf::from(p),
            Err(_) => return paths,
        };

        let profiles = [
            // Chrome
            local_app_data.join(r"Google\Chrome\User Data\Default\History"),
            local_app_data.join(r"Google\Chrome\User Data\Profile 1\History"),
            // Microsoft Edge (Chromium)
            local_app_data.join(r"Microsoft\Edge\User Data\Default\History"),
            local_app_data.join(r"Microsoft\Edge\User Data\Profile 1\History"),
            // Brave
            local_app_data.join(r"BraveSoftware\Brave-Browser\User Data\Default\History"),
        ];

        for p in &profiles {
            if p.exists() {
                paths.push(p.clone());
            }
        }
        paths
    }

    /// Copies the History SQLite DB to a temp file (original is locked by browser)
    /// and queries URL counts from the past 24 hours.
    fn query_history(db_path: &PathBuf) -> Option<HistoryStats> {
        // Build temp copy path (in ProgramData temp, accessible from service context)
        let tmp_dir = std::env::var("TEMP")
            .or_else(|_| std::env::var("TMP"))
            .unwrap_or_else(|_| r"C:\Windows\Temp".to_string());
        let tmp_path = PathBuf::from(&tmp_dir).join("insiedr_history_snapshot.db");

        // Copy — ignore errors if browser has a file lock; read-only copy usually works
        if fs::copy(db_path, &tmp_path).is_err() {
            return None;
        }

        // Open the copy as read-only
        let conn = Connection::open_with_flags(
            &tmp_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .ok()?;

        // Chrome/Edge history stores timestamps as microseconds since 1601-01-01.
        // 24h ago in Chrome time = (now_unix + 11644473600) * 1e6 - 86400 * 1e6
        let chrome_epoch_offset_us: i64 = 11_644_473_600 * 1_000_000;
        let now_us = chrono::Utc::now().timestamp_micros() + chrome_epoch_offset_us;
        let cutoff_us = now_us - 86_400 * 1_000_000_i64; // 24 hours ago

        // Query visits in past 24h
        let mut stmt = conn.prepare(
            "SELECT u.url, v.visit_time
             FROM visits v
             JOIN urls u ON u.id = v.url
             WHERE v.visit_time >= ?1
             LIMIT 2000"
        ).ok()?;

        let rows = stmt.query_map([cutoff_us], |row| {
            let url: String = row.get(0)?;
            Ok(url)
        }).ok()?;

        let mut urls: Vec<String> = Vec::new();
        for r in rows.flatten() {
            urls.push(r);
        }

        // Clean up temp file
        let _ = fs::remove_file(&tmp_path);

        if urls.is_empty() {
            return Some(HistoryStats::default());
        }

        // ── Compute features ──────────────────────────────────────────────
        let http_count = urls.len();

        // Extract hostname per URL
        let domains: Vec<String> = urls.iter()
            .filter_map(|u| {
                let s = u.trim_start_matches("https://").trim_start_matches("http://");
                s.split('/').next().map(|h| h.to_lowercase())
            })
            .collect();

        let mut domain_freq: HashMap<String, usize> = HashMap::new();
        for d in &domains {
            *domain_freq.entry(d.clone()).or_insert(0) += 1;
        }
        let unique_domains = domain_freq.len();
        let unique_urls: std::collections::HashSet<_> = urls.iter().collect();

        // Shannon entropy of domain distribution
        let total = domains.len() as f64;
        let entropy = domain_freq.values()
            .map(|&cnt| {
                let p = cnt as f64 / total;
                -p * p.log2()
            })
            .sum::<f64>();

        // Heuristic flags
        let file_sharing_keywords = ["drive.google", "onedrive", "dropbox", "mega.nz", "wetransfer", "box.com"];
        let job_search_keywords    = ["linkedin", "indeed", "glassdoor", "monster", "naukri", "jobsite"];
        let suspicious_tlds        = [".ru", ".cn", ".tk", ".xyz", ".top", ".pw"];

        let file_sharing_visits = domains.iter()
            .filter(|d| file_sharing_keywords.iter().any(|k| d.contains(k)))
            .count();
        let job_search_visits = domains.iter()
            .filter(|d| job_search_keywords.iter().any(|k| d.contains(k)))
            .count();
        let suspicious_urls = domains.iter()
            .filter(|d| suspicious_tlds.iter().any(|t| d.ends_with(t)))
            .count();

        // External domain ratio: domains that are not internal/local
        let external_domains = domains.iter()
            .filter(|d| !d.starts_with("127.") && !d.starts_with("192.168.") && !d.starts_with("10.") && *d != "localhost")
            .count();
        let external_ratio = if !domains.is_empty() { external_domains as f64 / domains.len() as f64 } else { 0.0 };

        Some(HistoryStats {
            http_count,
            unique_url_count: unique_urls.len(),
            unique_domain_count: unique_domains,
            file_sharing_visits,
            job_search_visits,
            suspicious_url_count: suspicious_urls,
            domain_entropy: (entropy * 1000.0).round() / 1000.0,
            external_url_ratio: (external_ratio * 1000.0).round() / 1000.0,
        })
    }
}

#[derive(Default)]
struct HistoryStats {
    http_count:          usize,
    unique_url_count:    usize,
    unique_domain_count: usize,
    file_sharing_visits: usize,
    job_search_visits:   usize,
    suspicious_url_count: usize,
    domain_entropy:      f64,
    external_url_ratio:  f64,
}

impl Default for BrowserHistoryCollector {
    fn default() -> Self { Self::new() }
}

impl Collector for BrowserHistoryCollector {
    fn name(&self) -> &'static str { "http" }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let candidates = Self::candidate_db_paths();

        // Try each browser DB in order; use the first that succeeds
        let mut stats = HistoryStats::default();
        let mut found = false;
        for path in &candidates {
            if let Some(s) = Self::query_history(path) {
                stats = s;
                found = true;
                break;
            }
        }

        let quality = if found && stats.http_count > 0 {
            QualityFlags { exact: true, partial: false, elevated: false, heuristic: false }
        } else {
            QualityFlags { exact: false, partial: true, elevated: false, heuristic: true }
        };

        CollectorResult::success(
            self.name(),
            now,
            json!({
                // G-model canonical fields
                "http_count":                  stats.http_count as f64,
                "daily_http_request_count":    stats.http_count as f64,
                "unique_url_count":            stats.unique_url_count as f64,
                "suspicious_url_count":        stats.suspicious_url_count as f64,
                "file_sharing_site_visits":    stats.file_sharing_visits as f64,
                "job_search_site_visits":      stats.job_search_visits as f64,
                "http_after_hours":            0.0,
                "daily_unique_domain_count":   stats.unique_domain_count as f64,
                "daily_new_domain_count":      0.0,
                "daily_domain_access_entropy": stats.domain_entropy,
                "daily_external_domain_ratio": stats.external_url_ratio,
                // Legacy / extra fields
                "url_access_count":            stats.http_count,
                "domain_entropy":              stats.domain_entropy,
                "cloud_storage_uploads":       0,
                "watchlisted_domain_hits":     stats.suspicious_url_count,
                "external_url_ratio":          stats.external_url_ratio,
                "browser_db_found":            found
            }),
            quality,
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
        assert!(res.metrics.get("daily_http_request_count").is_some());
        // If no browser found, browser_db_found will be false but collection still succeeds
        println!("Browser found: {:?}", res.metrics.get("browser_db_found"));
    }
}
