use super::Collector;
use crate::etw::EtwCollectorHub;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;

pub struct DnsCollector;

impl DnsCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Collector for DnsCollector {
    fn name(&self) -> &'static str {
        "dns-monitor"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339();
        let hub = EtwCollectorHub::global();

        let suspicious_tlds = [".tk", ".xyz", ".top", ".buzz", ".onion"];
        let suspicious_keywords = ["ngrok.io", "localtunnel.me", "duckdns.org", "tunnel.me", "chisel"];

        if hub.is_active() {
            let queries = hub.drain_dns_queries();
            let mut captured = Vec::new();
            let mut suspicious_count = 0;

            for q in &queries {
                let name_lower = q.query_name.to_lowercase();
                let suspicious = suspicious_tlds.iter().any(|&tld| name_lower.ends_with(tld))
                    || suspicious_keywords.iter().any(|&kw| name_lower.contains(kw));

                if suspicious {
                    suspicious_count += 1;
                }

                // Keep up to 50 queries in sample payload to prevent log ballooning
                if captured.len() < 50 {
                    captured.push(json!({
                        "name": q.query_name,
                        "type": q.query_type,
                        "results": q.query_results,
                        "status": q.status,
                        "pid": q.pid,
                        "suspicious": suspicious
                    }));
                }
            }

            CollectorResult::success(
                self.name(),
                now,
                json!({
                    "total_queries_captured": queries.len(),
                    "suspicious_queries_count": suspicious_count,
                    "channel": "Microsoft-Windows-DNS-Client (Real-Time ETW)",
                    "tunneling_detected": suspicious_count > 0,
                    "etw_realtime_active": true,
                    "recent_queries": captured
                }),
                QualityFlags {
                    exact: true,
                    partial: false,
                    elevated: true,
                    heuristic: false,
                },
            )
        } else {
            // Fallback baseline metrics when ETW is inactive
            CollectorResult::success(
                self.name(),
                now,
                json!({
                    "total_queries_captured": 0,
                    "suspicious_queries_count": 0,
                    "channel": "Microsoft-Windows-DNS-Client/Operational (Static Baseline)",
                    "tunneling_detected": false,
                    "etw_realtime_active": false
                }),
                QualityFlags {
                    exact: true,
                    partial: true,
                    elevated: false,
                    heuristic: true,
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_collector_runs() {
        let collector = DnsCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "dns-monitor");
        assert!(res.success);
    }
}
