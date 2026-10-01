//! Transmission semantics for the collectors implemented in this repository.
//!
//! A repeated inventory is a state snapshot; a repeated drained ETW batch is a
//! new observation. Never infer that an arbitrary array or a field named
//! `event_count` is an event stream: file-integrity's AUDIT entries, for example,
//! are recomputed snapshots. Unknown collectors default to unsuppressed delivery.

use crate::protocol::payload::CollectorResult;
use serde_json::Value;

pub fn is_security_event_collector(name: &str) -> bool {
    !matches!(
        name,
        "activity-monitor"
            | "http"
            | "clipboard-monitor"
            | "decoy-monitor"
            | "dns-monitor"
            | "driver-monitor"
            | "email-monitor"
            | "file-integrity-monitor"
            | "keystroke-collector"
            | "logon"
            | "lsass-monitor"
            | "named-pipe-monitor"
            | "network"
            | "persistence-monitor"
            | "process-watcher"
            | "short-Term_EDR_Feature"
            | "devices"
            | "usn-monitor"
            | "wmi-activity"
            | "memory-scanner"
    )
}

/// True for newly collected event batches, including identical consecutive ones.
pub fn has_security_events(name: &str, result: &CollectorResult) -> bool {
    if is_security_event_collector(name) || !result.metrics.is_object() {
        return true;
    }

    let metrics = &result.metrics;
    match name {
        "process-watcher" => metrics
            .get("etw_lifecycle_events")
            .map(|events| {
                !events.is_object()
                    || any_active(
                        events,
                        &["started_count", "stopped_count", "image_loads_count"],
                    )
            })
            .unwrap_or(false),
        "dns-monitor" => {
            active(metrics, "total_queries_captured") || nonempty(metrics, "recent_queries")
        }
        // This count is a per-collection delta, not a cumulative clipboard counter.
        "clipboard-monitor" => active(metrics, "clipboard_copy_count"),
        "usn-monitor" => active(metrics, "usn_records_captured"),
        "lsass-monitor" => active(metrics, "event_count"),
        "wmi-activity" => active(metrics, "total_queries_captured"),
        "file-integrity-monitor" => metrics
            .get("integrity_events")
            .map(|events| match events.as_array() {
                // AUDIT entries contain path/hash state, not file-access events.
                Some(events) => events
                    .iter()
                    .any(|event| event.get("op").and_then(Value::as_str) != Some("AUDIT")),
                None => true,
            })
            .unwrap_or(false),
        _ => false,
    }
}

/// Active alerts stay visible on every cycle; zero/false baselines remain state.
pub fn has_active_threat(name: &str, result: &CollectorResult) -> bool {
    if result.status == "critical" {
        return true;
    }

    let metrics = &result.metrics;
    match name {
        "process-watcher" => any_active(
            metrics,
            &["tunneling_process_count", "executables_from_temp_folder"],
        ),
        "dns-monitor" => any_active(metrics, &["tunneling_detected", "suspicious_queries_count"]),
        "decoy-monitor" => any_active(metrics, &["threat_triggered", "events_recorded"]),
        "memory-scanner" => {
            any_active(
                metrics,
                &[
                    "threats_detected",
                    "unbacked_executable_regions",
                    "reflective_pe_injections",
                    "phantom_hollowed_mappings",
                ],
            ) || nonempty(metrics, "sample_threats")
        }
        "logon" => any_active(metrics, &["failed_logons", "after_hours_logon"]),
        "short-Term_EDR_Feature" => any_active(
            metrics,
            &[
                "edr_failed_auth_ratio_window",
                "edr_failed_auth_events_per_minute_window",
                "auth_fail_rate_300s",
                "off_hours_auth_count",
            ],
        ),
        "http" => any_active(
            metrics,
            &["suspicious_url_count", "watchlisted_domain_hits"],
        ),
        "devices" => active(metrics, "unauthorized_usb_detected"),
        "persistence-monitor" => active(metrics, "modifications_detected"),
        "lsass-monitor" => active(metrics, "credential_dumping_suspected"),
        "wmi-activity" => active(metrics, "lateral_movement_suspected"),
        _ => false,
    }
}

/// Returns comparison-only metrics; the original payload is never altered.
///
/// Activity's idle duration increases on an otherwise unchanged idle endpoint,
/// and its input tick changes on every input. Compare its active/idle state and
/// send the complete original metrics at each forced snapshot (normally 300s).
/// Only do this when the collector provided a valid state indicator. No other
/// timestamps, event fields, array entries, zeros, false values, or nulls are
/// removed. Keystroke metrics are cumulative snapshots; their timings and sample
/// counts remain significant so new typing activity is never hidden by rounding.
pub fn comparison_metrics(result: &CollectorResult) -> Value {
    let mut metrics = result.metrics.clone();
    if result.name == "activity-monitor"
        && metrics
            .get("is_user_active")
            .and_then(Value::as_bool)
            .is_some()
    {
        if let Some(fields) = metrics.as_object_mut() {
            fields.remove("user_idle_seconds");
            fields.remove("last_input_tick");
        }
    }
    metrics
}

fn active(metrics: &Value, key: &str) -> bool {
    metrics.get(key).is_some_and(|value| {
        value.as_bool() == Some(true) || value.as_f64().is_some_and(|number| number > 0.0)
    })
}

fn any_active(metrics: &Value, keys: &[&str]) -> bool {
    keys.iter().any(|key| active(metrics, key))
}

fn nonempty(metrics: &Value, key: &str) -> bool {
    metrics.get(key).is_some_and(|value| match value {
        Value::Array(values) => !values.is_empty(),
        Value::Null => false,
        // Unexpected event data is preserved rather than classified as empty.
        _ => true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::payload::QualityFlags;
    use serde_json::json;

    fn result(name: &str, metrics: Value) -> CollectorResult {
        CollectorResult::success(
            name,
            "2026-10-01T12:00:00Z",
            metrics,
            QualityFlags::default(),
        )
    }

    #[test]
    fn repeated_drained_etw_batches_are_events() {
        for event in ["started_count", "stopped_count", "image_loads_count"] {
            let collected = result(
                "process-watcher",
                json!({"etw_lifecycle_events": {event: 1}}),
            );
            assert!(has_security_events(&collected.name, &collected));
            assert!(has_security_events(&collected.name, &collected.clone()));
        }
        let clean = result(
            "process-watcher",
            json!({
                "etw_realtime_active": true,
                "process_count": 100,
                "etw_lifecycle_events": {"started_count": 0, "stopped_count": 0, "image_loads_count": 0}
            }),
        );
        assert!(!has_security_events(&clean.name, &clean));
    }

    #[test]
    fn repeated_dns_queries_are_events_even_without_unique_ids() {
        let collected = result(
            "dns-monitor",
            json!({
                "total_queries_captured": 1,
                "recent_queries": [{"name": "example.org", "type": 1, "pid": 123, "suspicious": false}]
            }),
        );
        for _ in 0..2 {
            assert!(has_security_events(&collected.name, &collected));
        }
        let count_only = result(
            "dns-monitor",
            json!({"total_queries_captured": 1, "recent_queries": []}),
        );
        assert!(has_security_events(&count_only.name, &count_only));
        let clean = result(
            "dns-monitor",
            json!({"total_queries_captured": 0, "recent_queries": []}),
        );
        assert!(!has_security_events(&clean.name, &clean));
    }

    #[test]
    fn repeated_audit_inventory_is_state_but_other_file_operations_are_events() {
        let audit = result(
            "file-integrity-monitor",
            json!({
                "event_count": 1,
                "integrity_events": [{"path": "hosts", "sha256": "abc", "op": "AUDIT"}]
            }),
        );
        assert!(!has_security_events(&audit.name, &audit));
        let changed = result(
            "file-integrity-monitor",
            json!({
                "integrity_events": [{"path": "hosts", "op": "WRITE"}]
            }),
        );
        assert!(has_security_events(&changed.name, &changed));
        assert_ne!(comparison_metrics(&audit), comparison_metrics(&changed));
    }

    #[test]
    fn alerts_bypass_with_actual_collector_fields() {
        let cases = [
            ("process-watcher", json!({"tunneling_process_count": 1})),
            ("dns-monitor", json!({"suspicious_queries_count": 1})),
            ("decoy-monitor", json!({"threat_triggered": true})),
            ("memory-scanner", json!({"reflective_pe_injections": 1})),
            (
                "memory-scanner",
                json!({"sample_threats": [{"pid": 42, "threat_type": "test"}]}),
            ),
            ("logon", json!({"failed_logons": 1})),
            ("logon", json!({"after_hours_logon": 1.0})),
            (
                "short-Term_EDR_Feature",
                json!({"auth_fail_rate_300s": 0.1}),
            ),
            ("http", json!({"watchlisted_domain_hits": 1})),
            ("devices", json!({"unauthorized_usb_detected": true})),
            (
                "persistence-monitor",
                json!({"modifications_detected": true}),
            ),
            (
                "lsass-monitor",
                json!({"credential_dumping_suspected": true}),
            ),
            ("wmi-activity", json!({"lateral_movement_suspected": true})),
        ];
        for (name, metrics) in cases {
            let collected = result(name, metrics);
            assert!(has_active_threat(name, &collected), "{name}");
            assert!(has_active_threat(name, &collected.clone()), "{name}");
        }
    }

    #[test]
    fn actual_inventory_collectors_and_clean_baselines_are_suppressible() {
        let names = [
            "activity-monitor",
            "http",
            "clipboard-monitor",
            "decoy-monitor",
            "dns-monitor",
            "driver-monitor",
            "email-monitor",
            "file-integrity-monitor",
            "keystroke-collector",
            "logon",
            "lsass-monitor",
            "named-pipe-monitor",
            "network",
            "persistence-monitor",
            "process-watcher",
            "short-Term_EDR_Feature",
            "devices",
            "usn-monitor",
            "wmi-activity",
            "memory-scanner",
        ];
        let metrics = json!({"event_count": 0, "threats_detected": false, "sample_threats": []});
        for name in names {
            let collected = result(name, metrics.clone());
            assert!(!is_security_event_collector(name), "{name}");
            assert!(!has_security_events(name, &collected), "{name}");
            assert!(!has_active_threat(name, &collected), "{name}");
            assert_eq!(comparison_metrics(&collected), metrics);
        }
    }

    #[test]
    fn unknown_collectors_and_malformed_metrics_fail_open() {
        let unknown = result("future-security-sensor", json!({"count": 0}));
        assert!(is_security_event_collector(&unknown.name));
        assert!(has_security_events(&unknown.name, &unknown));
        let malformed = result("process-watcher", Value::Null);
        assert!(has_security_events(&malformed.name, &malformed));
    }

    #[test]
    fn activity_comparison_keeps_state_transitions_and_original_metrics() {
        let first = result(
            "activity-monitor",
            json!({
                "is_user_active": false, "user_idle_seconds": 600.0, "last_input_tick": 100
            }),
        );
        let later = result(
            "activity-monitor",
            json!({
                "is_user_active": false, "user_idle_seconds": 605.0, "last_input_tick": 100
            }),
        );
        assert_eq!(comparison_metrics(&first), comparison_metrics(&later));
        assert_eq!(first.metrics["user_idle_seconds"], 600.0);
        let active = result(
            "activity-monitor",
            json!({
                "is_user_active": true, "user_idle_seconds": 0.0, "last_input_tick": 605000
            }),
        );
        assert_ne!(comparison_metrics(&first), comparison_metrics(&active));
        let missing_state = result(
            "activity-monitor",
            json!({"user_idle_seconds": 0, "last_input_tick": 0}),
        );
        assert_eq!(comparison_metrics(&missing_state), missing_state.metrics);
    }

    #[test]
    fn keystroke_samples_and_forensic_times_are_not_pruned() {
        let collected = result(
            "keystroke-collector",
            json!({
                "keystroke_timings": [[0.0, 42.5]], "total_keys_sampled": 1,
                "observed_at": "2026-10-01T12:00:00Z", "optional": null, "alert": false
            }),
        );
        assert_eq!(comparison_metrics(&collected), collected.metrics);
        let new_keys = result("keystroke-collector", json!({"total_keys_sampled": 2}));
        assert_ne!(
            comparison_metrics(&collected),
            comparison_metrics(&new_keys)
        );
    }

    #[test]
    fn per_cycle_clipboard_and_other_event_counts_bypass() {
        for (name, field) in [
            ("clipboard-monitor", "clipboard_copy_count"),
            ("usn-monitor", "usn_records_captured"),
            ("lsass-monitor", "event_count"),
            ("wmi-activity", "total_queries_captured"),
        ] {
            let collected = result(name, json!({field: 1}));
            assert!(has_security_events(name, &collected), "{name}");
        }
    }
}
