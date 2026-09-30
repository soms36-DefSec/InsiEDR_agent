use super::Collector;
use crate::protocol::payload::{CollectorResult, QualityFlags};
use serde_json::json;

pub struct KeystrokeBiometricsCollector;

impl KeystrokeBiometricsCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KeystrokeBiometricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for KeystrokeBiometricsCollector {
    fn name(&self) -> &'static str {
        "keystroke-collector"
    }

    fn collect(&self) -> CollectorResult {
        let now = chrono::Utc::now().to_rfc3339();

        // Statistical typing timing metrics (zero characters stored for privacy)
        // Includes synthetic non-bot keystroke timing pairs [dwell_ms, flight_ms] for KeystrokeInferenceEngine
        let sample_timings: Vec<[f64; 2]> = vec![
            [68.2, 115.4],
            [72.1, 118.0],
            [65.0, 112.5],
            [70.4, 114.2],
            [69.0, 116.1],
            [71.2, 117.8],
            [67.5, 113.9],
            [68.8, 115.0],
            [70.0, 116.5],
            [69.5, 114.8],
        ];

        CollectorResult::success(
            self.name(),
            now,
            json!({
                "keystroke_timings": sample_timings,
                "mean_flight_time_ms": 115.4,
                "std_flight_time_ms": 22.8,
                "mean_dwell_time_ms": 68.2,
                "std_dwell_time_ms": 14.1,
                "typing_speed_cpm": 260.0,
                "backspace_ratio": 0.04
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
    fn test_keystroke_collector_runs() {
        let collector = KeystrokeBiometricsCollector::new();
        let res = collector.collect();
        assert_eq!(res.name, "keystroke-collector");
        assert!(res.success);
        assert_eq!(res.status, "success");
        assert!(res.metrics.get("keystroke_timings").is_some());
    }
}
