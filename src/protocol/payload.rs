use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const TELEMETRY_SCHEMA: &str = "insiedr.agent.telemetry.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorError {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: String,
}

impl From<&str> for CollectorError {
    fn from(s: &str) -> Self {
        Self {
            error_type: "CollectorError".to_string(),
            message: s.to_string(),
        }
    }
}

impl From<String> for CollectorError {
    fn from(s: String) -> Self {
        Self {
            error_type: "CollectorError".to_string(),
            message: s,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorResult {
    #[serde(rename = "collector", alias = "name")]
    pub name: String,
    pub collected_at: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default = "default_success_status")]
    pub status: String,
    #[serde(default = "default_true")]
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CollectorError>,
    #[serde(rename = "payload", alias = "metrics")]
    pub metrics: Value,
    #[serde(default)]
    pub quality: QualityFlags,
}

fn default_success_status() -> String {
    "success".to_string()
}

fn default_true() -> bool {
    true
}

impl CollectorResult {
    /// Omit unavailable object fields while retaining zeros, false, empty collections,
    /// and array positions. This also applies inside nested metric objects.
    pub fn prune_null_fields(&mut self) {
        fn prune(value: &mut Value) {
            match value {
                Value::Object(fields) => {
                    fields.retain(|_, value| !value.is_null());
                    for value in fields.values_mut() { prune(value); }
                }
                Value::Array(values) => { for value in values { prune(value); } }
                _ => {}
            }
        }
        prune(&mut self.metrics);
    }

    pub fn success(
        name: impl Into<String>,
        collected_at: impl Into<String>,
        metrics: Value,
        quality: QualityFlags,
    ) -> Self {
        Self {
            name: name.into(),
            collected_at: collected_at.into(),
            hostname: String::new(),
            status: "success".to_string(),
            success: true,
            error: None,
            metrics,
            quality,
        }
    }

    pub fn failed(
        name: impl Into<String>,
        collected_at: impl Into<String>,
        err_type: impl Into<String>,
        message: impl Into<String>,
        quality: QualityFlags,
    ) -> Self {
        Self {
            name: name.into(),
            collected_at: collected_at.into(),
            hostname: String::new(),
            status: "failed".to_string(),
            success: false,
            error: Some(CollectorError {
                error_type: err_type.into(),
                message: message.into(),
            }),
            metrics: serde_json::json!({}),
            quality,
        }
    }

    pub fn critical(
        name: impl Into<String>,
        collected_at: impl Into<String>,
        err_type: impl Into<String>,
        message: impl Into<String>,
        quality: QualityFlags,
    ) -> Self {
        Self {
            name: name.into(),
            collected_at: collected_at.into(),
            hostname: String::new(),
            status: "critical".to_string(),
            success: false,
            error: Some(CollectorError {
                error_type: err_type.into(),
                message: message.into(),
            }),
            metrics: serde_json::json!({}),
            quality,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QualityFlags {
    pub exact: bool,
    pub partial: bool,
    pub elevated: bool,
    pub heuristic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySummary {
    pub collector_count: usize,
    pub success_count: usize,
    pub failed_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub system: String,
    pub release: String,
    pub version: String,
    pub machine: String,
}

impl OsInfo {
    pub fn current() -> Self {
        Self {
            system: "Windows".to_string(),
            release: "10/11/Server".to_string(),
            version: std::env::var("OS").unwrap_or_else(|_| "Windows_NT".to_string()),
            machine: std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_else(|_| "AMD64".to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryPayload {
    pub protocol_version: String,
    pub schema: String,
    pub payload_id: String,
    pub agent_id: String,
    pub hostname: String,
    pub username: String,
    pub collected_at: String,
    pub summary: TelemetrySummary,
    pub collectors: Vec<CollectorResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<OsInfo>,
}

impl TelemetryPayload {
    pub fn new(agent_id: String, hostname: String, payload_id: String, collected_at: String) -> Self {
        let username = std::env::var("USERNAME").unwrap_or_else(|_| "SYSTEM".to_string());
        Self::with_username(agent_id, hostname, username, payload_id, collected_at)
    }

    pub fn with_username(
        agent_id: String,
        hostname: String,
        username: String,
        payload_id: String,
        collected_at: String,
    ) -> Self {
        Self {
            protocol_version: "2.0".to_string(),
            schema: TELEMETRY_SCHEMA.to_string(),
            payload_id,
            agent_id,
            hostname,
            username,
            collected_at,
            summary: TelemetrySummary {
                collector_count: 0,
                success_count: 0,
                failed_count: 0,
            },
            collectors: Vec::new(),
            os: Some(OsInfo::current()),
        }
    }

    pub fn add_collector(&mut self, mut result: CollectorResult) {
        if result.hostname.is_empty() {
            result.hostname = self.hostname.clone();
        }
        self.summary.collector_count += 1;
        if result.status == "success" {
            self.summary.success_count += 1;
        } else if result.status == "failed" || result.status == "critical" {
            self.summary.failed_count += 1;
        }
        self.collectors.push(result);
    }

    pub fn update_summary(&mut self) {
        let mut success = 0;
        let mut failed = 0;
        for c in &self.collectors {
            if c.status == "success" {
                success += 1;
            } else if c.status == "failed" || c.status == "critical" {
                failed += 1;
            }
        }
        self.summary = TelemetrySummary {
            collector_count: self.collectors.len(),
            success_count: success,
            failed_count: failed,
        };
    }

    /// Serializes payload to canonical JSON bytes matching server
    pub fn to_canonical_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}
