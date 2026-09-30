use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostMetrics {
    pub cpu_percent: f32,
    pub memory_mb: f32,
    pub spool_queue_depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub agent_id: String,
    pub hostname: String,
    pub ip_address: String,
    pub agent_version: String,
    pub status: String,
    pub metrics: HostMetrics,
    pub config_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteTask {
    pub task_id: String,
    pub command: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub status: String,
    #[serde(default)]
    pub pending_tasks: Vec<RemoteTask>,
    #[serde(default)]
    pub config_update: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResultPayload {
    pub agent_id: String,
    pub task_id: String,
    pub status: String,
    pub exit_code: i32,
    pub message: String,
    pub timestamp: String,
}
