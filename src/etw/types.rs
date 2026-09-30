use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwProcessStart {
    pub pid: u32,
    pub parent_pid: u32,
    pub image_name: String,
    pub command_line: String,
    pub user_sid: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwProcessStop {
    pub pid: u32,
    pub exit_code: u32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwImageLoad {
    pub pid: u32,
    pub file_name: String,
    pub image_base: u64,
    pub image_size: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwDnsQuery {
    pub pid: u32,
    pub query_name: String,
    pub query_type: u32,
    pub query_results: String,
    pub status: u32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum EtwEvent {
    ProcessStart(EtwProcessStart),
    ProcessStop(EtwProcessStop),
    ImageLoad(EtwImageLoad),
    DnsQuery(EtwDnsQuery),
}
