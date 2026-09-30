use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE, Engine as _};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    pub server_url: Option<String>,
    pub agent_id: Option<String>,
    pub crypto_scheme: Option<String>,
    pub key_id: Option<String>,
    pub aes_key_base64: Option<String>,
    pub heartbeat_interval_secs: Option<u64>,
    pub spool_db_path: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AgentConfig {
    pub server_url: String,
    pub agent_id: String,
    pub hostname: String,
    pub username: String,
    pub crypto_scheme: String,
    pub key_id: String,
    pub aes_key_bytes: Vec<u8>,
    pub hpke_server_pub_bytes: Vec<u8>,
    pub heartbeat_interval_secs: u64,
    pub spool_db_path: String,
}

impl AgentConfig {
    pub fn load() -> Self {
        Self::default()
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        let hostname = env::var("COMPUTERNAME").unwrap_or_else(|_| "INSIEDR-HOST".to_string());
        let username = env::var("USERNAME")
            .or_else(|_| env::var("USER"))
            .unwrap_or_else(|_| "SYSTEM".to_string());

        // Attempt to discover agent_config.json
        let candidate_paths = vec![
            env::var("INSIEDR_CONFIG_PATH").ok().map(PathBuf::from),
            Some(PathBuf::from("agent_config.json")),
            env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("agent_config.json"))),
            Some(PathBuf::from(r"C:\Program Files\InsiEDR\agent_config.json")),
            Some(PathBuf::from(r"C:\ProgramData\InsiEDR\agent_config.json")),
        ];

        let mut file_cfg = ConfigFile::default();
        for opt in candidate_paths.into_iter().flatten() {
            if opt.is_file() {
                if let Ok(content) = fs::read_to_string(&opt) {
                    if let Ok(parsed) = serde_json::from_str::<ConfigFile>(&content) {
                        println!("[Config] Loaded configuration from {}", opt.display());
                        file_cfg = parsed;
                        break;
                    }
                }
            }
        }

        let agent_id = file_cfg.agent_id
            .or_else(|| env::var("INSIEDR_AGENT_ID").ok())
            .unwrap_or_else(|| format!("AGENT-{hostname}"));

        let server_url = file_cfg.server_url
            .or_else(|| env::var("INSIEDR_SERVER_URL").ok())
            .unwrap_or_else(|| "http://127.0.0.1:5000".to_string());

        let crypto_scheme = file_cfg.crypto_scheme
            .or_else(|| env::var("INSIEDR_CRYPTO_SCHEME").ok())
            .unwrap_or_else(|| "aes-256-gcm".to_string());

        let key_id = file_cfg.key_id
            .or_else(|| env::var("INSIEDR_KEY_ID").ok())
            .unwrap_or_else(|| "default".to_string());

        let heartbeat_interval_secs = file_cfg.heartbeat_interval_secs
            .or_else(|| env::var("INSIEDR_HEARTBEAT_SECS").ok().and_then(|s| s.parse().ok()))
            .unwrap_or(5);

        let spool_db_path = file_cfg.spool_db_path
            .or_else(|| env::var("INSIEDR_SPOOL_DB_PATH").ok())
            .unwrap_or_else(|| "spool.db".to_string());

        // Parse AES Key: support custom base64 or fallback to default
        let mut aes_key_bytes = vec![0x42; 32];
        let b64_candidate = file_cfg.aes_key_base64
            .or_else(|| env::var("INSIEDR_AES_KEY_BASE64").ok());

        if let Some(b64_str) = b64_candidate {
            if let Ok(decoded) = URL_SAFE.decode(b64_str.trim()).or_else(|_| STANDARD.decode(b64_str.trim())) {
                if decoded.len() == 32 {
                    aes_key_bytes = decoded;
                }
            }
        }

        let hpke_server_pub_bytes = vec![0x42; 32];

        Self {
            server_url,
            agent_id,
            hostname,
            username,
            crypto_scheme,
            key_id,
            aes_key_bytes,
            hpke_server_pub_bytes,
            heartbeat_interval_secs,
            spool_db_path,
        }
    }
}
