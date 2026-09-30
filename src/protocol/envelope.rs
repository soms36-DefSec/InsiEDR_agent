use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: &str = "2.0";
pub const SCHEME_AESGCM: &str = "aes-256-gcm";
pub const SCHEME_HPKE: &str = "hpke";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEnvelope {
    pub protocol_version: String,
    pub scheme: String,
    pub key_id: String,
    pub payload_id: String,
    pub created_at: String,
    pub nonce: String,
    pub ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encapped_key: Option<String>,
}

impl WireEnvelope {
    pub fn new_aesgcm(
        payload_id: String,
        key_id: String,
        nonce_b64: String,
        ciphertext_b64: String,
        created_at: String,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            scheme: SCHEME_AESGCM.to_string(),
            key_id,
            payload_id,
            created_at,
            nonce: nonce_b64,
            ciphertext: ciphertext_b64,
            encapped_key: None,
        }
    }

    pub fn new_hpke(
        payload_id: String,
        key_id: String,
        encapped_key_b64: String,
        nonce_b64: String,
        ciphertext_b64: String,
        created_at: String,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            scheme: SCHEME_HPKE.to_string(),
            key_id,
            payload_id,
            created_at,
            nonce: nonce_b64,
            ciphertext: ciphertext_b64,
            encapped_key: Some(encapped_key_b64),
        }
    }
}
