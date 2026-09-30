pub mod envelope;
pub mod payload;
pub mod heartbeat;

pub const PROTOCOL_VERSION: &str = "2.0";
pub const HEADER_CRYPTO_SCHEME: &str = "X-CRYPTO-SCHEME";
pub const HEADER_PROTOCOL_VERSION: &str = "X-PROTOCOL-VERSION";
pub const HEADER_AGENT_ID: &str = "X-AGENT-ID";
pub const HEADER_PAYLOAD_ID: &str = "X-PAYLOAD-ID";
pub const HEADER_KEY_ID: &str = "X-KEY-ID";
pub const HEADER_ENCAPPED_KEY: &str = "X-ENCAPPED-KEY";
