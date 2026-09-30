use crate::protocol::heartbeat::{HeartbeatRequest, HeartbeatResponse, TaskResultPayload};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::Client;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug)]
pub enum TransportError {
    HttpError(reqwest::Error),
    ServerRejected(u16, String),
    SerializationError(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HttpError(e) => write!(f, "HTTP transport error: {}", e),
            Self::ServerRejected(code, msg) => write!(f, "Server rejected request ({code}): {msg}"),
            Self::SerializationError(e) => write!(f, "JSON serialization error: {e}"),
        }
    }
}

impl std::error::Error for TransportError {}

#[derive(Clone)]
pub struct InsiTransportClient {
    client: Client,
    server_base_url: String,
}

impl InsiTransportClient {
    pub fn new(server_base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(5)
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            server_base_url: server_base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Transmits an encrypted telemetry envelope to `POST /api/logs`.
    pub async fn send_telemetry(
        &self,
        envelope_json: &str,
        custom_headers: &HashMap<String, String>,
    ) -> Result<bool, TransportError> {
        let url = format!("{}/api/logs", self.server_base_url);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        for (k, v) in custom_headers {
            if let Ok(name) = HeaderName::from_str(k) {
                if let Ok(val) = HeaderValue::from_str(v) {
                    headers.insert(name, val);
                }
            }
        }

        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .body(envelope_json.to_string())
            .send()
            .await
            .map_err(TransportError::HttpError)?;

        let status = resp.status();
        if status.is_success() || status.as_u16() == 202 {
            Ok(true)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(TransportError::ServerRejected(status.as_u16(), body))
        }
    }

    /// Sends periodic heartbeat to `POST /api/agent/heartbeat`.
    pub async fn send_heartbeat(
        &self,
        req: &HeartbeatRequest,
    ) -> Result<HeartbeatResponse, TransportError> {
        let url = format!("{}/api/agent/heartbeat", self.server_base_url);

        let resp = self
            .client
            .post(&url)
            .json(req)
            .send()
            .await
            .map_err(TransportError::HttpError)?;

        if resp.status().is_success() {
            let hb_resp = resp
                .json::<HeartbeatResponse>()
                .await
                .map_err(TransportError::HttpError)?;
            Ok(hb_resp)
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(TransportError::ServerRejected(status, body))
        }
    }

    /// Sends command execution result back to `POST /api/agent/task_result`.
    pub async fn send_task_result(
        &self,
        result: &TaskResultPayload,
    ) -> Result<(), TransportError> {
        let url = format!("{}/api/agent/task_result", self.server_base_url);

        let resp = self
            .client
            .post(&url)
            .json(result)
            .send()
            .await
            .map_err(TransportError::HttpError)?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(TransportError::ServerRejected(status, body))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_url_formatting() {
        let client = InsiTransportClient::new("http://localhost:5000/");
        assert_eq!(client.server_base_url, "http://localhost:5000");

        let client2 = InsiTransportClient::new("https://edr.corp.net");
        assert_eq!(client2.server_base_url, "https://edr.corp.net");
    }

    #[test]
    fn test_transport_error_display() {
        let err = TransportError::ServerRejected(403, "Forbidden token".into());
        let msg = format!("{err}");
        assert!(msg.contains("403"));
        assert!(msg.contains("Forbidden token"));
    }
}
