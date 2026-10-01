use crate::protocol::heartbeat::{HeartbeatRequest, HeartbeatResponse, TaskResultPayload};
use crate::protocol::HEADER_PAYLOAD_ID;
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

#[derive(serde::Deserialize)]
struct TelemetryAcknowledgement {
    ok: bool,
    payload_id: String,
    status: String,
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
    /// Only the explicit durable acceptance contract can release queued data.
    pub async fn send_telemetry(
        &self,
        envelope_json: &str,
        custom_headers: &HashMap<String, String>,
    ) -> Result<bool, TransportError> {
        let url = format!("{}/api/logs", self.server_base_url);

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        for (k, v) in custom_headers {
            let name = HeaderName::from_str(k).map_err(|_| {
                TransportError::SerializationError(format!("Invalid telemetry header name: {k}"))
            })?;
            let val = HeaderValue::from_str(v).map_err(|_| {
                TransportError::SerializationError(format!("Invalid telemetry header value: {k}"))
            })?;
            headers.insert(name, val);
        }
        let payload_id = headers
            .get(HEADER_PAYLOAD_ID)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                TransportError::SerializationError("Missing telemetry payload ID header".into())
            })?
            .to_owned();

        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .body(envelope_json.to_string())
            .send()
            .await
            .map_err(TransportError::HttpError)?;

        let status = resp.status();
        let body = resp.text().await.map_err(TransportError::HttpError)?;
        if status != reqwest::StatusCode::ACCEPTED {
            return Err(TransportError::ServerRejected(status.as_u16(), body));
        }
        let acknowledgement: TelemetryAcknowledgement =
            serde_json::from_str(&body).map_err(|_| {
                TransportError::ServerRejected(
                    status.as_u16(),
                    "Invalid telemetry acknowledgement JSON".into(),
                )
            })?;
        if !acknowledgement.ok
            || acknowledgement.status != "accepted"
            || acknowledgement.payload_id != payload_id
        {
            return Err(TransportError::ServerRejected(
                status.as_u16(),
                "Telemetry acknowledgement does not match the submitted payload".into(),
            ));
        }
        Ok(true)
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
    pub async fn send_task_result(&self, result: &TaskResultPayload) -> Result<(), TransportError> {
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn submit_to_stub(status: u16, body: &str) -> Result<bool, TransportError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            loop {
                let read = socket.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0, "client closed before submitting the envelope");
                request.extend_from_slice(&buffer[..read]);
                if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&request[..end])
                        .unwrap()
                        .to_ascii_lowercase();
                    let content_length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .unwrap()
                        .trim()
                        .parse::<usize>()
                        .unwrap();
                    if request.len() >= end + 4 + content_length {
                        assert!(headers.starts_with("post /api/logs http/1.1"));
                        assert!(headers.contains("x-payload-id: test-payload"));
                        assert_eq!(&request[end + 4..], b"{\"payload_id\":\"test-payload\"}");
                        break;
                    }
                }
            }
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        let mut client = InsiTransportClient::new(&format!("http://{address}"));
        // These tests use a loopback stub regardless of workstation proxy settings.
        client.client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let headers = HashMap::from([(HEADER_PAYLOAD_ID.to_string(), "test-payload".to_string())]);
        let result = client
            .send_telemetry("{\"payload_id\":\"test-payload\"}", &headers)
            .await;
        server.await.unwrap();
        result
    }

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

    #[tokio::test]
    async fn accepts_only_explicit_durable_acknowledgements() {
        let ack = r#"{"ok":true,"payload_id":"test-payload","status":"accepted"}"#;
        assert!(submit_to_stub(202, ack).await.unwrap());
        // An identical durable duplicate uses the same explicit ACK contract.
        assert!(submit_to_stub(202, ack).await.unwrap());
        for status in [200, 201, 204, 409, 500, 503] {
            assert!(matches!(submit_to_stub(status, ack).await,
                Err(TransportError::ServerRejected(code, _)) if code == status));
        }
    }

    #[tokio::test]
    async fn rejected_or_malformed_ack_cannot_release_pending_events() {
        for ack in [
            "",
            "not json",
            "{}",
            r#"{"ok":true,"payload_id":"different-payload","status":"accepted"}"#,
            r#"{"ok":false,"payload_id":"test-payload","status":"accepted"}"#,
            r#"{"ok":true,"payload_id":"test-payload","status":"queued"}"#,
            r#"{"ok":"true","payload_id":"test-payload","status":"accepted"}"#,
        ] {
            assert!(matches!(
                submit_to_stub(202, ack).await,
                Err(TransportError::ServerRejected(202, _))
            ));
        }
    }

    #[tokio::test]
    async fn missing_identity_is_rejected_before_network_submission() {
        let client = InsiTransportClient::new("http://127.0.0.1:1");
        assert!(matches!(
            client.send_telemetry("{}", &HashMap::new()).await,
            Err(TransportError::SerializationError(_))
        ));
    }
}
