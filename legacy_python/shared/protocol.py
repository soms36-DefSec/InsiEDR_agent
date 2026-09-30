from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping


PROTOCOL_VERSION = "2.0"
TELEMETRY_SCHEMA = "insiedr.agent.telemetry.v1"

CRYPTO_SCHEME_AESGCM = "aes-256-gcm"
CRYPTO_SCHEME_FERNET = "fernet"
CRYPTO_SCHEME_HPKE = "hpke"

HEADER_CRYPTO_SCHEME = "X-CRYPTO-SCHEME"
HEADER_PROTOCOL_VERSION = "X-PROTOCOL-VERSION"
HEADER_AGENT_ID = "X-AGENT-ID"
HEADER_PAYLOAD_ID = "X-PAYLOAD-ID"
HEADER_KEY_ID = "X-KEY-ID"
HEADER_ENCAPPED_KEY = "X-ENCAPPED-KEY"

INGEST_CONTENT_TYPE = "application/json"


def build_hpke_aad(payload_id: str, agent_id: str) -> bytes:
    """Constructs deterministic Authenticated Associated Data (AAD) for HPKE AEAD encryption."""
    return f"insiedr.hpke.telemetry.v2:{payload_id}:{agent_id}".encode("utf-8")


class ProtocolError(ValueError):
    """Raised when a payload does not satisfy the agent/server wire contract."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    ).encode("utf-8")


def parse_json_bytes(data: bytes) -> dict[str, Any]:
    decoded = json.loads(data.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ProtocolError("payload JSON must decode to an object")
    return decoded


def validate_telemetry_payload(payload: Mapping[str, Any]) -> None:
    required = {
        "protocol_version": str,
        "schema": str,
        "payload_id": str,
        "agent_id": str,
        "hostname": str,
        "collected_at": str,
        "collectors": list,
    }
    for key, expected_type in required.items():
        value = payload.get(key)
        if not isinstance(value, expected_type) or value in ("", None):
            raise ProtocolError(f"telemetry payload field '{key}' is missing or invalid")
    if payload["protocol_version"] != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version: {payload['protocol_version']}")
    if payload["schema"] != TELEMETRY_SCHEMA:
        raise ProtocolError(f"unsupported telemetry schema: {payload['schema']}")


def encrypted_payload_headers(envelope: Mapping[str, Any], agent_id: str, payload_id: str) -> dict[str, str]:
    headers = {
        "Content-Type": INGEST_CONTENT_TYPE,
        HEADER_CRYPTO_SCHEME: str(envelope.get("scheme", "")),
        HEADER_PROTOCOL_VERSION: PROTOCOL_VERSION,
        HEADER_AGENT_ID: agent_id,
        HEADER_PAYLOAD_ID: payload_id,
    }
    key_id = envelope.get("key_id")
    if key_id:
        headers[HEADER_KEY_ID] = str(key_id)
    return headers
