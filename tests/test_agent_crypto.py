"""
tests/test_agent_crypto.py
--------------------------
Comprehensive unit test suite for InsiEDR endpoint agent cryptographic engine:
- HPKE vs AES-GCM engine creation via factory
- AgentConfig environment parsing (public key, key path, scheme auto-detection)
- Telemetry payload encryption compliance
- LocalEncryptedQueue offline storage validation with HPKE
"""
import os
import json
import uuid
import pytest
from pathlib import Path
from unittest.mock import patch

from shared.crypto_utils import (
    generate_x25519_keypair,
    export_x25519_public_key,
    normalize_aes_key,
)
from shared.protocol import (
    CRYPTO_SCHEME_HPKE,
    CRYPTO_SCHEME_AESGCM,
    PROTOCOL_VERSION,
)
from agent.config import AgentConfig, ConfigError
from agent.crypto import (
    HPKECrypto,
    AESGCMCrypto,
    create_agent_crypto,
)
from agent.queue import LocalEncryptedQueue


def _sample_payload(payload_id: str | None = None) -> dict:
    pid = payload_id or str(uuid.uuid4())
    return {
        "schema": "insiedr.agent.telemetry.v1",
        "protocol_version": PROTOCOL_VERSION,
        "payload_id": pid,
        "agent_id": "test-host-agent",
        "collected_at": "2026-09-15T03:00:00Z",
        "hostname": "ENDPOINT-WIN11",
        "username": "analyst",
        "collectors": [],
        "summary": {"collector_count": 0, "success_count": 0, "failed_count": 0},
    }


def test_agent_config_from_env_with_hpke(monkeypatch):
    _, raw_pub = generate_x25519_keypair()
    pub_b64 = export_x25519_public_key(raw_pub)

    monkeypatch.setenv("INSIEDR_AGENT_SERVER", "https://edr.corp.local/api/logs")
    monkeypatch.setenv("INSIEDR_SERVER_PUBLIC_KEY", pub_b64)
    monkeypatch.setenv("INSIEDR_SERVER_KEY_ID", "corp-x25519-v1")
    monkeypatch.delenv("INSIEDR_AES_KEY", raising=False)
    monkeypatch.delenv("AES_KEY", raising=False)

    config = AgentConfig.from_env()
    assert config.encryption_scheme == CRYPTO_SCHEME_HPKE
    assert config.server_key_id == "corp-x25519-v1"
    assert config.server_public_key is not None

    crypto = create_agent_crypto(config)
    assert isinstance(crypto, HPKECrypto)
    assert crypto.key_id == "corp-x25519-v1"


def test_agent_config_from_env_with_key_path(monkeypatch, tmp_path):
    _, raw_pub = generate_x25519_keypair()
    pub_b64 = export_x25519_public_key(raw_pub)
    key_file = tmp_path / "server_public.key"
    key_file.write_text(pub_b64, encoding="ascii")

    monkeypatch.setenv("INSIEDR_AGENT_SERVER", "https://edr.corp.local/api/logs")
    monkeypatch.setenv("INSIEDR_SERVER_PUBLIC_KEY_PATH", str(key_file))
    monkeypatch.delenv("INSIEDR_SERVER_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("INSIEDR_AES_KEY", raising=False)

    config = AgentConfig.from_env()
    assert config.encryption_scheme == CRYPTO_SCHEME_HPKE
    crypto = create_agent_crypto(config)
    assert isinstance(crypto, HPKECrypto)


def test_agent_config_from_env_legacy_aes_fallback(monkeypatch):
    aes_key_hex = "e548bcb6e1e7da40ccac2adeba65f34554458de520e9a0780f3a5f04f01a72d7"
    monkeypatch.setenv("INSIEDR_AGENT_SERVER", "https://edr.corp.local/api/logs")
    monkeypatch.setenv("INSIEDR_AES_KEY", aes_key_hex)
    monkeypatch.delenv("INSIEDR_SERVER_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("INSIEDR_SERVER_PUBLIC_KEY_PATH", raising=False)
    monkeypatch.delenv("INSIEDR_CRYPTO_SCHEME", raising=False)

    config = AgentConfig.from_env()
    assert config.encryption_scheme == CRYPTO_SCHEME_AESGCM
    crypto = create_agent_crypto(config)
    assert isinstance(crypto, AESGCMCrypto)


def test_agent_crypto_factory_missing_keys():
    mock_config = type("MockConfig", (), {
        "encryption_scheme": "hpke",
        "server_public_key": None,
        "aes_key": None,
        "server_key_id": "k1",
    })()

    with pytest.raises(ValueError, match="HPKE encryption selected but server public key is missing"):
        create_agent_crypto(mock_config)


def test_hpke_crypto_wire_envelope():
    _, raw_pub = generate_x25519_keypair()
    agent_crypto = HPKECrypto(raw_pub, key_id="prod-key-01")

    payload = _sample_payload("test-payload-123")
    envelope = agent_crypto.encrypt_payload(payload)

    assert envelope["protocol_version"] == PROTOCOL_VERSION
    assert envelope["scheme"] == CRYPTO_SCHEME_HPKE
    assert envelope["payload_id"] == "test-payload-123"
    assert envelope["key_id"] == "prod-key-01"
    assert "encapped_key" in envelope
    assert "nonce" in envelope
    assert "ciphertext" in envelope
    assert "created_at" in envelope


def test_agent_local_queue_offline_buffering(tmp_path):
    _, raw_pub = generate_x25519_keypair()
    agent_crypto = HPKECrypto(raw_pub, key_id="queue-test-key")
    queue = LocalEncryptedQueue(tmp_path / "agent_queue")

    # Enqueue 5 HPKE envelopes
    for i in range(5):
        payload = _sample_payload(f"p-offline-{i}")
        envelope = agent_crypto.encrypt_payload(payload)
        queue.enqueue(envelope)

    items = list(queue.iter_items())
    assert len(items) == 5
    for item in items:
        assert item.body["envelope"]["scheme"] == "hpke"
        assert "encapped_key" in item.body["envelope"]
