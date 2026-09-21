from __future__ import annotations

import os
from typing import Any, Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from shared.crypto_utils import b64encode, normalize_aes_key, key_fingerprint
from shared.protocol import (
    CRYPTO_SCHEME_AESGCM,
    PROTOCOL_VERSION,
    canonical_json_bytes,
    utc_now_iso,
)

AES_GCM_AAD = b"insiedr.agent.telemetry.v2"


class AESGCMCrypto:
    """Legacy symmetric AES-256-GCM encryption engine for backwards compatibility."""
    scheme = CRYPTO_SCHEME_AESGCM

    def __init__(self, key: bytes | str) -> None:
        self.key = normalize_aes_key(key)
        self._aesgcm = AESGCM(self.key)
        self.key_id = key_fingerprint(self.key)

    def encrypt_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        plaintext = canonical_json_bytes(payload)
        nonce = os.urandom(12)
        ciphertext_bytes = self._aesgcm.encrypt(nonce, plaintext, AES_GCM_AAD)

        return {
            "protocol_version": PROTOCOL_VERSION,
            "scheme": self.scheme,
            "payload_id": payload.get("payload_id"),
            "key_id": self.key_id,
            "nonce": b64encode(nonce),
            "ciphertext": b64encode(ciphertext_bytes),
            "created_at": utc_now_iso(),
        }
