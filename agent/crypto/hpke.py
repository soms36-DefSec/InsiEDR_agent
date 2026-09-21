from __future__ import annotations

import os
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from shared.crypto_utils import (
    b64encode,
    load_x25519_public_key,
    derive_hpke_shared_key,
    public_key_fingerprint,
)
from shared.protocol import (
    CRYPTO_SCHEME_HPKE,
    PROTOCOL_VERSION,
    canonical_json_bytes,
    utc_now_iso,
)

HPKE_AAD = b"insiedr.hpke.telemetry.v2"


class HPKECrypto:
    """Hybrid Public-Key Encryption (HPKE) engine for endpoint telemetry.
    Adheres to RFC 9180 DHKEM(X25519, HKDF-SHA256) + AES-256-GCM.

    The endpoint agent holds ONLY the Server's Public Key. For every payload:
    1. Generates single-use ephemeral X25519 keypair (sk_E, pk_E).
    2. Performs ECDH scalar multiplication: dh = sk_E * pk_Server.
    3. Derives 256-bit symmetric key using HKDF-SHA256.
    4. Encrypts canonical JSON payload via AES-256-GCM with fresh 12-byte nonce.
    5. Returns wire envelope containing ephemeral public key ('encapped_key'),
       'nonce', 'ciphertext' (with AEAD tag), 'key_id', and metadata.
    """
    scheme = CRYPTO_SCHEME_HPKE

    def __init__(
        self,
        server_public_key: bytes | str | x25519.X25519PublicKey,
        key_id: str = "default",
    ) -> None:
        self.server_public_key = load_x25519_public_key(server_public_key)
        self.key_id = str(key_id or "default")
        self._server_pub_bytes = self.server_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.fingerprint = public_key_fingerprint(self._server_pub_bytes)

    def encrypt_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        plaintext = canonical_json_bytes(payload)

        # Generate ephemeral sender keypair (PFS guarantee)
        ephemeral_priv = x25519.X25519PrivateKey.generate()
        ephemeral_pub = ephemeral_priv.public_key()
        ephemeral_pub_bytes = ephemeral_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

        # Compute ECDH and derive key
        shared_secret = ephemeral_priv.exchange(self.server_public_key)
        derived_key = derive_hpke_shared_key(
            shared_secret=shared_secret,
            sender_pub=ephemeral_pub_bytes,
            receiver_pub=self._server_pub_bytes,
            key_id=self.key_id,
        )

        # Encrypt with AES-256-GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(derived_key)
        ciphertext_bytes = aesgcm.encrypt(nonce, plaintext, HPKE_AAD)

        return {
            "protocol_version": PROTOCOL_VERSION,
            "scheme": self.scheme,
            "payload_id": payload.get("payload_id"),
            "key_id": self.key_id,
            "encapped_key": b64encode(ephemeral_pub_bytes),
            "nonce": b64encode(nonce),
            "ciphertext": b64encode(ciphertext_bytes),
            "created_at": utc_now_iso(),
        }
