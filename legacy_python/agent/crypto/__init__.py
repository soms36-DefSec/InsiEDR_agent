from __future__ import annotations

from typing import Any

from shared.protocol import CRYPTO_SCHEME_HPKE, CRYPTO_SCHEME_AESGCM
from .aesgcm import AESGCMCrypto
from .hpke import HPKECrypto


def create_agent_crypto(config: Any):
    """Factory to instantiate the appropriate cryptographic engine based on AgentConfig."""
    scheme = getattr(config, "encryption_scheme", "")
    server_pub = getattr(config, "server_public_key", None)
    aes_key = getattr(config, "aes_key", None)
    server_key_id = getattr(config, "server_key_id", "default") or "default"

    # Prefer HPKE if scheme is hpke or if server_public_key is provided
    if scheme == CRYPTO_SCHEME_HPKE or server_pub is not None:
        if not server_pub:
            raise ValueError("HPKE encryption selected but server public key is missing")
        return HPKECrypto(server_pub, key_id=server_key_id)

    # Fallback to symmetric AES-GCM for backwards compatibility
    if aes_key:
        return AESGCMCrypto(aes_key)

    raise ValueError("no cryptographic material configured (neither server_public_key nor aes_key provided)")


__all__ = ["AESGCMCrypto", "HPKECrypto", "create_agent_crypto"]
