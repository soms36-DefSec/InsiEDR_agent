use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};
use std::fmt;

pub const AES_GCM_KEY_LEN: usize = 32;
pub const AES_GCM_AAD: &[u8] = b"insiedr.agent.telemetry.v2";

#[derive(Debug)]
pub enum AesGcmError {
    InvalidKeyLength(usize),
    EncryptionError,
    DecryptionError,
    Base64Error(String),
}

impl std::error::Error for AesGcmError {}

impl fmt::Display for AesGcmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(len) => write!(f, "Invalid AES-GCM key length: {} (expected 32)", len),
            Self::EncryptionError => write!(f, "AES-GCM encryption failed"),
            Self::DecryptionError => write!(f, "AES-GCM decryption failed or authentication tag mismatch"),
            Self::Base64Error(e) => write!(f, "Base64 decode error: {}", e),
        }
    }
}

struct SingleNonce(Option<[u8; NONCE_LEN]>);

impl NonceSequence for SingleNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let nonce_bytes = self.0.take().ok_or(Unspecified)?;
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

use zeroize::Zeroize;

pub struct AesGcmEngine {
    key: [u8; AES_GCM_KEY_LEN],
    rng: SystemRandom,
}

impl Drop for AesGcmEngine {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl AesGcmEngine {
    pub fn new(key_bytes: &[u8]) -> Result<Self, AesGcmError> {
        if key_bytes.len() != AES_GCM_KEY_LEN {
            return Err(AesGcmError::InvalidKeyLength(key_bytes.len()));
        }
        let mut key = [0u8; AES_GCM_KEY_LEN];
        key.copy_from_slice(key_bytes);
        Ok(Self {
            key,
            rng: SystemRandom::new(),
        })
    }

    /// Encrypts plaintext bytes using AES-256-GCM with exact AAD = b"insiedr.agent.telemetry.v2".
    /// Returns URL-safe Base64 encoded (nonce, ciphertext_with_tag).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(String, String), AesGcmError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| AesGcmError::EncryptionError)?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key)
            .map_err(|_| AesGcmError::EncryptionError)?;
        let mut sealing_key = SealingKey::new(unbound_key, SingleNonce(Some(nonce_bytes)));

        let mut in_out = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(Aad::from(AES_GCM_AAD), &mut in_out)
            .map_err(|_| AesGcmError::EncryptionError)?;

        let nonce_b64 = URL_SAFE.encode(nonce_bytes);
        let ciphertext_b64 = URL_SAFE.encode(&in_out);

        Ok((nonce_b64, ciphertext_b64))
    }

    /// Decrypts URL-safe Base64 encoded nonce and ciphertext with verification of AAD and tag.
    pub fn decrypt(&self, nonce_b64: &str, ciphertext_b64: &str) -> Result<Vec<u8>, AesGcmError> {
        let nonce_raw = URL_SAFE
            .decode(nonce_b64.trim())
            .map_err(|e| AesGcmError::Base64Error(e.to_string()))?;
        if nonce_raw.len() != NONCE_LEN {
            return Err(AesGcmError::DecryptionError);
        }
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&nonce_raw);

        let mut in_out = URL_SAFE
            .decode(ciphertext_b64.trim())
            .map_err(|e| AesGcmError::Base64Error(e.to_string()))?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key)
            .map_err(|_| AesGcmError::DecryptionError)?;
        let mut opening_key = OpeningKey::new(unbound_key, SingleNonce(Some(nonce_bytes)));

        let decrypted = opening_key
            .open_in_place(Aad::from(AES_GCM_AAD), &mut in_out)
            .map_err(|_| AesGcmError::DecryptionError)?;

        Ok(decrypted.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let engine = AesGcmEngine::new(&key).unwrap();
        let plaintext = b"{\"message\": \"insiedr telemetry test\"}";

        let (nonce_b64, ciphertext_b64) = engine.encrypt(plaintext).unwrap();
        assert!(!nonce_b64.is_empty());
        assert!(!ciphertext_b64.is_empty());

        let decrypted = engine.decrypt(&nonce_b64, &ciphertext_b64).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }
}

