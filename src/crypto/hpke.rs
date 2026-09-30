use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::error::Unspecified;
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use std::fmt;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

pub const HPKE_KDF_SALT: &[u8] = b"insiedr.hpke.v1.kem.salt";
pub const HPKE_KDF_INFO_PREFIX: &[u8] = b"insiedr.hpke.v1.aes256gcm";
pub const HPKE_AAD: &[u8] = b"insiedr.hpke.telemetry.v2";

#[derive(Debug)]
pub enum HpkeError {
    InvalidKeyLength,
    InvalidPublicKey,
    KeyDerivationError,
    EncryptionError,
    DecryptionError,
    Base64Error(String),
}

impl std::error::Error for HpkeError {}

impl fmt::Display for HpkeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength => write!(f, "Invalid key length for X25519 (expected 32 bytes)"),
            Self::InvalidPublicKey => write!(f, "Invalid X25519 public key"),
            Self::KeyDerivationError => write!(f, "HKDF-SHA256 key derivation failed"),
            Self::EncryptionError => write!(f, "HPKE AEAD encryption failed"),
            Self::DecryptionError => write!(f, "HPKE AEAD decryption or authentication tag mismatch"),
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

#[allow(dead_code)]
struct HkdfKey(pub [u8; 32]);

impl hkdf::KeyType for HkdfKey {
    fn len(&self) -> usize {
        32
    }
}

pub struct HpkeEngine {
    server_public_key: X25519PublicKey,
    server_public_key_bytes: [u8; 32],
    key_id: String,
    rng: SystemRandom,
}

impl HpkeEngine {
    pub fn new(server_pub_bytes: &[u8], key_id: &str) -> Result<Self, HpkeError> {
        if server_pub_bytes.len() != 32 {
            return Err(HpkeError::InvalidKeyLength);
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(server_pub_bytes);
        let server_public_key = X25519PublicKey::from(key_arr);

        Ok(Self {
            server_public_key,
            server_public_key_bytes: key_arr,
            key_id: key_id.to_string(),
            rng: SystemRandom::new(),
        })
    }

    /// Derives symmetric key using HKDF-SHA256 matching Python server:
    /// info = b"insiedr.hpke.v1.aes256gcm" + sender_pub + receiver_pub + key_id
    fn derive_symmetric_key(
        shared_secret: &[u8; 32],
        sender_pub: &[u8; 32],
        receiver_pub: &[u8; 32],
        key_id: &str,
    ) -> Result<[u8; 32], HpkeError> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HPKE_KDF_SALT);
        let prk = salt.extract(shared_secret);

        let mut info = Vec::with_capacity(HPKE_KDF_INFO_PREFIX.len() + 32 + 32 + key_id.len());
        info.extend_from_slice(HPKE_KDF_INFO_PREFIX);
        info.extend_from_slice(sender_pub);
        info.extend_from_slice(receiver_pub);
        info.extend_from_slice(key_id.as_bytes());

        let info_slice: &[&[u8]] = &[&info];
        let okm = prk
            .expand(info_slice, HkdfKey([0u8; 32]))
            .map_err(|_| HpkeError::KeyDerivationError)?;

        let mut derived = [0u8; 32];
        okm.fill(&mut derived)
            .map_err(|_| HpkeError::KeyDerivationError)?;

        Ok(derived)
    }

    /// Encrypts telemetry with HPKE (X25519-HKDF-AES256GCM).
    /// Returns (encapped_key_b64, nonce_b64, ciphertext_b64).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(String, String, String), HpkeError> {
        use zeroize::Zeroize;

        // 1. Generate ephemeral private key and public key
        let mut ephemeral_priv_bytes = [0u8; 32];
        self.rng
            .fill(&mut ephemeral_priv_bytes)
            .map_err(|_| HpkeError::EncryptionError)?;
        let ephemeral_secret = X25519StaticSecret::from(ephemeral_priv_bytes);
        ephemeral_priv_bytes.zeroize();
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        let ephemeral_pub_bytes = *ephemeral_public.as_bytes();

        // 2. Diffie-Hellman Key Exchange with Server Public Key
        let shared_secret = ephemeral_secret.diffie_hellman(&self.server_public_key);

        // 3. Derive 32-byte AES-GCM Key via HKDF-SHA256
        let mut derived_aes_key = Self::derive_symmetric_key(
            shared_secret.as_bytes(),
            &ephemeral_pub_bytes,
            &self.server_public_key_bytes,
            &self.key_id,
        )?;

        // 4. Generate 12-byte random nonce
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| HpkeError::EncryptionError)?;

        // 5. Encrypt with AES-256-GCM using AAD = b"insiedr.hpke.telemetry.v2"
        let unbound_key = UnboundKey::new(&AES_256_GCM, &derived_aes_key)
            .map_err(|_| HpkeError::EncryptionError)?;
        derived_aes_key.zeroize();
        let mut sealing_key = SealingKey::new(unbound_key, SingleNonce(Some(nonce_bytes)));

        let mut in_out = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(Aad::from(HPKE_AAD), &mut in_out)
            .map_err(|_| HpkeError::EncryptionError)?;

        let encapped_key_b64 = URL_SAFE.encode(ephemeral_pub_bytes);
        let nonce_b64 = URL_SAFE.encode(nonce_bytes);
        let ciphertext_b64 = URL_SAFE.encode(&in_out);

        Ok((encapped_key_b64, nonce_b64, ciphertext_b64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hpke_encryption_structure() {
        let server_pub = [0x55u8; 32];
        let engine = HpkeEngine::new(&server_pub, "test-key-id").unwrap();
        let plaintext = b"{\"user\": \"employee1\", \"event\": \"file_access\"}";

        let (encapped_b64, nonce_b64, cipher_b64) = engine.encrypt(plaintext).unwrap();
        assert!(!encapped_b64.is_empty());
        assert!(!nonce_b64.is_empty());
        assert!(!cipher_b64.is_empty());
    }
}

