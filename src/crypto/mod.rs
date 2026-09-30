pub mod aesgcm;
pub mod hpke;
pub mod dpapi;

use zeroize::Zeroize;

/// Secure memory buffer that automatically wipes itself upon drop.
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretBuffer(pub Vec<u8>);

impl SecretBuffer {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
