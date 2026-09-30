use std::fmt;
use std::ptr;
use windows::core::PCWSTR;
use windows::Win32::Foundation::LocalFree;
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
    CRYPT_INTEGER_BLOB,
};

#[derive(Debug)]
pub enum DpapiError {
    ProtectFailed(String),
    UnprotectFailed(String),
}

impl std::fmt::Display for DpapiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtectFailed(msg) => write!(f, "DPAPI CryptProtectData failed: {}", msg),
            Self::UnprotectFailed(msg) => write!(f, "DPAPI CryptUnprotectData failed: {}", msg),
        }
    }
}

impl std::error::Error for DpapiError {}

/// Encrypts bytes using Windows DPAPI machine master key.
/// Only processes with LocalSystem / Administrative access on this machine can decrypt.
pub fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        CryptProtectData(
            &in_blob,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
        .map_err(|e| DpapiError::ProtectFailed(e.to_string()))?;

        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let result = slice.to_vec();

        LocalFree(windows::Win32::Foundation::HLOCAL(out_blob.pbData as _));
        Ok(result)
    }
}

/// Decrypts bytes previously protected by DPAPI on this machine.
pub fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: ciphertext.len() as u32,
            pbData: ciphertext.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        CryptUnprotectData(
            &in_blob,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
        .map_err(|e| DpapiError::UnprotectFailed(e.to_string()))?;

        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let result = slice.to_vec();

        LocalFree(windows::Win32::Foundation::HLOCAL(out_blob.pbData as _));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpapi_machine_roundtrip() {
        let secret_data = b"InsiEDR-Super-Secret-Key-12345";
        let protected = dpapi_protect(secret_data).expect("DPAPI protect failed");
        assert!(!protected.is_empty());
        assert_ne!(&protected[..], secret_data);

        let unprotected = dpapi_unprotect(&protected).expect("DPAPI unprotect failed");
        assert_eq!(&unprotected[..], secret_data);
    }
}

