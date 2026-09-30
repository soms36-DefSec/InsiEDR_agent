use insiedr_core::crypto::aesgcm::AesGcmEngine;
use insiedr_core::protocol::envelope::WireEnvelope;

#[test]
fn generate_cross_verification_envelopes() {
    let test_key = [0x42u8; 32];
    let plaintext = b"{\"verification\": \"rust_to_python_interop_success\", \"score\": 100}";

    // 1. AES-GCM
    let aes = AesGcmEngine::new(&test_key).unwrap();
    let (nonce, cipher) = aes.encrypt(plaintext).unwrap();
    let aes_env = WireEnvelope::new_aesgcm(
        "payload-test-aes".into(),
        "default".into(),
        nonce,
        cipher,
        "2026-09-23T14:15:00Z".into(),
    );

    // 2. Write to scratch file for Python verification
    let scratch_dir = r"C:\Users\SOMS\.gemini\antigravity\brain\d6370041-7fd7-4502-b018-1889f9d157a5\scratch";
    let _ = std::fs::create_dir_all(scratch_dir);

    let aes_json = serde_json::to_string_pretty(&aes_env).unwrap();
    std::fs::write(format!(r"{}\aes_envelope.json", scratch_dir), aes_json).unwrap();
    println!("AES-GCM envelope generated for Python cross-verification.");
}
