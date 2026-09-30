//! Shared token hashing and the pinned runtime's symmetric persistence encoding.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthError, AuthResult};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use sha2::{Digest, Sha256};

pub(crate) fn hash_token(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

// Upstream symmetricEncrypt uses SHA256(secret), XChaCha20-Poly1305's managed
// 24-byte nonce followed by ciphertext/tag, serialized as lowercase hexadecimal.
pub(crate) fn encrypt(plain: &str, secret: &str) -> AuthResult<String> {
    let cipher = XChaCha20Poly1305::new(&Sha256::digest(secret.as_bytes()));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plain.as_bytes())
        .map_err(|_| AuthError::internal("OTP encryption failed"))?;
    let bytes = nonce.iter().copied().chain(ciphertext);
    Ok(bytes.map(|byte| format!("{byte:02x}")).collect())
}

pub(crate) fn decrypt(stored: &str, secret: &str) -> AuthResult<String> {
    if !stored.len().is_multiple_of(2) {
        return Err(AuthError::internal("Invalid encrypted OTP"));
    }
    let bytes: Vec<u8> = stored
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| {
            let value = std::str::from_utf8(chunk)
                .map_err(|_| AuthError::internal("Invalid encrypted OTP"))?;
            u8::from_str_radix(value, 16).map_err(|_| AuthError::internal("Invalid encrypted OTP"))
        })
        .collect::<AuthResult<_>>()?;
    let (nonce, ciphertext) = bytes
        .split_at_checked(24)
        .ok_or_else(|| AuthError::internal("Invalid encrypted OTP"))?;
    let cipher = XChaCha20Poly1305::new(&Sha256::digest(secret.as_bytes()));
    let plain = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| AuthError::internal("OTP decryption failed"))?;
    String::from_utf8(plain).map_err(|_| AuthError::internal("Invalid encrypted OTP"))
}
