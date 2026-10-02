//! Shared token hashing and the pinned runtime's symmetric persistence encoding.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthError, AuthResult};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use sha2::{Digest, Sha256};
use std::fmt::Write;

/// Encrypt persistence data with the configured current version.
pub(in crate::plugins) fn encrypt_with_config(
    plain: &str,
    config: &better_auth_core::AuthConfig,
) -> AuthResult<String> {
    let encrypted = encrypt(plain, config.current_secret())?;
    match &config.managed_secrets {
        Some(keys) => Ok(format!("$ba${}${encrypted}", keys.current_version())),
        None => Ok(encrypted),
    }
}

/// Resolve a versioned reader without trying unrelated keys. Bare persistence
/// data requires an explicit legacy key in managed mode.
pub(in crate::plugins) fn decrypt_with_config(
    stored: &str,
    config: &better_auth_core::AuthConfig,
) -> AuthResult<String> {
    let Some(keys) = &config.managed_secrets else {
        return decrypt(stored, config.current_secret());
    };
    if let Some((version, ciphertext)) = parse_envelope(stored) {
        let key = keys.key(version).ok_or_else(|| AuthError::internal("Encrypted secret version has been retired"))?;
        return decrypt(ciphertext, key);
    }
    let legacy = keys.legacy_secret().ok_or_else(|| AuthError::internal("Legacy encrypted data requires an explicit legacy secret"))?;
    decrypt(stored, legacy)
}

fn parse_envelope(stored: &str) -> Option<(u64, &str)> {
    let (version, ciphertext) = stored.strip_prefix("$ba$")?.split_once('$')?;
    // The installed runtime uses parseInt(version, 10): leading whitespace,
    // a plus sign and a numeric prefix are accepted; a negative value is not.
    let version = version.trim_start().strip_prefix('+').unwrap_or(version.trim_start());
    let length = version.bytes().take_while(u8::is_ascii_digit).count();
    let version = version.get(..length)?.parse().ok()?;
    Some((version, ciphertext))
}

pub(in crate::plugins) fn hash_token(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

// Upstream symmetricEncrypt uses SHA256(secret), XChaCha20-Poly1305's managed
// 24-byte nonce followed by ciphertext/tag, serialized as lowercase hexadecimal.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) fn encrypt(plain: &str, secret: &str) -> AuthResult<String> {
    let cipher = XChaCha20Poly1305::new(&Sha256::digest(secret.as_bytes()));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plain.as_bytes())
        .map_err(|_error| AuthError::internal("token encryption failed"))?;
    let bytes = nonce.iter().copied().chain(ciphertext);
    Ok(bytes.fold(String::new(), |mut output, byte| {
        _ = write!(output, "{byte:02x}");
        output
    }))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) fn decrypt(stored: &str, secret: &str) -> AuthResult<String> {
    if !stored.len().is_multiple_of(2) {
        return Err(AuthError::internal("Invalid encrypted token"));
    }
    let bytes: Vec<u8> = stored
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| {
            let value = std::str::from_utf8(chunk)
                .map_err(|_error| AuthError::internal("Invalid encrypted token"))?;
            u8::from_str_radix(value, 16)
                .map_err(|_error| AuthError::internal("Invalid encrypted token"))
        })
        .collect::<AuthResult<_>>()?;
    let (nonce, ciphertext) = bytes
        .split_at_checked(24)
        .ok_or_else(|| AuthError::internal("Invalid encrypted token"))?;
    let cipher = XChaCha20Poly1305::new(&Sha256::digest(secret.as_bytes()));
    let plain = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_error| AuthError::internal("token decryption failed"))?;
    String::from_utf8(plain).map_err(|_error| AuthError::internal("Invalid encrypted token"))
}
