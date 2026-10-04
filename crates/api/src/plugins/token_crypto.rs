//! Shared token hashing and the pinned runtime's symmetric persistence encoding.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::{AuthError, AuthResult};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
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
    let secret = decryption_key(stored, config)?;
    let ciphertext = if config.managed_secrets.is_some() {
        parse_envelope(stored).map_or(stored, |(_, ciphertext)| ciphertext)
    } else {
        stored
    };
    decrypt(ciphertext, secret)
}

// Callers may use this key only after decrypting and validating the envelope.
// It binds native state proofs to that exact authenticated key version.
pub(in crate::plugins) fn decryption_key<'a>(
    stored: &str,
    config: &'a better_auth_core::AuthConfig,
) -> AuthResult<&'a str> {
    let Some(keys) = &config.managed_secrets else {
        return Ok(config.current_secret());
    };
    if let Some((version, _)) = parse_envelope(stored) {
        return keys.key(version).ok_or_else(|| {
            AuthError::Encryption("Encrypted secret version has been retired".into())
        });
    }
    keys.legacy_secret().ok_or_else(|| {
        AuthError::Encryption("Legacy encrypted data requires an explicit legacy secret".into())
    })
}

fn parse_envelope(stored: &str) -> Option<(u64, &str)> {
    let (version, ciphertext) = stored.strip_prefix("$ba$")?.split_once('$')?;
    // The installed runtime uses parseInt(version, 10): leading whitespace,
    // a plus sign and a numeric prefix are accepted; a negative value is not.
    let version = version.trim_start_matches(better_auth_core::utils::javascript::is_whitespace);
    let (negative, version) = if let Some(version) = version.strip_prefix('-') {
        (true, version)
    } else {
        (false, version.strip_prefix('+').unwrap_or(version))
    };
    let length = version.bytes().take_while(u8::is_ascii_digit).count();
    let version: u64 = version.get(..length)?.parse().ok()?;
    if negative && version != 0 {
        return None;
    }
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
    let mut nonce_bytes = [0u8; 24];
    rand::fill(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plain.as_bytes())
        .map_err(|_error| AuthError::Encryption("token encryption failed".into()))?;
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
        return Err(AuthError::Encryption("Invalid encrypted token".into()));
    }
    let bytes: Vec<u8> = stored
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| {
            let value = std::str::from_utf8(chunk)
                .map_err(|_error| AuthError::Encryption("Invalid encrypted token".into()))?;
            u8::from_str_radix(value, 16)
                .map_err(|_error| AuthError::Encryption("Invalid encrypted token".into()))
        })
        .collect::<AuthResult<_>>()?;
    let (nonce, ciphertext) = bytes
        .split_at_checked(24)
        .ok_or_else(|| AuthError::Encryption("Invalid encrypted token".into()))?;
    let cipher = XChaCha20Poly1305::new(&Sha256::digest(secret.as_bytes()));
    let plain = cipher
        .decrypt(
            &XNonce::try_from(nonce)
                .map_err(|_error| AuthError::Encryption("Invalid encrypted token".into()))?,
            ciphertext,
        )
        .map_err(|_error| AuthError::Encryption("token decryption failed".into()))?;
    String::from_utf8(plain)
        .map_err(|_error| AuthError::Encryption("Invalid encrypted token".into()))
}
