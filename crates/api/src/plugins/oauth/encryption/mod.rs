//! AES-256-GCM encryption utilities for OAuth tokens.
//!
//! When `AccountConfig::encrypt_oauth_tokens` is `true`, access tokens,
//! refresh tokens, and ID tokens are encrypted before being persisted and
//! decrypted transparently on read.

#[cfg(test)]
mod tests;

use better_auth_core::AuthError;

/// A set of OAuth tokens (access, refresh, id) after conditional encryption.
pub struct EncryptedTokenSet {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
}

impl std::fmt::Debug for EncryptedTokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedTokenSet").finish_non_exhaustive()
    }
}

/// Encrypt a plaintext string using AES-256-GCM.
///
/// Returns a base64-encoded string of `nonce || ciphertext`.
///
/// # Errors
///
/// Returns an error if token encryption fails.
pub fn encrypt_token(plaintext: &str, secret: &str) -> Result<String, AuthError> {
    crate::plugins::token_crypto::encrypt(plaintext, secret)
}

/// Source recognizes even-length hexadecimal (and versioned `$ba$` envelopes)
/// as ciphertext. Other strings, including old plaintext tokens, pass through.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub fn decrypt_token(stored: &str, secret: &str) -> Result<String, AuthError> {
    let likely_encrypted = stored.starts_with("$ba$")
        || (!stored.is_empty()
            && stored.len().is_multiple_of(2)
            && stored.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if !likely_encrypted {
        return Ok(stored.to_owned());
    }
    crate::plugins::token_crypto::decrypt(stored, secret)
}

/// Conditionally encrypt a token value. Returns the original value when
/// encryption is disabled, or the encrypted value when enabled.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub fn maybe_encrypt(
    value: Option<String>,
    encrypt: bool,
    secret: &str,
) -> Result<Option<String>, AuthError> {
    match (value, encrypt) {
        (Some(v), true) if !v.is_empty() => Ok(Some(encrypt_token(&v, secret)?)),
        (v, _) => Ok(v),
    }
}

/// Conditionally decrypt a token value. Returns the original value when
/// encryption is disabled, or the decrypted value when enabled.
///
/// # Errors
///
/// Propagates decryption errors when token encryption is enabled.
pub fn maybe_decrypt(
    value: Option<&str>,
    encrypt: bool,
    secret: &str,
) -> Result<Option<String>, AuthError> {
    match (value, encrypt) {
        (Some(v), true) => decrypt_token(v, secret).map(Some),
        (Some(v), false) => Ok(Some(v.to_owned())),
        (None, _) => Ok(None),
    }
}

/// Read `encrypt_oauth_tokens` and `secret` from the auth context and
/// conditionally encrypt a full set of OAuth tokens in one call.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub fn encrypt_token_set(
    ctx: &better_auth_core::AuthContext<impl better_auth_core::AuthSchema>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
) -> Result<EncryptedTokenSet, AuthError> {
    let encrypt = ctx.config.account.encrypt_oauth_tokens;
    let secret = &ctx.config.secret;
    Ok(EncryptedTokenSet {
        access_token: maybe_encrypt(access_token, encrypt, secret)?,
        refresh_token: maybe_encrypt(refresh_token, encrypt, secret)?,
        // Source persists provider ID tokens as returned, independently of this option.
        id_token,
    })
}
