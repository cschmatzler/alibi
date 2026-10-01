//! Pinned symmetric persistence encoding and OAuth token truthiness.
//!
//! When `AccountConfig::encrypt_oauth_tokens` is `true`, access tokens,
//! and refresh tokens are encrypted before being persisted and
//! decrypted transparently on read. ID tokens remain provider plaintext.

use better_auth_core::AuthError;

/// Persist using the pinned single-secret symmetric encoding:
/// SHA-256(secret), XChaCha20-Poly1305, 24-byte nonce, lowercase hexadecimal.
pub fn encrypt_token(plaintext: &str, secret: &str) -> Result<String, AuthError> {
    crate::plugins::token_crypto::encrypt(plaintext, secret)
}

/// Source recognizes even-length hexadecimal (and versioned `$ba$` envelopes)
/// as ciphertext. Other strings, including old plaintext tokens, pass through.
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
pub fn maybe_decrypt(
    value: Option<&str>,
    encrypt: bool,
    secret: &str,
) -> Result<Option<String>, AuthError> {
    match (value, encrypt) {
        (Some(v), true) => decrypt_token(v, secret).map(Some),
        (Some(v), false) => Ok(Some(v.to_string())),
        (None, _) => Ok(None),
    }
}

/// A set of OAuth tokens (access, refresh, id) after conditional encryption.
pub struct EncryptedTokenSet {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
}

/// Read `encrypt_oauth_tokens` and `secret` from the auth context and
/// conditionally encrypt a full set of OAuth tokens in one call.
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

#[cfg(test)]
mod tests {
    use super::*;

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/utils.ts; adapted to the Rust OAuth token encryption helpers.
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secret = "a]vt!MFX8H-e!4igKa5)Tu.{ec:2$z%n";
        let plaintext = "ya29.a0AfH6SMBx-some-access-token";

        let encrypted = encrypt_token(plaintext, secret).unwrap();
        assert_ne!(encrypted, plaintext);

        let decrypted = decrypt_token(&encrypted, secret).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/utils.ts; adapted to the Rust OAuth token encryption helpers.
    #[test]
    fn test_maybe_encrypt_none() {
        let result = maybe_encrypt(None, true, "secret-key-that-is-32-chars-long").unwrap();
        assert!(result.is_none());
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/utils.ts; adapted to the Rust OAuth token encryption helpers.
    #[test]
    fn test_maybe_encrypt_disabled() {
        let token = "plain-token".to_string();
        let result = maybe_encrypt(Some(token.clone()), false, "secret").unwrap();
        assert_eq!(result, Some(token));
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/utils.ts; adapted to the Rust OAuth token encryption helpers.
    #[test]
    fn test_maybe_decrypt_none() {
        let result = maybe_decrypt(None, true, "secret-key-that-is-32-chars-long").unwrap();
        assert!(result.is_none());
    }
}
