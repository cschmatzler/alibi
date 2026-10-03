//! Versioned XChaCha20-Poly1305 persistence encryption for OAuth tokens.
//!
//! When `AccountConfig::encrypt_oauth_tokens` is `true`, access tokens,
//! refresh tokens, and ID tokens are encrypted before being persisted and
//! decrypted transparently on read.

use better_auth_core::{AuthConfig, AuthError};

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

/// Encrypt a plaintext string with a single persistence key.
///
/// Returns hexadecimal nonce/ciphertext. Use [`encrypt_token_with_config`] to
/// write a managed key version.
///
/// # Errors
/// Returns an error if token encryption fails.
pub fn encrypt_token(plaintext: &str, secret: &str) -> Result<String, AuthError> {
    encrypt_token_with_config(plaintext, &AuthConfig::new(secret))
}

/// Decrypt a token with a single persistence key, passing through plaintext.
///
/// Use [`decrypt_token_with_config`] to read managed or legacy key versions.
///
/// # Errors
/// Returns an error if an encrypted token cannot be authenticated or decoded.
pub fn decrypt_token(stored: &str, secret: &str) -> Result<String, AuthError> {
    decrypt_token_with_config(stored, &AuthConfig::new(secret))
}

/// Conditionally encrypt a token with a single persistence key.
///
/// # Errors
/// Returns an error if token encryption fails.
pub fn maybe_encrypt(
    value: Option<String>,
    encrypt: bool,
    secret: &str,
) -> Result<Option<String>, AuthError> {
    maybe_encrypt_with_config(value, encrypt, &AuthConfig::new(secret))
}

/// Conditionally decrypt a token with a single persistence key.
///
/// # Errors
/// Returns an error if an encrypted token cannot be authenticated or decoded.
pub fn maybe_decrypt(
    value: Option<&str>,
    encrypt: bool,
    secret: &str,
) -> Result<Option<String>, AuthError> {
    maybe_decrypt_with_config(value, encrypt, &AuthConfig::new(secret))
}

/// Encrypt a plaintext string with the current configured persistence key.
///
/// Returns hexadecimal nonce/ciphertext, inside a versioned envelope in managed mode.
///
/// # Errors
///
/// Returns an error if token encryption fails.
pub fn encrypt_token_with_config(
    plaintext: &str,
    secret: &better_auth_core::AuthConfig,
) -> Result<String, AuthError> {
    crate::plugins::token_crypto::encrypt_with_config(plaintext, secret)
}

/// Source recognizes even-length hexadecimal (and versioned `$ba$` envelopes)
/// as ciphertext. Other strings, including old plaintext tokens, pass through.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub fn decrypt_token_with_config(
    stored: &str,
    secret: &better_auth_core::AuthConfig,
) -> Result<String, AuthError> {
    let likely_encrypted = stored.starts_with("$ba$")
        || (!stored.is_empty()
            && stored.len().is_multiple_of(2)
            && stored.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if !likely_encrypted {
        return Ok(stored.to_owned());
    }
    crate::plugins::token_crypto::decrypt_with_config(stored, secret)
}

/// Conditionally encrypt a token value. Returns the original value when
/// encryption is disabled, or the encrypted value when enabled.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub fn maybe_encrypt_with_config(
    value: Option<String>,
    encrypt: bool,
    secret: &better_auth_core::AuthConfig,
) -> Result<Option<String>, AuthError> {
    match (value, encrypt) {
        (Some(v), true) if !v.is_empty() => Ok(Some(encrypt_token_with_config(&v, secret)?)),
        (v, _) => Ok(v),
    }
}

/// Conditionally decrypt a token value. Returns the original value when
/// encryption is disabled, or the decrypted value when enabled.
///
/// # Errors
///
/// Propagates decryption errors when token encryption is enabled.
pub fn maybe_decrypt_with_config(
    value: Option<&str>,
    encrypt: bool,
    secret: &better_auth_core::AuthConfig,
) -> Result<Option<String>, AuthError> {
    match (value, encrypt) {
        (Some(v), true) => decrypt_token_with_config(v, secret).map(Some),
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
    let secret = &ctx.config;
    Ok(EncryptedTokenSet {
        access_token: maybe_encrypt_with_config(access_token, encrypt, secret)?,
        refresh_token: maybe_encrypt_with_config(refresh_token, encrypt, secret)?,
        // Source persists provider ID tokens as returned, independently of this option.
        id_token,
    })
}

pub(super) fn provider_token_nulls(
    tokens: &super::providers::OAuthTokenSet,
    preserve_raw: bool,
) -> [bool; 3] {
    ["access_token", "refresh_token", "id_token"].map(|field| {
        preserve_raw
            && tokens
                .raw
                .as_ref()
                .and_then(|raw| raw.get(field))
                .is_some_and(serde_json::Value::is_null)
    })
}

/// Persist published grant scalars through the actual adapter's TEXT affinity.
/// Typed application callbacks and providers without the source policy retain
/// the native token interface. Source's encryption rejects truthy nonstrings.
pub(super) async fn encrypt_provider_token_set(
    ctx: &better_auth_core::AuthContext<impl better_auth_core::AuthSchema>,
    tokens: &super::providers::OAuthTokenSet,
    preserve_raw: bool,
) -> Result<EncryptedTokenSet, AuthError> {
    let Some(raw) = tokens.raw.as_ref().filter(|_| preserve_raw) else {
        return encrypt_token_set(
            ctx,
            tokens.access_token.clone(),
            tokens.refresh_token.clone(),
            tokens.id_token.clone(),
        );
    };
    // An invalid JavaScript Date is present, rather than an omitted expiry.
    // Typed Rust dates cannot carry it: reject it at persistence after userinfo,
    // instead of silently admitting an account with no expiry.
    for field in ["expires_in", "refresh_token_expires_in"] {
        if raw.get(field).is_some_and(|value| {
            super::providers::remaining_profile::truthy(value)
                && super::providers::remaining_profile::grant_expiry(value, true).is_none()
        }) {
            return Err(AuthError::internal("Invalid provider token expiry"));
        }
    }
    let mut result = EncryptedTokenSet {
        access_token: None,
        refresh_token: None,
        id_token: None,
    };
    for (field, target, encrypted) in [
        (
            "access_token",
            &mut result.access_token,
            ctx.config.account.encrypt_oauth_tokens,
        ),
        (
            "refresh_token",
            &mut result.refresh_token,
            ctx.config.account.encrypt_oauth_tokens,
        ),
        ("id_token", &mut result.id_token, false),
    ] {
        let Some(value) = raw.get(field) else {
            continue;
        };
        if encrypted && super::providers::remaining_profile::truthy(value) {
            let value = value.as_str().ok_or_else(|| {
                AuthError::internal("Provider token encryption requires a string")
            })?;
            *target = Some(encrypt_token_with_config(value, &ctx.config)?);
        } else {
            *target = ctx.database.provider_token_text(value).await?;
        }
    }
    Ok(result)
}

// LCOV_EXCL_START
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
        let token = "plain-token".to_owned();
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
// LCOV_EXCL_STOP
