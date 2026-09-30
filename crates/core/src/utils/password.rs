//! Shared password utilities for hashing, verification, validation and
//! session-cookie construction.
//!
//! Lives in `better-auth-core` so that any crate in the workspace (plugins,
//! integrations, etc.) can reuse these primitives without duplicating logic.

use std::sync::Arc;

use async_trait::async_trait;
use rand::{RngCore, rngs::OsRng};
use serde::Serialize;
use unicode_normalization::UnicodeNormalization;

use crate::error::{AuthError, AuthResult};
use crate::plugin::AuthContext;
use crate::schema::AuthSchema;
use crate::types::UpdateUser;

// ---------------------------------------------------------------------------
// PasswordHasher trait
// ---------------------------------------------------------------------------

/// Custom password hasher trait for pluggable password hashing strategies.
///
/// When provided in plugin configs, this overrides the default scrypt-based
/// password hashing.
#[async_trait]
pub trait PasswordHasher: Send + Sync {
    /// Hash a plaintext password and return the hash string.
    async fn hash(&self, password: &str) -> AuthResult<String>;
    /// Verify a password against a hash string. Returns `true` if the password matches.
    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool>;
}

/// The pinned Better Auth password format: hexadecimal salt and scrypt key.
#[derive(Clone, Default)]
pub struct ScryptHasher;

fn derive_scrypt(password: &str, salt: &str) -> AuthResult<[u8; 64]> {
    let params = scrypt::Params::new(14, 16, 1, 64)
        .map_err(|error| AuthError::PasswordHash(error.to_string()))?;
    let password = password.nfkc().collect::<String>();
    let mut key = [0; 64];
    // Upstream passes the hexadecimal salt STRING to scrypt, not its decoded bytes.
    scrypt::scrypt(password.as_bytes(), salt.as_bytes(), &params, &mut key)
        .map_err(|error| AuthError::PasswordHash(error.to_string()))?;
    Ok(key)
}

fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[async_trait]
impl PasswordHasher for ScryptHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        let password = password.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut salt = [0; 16];
            OsRng.fill_bytes(&mut salt);
            let salt = hexadecimal(&salt);
            let key = derive_scrypt(&password, &salt)?;
            Ok(format!("{salt}:{}", hexadecimal(&key)))
        })
        .await
        .map_err(|error| AuthError::PasswordHash(error.to_string()))?
    }

    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        let mut parts = hash.split(':');
        let salt = parts
            .next()
            .filter(|salt| !salt.is_empty())
            .ok_or_else(|| AuthError::PasswordHash("Invalid password hash".into()))?
            .to_owned();
        let expected = parts
            .next()
            .filter(|key| !key.is_empty())
            .ok_or_else(|| AuthError::PasswordHash("Invalid password hash".into()))?
            .to_owned();
        let password = password.to_owned();
        tokio::task::spawn_blocking(move || {
            let actual = hexadecimal(&derive_scrypt(&password, &salt)?);
            Ok(actual.len() == expected.len()
                && actual
                    .bytes()
                    .zip(expected.bytes())
                    .fold(0u8, |different, (left, right)| different | (left ^ right))
                    == 0)
        })
        .await
        .map_err(|error| AuthError::PasswordHash(error.to_string()))?
    }
}

// ---------------------------------------------------------------------------
// hash / verify helpers
// ---------------------------------------------------------------------------

/// Hash `password` using the custom `hasher` (if provided) or the default
/// scrypt algorithm and NFKC normalization.
pub async fn hash_password(
    hasher: Option<&Arc<dyn PasswordHasher>>,
    password: &str,
) -> AuthResult<String> {
    if let Some(hasher) = hasher {
        return hasher.hash(password).await;
    }

    ScryptHasher.hash(password).await
}

/// Verify `password` against `hash` using the custom `hasher` (if provided) or
/// the default scrypt algorithm. Returns `Ok(())` on match, or
/// `Err(AuthError::InvalidCredentials)` on mismatch.
pub async fn verify_password(
    hasher: Option<&Arc<dyn PasswordHasher>>,
    password: &str,
    hash: &str,
) -> AuthResult<()> {
    if let Some(hasher) = hasher {
        return hasher.verify(hash, password).await.and_then(|valid| {
            if valid {
                Ok(())
            } else {
                Err(AuthError::InvalidCredentials)
            }
        });
    }

    if ScryptHasher.verify(hash, password).await? {
        Ok(())
    } else {
        Err(AuthError::InvalidCredentials)
    }
}

// ---------------------------------------------------------------------------
// Password validation
// ---------------------------------------------------------------------------

/// Validate `password` against both the plugin-level length limits and the
/// global `PasswordConfig` strength rules.  Performs min-length, max-length,
/// uppercase, lowercase, digit and special-character checks.
pub fn validate_password(
    password: &str,
    min_length: usize,
    max_length: usize,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthResult<()> {
    let config = &ctx.config.password;

    let length = password.encode_utf16().count();
    if length < min_length {
        let _ = config;
        return Err(AuthError::bad_request("Password too short"));
    }

    if length > max_length {
        return Err(AuthError::bad_request("Password too long"));
    }

    if config.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return Err(AuthError::bad_request(
            "Password must contain at least one uppercase letter",
        ));
    }

    if config.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        return Err(AuthError::bad_request(
            "Password must contain at least one lowercase letter",
        ));
    }

    if config.require_numbers && !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(AuthError::bad_request(
            "Password must contain at least one number",
        ));
    }

    if config.require_special
        && !password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
    {
        return Err(AuthError::bad_request(
            "Password must contain at least one special character",
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Serialisation helper
// ---------------------------------------------------------------------------

/// Serialize any `Serialize`-able value to `serde_json::Value`, converting
/// errors to `AuthError::internal`.
pub fn serialize_to_value(value: &impl Serialize) -> AuthResult<serde_json::Value> {
    serde_json::to_value(value)
        .map_err(|e| AuthError::internal(format!("Failed to serialize value: {}", e)))
}

// ---------------------------------------------------------------------------
// UpdateUser helper
// ---------------------------------------------------------------------------

/// Build an `UpdateUser` that only changes the `metadata` field.
pub fn update_user_metadata(metadata: serde_json::Value) -> UpdateUser {
    UpdateUser {
        metadata: Some(metadata),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scrypt_verifies_pinned_runtime_vectors_and_normalizes_unicode() {
        // Produced with pinned @better-auth/utils/password.node.mjs parameters.
        let plain = "00112233445566778899aabbccddeeff:73122e887cfc14f91396cdef78dfe4b9dec28d459037601c4904cedba5a637ab97b39b40c236df5d42881d0109ca8cf0f85e39dbaba2911c190915bd8f30fe85";
        let unicode = "00112233445566778899aabbccddeeff:d891432b268618420fb652f0515c0fcf5ae943c484f883e35d18a14c683ded87c0e469ab0cbdca84868fdb3680e7059018c0a6f90060eb0d866934dacfeae6a5";
        assert!(verify_password(None, "password123", plain).await.is_ok());
        assert!(matches!(
            verify_password(None, "incorrect", plain).await,
            Err(AuthError::InvalidCredentials)
        ));
        assert!(verify_password(None, "Ａuth-é-🔒", unicode).await.is_ok());
        assert!(
            verify_password(None, "Auth-e\u{301}-🔒", unicode)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn scrypt_uses_random_hex_salt_and_rejects_malformed_or_changed_hashes() {
        let first = hash_password(None, "password123").await.expect("hash");
        let second = hash_password(None, "password123").await.expect("hash");
        assert_ne!(first, second);
        assert_eq!(first.len(), 32 + 1 + 128);
        assert!(
            first
                .split(':')
                .all(|part| part.bytes().all(|byte| byte.is_ascii_hexdigit()))
        );
        assert!(verify_password(None, "password123", &first).await.is_ok());
        assert!(matches!(
            verify_password(None, "password123", "bad").await,
            Err(AuthError::PasswordHash(_))
        ));
        assert!(matches!(
            verify_password(None, "password123", ":key").await,
            Err(AuthError::PasswordHash(_))
        ));
        assert!(matches!(
            verify_password(None, "password123", "salt:").await,
            Err(AuthError::PasswordHash(_))
        ));
        let altered = format!("{}0", first);
        assert!(matches!(
            verify_password(None, "password123", &altered).await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn password_length_matches_utf16_code_units() {
        let context = crate::AuthContext::new(
            Arc::new(crate::AuthConfig::new(
                "password-tests-only-minimum-32-character-secret",
            )),
            crate::test_store::test_database().await,
        );
        assert!(validate_password("éééé", 8, 128, &context).is_err());
        assert!(validate_password("🔒🔒🔒🔒", 8, 8, &context).is_ok());
        assert!(validate_password("🔒🔒🔒🔒", 8, 7, &context).is_err());
    }
}
