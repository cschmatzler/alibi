//! Explicit administrative conversion of pre-Source native OAuth token rows.
//!
//! This module registers no routes and is never called by live token readers.
//! A trusted operator must supply the original secret and independently verified
//! historical ownership; legacy ciphertext authenticates no account identity.

use super::token_crypto;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
pub use alibi_core::oauth_token_conversion::{
    OAuthTokenConversionStore, OAuthTokenSnapshot, OAuthTokenValues,
};
use alibi_core::{AuthConfig, AuthError, AuthResult, AuthSchema};
use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use sha2::Sha256;

/// Operator-provided classification, never inferred from stored text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenEncoding {
    /// SQL NULL; must match an absent observed value.
    Absent,
    /// Known plaintext from trusted installation history.
    Plain,
    /// Native AES-GCM/HKDF/standard-base64 format from before Source alignment.
    LegacyNative,
    /// Current Source format (including a configured managed-secret envelope).
    /// Valid only for access and refresh tokens; authenticated and retained.
    Source,
}

/// Reviewed manifest entry. Do not build from untrusted client input or infer
/// historical ownership from the current database owner. Deliberately not Debug.
#[derive(Clone)]
pub struct TrustedOAuthTokenManifest {
    pub observed: OAuthTokenSnapshot,
    pub access_encoding: TokenEncoding,
    pub refresh_encoding: TokenEncoding,
    pub id_encoding: TokenEncoding,
}

/// Prepared row conversion. All encrypted fields authenticated before this
/// value exists. Keep it private; the ID token may be plaintext.
pub struct OAuthTokenConversion {
    observed: OAuthTokenSnapshot,
    replacement: OAuthTokenValues,
}

impl OAuthTokenConversion {
    /// Authenticate every encrypted field and prepare Source-compatible values.
    /// Plain access/refresh values become encrypted; plain ID values remain plain.
    /// Requires encryption enabled in the destination runtime configuration.
    ///
    /// # Errors
    /// Wrong key, tamper, invalid UTF-8, NULL/classification disagreement or an
    /// encrypted Source ID token rejects the entire row without writing anything.
    pub fn prepare(
        manifest: TrustedOAuthTokenManifest,
        original_secret: &str,
        destination: &AuthConfig,
    ) -> AuthResult<Self> {
        if !destination.account.encrypt_oauth_tokens {
            return Err(AuthError::bad_request(
                "Destination OAuth token encryption must be enabled",
            ));
        }
        if manifest.id_encoding == TokenEncoding::Source {
            return Err(AuthError::bad_request(
                "Source ID tokens must be classified as plain",
            ));
        }
        let observed = manifest.observed;
        // Authenticate all fields before preparing a replacement or touching storage.
        let access = decode(
            observed.tokens.access_token.as_deref(),
            manifest.access_encoding,
            original_secret,
            destination,
        )?;
        let refresh = decode(
            observed.tokens.refresh_token.as_deref(),
            manifest.refresh_encoding,
            original_secret,
            destination,
        )?;
        let id_token = decode(
            observed.tokens.id_token.as_deref(),
            manifest.id_encoding,
            original_secret,
            destination,
        )?;
        let access_token = encode(
            access,
            &observed.tokens.access_token,
            manifest.access_encoding,
            destination,
        )?;
        let refresh_token = encode(
            refresh,
            &observed.tokens.refresh_token,
            manifest.refresh_encoding,
            destination,
        )?;
        Ok(Self {
            observed,
            replacement: OAuthTokenValues {
                access_token,
                refresh_token,
                id_token,
            },
        })
    }

    /// Apply one atomic row CAS through a physical adapter. `false` means the row
    /// changed or disappeared. Repeating the same plan cannot overwrite a refresh
    /// or reassignment. A storage failure may be retried with this same plan.
    ///
    /// # Errors
    /// Returns adapter errors; no token subset is committed.
    pub async fn apply<S: AuthSchema>(
        &self,
        store: &impl OAuthTokenConversionStore<S>,
    ) -> AuthResult<bool> {
        store
            .compare_and_swap_oauth_tokens(&self.observed, &self.replacement)
            .await
    }
}

fn decode(
    value: Option<&str>,
    encoding: TokenEncoding,
    secret: &str,
    config: &AuthConfig,
) -> AuthResult<Option<String>> {
    match (value, encoding) {
        (None, TokenEncoding::Absent) => Ok(None),
        (Some(value), TokenEncoding::Plain) => Ok(Some(value.to_owned())),
        (Some(value), TokenEncoding::LegacyNative) => decrypt_legacy(value, secret).map(Some),
        (Some(value), TokenEncoding::Source) => {
            token_crypto::decrypt_with_config(value, config).map(Some)
        }
        _ => Err(AuthError::bad_request(
            "Token classification does not match presence",
        )),
    }
}

fn encode(
    plain: Option<String>,
    observed: &Option<String>,
    encoding: TokenEncoding,
    config: &AuthConfig,
) -> AuthResult<Option<String>> {
    if encoding == TokenEncoding::Source {
        return Ok(observed.clone());
    }
    plain
        .map(|plain| token_crypto::encrypt_with_config(&plain, config))
        .transpose()
}

fn decrypt_legacy(value: &str, secret: &str) -> AuthResult<String> {
    let invalid = || AuthError::Encryption("Legacy OAuth token authentication failed".into());
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(None, secret.as_bytes())
        .expand(b"better-auth-oauth-token-encryption", &mut key)
        .map_err(|_| invalid())?;
    let bytes = STANDARD.decode(value).map_err(|_| invalid())?;
    let (nonce, ciphertext) = bytes.split_at_checked(12).ok_or_else(invalid)?;
    let plain = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| invalid())?
        .decrypt(
            &Nonce::try_from(nonce)
                .map_err(|_error| AuthError::Encryption("Invalid nonce".into()))?,
            ciphertext,
        )
        .map_err(|_| invalid())?;
    String::from_utf8(plain).map_err(|_| invalid())
}
