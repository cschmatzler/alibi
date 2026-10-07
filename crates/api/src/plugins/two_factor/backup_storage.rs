use alibi_core::{AuthError, AuthResult};
use async_trait::async_trait;
use std::sync::Arc;

/// Async persistence callbacks for the complete backup-code JSON string.
///
/// Returning [`AuthError::Internal`] represents an ordinary application throw:
/// HTTP callers receive an empty 500. Explicit API errors retain their public
/// status and body, even when their message matches an ordinary failure.
#[async_trait]
pub trait TwoFactorBackupCipher: Send + Sync {
    async fn encrypt(&self, json: &str) -> AuthResult<String>;
    async fn decrypt(&self, stored: &str) -> AuthResult<String>;
}

/// Backup persistence policy. Encrypted storage is the pinned default.
#[derive(Clone, Default)]
pub enum TwoFactorBackupStorage {
    #[default]
    Encrypted,
    Plain,
    CustomCipher(Arc<dyn TwoFactorBackupCipher>),
}

impl std::fmt::Debug for TwoFactorBackupStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Encrypted => "Encrypted",
            Self::Plain => "Plain",
            Self::CustomCipher(_) => "CustomCipher",
        })
    }
}

impl TwoFactorBackupStorage {
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(in crate::plugins) async fn store_codes(
        &self,
        codes: &[String],
        secret: &alibi_core::AuthConfig,
    ) -> AuthResult<String> {
        self.store_json(serde_json::to_string(codes)?, secret).await
    }

    pub(in crate::plugins) async fn store_json(
        &self,
        json: String,
        secret: &alibi_core::AuthConfig,
    ) -> AuthResult<String> {
        match self {
            Self::Encrypted => super::encrypt_value(secret, &json),
            Self::Plain => Ok(json),
            Self::CustomCipher(cipher) => cipher.encrypt(&json).await.map_err(callback_error),
        }
    }

    // Keep the parsed value until the operation's truthiness/shape checks have
    // run. JSON.stringify maps Infinity to null; doing that during decoding
    // would incorrectly spend a pending attempt instead of restoring it.
    pub(in crate::plugins) async fn load_value(
        &self,
        stored: &str,
        secret: &alibi_core::AuthConfig,
    ) -> AuthResult<Option<alibi_core::utils::json::JsValue>> {
        let json = match self {
            Self::Encrypted => super::decrypt_value(secret, stored)?,
            Self::Plain => stored.to_owned(),
            Self::CustomCipher(cipher) => cipher.decrypt(stored).await.map_err(callback_error)?,
        };
        Ok(alibi_core::utils::json::parse_value(&json).ok())
    }
}

pub(super) fn json_date(value: &str) -> Option<String> {
    alibi_core::utils::datetime::normalize_json_date(value)
}

pub(super) fn normalize_json_dates(value: &mut alibi_core::utils::json::JsValue) {
    use alibi_core::utils::json::JsValue;
    match value {
        JsValue::String(text) => {
            if let Some(date) = json_date(text) {
                *text = date;
            }
        }
        JsValue::Array(values) => values.iter_mut().for_each(normalize_json_dates),
        JsValue::Object(values) => values.values_mut().for_each(normalize_json_dates),
        _ => {}
    }
}

pub(super) fn truthy(value: &alibi_core::utils::json::JsValue) -> bool {
    use alibi_core::utils::json::JsValue;
    match value {
        JsValue::Null | JsValue::Bool(false) => false,
        JsValue::Number(number) => *number != 0.0 && !number.is_nan(),
        JsValue::String(text) => !text.is_empty(),
        _ => true,
    }
}

fn callback_error(error: AuthError) -> AuthError {
    match error {
        AuthError::Internal(_) => AuthError::CallbackFailure(Box::new(error)),
        error => error,
    }
}
