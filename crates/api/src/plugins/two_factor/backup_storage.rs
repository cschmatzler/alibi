use async_trait::async_trait;
use better_auth_core::AuthResult;
use std::sync::Arc;

/// Async persistence callbacks for the complete backup-code JSON string.
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
        secret: &better_auth_core::AuthConfig,
    ) -> AuthResult<String> {
        self.store_json(serde_json::to_string(codes)?, secret).await
    }

    pub(in crate::plugins) async fn store_json(
        &self,
        json: String,
        secret: &better_auth_core::AuthConfig,
    ) -> AuthResult<String> {
        match self {
            Self::Encrypted => super::encrypt_value(secret, &json),
            Self::Plain => Ok(json),
            Self::CustomCipher(cipher) => cipher.encrypt(&json).await,
        }
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(in crate::plugins) async fn load_codes(
        &self,
        stored: &str,
        secret: &better_auth_core::AuthConfig,
    ) -> AuthResult<Option<Vec<String>>> {
        Ok(self
            .load_value(stored, secret)
            .await?
            .and_then(|value| serde_json::from_value(value).ok()))
    }

    // Verification must retain non-string elements in installed arrays. The
    // typed server-only view continues to require an array of strings.
    pub(in crate::plugins) async fn load_value(
        &self,
        stored: &str,
        secret: &better_auth_core::AuthConfig,
    ) -> AuthResult<Option<serde_json::Value>> {
        let json = match self {
            Self::Encrypted => super::decrypt_value(secret, stored)?,
            Self::Plain => stored.to_owned(),
            Self::CustomCipher(cipher) => cipher.decrypt(stored).await?,
        };
        Ok(serde_json::from_str(&json).ok().map(|mut value| {
            normalize_json_dates(&mut value);
            value
        }))
    }
}

// Published safeJSONParse revives matching ISO strings into Date objects.
// Keep representable canonical dates from authenticating as string codes and
// preserve their JSON serialization when another code consumes the array.
pub(super) fn json_date(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::Timelike;

    if !value.ends_with('Z')
        || value.get(10..11) != Some("T")
        || !value
            .get(..4)
            .is_some_and(|year| year.bytes().all(|byte| byte.is_ascii_digit()))
        || !(value.len() == 20
            || (value.as_bytes().get(19) == Some(&b'.')
                && value
                    .get(20..value.len().checked_sub(1)?)
                    .is_some_and(|fraction| {
                        !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit())
                    })))
    {
        return None;
    }
    let date = chrono::DateTime::parse_from_rfc3339(value).ok()?;
    // JavaScript Date does not accept leap seconds.
    (date.nanosecond() < 1_000_000_000).then(|| date.with_timezone(&chrono::Utc))
}

fn normalize_json_dates(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            if let Some(date) = json_date(text) {
                *text = date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            }
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(normalize_json_dates),
        serde_json::Value::Object(values) => values.values_mut().for_each(normalize_json_dates),
        _ => {}
    }
}
