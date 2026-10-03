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
        let json = serde_json::to_string(codes)?;
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
        let json = match self {
            Self::Encrypted => super::decrypt_value(secret, stored)?,
            Self::Plain => stored.to_owned(),
            Self::CustomCipher(cipher) => cipher.decrypt(stored).await?,
        };
        Ok(serde_json::from_str(&json).ok())
    }
}
