use crate::token_crypto;
use alibi_core::AuthResult;
use async_trait::async_trait;
use std::sync::Arc;

/// Application-owned irreversible OTP representation.
#[async_trait]
pub trait TwoFactorOtpHasher: Send + Sync {
    async fn hash(&self, otp: &str) -> AuthResult<String>;
}

/// Application-owned reversible OTP representation.
#[async_trait]
pub trait TwoFactorOtpCipher: Send + Sync {
    async fn encrypt(&self, otp: &str) -> AuthResult<String>;
    async fn decrypt(&self, stored: &str) -> AuthResult<String>;
}

/// Persistence format for delivered two-factor OTPs.
#[derive(Clone, Default)]
pub enum TwoFactorOtpStorage {
    #[default]
    Plain,
    Hashed,
    Encrypted,
    CustomHash(Arc<dyn TwoFactorOtpHasher>),
    CustomCipher(Arc<dyn TwoFactorOtpCipher>),
}

impl std::fmt::Debug for TwoFactorOtpStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Plain => "Plain",
            Self::Hashed => "Hashed",
            Self::Encrypted => "Encrypted",
            Self::CustomHash(_) => "CustomHash",
            Self::CustomCipher(_) => "CustomCipher",
        })
    }
}

impl TwoFactorOtpStorage {
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn store(
        &self,
        otp: &str,
        secret: &alibi_core::AuthConfig,
    ) -> AuthResult<String> {
        match self {
            Self::Plain => Ok(otp.to_owned()),
            Self::Hashed => Ok(token_crypto::hash_token(otp)),
            Self::Encrypted => token_crypto::encrypt_with_config(otp, secret),
            Self::CustomHash(callback) => callback.hash(otp).await,
            Self::CustomCipher(callback) => callback.encrypt(otp).await,
        }
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn verify(
        &self,
        stored: &str,
        input: &str,
        secret: &alibi_core::AuthConfig,
    ) -> AuthResult<bool> {
        let (left, right) = match self {
            Self::Plain => (stored.to_owned(), input.to_owned()),
            Self::Hashed => (stored.to_owned(), token_crypto::hash_token(input)),
            Self::Encrypted => (
                token_crypto::decrypt_with_config(stored, secret)?,
                input.to_owned(),
            ),
            Self::CustomHash(callback) => (stored.to_owned(), callback.hash(input).await?),
            Self::CustomCipher(callback) => (callback.decrypt(stored).await?, input.to_owned()),
        };
        Ok(left.len() == right.len()
            && left
                .bytes()
                .zip(right.bytes())
                .fold(0u8, |difference, (a, b)| difference | (a ^ b))
                == 0)
    }
}
