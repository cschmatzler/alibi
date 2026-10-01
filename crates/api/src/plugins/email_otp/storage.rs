use crate::plugins::token_crypto::{decrypt, encrypt, hash_token};
use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResult};
use std::sync::Arc;

/// Application-owned codec for custom hash/encryption storage.
/// `retrieve` returns `None` when the representation is intentionally irreversible.
#[async_trait]
pub trait EmailOtpCodec: Send + Sync {
    async fn store(&self, otp: &str) -> AuthResult<String>;
    async fn verify(&self, stored: &str, otp: &str) -> AuthResult<bool>;
    async fn retrieve(&self, stored: &str) -> AuthResult<Option<String>>;
}

#[derive(Clone)]
pub enum EmailOtpStorage {
    Plain,
    Hashed,
    Encrypted,
    Custom(Arc<dyn EmailOtpCodec>),
}

impl std::fmt::Debug for EmailOtpStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => f.write_str("EmailOtpStorage::Plain"),
            Self::Hashed => f.write_str("EmailOtpStorage::Hashed"),
            Self::Encrypted => f.write_str("EmailOtpStorage::Encrypted"),
            Self::Custom(..) => f.write_str("EmailOtpStorage::Custom"),
        }
    }
}

impl EmailOtpStorage {
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn store(&self, otp: &str, secret: &str) -> AuthResult<String> {
        match self {
            Self::Plain => Ok(otp.to_owned()),
            Self::Hashed => Ok(hash_token(otp)),
            Self::Encrypted => encrypt(otp, secret),
            Self::Custom(codec) => codec.store(otp).await,
        }
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn verify(&self, stored: &str, otp: &str, secret: &str) -> AuthResult<bool> {
        match self {
            Self::Plain => Ok(constant_time_equal(stored, otp)),
            Self::Hashed => Ok(constant_time_equal(stored, &hash_token(otp))),
            Self::Encrypted => Ok(constant_time_equal(&decrypt(stored, secret)?, otp)),
            Self::Custom(codec) => codec.verify(stored, otp).await,
        }
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn retrieve(&self, stored: &str, secret: &str) -> AuthResult<Option<String>> {
        let plain = match self {
            Self::Plain => Some(stored.to_owned()),
            Self::Hashed => None,
            Self::Encrypted => Some(decrypt(stored, secret)?),
            Self::Custom(codec) => codec.retrieve(stored).await?,
        };
        plain.map(Some).ok_or_else(|| {
            AuthError::bad_request("OTP is hashed, cannot return the plain text OTP")
        })
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn reusable(&self, stored: &str, secret: &str) -> AuthResult<Option<String>> {
        match self {
            Self::Hashed => Ok(None),
            Self::Custom(codec) => codec.retrieve(stored).await,
            Self::Plain | Self::Encrypted => self.retrieve(stored, secret).await,
        }
    }
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}
