//! Application-owned client-secret hashing shared by registration, rotation and authentication.
use alibi_core::{AuthContext, AuthResult, AuthSchema};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;

/// Custom client-secret hash storage, matching `storeClientSecret.hash` and optional `verify`.
#[async_trait]
pub trait OAuthClientSecretHasher: Send + Sync + std::fmt::Debug {
    async fn hash(&self, secret: &str) -> AuthResult<String>;
    /// Override verification for application-owned formats or password hashing.
    /// The default hashes the presented secret and compares it in constant time.
    async fn verify(&self, secret: &str, stored: &str) -> AuthResult<bool> {
        let hash = self.hash(secret).await?;
        Ok(bool::from(hash.as_bytes().ct_eq(stored.as_bytes())))
    }
}

/// Custom reversible client-secret storage, matching `storeClientSecret.encrypt` and `decrypt`.
#[async_trait]
pub trait OAuthClientSecretCipher: Send + Sync + std::fmt::Debug {
    async fn encrypt(&self, secret: &str) -> AuthResult<String>;
    async fn decrypt(&self, stored: &str) -> AuthResult<String>;
}

pub(super) async fn store<S: AuthSchema>(
    ctx: &AuthContext<S>,
    config: &super::OAuthProviderConfig,
    secret: &str,
) -> AuthResult<String> {
    if let Some(hasher) = &config.client_secret_hasher {
        return hasher.hash(secret).await;
    }
    if let Some(cipher) = &config.client_secret_cipher {
        return cipher.encrypt(secret).await;
    }
    if config.disable_jwt_plugin {
        crate::token_crypto::encrypt_with_config(secret, &ctx.config)
    } else {
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(secret)))
    }
}

pub(super) async fn verify<S: AuthSchema>(
    ctx: &AuthContext<S>,
    config: &super::OAuthProviderConfig,
    secret: &str,
    stored: &str,
) -> AuthResult<bool> {
    if secret.is_empty() {
        return Ok(false);
    }
    if let Some(hasher) = &config.client_secret_hasher {
        return hasher.verify(secret, stored).await;
    }
    if let Some(cipher) = &config.client_secret_cipher {
        let plaintext = cipher.decrypt(stored).await?;
        return Ok(bool::from(plaintext.as_bytes().ct_eq(secret.as_bytes())));
    }
    if config.disable_jwt_plugin {
        Ok(
            crate::token_crypto::decrypt_with_config(stored, &ctx.config)
                .is_ok_and(|plaintext| bool::from(plaintext.as_bytes().ct_eq(secret.as_bytes()))),
        )
    } else {
        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(secret));
        Ok(bool::from(hash.as_bytes().ct_eq(stored.as_bytes())))
    }
}

pub(super) async fn decrypt<S: AuthSchema>(
    ctx: &AuthContext<S>,
    config: &super::OAuthProviderConfig,
    stored: &str,
) -> AuthResult<String> {
    if let Some(cipher) = &config.client_secret_cipher {
        return cipher.decrypt(stored).await;
    }
    crate::token_crypto::decrypt_with_config(stored, &ctx.config)
}
