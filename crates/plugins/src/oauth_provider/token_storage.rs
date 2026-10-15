//! Application-owned token hashing shared by issuance, lookup and trusted server callers.
use alibi_core::AuthResult;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};

/// Custom opaque-token storage matching Better Auth's `storeTokens.hash` callback.
/// `kind` identifies the token domain; trusted callers may also supply application kinds.
#[async_trait]
pub trait OAuthTokenHasher: Send + Sync + std::fmt::Debug {
    async fn hash(&self, token: &str, kind: &str) -> AuthResult<String>;
}
impl super::OAuthProviderPlugin {
    /// Hash a token using this provider's storage policy (`getOAuthProviderApi().hashToken`).
    pub async fn hash_token(&self, token: &str, kind: &str) -> AuthResult<String> {
        if let Some(hasher) = &self.config.token_hasher {
            hasher.hash(token, kind).await
        } else {
            Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(token)))
        }
    }
}
