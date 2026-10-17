//! Application-owned token hashing shared by issuance, lookup and trusted server callers.
use alibi_core::AuthResult;
use alibi_core::store::OAuthTokenKind;
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
    fn token_prefix(&self, kind: OAuthTokenKind) -> &str {
        match kind {
            OAuthTokenKind::Access => self.config.opaque_access_token_prefix.as_deref(),
            OAuthTokenKind::Refresh => self.config.refresh_token_prefix.as_deref(),
        }
        .unwrap_or_default()
    }

    pub(super) fn encode_token_prefix(&self, token: &str, kind: OAuthTokenKind) -> String {
        format!("{}{token}", self.token_prefix(kind))
    }

    /// Match the reference's nonempty-prefix `startsWith` guard followed by one
    /// literal `replace`. Missing/empty configuration still accepts raw tokens.
    pub(super) fn decode_token_prefix<'a>(
        &self,
        token: &'a str,
        kind: OAuthTokenKind,
    ) -> Option<&'a str> {
        let prefix = self.token_prefix(kind);
        if prefix.is_empty() {
            Some(token)
        } else {
            token.strip_prefix(prefix)
        }
    }

    /// Hash a token using this provider's storage policy (`getOAuthProviderApi().hashToken`).
    pub async fn hash_token(&self, token: &str, kind: &str) -> AuthResult<String> {
        if let Some(hasher) = &self.config.token_hasher {
            hasher.hash(token, kind).await
        } else {
            Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(token)))
        }
    }
}
