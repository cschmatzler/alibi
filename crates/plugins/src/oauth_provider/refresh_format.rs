//! Application-owned refresh presentation, after storage and before the wire prefix.
use alibi_core::{AuthError, AuthResult};
use async_trait::async_trait;
use std::{future::Future, pin::Pin};

/// A synchronous value or an asynchronous encryption callback result.
///
/// A `Promise` is awaited and its resolved value presented, as Better Auth
/// awaits `formatRefreshToken.encrypt` since 1.7.21. Its failure fails the
/// issuance, like a synchronous error.
pub enum OAuthRefreshTokenEncryption {
    Immediate(String),
    Promise(Pin<Box<dyn Future<Output = AuthResult<String>> + Send + 'static>>),
}

/// Decoded storage preimage. In 1.7.12 consumers use the persisted session binding,
/// not this optional callback-supplied session ID.
#[derive(Debug, Clone)]
pub struct OAuthDecodedRefreshToken {
    pub token: String,
    pub session_id: Option<String>,
}

/// Better Auth's `formatRefreshToken`. Both callbacks are required by its types;
/// absence of the whole formatter preserves raw refresh credentials.
#[async_trait]
pub trait OAuthRefreshTokenFormatter: Send + Sync + std::fmt::Debug {
    /// Invoked after refresh persistence (and rotation claim), before prefixing.
    fn encrypt(
        &self,
        token: &str,
        session_id: Option<&str>,
    ) -> AuthResult<OAuthRefreshTokenEncryption>;

    /// Invoked after removing the configured prefix. For lookup, JOSE value
    /// errors can use their standard `ERR_JWE_*`, `ERR_JWT_*`, or related code
    /// in `AuthError::Api` and will be treated as unknown tokens.
    async fn decrypt(&self, token: &str) -> AuthResult<OAuthDecodedRefreshToken>;
}

impl super::OAuthProviderPlugin {
    pub(super) async fn encode_refresh_token(
        &self,
        token: &str,
        session_id: Option<&str>,
    ) -> AuthResult<String> {
        let formatted = match &self.config.refresh_token_formatter {
            None => token.to_owned(),
            Some(formatter) => match formatter.encrypt(token, session_id)? {
                OAuthRefreshTokenEncryption::Immediate(value) => value,
                OAuthRefreshTokenEncryption::Promise(future) => future.await?,
            },
        };
        Ok(self.encode_token_prefix(&formatted, alibi_core::store::OAuthTokenKind::Refresh))
    }

    pub(super) async fn decode_refresh_token(
        &self,
        token: &str,
    ) -> AuthResult<Option<OAuthDecodedRefreshToken>> {
        let Some(token) =
            self.decode_token_prefix(token, alibi_core::store::OAuthTokenKind::Refresh)
        else {
            return Ok(None);
        };
        Ok(Some(match &self.config.refresh_token_formatter {
            Some(formatter) => formatter.decrypt(token).await?,
            None => OAuthDecodedRefreshToken {
                token: token.to_owned(),
                session_id: None,
            },
        }))
    }
    pub(super) async fn decode_refresh_token_for_lookup(
        &self,
        token: &str,
    ) -> AuthResult<Option<OAuthDecodedRefreshToken>> {
        match self.decode_refresh_token(token).await {
            Err(error) if jose_token_error(&error) => Ok(None),
            result => result,
        }
    }
}

fn jose_token_error(error: &AuthError) -> bool {
    match error {
        AuthError::CallbackFailure(cause) => jose_token_error(cause),
        AuthError::Api { code: Some(code), .. } => {
            matches!(code.as_str(), "ERR_JWKS_NO_MATCHING_KEY")
                || ["ERR_JOSE_", "ERR_JWT_", "ERR_JWS_", "ERR_JWE_", "ERR_JWK_"]
                    .iter().any(|prefix| code.starts_with(prefix))
        }
        _ => false,
    }

}
