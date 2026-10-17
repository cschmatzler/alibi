//! Application-owned refresh presentation, after storage and before the wire prefix.
use alibi_core::AuthResult;
use async_trait::async_trait;
use std::{future::Future, pin::Pin};

/// A synchronous value or an asynchronous encryption callback result.
///
/// Pinned Better Auth 1.7.7 concatenates the result without awaiting it. A
/// `Promise` therefore runs detached and presents as `[object Promise]`, not its
/// resolved ciphertext. Use `Immediate` for usable encrypted credentials.
/// Detached failures do not propagate to the response; this API does not emulate
/// JavaScript's process-level unhandled-rejection policy.
pub enum OAuthRefreshTokenEncryption {
    Immediate(String),
    Promise(Pin<Box<dyn Future<Output = AuthResult<String>> + Send + 'static>>),
}

/// Decoded storage preimage. In 1.7.7 consumers use the persisted session binding,
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

    /// Invoked after removing the configured prefix; unlike encryption this is awaited.
    async fn decrypt(&self, token: &str) -> AuthResult<OAuthDecodedRefreshToken>;
}

impl super::OAuthProviderPlugin {
    pub(super) fn encode_refresh_token(
        &self,
        token: &str,
        session_id: Option<&str>,
    ) -> AuthResult<String> {
        let formatted = match &self.config.refresh_token_formatter {
            None => token.to_owned(),
            Some(formatter) => match formatter.encrypt(token, session_id)? {
                OAuthRefreshTokenEncryption::Immediate(value) => value,
                OAuthRefreshTokenEncryption::Promise(future) => {
                    // JS promises are eager; dropping a Rust future would suppress
                    // application work. Neither its value nor rejection affects
                    // the already-coerced wire value in pinned 1.7.7.
                    drop(tokio::spawn(future));
                    "[object Promise]".to_owned()
                }
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
}
