//! Application inputs resolved before a passkey challenge is persisted.
use alibi_core::{AuthConfig, AuthRequest, AuthResult, ContextExtensions, wire::UserView};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

pub struct PasskeyOptionsContext<'a> {
    pub request: &'a AuthRequest,
    pub auth_config: &'a AuthConfig,
    pub extensions: &'a ContextExtensions,
    pub user: Option<&'a UserView>,
}

#[async_trait]
pub trait PasskeyExtensionsResolver: Send + Sync {
    async fn resolve(&self, context: &PasskeyOptionsContext<'_>) -> AuthResult<Value>;
}

#[derive(Clone)]
pub enum PasskeyExtensions {
    Static(Value),
    Resolver(Arc<dyn PasskeyExtensionsResolver>),
}
impl std::fmt::Debug for PasskeyExtensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static(value) => f.debug_tuple("Static").field(value).finish(),
            Self::Resolver(_) => f.write_str("Resolver(..)"),
        }
    }
}
impl PasskeyExtensions {
    pub(super) async fn resolve(&self, context: &PasskeyOptionsContext<'_>) -> AuthResult<Value> {
        let value = match self {
            Self::Static(value) => Ok(value.clone()),
            Self::Resolver(resolver) => resolver.resolve(context).await.map_err(|error| {
                if alibi_core::endpoint::is_endpoint_api_error(&error) {
                    error
                } else {
                    alibi_core::AuthError::CallbackFailure(Box::new(error))
                }
            }),
        }?;
        if !value.is_object() {
            return Err(alibi_core::AuthError::config(
                "Passkey extensions must be an object",
            ));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PasskeyAuthenticatorSelection {
    pub resident_key: Option<String>,
    pub user_verification: Option<String>,
    pub authenticator_attachment: Option<String>,
}
