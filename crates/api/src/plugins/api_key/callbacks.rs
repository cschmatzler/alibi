use async_trait::async_trait;
use better_auth_core::{AuthConfig, AuthContext, AuthRequest, AuthSchema, ContextExtensions};

/// Immutable application context for trusted API-key lookup and validation.
///
/// HTTP authentication supplies the actual request. Programmatic verification
/// supplies no request unless using `verify_api_key_with_request`. Applications
/// may capture their own typed store or service in the callback implementation.
pub struct ApiKeyCallbackContext<'a> {
    pub request: Option<&'a AuthRequest>,
    pub auth_config: &'a AuthConfig,
    pub extensions: &'a ContextExtensions,
    pub configuration_id: &'a str,
}

impl<'a> ApiKeyCallbackContext<'a> {
    pub(super) fn new(
        request: Option<&'a AuthRequest>,
        ctx: &'a AuthContext<impl AuthSchema>,
        configuration_id: &'a str,
    ) -> Self {
        Self {
            request,
            auth_config: &ctx.config,
            extensions: &ctx.extensions,
            configuration_id,
        }
    }
}

/// Application lookup replaces configured API-key headers entirely.
///
/// `None` or an empty string leaves normal session authentication in control.
/// A matching getter is called again when the authentication hook executes,
/// following upstream's matcher/handler ordering.
pub trait ApiKeyGetter: Send + Sync {
    fn get_key(&self, context: &ApiKeyCallbackContext<'_>) -> Option<String>;
}

/// Trusted acceptance predicate, evaluated before key usage is consumed.
///
/// Explicitly scoped programmatic verification evaluates it before lookup;
/// unscoped verification first resolves the persisted issuing configuration.
#[async_trait]
pub trait ApiKeyValidator: Send + Sync {
    async fn validate(&self, context: &ApiKeyCallbackContext<'_>, key: &str) -> bool;
}
