use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthContext, AuthRequest, AuthResult, AuthSchema, ContextExtensions,
};

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

impl std::fmt::Debug for ApiKeyCallbackContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyCallbackContext")
            .finish_non_exhaustive()
    }
}

impl<'a> ApiKeyCallbackContext<'a> {
    #[must_use]
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

/// Ordered resource/action permissions, following JavaScript object insertion order.
pub type ApiKeyPermissions = indexmap::IndexMap<String, Vec<String>>;

/// Inputs passed to an application key generator; length excludes the prefix.
pub struct ApiKeyGenerationOptions<'a> {
    pub length: usize,
    pub prefix: Option<&'a str>,
}

impl std::fmt::Debug for ApiKeyGenerationOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyGenerationOptions")
            .finish_non_exhaustive()
    }
}

/// Trusted custom secret generation. The application owns the returned full key.
#[async_trait]
pub trait ApiKeyGenerator: Send + Sync {
    async fn generate_key(&self, options: &ApiKeyGenerationOptions<'_>) -> AuthResult<String>;
}

/// Trusted dynamic defaults, evaluated even when creation supplies an override.
#[async_trait]
pub trait ApiKeyDefaultPermissions: Send + Sync {
    async fn default_permissions(
        &self,
        reference_id: &str,
        context: &ApiKeyCallbackContext<'_>,
    ) -> AuthResult<ApiKeyPermissions>;
}
