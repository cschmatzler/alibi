use alibi_core::{AuthConfig, AuthContext, AuthRequest, AuthResult, AuthSchema, ContextExtensions};
use async_trait::async_trait;

/// Immutable application context for trusted API-key lookup and validation.
///
/// HTTP authentication supplies the actual request. Programmatic verification
/// supplies no request unless using `verify_api_key_with_request`. Applications
/// may capture their own typed store or service in the callback implementation.
pub struct ApiKeyCallbackContext<'a> {
    pub request: Option<&'a AuthRequest>,
    /// Genuine logical context when verification is dispatched as a registered endpoint.
    /// It never manufactures a physical request for virtual calls.
    pub endpoint: Option<alibi_core::endpoint::EndpointCall>,
    pub auth_config: &'a AuthConfig,
    pub extensions: &'a ContextExtensions,
    pub configuration_id: &'a str,
    /// Original trusted verification input, including the requested scope and
    /// permissions. HTTP authentication callbacks have no server-only input.
    pub verification_input: Option<&'a super::VerifyApiKey<'a>>,
}

impl std::fmt::Debug for ApiKeyCallbackContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyCallbackContext")
            .finish_non_exhaustive()
    }
}

impl<'a> ApiKeyCallbackContext<'a> {
    pub(super) fn with_endpoint(mut self, endpoint: &alibi_core::endpoint::EndpointCall) -> Self {
        self.endpoint = Some(endpoint.clone());
        self
    }
    #[must_use]
    pub(super) fn new(
        request: Option<&'a AuthRequest>,
        ctx: &'a AuthContext<impl AuthSchema>,
        configuration_id: &'a str,
    ) -> Self {
        Self {
            request,
            endpoint: alibi_core::endpoint::current_endpoint_call_context(),
            auth_config: &ctx.config,
            extensions: &ctx.extensions,
            configuration_id,
            verification_input: None,
        }
    }

    #[must_use]
    pub(super) const fn with_verification_input(
        mut self,
        input: &'a super::VerifyApiKey<'a>,
    ) -> Self {
        self.verification_input = Some(input);
        self
    }
}

/// Application lookup replaces configured API-key headers entirely.
///
/// `None` or an empty string leaves normal session authentication in control.
/// A matching getter is called again when the authentication hook executes,
/// following upstream's matcher/handler ordering.
/// Errors during matching become the hook matcher's public 500 response;
/// errors from the subsequent handler preserve the application API error.
pub trait ApiKeyGetter: Send + Sync {
    /// Look up the actual request's credential.
    ///
    /// # Errors
    /// Returns an application failure from credential lookup.
    fn get_key(&self, context: &ApiKeyCallbackContext<'_>) -> AuthResult<Option<String>>;
}

/// Trusted acceptance predicate, evaluated before key usage is consumed.
///
/// Explicitly scoped programmatic verification evaluates it before lookup;
/// unscoped verification first resolves the persisted issuing configuration.
/// A scoped callback error is returned directly. Unscoped verification catches
/// it in the same validation phase as stored key errors.
#[async_trait]
pub trait ApiKeyValidator: Send + Sync {
    /// Accept or reject a credential before consuming its usage.
    ///
    /// # Errors
    /// Returns an application failure from credential validation.
    async fn validate(&self, context: &ApiKeyCallbackContext<'_>, key: &str) -> AuthResult<bool>;
}

/// Ordered resource/action permissions, following JavaScript object insertion order.
pub type ApiKeyPermissions = indexmap::IndexMap<String, Vec<String>>;

/// Inputs passed to an application key generator; length excludes the prefix.
pub struct ApiKeyGenerationOptions<'a> {
    /// Raw configured number after zero/NaN fallback; custom generators own
    /// fractional and nonfinite values without an integer coercion.
    pub length: f64,
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
