use body::parse_dispatch_body;
use routing::route_path_matches;
mod body;
mod builder;
mod builtin;
mod endpoint;
mod http;
mod http_hooks;
mod routing;
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse,
    AuthResult, AuthRoute, AuthSchema, AuthStore, BeforeRequestAction, EmailProvider,
    HttpEndpointResponse, HttpMethod, HttpRequestAction, OkResponse, OpenApiBuilder,
    OpenApiRegistry, OpenApiSpec, SessionManager, core_paths,
    hooks::{RequestHookContext, with_request_hook_context_value},
    middleware::{
        self, BodyLimitConfig, BodyLimitMiddleware, CorsConfig, CorsMiddleware, CsrfConfig,
        CsrfMiddleware, Middleware, RateLimitConfig, RateLimitMiddleware,
    },
};
use std::sync::Arc;

pub struct BetterAuth<S: AuthSchema> {
    config: Arc<AuthConfig>,
    telemetry: crate::telemetry::TelemetryConfig,
    pub(super) plugins: Vec<Box<dyn AuthPlugin<S>>>,
    transport_middlewares: Vec<Box<dyn Middleware>>,
    middlewares: Vec<Box<dyn Middleware>>,
    cors: CorsMiddleware,
    request_protection: CsrfMiddleware,
    body_limit: BodyLimitConfig,
    store: Arc<dyn AuthStore<S>>,
    session_manager: SessionManager<S>,
    pub(super) context: AuthContext<S>,
    openapi: Arc<OpenApiRegistry>,
    pub(super) endpoint_hooks: Vec<Arc<dyn better_auth_core::endpoint::EndpointHook<S>>>,
}

impl<S: AuthSchema> std::fmt::Debug for BetterAuth<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BetterAuth").finish_non_exhaustive()
    }
}

/// Initial builder for configuring `BetterAuth`.
pub struct AuthBuilder<S: AuthSchema> {
    config: AuthConfig,
    telemetry: crate::telemetry::TelemetryConfig,
    store: Option<Arc<dyn AuthStore<S>>>,
    // Explicit adapter configuration is a Source server store even when sessions
    // use a nonpersistent policy; the native noDB constructor is separate.
    has_external_store: bool,
    plugins: Vec<Box<dyn AuthPlugin<S>>>,
    csrf_config: Option<CsrfConfig>,
    rate_limit_config: Option<RateLimitConfig>,
    cors_config: Option<CorsConfig>,
    body_limit_config: Option<BodyLimitConfig>,
    custom_middlewares: Vec<Box<dyn Middleware>>,
    endpoint_hooks: Vec<Arc<dyn better_auth_core::endpoint::EndpointHook<S>>>,
}

impl<S: AuthSchema> std::fmt::Debug for AuthBuilder<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthBuilder").finish_non_exhaustive()
    }
}

impl<S: AuthSchema> AuthBuilder<S> {
    /// Configure opt-in application-owned telemetry.
    #[must_use]
    pub fn telemetry(mut self, telemetry: crate::telemetry::TelemetryConfig) -> Self {
        self.telemetry = telemetry;
        self
    }

    /// Configure CSRF protection.
    #[must_use]
    pub const fn csrf(mut self, config: CsrfConfig) -> Self {
        self.csrf_config = Some(config);
        self
    }

    /// Configure body size limit.
    #[must_use]
    pub const fn body_limit(mut self, config: BodyLimitConfig) -> Self {
        self.body_limit_config = Some(config);
        self
    }
}

impl<S: AuthSchema> BetterAuth<S> {
    /// Publish an application-owned event to the configured telemetry sink.
    /// Delivery is awaited; a sink failure is logged and does not fail authentication.
    /// The host is responsible for excluding secrets and personal data from its payload.
    pub async fn publish_telemetry(&self, event: crate::telemetry::TelemetryEvent) {
        self.telemetry.publish(event).await;
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Return the initialized context for server-only plugin APIs.
    ///
    /// The context includes metadata registered by every installed plugin.
    #[must_use]
    pub const fn context(&self) -> &AuthContext<S> {
        &self.context
    }

    /// Get the effective request body size limit.
    ///
    /// Transports read the body before any middleware runs, so they need this
    /// to bound the read itself rather than rejecting after buffering.
    #[must_use]
    pub const fn body_limit(&self) -> &BodyLimitConfig {
        &self.body_limit
    }

    /// Get the session manager.
    #[must_use]
    pub const fn session_manager(&self) -> &SessionManager<S> {
        &self.session_manager
    }

    /// Get all routes from plugins.
    #[must_use]
    pub fn routes(&self) -> Vec<(String, &dyn AuthPlugin<S>)> {
        let mut routes = Vec::new();
        for plugin in &self.plugins {
            for route in plugin.routes() {
                routes.push((route.path, plugin.as_ref()));
            }
        }
        routes
    }

    /// Snapshot of actual registered routes, independent of documentation filters.
    /// The native embedding endpoint `/__test/openapi.json` is owned by `OpenApiPlugin`.
    #[must_use]
    pub fn registered_routes(&self) -> Vec<AuthRoute> {
        self.openapi.registered_routes()
    }

    /// Get all plugins.
    #[must_use]
    pub fn plugins(&self) -> &[Box<dyn AuthPlugin<S>>] {
        &self.plugins
    }

    /// Get plugin by name.
    #[must_use]
    pub fn get_plugin(&self, name: &str) -> Option<&dyn AuthPlugin<S>> {
        self.plugins
            .iter()
            .find(|p| p.name() == name)
            .map(AsRef::as_ref)
    }

    /// List all plugin names.
    #[must_use]
    pub fn plugin_names(&self) -> Vec<&'static str> {
        self.plugins.iter().map(|p| p.name()).collect()
    }

    /// Generate the `OpenAPI` spec for all registered routes.
    #[must_use]
    pub fn openapi_spec(&self) -> OpenApiSpec {
        OpenApiBuilder::registered(&self.config, &self.openapi).build()
    }

    /// Generate documentation including registered Rust extension endpoints.
    #[must_use]
    pub fn openapi_spec_with_native_extensions(&self) -> OpenApiSpec {
        OpenApiBuilder::registered_with_native_extensions(&self.config, &self.openapi, true).build()
    }
}
