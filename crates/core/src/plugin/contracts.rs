use crate::{
    AuthContext, AuthError, AuthInitContext, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
/// A plugin override for delivery of the core email-verification challenge.
#[async_trait]
pub trait VerificationEmailOverride<S: AuthSchema>: Send + Sync {
    async fn send(
        &self,
        user: &crate::wire::UserView,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()>;

    async fn send_in_transaction(
        &self,
        user: &crate::wire::UserView,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
        _transaction: &dyn crate::store::AuthTransaction<S>,
    ) -> AuthResult<()> {
        self.send(user, request, ctx).await
    }
}

pub struct VerificationEmailOverrideHandle<S: AuthSchema>(
    pub Arc<dyn VerificationEmailOverride<S>>,
);

/// Action returned by [`AuthPlugin::before_request`].
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "Preserve public InjectSession construction as session views gain configured output policies"
)]
pub enum BeforeRequestAction {
    /// Short-circuit with this response (e.g. return session JSON).
    Respond(AuthResponse),
    /// Inject a virtual session so downstream handlers see it as authenticated.
    InjectSession { session: crate::wire::SessionView },
    /// Replace headers for subsequent hooks, endpoint dispatch and response hooks.
    /// Authentication adapters can establish a verified signed cookie while
    /// retaining normal session lookup, expiry and revocation checks.
    ReplaceHeaders { headers: HashMap<String, String> },
}

/// Physical HTTP hook control flow, before route selection and endpoint hooks.
#[derive(Debug)]
pub enum HttpRequestAction {
    /// Finish transport processing without endpoint or HTTP response hooks.
    Respond(AuthResponse),
    /// Replace physical input for later HTTP hooks and route selection.
    /// Dispatch discards session state, extensions and queued headers on this value.
    ReplaceRequest(Box<AuthRequest>),
}

/// Endpoint output distinguishing a logical value from a native raw response.
/// Raw responses bypass completed endpoint hooks, while HTTP response hooks
/// still observe them, matching a Source endpoint returning a `Response`.
#[derive(Debug)]
pub enum HttpEndpointResponse {
    Value(AuthResponse),
    Raw(AuthResponse),
}

/// Plugin trait that all authentication plugins must implement.
///
#[async_trait]
pub trait AuthPlugin<S: AuthSchema>: Send + Sync {
    /// Plugin name - should be unique
    fn name(&self) -> &'static str;

    /// Routes that this plugin handles
    fn routes(&self) -> Vec<AuthRoute>;

    /// Ordered rate-limit policies supplied by this installed plugin.
    fn rate_limits(&self) -> Vec<crate::middleware::rate_limit::PluginRateLimit> {
        Vec::new()
    }

    /// Trusted operations available through host dispatch, independently of HTTP visibility.
    fn server_endpoints(&self) -> Vec<crate::endpoint::EndpointDefinition> {
        Vec::new()
    }

    /// Installed logical-call hooks, in this plugin's registration order.
    fn endpoint_hooks(&self) -> Vec<&dyn crate::endpoint::EndpointHook<S>> {
        Vec::new()
    }

    /// Validate actual input after all before-hook patches have been applied.
    /// # Errors
    /// Returns an intentional validation error, which completed hooks can observe.
    fn validate_endpoint(
        &self,
        call: &crate::endpoint::EndpointCall,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<crate::endpoint::EndpointInput> {
        Ok(crate::endpoint::EndpointInput {
            body: call.body().cloned(),
            query: call.query().cloned(),
        })
    }

    /// Execute a registered operation with validated handler-phase context.
    /// # Errors
    /// Returns the operation's actual API or application failure.
    async fn on_endpoint(
        &self,
        _call: &crate::endpoint::EndpointCall,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<crate::endpoint::EndpointResponse> {
        Err(AuthError::not_implemented(
            "This plugin does not implement trusted endpoint calls",
        ))
    }

    /// Media types accepted before request hooks and endpoint dispatch. An empty
    /// list disables the media restriction for an application-owned endpoint.
    fn allowed_media_types(&self, _route: &AuthRoute) -> Vec<&'static str> {
        vec!["application/json"]
    }

    /// Session field policies contributed by this registered plugin.
    fn session_fields(&self) -> indexmap::IndexMap<String, crate::field_policy::FieldConfig> {
        indexmap::IndexMap::new()
    }

    fn user_fields(&self) -> crate::field_policy::FieldConfigs {
        crate::field_policy::FieldConfigs::new()
    }

    fn account_fields(&self) -> crate::field_policy::FieldConfigs {
        crate::field_policy::FieldConfigs::new()
    }

    /// Documentation annotations collected after all plugins initialize.
    /// Override this hook for custom endpoints and model field policies.
    fn openapi_metadata(&self, _ctx: &AuthInitContext<S>) -> crate::openapi::PluginOpenApiMetadata {
        self.static_openapi_metadata()
    }

    /// Base declarations for documentation without an initialized auth instance.
    fn static_openapi_metadata(&self) -> crate::openapi::PluginOpenApiMetadata {
        crate::openapi::annotations::route_metadata(&self.routes())
    }

    /// Called when the plugin is initialized
    async fn on_init(&self, _ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        Ok(())
    }

    /// Inspect the original physical HTTP request before routing, body parsing,
    /// origin validation and endpoint hooks. Disabled paths and transport/rate
    /// limiting middleware run first. Returning a response stops dispatch and
    /// later plugin hooks. Server-only endpoint calls do not invoke this hook.
    async fn on_http_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }

    /// Inspect or replace the physical request. The default preserves existing
    /// `on_http_request` implementations. Request-local configuration has already
    /// been resolved from the incoming request, matching the Source HTTP handler.
    async fn on_http_request_action(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<HttpRequestAction>> {
        Ok(self
            .on_http_request(req, ctx)
            .await?
            .map(HttpRequestAction::Respond))
    }

    /// Observe the routed HTTP response before transport middleware (including CORS).
    /// Hooks run in registration order; the first replacement stops this chain.
    /// Early HTTP request-hook responses skip this stage. Errors escape dispatch;
    /// they cannot reverse writes already committed by an endpoint.
    async fn on_http_response(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
        _response: &AuthResponse,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }

    /// Called after route matching and before endpoint dispatch.
    ///
    /// Return `Some(BeforeRequestAction::Respond(..))` to short-circuit with a
    /// response, `Some(BeforeRequestAction::InjectSession { .. })` to attach a
    /// virtual session (e.g. API-key → session emulation),
    /// `Some(BeforeRequestAction::ReplaceHeaders { .. })` to transform request
    /// headers, or `None` to continue endpoint dispatch.
    async fn before_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        Ok(None)
    }

    /// Called for each request - return Some(response) to handle, None to pass through
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>>;

    /// Dispatch the resolved HTTP endpoint. Existing plugins return logical
    /// values through `on_request`; plugins returning a native raw response can
    /// override this method to bypass the endpoint after-hook pipeline.
    async fn on_http_endpoint(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<HttpEndpointResponse>> {
        Ok(self
            .on_request(req, ctx)
            .await?
            .map(HttpEndpointResponse::Value))
    }

    /// Transform a completed response, including redirects and rejections.
    ///
    /// Hooks run in plugin registration order with the normalized auth path.
    /// This supports cookie and header lifecycles that span other plugins.
    async fn after_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        Ok(response)
    }

    /// Called after a user is created
    async fn on_user_created(&self, _user: &S::User, _ctx: &AuthContext<S>) -> AuthResult<()> {
        Ok(())
    }

    /// Called after a session is created
    async fn on_session_created(
        &self,
        _session: &S::Session,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        Ok(())
    }

    /// Called before a user is deleted
    async fn on_user_deleted(&self, _user_id: &str, _ctx: &AuthContext<S>) -> AuthResult<()> {
        Ok(())
    }

    /// Called before a session is deleted
    async fn on_session_deleted(
        &self,
        _session_token: &str,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        Ok(())
    }
}

impl<S: AuthSchema> std::fmt::Debug for VerificationEmailOverrideHandle<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationEmailOverrideHandle")
            .finish_non_exhaustive()
    }
}
