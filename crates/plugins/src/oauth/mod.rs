mod account;
mod endpoint;
pub use account::{OAuthAccountApi, OAuthAccountSelection};
pub(crate) use endpoint::start_social_flow_response;
pub use types::{
    AccessTokenResponse as OAuthAccessToken, AccountInfoAccount as OAuthAccountIdentity,
    AccountInfoResponse as OAuthAccountProfile,
};
mod client_assertion;
pub(crate) use client_assertion::ALGORITHMS as PRIVATE_KEY_JWT_SIGNING_ALGORITHMS;
pub use client_assertion::OAuthPrivateKeyJwtOptions;

pub(crate) mod logout;

mod account_cookie;

pub mod encryption;

pub(crate) mod handlers;

pub(crate) mod id_token;

mod providers;

pub(crate) mod state;

mod types;
use alibi_core::AuthResult;
use alibi_core::{AuthContext, AuthPlugin, AuthRoute};
use alibi_core::{AuthRequest, AuthResponse, HttpMethod};
use async_trait::async_trait;
pub use endpoint::OAuthRefreshResult;
pub(crate) use handlers::{
    OAuthProcessPolicy, OAuthSignInError, create_account_cookie_headers, process_oauth_sign_in,
};
pub use handlers::{oauth_callback_path, oauth_disable_sign_up_option, resolve_oauth_account_key};
pub use id_token::{
    HttpOAuthJwksSource, OAuthIdTokenClaimsVerifier, OAuthIdTokenConfig, OAuthJwksSelection,
    OAuthJwksSource, OAuthNonceComparison,
};
pub use providers::{
    AppleOptions, AtlassianOptions, CloudflareOptions, CognitoOptions, DropboxAccessType,
    DropboxOptions, FacebookOptions, FigmaOptions, GenericOAuthConfig, GenericOAuthError,
    GenericOAuthMetadata, GenericOAuthResolved, HuggingFaceOptions, KakaoOptions, KickOptions,
    LineOptions, LinearOptions, LinkedInOptions, MicrosoftOptions, MicrosoftProfilePhotoSize,
    NaverOptions, NotionOptions, OAuthAccountKey, OAuthAccountKeyContext, OAuthAccountKeyResolver,
    OAuthAccountSubject, OAuthAuthorizationCodeCallback, OAuthAuthorizationCodeContext,
    OAuthAuthorizationCodeHandler, OAuthAuthorizationPolicy, OAuthCallbackUserName,
    OAuthCallbackUserPayload, OAuthClientAssertion, OAuthClientAssertionContext,
    OAuthClientAssertionGetter, OAuthConfig, OAuthEndSessionConfig, OAuthIdTokenVerifier,
    OAuthProfileMapper, OAuthProvider, OAuthRefreshContext, OAuthRefreshTokenHandler,
    OAuthRefreshTokenParams, OAuthRefreshTokenParamsResolver, OAuthScopeEncoding, OAuthScopeOrder,
    OAuthTokenEndpointAuth, OAuthTokenGrant, OAuthTokenSet, OAuthUserInfo, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse, PayPalEnvironment, PayPalOptions, PaybinOptions,
    PolarOptions, RailwayOptions, RedditOptions, RobloxOptions, SalesforceEnvironment,
    SalesforceOptions, SlackOptions, SpotifyOptions, TikTokOptions, TwitchOptions, TwitterOptions,
    VercelOptions, VkOptions, WeChatLanguage, WeChatOptions, ZoomOptions,
};
pub(crate) use state::{
    CapturedOAuthServerContext, OAuthServerContext, RecoveredOAuthServerContext,
};
pub use types::{
    LinkSocialRequest as OAuthLinkSocialRequest, OAuthCallbackInput, OAuthIdTokenRequest,
    SocialSignInRequest as OAuthSocialSignInRequest,
    SocialSignInResponse as OAuthSocialSignInResponse,
};

pub struct OAuthPlugin {
    config: OAuthConfig,
}

impl OAuthPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: OAuthConfig::default(),
        }
    }

    #[must_use]
    pub const fn with_config(config: OAuthConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn add_provider(mut self, name: &str, provider: OAuthProvider) -> Self {
        _ = self.config.providers.insert(name.to_owned(), provider);
        self
    }

    /// Resolve a generic provider's discovery now and register it. When
    /// discovery leaves it unusable, the provider is skipped and discovery is
    /// retried by the next request that names it, until it succeeds.
    /// # Errors
    /// Returns a configuration error that discovery cannot fix.
    pub async fn add_generic_provider(
        mut self,
        name: &str,
        config: GenericOAuthConfig,
    ) -> Result<Self, GenericOAuthError> {
        if let Some(resolved) = config.clone().resolve().await? {
            return Ok(self.add_provider(name, resolved.provider));
        }
        _ = std::sync::Arc::make_mut(&mut self.config.deferred)
            .insert(name.to_owned(), providers::DeferredDiscovery::new(config));
        Ok(self)
    }
}

/// The provider an endpoint call names, read as the generic plugin's retry
/// matcher does: `body.provider`, `body.providerId`, `query.provider`, then the
/// path's `id`.
fn requested_provider(call: &alibi_core::endpoint::EndpointCall) -> Option<&str> {
    use alibi_core::utils::json::JsValue;
    fn field<'a>(input: Option<&'a JsValue>, key: &str) -> Option<&'a JsValue> {
        input
            .and_then(|input| input.get(key))
            .filter(|value| !matches!(value, JsValue::Null))
    }
    field(call.body(), "provider")
        .or_else(|| field(call.body(), "providerId"))
        .or_else(|| field(call.query(), "provider"))
        .or_else(|| field(call.params(), "id"))
        .and_then(JsValue::as_str)
}

impl Default for OAuthPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<S: alibi_core::AuthSchema> AuthPlugin<S> for OAuthPlugin {
    route_openapi_metadata!(S);

    fn name(&self) -> &'static str {
        "oauth"
    }

    fn server_endpoints(&self) -> Vec<alibi_core::endpoint::EndpointDefinition> {
        endpoint::definitions()
    }
    fn validate_endpoint(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        _: &AuthContext<S>,
    ) -> AuthResult<alibi_core::endpoint::EndpointInput> {
        endpoint::validate(call)
    }
    async fn on_endpoint(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<alibi_core::endpoint::EndpointResponse> {
        if call.operation_id() == "handleOAuthCallback" {
            return self.call_callback_endpoint(call, ctx).await;
        }
        if call.operation_id() == "linkSocialAccount" {
            return self.call_link_endpoint(call, ctx).await;
        }
        if call.operation_id() == "socialSignIn" {
            return self.call_social_endpoint(call, ctx).await;
        }
        self.call_account_endpoint(call, ctx).await
    }

    fn endpoint_hooks(&self) -> Vec<&dyn alibi_core::endpoint::EndpointHook<S>> {
        vec![self]
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/sign-in/social", "social_sign_in"),
            AuthRoute::get("/callback/{provider}", "oauth_callback")
                .with_context_path("/callback/:id"),
            AuthRoute::post("/callback/{provider}", "oauth_callback_post")
                .with_context_path("/callback/:id"),
            AuthRoute::post("/link-social", "link_social"),
            AuthRoute::post("/get-access-token", "get_access_token"),
            AuthRoute::post("/refresh-token", "refresh_token"),
            AuthRoute::get("/account-info", "account_info"),
        ]
    }

    async fn on_init(&self, ctx: &mut alibi_core::AuthInitContext<S>) -> AuthResult<()> {
        ctx.extensions.insert(self.config.clone());
        Ok(())
    }

    fn allowed_media_types(&self, route: &AuthRoute) -> Vec<&'static str> {
        if route.path == "/callback/{provider}" {
            vec!["application/x-www-form-urlencoded", "application/json"]
        } else {
            vec!["application/json"]
        }
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/sign-in/social") => Ok(Some(
                handlers::handle_social_sign_in(&self.config, req, ctx).await?,
            )),
            (HttpMethod::Get | HttpMethod::Post, path) if path_matches_callback(path) => {
                let provider = extract_provider_from_callback(path);
                Ok(Some(
                    handlers::handle_callback(&self.config, &provider, req, ctx).await?,
                ))
            }
            (HttpMethod::Post, "/link-social") => Ok(Some(
                handlers::handle_link_social(&self.config, req, ctx).await?,
            )),
            (HttpMethod::Post, "/get-access-token") => Ok(Some(
                account::handle_get_access_token(&self.config, req, ctx).await?,
            )),
            (HttpMethod::Post, "/refresh-token") => Ok(Some(
                account::handle_refresh_token(&self.config, req, ctx).await?,
            )),
            (HttpMethod::Get, "/account-info") => Ok(Some(
                account::handle_account_info(&self.config, req, ctx).await?,
            )),
            _ => Ok(None),
        }
    }

    async fn after_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        for header in Self::cache_account_headers(req, ctx, &response.headers)? {
            response.headers.append("set-cookie", header);
        }
        Ok(response)
    }
}

impl std::fmt::Debug for OAuthPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthPlugin").finish_non_exhaustive()
    }
}

/// Check if the path matches `/callback/{provider}` (with optional query string).
fn path_matches_callback(path: &str) -> bool {
    let path_without_query = path.split('?').next().unwrap_or(path);
    path_without_query
        .strip_prefix("/callback/")
        .is_some_and(|provider| !provider.is_empty() && !provider.contains('/'))
}

/// Extract the provider name from `/callback/{provider}?...`.
fn extract_provider_from_callback(path: &str) -> String {
    let path_without_query = path.split('?').next().unwrap_or(path);
    path_without_query
        .strip_prefix("/callback/")
        .unwrap_or_default()
        .to_owned()
}

impl OAuthPlugin {
    fn cache_account_headers<S: alibi_core::AuthSchema>(
        req: &impl alibi_core::session::SessionRequest,
        ctx: &AuthContext<S>,
        headers: &alibi_core::Headers,
    ) -> AuthResult<Vec<String>> {
        // Source renews an existing account JWE whenever setCookieCache emits
        // a session cache, unless this endpoint already owns account issuance.
        let account_name =
            alibi_core::utils::cookie_utils::related_cookie_name(&ctx.config, "account_data");
        let cache_name =
            alibi_core::utils::cookie_utils::related_cookie_name(&ctx.config, "session_data");
        let account_chunks = format!("{account_name}.");
        let cache_chunks = format!("{cache_name}.");
        let pending: Vec<_> = headers
            .get_all("set-cookie")
            .filter_map(|raw| cookie::Cookie::parse(raw.clone()).ok())
            .collect();
        if !ctx.config.account.store_account_cookie
            || pending.iter().any(|cookie| {
                cookie.name() == account_name || cookie.name().starts_with(&account_chunks)
            })
            || !pending.iter().any(|cookie| {
                (cookie.name() == cache_name || cookie.name().starts_with(&cache_chunks))
                    && !cookie.value().is_empty()
                    && cookie.max_age().is_none_or(|age| age.whole_seconds() != 0)
            })
        {
            return Ok(Vec::new());
        }
        let Some((user, _)) = alibi_core::session::cookie_cache::runtime::published_session(req)
            .or_else(|| {
                req.endpoint_call()
                    .and_then(alibi_core::endpoint::EndpointCall::session_hook_snapshot)
            })
            .or_else(|| {
                req.physical_request()
                    .and_then(AuthRequest::session_hook_snapshot)
            })
        else {
            return Ok(Vec::new());
        };
        let Ok(Some(account)) = handlers::decode_account_cookie(req, &ctx.config) else {
            return Ok(Vec::new());
        };
        let headers = if account.user_id == user.id {
            handlers::create_account_cookie_headers(&ctx.config, &account, req)?
        } else {
            alibi_core::session::cookie_cache::runtime::chunked_cookie_headers(
                &account_name,
                "",
                Some(0.0),
                &ctx.config,
                req.session_headers(),
                true,
            )?
        };
        Ok(headers)
    }
}

#[async_trait]
impl<S: alibi_core::AuthSchema> alibi_core::endpoint::EndpointHook<S> for OAuthPlugin {
    fn matches_before(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<bool> {
        Ok(requested_provider(call).is_some_and(|name| self.config.awaits_discovery(name)))
    }
    async fn before(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<alibi_core::endpoint::BeforeEndpointAction>> {
        if let Some(name) = requested_provider(call) {
            self.config.retry_discovery(name).await;
        }
        Ok(None)
    }
    async fn after(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        ctx: &AuthContext<S>,
        mut response: alibi_core::endpoint::EndpointResponse,
    ) -> AuthResult<alibi_core::endpoint::EndpointResponse> {
        for header in Self::cache_account_headers(call, ctx, response.headers())? {
            response = response.with_header("set-cookie", header);
        }
        Ok(response)
    }
}
