mod account;

mod account_cookie;

pub mod encryption;

pub(in crate::plugins) mod handlers;

pub(in crate::plugins) mod id_token;

mod providers;

pub(in crate::plugins) mod state;

mod types;

use async_trait::async_trait;
use better_auth_core::AuthResult;
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};
pub(in crate::plugins) use handlers::{
    OAuthProcessPolicy, OAuthSignInError, create_account_cookie_header, process_oauth_sign_in,
};
pub use id_token::{
    HttpOAuthJwksSource, OAuthIdTokenConfig, OAuthJwksSelection, OAuthJwksSource,
    OAuthNonceComparison,
};
pub use providers::{
    AppleOptions, AtlassianOptions, CloudflareOptions, CognitoOptions, DropboxAccessType,
    DropboxOptions, FacebookOptions, FigmaOptions, HuggingFaceOptions, KakaoOptions, KickOptions, LinkedInOptions,
    OAuthAccountSubject, OAuthAuthorizationPolicy, OAuthCallbackUserName, OAuthCallbackUserPayload,
    OAuthConfig, OAuthIdTokenVerifier, OAuthProvider, OAuthRefreshTokenHandler, OAuthScopeEncoding,
    OAuthScopeOrder, OAuthTokenEndpointAuth, OAuthTokenSet, OAuthUserInfo, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
pub(in crate::plugins) use state::{
    CapturedOAuthServerContext, OAuthServerContext, RecoveredOAuthServerContext,
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
        drop(self.config.providers.insert(name.to_owned(), provider));
        self
    }
}

impl Default for OAuthPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for OAuthPlugin {
    fn name(&self) -> &'static str {
        "oauth"
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

    async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
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
        // Source renews an existing account JWE whenever setCookieCache emits
        // a session cache, unless this endpoint already owns account issuance.
        let account_name =
            better_auth_core::utils::cookie_utils::related_cookie_name(&ctx.config, "account_data");
        let cache_name =
            better_auth_core::utils::cookie_utils::related_cookie_name(&ctx.config, "session_data");
        let account_chunks = format!("{account_name}.");
        let cache_chunks = format!("{cache_name}.");
        let pending: Vec<_> = response
            .headers
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
            return Ok(response);
        }
        let Some((user, _)) = better_auth_core::cache::runtime::published_session(req)
            .or_else(|| req.session_hook_snapshot())
        else {
            return Ok(response);
        };
        let Ok(Some(account)) = handlers::decode_account_cookie(req, &ctx.config) else {
            return Ok(response);
        };
        let header = if account.user_id == user.id {
            handlers::create_account_cookie_header(&ctx.config, &account)?
        } else {
            better_auth_core::utils::cookie_utils::create_clear_cookie(&account_name, &ctx.config)
        };
        response.headers.append("set-cookie", header);
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
