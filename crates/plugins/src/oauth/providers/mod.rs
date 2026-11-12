macro_rules! js {
    ($($tokens:tt)*) => { alibi_core::utils::json::JsValue::from(serde_json::json!($($tokens)*)) };
}
pub(crate) use js;

mod discord;
mod generic;
mod github;
mod gitlab;
mod google;
pub(super) mod remaining_profile;
pub(crate) use generic::DeferredDiscovery;
pub use generic::{
    GenericOAuthConfig, GenericOAuthError, GenericOAuthMetadata, GenericOAuthResolved,
};
mod roblox;
pub use roblox::RobloxOptions;
mod salesforce;
pub use salesforce::{SalesforceEnvironment, SalesforceOptions};
mod slack;
pub use slack::SlackOptions;
mod spotify;
pub use spotify::SpotifyOptions;
mod tiktok;
pub use tiktok::TikTokOptions;
mod twitch;
pub use twitch::TwitchOptions;
mod twitter;
pub use twitter::TwitterOptions;
mod vercel;
pub use vercel::VercelOptions;
mod vk;
pub use vk::VkOptions;
mod wechat;
pub use wechat::{WeChatLanguage, WeChatOptions};
mod zoom;
pub use zoom::ZoomOptions;

mod reddit;
pub use reddit::RedditOptions;
mod railway;
pub use railway::RailwayOptions;
mod paypal;
pub use paypal::{PayPalEnvironment, PayPalOptions};

mod paybin;
pub use paybin::PaybinOptions;
mod polar;
pub use polar::PolarOptions;

mod notion;
pub use notion::NotionOptions;

mod cloudflare;
pub use cloudflare::CloudflareOptions;

mod cognito;
pub use cognito::CognitoOptions;

mod dropbox;
pub use dropbox::{DropboxAccessType, DropboxOptions};
mod figma;
pub use figma::FigmaOptions;

mod facebook;
pub use facebook::FacebookOptions;

mod atlassian;
pub use atlassian::AtlassianOptions;

mod apple;
pub use apple::AppleOptions;

mod microsoft;
use alibi_core::utils::json::{JsObject as Map, JsString, JsValue as Value};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
pub use microsoft::{MicrosoftOptions, MicrosoftProfilePhotoSize};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

/// Trusted OIDC logout endpoint and optional default return URI.
#[derive(Debug, Clone)]
pub struct OAuthEndSessionConfig {
    pub endpoint: String,
    pub post_logout_redirect_uri: Option<String>,
}

/// Configuration for the OAuth plugin, containing all registered providers.
#[derive(Clone, Default)]
pub struct OAuthConfig {
    pub providers: HashMap<String, OAuthProvider>,
    /// Generic providers whose startup discovery left them unusable. Shared by
    /// every clone, so a provider recovered by one request serves all later ones.
    pub(crate) deferred: Arc<HashMap<String, generic::DeferredDiscovery>>,
}

impl OAuthConfig {
    /// The provider registered as `name`. A generic provider recovered after
    /// failed startup discovery takes precedence, as it was registered first.
    #[must_use]
    pub fn provider(&self, name: &str) -> Option<&OAuthProvider> {
        self.deferred
            .get(name)
            .and_then(generic::DeferredDiscovery::provider)
            .or_else(|| self.providers.get(name))
    }

    /// Whether `name` is a generic provider still waiting for discovery.
    pub(crate) fn awaits_discovery(&self, name: &str) -> bool {
        self.deferred
            .get(name)
            .is_some_and(|deferred| deferred.provider().is_none())
    }

    /// Retries discovery for a provider skipped at startup. Concurrent requests
    /// share one attempt, and a failed attempt leaves the provider pending.
    pub(crate) async fn retry_discovery(&self, name: &str) {
        if let Some(deferred) = self.deferred.get(name) {
            deferred.retry().await;
        }
    }
}

/// A provider grant, and the typed result of [`OAuthAccountApi`](crate::oauth::OAuthAccountApi)'s
/// token operations.
#[derive(Debug, Clone, Default)]
pub struct OAuthTokenSet {
    pub token_type: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub id_token: Option<String>,
    pub raw: Option<Value>,
}

/// User information extracted from an OAuth provider's user info endpoint.
#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    /// Trusted mapped application values; writes select initialized declared input fields.
    pub additional_fields: Map,
    pub id: JsString,
    pub email: JsString,
    pub name: Option<JsString>,
    pub image: Option<JsString>,
    pub email_verified: bool,
}

impl OAuthUserInfo {
    pub(crate) fn from_fields(fields: &Map, subject: Option<&JsString>) -> Self {
        let scalar = |name| match fields.get(name) {
            Some(Value::String(value)) => Some(value.clone()),
            Some(Value::Number(value)) => Some(ryu_js::Buffer::new().format(*value).into()),
            Some(Value::Bool(value)) => Some(value.to_string().into()),
            _ => None,
        };
        Self {
            id: subject
                .cloned()
                .or_else(|| scalar("id"))
                .unwrap_or_default(),
            email: fields
                .get("email")
                .and_then(Value::as_js_string)
                .cloned()
                .unwrap_or_default(),
            name: scalar("name"),
            image: scalar("image"),
            email_verified: email_verified_claim(fields.get("emailVerified")),
            additional_fields: fields.clone(),
        }
    }
    /// Original mapped public values. This is output, never account authority.
    #[must_use]
    pub fn public_profile(&self, include_id: bool) -> Map {
        let mut output = self.additional_fields.clone();
        _ = output.insert("email".into(), Value::String(self.email.clone().into()));
        _ = output.insert("emailVerified".into(), Value::Bool(self.email_verified));
        if include_id {
            _ = output.insert("id".into(), Value::String(self.id.clone().into()));
        }
        if let Some(name) = &self.name {
            _ = output.insert("name".into(), Value::String(name.clone().into()));
        }
        if let Some(image) = &self.image {
            _ = output.insert("image".into(), Value::String(image.clone().into()));
        }
        output
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, Deserialize)]
pub struct OAuthCallbackUserPayload {
    pub name: Option<OAuthCallbackUserName>,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthCallbackUserName {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthUserInfoRequest {
    /// The route has verified a client-submitted ID token, rather than a code grant.
    pub client_submitted_id_token: bool,
    pub token_type: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub id_token: Option<String>,
    pub raw: Option<Value>,
    pub user: Option<OAuthCallbackUserPayload>,
}

impl OAuthUserInfoRequest {
    /// Profile lookup carrying a granted token set and the callback's user payload.
    #[must_use]
    pub fn from_tokens(tokens: &OAuthTokenSet, user: Option<OAuthCallbackUserPayload>) -> Self {
        Self {
            client_submitted_id_token: false,
            token_type: tokens.token_type.clone(),
            access_token: tokens.access_token.clone(),
            refresh_token: tokens.refresh_token.clone(),
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scopes: tokens.scopes.clone(),
            id_token: tokens.id_token.clone(),
            raw: tokens.raw.clone(),
            user,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OAuthUserInfoResponse {
    /// Source user object, independent from stable account authority.
    pub user: Map,
    pub data: Value,
    /// Stable account authority resolved independently from mapped public fields.
    pub account_subject: Option<JsString>,
}

/// Resolve a provider's stable account identity from its original profile.
pub type OAuthAccountSubject = fn(&Value) -> Result<JsString, String>;

#[async_trait]
pub trait OAuthUserInfoHandler: Send + Sync {
    /// Retain factory-specific use of the original configured client array.
    fn configured_client_ids(&self, _ids: &[String]) -> Option<Arc<dyn OAuthUserInfoHandler>> {
        None
    }

    /// Reconfigure built-in Google admission without wrapping application handlers.
    fn configured_hosted_domain(&self, _domain: &str) -> Option<Arc<dyn OAuthUserInfoHandler>> {
        None
    }

    /// Custom application callbacks throw on failure; factory transports can
    /// return a missing profile and tag only their uncaught projection failures.
    fn errors_are_exceptions(&self) -> bool {
        true
    }

    /// Factory handlers can install application mapping before projecting raw
    /// profile fields. Custom getUserInfo callbacks retain their precedence.
    fn mapped_handler(
        &self,
        _mapper: Arc<dyn OAuthProfileMapper>,
    ) -> Option<Arc<dyn OAuthUserInfoHandler>> {
        None
    }

    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String>;

    async fn get_user_info_from_id_token(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        self.get_user_info(request).await
    }
}

pub(crate) fn email_verified_claim(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(true))) || value.and_then(Value::as_str) == Some("true")
}

/// Asynchronous partial application mapping of the original provider profile.
/// Absent keys retain published defaults; raw output remains independent from
/// typed persistence, and returned IDs never replace original account authority.
#[async_trait]
pub trait OAuthProfileMapper: Send + Sync {
    async fn map_profile(&self, profile: Value) -> Result<Map, String>;
}

pub(super) fn apply_application_mapping(
    response: &mut OAuthUserInfoResponse,
    mapped: Map,
) -> Result<(), String> {
    response.user.extend(mapped);
    Ok(())
}

/// Metadata of the request triggering an OAuth token refresh.
/// Headers, cookies and body fields are untrusted. Applications must validate
/// tenant/scope/audience entitlements before forwarding derived values.
#[derive(Clone, Copy)]
pub struct OAuthRefreshContext<'a> {
    pub request: &'a alibi_core::AuthRequest,
}

/// An asynchronous alternative to static `refreshTokenParams`.
#[async_trait]
pub trait OAuthRefreshTokenParamsResolver: Send + Sync {
    async fn resolve(
        &self,
        context: Option<OAuthRefreshContext<'_>>,
    ) -> Result<Option<std::collections::BTreeMap<String, String>>, String>;
}

#[derive(Clone)]
pub struct OAuthRefreshTokenParams(pub Arc<dyn OAuthRefreshTokenParamsResolver>);
impl std::fmt::Debug for OAuthRefreshTokenParams {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OAuthRefreshTokenParams(..)")
    }
}

#[async_trait]
pub trait OAuthRefreshTokenHandler: Send + Sync {
    /// Reconfigure a factory transport that directly interpolates client IDs.
    fn configured_client_ids(&self, _ids: &[String]) -> Option<Arc<dyn OAuthRefreshTokenHandler>> {
        None
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthTokenSet, String>;

    /// Context-aware application handlers may override this method. Existing
    /// factory handlers retain their token-only implementation.
    async fn refresh_access_token_with_context(
        &self,
        refresh_token: &str,
        _context: Option<OAuthRefreshContext<'_>>,
    ) -> Result<OAuthTokenSet, String> {
        self.refresh_access_token(refresh_token).await
    }
}

#[async_trait]
pub trait OAuthIdTokenVerifier: Send + Sync {
    async fn verify_id_token(&self, token: &str, nonce: Option<&str>) -> Result<bool, String>;
}

/// The actual token grant for an application's asynchronous client assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthTokenGrant {
    AuthorizationCode,
    RefreshToken,
}

#[derive(Debug, Clone)]
pub struct OAuthClientAssertionContext {
    pub client_id: String,
    pub token_endpoint: String,
    pub grant_type: OAuthTokenGrant,
}

/// Produces a fresh application credential for the actual bound token request.
#[async_trait]
pub trait OAuthClientAssertionGetter: Send + Sync {
    async fn get_client_assertion(
        &self,
        context: OAuthClientAssertionContext,
    ) -> Result<String, String>;
}

/// Cloneable application callback whose Debug output never prints credentials.
#[derive(Clone)]
pub struct OAuthClientAssertion(pub Arc<dyn OAuthClientAssertionGetter>);

impl std::fmt::Debug for OAuthClientAssertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthClientAssertion")
            .finish_non_exhaustive()
    }
}

/// Configuration for a single OAuth provider.
#[derive(Clone, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Preserve independent public provider policy switches"
)]
pub struct OAuthProvider {
    pub client_id: String,
    /// Additional Google client IDs accepted when verifying ID tokens.
    pub additional_client_ids: Vec<String>,
    /// Google Workspace domain restriction, independently of authorization parameters.
    pub hosted_domain: Option<String>,
    /// Require a verified provider email before creating the authentication session.
    pub require_email_verification: bool,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: Option<String>,
    pub scopes: Vec<String>,
    /// Built-in authorization behavior. `None` preserves custom-provider behavior.
    /// `scopes` remains the provider's base scope list; this policy adds configured
    /// and request scopes in the provider's published order.
    pub authorization: Option<OAuthAuthorizationPolicy>,
    pub authorization_params: Vec<(String, String)>,
    /// Query parameter names accepted from per-request `authorizationParams`.
    /// Empty by default. Unlisted names and reserved OAuth parameters are ignored.
    /// Allowed values override `authorization_params` and `additionalParams`,
    /// but provider policy's `fixed_authorization_params` take precedence.
    pub allowed_request_params: Vec<String>,
    /// Selects the factory account subject from the original provider profile.
    pub account_subject: Option<OAuthAccountSubject>,
    pub map_user_info: Option<fn(Value) -> Result<Map, String>>,
    pub get_user_info: Option<Arc<dyn OAuthUserInfoHandler>>,
    pub refresh_access_token: Option<Arc<dyn OAuthRefreshTokenHandler>>,
    /// Application override takes precedence over the trusted built-in JWKS policy.
    pub verify_id_token: Option<Arc<dyn OAuthIdTokenVerifier>>,
    pub id_token: Option<super::id_token::OAuthIdTokenConfig>,
    /// Disable the complete ID-token branch, including an application verifier override.
    pub disable_id_token_sign_in: bool,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    /// Start a new state-bound authorization flow for a callback without state.
    pub allow_idp_initiated: bool,
    pub override_user_info_on_sign_in: bool,
}

/// Ordering of configured and per-request additions to a provider's base scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthScopeOrder {
    ConfiguredThenRequested,
    RequestedThenConfigured,
}

/// Encoding of the scope query value required by a provider's authorization endpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OAuthScopeEncoding {
    #[default]
    Form,
    UriComponent,
}

/// OAuth token-endpoint credential transport selected by a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthTokenEndpointAuth {
    ClientSecretBasic,
    ClientSecretPost,
    PrivateKeyJwt,
    None,
    /// `TikTok` authenticates with `client_key` and `client_secret`, never `client_id`.
    ClientKeyPost,
}

/// Post transport for a confidential client, or none when no secret is configured.
pub(super) fn client_secret_auth(client_secret: Option<&str>) -> OAuthTokenEndpointAuth {
    if client_secret.is_some_and(|secret| !secret.is_empty()) {
        OAuthTokenEndpointAuth::ClientSecretPost
    } else {
        OAuthTokenEndpointAuth::None
    }
}

#[derive(Debug, Clone)]
pub struct OAuthAuthorizationCodeContext {
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub device_id: Option<String>,
}

#[async_trait]
pub trait OAuthAuthorizationCodeHandler: Send + Sync {
    /// Reconfigure a factory transport that directly interpolates client IDs.
    fn configured_client_ids(
        &self,
        _ids: &[String],
    ) -> Option<Arc<dyn OAuthAuthorizationCodeHandler>> {
        None
    }

    async fn validate_authorization_code(
        &self,
        context: OAuthAuthorizationCodeContext,
    ) -> Result<OAuthTokenSet, String>;
}

#[derive(Clone)]
pub struct OAuthAuthorizationCodeCallback(pub Arc<dyn OAuthAuthorizationCodeHandler>);
impl std::fmt::Debug for OAuthAuthorizationCodeCallback {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OAuthAuthorizationCodeCallback(..)")
    }
}

/// Raw provider profile and actual grant tokens for application account authority.
#[derive(Debug, Clone)]
pub struct OAuthAccountKeyContext {
    pub tokens: OAuthTokenSet,
    pub profile: Value,
}
#[async_trait]
pub trait OAuthAccountKeyResolver: Send + Sync {
    async fn resolve(&self, context: OAuthAccountKeyContext) -> Result<Value, String>;
}
#[derive(Clone)]
pub struct OAuthAccountKey(pub Arc<dyn OAuthAccountKeyResolver>);
impl std::fmt::Debug for OAuthAccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthAccountKey").finish_non_exhaustive()
    }
}

/// Immutable authorization configuration used by the built-in social providers.
/// Scope entries retain their original order and whitespace; providers may
/// opt into removing exact duplicates.
#[derive(Debug, Clone)]
pub struct OAuthAuthorizationPolicy {
    /// Optional application subject resolver; precedes the profile-only factory subject.
    pub account_key: Option<OAuthAccountKey>,
    /// Application callback path, normalized relative to the authentication base.
    pub callback_path: Option<String>,
    /// Preserve explicit false separately from absent provider signup configuration.
    pub disable_sign_up_option: Option<bool>,
    /// Trusted discovery issuer for authorization-response mixup protection.
    pub issuer: Option<String>,
    /// RP-initiated logout from trusted generic-provider configuration.
    pub end_session: Option<OAuthEndSessionConfig>,
    /// Verify code-grant ID tokens against trusted discovery metadata before profile admission.
    pub verify_grant_id_token: bool,
    /// Bind discovered ID tokens to a nonce in authenticated OAuth state.
    pub id_token_nonce_binding: bool,
    /// Discovery advertised OIDC signing algorithms; prepend openid if absent.
    pub discovery_openid_scope: bool,
    /// Application-owned or provider-specific code grant implementation.
    pub authorization_code: Option<OAuthAuthorizationCodeCallback>,
    /// A code grant can retain PKCE even when authorization disables it (Zoom).
    pub authorization_code_pkce: Option<bool>,
    /// Name of the client identifier in custom authorization URLs.
    pub client_id_parameter: String,
    /// Custom URL factories may interpolate the entire client array.
    pub literal_client_id: Option<String>,
    /// `WeChat`'s custom factory constructs an expiry even for zero/null seconds.
    pub token_expiry_always: bool,
    /// Custom factory token objects can omit returned grant ID tokens.
    pub token_response_omits_id_token: bool,
    pub scope_separator: String,
    pub emit_empty_scope: bool,
    pub authorization_fragment: Option<String>,
    /// Dedicated factories may lack a built-in refresh implementation (Vercel).
    pub supports_refresh: bool,
    /// `TikTok`'s published factory ignores mapProfileToUser.
    pub supports_profile_mapper: bool,
    /// Published social factories pass through omitted access tokens to userinfo.
    pub allow_missing_access_token: bool,
    /// Generic-provider fallback, applied only when a grant omits actual expiry.
    pub default_access_token_expires_in: Option<f64>,
    pub configured_scopes: Vec<String>,
    /// Providers such as `PayPal` deliberately omit even configured/requested scopes.
    pub omit_scopes: bool,
    pub scope_encoding: OAuthScopeEncoding,
    /// Retain the first occurrence of each scope, as Cloudflare requires.
    pub deduplicate_scopes: bool,
    pub require_client_id: bool,
    /// `None` preserves the existing generic provider credential transport.
    pub token_endpoint_auth: Option<OAuthTokenEndpointAuth>,
    /// Grant-specific authentication when refresh differs from code exchange.
    pub refresh_token_endpoint_auth: Option<OAuthTokenEndpointAuth>,
    /// Provider parameters applied after caller additions.
    pub fixed_authorization_params: Vec<(String, String)>,
    /// Optional application client key sent in authorization-code forms only.
    pub authorization_code_client_key: Option<String>,
    /// Trusted provider headers applied to authorization-code grants only.
    pub authorization_code_headers: Vec<(String, String)>,
    /// Trusted additional code-grant form fields (`tokenUrlParams`). Fields
    /// already supplied by the grant, including PKCE, are preserved. Token
    /// authentication is applied afterwards and retains credential authority.
    pub authorization_code_params: std::collections::BTreeMap<String, String>,
    /// Trusted static refresh form fields (`refreshTokenParams`). Ordinary
    /// fields replace defaults; grant type and refresh token cannot be replaced.
    /// Validate tenant, scope, and audience entitlements before configuring them.
    pub refresh_token_params: std::collections::BTreeMap<String, String>,
    /// When configured, replaces the static map at each default refresh grant.
    /// `Ok(None)` supplies no additions; errors abort before transport/writes.
    /// Custom refresh handlers take precedence and bypass this resolver.
    pub refresh_token_params_resolver: Option<OAuthRefreshTokenParams>,
    /// Required by `private_key_jwt`; invoked afresh for each real token grant.
    pub client_assertion: Option<OAuthClientAssertion>,
    /// Exact configured refresh scope, including an explicitly empty value.
    pub refresh_scope: Option<String>,
    pub response_type: String,
    /// Application callback URI overrides the generated provider callback.
    pub redirect_uri: Option<String>,
    pub response_mode: Option<String>,
    pub require_client_secret: bool,
    pub login_hint: bool,
    pub disable_default_scopes: bool,
    pub scope_order: OAuthScopeOrder,
    pub pkce: bool,
    /// Published factory name when authorization requires a PKCE verifier.
    pub code_verifier_required_for: Option<&'static str>,
    pub prompt: Option<String>,
    /// Used when `prompt` is absent or empty; Discord defaults to `none`.
    pub default_prompt: Option<String>,
    /// Discord emits this JS number only when the effective scopes contain `bot`.
    pub discord_permissions: Option<f64>,
    /// Preserve thrown decoded grant-profile failures instead of redirecting.
    /// Missing/falsy ID tokens still follow the absent-profile redirect.
    pub propagate_grant_profile_errors: bool,
    /// Preserve effective raw email type errors at their callback stage.
    /// Typed native profile fields remain unchanged.
    pub preserve_raw_email_errors: bool,
    /// Retain the published adapter scalar rather than discarding it in bool projection.
    pub preserve_raw_profile_scalars: bool,
    /// Some published factories omit their returned options object entirely.
    pub honor_factory_options: bool,
    /// Preserve uncaught published profile/application callback exceptions.
    pub source_profile_exceptions: bool,
}

impl Default for OAuthAuthorizationPolicy {
    fn default() -> Self {
        Self {
            account_key: None,
            callback_path: None,
            disable_sign_up_option: None,
            issuer: None,
            end_session: None,
            verify_grant_id_token: false,
            id_token_nonce_binding: false,
            discovery_openid_scope: false,
            authorization_code: None,
            authorization_code_pkce: None,
            client_id_parameter: "client_id".into(),
            literal_client_id: None,
            token_expiry_always: false,
            token_response_omits_id_token: false,
            scope_separator: " ".into(),
            emit_empty_scope: false,
            authorization_fragment: None,
            supports_refresh: true,
            supports_profile_mapper: true,
            default_access_token_expires_in: None,
            allow_missing_access_token: false,
            configured_scopes: Vec::new(),
            omit_scopes: false,
            scope_encoding: OAuthScopeEncoding::Form,
            deduplicate_scopes: false,
            require_client_id: false,
            token_endpoint_auth: None,
            refresh_token_endpoint_auth: None,
            fixed_authorization_params: Vec::new(),
            authorization_code_client_key: None,
            authorization_code_headers: Vec::new(),
            authorization_code_params: std::collections::BTreeMap::new(),
            refresh_token_params: std::collections::BTreeMap::new(),
            refresh_token_params_resolver: None,
            client_assertion: None,
            refresh_scope: None,
            response_type: "code".into(),
            redirect_uri: None,
            response_mode: None,
            require_client_secret: false,
            login_hint: true,
            disable_default_scopes: false,
            scope_order: OAuthScopeOrder::ConfiguredThenRequested,
            pkce: true,
            code_verifier_required_for: None,
            prompt: None,
            default_prompt: None,
            discord_permissions: None,
            propagate_grant_profile_errors: false,
            preserve_raw_email_errors: false,
            preserve_raw_profile_scalars: false,
            honor_factory_options: true,
            source_profile_exceptions: false,
        }
    }
}

impl OAuthProvider {
    /// Install asynchronous partial mapping on the dedicated factory's profile
    /// handler. Installing a custom userinfo handler afterwards replaces both
    /// the default transport and mapping, matching getUserInfo precedence.
    #[must_use]
    pub fn with_profile_mapper(mut self, mapper: Arc<dyn OAuthProfileMapper>) -> Self {
        if self
            .authorization
            .as_ref()
            .is_none_or(|policy| policy.supports_profile_mapper)
            && let Some(handler) = self.get_user_info.take()
        {
            self.get_user_info = Some(handler.mapped_handler(mapper).unwrap_or(handler));
        }
        self
    }

    #[must_use]
    pub fn with_client_ids(mut self, client_ids: Vec<String>) -> Self {
        if let Some(handler) = self
            .get_user_info
            .as_ref()
            .and_then(|handler| handler.configured_client_ids(&client_ids))
        {
            self.get_user_info = Some(handler);
        }
        if let Some(handler) = self
            .refresh_access_token
            .as_ref()
            .and_then(|handler| handler.configured_client_ids(&client_ids))
        {
            self.refresh_access_token = Some(handler);
        }
        if let Some(policy) = self.authorization.as_mut() {
            if policy.client_id_parameter == "appid" {
                policy.literal_client_id = Some(client_ids.join(","));
            }
            if let Some(handler) = policy
                .authorization_code
                .as_ref()
                .and_then(|callback| callback.0.configured_client_ids(&client_ids))
            {
                policy.authorization_code = Some(OAuthAuthorizationCodeCallback(handler));
            }
        }
        if let Some(policy) = self.id_token.as_mut() {
            policy.client_ids = Some(client_ids.clone());
        }
        let mut ids = client_ids.into_iter();
        self.client_id = ids.next().unwrap_or_default();
        self.additional_client_ids = ids.collect();
        self
    }

    #[must_use]
    pub const fn require_email_verification(mut self, required: bool) -> Self {
        self.require_email_verification = required;
        self
    }
}

impl std::fmt::Debug for OAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthConfig").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for OAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthProvider").finish_non_exhaustive()
    }
}

mod huggingface;
mod kakao;
mod kick;
mod line;
pub use huggingface::HuggingFaceOptions;
pub use kakao::KakaoOptions;
pub use kick::KickOptions;
pub use line::LineOptions;

mod naver;
pub use naver::NaverOptions;

// LCOV_EXCL_START
#[cfg(test)]
pub(crate) mod test_support {
    use super::{OAuthProfileMapper, OAuthProvider, OAuthUserInfoRequest, OAuthUserInfoResponse};
    use alibi_core::utils::json::{JsObject, JsValue};

    /// Asserts the shared public-profile shape of a partial mapping test.
    pub(crate) fn assert_partial_profile_mapping(user: &JsObject, mapped: bool) {
        let name = if mapped { "Mapped" } else { "Original" };
        assert_eq!(user.get("email"), Some(&JsValue::Null));
        assert_eq!(user.get("image"), Some(&JsValue::Null));
        assert_eq!(user["name"], name);
        assert_eq!(user.get("name").and_then(JsValue::as_str), Some(name));
        if mapped {
            assert_eq!(user["id"], "public-id");
            assert_eq!(user["custom"], true);
        } else {
            assert!(!user.contains_key("id"));
        }
    }

    /// Asserts raw fields survive the user envelope while undefined keys are dropped on the wire.
    pub(crate) fn assert_undefined_wire_fields(
        user: JsObject,
        mapped: bool,
        expected_wire: JsValue,
        undefined_keys: &[&str],
    ) {
        let mut expected_user = expected_wire.as_object().unwrap().clone();
        for key in undefined_keys {
            _ = expected_user.insert((*key).into(), JsValue::Undefined);
            assert_eq!(user.get(*key), Some(&JsValue::Undefined), "{key}");
        }
        assert_eq!(user, expected_user);
        assert_eq!(user.contains_key("id"), mapped);
        let bytes = alibi_core::utils::json::stringify(&JsValue::Object(user))
            .unwrap()
            .unwrap();
        let encoded: JsValue = alibi_core::utils::json::from_slice(&bytes).unwrap();
        assert_eq!(encoded, expected_wire);
        for key in undefined_keys {
            assert!(encoded.get(*key).is_none(), "{key}");
        }
    }

    /// Fetches the profile with a fixed access token through the provider's handler.
    pub(crate) async fn access_token_profile(
        provider: &OAuthProvider,
    ) -> Result<OAuthUserInfoResponse, String> {
        provider
            .get_user_info
            .as_ref()
            .unwrap()
            .get_user_info(OAuthUserInfoRequest {
                access_token: Some("access".into()),
                ..Default::default()
            })
            .await
    }

    /// Profile mapper that returns the same partial public profile every time.
    pub(crate) struct PartialProfileMapper(pub JsValue);

    #[async_trait::async_trait]
    impl OAuthProfileMapper for PartialProfileMapper {
        async fn map_profile(&self, profile: JsValue) -> Result<JsObject, String> {
            assert_eq!(profile, self.0);
            Ok(
                alibi_core::utils::json::from_value(crate::oauth::providers::js!({
                    "id": "public-id", "name": "Mapped", "custom": true
                }))
                .unwrap(),
            )
        }
    }

    /// Profile mapper whose sparse result keeps only the declared public fields.
    pub(crate) struct SparseProfileMapper(pub JsValue);

    #[async_trait::async_trait]
    impl OAuthProfileMapper for SparseProfileMapper {
        async fn map_profile(&self, profile: JsValue) -> Result<JsObject, String> {
            assert_eq!(profile, self.0);
            let mut mapped = crate::oauth::providers::js!({
                "id": "public-id", "name": null, "email": null,
                "emailVerified": 0, "custom": false
            })
            .as_object()
            .unwrap()
            .clone();
            _ = mapped.insert("image".into(), JsValue::Undefined);
            Ok(mapped)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    async fn start_github_mock_server(
        profile: Value,
        emails: Value,
    ) -> (String, String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = std::sync::Arc::clone(&requests);

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let profile = profile.clone();
                let emails = emails.clone();
                let requests_2 = std::sync::Arc::clone(&captured_requests);
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 4096];
                    let read = stream.read(&mut buffer).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(
                        (buffer)
                            .get(..read)
                            .expect("fixture contains the requested index"),
                    )
                    .to_string();
                    requests_2.lock().await.push(request.clone());

                    let (status, body) = if request.contains("/user/emails") {
                        ("200 OK", emails.to_string())
                    } else if request.contains("/user") {
                        ("200 OK", profile.to_string())
                    } else {
                        (
                            "404 Not Found",
                            crate::oauth::providers::js!({ "error": "not found" }).to_string(),
                        )
                    };

                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len(),
                    );

                    _ = stream.write_all(response.as_bytes()).await;
                    _ = stream.flush().await;
                });
            }
        });

        let base_url = format!("http://127.0.0.1:{}", addr.port());
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        (
            format!("{base_url}/user"),
            format!("{base_url}/user/emails"),
            requests,
        )
    }

    // Upstream source: packages/core/src/social-providers/github.ts :: github().createAuthorizationURL default scope list.
    #[test]
    fn github_provider_uses_ts_default_scopes() {
        let provider = OAuthProvider::github("github-client-id", "github-client-secret");

        assert_eq!(
            provider.scopes,
            vec!["read:user".to_owned(), "user:email".to_owned()]
        );
        assert!(provider.get_user_info.is_some());
        assert!(provider.map_user_info.is_none());
    }

    // Upstream source: packages/core/src/social-providers/github.ts :: github().getUserInfo fallback from profile.email to /user/emails, login fallback for name, and request headers.
    #[tokio::test]
    async fn github_provider_get_user_info_uses_email_fallback_and_login_name() {
        let (user_url, emails_url, requests) = start_github_mock_server(
            crate::oauth::providers::js!({
                "id": 42,
                "login": "octocat",
                "name": null,
                "email": null,
                "avatar_url": "https://avatars.githubusercontent.com/u/42?v=4",
            }),
            crate::oauth::providers::js!([
                {
                    "email": "octocat@example.com",
                    "primary": true,
                    "verified": true,
                    "visibility": "private"
                },
                {
                    "email": "secondary@example.com",
                    "primary": false,
                    "verified": false,
                    "visibility": "private"
                }
            ]),
        )
        .await;

        let provider = OAuthProvider::github_with_endpoints(
            "github-client-id",
            "github-client-secret",
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            &user_url,
            &emails_url,
        );
        let handler = provider.get_user_info.as_ref().unwrap();

        let response = handler
            .get_user_info(OAuthUserInfoRequest {
                access_token: Some("github-access-token".to_owned()),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(response.user["id"], "42");
        assert_eq!(response.user["email"], "octocat@example.com");
        assert_eq!(
            response.user.get("name").and_then(Value::as_str),
            Some("octocat")
        );
        assert_eq!(
            response.user.get("image").and_then(Value::as_str),
            Some("https://avatars.githubusercontent.com/u/42?v=4")
        );
        assert!(
            response
                .user
                .get("emailVerified")
                .is_some_and(Value::is_truthy)
        );
        assert_eq!(
            (*(response.data)
                .get("email")
                .expect("fixture contains the requested index")),
            crate::oauth::providers::js!("octocat@example.com")
        );

        let requests = requests.lock().await;
        assert_eq!(requests.len(), 2);
        for request in requests.iter() {
            let lowered = request.to_ascii_lowercase();
            assert!(lowered.contains("authorization: bearer github-access-token"));
            assert!(lowered.contains("user-agent: better-auth"));
        }
    }

    // Upstream source: packages/core/src/social-providers/github.ts :: github().getUserInfo keeps profile.email when present and resolves verified status from the matching email record.
    #[tokio::test]
    async fn github_provider_get_user_info_keeps_inline_email() {
        let (user_url, emails_url, _) = start_github_mock_server(
            crate::oauth::providers::js!({
                "id": "github-inline-email",
                "login": "octocat",
                "name": "Octo Cat",
                "email": "public@example.com",
                "avatar_url": null,
            }),
            crate::oauth::providers::js!([
                {
                    "email": "primary@example.com",
                    "primary": true,
                    "verified": true,
                    "visibility": "private"
                },
                {
                    "email": "public@example.com",
                    "primary": false,
                    "verified": false,
                    "visibility": "public"
                }
            ]),
        )
        .await;

        let provider = OAuthProvider::github_with_endpoints(
            "github-client-id",
            "github-client-secret",
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            &user_url,
            &emails_url,
        );
        let handler = provider.get_user_info.as_ref().unwrap();

        let response = handler
            .get_user_info(OAuthUserInfoRequest {
                access_token: Some("github-access-token".to_owned()),
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(response.user["email"], "public@example.com");
        assert_eq!(
            response.user.get("name").and_then(Value::as_str),
            Some("Octo Cat")
        );
        assert!(
            !response
                .user
                .get("emailVerified")
                .is_some_and(Value::is_truthy)
        );
    }
}
// LCOV_EXCL_STOP

mod linkedin;
pub use linkedin::LinkedInOptions;
mod linear;
pub use linear::LinearOptions;

#[cfg(test)]
mod admission_tests {
    use super::*;
    use crate::oauth::handlers::{callback_core, fetch_user_info_from_provider};
    use crate::oauth::state::{OAuthStatePayload, state_verification_identifier};
    use alibi_core::utils::json::JsObject as Map;
    use alibi_core::{
        AuthError, AuthRequest, AuthResponse, CreateVerification, HttpMethod, OAuthStateStrategy,
    };
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub(super) struct HttpFixture {
        pub(super) url: String,
        server: tokio::task::JoinHandle<()>,
    }
    impl HttpFixture {
        pub(super) async fn new(status: u16, body: Value) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = [0; 8192];
                    let _ = stream.read(&mut request).await.unwrap();
                    let inspect = request.starts_with(b"GET /inspect?");
                    let status = if inspect { 200 } else { status };
                    let body = if inspect {
                        crate::oauth::providers::js!({"data":{"is_valid":true,"app_id":"client","user_id":"1"}})
                        .to_string()
                    } else {
                        body.to_string()
                    };
                    stream.write_all(format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
                ).as_bytes()).await.unwrap();
                }
            });
            Self { url, server }
        }
    }
    impl Drop for HttpFixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    struct RawIdMapper(Value);
    #[async_trait]
    impl OAuthProfileMapper for RawIdMapper {
        async fn map_profile(&self, _: Value) -> Result<Map, String> {
            Ok(crate::oauth::providers::js!({"id": self.0})
                .as_object()
                .unwrap()
                .clone())
        }
    }

    #[tokio::test]
    async fn mapped_public_ids_do_not_run_object_to_primitive_coercion() {
        use base64::Engine;
        for mapped_id in [
            crate::oauth::providers::js!({"toString":0}),
            crate::oauth::providers::js!([{"toString":0}]),
            Value::Null,
        ] {
            let profile = crate::oauth::providers::js!({"sub":"subject","email":"a@example.com"});
            let token = format!(
                "h.{}.s",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(profile.to_string())
            );
            let mut generic = GenericOAuthConfig::new("client", "secret");
            generic.map_profile = Some(Arc::new(RawIdMapper(mapped_id.clone())));
            for provider in [
                OAuthProvider::google("client", "secret")
                    .with_profile_mapper(Arc::new(RawIdMapper(mapped_id.clone()))),
                generic.resolve().await.unwrap().unwrap().provider,
            ] {
                let response = fetch_user_info_from_provider(
                    &provider,
                    OAuthUserInfoRequest {
                        id_token: Some(token.clone()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
                assert_eq!(response.user["id"], mapped_id);
                assert_eq!(response.data["sub"], "subject");
                assert_eq!(
                    provider.account_subject.unwrap()(&response.data).unwrap(),
                    "subject"
                );
            }
        }
    }

    pub(super) struct RejectMapper;
    #[async_trait]
    impl OAuthProfileMapper for RejectMapper {
        async fn map_profile(&self, _: Value) -> Result<Map, String> {
            Err("application mapping threw".into())
        }
    }
    pub(super) struct RejectHandler;
    #[async_trait]
    impl OAuthUserInfoHandler for RejectHandler {
        async fn get_user_info(
            &self,
            _: OAuthUserInfoRequest,
        ) -> Result<OAuthUserInfoResponse, String> {
            Err("application profile handler threw".into())
        }
    }
    struct Grant(OAuthTokenSet);
    #[async_trait]
    impl OAuthAuthorizationCodeHandler for Grant {
        async fn validate_authorization_code(
            &self,
            _: OAuthAuthorizationCodeContext,
        ) -> Result<OAuthTokenSet, String> {
            Ok(self.0.clone())
        }
    }

    fn provider(name: &str, endpoint: &str) -> OAuthProvider {
        macro_rules! endpoint_provider {
            ($options:ident, $factory:ident) => {{
                let mut options = $options::new("client", Some("secret".into()));
                options.user_info_endpoint = Some(endpoint.into());
                OAuthProvider::$factory(options)
            }};
        }
        match name {
            "atlassian" => {
                let mut options = AtlassianOptions::new("client", "secret");
                options.user_info_endpoint = Some(endpoint.into());
                OAuthProvider::atlassian_with_options(options)
            }
            "dropbox" => endpoint_provider!(DropboxOptions, dropbox_with_options),
            "figma" => endpoint_provider!(FigmaOptions, figma_with_options),
            "huggingface" => endpoint_provider!(HuggingFaceOptions, huggingface_with_options),
            "kakao" => endpoint_provider!(KakaoOptions, kakao_with_options),
            "kick" => endpoint_provider!(KickOptions, kick_with_options),
            "line" => endpoint_provider!(LineOptions, line_with_options),
            "linear" => endpoint_provider!(LinearOptions, linear_with_options),
            "linkedin" => endpoint_provider!(LinkedInOptions, linkedin_with_options),
            "facebook" => {
                let mut options = FacebookOptions::new("client", Some("secret".into()));
                options.user_info_endpoint = Some(endpoint.into());
                options.token_inspection_endpoint = Some(format!("{endpoint}/inspect"));
                OAuthProvider::facebook_with_options(options)
            }
            "cloudflare" => {
                let mut options = CloudflareOptions::new("client", Some("secret".into()));
                options.user_info_endpoint = Some(endpoint.into());
                OAuthProvider::cloudflare_with_options(options)
            }
            "cognito" => {
                let mut options = CognitoOptions::new(
                    "client",
                    Some("secret".into()),
                    "example.com",
                    "us-east-1",
                    "us-east-1_pool",
                );
                options.user_info_endpoint = Some(endpoint.into());
                OAuthProvider::cognito(options).unwrap()
            }
            "paypal" => {
                let mut options = PayPalOptions::new("client", "secret");
                options.user_info_endpoint = Some(endpoint.into());
                OAuthProvider::paypal_with_options(options)
            }
            "github" => OAuthProvider::github_with_endpoints(
                "client", "secret", endpoint, endpoint, endpoint, endpoint,
            ),
            "gitlab" => OAuthProvider::gitlab_with_issuer("client", "secret", endpoint),
            _ => panic!("unregistered fixture {name}"),
        }
    }

    pub(super) fn request() -> OAuthUserInfoRequest {
        OAuthUserInfoRequest {
            access_token: Some("access".into()),
            ..Default::default()
        }
    }
    fn is_exception(error: &AuthError) -> bool {
        matches!(error, AuthError::Api { code: Some(code), .. } if code == "OAUTH_PROFILE_EXCEPTION")
    }
    pub(super) async fn callback(
        mut provider: OAuthProvider,
        tokens: OAuthTokenSet,
    ) -> AuthResponse {
        provider.authorization.as_mut().unwrap().authorization_code =
            Some(OAuthAuthorizationCodeCallback(Arc::new(Grant(tokens))));
        let mut config = crate::test_helpers::create_test_config();
        config.account.store_state_strategy = OAuthStateStrategy::Database;
        config.account.skip_state_cookie_check = true;
        let ctx = crate::test_helpers::create_test_context_with_config(config).await;
        let payload = OAuthStatePayload::new(
            "http://localhost:3000/done".into(),
            "verifier".into(),
            None,
            None,
            None,
            None,
            serde_json::Map::new(),
        );
        ctx.verifications()
            .create(CreateVerification {
                identifier: state_verification_identifier("state"),
                value: serde_json::to_string(&payload).unwrap(),
                expires_at: Utc::now() + Duration::minutes(10),
            })
            .await
            .unwrap()
            .unwrap();
        let config = OAuthConfig {
            providers: HashMap::from([("provider".into(), provider)]),
            ..Default::default()
        };
        callback_core(
            &config,
            "provider",
            &HashMap::from([
                ("state".into(), "state".into()),
                ("code".into(), "code".into()),
            ]),
            &AuthRequest::new(HttpMethod::Get, "/callback/provider"),
            &ctx,
        )
        .await
        .unwrap()
    }
    pub(super) async fn assert_outcome(
        provider: OAuthProvider,
        request: OAuthUserInfoRequest,
        exception: bool,
    ) {
        let error = fetch_user_info_from_provider(&provider, request.clone())
            .await
            .unwrap_err();
        assert_eq!(is_exception(&error), exception, "{error:?}");
        let response = callback(
            provider,
            OAuthTokenSet {
                access_token: request.access_token,
                id_token: request.id_token,
                raw: request.raw,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(response.status, if exception { 500 } else { 302 });
        if exception {
            assert!(!response.headers.contains_key("location"));
            assert!(!response.headers.contains_key("set-cookie"));
        } else {
            assert!(response.headers["location"].contains("unable_to_get_user_info"));
            assert!(response.headers.contains_key("set-cookie"));
        }
    }

    #[tokio::test]
    async fn dedicated_profiles_distinguish_null_transport_and_mapping_exceptions_through_callback()
    {
        let profile = crate::oauth::providers::js!({
            "id":"1", "sub":"subject", "oid":"object", "user_id":"user", "account_id":"account",
            "state":"active", "email":"user@example.com", "name":"User",
            "picture":{"data":{"url":"https://example.com/photo"}},
            "data":[{"user_id":1,"name":"User","email":"user@example.com"}],
            "success":true, "result":{"id":"cf","email":"user@example.com"}
        });
        for name in [
            "atlassian",
            "cloudflare",
            "cognito",
            "dropbox",
            "facebook",
            "figma",
            "github",
            "gitlab",
            "huggingface",
            "kakao",
            "kick",
            "line",
            "linear",
            "linkedin",
            "paypal",
        ] {
            let mut body = profile.clone();
            if name == "linear" {
                body =
                    crate::oauth::providers::js!({"data":{"viewer":{"id":"viewer","name":"User"}}});
            }
            let server = HttpFixture::new(200, body).await;
            let mapped = provider(name, &server.url).with_profile_mapper(Arc::new(RejectMapper));
            let caught = matches!(name, "atlassian" | "cognito" | "figma" | "paypal");
            assert_outcome(mapped, request(), !caught).await;

            let failure = HttpFixture::new(500, Value::Null).await;
            assert_outcome(provider(name, &failure.url), request(), false).await;

            let mut custom = provider(name, &server.url);
            custom.get_user_info = Some(Arc::new(RejectHandler));
            assert_outcome(custom, request(), true).await;
        }
    }

    #[tokio::test]
    async fn dedicated_raw_fields_and_account_subjects_do_not_require_scalar_profiles() {
        for name in [
            "atlassian",
            "cloudflare",
            "cognito",
            "dropbox",
            "figma",
            "huggingface",
            "kakao",
            "kick",
            "line",
            "linear",
            "linkedin",
        ] {
            for subject in [
                crate::oauth::providers::js!({}),
                crate::oauth::providers::js!(["raw", 7]),
                Value::Null,
            ] {
                let raw = crate::oauth::providers::js!({
                    "id":subject, "sub":subject, "account_id":subject, "user_id":subject,
                    "email":{"raw":true}, "name":{"raw":true}, "handle":{"raw":true},
                    "picture":{"raw":true}, "img_url":{"raw":true}, "avatarUrl":{"raw":true},
                    "kakao_account":{"email":{"raw":true},"profile":{"nickname":{"raw":true}}},
                });
                let body = match name {
                    "cloudflare" => crate::oauth::providers::js!({"success":true,"result":raw}),
                    "kick" => crate::oauth::providers::js!({"data":[raw]}),
                    "linear" => crate::oauth::providers::js!({"data":{"viewer":raw}}),
                    _ => raw.clone(),
                };
                let server = HttpFixture::new(200, body).await;
                let provider = provider(name, &server.url);
                let response = fetch_user_info_from_provider(&provider, request())
                    .await
                    .unwrap_or_else(|error| panic!("{name}: {error:?}"));
                assert_eq!(response.data, raw, "{name}");
                let expected = super::remaining_profile::raw_subject(Some(&subject));
                assert_eq!(
                    provider.account_subject.unwrap()(&response.data),
                    expected,
                    "{name}"
                );
                assert!(!response.user.is_empty(), "{name}");
            }
        }
        let provider = OAuthProvider::facebook("client", "secret");
        for subject in [
            crate::oauth::providers::js!({}),
            crate::oauth::providers::js!(["raw", 7]),
            Value::Null,
        ] {
            assert_eq!(
                provider.account_subject.unwrap()(
                    &crate::oauth::providers::js!({"sub":subject,"id":"fallback"})
                ),
                super::remaining_profile::raw_subject(Some(&subject))
            );
        }
    }

    #[tokio::test]
    async fn kick_profile_indexing_accepts_object_properties_and_bmp_strings() {
        for (rows, expected) in [
            (
                crate::oauth::providers::js!({"0":{"user_id":"one","name":"User"}}),
                crate::oauth::providers::js!({"user_id":"one","name":"User"}),
            ),
            (
                crate::oauth::providers::js!("éz"),
                crate::oauth::providers::js!("é"),
            ),
        ] {
            let server = HttpFixture::new(200, crate::oauth::providers::js!({"data":rows})).await;
            let response = fetch_user_info_from_provider(&provider("kick", &server.url), request())
                .await
                .unwrap();
            assert_eq!(response.data, expected);
        }
        struct NullMapper(Arc<std::sync::atomic::AtomicUsize>);
        #[async_trait]
        impl OAuthProfileMapper for NullMapper {
            async fn map_profile(&self, profile: Value) -> Result<Map, String> {
                assert_eq!(profile, Value::Null);
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(Map::new())
            }
        }
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server = HttpFixture::new(200, crate::oauth::providers::js!({"data":{"0":null}})).await;
        assert_outcome(
            provider("kick", &server.url).with_profile_mapper(Arc::new(NullMapper(calls.clone()))),
            request(),
            true,
        )
        .await;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cloudflare_name_join_coercion_is_a_source_exception() {
        let server = HttpFixture::new(
            200,
            crate::oauth::providers::js!({
                "success":true, "result":{"id":"cf","first_name":{"toString":0}}
            }),
        )
        .await;
        assert_outcome(provider("cloudflare", &server.url), request(), true).await;
    }

    #[tokio::test]
    async fn repository_profiles_defer_missing_subject_admission_until_after_mapping() {
        for (name, profile) in [
            (
                "github",
                crate::oauth::providers::js!({"email":"a@example.com"}),
            ),
            (
                "gitlab",
                crate::oauth::providers::js!({"state":"active","email":"a@example.com"}),
            ),
        ] {
            let server = HttpFixture::new(200, profile).await;
            let provider = provider(name, &server.url);
            let response = fetch_user_info_from_provider(&provider, request())
                .await
                .unwrap();
            assert!(provider.account_subject.unwrap()(&response.data).is_err());
            assert_outcome(
                provider.with_profile_mapper(Arc::new(RejectMapper)),
                request(),
                true,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn dedicated_null_profile_admission_matches_source_checks() {
        for (name, throws) in [
            ("atlassian", false),
            ("cloudflare", false),
            ("cognito", false),
            ("dropbox", true),
            ("facebook", false),
            ("figma", false),
            ("github", false),
            ("gitlab", true),
            ("huggingface", true),
            ("kakao", false),
            ("kick", true),
            ("line", false),
            ("linear", false),
            ("linkedin", true),
            ("paypal", false),
        ] {
            let server = HttpFixture::new(200, Value::Null).await;
            assert_outcome(provider(name, &server.url), request(), throws).await;
        }
    }

    #[tokio::test]
    async fn jwt_profile_admission_distinguishes_absence_decode_and_mapping_exceptions() {
        let mut microsoft = MicrosoftOptions::new("client", Some("secret".into()));
        microsoft.disable_profile_photo = true;
        for provider in [
            OAuthProvider::apple("client", "secret"),
            OAuthProvider::google("client", "secret"),
            OAuthProvider::microsoft(microsoft).unwrap(),
            OAuthProvider::twitch("client", Some("secret")),
        ] {
            assert_outcome(provider.clone(), request(), false).await;
            assert_outcome(
                provider.clone(),
                OAuthUserInfoRequest {
                    id_token: Some("malformed".into()),
                    ..request()
                },
                true,
            )
            .await;
            use base64::Engine;
            let token = format!(
                "e30.{}.sig",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(r#"{"sub":"subject","oid":"object"}"#)
            );
            assert_outcome(
                provider.with_profile_mapper(Arc::new(RejectMapper)),
                OAuthUserInfoRequest {
                    id_token: Some(token),
                    ..request()
                },
                true,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn microsoft_verification_throws_after_mapping_and_uses_raw_email() {
        use base64::Engine;
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountMapper(Arc<AtomicUsize>);
        #[async_trait]
        impl OAuthProfileMapper for CountMapper {
            async fn map_profile(&self, _: Value) -> Result<Map, String> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(Map::new())
            }
        }
        let count = Arc::new(AtomicUsize::new(0));
        let mut options = MicrosoftOptions::new("client", None);
        options.disable_profile_photo = true;
        let provider = OAuthProvider::microsoft(options)
            .unwrap()
            .with_profile_mapper(Arc::new(CountMapper(count.clone())));
        for (list, verified) in [
            (crate::oauth::providers::js!([7]), true),
            (crate::oauth::providers::js!(["7"]), false),
            (crate::oauth::providers::js!("prefix7suffix"), true),
        ] {
            let profile = crate::oauth::providers::js!({"oid":"object","email":7,"verified_primary_email":list});
            let token = format!(
                "e30.{}.sig",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(profile.to_string())
            );
            let response = fetch_user_info_from_provider(
                &provider,
                OAuthUserInfoRequest {
                    id_token: Some(token),
                    ..request()
                },
            )
            .await
            .unwrap();
            assert_eq!(response.user["emailVerified"], verified);
        }
        let token = format!(
            "e30.{}.sig",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(r#"{"oid":"object","email":7,"verified_primary_email":true}"#)
        );
        assert_outcome(
            provider,
            OAuthUserInfoRequest {
                id_token: Some(token),
                ..request()
            },
            true,
        )
        .await;
        assert_eq!(count.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn apple_missing_subject_still_runs_mapper_before_account_admission() {
        assert_outcome(
            OAuthProvider::apple("client", "secret").with_profile_mapper(Arc::new(RejectMapper)),
            OAuthUserInfoRequest {
                id_token: Some("e30.e30.sig".into()),
                ..request()
            },
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn facebook_inspection_null_and_custom_handler_throw_are_distinct() {
        let server = HttpFixture::new(200, Value::Null).await;
        let mut options = FacebookOptions::new("client", Some("secret".into()));
        options.token_inspection_endpoint = Some(format!("{}/inspect", server.url));
        options.get_user_info = Some(Arc::new(RejectHandler));
        assert_outcome(
            OAuthProvider::facebook_with_options(options.clone()),
            request(),
            true,
        )
        .await;
        options.token_inspection_endpoint = Some(server.url.clone());
        assert_outcome(
            OAuthProvider::facebook_with_options(options),
            request(),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn facebook_missing_picture_is_a_source_exception_not_profile_null() {
        let server = HttpFixture::new(
            200,
            crate::oauth::providers::js!({"id":"1","email":"user@example.com"}),
        )
        .await;
        assert_outcome(provider("facebook", &server.url), request(), true).await;
    }
}
