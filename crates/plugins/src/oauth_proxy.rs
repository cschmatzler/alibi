//! OAuth code exchange on a production host, followed by stateful completion on
//! the originating preview host with database or authenticated cookie state.
use super::oauth::handlers::{
    OAuthSignInError, complete_link_social, create_account_cookie_headers,
    fetch_user_info_from_provider, parse_callback_user_payload,
    validate_authorization_code_via_provider,
};
use super::oauth::state::{
    OAuthStatePayload, RecoveredOAuthServerContext, decode_cookie_state_value, get_cookie,
    state_cookie_name, state_verification_identifier, verified_server_context,
};
use super::oauth::{
    OAuthConfig, OAuthProcessPolicy, OAuthTokenSet, OAuthUserInfo, OAuthUserInfoRequest,
    oauth_callback_path, oauth_disable_sign_up_option, resolve_oauth_account_key,
};
use super::token_crypto::EncryptionPurpose;
use alibi_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, AuthSession, BeforeRequestAction, HttpMethod, OAuthStateStrategy,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};

struct OAuthProxyUnhandledError(AtomicBool);

/// Immutable application configuration.
///
/// URLs are application origins; the auth
/// base path is appended to the production URL. A dedicated secret can be shared
/// between hosts independently of their ordinary authentication secrets.
#[derive(Clone)]
pub struct OAuthProxyConfig {
    pub current_url: Option<String>,
    pub production_url: Option<String>,
    pub max_age_seconds: f64,
    pub secret: Option<String>,
}

impl std::fmt::Debug for OAuthProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthProxyConfig")
            .field("current_url", &self.current_url)
            .field("production_url", &self.production_url)
            .field("max_age_seconds", &self.max_age_seconds)
            .field("secret", &self.secret.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl Default for OAuthProxyConfig {
    fn default() -> Self {
        Self {
            current_url: None,
            production_url: None,
            max_age_seconds: 60.0,
            secret: None,
        }
    }
}

#[derive(Clone, Default)]
pub struct OAuthProxyPlugin {
    config: OAuthProxyConfig,
}

#[derive(Clone)]
pub(crate) struct OAuthProxyFlow {
    pub(crate) effective_auth_base_url: String,
    pub(crate) callback_url: String,
}

#[derive(Clone)]
pub(crate) struct IssuedProxyState {
    pub(crate) state: String,
    pub(crate) payload: OAuthStatePayload,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatePackage {
    state: String,
    state_cookie: String,
    #[serde(rename = "isOAuthProxy")]
    is_oauth_proxy: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyUser {
    id: String,
    email: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<String>,
    #[serde(flatten)]
    additional_fields: alibi_core::field_policy::FieldOutput,
    #[serde(default)]
    email_verified: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyAccount {
    provider_id: String,
    account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "alibi_core::utils::datetime::serialize_optional"
    )]
    access_token_expires_at: Option<DateTime<Utc>>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "alibi_core::utils::datetime::serialize_optional"
    )]
    refresh_token_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyPayload {
    user_info: ProxyUser,
    account: ProxyAccount,
    #[serde(
        default,
        deserialize_with = "alibi_core::utils::json::deserialize_optional_value"
    )]
    profile: Option<Value>,
    scopes: Option<Vec<String>>,
    state: String,
    #[serde(rename = "callbackURL")]
    callback_url: String,
    #[serde(rename = "newUserURL", skip_serializing_if = "Option::is_none")]
    new_user_url: Option<String>,
    #[serde(rename = "errorURL", skip_serializing_if = "Option::is_none")]
    error_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disable_sign_up: Option<bool>,
    timestamp: f64,
}

impl OAuthProxyPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub const fn with_config(config: OAuthProxyConfig) -> Self {
        Self { config }
    }
    fn encrypt<S: AuthSchema>(
        &self,
        plain: &str,
        ctx: &AuthContext<S>,
        purpose: EncryptionPurpose,
    ) -> AuthResult<String> {
        match &self.config.secret {
            Some(secret) => super::token_crypto::encrypt_for_purpose(plain, secret, purpose),
            None => {
                super::token_crypto::encrypt_with_config_for_purpose(plain, &ctx.config, purpose)
            }
        }
    }
    fn decrypt<S: AuthSchema>(
        &self,
        stored: &str,
        ctx: &AuthContext<S>,
        purpose: EncryptionPurpose,
    ) -> AuthResult<String> {
        match &self.config.secret {
            Some(secret) => super::token_crypto::decrypt_for_purpose(stored, secret, purpose),
            None => {
                super::token_crypto::decrypt_with_config_for_purpose(stored, &ctx.config, purpose)
            }
        }
    }
    fn current<S: AuthSchema>(&self, req: &AuthRequest, ctx: &AuthContext<S>) -> String {
        if let Some(value) = self
            .config
            .current_url
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            return value.clone();
        }
        if let Some(url) = req.url()
            && ctx
                .config
                .is_redirect_target_trusted(&url.origin().ascii_serialization())
        {
            return url.to_string();
        }
        if let Some(url) = vendor_base_url().filter(|value| {
            url::Url::parse(value).is_ok_and(|url| !matches!(url.origin(), url::Origin::Opaque(_)))
        }) {
            return url;
        }
        ctx.config.base_url.clone()
    }
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "Preserve JavaScript Number rounding at the compatibility boundary"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep proxy state verification, persistence, and redirect construction in protocol order"
    )]
    async fn forward<S: AuthSchema>(
        &self,
        provider_id: &str,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        // Source defu(query, body): query values win, missing/null body
        // values only supply defaults. Keep this request-local for concurrent hosts.
        let body = req.body_as_json::<Value>().ok();
        let mut params = std::collections::HashMap::new();
        if let Some(object) = body.as_ref().and_then(Value::as_object) {
            params.extend(object.iter().filter_map(|(key, value)| {
                value.as_str().map(|value| (key.clone(), value.to_owned()))
            }));
        }
        params.extend(
            req.query
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        let Some(encrypted) = params.get("state") else {
            return Ok(None);
        };
        let Ok(plain) = self.decrypt(encrypted, ctx, EncryptionPurpose::ProxyPackage) else {
            return Ok(None);
        };
        let Ok(package) = alibi_core::utils::json::from_slice::<StatePackage>(plain.as_bytes())
        else {
            return Ok(None);
        };
        if !package.is_oauth_proxy || package.state.is_empty() || package.state_cookie.is_empty() {
            return Ok(None);
        }
        let Ok(plain_2) = self.decrypt(&package.state_cookie, ctx, EncryptionPurpose::ProxyState)
        else {
            return Ok(None);
        };
        let Ok(state) =
            alibi_core::utils::json::from_slice::<OAuthStatePayload>(plain_2.as_bytes())
        else {
            return Ok(None);
        };
        let error_url = state
            .error_url
            .clone()
            .filter(|value| !value.is_empty())
            .or_else(|| {
                ctx.config
                    .api_error_url
                    .clone()
                    .filter(|value| !value.is_empty())
            })
            .unwrap_or_else(|| format!("{}/error", auth_base(ctx)));
        if state
            .additional_data
            .get("oauthState")
            .is_some_and(|nonce| nonce.as_str() != Some(package.state.as_str()))
        {
            return Ok(Some(error_redirect(&error_url, "state_mismatch", None)?));
        }
        if let Some(error) = params.get("error").filter(|value| !value.is_empty()) {
            return Ok(Some(error_redirect(&error_url, error, None)?));
        }
        let Some(code) = params.get("code").filter(|value| !value.is_empty()) else {
            return Ok(Some(error_redirect(&error_url, "no_code", None)?));
        };
        let oauth = ctx
            .extensions
            .get::<OAuthConfig>()
            .ok_or_else(|| AuthError::config("OAuth proxy requires OAuthPlugin"))?;
        let Some(provider) = oauth.providers.get(provider_id) else {
            return Ok(Some(error_redirect(
                &error_url,
                "oauth_provider_not_found",
                None,
            )?));
        };
        let Ok(tokens) = validate_authorization_code_via_provider(
            provider,
            code,
            &format!(
                "{}{}",
                auth_base(ctx),
                oauth_callback_path(provider_id, provider)
            ),
            provider
                .authorization
                .as_ref()
                .is_none_or(|policy| policy.pkce)
                .then_some(state.code_verifier.as_str()),
            params.get("device_id").map(String::as_str),
        )
        .await
        else {
            return Ok(Some(error_redirect(&error_url, "invalid_code", None)?));
        };
        // Like the source proxy middleware, application/profile lookup errors
        // propagate; only an absent profile is a redirect-level failure.
        let mut info = fetch_user_info_from_provider(
            provider,
            OAuthUserInfoRequest {
                token_type: tokens.token_type.clone(),
                access_token: tokens.access_token.clone(),
                refresh_token: tokens.refresh_token.clone(),
                access_token_expires_at: tokens.access_token_expires_at,
                refresh_token_expires_at: tokens.refresh_token_expires_at,
                scopes: tokens.scopes.clone(),
                id_token: tokens.id_token.clone(),
                raw: tokens.raw.clone(),
                user: parse_callback_user_payload(params.get("user").map(String::as_str)),
            },
        )
        .await?;
        if info.user.email.is_empty() {
            return Ok(Some(error_redirect(&error_url, "email_not_found", None)?));
        }
        if resolve_oauth_account_key(provider, &tokens, &mut info)
            .await
            .is_err()
        {
            return Ok(Some(error_redirect(
                &error_url,
                "unable_to_get_user_info",
                None,
            )?));
        }
        let mut callback = url::Url::parse(&state.callback_url)
            .map_err(|_error| AuthError::internal("Invalid proxy callback URL"))?;
        let callback_url = callback
            .query_pairs()
            .find(|(key, _)| key == "callbackURL")
            .map_or_else(
                || state.callback_url.clone(),
                |(_, value)| value.into_owned(),
            );
        let payload = ProxyPayload {
            user_info: ProxyUser {
                id: info.user.id.clone(),
                email: info.user.email,
                name: info.user.name.unwrap_or_default(),
                image: info.user.image,
                additional_fields: Default::default(),
                email_verified: info.user.email_verified,
            },
            profile: Some(info.data),
            scopes: Some(tokens.scopes.clone()),
            account: ProxyAccount {
                provider_id: provider_id.to_owned(),
                account_id: info.user.id,
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                id_token: tokens.id_token,
                access_token_expires_at: tokens.access_token_expires_at,
                refresh_token_expires_at: tokens.refresh_token_expires_at,
                scope: Some(tokens.scopes.join(",")),
            },
            state: package.state,
            callback_url,
            new_user_url: state.new_user_url,
            error_url: state.error_url,
            disable_sign_up: if provider.disable_implicit_sign_up
                && !state.request_sign_up.unwrap_or(false)
            {
                Some(true)
            } else {
                oauth_disable_sign_up_option(provider)
            },
            timestamp: Utc::now().timestamp_millis() as f64,
        };
        _ = callback.query_pairs_mut().append_pair(
            "profile",
            &self.encrypt(
                &alibi_core::utils::json::to_string(&payload)?,
                ctx,
                EncryptionPurpose::ProxyProfile,
            )?,
        );
        Ok(Some(redirect(callback.as_str())))
    }
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "Preserve JavaScript Number rounding at the compatibility boundary"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep proxy state consumption, identity linking, and session issuance in protocol order"
    )]
    async fn complete<S: AuthSchema>(
        &self,
        provider_id: Option<&str>,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let callback = req
            .query
            .get("callbackURL")
            .ok_or_else(|| AuthError::bad_request("Missing callbackURL"))?;
        if !ctx.config.current_origin_check_disabled()
            && !ctx.config.is_redirect_target_trusted(callback)
        {
            return Err(AuthError::forbidden("Invalid callbackURL"));
        }
        let default_error = ctx
            .config
            .api_error_url
            .clone()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                format!(
                    "{}/api/auth/error",
                    ctx.config.base_url.trim_end_matches('/')
                )
            });
        let Some(profile) = req
            .query
            .get("profile")
            .filter(|profile| !profile.is_empty())
        else {
            return error_redirect(&default_error, "missing_profile", None);
        };
        let Ok(plain) = self.decrypt(profile, ctx, EncryptionPurpose::ProxyProfile) else {
            return error_redirect(&default_error, "invalid_profile", None);
        };
        let Ok(raw) = alibi_core::utils::json::from_slice::<Value>(plain.as_bytes()) else {
            return error_redirect(&default_error, "invalid_payload", None);
        };
        if raw.get("profile").is_some_and(|value| !value.is_object())
            || raw.get("scopes").is_some_and(|value| {
                !value
                    .as_array()
                    .is_some_and(|items| items.iter().all(Value::is_string))
            })
            || ["newUserURL", "errorURL"]
                .iter()
                .any(|field| raw.get(*field).is_some_and(|value| !value.is_string()))
            || raw
                .get("disableSignUp")
                .is_some_and(|value| !value.is_boolean())
        {
            return error_redirect(&default_error, "invalid_payload", None);
        }
        let Ok(payload) = alibi_core::utils::json::from_slice::<ProxyPayload>(plain.as_bytes())
        else {
            return error_redirect(&default_error, "invalid_payload", None);
        };
        if payload
            .profile
            .as_ref()
            .is_some_and(|profile_2| !profile_2.is_object())
            || !payload.timestamp.is_finite()
            || payload.state.is_empty()
            || payload.callback_url.is_empty()
        {
            return error_redirect(&default_error, "invalid_payload", None);
        }
        let error_url = payload
            .error_url
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(&default_error);
        if provider_id.is_some_and(|id| id != payload.account.provider_id) {
            return error_redirect(error_url, "provider_mismatch", None);
        }
        let age = (Utc::now().timestamp_millis() as f64 - payload.timestamp) / 1000.0;
        if age > self.config.max_age_seconds || age < -10.0 {
            return error_redirect(error_url, "payload_expired", None);
        }
        let cookie_name = state_cookie_name(&ctx.config);
        let authenticated_cookie = get_cookie(req, &cookie_name);
        let state: OAuthStatePayload = match ctx.config.account.store_state_strategy {
            OAuthStateStrategy::Automatic | OAuthStateStrategy::Database => {
                let Ok(Some(row)) = ctx
                    .verifications()
                    .find(&state_verification_identifier(&payload.state))
                    .await
                else {
                    return error_redirect(error_url, "state_mismatch", None);
                };
                let Ok(state) = alibi_core::utils::json::from_slice(row.value()?.as_bytes()) else {
                    return error_redirect(error_url, "state_mismatch", None);
                };
                state
            }
            OAuthStateStrategy::Cookie => {
                // Proxy restoration only skips the database correlation cookie.
                // Cookie state still requires the originating browser's full,
                // authenticated state and an exact nonce match.
                let Some(cookie) = authenticated_cookie.as_deref() else {
                    return error_redirect(error_url, "state_mismatch", None);
                };
                let Ok(state) = decode_cookie_state_value(&ctx.config, cookie) else {
                    return error_redirect(error_url, "state_mismatch", None);
                };
                if state
                    .additional_data
                    .get("oauthState")
                    .and_then(Value::as_str)
                    != Some(payload.state.as_str())
                {
                    return error_redirect(error_url, "state_mismatch", None);
                }
                state
            }
        };
        if state
            .additional_data
            .get("oauthState")
            .is_some_and(|nonce| nonce.as_str() != Some(payload.state.as_str()))
        {
            return error_redirect(error_url, "state_mismatch", None);
        }
        let clear = alibi_core::utils::cookie_utils::create_clear_cookie(
            &state_cookie_name(&ctx.config),
            &ctx.config,
        )?;
        req.queue_response_header("Set-Cookie", clear);
        if matches!(
            ctx.config.account.store_state_strategy,
            OAuthStateStrategy::Automatic | OAuthStateStrategy::Database
        ) && ctx
            .verifications()
            .delete(&state_verification_identifier(&payload.state))
            .await
            .is_err()
        {
            return error_redirect(error_url, "state_mismatch", None);
        }
        if state.is_expired() {
            return error_redirect(error_url, "state_mismatch", None);
        }
        // Recover authority only from the admitted state. Cookie state uses
        // the key that authenticated that cookie; database state retains its
        // native proof across reader-key rotation.
        let context = match ctx.config.account.store_state_strategy {
            OAuthStateStrategy::Automatic | OAuthStateStrategy::Database => ctx
                .config
                .verification_secrets()
                .find_map(|secret| verified_server_context(&state, &payload.state, secret)),
            OAuthStateStrategy::Cookie => authenticated_cookie
                .as_deref()
                .and_then(|cookie| super::token_crypto::decryption_key(cookie, &ctx.config).ok())
                .and_then(|secret| verified_server_context(&state, &payload.state, secret)),
        };
        if let Some(context) = context {
            req.extensions()
                .insert(RecoveredOAuthServerContext(context));
        }
        let user = OAuthUserInfo {
            additional_fields: payload.user_info.additional_fields,
            // Account authority comes from the account key, never the loose
            // display profile's id. Forwarding resolves both to the same key.
            id: payload.account.account_id,
            email: payload.user_info.email.to_lowercase(),
            name: Some(payload.user_info.name),
            image: payload.user_info.image,
            email_verified: payload.user_info.email_verified,
        };
        let tokens = OAuthTokenSet {
            access_token: payload.account.access_token,
            refresh_token: payload.account.refresh_token,
            id_token: payload.account.id_token,
            access_token_expires_at: payload.account.access_token_expires_at,
            refresh_token_expires_at: payload.account.refresh_token_expires_at,
            scopes: payload.scopes.unwrap_or_else(|| {
                payload
                    .account
                    .scope
                    .map(|scope| scope.split(',').map(String::from).collect())
                    .unwrap_or_default()
            }),
            ..Default::default()
        };
        let profile = payload.profile.unwrap_or(Value::Null);
        if let Some(link) = state.link.as_ref() {
            return match complete_link_social(
                &payload.account.provider_id,
                &user,
                &profile,
                &tokens,
                link,
                ctx,
            )
            .await
            {
                Ok(()) => Ok(redirect(&payload.callback_url)),
                Err(error) => {
                    if error.is_ambiguous_account() {
                        return Ok(AuthResponse::new(500));
                    }
                    let (code, description) = match &error {
                        OAuthSignInError::Generic(message) => (message.clone(), None),
                        _ => error.redirect_parts(),
                    };
                    error_redirect(error_url, &code, description)
                }
            };
        }
        let user_output = raw
            .get("userInfo")
            .and_then(Value::as_object)
            .map(|values| {
                values
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect::<alibi_core::field_policy::FieldOutput>()
            });
        let outcome = match super::oauth::handlers::process_oauth_sign_in_with_output(
            super::oauth::handlers::OAuthIdentity {
                provider_name: &payload.account.provider_id,
                user: &user,
                profile: &profile,
            },
            &OAuthProcessPolicy {
                callback_url: Some(payload.callback_url.clone()),
                ..Default::default()
            },
            &tokens,
            payload.disable_sign_up.unwrap_or(false),
            &alibi_core::RequestMeta::from_request(req),
            ctx,
            (user_output.as_ref(), None),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                if error.is_ambiguous_account() {
                    return Ok(
                        crate::oauth::handlers::ambiguous_account_sign_in_response(ctx),
                    );
                }
                if let OAuthSignInError::SessionAuth(error) = error {
                    return match error {
                        AuthError::SessionCreationCancelled => {
                            error_redirect(error_url, "unable_to_create_session", None)
                        }
                        AuthError::Api {
                            code: Some(code),
                            message,
                            ..
                        } => error_redirect(error_url, &code, Some(&message)),
                        AuthError::Upstream { code, message, .. } => {
                            error_redirect(error_url, code, Some(message))
                        }
                        error @ (AuthError::Api { .. }
                        | AuthError::BadRequest(_)
                        | AuthError::InvalidRequest(_)
                        | AuthError::Validation(_)
                        | AuthError::InvalidCredentials
                        | AuthError::Unauthenticated
                        | AuthError::AuthenticationFailed(_)
                        | AuthError::SessionNotFound
                        | AuthError::Forbidden(_)
                        | AuthError::UserCreationCancelled
                        | AuthError::BannedUser(_)
                        | AuthError::Unauthorized
                        | AuthError::UserNotFound
                        | AuthError::NotFound(_)
                        | AuthError::Conflict(_)
                        | AuthError::MethodNotAllowed(_)
                        | AuthError::PayloadTooLarge(_)
                        | AuthError::UnprocessableEntity(_)
                        | AuthError::RateLimited { .. }
                        | AuthError::NotImplemented(_)
                        | AuthError::Config(_)
                        | AuthError::Database(_)
                        | AuthError::Serialization(_)
                        | AuthError::Plugin { .. }
                        | AuthError::CallbackFailure(_)
                        | AuthError::Internal(_)
                        | AuthError::Encryption(_)
                        | AuthError::PasswordHash(_)
                        | AuthError::Jwt(_))
                            if error.status_code() < 500
                                || matches!(error, AuthError::Api { .. }) =>
                        {
                            Err(error)
                        }
                        _error @ (AuthError::Api { .. }
                        | AuthError::BadRequest(_)
                        | AuthError::InvalidRequest(_)
                        | AuthError::Validation(_)
                        | AuthError::InvalidCredentials
                        | AuthError::Unauthenticated
                        | AuthError::AuthenticationFailed(_)
                        | AuthError::SessionNotFound
                        | AuthError::Forbidden(_)
                        | AuthError::UserCreationCancelled
                        | AuthError::BannedUser(_)
                        | AuthError::Unauthorized
                        | AuthError::UserNotFound
                        | AuthError::NotFound(_)
                        | AuthError::Conflict(_)
                        | AuthError::MethodNotAllowed(_)
                        | AuthError::PayloadTooLarge(_)
                        | AuthError::UnprocessableEntity(_)
                        | AuthError::RateLimited { .. }
                        | AuthError::NotImplemented(_)
                        | AuthError::Config(_)
                        | AuthError::Database(_)
                        | AuthError::Serialization(_)
                        | AuthError::Plugin { .. }
                        | AuthError::CallbackFailure(_)
                        | AuthError::Internal(_)
                        | AuthError::Encryption(_)
                        | AuthError::PasswordHash(_)
                        | AuthError::Jwt(_)) => {
                            // Source's ordinary exception response discards the
                            // accumulated endpoint headers; APIError redirects
                            // above retain the state-cookie cleanup instead.
                            drop(req.take_response_headers());
                            req.extensions()
                                .insert(OAuthProxyUnhandledError(AtomicBool::new(true)));
                            Ok(AuthResponse::new(500))
                        }
                    };
                }
                let (code, description) = error.redirect_parts();
                return error_redirect(error_url, &code, description);
            }
        };
        let target = if outcome.is_register {
            payload
                .new_user_url
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or(&payload.callback_url)
        } else {
            &payload.callback_url
        };
        let dont_remember = ctx.session_manager().has_dont_remember_cookie(req);
        let mut response = redirect(target).with_appended_header(
            "Set-Cookie",
            alibi_core::utils::cookie_utils::create_session_cookie_with_max_age(
                Some(outcome.session.token()),
                (!dont_remember).then(|| ctx.config.session.expires_in.num_seconds()),
                &ctx.config,
            )?,
        );
        if dont_remember {
            response.headers.append(
                "Set-Cookie",
                alibi_core::utils::cookie_utils::create_session_like_cookie(
                    &alibi_core::utils::cookie_utils::related_cookie_name(
                        &ctx.config,
                        "dont_remember",
                    ),
                    &alibi_core::utils::cookie_utils::sign_cookie_value(
                        "true",
                        ctx.config.current_secret(),
                    ),
                    None,
                    &ctx.config,
                )?,
            );
        }
        if let Some(account) = outcome.account_cookie.as_ref() {
            for header in create_account_cookie_headers(&ctx.config, account, req)? {
                response.headers.append("Set-Cookie", header);
            }
        }
        Ok(response)
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for OAuthProxyPlugin {
    fn static_openapi_metadata(&self) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::plugin_metadata(
            <Self as alibi_core::AuthPlugin<S>>::name(self),
            &<Self as alibi_core::AuthPlugin<S>>::routes(self),
        )
    }

    fn openapi_metadata(
        &self,
        ctx: &alibi_core::AuthInitContext<S>,
    ) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::instance_plugin_metadata(
            <Self as alibi_core::AuthPlugin<S>>::name(self),
            &<Self as alibi_core::AuthPlugin<S>>::routes(self),
            ctx,
        )
    }

    fn name(&self) -> &'static str {
        "oauth-proxy"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/callback/{provider}/oauth-proxy", "oauth_proxy"),
            AuthRoute::get("/oauth-proxy-callback", "oauth_proxy_legacy"),
        ]
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if let Some(provider) = regular_provider(req.path()) {
            return Ok(self
                .forward(provider, req, ctx)
                .await?
                .map(BeforeRequestAction::Respond));
        }
        if *req.method() != HttpMethod::Post
            || !(req.path().starts_with("/sign-in/social") || req.path() == "/link-social")
        {
            return Ok(None);
        }
        if req
            .headers
            .get("x-skip-oauth-proxy")
            .is_some_and(|value| !value.is_empty())
        {
            return Ok(None);
        }
        let environment_production = std::env::var("BETTER_AUTH_URL")
            .ok()
            .filter(|value| !value.is_empty());
        let production = self
            .config
            .production_url
            .as_deref()
            .filter(|value| !value.is_empty())
            .or(environment_production.as_deref())
            .unwrap_or(&ctx.config.base_url);
        // Skip resolution deliberately uses the transport URL even when its
        // origin is not trusted. Receiver selection below performs its own check.
        let transport = req.url().map(url::Url::as_str);
        let vendor = vendor_base_url();
        let skip_current = self
            .config
            .current_url
            .as_deref()
            .filter(|value| !value.is_empty())
            .or(transport)
            .or(vendor.as_deref());
        if skip_current
            .and_then(|value| url::Url::parse(value).ok())
            .zip(url::Url::parse(production).ok())
            .is_some_and(|(current, production)| current.origin() == production.origin())
        {
            return Ok(None);
        }
        let current = url::Url::parse(&self.current(req, ctx))
            .map_err(|_error| AuthError::config("Invalid OAuth proxy current URL"))?;
        let Ok(body) = req.body_as_json::<Value>() else {
            return Ok(None);
        };
        let Some(provider) = body
            .get("provider")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let original = body
            .get("callbackURL")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map_or_else(|| auth_base(ctx), String::from);
        let mut callback = url::Url::parse(&format!(
            "{}{}/callback/{provider}/oauth-proxy",
            current.origin().ascii_serialization(),
            ctx.config.base_path
        ))
        .map_err(|_error| AuthError::config("Invalid OAuth proxy callback URL"))?;
        _ = callback
            .query_pairs_mut()
            .append_pair("callbackURL", &original);
        req.extensions().insert(OAuthProxyFlow {
            effective_auth_base_url: format!(
                "{}{}",
                self.config
                    .production_url
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .unwrap_or(&ctx.config.base_url)
                    .trim_end_matches('/'),
                ctx.config.base_path
            ),
            callback_url: callback.to_string(),
        });
        Ok(None)
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if *req.method() != HttpMethod::Get {
            return Ok(None);
        }
        if let Some(provider) = completion_provider(req.path()) {
            return Ok(Some(self.complete(Some(provider), req, ctx).await?));
        }
        if req.path() == "/oauth-proxy-callback" {
            return Ok(Some(self.complete(None, req, ctx).await?));
        }
        Ok(None)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        let Some(issued) = req.extensions().get::<IssuedProxyState>() else {
            return Ok(response);
        };
        let Ok(mut body) = alibi_core::utils::json::from_slice::<Value>(&response.body) else {
            return Ok(response);
        };
        let Some(original_url) = body.get("url").and_then(Value::as_str) else {
            return Ok(response);
        };
        let Ok(mut url) = url::Url::parse(original_url) else {
            return Ok(response);
        };
        if !url
            .query_pairs()
            .any(|(key, value)| key == "state" && value == issued.state)
        {
            return Ok(response);
        }
        let package = StatePackage {
            state: issued.state.clone(),
            state_cookie: self.encrypt(
                &alibi_core::utils::json::to_string(&issued.payload)?,
                ctx,
                EncryptionPurpose::ProxyState,
            )?,
            is_oauth_proxy: true,
        };
        let encrypted = self.encrypt(
            &alibi_core::utils::json::to_string(&package)?,
            ctx,
            EncryptionPurpose::ProxyPackage,
        )?;
        let pairs: Vec<_> = url
            .query_pairs()
            .filter(|(key, _)| key != "state")
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        _ = url
            .query_pairs_mut()
            .clear()
            .extend_pairs(pairs)
            .append_pair("state", &encrypted);
        if let Some(value) = body.get_mut("url") {
            *value = json!(url.as_str());
        }
        response.body = alibi_core::utils::json::to_vec(&body)?;
        if response.headers.get("location").is_some() {
            drop(response.headers.insert("Location", url.as_str()));
        }
        Ok(response)
    }
}

impl std::fmt::Debug for OAuthProxyPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthProxyPlugin").finish_non_exhaustive()
    }
}

/// Internal dispatch bridge for an ordinary unhandled proxy session error.
/// The marker is private and public dispatch resets request extensions.
#[doc(hidden)]
#[must_use]
pub fn take_unhandled_error(req: &AuthRequest) -> bool {
    req.extensions()
        .get::<OAuthProxyUnhandledError>()
        .is_some_and(|marker| marker.0.swap(false, Ordering::Relaxed))
}

fn auth_base<S: AuthSchema>(ctx: &AuthContext<S>) -> String {
    format!(
        "{}{}",
        ctx.config.base_url.trim_end_matches('/'),
        ctx.config.base_path
    )
}

fn redirect(target: &str) -> AuthResponse {
    AuthResponse::new(302)
        .with_header("content-type", "application/json")
        .with_header("Location", target)
}

fn error_redirect(base: &str, code: &str, description: Option<&str>) -> AuthResult<AuthResponse> {
    let mut url =
        url::Url::parse(base).map_err(|_error| AuthError::internal("Invalid OAuth error URL"))?;
    _ = url.query_pairs_mut().append_pair("error", code);
    if let Some(message) = description {
        _ = url
            .query_pairs_mut()
            .append_pair("error_description", message);
    }
    Ok(redirect(url.as_str()))
}

fn regular_provider(path: &str) -> Option<&str> {
    path.strip_prefix("/callback/")
        .filter(|id| !id.is_empty() && !id.contains('/'))
}

fn completion_provider(path: &str) -> Option<&str> {
    path.strip_prefix("/callback/")?
        .strip_suffix("/oauth-proxy")
        .filter(|id| !id.is_empty() && !id.contains('/'))
}

fn vendor_base_url() -> Option<String> {
    if let Ok(value) = std::env::var("VERCEL_URL")
        && !value.is_empty()
    {
        return Some(format!("https://{value}"));
    }
    [
        "NETLIFY_URL",
        "RENDER_URL",
        "AWS_LAMBDA_FUNCTION_NAME",
        "GOOGLE_CLOUD_FUNCTION_NAME",
        "AZURE_FUNCTION_NAME",
    ]
    .into_iter()
    .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}
