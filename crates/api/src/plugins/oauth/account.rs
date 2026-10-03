use super::encryption::{
    encrypt_provider_token_set, maybe_decrypt_with_config, provider_token_nulls,
};
use super::handlers::{
    create_account_cookie_headers, decode_account_cookie, fetch_user_info_from_provider,
    refresh_tokens_via_provider,
};
use super::providers::{OAuthConfig, OAuthTokenSet, OAuthUserInfoRequest};
use super::state::AccountCookiePayload;
use super::types::{
    AccessTokenResponse, AccountInfoAccount, AccountInfoResponse, RefreshTokenResponse,
};
use better_auth_core::entity::AuthAccount;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, UpdateAccount,
};
use chrono::Utc;

#[derive(Debug, Clone)]
pub enum OAuthAccountSelection {
    Id(String),
    Cookie,
}

impl OAuthAccountSelection {
    fn from_body(req: &AuthRequest) -> Result<Self, String> {
        let value = req
            .body_as_json()
            .map_err(|_error| "Invalid input".to_owned())?;
        Self::from_value(&value)
    }

    fn from_query(req: &AuthRequest) -> Result<Self, String> {
        Self::from_value(&serde_json::Value::Object(
            req.query
                .iter()
                .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
                .collect(),
        ))
    }

    fn from_value(value: &serde_json::Value) -> Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "Invalid input".to_owned())?;
        if object
            .get("userId")
            .is_some_and(|value_2| !value_2.is_string())
        {
            return Err("Invalid input".into());
        }
        let account_id = object.get("accountId").and_then(serde_json::Value::as_str);
        let use_cookie = object
            .get("useAccountCookie")
            .and_then(serde_json::Value::as_bool)
            == Some(true);
        let (selection, field) = match (account_id, use_cookie) {
            (Some(id), false) => (Self::Id(id.to_owned()), "accountId"),
            (None, true) => (Self::Cookie, "useAccountCookie"),
            _ => return Err("Invalid input".into()),
        };
        let unknown: Vec<_> = object
            .keys()
            .filter(|key| key.as_str() != field && key.as_str() != "userId")
            .collect();
        if !unknown.is_empty() {
            let suffix = if unknown.len() == 1 { "" } else { "s" };
            let names = unknown
                .into_iter()
                .map(|key| serde_json::Value::String(key.clone()).to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!("Unrecognized key{suffix}: {names}"));
        }
        Ok(selection)
    }

    async fn resolve(
        &self,
        req: &AuthRequest,
        user_id: &str,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AccountCookiePayload> {
        let account = match self {
            Self::Id(account_id) => ctx
                .database
                .get_user_accounts_record(user_id)
                .await?
                .iter()
                .find(|account| account.id().as_ref() == account_id.as_str())
                .map(AccountCookiePayload::from_account),
            Self::Cookie if ctx.config.account.store_account_cookie => {
                decode_account_cookie(req, &ctx.config)?
                    .filter(|account| account.user_id == user_id)
            }
            Self::Cookie => None,
        };
        account.ok_or_else(|| AuthError::bad_request("Account not found"))
    }
}

const fn access_token_failure() -> AuthError {
    AuthError::Upstream {
        status: 400,
        code: "FAILED_TO_GET_ACCESS_TOKEN",
        message: "Failed to get a valid access token",
    }
}

const fn refresh_token_failure() -> AuthError {
    AuthError::Upstream {
        status: 400,
        code: "FAILED_TO_REFRESH_ACCESS_TOKEN",
        message: "Failed to refresh access token",
    }
}

fn invalid_selection(location: &str, message: &str) -> AuthResult<AuthResponse> {
    Ok(AuthResponse::json(
        400,
        &better_auth_core::ErrorCodeMessageResponse {
            code: Some("VALIDATION_ERROR".into()),
            message: format!("[{location}] {message}"),
        },
    )?)
}

fn scopes(account: &AccountCookiePayload) -> Vec<String> {
    account
        .scope
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .map(|scope| scope.trim_matches(super::providers::remaining_profile::js_whitespace))
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect()
}

async fn persist_tokens(
    account: &mut AccountCookiePayload,
    tokens: &OAuthTokenSet,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    provider: &super::providers::OAuthProvider,
) -> AuthResult<()> {
    let raw_policy = provider.authorization.as_ref();
    let encrypted = encrypt_provider_token_set(ctx, tokens, raw_policy).await?;
    let preserve_raw = provider
        .authorization
        .as_ref()
        .is_some_and(|policy| policy.preserve_raw_profile_scalars);
    let refresh_incoming = tokens.raw.as_ref().filter(|_| preserve_raw).map_or(
        tokens
            .refresh_token
            .as_ref()
            .is_some_and(|token| !token.is_empty()),
        |raw| {
            raw.get("refresh_token")
                .is_some_and(super::providers::remaining_profile::truthy)
        },
    );
    let id_incoming = tokens.raw.as_ref().filter(|_| preserve_raw).map_or(
        tokens
            .id_token
            .as_ref()
            .is_some_and(|token| !token.is_empty()),
        |raw| {
            if raw_policy.is_some_and(|policy| policy.token_response_omits_id_token) {
                return false;
            }
            raw.get("id_token")
                .is_some_and(super::providers::remaining_profile::truthy)
        },
    );
    let mut nulls = provider_token_nulls(tokens, raw_policy);
    nulls[0] |= tokens
        .raw
        .as_ref()
        .and_then(|raw| raw.get("access_token"))
        .is_some_and(serde_json::Value::is_null);
    let update = UpdateAccount {
        provider_token_nulls: [nulls[0], false, false],
        access_token: encrypted
            .access_token
            .or_else(|| (!nulls[0]).then(|| account.access_token.clone()).flatten()),
        refresh_token: if refresh_incoming {
            encrypted.refresh_token
        } else {
            account.refresh_token.clone()
        },
        id_token: if id_incoming {
            encrypted.id_token
        } else {
            account.id_token.clone()
        },
        access_token_expires_at: tokens
            .access_token_expires_at
            .or(account.access_token_expires_at),
        refresh_token_expires_at: tokens
            .refresh_token_expires_at
            .or(account.refresh_token_expires_at),
        ..Default::default()
    };
    if let Some(id) = account.id.as_deref() {
        *account = AccountCookiePayload::from_account(
            &ctx.database.update_account_record(id, update).await?,
        );
    } else {
        account.access_token = update.access_token;
        account.refresh_token = update.refresh_token;
        account.id_token = update.id_token;
        account.access_token_expires_at = update.access_token_expires_at;
        account.refresh_token_expires_at = update.refresh_token_expires_at;
    }
    Ok(())
}

async fn valid_access_token(
    account: &mut AccountCookiePayload,
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(AccessTokenResponse, bool)> {
    let provider = config.providers.get(&account.provider_id).ok_or_else(|| {
        AuthError::bad_request(format!(
            "Provider {} is not supported.",
            account.provider_id
        ))
    })?;
    let original = account.clone();
    let encrypted = ctx.config.account.encrypt_oauth_tokens;
    let expired = account.access_token_expires_at.is_some_and(|expires_at| {
        expires_at.timestamp_millis() - Utc::now().timestamp_millis() < 5_000
    });
    let refreshed = if expired
        && (provider.refresh_access_token.is_some()
            || provider
                .authorization
                .as_ref()
                .is_none_or(|policy| policy.supports_refresh))
        && let Some(stored_refresh) = account
            .refresh_token
            .as_deref()
            .filter(|token| !token.is_empty())
    {
        let refresh_token = maybe_decrypt_with_config(Some(stored_refresh), encrypted, &ctx.config)
            .map_err(|_error| access_token_failure())?
            .unwrap_or_default();
        let tokens = refresh_tokens_via_provider(
            provider,
            &refresh_token,
            Some(super::providers::OAuthRefreshContext { request: req }),
        )
        .await
        .map_err(|_error| access_token_failure())?;
        persist_tokens(account, &tokens, ctx, provider)
            .await
            .map_err(|_error| access_token_failure())?;
        Some(tokens)
    } else {
        None
    };
    let access_token = match refreshed
        .as_ref()
        .and_then(|tokens| tokens.access_token.clone())
    {
        Some(token) => token,
        None => maybe_decrypt_with_config(original.access_token.as_deref(), encrypted, &ctx.config)
            .map_err(|_error| access_token_failure())?
            .unwrap_or_default(),
    };
    Ok((
        AccessTokenResponse {
            access_token: Some(access_token),
            access_token_expires_at: refreshed
                .as_ref()
                .and_then(|tokens| tokens.access_token_expires_at)
                .or(original.access_token_expires_at)
                .map(|value| value.to_rfc3339()),
            scopes: scopes(account),
            id_token: refreshed
                .as_ref()
                .and_then(|tokens| tokens.id_token.clone())
                .or(original.id_token),
        },
        refreshed.is_some(),
    ))
}

fn token_response(
    value: &impl serde::Serialize,
    account: &AccountCookiePayload,
    set_cookie: bool,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let mut response = AuthResponse::json(200, value)?;
    if set_cookie && ctx.config.account.store_account_cookie {
        for header in create_account_cookie_headers(&ctx.config, account, req)? {
            response.headers.append("Set-Cookie", header);
        }
    }
    Ok(response)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
async fn handle_get_access_token_for_user(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    server_user: Option<&str>,
) -> AuthResult<AuthResponse> {
    let selection = match OAuthAccountSelection::from_body(req) {
        Ok(selection) => selection,
        Err(message) => return invalid_selection("body", &message),
    };
    let mut session_request = req.clone();
    drop(
        session_request
            .query
            .insert("disableCookieCache".into(), "true".into()),
    );
    let user_id = if let Some(user_id) = server_user {
        user_id.to_owned()
    } else {
        let (_, session) = match ctx.require_cached_session(&session_request).await {
            Ok(session) => session,
            Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
                return Ok(AuthResponse::new(401).with_header("Content-Type", "application/json"));
            }
            Err(error) => return Err(error),
        };
        session.user_id
    };
    let mut account = selection.resolve(req, &user_id, ctx).await?;
    let (response, refreshed) = valid_access_token(&mut account, config, req, ctx).await?;
    token_response(&response, &account, refreshed, req, ctx)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
async fn handle_refresh_token_for_user(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    server_user: Option<&str>,
) -> AuthResult<AuthResponse> {
    let selection = match OAuthAccountSelection::from_body(req) {
        Ok(selection) => selection,
        Err(message) => return invalid_selection("body", &message),
    };
    let mut session_request = req.clone();
    drop(
        session_request
            .query
            .insert("disableCookieCache".into(), "true".into()),
    );
    let user_id = if let Some(user_id) = server_user {
        user_id.to_owned()
    } else {
        let (_, session) = match ctx.require_cached_session(&session_request).await {
            Ok(session) => session,
            Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
                return Ok(AuthResponse::new(401).with_header("Content-Type", "application/json"));
            }
            Err(error) => return Err(error),
        };
        session.user_id
    };
    let mut account = selection.resolve(req, &user_id, ctx).await?;
    let provider = config.providers.get(&account.provider_id).ok_or_else(|| {
        AuthError::bad_request(format!(
            "Provider {} is not supported.",
            account.provider_id
        ))
    })?;
    if provider.refresh_access_token.is_none()
        && provider
            .authorization
            .as_ref()
            .is_some_and(|policy| !policy.supports_refresh)
    {
        return Ok(AuthResponse::json(
            400,
            &serde_json::json!({"code":"TOKEN_REFRESH_NOT_SUPPORTED","message":format!("Provider {} does not support token refreshing.",account.provider_id)}),
        )?);
    }
    let stored_refresh = account
        .refresh_token
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AuthError::bad_request("Refresh token not found"))?;
    let refresh_token = maybe_decrypt_with_config(
        Some(stored_refresh),
        ctx.config.account.encrypt_oauth_tokens,
        &ctx.config,
    )
    .map_err(|_error| refresh_token_failure())?
    .unwrap_or_default();
    let tokens = refresh_tokens_via_provider(
        provider,
        &refresh_token,
        Some(super::providers::OAuthRefreshContext { request: req }),
    )
    .await
    .map_err(|_error| refresh_token_failure())?;
    persist_tokens(&mut account, &tokens, ctx, provider)
        .await
        .map_err(|_error| refresh_token_failure())?;
    let raw_grant = tokens.raw.clone().filter(|_| {
        provider
            .authorization
            .as_ref()
            .is_some_and(|policy| policy.preserve_raw_profile_scalars)
    });
    let response = RefreshTokenResponse {
        access_token: tokens.access_token,
        access_token_expires_at: tokens
            .access_token_expires_at
            .map(|value| value.to_rfc3339()),
        refresh_token: Some(tokens.refresh_token.unwrap_or(refresh_token)),
        refresh_token_expires_at: account
            .refresh_token_expires_at
            .map(|value| value.to_rfc3339()),
        scope: account.scope.clone(),
        id_token: account.id_token.clone(),
        provider_id: account.provider_id.clone(),
        account_id: account.id.clone(),
    };
    let mut response =
        serde_json::to_value(response).map_err(|error| AuthError::internal(error.to_string()))?;
    if let Some(raw) = raw_grant {
        let object = response
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("Invalid refresh output"))?;
        match raw.get("access_token") {
            Some(value) => {
                drop(object.insert("accessToken".into(), value.clone()));
            }
            None => {
                drop(object.remove("accessToken"));
            }
        }
        if let Some(value) = raw.get("refresh_token").filter(|value| !value.is_null()) {
            drop(object.insert("refreshToken".into(), value.clone()));
        }
        if let Some(value) = raw
            .get("id_token")
            .filter(|_| {
                !provider
                    .authorization
                    .as_ref()
                    .is_some_and(|policy| policy.token_response_omits_id_token)
            })
            .filter(|value| super::providers::remaining_profile::truthy(value))
        {
            drop(object.insert("idToken".into(), value.clone()));
        }
    }
    token_response(
        &response,
        &account,
        matches!(selection, OAuthAccountSelection::Cookie),
        req,
        ctx,
    )
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
async fn handle_account_info_for_user(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    server_user: Option<&str>,
) -> AuthResult<AuthResponse> {
    let selection = match OAuthAccountSelection::from_query(req) {
        Ok(selection) => selection,
        Err(message) => return invalid_selection("query", &(message)),
    };
    // Source's account helper disables browser cookie-cache reads for stateful
    // accounts while retaining a genuinely established virtual principal.
    let mut session_request = req.clone();
    drop(
        session_request
            .query
            .insert("disableCookieCache".into(), "true".into()),
    );
    let user_id = if let Some(user_id) = server_user {
        user_id.to_owned()
    } else {
        let (_, session) = match ctx.require_cached_session(&session_request).await {
            Ok(session) => session,
            Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
                return Ok(AuthResponse::new(401).with_header("Content-Type", "application/json"));
            }
            Err(error) => return Err(error),
        };
        session.user_id
    };
    let mut account = selection.resolve(req, &user_id, ctx).await?;
    let provider = config
        .providers
        .get(&account.provider_id)
        .ok_or(AuthError::Upstream {
            status: 400,
            code: "PROVIDER_NOT_CONFIGURED",
            message: "Account is not associated with a configured social provider.",
        })?;
    let (tokens, refreshed) = valid_access_token(&mut account, config, req, ctx).await?;
    let access_token = tokens
        .access_token
        .filter(|token| !token.is_empty())
        .ok_or_else(|| AuthError::bad_request("Access token not found"))?;
    let info = match fetch_user_info_from_provider(
        provider,
        OAuthUserInfoRequest {
            access_token: Some(access_token),
            access_token_expires_at: account.access_token_expires_at,
            scopes: tokens.scopes,
            id_token: tokens.id_token,
            ..Default::default()
        },
    )
    .await
    {
        Ok(info) => info,
        Err(AuthError::Api {
            code: Some(code), ..
        }) if code == "OAUTH_PROFILE_EXCEPTION" => return Ok(AuthResponse::new(500)),
        Err(error) => return Err(error),
    };
    let response = AccountInfoResponse {
        user: info
            .user_output
            .unwrap_or_else(|| info.user.public_profile(false)),
        data: info.data,
        account: AccountInfoAccount {
            id: account.id.clone(),
            provider_id: account.provider_id.clone(),
            account_id: account.account_id.clone(),
        },
    };
    token_response(&response, &account, refreshed, req, ctx)
}

pub(super) async fn handle_get_access_token(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    handle_get_access_token_for_user(config, req, ctx, None).await
}

pub(super) async fn handle_refresh_token(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    handle_refresh_token_for_user(config, req, ctx, None).await
}

pub(super) async fn handle_account_info(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    handle_account_info_for_user(config, req, ctx, None).await
}

/// Trusted direct account operations. The caller supplies the authorized user;
/// these methods are not HTTP routes. HTTP handlers always resolve the session
/// first, and cannot select a principal with a `userId` body/query field.
pub struct OAuthAccountApi;
impl OAuthAccountApi {
    /// # Errors
    /// Returns storage, provider, selection, or token errors.
    pub async fn get_access_token(
        user_id: &str,
        selection: OAuthAccountSelection,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (config, req) = server_request(user_id, selection, "/get-access-token", ctx)?;
        handle_get_access_token_for_user(&config, &req, ctx, Some(user_id)).await
    }
    /// # Errors
    /// Returns storage, provider, selection, or refresh errors.
    pub async fn refresh_token(
        user_id: &str,
        selection: OAuthAccountSelection,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (config, req) = server_request(user_id, selection, "/refresh-token", ctx)?;
        handle_refresh_token_for_user(&config, &req, ctx, Some(user_id)).await
    }
    /// # Errors
    /// Returns storage, provider, selection, or profile errors.
    pub async fn account_info(
        user_id: &str,
        selection: OAuthAccountSelection,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (config, req) = server_request(user_id, selection, "/account-info", ctx)?;
        handle_account_info_for_user(&config, &req, ctx, Some(user_id)).await
    }
}
fn server_request(
    user_id: &str,
    selection: OAuthAccountSelection,
    path: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(std::sync::Arc<OAuthConfig>, AuthRequest)> {
    if user_id.is_empty() {
        return Err(AuthError::Upstream {
            status: 400,
            code: "USER_ID_OR_SESSION_REQUIRED",
            message: "Either userId or session is required",
        });
    }
    let config = ctx
        .extensions
        .get::<OAuthConfig>()
        .ok_or_else(|| AuthError::config("OAuth plugin is not initialized"))?;
    let mut req = AuthRequest::new(
        if path == "/account-info" {
            better_auth_core::HttpMethod::Get
        } else {
            better_auth_core::HttpMethod::Post
        },
        path,
    );
    match selection {
        OAuthAccountSelection::Id(id) => {
            drop(req.query.insert("accountId".into(), id.clone()));
            req.body = Some(
                serde_json::to_vec(&serde_json::json!({"accountId":id}))
                    .map_err(|e| AuthError::internal(e.to_string()))?,
            );
        }
        OAuthAccountSelection::Cookie => return Err(AuthError::bad_request("Account not found")),
    }
    Ok((config, req))
}
