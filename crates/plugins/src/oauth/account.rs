use super::OAuthAccountProfile;
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
use alibi_core::entity::AuthAccount;
use alibi_core::error::codes;
use alibi_core::{AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, UpdateAccount};
use chrono::Utc;

#[derive(Debug, Clone)]
pub enum OAuthAccountSelection {
    Id(String),
    Cookie,
}

pub(super) trait AccountRequest: alibi_core::session::SessionRequest {
    fn refresh_context(&self) -> Option<super::providers::OAuthRefreshContext<'_>>;
}
impl AccountRequest for AuthRequest {
    fn refresh_context(&self) -> Option<super::providers::OAuthRefreshContext<'_>> {
        Some(super::providers::OAuthRefreshContext { request: self })
    }
}
impl AccountRequest for alibi_core::endpoint::EndpointCall {
    fn refresh_context(&self) -> Option<super::providers::OAuthRefreshContext<'_>> {
        self.request()
            .map(|request| super::providers::OAuthRefreshContext { request })
    }
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

    pub(super) fn from_value(value: &serde_json::Value) -> Result<Self, String> {
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
        req: &impl alibi_core::session::SessionRequest,
        user_id: &str,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
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
        code: codes::FAILED_TO_GET_ACCESS_TOKEN,
        message: "Failed to get a valid access token",
    }
}

const fn refresh_token_failure() -> AuthError {
    AuthError::Upstream {
        status: 400,
        code: codes::FAILED_TO_REFRESH_ACCESS_TOKEN,
        message: "Failed to refresh access token",
    }
}

fn invalid_selection(location: &str, message: &str) -> AuthResult<AuthResponse> {
    Ok(AuthResponse::json(
        400,
        &alibi_core::ErrorCodeMessageResponse {
            code: Some(codes::VALIDATION_ERROR.into()),
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
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    provider: &super::providers::OAuthProvider,
) -> AuthResult<()> {
    let raw_policy = provider.authorization.as_ref();
    let encrypted = encrypt_provider_token_set(ctx, tokens, raw_policy).await?;
    let preserve_raw = provider
        .authorization
        .as_ref()
        .is_some_and(|policy| policy.preserve_raw_profile_scalars);
    let refresh_incoming = tokens.raw.as_ref().filter(|_| preserve_raw).map_or_else(
        || {
            tokens
                .refresh_token
                .as_ref()
                .is_some_and(|token| !token.is_empty())
        },
        |raw| {
            raw.get("refresh_token")
                .is_some_and(super::providers::remaining_profile::truthy)
        },
    );
    let id_incoming = tokens.raw.as_ref().filter(|_| preserve_raw).map_or_else(
        || {
            tokens
                .id_token
                .as_ref()
                .is_some_and(|token| !token.is_empty())
        },
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
    req: &impl AccountRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<(OAuthTokenSet, bool)> {
    let provider = config.provider(&account.provider_id).ok_or_else(|| {
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
        let tokens = refresh_tokens_via_provider(provider, &refresh_token, req.refresh_context())
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
        OAuthTokenSet {
            access_token: Some(access_token),
            access_token_expires_at: refreshed
                .as_ref()
                .and_then(|tokens| tokens.access_token_expires_at)
                .or(original.access_token_expires_at),
            scopes: scopes(account),
            id_token: refreshed
                .as_ref()
                .and_then(|tokens| tokens.id_token.clone())
                .or(original.id_token),
            ..Default::default()
        },
        refreshed.is_some(),
    ))
}

pub(super) async fn handle_get_access_token(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let selection = match OAuthAccountSelection::from_body(req) {
        Ok(selection) => selection,
        Err(message) => return invalid_selection("body", &message),
    };
    let mut session_request = req.clone();
    _ = session_request
        .query
        .insert("disableCookieCache".into(), "true".into());
    let user_id = match ctx.require_cached_session(&session_request).await {
        Ok((_, session)) => session.user_id,
        Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
            return Ok(AuthResponse::new(401).with_header("Content-Type", "application/json"));
        }
        Err(error) => return Err(error),
    };
    let (tokens, headers) =
        get_access_token_for_selection(config, req, ctx, &user_id, selection).await?;
    let mut response = AuthResponse::json(200, &AccessTokenResponse::from(tokens))?;
    for header in headers {
        response.headers.append("set-cookie", header);
    }
    Ok(response)
}

pub(super) async fn get_access_token_for_selection(
    config: &OAuthConfig,
    request: &impl AccountRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    user_id: &str,
    selection: OAuthAccountSelection,
) -> AuthResult<(OAuthTokenSet, Vec<String>)> {
    let mut account = selection.resolve(request, user_id, ctx).await?;
    let (value, refreshed) = valid_access_token(&mut account, config, request, ctx).await?;
    let headers = if refreshed && ctx.config.account.store_account_cookie {
        create_account_cookie_headers(&ctx.config, &account, request)?
    } else {
        Vec::new()
    };
    Ok((value, headers))
}

pub(super) async fn handle_refresh_token(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let selection = match OAuthAccountSelection::from_body(req) {
        Ok(selection) => selection,
        Err(message) => return invalid_selection("body", &message),
    };
    let mut session_request = req.clone();
    _ = session_request
        .query
        .insert("disableCookieCache".into(), "true".into());
    let user_id = match ctx.require_cached_session(&session_request).await {
        Ok((_, session)) => session.user_id,
        Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
            return Ok(AuthResponse::new(401).with_header("Content-Type", "application/json"));
        }
        Err(error) => return Err(error),
    };
    let (tokens, account, headers) =
        refresh_token_for_selection(config, req, ctx, &user_id, selection).await?;
    let mut response = AuthResponse::json(200, &refresh_token_body(config, &tokens, &account)?)?;
    for header in headers {
        response.headers.append("set-cookie", header);
    }
    Ok(response)
}

pub(super) async fn refresh_token_for_selection(
    config: &OAuthConfig,
    req: &impl AccountRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    user_id: &str,
    selection: OAuthAccountSelection,
) -> AuthResult<(OAuthTokenSet, AccountCookiePayload, Vec<String>)> {
    let mut account = selection.resolve(req, user_id, ctx).await?;
    let provider = config.provider(&account.provider_id).ok_or_else(|| {
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
        return Err(AuthError::Api {
            status: 400,
            code: Some(codes::TOKEN_REFRESH_NOT_SUPPORTED.into()),
            message: format!(
                "Provider {} does not support token refreshing.",
                account.provider_id
            ),
        });
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
    let tokens = refresh_tokens_via_provider(provider, &refresh_token, req.refresh_context())
        .await
        .map_err(|_error| refresh_token_failure())?;
    persist_tokens(&mut account, &tokens, ctx, provider)
        .await
        .map_err(|_error| refresh_token_failure())?;
    let tokens = OAuthTokenSet {
        refresh_token: tokens.refresh_token.or(Some(refresh_token)),
        refresh_token_expires_at: account.refresh_token_expires_at,
        scopes: scopes(&account),
        id_token: account.id_token.clone(),
        ..tokens
    };
    let headers = if matches!(selection, OAuthAccountSelection::Cookie)
        && ctx.config.account.store_account_cookie
    {
        create_account_cookie_headers(&ctx.config, &account, req)?
    } else {
        Vec::new()
    };
    Ok((tokens, account, headers))
}

/// Source's `/refresh-token` body: the refreshed grant plus the stored scope
/// and account identity, with provider-defined raw token scalars preserved.
pub(super) fn refresh_token_body(
    config: &OAuthConfig,
    tokens: &OAuthTokenSet,
    account: &AccountCookiePayload,
) -> AuthResult<serde_json::Value> {
    let policy = config
        .provider(&account.provider_id)
        .and_then(|provider| provider.authorization.as_ref());
    let response = RefreshTokenResponse {
        access_token: tokens.access_token.clone(),
        access_token_expires_at: tokens
            .access_token_expires_at
            .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        refresh_token: tokens.refresh_token.clone(),
        refresh_token_expires_at: tokens
            .refresh_token_expires_at
            .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        scope: account.scope.clone(),
        id_token: tokens.id_token.clone(),
        provider_id: account.provider_id.clone(),
        account_id: account.id.clone(),
    };
    let mut response =
        serde_json::to_value(response).map_err(|error| AuthError::internal(error.to_string()))?;
    if let Some(raw) = tokens
        .raw
        .as_ref()
        .filter(|_| policy.is_some_and(|policy| policy.preserve_raw_profile_scalars))
    {
        let object = response
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("Invalid refresh output"))?;
        match raw.get("access_token") {
            Some(value) => {
                _ = object.insert("accessToken".into(), value.clone());
            }
            None => {
                _ = object.remove("accessToken");
            }
        }
        if let Some(value) = raw.get("refresh_token").filter(|value| !value.is_null()) {
            _ = object.insert("refreshToken".into(), value.clone());
        }
        if let Some(value) = raw
            .get("id_token")
            .filter(|_| !policy.is_some_and(|policy| policy.token_response_omits_id_token))
            .filter(|value| super::providers::remaining_profile::truthy(value))
        {
            _ = object.insert("idToken".into(), value.clone());
        }
    }
    Ok(response)
}

pub(super) async fn handle_account_info(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let selection = match OAuthAccountSelection::from_query(req) {
        Ok(selection) => selection,
        Err(message) => return invalid_selection("query", &(message)),
    };
    // Source's account helper disables browser cookie-cache reads for stateful
    // accounts while retaining a genuinely established virtual principal.
    let mut session_request = req.clone();
    _ = session_request
        .query
        .insert("disableCookieCache".into(), "true".into());
    let user_id = match ctx.require_cached_session(&session_request).await {
        Ok((_, session)) => session.user_id,
        Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
            return Ok(AuthResponse::new(401).with_header("Content-Type", "application/json"));
        }
        Err(error) => return Err(error),
    };
    let (value, headers) =
        match account_info_for_selection(config, req, ctx, &user_id, selection).await {
            Ok(response) => response,
            Err(AuthError::Api {
                code: Some(code), ..
            }) if code == "OAUTH_PROFILE_EXCEPTION" => return Ok(AuthResponse::new(500)),
            Err(error) => return Err(error),
        };
    let mut response = AuthResponse::json(200, &value)?;
    for header in headers {
        response.headers.append("set-cookie", header);
    }
    Ok(response)
}

pub(super) async fn account_info_for_selection(
    config: &OAuthConfig,
    req: &impl AccountRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    user_id: &str,
    selection: OAuthAccountSelection,
) -> AuthResult<(AccountInfoResponse, Vec<String>)> {
    let mut account = selection.resolve(req, user_id, ctx).await?;
    let provider = config
        .provider(&account.provider_id)
        .ok_or(AuthError::Upstream {
            status: 400,
            code: codes::PROVIDER_NOT_CONFIGURED,
            message: "Account is not associated with a configured social provider.",
        })?;
    let (tokens, refreshed) = valid_access_token(&mut account, config, req, ctx).await?;
    let access_token = tokens
        .access_token
        .filter(|token| !token.is_empty())
        .ok_or_else(|| AuthError::bad_request("Access token not found"))?;
    let info = fetch_user_info_from_provider(
        provider,
        OAuthUserInfoRequest {
            access_token: Some(access_token),
            access_token_expires_at: account.access_token_expires_at,
            scopes: tokens.scopes,
            id_token: tokens.id_token,
            ..Default::default()
        },
    )
    .await?;
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
    let headers = if refreshed && ctx.config.account.store_account_cookie {
        create_account_cookie_headers(&ctx.config, &account, req)?
    } else {
        Vec::new()
    };
    Ok((response, headers))
}

/// Trusted direct account operations. The caller supplies the authorized user;
/// these methods are not HTTP routes. HTTP handlers always resolve the session
/// first, and cannot select a principal with a `userId` body/query field.
pub struct OAuthAccountApi;
impl OAuthAccountApi {
    /// Source's `getAccessToken` result: a valid access token, refreshed and
    /// persisted when it is within five seconds of expiry, with its expiry,
    /// the stored scopes and the ID token.
    pub async fn get_access_token(
        user_id: &str,
        selection: OAuthAccountSelection,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<OAuthTokenSet> {
        let (config, req) = server_request(user_id, &selection, "/get-access-token", ctx)?;
        let (tokens, _) =
            get_access_token_for_selection(&config, &req, ctx, user_id, selection).await?;
        Ok(tokens)
    }
    /// Source's `refreshToken` result: the refreshed grant, the retained refresh
    /// token when the provider did not rotate it, and the stored scopes.
    pub async fn refresh_token(
        user_id: &str,
        selection: OAuthAccountSelection,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<OAuthTokenSet> {
        let (config, req) = server_request(user_id, &selection, "/refresh-token", ctx)?;
        let (tokens, _, _) = Box::pin(refresh_token_for_selection(
            &config, &req, ctx, user_id, selection,
        ))
        .await?;
        Ok(tokens)
    }
    pub async fn account_info(
        user_id: &str,
        selection: OAuthAccountSelection,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<OAuthAccountProfile> {
        let (config, req) = server_request(user_id, &selection, "/account-info", ctx)?;
        let (profile, _) = Box::pin(account_info_for_selection(
            &config, &req, ctx, user_id, selection,
        ))
        .await?;
        Ok(profile)
    }
}
fn server_request(
    user_id: &str,
    selection: &OAuthAccountSelection,
    path: &str,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<(std::sync::Arc<OAuthConfig>, AuthRequest)> {
    if user_id.is_empty() {
        return Err(AuthError::Upstream {
            status: 400,
            code: codes::USER_ID_OR_SESSION_REQUIRED,
            message: "Either userId or session is required",
        });
    }
    let config = ctx
        .extensions
        .get::<OAuthConfig>()
        .ok_or_else(|| AuthError::config("OAuth plugin is not initialized"))?;
    let mut req = AuthRequest::new(
        if path == "/account-info" {
            alibi_core::HttpMethod::Get
        } else {
            alibi_core::HttpMethod::Post
        },
        path,
    );
    match selection {
        OAuthAccountSelection::Id(id) => {
            _ = req.query.insert("accountId".into(), id.clone());
            req.body = Some(
                serde_json::to_vec(&serde_json::json!({"accountId":id}))
                    .map_err(|e| AuthError::internal(e.to_string()))?,
            );
        }
        OAuthAccountSelection::Cookie => return Err(AuthError::bad_request("Account not found")),
    }
    Ok((config, req))
}
