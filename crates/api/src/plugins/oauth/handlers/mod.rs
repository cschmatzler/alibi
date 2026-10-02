#[cfg(test)]
mod tests;

use super::encryption::encrypt_token_set;
use super::providers::{
    OAuthCallbackUserName, OAuthCallbackUserPayload, OAuthConfig, OAuthProvider, OAuthScopeOrder,
    OAuthTokenEndpointAuth, OAuthTokenSet, OAuthUserInfo, OAuthUserInfoRequest,
    OAuthUserInfoResponse,
};
use super::state::{
    AccountCookiePayload, OAuthStateLink, OAuthStatePayload, RecoveredOAuthServerContext,
    account_cookie_name, capture_server_context, create_account_cookie_value,
    create_cookie_state_value, create_database_state_cookie_value, decode_account_cookie_value,
    decode_cookie_state_value, decode_database_state_cookie_value, filter_additional_state_data,
    get_cookie, state_cookie_name, verified_server_context,
};
use super::types::{
    LinkSocialRequest, OAuthIdTokenRequest, SocialSignInRequest, SocialSignInResponse,
};
use crate::plugins::helpers::{SessionIssueError, apply_default_role, issue_user_session};
use base64::Engine;
use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::user_validation::{
    UserValidationAction, UserValidationData, UserValidationSource, validate_user_info,
};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateAccount, CreateUser,
    CreateVerification, UpdateAccount, UpdateUser,
};
use chrono::{Duration, Utc};
use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub(in crate::plugins) struct ProcessOAuthUserResult {
    pub(in crate::plugins) session: SessionView,
    pub(in crate::plugins) user: UserView,
    pub(in crate::plugins) is_register: bool,
    pub(in crate::plugins) account_cookie: Option<AccountCookiePayload>,
}

pub(in crate::plugins) enum OAuthSignInError {
    Generic(String),
    AccountLookup(AuthError),
    SessionAuth(AuthError),
    IdentityDenied { code: String, message: String },
    Banned(String),
    EmailNotVerified,
}

impl OAuthSignInError {
    fn from_identity_denial(error: AuthError) -> Self {
        let (_, code, message) = error.error_payload();
        Self::IdentityDenied {
            code: code.unwrap_or_else(|| "validation_failed".into()),
            message,
        }
    }
    fn from_account_lookup(error: AuthError) -> Self {
        if matches!(
            error,
            AuthError::Database(better_auth_core::DatabaseError::AmbiguousAccount { .. })
        ) {
            Self::AccountLookup(error)
        } else {
            Self::Generic(error.to_string())
        }
    }

    pub(in crate::plugins) fn is_ambiguous_account(&self) -> bool {
        matches!(
            self,
            Self::AccountLookup(AuthError::Database(
                better_auth_core::DatabaseError::AmbiguousAccount { .. }
            ))
        )
    }

    pub(in crate::plugins) fn redirect_parts(&self) -> (String, Option<&str>) {
        match self {
            // Upstream turns a plain internal error string into the `error`
            // param verbatim, with no description.
            Self::Generic(message) => (message.replace(' ', "_"), None),
            Self::AccountLookup(error) | Self::SessionAuth(error) => {
                (error.to_string().replace(' ', "_"), None)
            }
            // An APIError instead redirects with its `code` and message, so the
            // param is the constant, not a lowercased word.
            Self::Banned(message) => ("BANNED_USER".to_owned(), Some(message.as_str())),
            Self::IdentityDenied { code, message } => (code.clone(), Some(message.as_str())),
            Self::EmailNotVerified => ("email_not_verified".to_owned(), None),
        }
    }
}

impl From<String> for OAuthSignInError {
    fn from(value: String) -> Self {
        Self::Generic(value)
    }
}

impl From<SessionIssueError> for OAuthSignInError {
    fn from(value: SessionIssueError) -> Self {
        match value {
            SessionIssueError::Auth(error) => Self::SessionAuth(error),
            SessionIssueError::Banned { message } => Self::Banned(message),
        }
    }
}

struct InitiatedOAuthFlow {
    response: SocialSignInResponse,
    state: String,
    payload: OAuthStatePayload,
}

struct FlowStartRequest<'a> {
    provider_name: &'a str,
    provider: &'a OAuthProvider,
    callback_url: &'a str,
    new_user_callback_url: Option<String>,
    error_callback_url: Option<String>,
    scopes: Option<&'a [String]>,
    login_hint: Option<&'a str>,
    additional_params: Option<&'a std::collections::BTreeMap<String, String>>,
    request_sign_up: Option<bool>,
    additional_data: serde_json::Map<String, serde_json::Value>,
    link: Option<OAuthStateLink>,
    disable_redirect: bool,
}

/// Normalized policy shared by social callbacks and One Tap.
#[derive(Clone, Default)]
pub(in crate::plugins) struct OAuthProcessPolicy {
    pub(in crate::plugins) override_user_info: bool,
    pub(in crate::plugins) require_email_verification: bool,
    pub(in crate::plugins) callback_url: Option<String>,
    pub(in crate::plugins) use_updated_user: bool,
}

impl OAuthProcessPolicy {
    const fn for_provider(provider: &OAuthProvider, callback_url: Option<String>) -> Self {
        Self {
            override_user_info: provider.override_user_info_on_sign_in,
            require_email_verification: provider.require_email_verification,
            callback_url,
            use_updated_user: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers (DRY)
// ---------------------------------------------------------------------------

/// Authenticate the current request and return the validated session.
async fn require_session<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> Result<better_auth_core::SessionView, AuthError> {
    ctx.require_cached_session(req)
        .await
        .map(|(_, session)| session)
}

fn generate_pkce() -> (String, String) {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    let mut random = thread_rng();
    let verifier: String = (0..128)
        .filter_map(|_| {
            ALPHABET
                .get(random.gen_range(0..ALPHABET.len()))
                .copied()
                .map(char::from)
        })
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
    (verifier, challenge)
}

fn build_authorization_url(
    provider: &OAuthProvider,
    callback_url: &str,
    scopes: Option<&[String]>,
    state: &str,
    code_challenge: &str,
    login_hint: Option<&str>,
    additional_params: Option<&std::collections::BTreeMap<String, String>>,
) -> AuthResult<String> {
    if provider
        .authorization
        .as_ref()
        .is_some_and(|policy| policy.require_client_secret)
        && (provider.client_id.is_empty() || provider.client_secret.is_empty())
    {
        return Err(AuthError::config(
            "Client ID and client secret are required",
        ));
    }
    if provider
        .authorization
        .as_ref()
        .is_some_and(|policy| policy.require_client_id)
        && provider.client_id.is_empty()
    {
        return Err(AuthError::config("Client ID is required"));
    }
    let effective_scopes: Vec<&str> = provider.authorization.as_ref().map_or_else(
        || {
            scopes.map_or_else(
                || provider.scopes.iter().map(String::as_str).collect(),
                |s| s.iter().map(String::as_str).collect(),
            )
        },
        |policy| {
            let mut effective = Vec::new();
            if !policy.disable_default_scopes {
                effective.extend(provider.scopes.iter().map(String::as_str));
            }
            let configured = policy.configured_scopes.iter().map(String::as_str);
            let requested = scopes.unwrap_or_default().iter().map(String::as_str);
            match policy.scope_order {
                OAuthScopeOrder::ConfiguredThenRequested => {
                    effective.extend(configured);
                    effective.extend(requested);
                }
                OAuthScopeOrder::RequestedThenConfigured => {
                    effective.extend(requested);
                    effective.extend(configured);
                }
            }
            if policy.deduplicate_scopes {
                let mut seen = std::collections::HashSet::new();
                effective.retain(|scope| seen.insert(*scope));
            }
            effective
        },
    );
    let scope_str = effective_scopes.join(" ");

    let mut url = url::Url::parse(&provider.auth_url)
        .map_err(|error| AuthError::internal(format!("Invalid auth URL: {error}")))?;
    set_authorization_param(
        &mut url,
        "response_type",
        provider
            .authorization
            .as_ref()
            .map_or("code", |policy| policy.response_type.as_str()),
    );
    set_authorization_param(&mut url, "client_id", &provider.client_id);
    set_authorization_param(&mut url, "state", state);
    if provider.authorization.is_none() || !effective_scopes.is_empty() {
        set_authorization_param(&mut url, "scope", &scope_str);
    }
    set_authorization_param(
        &mut url,
        "redirect_uri",
        provider
            .authorization
            .as_ref()
            .and_then(|policy| policy.redirect_uri.as_deref())
            .filter(|uri| !uri.is_empty())
            .unwrap_or(callback_url),
    );
    if provider
        .authorization
        .as_ref()
        .is_none_or(|policy| policy.pkce)
    {
        set_authorization_param(&mut url, "code_challenge_method", "S256");
        set_authorization_param(&mut url, "code_challenge", code_challenge);
    }
    if let Some(policy) = &provider.authorization {
        if let Some(mode) = policy
            .response_mode
            .as_deref()
            .filter(|mode| !mode.is_empty())
        {
            set_authorization_param(&mut url, "response_mode", mode);
        }
        if let Some(prompt) = policy
            .prompt
            .as_deref()
            .filter(|prompt| !prompt.is_empty())
            .or(policy.default_prompt.as_deref())
        {
            set_authorization_param(&mut url, "prompt", prompt);
        }
        if effective_scopes.contains(&"bot")
            && let Some(permissions) = policy.discord_permissions
        {
            let value = if permissions.is_nan() {
                "NaN".into()
            } else if permissions == f64::INFINITY {
                "Infinity".into()
            } else if permissions == f64::NEG_INFINITY {
                "-Infinity".into()
            } else {
                let number = serde_json::Number::from_f64(permissions)
                    .ok_or_else(|| AuthError::internal("Invalid Discord permissions number"))?;
                better_auth_core::utils::json::number_to_string(&number)?
            };
            set_authorization_param(&mut url, "permissions", &value);
        }
    }
    if let Some(login_hint) = login_hint.filter(|_| {
        provider
            .authorization
            .as_ref()
            .is_none_or(|policy| policy.login_hint)
    }) {
        set_authorization_param(&mut url, "login_hint", login_hint);
    }
    for (key, value) in &provider.authorization_params {
        set_authorization_param(&mut url, key, value);
    }
    if let Some(params) = additional_params {
        for (key, value) in params {
            set_authorization_param(&mut url, key, value);
        }
    }
    if provider.authorization.as_ref().is_some_and(|policy| {
        matches!(
            policy.scope_encoding,
            super::providers::OAuthScopeEncoding::UriComponent
        )
    }) && let Some(scope) = url
        .query_pairs()
        .find_map(|(key, value)| (key == "scope").then(|| value.into_owned()))
        .filter(|value| !value.is_empty())
    {
        let existing: Vec<_> = url
            .query_pairs()
            .filter(|(key, _)| key != "scope")
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        _ = url.query_pairs_mut().clear().extend_pairs(existing);
        let encoded = [
            ("%21", "!"),
            ("%27", "'"),
            ("%28", "("),
            ("%29", ")"),
            ("%2A", "*"),
        ]
        .into_iter()
        .fold(
            urlencoding::encode(&scope).into_owned(),
            |value, (encoded, literal)| value.replace(encoded, literal),
        );
        let query = format!("{}&scope={encoded}", url.query().unwrap_or_default());
        url.set_query(Some(&query));
    }
    Ok(url.to_string())
}

// URLSearchParams.set replaces duplicate values at the first occurrence;
// unrelated application-owned endpoint parameters retain their order.
fn set_authorization_param(url: &mut url::Url, key: &str, value: &str) {
    let mut replaced = false;
    let mut pairs = Vec::new();
    for (name, previous) in url.query_pairs() {
        if name == key {
            if !replaced {
                pairs.push((key.to_owned(), value.to_owned()));
                replaced = true;
            }
        } else {
            pairs.push((name.into_owned(), previous.into_owned()));
        }
    }
    if !replaced {
        pairs.push((key.to_owned(), value.to_owned()));
    }
    _ = url.query_pairs_mut().clear().extend_pairs(pairs);
}

fn validate_authorization_params(
    params: Option<&std::collections::BTreeMap<String, String>>,
) -> AuthResult<()> {
    const RESERVED: [&str; 8] = [
        "state",
        "client_id",
        "redirect_uri",
        "response_type",
        "code_challenge",
        "code_challenge_method",
        "nonce",
        "scope",
    ];
    if params.is_some_and(|params| params.keys().any(|key| RESERVED.contains(&key.as_str()))) {
        return Err(AuthError::Api {
            status: 400,
            code: Some("VALIDATION_ERROR".into()),
            message: format!(
                "[body.additionalParams] additionalParams cannot include reserved OAuth parameters: {}",
                RESERVED.join(", ")
            ),
        });
    }
    Ok(())
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) async fn refresh_tokens_via_provider(
    provider: &OAuthProvider,
    refresh_token: &str,
) -> AuthResult<OAuthTokenSet> {
    if let Some(handler) = &provider.refresh_access_token {
        return handler
            .refresh_access_token(refresh_token)
            .await
            .map_err(AuthError::internal);
    }

    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    let request = provider_token_request(provider, &mut form)?;
    let token_resp = request
        .form(&form)
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Token refresh failed: {e}")))?;

    if !token_resp.status().is_success() {
        let error_body = token_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_owned());
        return Err(AuthError::internal(format!(
            "Token refresh returned error: {error_body}"
        )));
    }

    let token_data: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse refresh response: {e}")))?;

    parse_token_response(token_data)
}

fn provider_token_request<'a>(
    provider: &'a OAuthProvider,
    form: &mut Vec<(&'a str, &'a str)>,
) -> AuthResult<reqwest::RequestBuilder> {
    let request = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| AuthError::internal(format!("Token HTTP client failed: {error}")))?
        .post(&provider.token_url)
        .header("Accept", "application/json");
    match provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.token_endpoint_auth)
    {
        None => {
            form.extend([
                ("client_id", provider.client_id.as_str()),
                ("client_secret", provider.client_secret.as_str()),
            ]);
            Ok(request)
        }
        Some(OAuthTokenEndpointAuth::None) => {
            if provider.client_id.is_empty() || !provider.client_secret.is_empty() {
                return Err(AuthError::config(
                    "Public token authentication requires client ID and no secret",
                ));
            }
            form.push(("client_id", &provider.client_id));
            Ok(request)
        }
        Some(method) => {
            if provider.client_id.is_empty() || provider.client_secret.is_empty() {
                return Err(AuthError::config(
                    "Client ID and client secret are required",
                ));
            }
            if method == OAuthTokenEndpointAuth::ClientSecretBasic {
                let encode = |value: &str| {
                    url::form_urlencoded::Serializer::new(String::new())
                        .append_key_only(value)
                        .finish()
                };
                Ok(request.basic_auth(
                    encode(&provider.client_id),
                    Some(encode(&provider.client_secret)),
                ))
            } else {
                form.extend([
                    ("client_id", provider.client_id.as_str()),
                    ("client_secret", provider.client_secret.as_str()),
                ]);
                Ok(request)
            }
        }
    }
}

fn parse_token_response(token_data: serde_json::Value) -> AuthResult<OAuthTokenSet> {
    let access_token = token_data
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::internal("Missing access_token in token response"))?
        .to_owned();
    let refresh_token = token_data
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(String::from);
    let id_token = token_data
        .get("id_token")
        .and_then(|v| v.as_str())
        .map(String::from);
    let expiry = |field: &str| -> Option<chrono::DateTime<Utc>> {
        let value = token_data.get(field)?;
        let seconds = match value {
            serde_json::Value::Number(number) => number.as_f64().filter(|value| *value != 0.0)?,
            serde_json::Value::String(value) if !value.is_empty() => {
                value.trim().parse::<f64>().ok()?
            }
            _ => return None,
        };
        let timestamp = Utc::now().timestamp_millis() as f64 + seconds * 1000.0;
        if !timestamp.is_finite() || timestamp.abs() > 8_640_000_000_000_000.0 {
            return None;
        }
        chrono::DateTime::from_timestamp_millis(timestamp.trunc() as i64)
    };
    let access_token_expires_at = expiry("expires_in");
    let refresh_token_expires_at = expiry("refresh_token_expires_in");
    let scopes = match token_data.get("scope") {
        Some(serde_json::Value::String(scope)) => {
            scope.split_whitespace().map(String::from).collect()
        }
        Some(serde_json::Value::Array(scopes)) => scopes
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(String::from)
            .collect(),
        _ => Vec::new(),
    };

    Ok(OAuthTokenSet {
        token_type: token_data
            .get("token_type")
            .and_then(|v| v.as_str())
            .map(String::from),
        access_token: Some(access_token),
        refresh_token,
        access_token_expires_at,
        refresh_token_expires_at,
        scopes,
        id_token,
        raw: Some(token_data),
    })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn validate_authorization_code_via_provider(
    provider: &OAuthProvider,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
    device_id: Option<&str>,
) -> AuthResult<OAuthTokenSet> {
    let redirect_uri = provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.redirect_uri.as_deref())
        .filter(|uri| !uri.is_empty())
        .unwrap_or(redirect_uri);
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ];
    if let Some(client_key) = provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.authorization_code_client_key.as_deref())
        .filter(|value| !value.is_empty())
    {
        form.push(("client_key", client_key));
    }
    if let Some(code_verifier) = code_verifier {
        form.push(("code_verifier", code_verifier));
    }
    if let Some(device_id) = device_id {
        form.push(("device_id", device_id));
    }

    let request = provider_token_request(provider, &mut form)?;
    let token_resp = request
        .form(&form)
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Token exchange failed: {e}")))?;

    if !token_resp.status().is_success() {
        let error_body = token_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_owned());
        return Err(AuthError::internal(format!(
            "Token exchange returned error: {error_body}"
        )));
    }

    let token_data: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse token response: {e}")))?;
    parse_token_response(token_data)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn fetch_user_info_from_provider(
    provider: &OAuthProvider,
    request: OAuthUserInfoRequest,
) -> AuthResult<OAuthUserInfoResponse> {
    if let Some(handler) = &provider.get_user_info {
        let response = handler
            .get_user_info(request)
            .await
            .map_err(AuthError::internal)?;
        return Ok(response);
    }

    if let Some(token) = request
        .id_token
        .as_deref()
        .filter(|_| provider.id_token.is_some())
    {
        // Direct sign-in verifies this immutable token before requesting its profile;
        // the code flow obtains it from the trusted provider token exchange.
        let payload = token
            .split('.')
            .nth(1)
            .ok_or_else(|| AuthError::internal("Missing ID-token payload"))?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let profile: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| AuthError::internal(error.to_string()))?;
        if !super::id_token::hosted_domain_allowed(
            provider,
            profile.get("hd").and_then(serde_json::Value::as_str),
        ) {
            return Err(AuthError::internal("Hosted domain mismatch"));
        }
        let mapper = provider
            .map_user_info
            .ok_or_else(|| AuthError::internal("Missing user-info mapper"))?;
        let user = mapper(profile.clone()).map_err(AuthError::internal)?;
        let response = OAuthUserInfoResponse {
            user,
            data: profile,
        };
        return Ok(response);
    }

    let user_info_url = provider
        .user_info_url
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing user_info_url for provider"))?;
    let access_token = request
        .access_token
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing access token for user-info lookup"))?;
    let mapper = provider
        .map_user_info
        .ok_or_else(|| AuthError::internal("Missing user-info mapper for provider"))?;

    let client = reqwest::Client::new();
    let user_info_resp = client
        .get(user_info_url)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to fetch user info: {e}")))?;

    if !user_info_resp.status().is_success() {
        let error_body = user_info_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_owned());
        return Err(AuthError::internal(format!(
            "User info request failed: {error_body}"
        )));
    }

    let user_info_json: serde_json::Value = user_info_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse user info: {e}")))?;

    let user = mapper(user_info_json.clone())
        .map_err(|e| AuthError::internal(format!("Failed to map user info: {e}")))?;

    let response = OAuthUserInfoResponse {
        user,
        data: user_info_json,
    };
    Ok(response)
}

fn resolve_account_subject(
    provider: &OAuthProvider,
    response: &mut OAuthUserInfoResponse,
) -> AuthResult<()> {
    if let Some(subject) = provider.account_subject {
        response.user.id = subject(&response.data).map_err(AuthError::internal)?;
    }
    Ok(())
}

pub(in crate::plugins) fn parse_callback_user_payload(
    user_data: Option<&str>,
) -> Option<OAuthCallbackUserPayload> {
    let value: serde_json::Value = serde_json::from_str(user_data?).ok()?;
    Some(OAuthCallbackUserPayload {
        name: value
            .get("name")
            .and_then(|value| value.as_object())
            .map(|name| OAuthCallbackUserName {
                first_name: name
                    .get("firstName")
                    .and_then(|value_2| value_2.as_str())
                    .map(String::from),
                last_name: name
                    .get("lastName")
                    .and_then(|value_3| value_3.as_str())
                    .map(String::from),
            }),
        email: value
            .get("email")
            .and_then(|value| value.as_str())
            .map(String::from),
    })
}

fn redirect_response(location: &str) -> AuthResponse {
    AuthResponse::new(302)
        .with_header("content-type", "application/json")
        .with_header("Location", location)
}

fn account_cookie_max_age(config: &better_auth_core::AuthConfig) -> f64 {
    better_auth_core::cache::effective_max_age(
        config
            .session
            .cookie_cache
            .as_ref()
            .map_or(300.0, |cache| cache.max_age),
    )
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) fn create_account_cookie_header(
    config: &better_auth_core::AuthConfig,
    secret: &str,
    payload: &AccountCookiePayload,
) -> AuthResult<String> {
    let max_age = account_cookie_max_age(config);
    let value = create_account_cookie_value(secret, payload, max_age)?;
    better_auth_core::cache::cookie_header(
        &account_cookie_name(config),
        &value,
        Some(max_age),
        config,
    )
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn decode_account_cookie(
    req: &AuthRequest,
    config: &better_auth_core::AuthConfig,
    secret: &str,
) -> AuthResult<Option<AccountCookiePayload>> {
    let Some(value) = get_cookie(req, &account_cookie_name(config)) else {
        return Ok(None);
    };
    decode_account_cookie_value(secret, &value).map(Some)
}

fn attach_state_cookie(
    response: AuthResponse,
    config: &better_auth_core::AuthConfig,
    secret: &str,
    state: &str,
) -> AuthResult<AuthResponse> {
    let value = create_database_state_cookie_value(secret, state)?;
    Ok(response.with_appended_header(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_cookie(
            &state_cookie_name(config),
            &value,
            Duration::minutes(5).num_seconds(),
            config,
        ),
    ))
}

fn attach_cookie_state_payload(
    response: AuthResponse,
    config: &better_auth_core::AuthConfig,
    secret: &str,
    payload: &OAuthStatePayload,
) -> AuthResult<AuthResponse> {
    let value = create_cookie_state_value(secret, payload)?;
    Ok(response.with_appended_header(
        "Set-Cookie",
        better_auth_core::utils::cookie_utils::create_cookie(
            &state_cookie_name(config),
            &value,
            Duration::minutes(5).num_seconds(),
            config,
        ),
    ))
}

fn validate_redirect_target(
    target: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    error_message: &str,
) -> AuthResult<()> {
    if ctx.config.current_origin_check_disabled() {
        return Ok(());
    }
    if ctx.config.is_redirect_target_trusted(target) {
        Ok(())
    } else {
        Err(AuthError::forbidden(error_message.to_owned()))
    }
}

fn build_redirect_url(
    base_url: &str,
    callback_url: Option<&str>,
    params: &[(&str, &str)],
) -> AuthResult<String> {
    let base = url::Url::parse(base_url)
        .map_err(|error| AuthError::internal(format!("Invalid base URL: {error}")))?;
    let mut url = if let Some(callback_url) = callback_url {
        base.join(callback_url)
            .map_err(|error| AuthError::bad_request(format!("Invalid callbackURL: {error}")))?
    } else {
        base.join("/error")
            .map_err(|error| AuthError::internal(format!("Invalid error URL: {error}")))?
    };
    if !params.is_empty() {
        let mut query_segments = Vec::new();
        if let Some(existing_query) = url.query()
            && !existing_query.is_empty()
        {
            query_segments.push(existing_query.to_owned());
        }
        for (key, value) in params {
            query_segments.push(format!(
                "{}={}",
                urlencoding::encode(key),
                urlencoding::encode(value),
            ));
        }
        let query = query_segments.join("&");
        url.set_query(Some(&query));
    }
    Ok(url.to_string())
}

fn auth_base_url(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> String {
    format!(
        "{}{}",
        ctx.config.base_url.trim_end_matches('/'),
        ctx.config.base_path
    )
}

pub(in crate::plugins) fn ambiguous_account_sign_in_response(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResponse {
    redirect_response(&format!(
        "{}/error?error=internal_server_error",
        auth_base_url(ctx)
    ))
}

async fn finish_oauth_session<S: better_auth_core::AuthSchema>(
    user: &S::User,
    is_register: bool,
    policy: &OAuthProcessPolicy,
    meta: &better_auth_core::RequestMeta,
    ctx: &AuthContext<S>,
) -> Result<crate::plugins::helpers::IssuedSession<S>, OAuthSignInError> {
    if !user.email_verified() {
        let config = ctx
            .extensions
            .get::<crate::plugins::email_verification::EmailVerificationConfig>();
        let should_send = if is_register {
            config
                .as_ref()
                .and_then(|config| config.send_on_sign_up)
                .unwrap_or(policy.require_email_verification)
        } else {
            policy.require_email_verification
                && config.as_ref().is_some_and(|config| config.send_on_sign_in)
        };
        if should_send {
            if let Some(config) = config {
                // OAuth delivery completes after identity/account commit, before a session.
                if config.send_verification_email.is_some() {
                    if let Some(email) = user.email() {
                        let plugin = crate::plugins::email_verification::EmailVerificationPlugin::with_config((*config).clone());
                        plugin
                            .send_verification_email_for_user(
                                user,
                                email,
                                policy.callback_url.as_deref(),
                                ctx,
                            )
                            .await
                            .map_err(|error| error.to_string())?;
                    }
                } else if let Some(sender) = ctx.email_verification_override() {
                    crate::plugins::authentication_helpers::run_notification(sender.0.send(
                        &ctx.user_view(user),
                        None,
                        ctx,
                    ))
                    .await;
                }
            } else if let Some(sender) = ctx.email_verification_override() {
                crate::plugins::authentication_helpers::run_notification(sender.0.send(
                    &ctx.user_view(user),
                    None,
                    ctx,
                ))
                .await;
            }
        }
        if policy.require_email_verification {
            return Err(OAuthSignInError::EmailNotVerified);
        }
    }
    issue_user_session(
        ctx,
        &user.id(),
        meta.ip_address.clone(),
        meta.user_agent.clone(),
    )
    .await
    .map_err(OAuthSignInError::from)
}

fn provider_candidate(user_info: &OAuthUserInfo, user_id: &str) -> CreateUser {
    let mut candidate = CreateUser::new();
    candidate.id = Some(user_id.to_owned());
    candidate.email = Some(user_info.email.to_lowercase());
    candidate.name = user_info.name.clone();
    candidate.image = user_info.image.clone();
    candidate.email_verified = Some(user_info.email_verified);
    candidate
}

async fn validate_provider_identity(
    provider: &str,
    profile: &serde_json::Value,
    user: &OAuthUserInfo,
    user_id: &str,
    action: UserValidationAction,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<(), OAuthSignInError> {
    let mut data = UserValidationData {
        user: provider_candidate(user, user_id),
        source: UserValidationSource::oauth(provider, profile, action),
    };
    // Sign-in completion supplies an empty name before the shared policy.
    // Explicit linking validates the original mapped optional name instead.
    data.user.name = Some(user.name.as_deref().unwrap_or_default().to_owned());
    validate_user_info(&ctx.config, &mut data)
        .await
        .map_err(OAuthSignInError::from_identity_denial)
}

/// Mapped provider identity together with its original provenance.
pub(in crate::plugins) struct OAuthIdentity<'a> {
    pub provider_name: &'a str,
    pub user: &'a OAuthUserInfo,
    pub profile: &'a serde_json::Value,
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep OAuth account matching, linking policy, and signup branches together for review"
)]
pub(in crate::plugins) async fn process_oauth_sign_in(
    identity: OAuthIdentity<'_>,
    policy: &OAuthProcessPolicy,
    tokens: &OAuthTokenSet,
    disable_sign_up: bool,
    meta: &better_auth_core::RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<ProcessOAuthUserResult, OAuthSignInError> {
    let OAuthIdentity {
        provider_name,
        user: user_info,
        profile,
    } = identity;
    if user_info.email.is_empty() {
        return Err(OAuthSignInError::Generic("email not found".to_owned()));
    }

    let linked_account = ctx
        .database
        .get_account(provider_name, &user_info.id)
        .await
        .map_err(OAuthSignInError::from_account_lookup)?;

    let token_bundle = encrypt_token_set(
        ctx,
        tokens.access_token.clone(),
        tokens.refresh_token.clone(),
        tokens.id_token.clone(),
    )
    .map_err(|error| error.to_string())?;

    if let Some(existing_account) = linked_account {
        let existing_user = ctx
            .database
            .get_user_by_id(&existing_account.user_id())
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "user not found".to_owned())?;
        validate_provider_identity(
            provider_name,
            profile,
            user_info,
            &existing_user.id(),
            UserValidationAction::SignIn,
            ctx,
        )
        .await?;
        if ctx.config.account.update_account_on_sign_in {
            drop(
                ctx.database
                    .update_account(
                        &existing_account.id(),
                        UpdateAccount {
                            access_token: token_bundle.access_token.clone(),
                            refresh_token: token_bundle.refresh_token.clone(),
                            id_token: token_bundle.id_token.clone(),
                            access_token_expires_at: tokens.access_token_expires_at,
                            refresh_token_expires_at: tokens.refresh_token_expires_at,
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?,
            );
        }

        let mut user = existing_user;

        if user_info.email_verified
            && !user.email_verified()
            && user
                .email()
                .is_some_and(|email| email.eq_ignore_ascii_case(&user_info.email))
        {
            let updated = ctx
                .database
                .update_user(
                    &user.id(),
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
            if policy.use_updated_user {
                user = updated;
            }
        }

        if policy.override_user_info {
            user = ctx
                .database
                .update_user(
                    &user.id(),
                    UpdateUser {
                        name: user_info.name.clone(),
                        image: user_info.image.clone(),
                        email: Some(user_info.email.to_lowercase()),
                        email_verified: Some(
                            user.email()
                                .is_some_and(|email| email.eq_ignore_ascii_case(&user_info.email))
                                && (user.email_verified() || user_info.email_verified),
                        ),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }

        let issued = finish_oauth_session(&user, false, policy, meta, ctx).await?;
        let account_cookie = ctx.config.account.store_account_cookie.then(|| {
            if !ctx.config.account.update_account_on_sign_in {
                return AccountCookiePayload::from_account(&existing_account);
            }
            AccountCookiePayload {
                id: Some(existing_account.id().to_string()),
                user_id: existing_account.user_id().to_string(),
                provider_id: provider_name.to_owned(),
                account_id: existing_account.account_id().to_owned(),
                access_token: token_bundle
                    .access_token
                    .or_else(|| existing_account.access_token().map(str::to_owned)),
                refresh_token: token_bundle
                    .refresh_token
                    .or_else(|| existing_account.refresh_token().map(str::to_owned)),
                id_token: token_bundle
                    .id_token
                    .or_else(|| existing_account.id_token().map(str::to_owned)),
                access_token_expires_at: tokens
                    .access_token_expires_at
                    .or_else(|| existing_account.access_token_expires_at()),
                refresh_token_expires_at: tokens
                    .refresh_token_expires_at
                    .or_else(|| existing_account.refresh_token_expires_at()),
                scope: existing_account.scope().map(str::to_owned),
                password: existing_account.password().map(str::to_owned),
                created_at: Some(existing_account.created_at()),
                updated_at: Some(existing_account.updated_at()),
            }
        });

        return Ok(ProcessOAuthUserResult {
            session: ctx.session_view(&issued.session),
            user: if policy.use_updated_user {
                ctx.user_view(&issued.user)
            } else {
                ctx.user_view(&user)
            },
            is_register: false,
            account_cookie,
        });
    }

    let existing_user = ctx
        .database
        .get_user_by_email(&user_info.email.to_lowercase())
        .await
        .map_err(|error| error.to_string())?;

    if let Some(existing_user) = existing_user {
        let linking = &ctx.config.account.account_linking;
        let trusted_provider = linking
            .trusted_providers
            .iter()
            .any(|trusted| trusted == provider_name);

        // Mirrors upstream's linking guard, including the local-account check:
        // an unverified local account is not implicitly linkable.
        if !linking.enabled
            || linking.disable_implicit_linking
            || (!trusted_provider && !user_info.email_verified)
            || (linking.require_local_email_verified && !existing_user.email_verified())
        {
            return Err(OAuthSignInError::Generic("account not linked".to_owned()));
        }

        let mut linked_user = existing_user;
        validate_provider_identity(
            provider_name,
            profile,
            user_info,
            &linked_user.id(),
            UserValidationAction::LinkAccount,
            ctx,
        )
        .await?;
        let created_account = ctx
            .database
            .create_account(CreateAccount {
                user_id: linked_user.id().to_string(),
                account_id: user_info.id.clone(),
                provider_id: provider_name.to_owned(),
                access_token: token_bundle.access_token,
                refresh_token: token_bundle.refresh_token,
                id_token: token_bundle.id_token,
                access_token_expires_at: tokens.access_token_expires_at,
                refresh_token_expires_at: tokens.refresh_token_expires_at,
                scope: (tokens.raw.is_some() || !tokens.scopes.is_empty())
                    .then(|| tokens.scopes.join(",")),
                password: None,
            })
            .await
            .map_err(|_error| "unable to link account".to_owned())?;

        if user_info.email_verified
            && !linked_user.email_verified()
            && linked_user
                .email()
                .is_some_and(|email| email.eq_ignore_ascii_case(&user_info.email))
        {
            let updated = ctx
                .database
                .update_user(
                    &linked_user.id(),
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
            if policy.use_updated_user {
                linked_user = updated;
            }
        }

        if linking.update_user_info_on_link {
            match ctx
                .database
                .update_user(
                    &linked_user.id(),
                    UpdateUser {
                        name: user_info.name.clone(),
                        image: user_info.image.clone(),
                        ..Default::default()
                    },
                )
                .await
            {
                Ok(updated) => linked_user = updated,
                Err(error) => tracing::warn!(%error, "Could not update user info on account link"),
            }
        }

        if policy.override_user_info {
            linked_user =
                ctx.database
                    .update_user(
                        &linked_user.id(),
                        UpdateUser {
                            name: user_info.name.clone(),
                            image: user_info.image.clone(),
                            email: Some(user_info.email.to_lowercase()),
                            email_verified: Some(
                                linked_user.email().is_some_and(|email| {
                                    email.eq_ignore_ascii_case(&user_info.email)
                                }) && (linked_user.email_verified() || user_info.email_verified),
                            ),
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?;
        }

        let issued = finish_oauth_session(&linked_user, false, policy, meta, ctx).await?;
        let account_cookie = ctx
            .config
            .account
            .store_account_cookie
            .then(|| AccountCookiePayload::from_account(&created_account));

        Ok(ProcessOAuthUserResult {
            session: ctx.session_view(&issued.session),
            user: if policy.use_updated_user {
                ctx.user_view(&issued.user)
            } else {
                ctx.user_view(&linked_user)
            },
            is_register: false,
            account_cookie,
        })
    } else {
        if disable_sign_up {
            return Err(OAuthSignInError::Generic("signup disabled".to_owned()));
        }

        let mut create_user = CreateUser::new()
            .with_email(user_info.email.to_lowercase())
            .with_name(user_info.name.as_deref().unwrap_or_default())
            .with_email_verified(user_info.email_verified);
        crate::plugins::authentication_helpers::apply_creation_input_defaults(
            ctx,
            &mut create_user,
        );
        apply_default_role(ctx, &mut create_user);
        create_user.image = user_info.image.clone();

        let mut create_account = CreateAccount {
            user_id: String::new(),
            account_id: user_info.id.clone(),
            provider_id: provider_name.to_owned(),
            access_token: token_bundle.access_token,
            refresh_token: token_bundle.refresh_token,
            id_token: token_bundle.id_token,
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scope: (tokens.raw.is_some() || !tokens.scopes.is_empty())
                .then(|| tokens.scopes.join(",")),
            password: None,
        };
        let source =
            UserValidationSource::oauth(provider_name, profile, UserValidationAction::CreateUser);
        // OAuth registration commits its identity and provider binding together.
        // Notifications and session creation follow the committed transaction.
        let (persisted_user, persisted_account) =
            better_auth_core::store::transaction(ctx.database.as_ref(), move |tx| {
                Box::pin(async move {
                    let user = tx.create_user_with_source(create_user, source).await?;
                    create_account.user_id = user.id().to_string();
                    let account = tx.create_account(create_account).await?;
                    Ok((user, account))
                })
            })
            .await
            .map_err(|error| {
                if error.status_code() == 403 {
                    OAuthSignInError::from_identity_denial(error)
                } else {
                    OAuthSignInError::Generic("unable to create user".to_owned())
                }
            })?;

        let issued = finish_oauth_session(&persisted_user, true, policy, meta, ctx).await?;
        let account_cookie = ctx
            .config
            .account
            .store_account_cookie
            .then(|| AccountCookiePayload::from_account(&persisted_account));

        Ok(ProcessOAuthUserResult {
            session: ctx.session_view(&issued.session),
            user: if policy.use_updated_user {
                ctx.user_view(&issued.user)
            } else {
                ctx.user_view(&persisted_user)
            },
            is_register: true,
            account_cookie,
        })
    }
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn complete_link_social(
    provider_name: &str,
    user_info: &OAuthUserInfo,
    profile: &serde_json::Value,
    tokens: &OAuthTokenSet,
    link: &OAuthStateLink,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<(), OAuthSignInError> {
    // Explicit linking validates fresh provider data before its trust/email
    // guards or account lookup. The candidate retains the selected local ID.
    let mut candidate = provider_candidate(user_info, &link.user_id);
    candidate.email = (!user_info.email.is_empty()).then(|| user_info.email.clone());
    validate_user_info(
        &ctx.config,
        &mut UserValidationData {
            user: candidate,
            source: UserValidationSource::oauth(
                provider_name,
                profile,
                UserValidationAction::LinkAccount,
            ),
        },
    )
    .await
    .map_err(OAuthSignInError::from_identity_denial)?;
    let linking = &ctx.config.account.account_linking;
    let trusted_provider = linking
        .trusted_providers
        .iter()
        .any(|trusted| trusted == provider_name);

    if !linking.enabled || (!trusted_provider && !user_info.email_verified) {
        return Err("unable_to_link_account".to_owned().into());
    }

    if !linking.allow_different_emails && !user_info.email.eq_ignore_ascii_case(&link.email) {
        return Err("email_does_not_match".to_owned().into());
    }

    if let Some(existing_account) = ctx
        .database
        .get_account(provider_name, &user_info.id)
        .await
        .map_err(OAuthSignInError::from_account_lookup)?
    {
        if existing_account.user_id() != link.user_id {
            return Err("account_already_linked_to_different_user".to_owned().into());
        }

        let token_bundle = encrypt_token_set(
            ctx,
            tokens.access_token.clone(),
            tokens.refresh_token.clone(),
            tokens.id_token.clone(),
        )
        .map_err(|error| error.to_string())?;

        drop(
            ctx.database
                .update_account(
                    &existing_account.id(),
                    UpdateAccount {
                        access_token: token_bundle.access_token,
                        refresh_token: token_bundle.refresh_token,
                        id_token: token_bundle.id_token,
                        access_token_expires_at: tokens.access_token_expires_at,
                        refresh_token_expires_at: tokens.refresh_token_expires_at,
                        scope: (tokens.raw.is_some() || !tokens.scopes.is_empty())
                            .then(|| tokens.scopes.join(",")),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?,
        );

        return Ok(());
    }

    let token_bundle = encrypt_token_set(
        ctx,
        tokens.access_token.clone(),
        tokens.refresh_token.clone(),
        tokens.id_token.clone(),
    )
    .map_err(|error| error.to_string())?;

    drop(
        ctx.database
            .create_account(CreateAccount {
                user_id: link.user_id.clone(),
                account_id: user_info.id.clone(),
                provider_id: provider_name.to_owned(),
                access_token: token_bundle.access_token,
                refresh_token: token_bundle.refresh_token,
                id_token: token_bundle.id_token,
                access_token_expires_at: tokens.access_token_expires_at,
                refresh_token_expires_at: tokens.refresh_token_expires_at,
                scope: (tokens.raw.is_some() || !tokens.scopes.is_empty())
                    .then(|| tokens.scopes.join(",")),
                password: None,
            })
            .await
            .map_err(|_error| "unable_to_link_account".to_owned())?,
    );

    Ok(())
}

async fn sign_in_with_id_token_core(
    body: &SocialSignInRequest,
    id_token: &OAuthIdTokenRequest,
    provider: &OAuthProvider,
    meta: &better_auth_core::RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SocialSignInResponse> {
    if provider.disable_id_token_sign_in
        || provider.verify_id_token.is_none() && provider.id_token.is_none()
    {
        return Err(AuthError::Upstream {
            status: 404,
            code: "ID_TOKEN_NOT_SUPPORTED",
            message: "id_token not supported",
        });
    }
    if !super::id_token::verify_provider_token(provider, &id_token.token, id_token.nonce.as_deref())
        .await
    {
        return Err(AuthError::Upstream {
            status: 401,
            code: "INVALID_TOKEN",
            message: "Invalid token",
        });
    }

    let mut user_info = fetch_user_info_from_provider(
        provider,
        OAuthUserInfoRequest {
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            access_token_expires_at: id_token
                .expires_at
                .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)),
            scopes: id_token.scopes.clone().unwrap_or_default(),
            id_token: Some(id_token.token.clone()),
            user: id_token.user.clone(),
            ..Default::default()
        },
    )
    .await
    .map_err(|_error| AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    })?;

    if user_info.user.email.is_empty() {
        return Err(AuthError::Upstream {
            status: 401,
            code: "USER_EMAIL_NOT_FOUND",
            message: "User email not found",
        });
    }

    resolve_account_subject(provider, &mut user_info).map_err(|_error| AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    })?;

    let outcome = process_oauth_sign_in(
        OAuthIdentity {
            provider_name: &body.provider,
            user: &user_info.user,
            profile: &user_info.data,
        },
        &OAuthProcessPolicy::for_provider(provider, body.callback_url.clone()),
        &OAuthTokenSet {
            access_token: id_token.access_token.clone(),
            id_token: Some(id_token.token.clone()),
            ..Default::default()
        },
        provider.disable_implicit_sign_up && !body.request_sign_up.unwrap_or(false)
            || provider.disable_sign_up,
        meta,
        ctx,
    )
    .await
    .map_err(|error| match error {
        OAuthSignInError::IdentityDenied { code, message } => AuthError::Api {
            status: 403,
            code: Some(code),
            message,
        },
        OAuthSignInError::AccountLookup(error) => error,
        OAuthSignInError::EmailNotVerified => AuthError::Upstream {
            status: 403,
            code: "EMAIL_NOT_VERIFIED",
            message: "Email not verified",
        },
        OAuthSignInError::Generic(message) | OAuthSignInError::Banned(message) => AuthError::Api {
            status: 401,
            code: Some("OAUTH_LINK_ERROR".into()),
            message,
        },
        OAuthSignInError::SessionAuth(error) => AuthError::Api {
            status: 401,
            code: Some("OAUTH_LINK_ERROR".into()),
            message: error.to_string(),
        },
    })?;

    Ok(SocialSignInResponse {
        url: None,
        redirect: false,
        status: None,
        token: Some(outcome.session.token().to_owned()),
        user: Some(outcome.user),
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep provider proof validation and account ownership checks adjacent to the linking write"
)]
async fn link_with_id_token_core(
    body: &LinkSocialRequest,
    id_token: &OAuthIdTokenRequest,
    provider: &OAuthProvider,
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SocialSignInResponse> {
    if provider.disable_id_token_sign_in
        || provider.verify_id_token.is_none() && provider.id_token.is_none()
    {
        return Err(AuthError::Upstream {
            status: 404,
            code: "ID_TOKEN_NOT_SUPPORTED",
            message: "id_token not supported",
        });
    }
    if !super::id_token::verify_provider_token(provider, &id_token.token, id_token.nonce.as_deref())
        .await
    {
        return Err(AuthError::Upstream {
            status: 401,
            code: "INVALID_TOKEN",
            message: "Invalid token",
        });
    }

    let mut response = fetch_user_info_from_provider(
        provider,
        OAuthUserInfoRequest {
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            access_token_expires_at: id_token
                .expires_at
                .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)),
            scopes: id_token.scopes.clone().unwrap_or_default(),
            id_token: Some(id_token.token.clone()),
            user: id_token.user.clone(),
            ..Default::default()
        },
    )
    .await
    .map_err(|_error| AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    })?;

    if response.user.email.is_empty() {
        return Err(AuthError::Upstream {
            status: 401,
            code: "USER_EMAIL_NOT_FOUND",
            message: "User email not found",
        });
    }

    resolve_account_subject(provider, &mut response).map_err(|_error| AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    })?;

    let linked_account = ctx
        .database
        .get_account(&body.provider, &response.user.id)
        .await?;
    if linked_account
        .as_ref()
        .is_some_and(|account| account.user_id() != session.user_id())
    {
        return Err(AuthError::Upstream {
            status: 409,
            code: "SOCIAL_ACCOUNT_ALREADY_LINKED",
            message: "Social account already linked",
        });
    }
    let existing_accounts = ctx.database.get_user_accounts(&session.user_id()).await?;
    if existing_accounts.iter().any(|account| {
        account.provider_id() == body.provider && account.account_id() == response.user.id
    }) {
        return Ok(SocialSignInResponse {
            url: Some(String::new()),
            redirect: false,
            status: Some(true),
            token: None,
            user: None,
        });
    }

    let current_user = ctx
        .database
        .get_user_by_id(&session.user_id())
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let current_email = current_user
        .email()
        .ok_or_else(|| AuthError::forbidden("User email not found"))?;
    let linking = &ctx.config.account.account_linking;
    let trusted_provider = linking
        .trusted_providers
        .iter()
        .any(|trusted| trusted == &body.provider);

    if !linking.enabled || (!trusted_provider && !response.user.email_verified) {
        return Err(AuthError::forbidden(
            "Account not linked - linking not allowed",
        ));
    }
    if !linking.allow_different_emails && !response.user.email.eq_ignore_ascii_case(current_email) {
        return Err(AuthError::forbidden(
            "Account not linked - different emails not allowed",
        ));
    }

    let token_bundle = encrypt_token_set(
        ctx,
        id_token.access_token.clone(),
        id_token.refresh_token.clone(),
        Some(id_token.token.clone()),
    )?;
    drop(
        ctx.database
            .create_account(CreateAccount {
                user_id: session.user_id().to_string(),
                provider_id: body.provider.clone(),
                account_id: response.user.id,
                access_token: token_bundle.access_token,
                refresh_token: token_bundle.refresh_token,
                id_token: token_bundle.id_token,
                access_token_expires_at: id_token
                    .expires_at
                    .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)),
                refresh_token_expires_at: None,
                scope: id_token.scopes.as_ref().map(|scopes| scopes.join(",")),
                password: None,
            })
            .await
            .map_err(|_error| {
                AuthError::bad_request("Account not linked - unable to create account")
            })?,
    );

    if linking.update_user_info_on_link {
        drop(
            ctx.database
                .update_user(
                    &session.user_id(),
                    UpdateUser {
                        name: response.user.name.clone(),
                        image: response.user.image.clone(),
                        ..Default::default()
                    },
                )
                .await,
        );
    }

    Ok(SocialSignInResponse {
        url: Some(String::new()),
        redirect: false,
        status: Some(true),
        token: None,
        user: None,
    })
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

async fn social_sign_in_core(
    body: &SocialSignInRequest,
    config: &OAuthConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<InitiatedOAuthFlow> {
    let provider = config
        .providers
        .get(&body.provider)
        .ok_or_else(|| AuthError::not_found("Provider not found"))?;

    let callback_url = body
        .callback_url
        .clone()
        .unwrap_or_else(|| ctx.config.base_url.clone());
    validate_redirect_target(&callback_url, ctx, "Invalid callbackURL")?;
    if let Some(error_callback_url) = body.error_callback_url.as_deref() {
        validate_redirect_target(error_callback_url, ctx, "Invalid errorCallbackURL")?;
    }
    if let Some(new_user_callback_url) = body.new_user_callback_url.as_deref() {
        validate_redirect_target(new_user_callback_url, ctx, "Invalid newUserCallbackURL")?;
    }

    initiate_oauth_flow_core(
        ctx,
        FlowStartRequest {
            provider_name: &body.provider,
            provider,
            callback_url: &callback_url,
            new_user_callback_url: body.new_user_callback_url.clone(),
            error_callback_url: body.error_callback_url.clone(),
            scopes: body.scopes.as_deref(),
            login_hint: body.login_hint.as_deref(),
            additional_params: body.additional_params.as_ref(),
            request_sign_up: body.request_sign_up,
            additional_data: filter_additional_state_data(body.additional_data.clone()),
            link: None,
            disable_redirect: body.disable_redirect.unwrap_or(false),
        },
    )
    .await
}

async fn link_social_core(
    body: &LinkSocialRequest,
    session: &impl AuthSession,
    config: &OAuthConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<InitiatedOAuthFlow> {
    let provider = config
        .providers
        .get(&body.provider)
        .ok_or_else(|| AuthError::not_found("Provider not found"))?;

    let callback_url = body
        .callback_url
        .clone()
        .unwrap_or_else(|| ctx.config.base_url.clone());
    validate_redirect_target(&callback_url, ctx, "Invalid callbackURL")?;
    if let Some(error_callback_url) = body.error_callback_url.as_deref() {
        validate_redirect_target(error_callback_url, ctx, "Invalid errorCallbackURL")?;
    }

    let user = ctx
        .database
        .get_user_by_id(&session.user_id())
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User email not found"))?;

    initiate_oauth_flow_core(
        ctx,
        FlowStartRequest {
            provider_name: &body.provider,
            provider,
            callback_url: &callback_url,
            new_user_callback_url: None,
            error_callback_url: body.error_callback_url.clone(),
            scopes: body.scopes.as_deref(),
            login_hint: None,
            additional_params: body.additional_params.as_ref(),
            request_sign_up: body.request_sign_up,
            additional_data: filter_additional_state_data(body.additional_data.clone()),
            link: Some(OAuthStateLink {
                email: email.to_lowercase(),
                user_id: session.user_id().to_string(),
            }),
            disable_redirect: body.disable_redirect.unwrap_or(false),
        },
    )
    .await
}

/// Shared logic for social sign-in and link-social flows.
///
/// Both flows build a verification payload, store it, construct the
/// authorization URL, and return a redirect response. The only difference
/// is `link_user_id` (None for sign-in, Some for linking).
async fn initiate_oauth_flow_core(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    request: FlowStartRequest<'_>,
) -> AuthResult<InitiatedOAuthFlow> {
    let (code_verifier, code_challenge) = generate_pkce();
    let state: String = {
        let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
        let mut random = thread_rng();
        (0..32)
            .filter_map(|_| {
                alphabet
                    .get(random.gen_range(0..alphabet.len()))
                    .copied()
                    .map(char::from)
            })
            .collect()
    };

    let proxy = better_auth_core::hooks::current_request_hook_context().and_then(|req| {
        req.extensions
            .get::<crate::plugins::oauth_proxy::OAuthProxyFlow>()
    });
    let mut payload = OAuthStatePayload::new(
        proxy
            .as_ref()
            .map_or(request.callback_url, |flow| flow.callback_url.as_str())
            .to_owned(),
        code_verifier,
        request.error_callback_url,
        request.new_user_callback_url,
        request.link,
        request.request_sign_up,
        request.additional_data,
    );
    capture_server_context(&mut payload, &state, &ctx.config.secret)?;
    drop(payload.additional_data.insert(
        "oauthState".to_owned(),
        serde_json::Value::String(state.clone()),
    ));
    if proxy.is_some()
        && let Some(req) = better_auth_core::hooks::current_request_hook_context()
    {
        req.extensions
            .insert(crate::plugins::oauth_proxy::IssuedProxyState {
                state: state.clone(),
                payload: payload.clone(),
            });
    }

    match ctx.config.account.store_state_strategy {
        better_auth_core::OAuthStateStrategy::Database => {
            let created = ctx
                .verifications()
                .create(CreateVerification {
                    identifier: state.clone(),
                    value: serde_json::to_string(&payload)?,
                    expires_at: Utc::now() + Duration::minutes(10),
                })
                .await?;
            if created.is_none() {
                return Err(AuthError::internal("Unable to create verification"));
            }
        }
        better_auth_core::OAuthStateStrategy::Cookie => {}
    }

    let url = build_authorization_url(
        request.provider,
        &format!(
            "{}/callback/{}",
            proxy.as_ref().map_or_else(
                || auth_base_url(ctx),
                |flow| flow.effective_auth_base_url.clone()
            ),
            request.provider_name
        ),
        request.scopes,
        &state,
        &code_challenge,
        request.login_hint,
        request.additional_params,
    )?;

    Ok(InitiatedOAuthFlow {
        response: SocialSignInResponse {
            url: Some(url),
            redirect: !request.disable_redirect,
            status: None,
            token: None,
            user: None,
        },
        state,
        payload,
    })
}

// ---------------------------------------------------------------------------
// Old handlers (rewritten to call core)
// ---------------------------------------------------------------------------

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) async fn handle_social_sign_in(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let body: SocialSignInRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    validate_authorization_params(body.additional_params.as_ref())?;
    let meta = better_auth_core::RequestMeta::from_request(req);
    if let Some(id_token) = &body.id_token {
        let provider = config
            .providers
            .get(&body.provider)
            .ok_or_else(|| AuthError::not_found("Provider not found"))?;
        let response = match sign_in_with_id_token_core(&body, id_token, provider, &meta, ctx).await
        {
            Err(AuthError::Database(better_auth_core::DatabaseError::AmbiguousAccount {
                ..
            })) => return Ok(ambiguous_account_sign_in_response(ctx)),
            result => result?,
        };
        let mut auth_response = AuthResponse::json(200, &response).map_err(AuthError::from)?;
        if let Some(token) = response.token.as_deref() {
            auth_response = auth_response.with_appended_header(
                "Set-Cookie",
                better_auth_core::utils::cookie_utils::create_session_cookie(token, &ctx.config),
            );
        }
        return Ok(auth_response);
    }

    let flow = match social_sign_in_core(&body, config, ctx).await {
        Err(error @ AuthError::Config(_)) => {
            tracing::error!(%error, "OAuth authorization configuration failed");
            return Ok(AuthResponse::new(500));
        }
        result => result?,
    };
    let response = flow.response;
    let mut auth_response = AuthResponse::json(200, &response).map_err(AuthError::from)?;

    if let Some(url) = response.url.as_deref()
        && response.redirect
    {
        auth_response = auth_response.with_header("Location", url);
    }
    if let Some(token) = response.token.as_deref() {
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            better_auth_core::utils::cookie_utils::create_session_cookie(token, &ctx.config),
        );
    }

    match ctx.config.account.store_state_strategy {
        better_auth_core::OAuthStateStrategy::Database => {
            if response.token.is_some() {
                return Ok(auth_response);
            }
            attach_state_cookie(auth_response, &ctx.config, &ctx.config.secret, &flow.state)
        }
        better_auth_core::OAuthStateStrategy::Cookie => {
            if response.token.is_some() {
                return Ok(auth_response);
            }
            attach_cookie_state_payload(
                auth_response,
                &ctx.config,
                &ctx.config.secret,
                &flow.payload,
            )
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep OAuth state consumption, provider errors, and cookie cleanup in their required order"
)]
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) async fn handle_callback(
    config: &OAuthConfig,
    provider_name: &str,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let default_error_url = format!("{}/error", auth_base_url(ctx));
    let meta = better_auth_core::RequestMeta::from_request(req);

    let mut merged = HashMap::new();
    if req.method() == &better_auth_core::HttpMethod::Post {
        if let Some(body) = &req.body
            && !body.is_empty()
        {
            let body_text = String::from_utf8(body.clone()).map_err(|error| {
                AuthError::bad_request(format!("Invalid callback body: {error}"))
            })?;
            let parsed_body =
                serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&body_text)
                    .ok()
                    .map(|body_2| {
                        body_2
                            .into_iter()
                            .filter_map(|(key, value)| match value {
                                serde_json::Value::String(value) => Some((key, value)),
                                serde_json::Value::Null => None,
                                other @ (serde_json::Value::Bool(_)
                                | serde_json::Value::Number(_)
                                | serde_json::Value::Array(_)
                                | serde_json::Value::Object(_)) => Some((key, other.to_string())),
                            })
                            .collect::<HashMap<String, String>>()
                    })
                    .or_else(|| {
                        Some(
                            url::form_urlencoded::parse(body_text.as_bytes())
                                .into_owned()
                                .collect::<HashMap<String, String>>(),
                        )
                    })
                    .ok_or_else(|| AuthError::bad_request("Invalid callback request"))?;
            merged.extend(parsed_body);
        }

        // Match the TS callback route: POST body seeds the redirect, but
        // explicit query parameters win over conflicting body fields.
        merged.extend(req.query.clone());

        let mut params = url::form_urlencoded::Serializer::new(String::new());
        let mut pairs: Vec<_> = merged.iter().collect();
        pairs.sort_by_key(|(left, _)| *left);
        for (key, value) in pairs {
            _ = params.append_pair(key, value);
        }
        return Ok(redirect_response(&format!(
            "{}/callback/{}?{}",
            auth_base_url(ctx),
            provider_name,
            params.finish()
        )));
    }

    let merged_2 = req.query.clone();

    let error = merged_2.get("error").cloned();
    let Some(state_param) = merged_2.get("state").cloned() else {
        let separator = if default_error_url.contains('?') {
            '&'
        } else {
            '?'
        };
        return Ok(redirect_response(&format!(
            "{default_error_url}{separator}state=state_not_found"
        )));
    };
    let payload = match ctx.config.account.store_state_strategy {
        better_auth_core::OAuthStateStrategy::Database => {
            let verification = match ctx.verifications().find(&state_param).await {
                Ok(Some(verification)) => verification,
                Ok(None) => {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=state_mismatch"
                    )));
                }
                Err(_) => {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=internal_server_error"
                    )));
                }
            };

            let payload: OAuthStatePayload = match verification.value().and_then(|value| {
                serde_json::from_str(value)
                    .map_err(|error| AuthError::internal(format!("Invalid state payload: {error}")))
            }) {
                Ok(payload) => payload,
                Err(_) => {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=internal_server_error"
                    )));
                }
            };
            let state_error_url = payload.error_url.as_deref().unwrap_or(&default_error_url);
            let state_mismatch = || {
                redirect_response(
                    &build_redirect_url(
                        &auth_base_url(ctx),
                        Some(state_error_url),
                        &[("error", "state_mismatch")],
                    )
                    .unwrap_or_else(|_| format!("{default_error_url}?error=state_mismatch")),
                )
            };
            if payload
                .additional_data
                .get("oauthState")
                .is_some_and(|value| value.as_str() != Some(state_param.as_str()))
            {
                return Ok(state_mismatch());
            }
            if !ctx.config.account.skip_state_cookie_check {
                let persisted_state =
                    get_cookie(req, &state_cookie_name(&ctx.config)).and_then(|value| {
                        decode_database_state_cookie_value(&ctx.config.secret, &value).ok()
                    });
                if persisted_state.as_deref() != Some(state_param.as_str()) {
                    return Ok(state_mismatch());
                }
            }
            if ctx.verifications().delete(&state_param).await.is_err() {
                return Ok(redirect_response(&format!(
                    "{default_error_url}?error=internal_server_error"
                ))
                .with_appended_header(
                    "Set-Cookie",
                    better_auth_core::utils::cookie_utils::create_clear_cookie(
                        &state_cookie_name(&ctx.config),
                        &ctx.config,
                    ),
                ));
            }
            payload
        }
        better_auth_core::OAuthStateStrategy::Cookie => {
            let Some(cookie_value) = get_cookie(req, &state_cookie_name(&ctx.config)) else {
                return Ok(redirect_response(&format!(
                    "{default_error_url}?error=please_restart_the_process"
                )));
            };
            match decode_cookie_state_value(&ctx.config.secret, &cookie_value) {
                Ok(payload)
                    if payload
                        .additional_data
                        .get("oauthState")
                        .and_then(serde_json::Value::as_str)
                        == Some(state_param.as_str()) =>
                {
                    payload
                }
                Ok(_) => {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=state_mismatch"
                    )));
                }
                Err(_) => {
                    return Ok(redirect_response(&format!(
                        "{default_error_url}?error=please_restart_the_process"
                    )));
                }
            }
        }
    };

    let clear_state_cookie = better_auth_core::utils::cookie_utils::create_clear_cookie(
        &state_cookie_name(&ctx.config),
        &ctx.config,
    );
    let error_url = payload
        .error_url
        .clone()
        .unwrap_or_else(|| default_error_url.clone());

    let redirect_on_error = |error_code: &str, description: Option<&str>| {
        let mut parameters = vec![("error", error_code)];
        if let Some(description) = description {
            parameters.push(("error_description", description));
        }
        redirect_response(
            &build_redirect_url(&auth_base_url(ctx), Some(&error_url), &parameters)
                .unwrap_or_else(|_error| format!("{default_error_url}?error={error_code}")),
        )
        .with_appended_header("Set-Cookie", clear_state_cookie.clone())
    };

    if payload.is_expired() {
        return Ok(redirect_on_error("state_mismatch", None));
    }
    if let Some(error) = error.as_deref() {
        return Ok(redirect_on_error(
            error,
            merged_2.get("error_description").map(String::as_str),
        ));
    }

    if let Some(context) = verified_server_context(&payload, &state_param, &ctx.config.secret) {
        req.extensions()
            .insert(RecoveredOAuthServerContext(context));
    }

    let Some(code) = merged_2.get("code").cloned() else {
        return Ok(redirect_on_error("no_code", None));
    };
    let Some(provider) = config.providers.get(provider_name) else {
        return Ok(redirect_on_error("oauth_provider_not_found", None));
    };

    let Ok(tokens) = validate_authorization_code_via_provider(
        provider,
        &code,
        &format!("{}/callback/{}", auth_base_url(ctx), provider_name),
        provider
            .authorization
            .as_ref()
            .is_none_or(|policy| policy.pkce)
            .then_some(payload.code_verifier.as_str()),
        merged_2.get("device_id").map(String::as_str),
    )
    .await
    else {
        return Ok(redirect_on_error("invalid_code", None));
    };

    let Ok(mut user_info) = fetch_user_info_from_provider(
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
            user: parse_callback_user_payload(merged_2.get("user").map(String::as_str)),
        },
    )
    .await
    else {
        return Ok(redirect_on_error("unable_to_get_user_info", None));
    };

    if resolve_account_subject(provider, &mut user_info).is_err() {
        return Ok(redirect_on_error("unable_to_get_user_info", None));
    }

    if let Some(link) = payload.link.as_ref() {
        if let Err(error_3) = complete_link_social(
            provider_name,
            &user_info.user,
            &user_info.data,
            &tokens,
            link,
            ctx,
        )
        .await
        {
            if error_3.is_ambiguous_account() {
                return Ok(AuthResponse::new(500));
            }
            let (code, description) = match &error_3 {
                OAuthSignInError::Generic(message) => (message.clone(), None),
                _ => error_3.redirect_parts(),
            };
            return Ok(redirect_on_error(&code, description));
        }

        return Ok(redirect_response(&payload.callback_url)
            .with_appended_header("Set-Cookie", clear_state_cookie));
    }

    let disable_sign_up = provider.disable_implicit_sign_up
        && !payload.request_sign_up.unwrap_or(false)
        || provider.disable_sign_up;
    let outcome = match process_oauth_sign_in(
        OAuthIdentity {
            provider_name,
            user: &user_info.user,
            profile: &user_info.data,
        },
        &OAuthProcessPolicy::for_provider(provider, Some(payload.callback_url.clone())),
        &tokens,
        disable_sign_up,
        &meta,
        ctx,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error_4) => {
            if error_4.is_ambiguous_account() {
                return Ok(redirect_response(&format!(
                    "{default_error_url}?error=internal_server_error"
                ))
                .with_appended_header("Set-Cookie", clear_state_cookie.clone()));
            }
            let (code_2, description) = error_4.redirect_parts();
            return Ok(redirect_on_error(&code_2, description));
        }
    };

    let redirect_target = if outcome.is_register {
        payload
            .new_user_url
            .as_deref()
            .unwrap_or(&payload.callback_url)
            .to_owned()
    } else {
        payload.callback_url.clone()
    };
    let mut response = redirect_response(&redirect_target)
        .with_appended_header("Set-Cookie", clear_state_cookie)
        .with_appended_header(
            "Set-Cookie",
            better_auth_core::utils::cookie_utils::create_session_cookie(
                outcome.session.token(),
                &ctx.config,
            ),
        );
    if let Some(account_cookie) = outcome.account_cookie.as_ref() {
        response = response.with_appended_header(
            "Set-Cookie",
            create_account_cookie_header(&ctx.config, &ctx.config.secret, account_cookie)?,
        );
    }
    Ok(response)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) async fn handle_link_social(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let session = require_session(req, ctx)
        .await
        .map_err(|error| match error {
            AuthError::Unauthenticated => AuthError::Api {
                status: 401,
                code: Some("UNAUTHORIZED".to_owned()),
                message: "Unauthorized".to_owned(),
            },
            error @ (AuthError::Api { .. }
            | AuthError::Upstream { .. }
            | AuthError::BadRequest(_)
            | AuthError::InvalidRequest(_)
            | AuthError::Validation(_)
            | AuthError::InvalidCredentials
            | AuthError::AuthenticationFailed(_)
            | AuthError::SessionNotFound
            | AuthError::Forbidden(_)
            | AuthError::SessionCreationCancelled
            | AuthError::UserCreationCancelled
            | AuthError::BannedUser(_)
            | AuthError::Unauthorized
            | AuthError::UserNotFound
            | AuthError::NotFound(_)
            | AuthError::Conflict(_)
            | AuthError::MethodNotAllowed(_)
            | AuthError::PayloadTooLarge(_)
            | AuthError::UnprocessableEntity(_)
            | AuthError::RateLimited
            | AuthError::NotImplemented(_)
            | AuthError::Config(_)
            | AuthError::Database(_)
            | AuthError::Serialization(_)
            | AuthError::Plugin { .. }
            | AuthError::CallbackFailure(_)
            | AuthError::Internal(_)
            | AuthError::PasswordHash(_)
            | AuthError::Jwt(_)) => error,
        })?;
    let body: LinkSocialRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    validate_authorization_params(body.additional_params.as_ref())?;
    if let Some(id_token) = &body.id_token {
        let provider = config
            .providers
            .get(&body.provider)
            .ok_or_else(|| AuthError::not_found("Provider not found"))?;
        let response = match link_with_id_token_core(&body, id_token, provider, &session, ctx).await
        {
            Err(AuthError::Database(better_auth_core::DatabaseError::AmbiguousAccount {
                ..
            })) => return Ok(AuthResponse::new(500)),
            result => result?,
        };
        return AuthResponse::json(200, &response).map_err(AuthError::from);
    }

    let flow = match link_social_core(&body, &session, config, ctx).await {
        Err(error @ AuthError::Config(_)) => {
            tracing::error!(%error, "OAuth linking authorization configuration failed");
            return Ok(AuthResponse::new(500));
        }
        result => result?,
    };
    let response = flow.response;
    let mut auth_response = AuthResponse::json(200, &response).map_err(AuthError::from)?;

    if let Some(url) = response.url.as_deref()
        && response.redirect
    {
        auth_response = auth_response.with_header("Location", url);
    }

    match ctx.config.account.store_state_strategy {
        better_auth_core::OAuthStateStrategy::Database => {
            attach_state_cookie(auth_response, &ctx.config, &ctx.config.secret, &flow.state)
        }
        better_auth_core::OAuthStateStrategy::Cookie => attach_cookie_state_payload(
            auth_response,
            &ctx.config,
            &ctx.config.secret,
            &flow.payload,
        ),
    }
}
