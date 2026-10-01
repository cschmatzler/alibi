use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;

use better_auth_core::entity::AuthAccount;
use better_auth_core::{AuthConfig, AuthRequest, AuthResult, OAuthStateStrategy};

/// Only trusted hooks populate this context before OAuth state issuance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OAuthServerContext {
    #[serde(rename = "anonymousUserId")]
    pub(crate) anonymous_user_id: String,
}

pub(crate) struct CapturedOAuthServerContext(pub(crate) OAuthServerContext);
pub(crate) struct RecoveredOAuthServerContext(pub(crate) OAuthServerContext);

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct OAuthStateLink {
    pub email: String,
    #[serde(rename = "userId")]
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct OAuthStatePayload {
    #[serde(rename = "callbackURL")]
    pub callback_url: String,
    #[serde(rename = "codeVerifier")]
    pub code_verifier: String,
    #[serde(rename = "errorURL", skip_serializing_if = "Option::is_none")]
    pub error_url: Option<String>,
    #[serde(rename = "newUserURL", skip_serializing_if = "Option::is_none")]
    pub new_user_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<OAuthStateLink>,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
    #[serde(rename = "requestSignUp", skip_serializing_if = "Option::is_none")]
    pub request_sign_up: Option<bool>,
    // Old state codecs permitted arbitrary client additionalData under these
    // names. Deserialize them without assigning authority; authenticate the
    // original values before narrowing to the trusted typed context.
    #[serde(
        rename = "serverContext",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "better_auth_core::utils::json::deserialize_optional_value"
    )]
    pub server_context: Option<Value>,
    #[serde(
        rename = "_serverContextProof",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "better_auth_core::utils::json::deserialize_optional_value"
    )]
    pub server_context_proof: Option<Value>,
    #[serde(flatten)]
    #[serde(deserialize_with = "better_auth_core::utils::json::deserialize_map")]
    pub additional_data: Map<String, Value>,
}

impl OAuthStatePayload {
    pub(crate) fn new(
        callback_url: String,
        code_verifier: String,
        error_url: Option<String>,
        new_user_url: Option<String>,
        link: Option<OAuthStateLink>,
        request_sign_up: Option<bool>,
        additional_data: Map<String, Value>,
    ) -> Self {
        Self {
            callback_url,
            code_verifier,
            error_url,
            new_user_url,
            link,
            expires_at: (Utc::now() + Duration::minutes(10)).timestamp_millis(),
            request_sign_up,
            server_context: None,
            server_context_proof: None,
            additional_data,
        }
    }

    pub(crate) fn is_expired(&self) -> bool {
        self.expires_at < Utc::now().timestamp_millis()
    }
}

fn server_context_mac(secret: &str, state: &str, context: &Value) -> AuthResult<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| better_auth_core::AuthError::internal("Invalid OAuth context signing key"))?;
    let bytes = better_auth_core::utils::json::to_vec(context)?;
    let state_len = u64::try_from(state.len())
        .map_err(|_| better_auth_core::AuthError::internal("OAuth state is too long"))?;
    let context_len = u64::try_from(bytes.len())
        .map_err(|_| better_auth_core::AuthError::internal("OAuth context is too long"))?;
    mac.update(b"better-auth-rs:oauth:server-context:v1\0");
    mac.update(&state_len.to_be_bytes());
    mac.update(state.as_bytes());
    mac.update(&context_len.to_be_bytes());
    mac.update(&bytes);
    Ok(mac)
}

pub(crate) fn capture_server_context(
    payload: &mut OAuthStatePayload,
    state: &str,
    secret: &str,
) -> AuthResult<()> {
    let Some(context) = better_auth_core::hooks::current_request_hook_context()
        .and_then(|request| request.extensions.get::<CapturedOAuthServerContext>())
    else {
        return Ok(());
    };
    let value = better_auth_core::utils::json::to_value(&context.0)?;
    let proof = URL_SAFE_NO_PAD.encode(
        server_context_mac(secret, state, &value)?
            .finalize()
            .into_bytes(),
    );
    payload.server_context = Some(value);
    payload.server_context_proof = Some(Value::String(proof));
    Ok(())
}

pub(crate) fn verified_server_context(
    payload: &OAuthStatePayload,
    state: &str,
    secret: &str,
) -> Option<OAuthServerContext> {
    let context = payload.server_context.as_ref()?;
    let proof = payload.server_context_proof.as_ref()?.as_str()?;
    if proof.len() != 43 {
        return None;
    }
    let proof = URL_SAFE_NO_PAD.decode(proof).ok()?;
    server_context_mac(secret, state, context)
        .ok()?
        .verify_slice(&proof)
        .ok()?;
    // Only an authenticated newly issued value may select a stored user.
    better_auth_core::utils::json::from_slice(&better_auth_core::utils::json::to_vec(context).ok()?)
        .ok()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccountCookiePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "idToken")]
    pub id_token: Option<String>,
    #[serde(
        rename = "accessTokenExpiresAt",
        serialize_with = "better_auth_core::utils::datetime::serialize_optional"
    )]
    pub access_token_expires_at: Option<chrono::DateTime<Utc>>,
    #[serde(
        rename = "refreshTokenExpiresAt",
        serialize_with = "better_auth_core::utils::datetime::serialize_optional"
    )]
    pub refresh_token_expires_at: Option<chrono::DateTime<Utc>>,
    pub scope: Option<String>,
    pub password: Option<String>,
    #[serde(
        rename = "createdAt",
        serialize_with = "better_auth_core::utils::datetime::serialize_optional"
    )]
    pub created_at: Option<chrono::DateTime<Utc>>,
    #[serde(
        rename = "updatedAt",
        serialize_with = "better_auth_core::utils::datetime::serialize_optional"
    )]
    pub updated_at: Option<chrono::DateTime<Utc>>,
}

impl AccountCookiePayload {
    pub(crate) fn from_account(account: &impl AuthAccount) -> Self {
        Self {
            id: Some(account.id().to_string()),
            user_id: account.user_id().to_string(),
            provider_id: account.provider_id().to_string(),
            account_id: account.account_id().to_string(),
            access_token: account.access_token().map(str::to_string),
            refresh_token: account.refresh_token().map(str::to_string),
            id_token: account.id_token().map(str::to_string),
            access_token_expires_at: account.access_token_expires_at(),
            refresh_token_expires_at: account.refresh_token_expires_at(),
            scope: account.scope().map(str::to_string),
            password: account.password().map(str::to_string),
            created_at: Some(account.created_at()),
            updated_at: Some(account.updated_at()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateCookieClaims {
    state: String,
    exp: usize,
    iat: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StatePayloadClaims {
    #[serde(flatten)]
    payload: OAuthStatePayload,
    exp: usize,
    iat: usize,
}

pub(crate) fn state_cookie_name(config: &AuthConfig) -> String {
    match config.account.store_state_strategy {
        OAuthStateStrategy::Cookie => related_cookie_name(config, "oauth_state"),
        OAuthStateStrategy::Database => related_cookie_name(config, "state"),
    }
}

pub(crate) fn account_cookie_name(config: &AuthConfig) -> String {
    related_cookie_name(config, "account_data")
}

pub(crate) fn create_database_state_cookie_value(secret: &str, state: &str) -> AuthResult<String> {
    let now = Utc::now();
    let claims = StateCookieClaims {
        state: state.to_string(),
        exp: (now + Duration::minutes(10)).timestamp() as usize,
        iat: now.timestamp() as usize,
    };
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

pub(crate) fn decode_database_state_cookie_value(secret: &str, token: &str) -> AuthResult<String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    Ok(decode::<StateCookieClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?
    .claims
    .state)
}

pub(crate) fn create_cookie_state_value(
    secret: &str,
    payload: &OAuthStatePayload,
) -> AuthResult<String> {
    let now = Utc::now();
    let claims = StatePayloadClaims {
        payload: payload.clone(),
        exp: (now + Duration::minutes(10)).timestamp() as usize,
        iat: now.timestamp() as usize,
    };
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

pub(crate) fn decode_cookie_state_value(
    secret: &str,
    token: &str,
) -> AuthResult<OAuthStatePayload> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    Ok(decode::<StatePayloadClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?
    .claims
    .payload)
}

pub(crate) fn create_account_cookie_value(
    secret: &str,
    payload: &AccountCookiePayload,
    max_age: f64,
) -> AuthResult<String> {
    super::account_cookie::encode(secret, payload, max_age)
}

pub(crate) fn decode_account_cookie_value(
    secret: &str,
    token: &str,
) -> AuthResult<AccountCookiePayload> {
    super::account_cookie::decode(secret, token)
}

pub(crate) fn get_cookie(req: &AuthRequest, name: &str) -> Option<String> {
    let header = req.headers.get("cookie")?;
    header
        .split(';')
        .filter_map(|cookie| {
            let trimmed = cookie.trim();
            let (cookie_name, cookie_value) = trimmed.split_once('=')?;
            (cookie_name == name).then_some(cookie_value.to_string())
        })
        .next()
}

pub(crate) fn related_cookie_name(config: &AuthConfig, suffix: &str) -> String {
    config
        .session
        .cookie_name
        .strip_suffix("session_token")
        .map(|prefix| format!("{}{}", prefix, suffix))
        .unwrap_or_else(|| format!("better-auth.{}", suffix))
}

pub(crate) fn filter_additional_state_data(
    additional_data: Option<Map<String, Value>>,
) -> Map<String, Value> {
    additional_data
        .unwrap_or_default()
        .into_iter()
        .filter(|(key, _)| !reserved_state_key(key))
        .collect()
}

fn reserved_state_key(key: &str) -> bool {
    matches!(
        key,
        "callbackURL"
            | "codeVerifier"
            | "errorURL"
            | "newUserURL"
            | "link"
            | "expiresAt"
            | "requestSignUp"
            | "serverContext"
            | "_serverContextProof"
    )
}
