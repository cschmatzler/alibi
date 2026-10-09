mod grant;
pub use grant::*;
mod http;
mod issuance;
mod redemption;
pub(super) mod types;

use crate::helpers::{SessionIssueError, create_user_session_record};
use alibi_core::entity::{AuthSession, AuthUser};
use alibi_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateDeviceCode, RequestMeta,
    UpdateDeviceCode,
};
use chrono::{Duration, Utc};
use rand::distr::{Alphanumeric, SampleString};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use types::{
    DeviceActionRequest, DeviceActionResponse, DeviceCodeRequest, DeviceCodeResponse,
    DeviceErrorResponse, DeviceTokenRequest, DeviceTokenResponse, DeviceVerifyResponse,
};
use url::Url;

const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

const DEVICE_STATUS_PENDING: &str = "pending";

const DEVICE_STATUS_APPROVED: &str = "approved";

const DEVICE_STATUS_DENIED: &str = "denied";

const DEFAULT_USER_CODE_CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const INVALID_DEVICE_CODE: &str = "Invalid device code";

const EXPIRED_DEVICE_CODE: &str = "Device code has expired";

const EXPIRED_USER_CODE: &str = "User code has expired";

const AUTHORIZATION_PENDING: &str = "Authorization pending";

const ACCESS_DENIED: &str = "Access denied";

const INVALID_USER_CODE: &str = "Invalid user code";

const DEVICE_CODE_ALREADY_PROCESSED: &str = "Device code already processed";

const DEVICE_CODE_NOT_CLAIMED: &str = "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying";

const POLLING_TOO_FREQUENTLY: &str = "Polling too frequently";

const USER_NOT_FOUND: &str = "User not found";

const FAILED_TO_CREATE_SESSION: &str = "Failed to create session";

const INVALID_DEVICE_CODE_STATUS: &str = "Invalid device code status";

const AUTHENTICATION_REQUIRED: &str = "Authentication required";

const INVALID_CLIENT_ID: &str = "Invalid client ID";

const CLIENT_ID_MISMATCH: &str = "Client ID mismatch";

const INVALID_REQUEST: &str = "Invalid request";

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

type ValidateClientCallback = dyn Fn(String) -> BoxFuture<AuthResult<bool>> + Send + Sync;

type DeviceAuthRequestCallback =
    dyn Fn(String, Option<String>) -> BoxFuture<AuthResult<()>> + Send + Sync;

type CodeGenerator = dyn Fn() -> BoxFuture<AuthResult<String>> + Send + Sync;

#[derive(Clone)]
struct DeviceAuthorizationConfig {
    expires_in: Duration,
    interval: Duration,
    device_code_length: usize,
    user_code_length: usize,
    generate_device_code: Option<Arc<CodeGenerator>>,
    generate_user_code: Option<Arc<CodeGenerator>>,
    validate_client: Option<Arc<ValidateClientCallback>>,
    on_device_auth_request: Option<Arc<DeviceAuthRequestCallback>>,
    verification_uri: Option<String>,
    grant: Option<Arc<dyn DeviceAuthorizationGrant>>,
}

impl Default for DeviceAuthorizationConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::minutes(30),
            interval: Duration::seconds(5),
            device_code_length: 40,
            user_code_length: 8,
            generate_device_code: None,
            generate_user_code: None,
            validate_client: None,
            on_device_auth_request: None,
            verification_uri: None,
            grant: None,
        }
    }
}

impl fmt::Debug for DeviceAuthorizationConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAuthorizationConfig")
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .field("device_code_length", &self.device_code_length)
            .field("user_code_length", &self.user_code_length)
            .field(
                "generate_device_code",
                &self.generate_device_code.as_ref().map(|_| "custom"),
            )
            .field(
                "generate_user_code",
                &self.generate_user_code.as_ref().map(|_| "custom"),
            )
            .field(
                "validate_client",
                &self.validate_client.as_ref().map(|_| "custom"),
            )
            .field(
                "on_device_auth_request",
                &self.on_device_auth_request.as_ref().map(|_| "custom"),
            )
            .field("verification_uri", &self.verification_uri)
            .finish()
    }
}

#[derive(Clone, Copy)]
enum DeviceDecision {
    Approve,
    Deny,
}

impl DeviceDecision {
    const fn status(self) -> &'static str {
        match self {
            Self::Approve => DEVICE_STATUS_APPROVED,
            Self::Deny => DEVICE_STATUS_DENIED,
        }
    }

    const fn forbidden_message(self) -> &'static str {
        match self {
            Self::Approve => "You are not authorized to approve this device authorization",
            Self::Deny => "You are not authorized to deny this device authorization",
        }
    }
}

/// OAuth 2.0 device authorization grant plugin.
pub struct DeviceAuthorizationPlugin {
    config: DeviceAuthorizationConfig,
}

impl fmt::Debug for DeviceAuthorizationPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAuthorizationPlugin")
            .finish_non_exhaustive()
    }
}

impl Default for DeviceAuthorizationPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceAuthorizationPlugin {
    /// Create the plugin with TS-aligned defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: DeviceAuthorizationConfig::default(),
        }
    }

    /// Override the device-code expiration window.
    #[must_use]
    pub const fn expires_in(mut self, duration: Duration) -> Self {
        self.config.expires_in = duration;
        self
    }

    /// Override the minimum polling interval enforced by `/device/token`.
    #[must_use]
    pub const fn interval(mut self, duration: Duration) -> Self {
        self.config.interval = duration;
        self
    }

    /// Override the generated device-code length.
    #[must_use]
    pub const fn device_code_length(mut self, length: usize) -> Self {
        self.config.device_code_length = length;
        self
    }

    /// Override the generated user-code length.
    #[must_use]
    pub const fn user_code_length(mut self, length: usize) -> Self {
        self.config.user_code_length = length;
        self
    }

    /// Override the verification page URI returned to devices.
    #[must_use]
    pub fn verification_uri(mut self, uri: impl Into<String>) -> Self {
        self.config.verification_uri = Some(uri.into());
        self
    }

    /// Use a custom device-code generator.
    #[must_use]
    pub fn generate_device_code_with<F>(mut self, generator: F) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        self.config.generate_device_code = Some(Arc::new(move || {
            let code = generator();
            Box::pin(async move { Ok(code) })
        }));
        self
    }

    /// Use a custom user-code generator.
    #[must_use]
    pub fn generate_user_code_with<F>(mut self, generator: F) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        self.config.generate_user_code = Some(Arc::new(move || {
            let code = generator();
            Box::pin(async move { Ok(code) })
        }));
        self
    }

    /// Use an asynchronous device-code generator.
    #[must_use]
    pub fn generate_device_code_async_with<F, Fut>(mut self, generator: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<String>> + Send + 'static,
    {
        self.config.generate_device_code = Some(Arc::new(move || Box::pin(generator())));
        self
    }

    /// Use an asynchronous user-code generator.
    #[must_use]
    pub fn generate_user_code_async_with<F, Fut>(mut self, generator: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<String>> + Send + 'static,
    {
        self.config.generate_user_code = Some(Arc::new(move || Box::pin(generator())));
        self
    }

    /// Validate the OAuth client identifier before issuing or redeeming codes.
    #[must_use]
    pub fn validate_client<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<bool>> + Send + 'static,
    {
        self.config.validate_client =
            Some(Arc::new(move |client_id| Box::pin(callback(client_id))));
        self
    }

    /// Run a hook when a device authorization request is created.
    #[must_use]
    pub fn on_device_auth_request<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(String, Option<String>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<()>> + Send + 'static,
    {
        self.config.on_device_auth_request = Some(Arc::new(move |client_id, scope| {
            Box::pin(callback(client_id, scope))
        }));
        self
    }

    async fn validate_client_id(&self, client_id: &str) -> AuthResult<bool> {
        match &self.config.validate_client {
            Some(callback) => callback(client_id.to_owned())
                .await
                .map_err(device_callback_error),
            None => Ok(true),
        }
    }

    async fn generate_device_code(&self) -> AuthResult<String> {
        match &self.config.generate_device_code {
            Some(generator) => generator().await.map_err(device_callback_error),
            None => {
                Ok(Alphanumeric.sample_string(&mut rand::rng(), self.config.device_code_length))
            }
        }
    }

    async fn generate_user_code(&self) -> AuthResult<String> {
        match &self.config.generate_user_code {
            Some(generator) => generator().await.map_err(device_callback_error),
            None => Ok(default_generate_user_code(self.config.user_code_length)),
        }
    }
}

#[derive(Clone, Copy)]
enum DeviceRequestKind {
    Issuance,
    Token,
    Decision,
}

alibi_core::impl_auth_plugin! {
    DeviceAuthorizationPlugin, "device-authorization";
    routes {
        post "/device/code" => handle_device_code, "device_code";
        post "/device/token" => handle_device_token, "device_token";
        get "/device" => handle_device_verify, "device_verify";
        post "/device/approve" => handle_device_approve, "device_approve";
        post "/device/deny" => handle_device_deny, "device_deny";
    }
    extra {
    fn static_openapi_metadata(&self) -> alibi_core::PluginOpenApiMetadata {
        self.grant_openapi(crate::metadata::plugin_metadata(<Self as alibi_core::AuthPlugin<S>>::name(self), &<Self as alibi_core::AuthPlugin<S>>::routes(self)))
    }

    fn openapi_metadata(&self, ctx: &alibi_core::AuthInitContext<S>) -> alibi_core::PluginOpenApiMetadata {
        self.grant_openapi(crate::metadata::instance_plugin_metadata(<Self as alibi_core::AuthPlugin<S>>::name(self), &<Self as alibi_core::AuthPlugin<S>>::routes(self), ctx))
    }

        fn rate_limits(&self) -> Vec<alibi_core::PluginRateLimit> {
            vec![alibi_core::PluginRateLimit { matches: |path| path == "/device", limit: alibi_core::EndpointRateLimit { window_seconds: self.config.expires_in.to_std().map_or(0.0, |duration| duration.as_secs_f64()), max_requests: 5.0 } }]
        }
        fn allowed_media_types(&self, route: &alibi_core::AuthRoute) -> Vec<&'static str> {
            if route.path == "/device/code" {
                vec!["application/json", "application/x-www-form-urlencoded"]
            } else {
                vec!["application/json"]
            }
        }
    }
}

fn device_callback_error(error: AuthError) -> AuthError {
    match error {
        AuthError::Api { .. } | AuthError::Upstream { .. } | AuthError::CallbackFailure(_) => error,
        error => AuthError::CallbackFailure(Box::new(error)),
    }
}

// Pinned createAuthEndpoint applies metadata.noStore when the handler starts,
// including application API errors, but excludes schema/media rejections.
fn set_device_no_store_headers(req: &AuthRequest) {
    req.queue_response_header("Cache-Control", "no-store");
    req.queue_response_header("Pragma", "no-cache");
    if let Some(call) = alibi_core::endpoint::current_endpoint_call_context() {
        call.set_response_header("Cache-Control", "no-store");
        call.set_response_header("Pragma", "no-cache");
    }
}

fn duration_seconds_floor(duration: Duration) -> i64 {
    let seconds = duration.num_seconds();
    // Chrono truncates toward zero; upstream Math.floor rounds negative fractions down.
    seconds - i64::from(duration < Duration::seconds(seconds))
}

fn is_unique_constraint_error(error: &AuthError) -> bool {
    let AuthError::Database(alibi_core::DatabaseError::Constraint(message)) = error else {
        return false;
    };
    let message = message.to_ascii_lowercase();
    message.contains("unique constraint")
        || message.contains("unique key constraint")
        || message.contains("duplicate entry")
        || message.contains("duplicate key")
        || message.contains("e11000")
}

fn deserialize_device_body<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
) -> Result<T, AuthResponse> {
    serde_json::from_value(value).map_err(|_error| AuthResponse::text(400, "Invalid request body"))
}

fn validate_device_media(req: &AuthRequest, issuance: bool) -> Result<bool, AuthResponse> {
    let raw_content_type = req
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.as_str());
    let content_type = raw_content_type.map(|value| {
        value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
    });
    let is_form = content_type.as_deref() == Some("application/x-www-form-urlencoded");
    let allowed = if issuance {
        "application/json, application/x-www-form-urlencoded"
    } else {
        "application/json"
    };
    let missing = req.body.is_some() && raw_content_type.is_none_or(str::is_empty);
    if missing
        || content_type
            .as_deref()
            .is_some_and(|value| value != "application/json" && !(issuance && is_form))
    {
        let message = if missing {
            format!("Content-Type is required. Allowed types: {allowed}")
        } else {
            format!(
                "Content-Type \"{}\" is not allowed. Allowed types: {allowed}",
                raw_content_type.unwrap_or_default()
            )
        };
        return Err(AuthResponse::json(
            415,
            &serde_json::json!({"message":message,"code":"UNSUPPORTED_MEDIA_TYPE"}),
        )
        .unwrap_or_else(|_| AuthResponse::text(415, "Unsupported media type")));
    }
    Ok(is_form)
}

fn parse_device_body(
    req: &AuthRequest,
    kind: DeviceRequestKind,
) -> Result<serde_json::Value, AuthResponse> {
    let issuance = matches!(kind, DeviceRequestKind::Issuance);
    let is_form = validate_device_media(req, issuance)?;
    let pairs = is_form.then(|| {
        url::form_urlencoded::parse(req.body.as_deref().unwrap_or_default())
            .into_owned()
            .collect::<Vec<_>>()
    });
    let mut body = if let Some(pairs) = &pairs {
        let mut object = serde_json::Map::new();
        for (key, value) in pairs {
            drop(object.insert(key.clone(), serde_json::Value::String(value.clone())));
        }
        serde_json::Value::Object(object)
    } else {
        req.body_as_json::<serde_json::Value>().map_err(|_error| {
            AuthResponse::json(
                400,
                &serde_json::json!({"code":"BAD_REQUEST","message":"Invalid JSON in request body"}),
            )
            .unwrap_or_else(|_| AuthResponse::text(400, "Invalid JSON"))
        })?
    };
    let fields = match kind {
        DeviceRequestKind::Issuance => &["client_id", "user_id", "scope"][..],
        DeviceRequestKind::Token => &["grant_type", "device_code", "client_id"][..],
        DeviceRequestKind::Decision => &["userCode"][..],
    };
    let mut issues = Vec::new();
    if body.is_object() {
        for field in fields {
            let value = body.get(*field);
            if !issuance && *field == "grant_type" {
                if value.and_then(serde_json::Value::as_str) != Some(DEVICE_GRANT_TYPE) {
                    issues.push(format!(
                        "[body.grant_type] Invalid input: expected \"{DEVICE_GRANT_TYPE}\""
                    ));
                }
            } else if !(value.is_some_and(serde_json::Value::is_string)
                || value.is_none() && issuance && matches!(*field, "user_id" | "scope"))
            {
                issues.push(format!(
                    "[body.{field}] Invalid input: expected string, received {}",
                    json_type(value)
                ));
            }
        }
    } else {
        issues.push(format!(
            "[body] Invalid input: expected object, received {}",
            json_type(Some(&body))
        ));
    }
    if !issues.is_empty() {
        let message = issues.join("; ");
        return Err(if issuance {
            device_error_response(400, "invalid_request", &message)
                .unwrap_or_else(|_| AuthResponse::text(400, message))
        } else {
            AuthResponse::json(
                400,
                &serde_json::json!({ "message": message, "code": "VALIDATION_ERROR" }),
            )
            .unwrap_or_else(|_| AuthResponse::text(400, "Validation failed"))
        });
    }
    if let Some(pairs) = &pairs {
        for field in fields {
            let values = pairs
                .iter()
                .filter(|(key, value)| key == field && !value.is_empty())
                .map(|(_, value)| value)
                .collect::<Vec<_>>();
            if values.len() > 1 {
                return Err(device_error_response(
                    400,
                    "invalid_request",
                    &format!("{field} must not be repeated"),
                )
                .unwrap_or_else(|_| AuthResponse::text(400, "Repeated request parameter"))
                .with_header("Cache-Control", "no-store")
                .with_header("Pragma", "no-cache"));
            }
            if let Some(value) = values.first()
                && let Some(object) = body.as_object_mut()
            {
                drop(object.insert(
                    (*field).to_owned(),
                    serde_json::Value::String((*value).clone()),
                ));
            }
        }
    }
    Ok(body)
}

const fn json_type(value: Option<&serde_json::Value>) -> &'static str {
    match value {
        None => "undefined",
        Some(serde_json::Value::Null) => "null",
        Some(serde_json::Value::Bool(_)) => "boolean",
        Some(serde_json::Value::Number(_)) => "number",
        Some(serde_json::Value::String(_)) => "string",
        Some(serde_json::Value::Array(_)) => "array",
        Some(serde_json::Value::Object(_)) => "object",
    }
}

fn build_verification_uris(
    verification_uri: Option<&str>,
    base_url: &str,
    user_code: &str,
) -> AuthResult<(String, String)> {
    let uri = verification_uri
        .filter(|uri| !uri.is_empty())
        .unwrap_or("/device");
    let parsed_verification_url = match Url::parse(uri) {
        Ok(url) => url,
        Err(_) => Url::parse(base_url)
            .map_err(|error| AuthError::config(format!("Invalid base URL: {error}")))?
            .join(uri)
            .map_err(|error| {
                AuthError::bad_request(format!("Invalid verification URI: {error}"))
            })?,
    };

    let mut verification_uri_complete = parsed_verification_url.clone();
    // URLSearchParams.set replaces the first matching key and removes any
    // later copies, preserving the surrounding query and fragment.
    let mut replaced = false;
    let mut pairs = Vec::new();
    for (key, value) in verification_uri_complete.query_pairs() {
        if key == "user_code" {
            if !replaced {
                pairs.push((key.into_owned(), user_code.to_owned()));
                replaced = true;
            }
        } else {
            pairs.push((key.into_owned(), value.into_owned()));
        }
    }
    if !replaced {
        pairs.push(("user_code".to_owned(), user_code.to_owned()));
    }
    let _ignored_extend_pairs = verification_uri_complete
        .query_pairs_mut()
        .clear()
        .extend_pairs(pairs);

    Ok((
        parsed_verification_url.to_string(),
        verification_uri_complete.to_string(),
    ))
}

async fn find_device_code_by_user_code(
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    user_code: &str,
) -> AuthResult<Option<alibi_core::DeviceCode>> {
    // Custom generators may include punctuation or mixed case. Upstream tries
    // their exact spelling first and only normalizes the default alphabet.
    if let Some(record) = ctx.database.get_device_code_by_user_code(user_code).await?
        && record.user_code == user_code
    {
        return Ok(Some(record));
    }
    let normalized = user_code
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_uppercase())
        .collect::<String>();
    if normalized == user_code
        || normalized.is_empty()
        || !normalized
            .bytes()
            .all(|byte| DEFAULT_USER_CODE_CHARSET.contains(&byte))
    {
        return Ok(None);
    }
    Ok(ctx
        .database
        .get_device_code_by_user_code(&normalized)
        .await?
        .filter(|record| record.user_code == normalized))
}

fn default_generate_user_code(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    rand::fill(&mut bytes);
    bytes
        .into_iter()
        .map(|byte| {
            let index = usize::from(byte) % DEFAULT_USER_CODE_CHARSET.len();
            char::from(
                DEFAULT_USER_CODE_CHARSET
                    .get(index)
                    .copied()
                    .unwrap_or(b'A'),
            )
        })
        .collect()
}

fn device_error_response(
    status: u16,
    error: &str,
    error_description: &str,
) -> AuthResult<AuthResponse> {
    AuthResponse::json(
        status,
        &DeviceErrorResponse {
            error: error.to_owned(),
            error_description: error_description.to_owned(),
        },
    )
    .map_err(AuthError::from)
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers;
    use alibi_core::{AuthResponse, CreateDeviceCode, CreateUser, HttpMethod};
    use chrono::{Duration, Utc};
    use serde_json::Value;
    use std::collections::HashMap;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    type TestSchema = alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

    #[tokio::test]
    async fn issuance_retries_collisions_three_times_and_runs_request_hook_once() {
        let ctx = test_helpers::create_test_context().await;
        let attempts = Arc::new(AtomicUsize::new(0));
        let hooks = Arc::new(AtomicUsize::new(0));
        let plugin = DeviceAuthorizationPlugin::new()
            .generate_device_code_with({
                let attempts = std::sync::Arc::clone(&attempts);
                move || {
                    let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                    if attempt < 2 {
                        "duplicate-device".to_owned()
                    } else {
                        "unique-device".to_owned()
                    }
                }
            })
            .generate_user_code_async_with(|| async { Ok("custom-code".to_owned()) })
            .on_device_auth_request({
                let hooks = std::sync::Arc::clone(&hooks);
                move |_, scope| {
                    let hooks = std::sync::Arc::clone(&hooks);
                    async move {
                        assert_eq!(scope, None);
                        hooks.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                }
            });
        ctx.database
            .create_device_code(CreateDeviceCode {
                device_code: "duplicate-device".to_owned(),
                user_code: "existing-code".to_owned(),
                user_id: None,
                expires_at: Utc::now() + Duration::hours(1),
                status: "pending".to_owned(),
                last_polled_at: None,
                polling_interval: Some(5000),
                client_id: Some("client".to_owned()),
                scope: None,
            })
            .await
            .unwrap();
        let request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/code",
            None,
            Some(serde_json::json!({ "client_id": "client", "scope": "", "user_id": "" })),
        );
        let response = plugin.handle_device_code(&request, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            (*(json_body(&response))
                .get("device_code")
                .unwrap_or(&Value::Null)),
            "unique-device"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert_eq!(hooks.load(Ordering::SeqCst), 1);
        let stored = ctx
            .database
            .get_device_code_by_device_code("unique-device")
            .await
            .unwrap()
            .unwrap();
        assert!(stored.scope.is_none());
        assert!(stored.user_id.is_none());

        let exhausted_attempts = Arc::new(AtomicUsize::new(0));
        let exhausted = DeviceAuthorizationPlugin::new().generate_device_code_with({
            let attempts_2 = std::sync::Arc::clone(&exhausted_attempts);
            move || {
                attempts_2.fetch_add(1, Ordering::SeqCst);
                "duplicate-device".to_owned()
            }
        });
        let failure = exhausted.handle_device_code(&request, &ctx).await.unwrap();
        assert_eq!(failure.status, 500);
        assert_eq!(
            json_body(&failure),
            serde_json::json!({ "error": "server_error", "error_description": "Failed to generate a unique device code" })
        );
        assert_eq!(exhausted_attempts.load(Ordering::SeqCst), 3);
        assert_eq!(
            ctx.database
                .get_device_code_by_device_code("duplicate-device")
                .await
                .unwrap()
                .unwrap()
                .user_code,
            "existing-code"
        );
    }

    #[tokio::test]
    async fn generators_enforce_unicode_character_limit_before_persistence() {
        let ctx = test_helpers::create_test_context().await;
        let request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/code",
            None,
            Some(serde_json::json!({ "client_id": "client" })),
        );
        let too_long = DeviceAuthorizationPlugin::new()
            .generate_device_code_async_with(|| async { Ok("🦀".repeat(192)) });
        let failure = too_long.handle_device_code(&request, &ctx).await.unwrap();
        assert_eq!(failure.status, 400);
        assert_eq!(
            (*(json_body(&failure))
                .get("error_description")
                .unwrap_or(&Value::Null)),
            "Generated device code must be at most 191 characters"
        );
        assert!(
            ctx.database
                .get_device_code_by_device_code(&"🦀".repeat(192))
                .await
                .unwrap()
                .is_none()
        );
        let too_long_user = DeviceAuthorizationPlugin::new()
            .generate_device_code_with(|| "short-device".to_owned())
            .generate_user_code_with(|| "🦀".repeat(192));
        let failure_2 = too_long_user
            .handle_device_code(&request, &ctx)
            .await
            .unwrap();
        assert_eq!(failure_2.status, 400);
        assert_eq!(
            (*(json_body(&failure_2))
                .get("error_description")
                .unwrap_or(&Value::Null)),
            "Generated user code must be at most 191 characters"
        );
        assert!(
            ctx.database
                .get_device_code_by_device_code("short-device")
                .await
                .unwrap()
                .is_none()
        );
        let valid = DeviceAuthorizationPlugin::new()
            .generate_device_code_with(|| "🦀".repeat(191))
            .generate_user_code_with(|| "🦀".repeat(191));
        assert_eq!(
            valid
                .handle_device_code(&request, &ctx)
                .await
                .unwrap()
                .status,
            200
        );
        assert!(
            ctx.database
                .get_device_code_by_device_code(&"🦀".repeat(191))
                .await
                .unwrap()
                .is_some()
        );
    }

    fn json_body(response: &AuthResponse) -> Value {
        serde_json::from_slice(&response.body).unwrap()
    }

    fn device_token_request(device_code: &str, client_id: &str) -> AuthRequest {
        test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/token",
            None,
            Some(serde_json::json!({
                "grant_type": DEVICE_GRANT_TYPE,
                "device_code": device_code,
                "client_id": client_id,
            })),
        )
    }

    fn device_verify_request(user_code: &str) -> AuthRequest {
        let mut query = HashMap::new();
        drop(query.insert("user_code".to_owned(), user_code.to_owned()));
        test_helpers::create_auth_request(HttpMethod::Get, "/device", None, None, query)
    }

    /// `GET /device` as a signed-in user, which is what binds the code to them.
    /// `/device/approve` and `/device/deny` reject codes that were never claimed.
    fn device_claim_request(user_code: &str, token: &str) -> AuthRequest {
        let mut query = HashMap::new();
        drop(query.insert("user_code".to_owned(), user_code.to_owned()));
        test_helpers::create_auth_request(HttpMethod::Get, "/device", Some(token), None, query)
    }

    async fn create_context_with_user(
        email: &str,
    ) -> (
        AuthContext<TestSchema>,
        alibi_core::wire::UserView,
        alibi_core::wire::SessionView,
    ) {
        test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email(email.to_owned())
                .with_name("Device Auth User"),
            Duration::hours(1),
        )
        .await
    }

    // Upstream source: packages/better-auth/src/plugins/device-authorization/routes.ts and device-authorization.test.ts; adapted to the Rust plugin handlers.
    #[tokio::test]
    async fn test_device_code_response_shape_and_storage() {
        let plugin = DeviceAuthorizationPlugin::new()
            .expires_in(Duration::minutes(5))
            .interval(Duration::seconds(2))
            .verification_uri("/auth/device?lang=en");
        let ctx = test_helpers::create_test_context().await;

        let request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/code",
            None,
            Some(serde_json::json!({
                "client_id": "test-client",
                "scope": "openid profile",
            })),
        );

        let response = plugin.handle_device_code(&request, &ctx).await.unwrap();
        let body = json_body(&response);

        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers.get("Cache-Control"),
            Some(&"no-store".to_owned())
        );
        assert_eq!((*(body).get("expires_in").unwrap_or(&Value::Null)), 300);
        assert_eq!((*(body).get("interval").unwrap_or(&Value::Null)), 2);
        assert!(
            (*(body).get("device_code").unwrap_or(&Value::Null))
                .as_str()
                .unwrap()
                .len()
                >= 40
        );
        assert!(
            (*(body).get("user_code").unwrap_or(&Value::Null))
                .as_str()
                .unwrap()
                .len()
                >= 8
        );
        assert!(
            (*(body).get("user_code").unwrap_or(&Value::Null))
                .as_str()
                .unwrap()
                .chars()
                .all(|char| {
                    u8::try_from(char).is_ok_and(|byte| DEFAULT_USER_CODE_CHARSET.contains(&byte))
                })
        );
        assert!(
            (*(body).get("verification_uri").unwrap_or(&Value::Null))
                .as_str()
                .unwrap()
                .contains("/auth/device?lang=en")
        );
        assert!(
            (*(body)
                .get("verification_uri_complete")
                .unwrap_or(&Value::Null))
            .as_str()
            .unwrap()
            .contains("lang=en")
        );
        assert!(
            (*(body)
                .get("verification_uri_complete")
                .unwrap_or(&Value::Null))
            .as_str()
            .unwrap()
            .contains("user_code=")
        );

        let stored = ctx
            .database
            .get_device_code_by_device_code(
                (*(body).get("device_code").unwrap_or(&Value::Null))
                    .as_str()
                    .unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.polling_interval, Some(2000));
        assert_eq!(stored.client_id.as_deref(), Some("test-client"));
        assert_eq!(stored.scope.as_deref(), Some("openid profile"));
    }

    // Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: client validation scenarios; adapted to the Rust plugin builder API.
    #[tokio::test]
    async fn test_device_code_rejects_invalid_client() {
        let plugin = DeviceAuthorizationPlugin::new()
            .validate_client(|client_id| async move { Ok(client_id == "valid-client") });
        let ctx = test_helpers::create_test_context().await;

        let request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/code",
            None,
            Some(serde_json::json!({
                "client_id": "invalid-client",
            })),
        );

        let response = plugin.handle_device_code(&request, &ctx).await.unwrap();
        let body = json_body(&response);

        assert_eq!(response.status, 400);
        assert_eq!(
            (*(body).get("error").unwrap_or(&Value::Null)),
            "invalid_client"
        );
        assert_eq!(
            (*(body).get("error_description").unwrap_or(&Value::Null)),
            INVALID_CLIENT_ID
        );
    }

    // Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: callback/generator coverage; adapted to the Rust plugin builder API.
    #[tokio::test]
    async fn test_device_code_uses_custom_generators_and_hook() {
        let hook_calls = Arc::new(AtomicUsize::new(0));
        let hook_calls_clone = std::sync::Arc::clone(&hook_calls);
        let plugin = DeviceAuthorizationPlugin::new()
            .generate_device_code_with(|| "custom-device-code".to_owned())
            .generate_user_code_with(|| "CUSTOM12".to_owned())
            .on_device_auth_request(move |client_id, scope| {
                let hook_calls_2 = std::sync::Arc::clone(&hook_calls_clone);
                async move {
                    assert_eq!(client_id, "hook-client");
                    assert_eq!(scope.as_deref(), Some("openid"));
                    hook_calls_2.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            })
            .verification_uri("https://example.com/device");
        let ctx = test_helpers::create_test_context().await;

        let request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/code",
            None,
            Some(serde_json::json!({
                "client_id": "hook-client",
                "scope": "openid",
            })),
        );

        let response = plugin.handle_device_code(&request, &ctx).await.unwrap();
        let body = json_body(&response);

        assert_eq!(
            (*(body).get("device_code").unwrap_or(&Value::Null)),
            "custom-device-code"
        );
        assert_eq!(
            (*(body).get("user_code").unwrap_or(&Value::Null)),
            "CUSTOM12"
        );
        assert_eq!(
            (*(body).get("verification_uri").unwrap_or(&Value::Null)),
            "https://example.com/device"
        );
        assert_eq!(
            (*(body)
                .get("verification_uri_complete")
                .unwrap_or(&Value::Null)),
            "https://example.com/device?user_code=CUSTOM12"
        );
        assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
    }

    // Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: "should return authorization_pending when not approved".
    #[tokio::test]
    async fn test_device_token_pending_returns_authorization_pending() {
        let plugin = DeviceAuthorizationPlugin::new();
        let ctx = test_helpers::create_test_context().await;

        let create_request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/code",
            None,
            Some(serde_json::json!({ "client_id": "test-client" })),
        );
        let create_response = plugin
            .handle_device_code(&create_request, &ctx)
            .await
            .unwrap();
        let create_body = json_body(&create_response);

        let token_request = device_token_request(
            (*(create_body).get("device_code").unwrap_or(&Value::Null))
                .as_str()
                .unwrap(),
            "test-client",
        );
        let token_response = plugin
            .handle_device_token(&token_request, &ctx)
            .await
            .unwrap();
        let token_body = json_body(&token_response);

        assert_eq!(token_response.status, 400);
        assert_eq!(
            (*(token_body).get("error").unwrap_or(&Value::Null)),
            "authorization_pending"
        );
        assert_eq!(
            (*(token_body)
                .get("error_description")
                .unwrap_or(&Value::Null)),
            AUTHORIZATION_PENDING
        );
    }

    // Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: "should return expired_token for expired device codes".
    #[tokio::test]
    async fn test_device_token_expired_returns_error_and_deletes_record() {
        let plugin = DeviceAuthorizationPlugin::new();
        let ctx = test_helpers::create_test_context().await;

        let stored = ctx
            .database
            .create_device_code(CreateDeviceCode {
                device_code: "expired-device-code".to_owned(),
                user_code: "EXPIRED12".to_owned(),
                user_id: None,
                expires_at: Utc::now() - Duration::seconds(1),
                status: DEVICE_STATUS_PENDING.to_owned(),
                last_polled_at: None,
                polling_interval: Some(5000),
                client_id: Some("test-client".to_owned()),
                scope: None,
            })
            .await
            .unwrap();

        let response = plugin
            .handle_device_token(
                &device_token_request(&stored.device_code, "test-client"),
                &ctx,
            )
            .await
            .unwrap();
        let body = json_body(&response);

        assert_eq!(response.status, 400);
        assert_eq!(
            (*(body).get("error").unwrap_or(&Value::Null)),
            "expired_token"
        );
        assert_eq!(
            (*(body).get("error_description").unwrap_or(&Value::Null)),
            EXPIRED_DEVICE_CODE
        );
        assert!(
            ctx.database
                .get_device_code_by_device_code(&stored.device_code)
                .await
                .unwrap()
                .is_none()
        );
    }

    // Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: "should return error for invalid device code".
    #[tokio::test]
    async fn test_device_token_invalid_device_code_returns_invalid_grant() {
        let plugin = DeviceAuthorizationPlugin::new();
        let ctx = test_helpers::create_test_context().await;

        let response = plugin
            .handle_device_token(
                &device_token_request("invalid-device-code", "test-client"),
                &ctx,
            )
            .await
            .unwrap();
        let body = json_body(&response);

        assert_eq!(response.status, 400);
        assert_eq!(
            (*(body).get("error").unwrap_or(&Value::Null)),
            "invalid_grant"
        );
        assert_eq!(
            (*(body).get("error_description").unwrap_or(&Value::Null)),
            INVALID_DEVICE_CODE
        );
    }

    // Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: "should enforce rate limiting with slow_down error".
    #[tokio::test]
    async fn test_device_token_rate_limits_with_slow_down() {
        let plugin = DeviceAuthorizationPlugin::new().interval(Duration::seconds(5));
        let ctx = test_helpers::create_test_context().await;

        let create_request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/code",
            None,
            Some(serde_json::json!({ "client_id": "test-client" })),
        );
        let create_response = plugin
            .handle_device_code(&create_request, &ctx)
            .await
            .unwrap();
        let create_body = json_body(&create_response);
        let device_code = (*(create_body).get("device_code").unwrap_or(&Value::Null))
            .as_str()
            .unwrap();

        let first = plugin
            .handle_device_token(&device_token_request(device_code, "test-client"), &ctx)
            .await
            .unwrap();
        assert_eq!(
            (*(json_body(&first)).get("error").unwrap_or(&Value::Null)),
            "authorization_pending"
        );

        let second = plugin
            .handle_device_token(&device_token_request(device_code, "test-client"), &ctx)
            .await
            .unwrap();
        let second_body = json_body(&second);

        assert_eq!(second.status, 400);
        assert_eq!(
            (*(second_body).get("error").unwrap_or(&Value::Null)),
            "slow_down"
        );
        assert_eq!(
            (*(second_body)
                .get("error_description")
                .unwrap_or(&Value::Null)),
            POLLING_TOO_FREQUENTLY
        );
    }

    // Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: verification scenarios.
    #[tokio::test]
    async fn test_device_verify_strips_hyphens_and_preserves_input_shape() {
        let plugin = DeviceAuthorizationPlugin::new();
        let ctx = test_helpers::create_test_context().await;

        ctx.database
            .create_device_code(CreateDeviceCode {
                device_code: "verify-device-code".to_owned(),
                user_code: "ABCD2345".to_owned(),
                user_id: None,
                expires_at: Utc::now() + Duration::minutes(5),
                status: DEVICE_STATUS_PENDING.to_owned(),
                last_polled_at: None,
                polling_interval: Some(5000),
                client_id: Some("test-client".to_owned()),
                scope: None,
            })
            .await
            .unwrap();

        let response = plugin
            .handle_device_verify(&device_verify_request("ABCD-2345"), &ctx)
            .await
            .unwrap();
        let body = json_body(&response);

        assert_eq!(response.status, 200);
        assert_eq!(
            (*(body).get("user_code").unwrap_or(&Value::Null)),
            "ABCD-2345"
        );
        assert_eq!(
            (*(body).get("status").unwrap_or(&Value::Null)),
            DEVICE_STATUS_PENDING
        );
    }

    // Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: invalid user code verification.
    #[tokio::test]
    async fn test_device_verify_invalid_user_code_returns_error() {
        let plugin = DeviceAuthorizationPlugin::new();
        let ctx = test_helpers::create_test_context().await;

        let response = plugin
            .handle_device_verify(&device_verify_request("INVALID"), &ctx)
            .await
            .unwrap();
        let body = json_body(&response);

        assert_eq!(response.status, 400);
        assert_eq!(
            (*(body).get("error").unwrap_or(&Value::Null)),
            "invalid_request"
        );
        assert_eq!(
            (*(body).get("error_description").unwrap_or(&Value::Null)),
            INVALID_USER_CODE
        );
    }

    // Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: approval flow, scope preservation, and OAuth-compliant token response.
    #[tokio::test]
    async fn test_device_approve_flow_creates_session_and_returns_oauth_token_response() {
        let plugin = DeviceAuthorizationPlugin::new();
        let (ctx, _user, session) = create_context_with_user("approve@example.com").await;

        let create_request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/code",
            None,
            Some(serde_json::json!({
                "client_id": "test-client",
                "scope": "read write profile",
            })),
        );
        let create_response = plugin
            .handle_device_code(&create_request, &ctx)
            .await
            .unwrap();
        let create_body = json_body(&create_response);
        let device_code = (*(create_body).get("device_code").unwrap_or(&Value::Null))
            .as_str()
            .unwrap()
            .to_owned();
        let user_code = (*(create_body).get("user_code").unwrap_or(&Value::Null))
            .as_str()
            .unwrap()
            .to_owned();

        plugin
            .handle_device_verify(&device_claim_request(&user_code, &session.token), &ctx)
            .await
            .unwrap();

        let approve_request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/approve",
            Some(&session.token),
            Some(serde_json::json!({ "userCode": user_code })),
        );
        let approve_response = plugin
            .handle_device_approve(&approve_request, &ctx)
            .await
            .unwrap();
        assert_eq!(
            (*(json_body(&approve_response))
                .get("success")
                .unwrap_or(&Value::Null)),
            true
        );

        let token_response = plugin
            .handle_device_token(&device_token_request(&device_code, "test-client"), &ctx)
            .await
            .unwrap();
        let token_body = json_body(&token_response);

        assert_eq!(token_response.status, 200);
        assert_eq!(
            token_response.headers.get("Cache-Control"),
            Some(&"no-store".to_owned())
        );
        assert_eq!(
            token_response.headers.get("Pragma"),
            Some(&"no-cache".to_owned())
        );
        assert_eq!(
            (*(token_body).get("token_type").unwrap_or(&Value::Null)),
            "Bearer"
        );
        assert_eq!(
            (*(token_body).get("scope").unwrap_or(&Value::Null)),
            "read write profile"
        );
        assert!(
            (*(token_body).get("expires_in").unwrap_or(&Value::Null))
                .as_i64()
                .unwrap()
                > 0
        );

        let access_token = (*(token_body).get("access_token").unwrap_or(&Value::Null))
            .as_str()
            .unwrap();
        assert!(
            ctx.database
                .get_session(access_token)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            ctx.database
                .get_device_code_by_device_code(&device_code)
                .await
                .unwrap()
                .is_none()
        );
    }

    // Upstream reference: packages/better-auth/src/plugins/device-authorization/routes.ts ::
    // deviceApprove rejects a record with no userId (DEVICE_CODE_NOT_CLAIMED), so a
    // signed-in caller cannot approve a code they never claimed via `GET /device`.
    #[tokio::test]
    async fn test_device_approve_rejects_unclaimed_code() {
        let plugin = DeviceAuthorizationPlugin::new();
        let (ctx, _user, session) = create_context_with_user("unclaimed@example.com").await;

        let create_request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/code",
            None,
            Some(serde_json::json!({ "client_id": "test-client" })),
        );
        let create_response = plugin
            .handle_device_code(&create_request, &ctx)
            .await
            .unwrap();
        let create_body = json_body(&create_response);
        let device_code = (*(create_body).get("device_code").unwrap_or(&Value::Null))
            .as_str()
            .unwrap()
            .to_owned();
        let user_code = (*(create_body).get("user_code").unwrap_or(&Value::Null))
            .as_str()
            .unwrap()
            .to_owned();

        // Deliberately skip the `GET /device` claim.
        let approve_request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/approve",
            Some(&session.token),
            Some(serde_json::json!({ "userCode": user_code })),
        );
        let approve_response = plugin
            .handle_device_approve(&approve_request, &ctx)
            .await
            .unwrap();
        let approve_body = json_body(&approve_response);

        assert_eq!(approve_response.status, 400);
        assert_eq!(
            (*(approve_body).get("error").unwrap_or(&Value::Null)),
            "invalid_request"
        );
        assert_eq!(
            (*(approve_body)
                .get("error_description")
                .unwrap_or(&Value::Null)),
            DEVICE_CODE_NOT_CLAIMED
        );

        let stored = ctx
            .database
            .get_device_code_by_device_code(&device_code)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, DEVICE_STATUS_PENDING);
        assert_eq!(stored.user_id, None);
    }

    // Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: denial flow.
    #[tokio::test]
    async fn test_device_deny_flow_returns_access_denied_and_deletes_record() {
        let plugin = DeviceAuthorizationPlugin::new();
        let (ctx, _user, session) = create_context_with_user("deny@example.com").await;

        let create_request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/code",
            None,
            Some(serde_json::json!({ "client_id": "test-client" })),
        );
        let create_response = plugin
            .handle_device_code(&create_request, &ctx)
            .await
            .unwrap();
        let create_body = json_body(&create_response);
        let device_code = (*(create_body).get("device_code").unwrap_or(&Value::Null))
            .as_str()
            .unwrap()
            .to_owned();
        let user_code = (*(create_body).get("user_code").unwrap_or(&Value::Null))
            .as_str()
            .unwrap()
            .to_owned();

        plugin
            .handle_device_verify(&device_claim_request(&user_code, &session.token), &ctx)
            .await
            .unwrap();

        let deny_request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/deny",
            Some(&session.token),
            Some(serde_json::json!({ "userCode": user_code })),
        );
        let deny_response = plugin
            .handle_device_deny(&deny_request, &ctx)
            .await
            .unwrap();
        assert_eq!(
            (*(json_body(&deny_response))
                .get("success")
                .unwrap_or(&Value::Null)),
            true
        );

        let token_response = plugin
            .handle_device_token(&device_token_request(&device_code, "test-client"), &ctx)
            .await
            .unwrap();
        let token_body = json_body(&token_response);

        assert_eq!(token_response.status, 400);
        assert_eq!(
            (*(token_body).get("error").unwrap_or(&Value::Null)),
            "access_denied"
        );
        assert_eq!(
            (*(token_body)
                .get("error_description")
                .unwrap_or(&Value::Null)),
            ACCESS_DENIED
        );
        assert!(
            ctx.database
                .get_device_code_by_device_code(&device_code)
                .await
                .unwrap()
                .is_none()
        );
    }

    // Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: auth-required and double-processing guard scenarios.
    #[tokio::test]
    async fn test_device_approve_requires_authentication_and_blocks_double_processing() {
        let plugin = DeviceAuthorizationPlugin::new();
        let (ctx, _user, session) = create_context_with_user("double@example.com").await;

        let create_request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/code",
            None,
            Some(serde_json::json!({ "client_id": "test-client" })),
        );
        let create_response = plugin
            .handle_device_code(&create_request, &ctx)
            .await
            .unwrap();
        let create_body = json_body(&create_response);
        let user_code = (*(create_body).get("user_code").unwrap_or(&Value::Null))
            .as_str()
            .unwrap()
            .to_owned();

        plugin
            .handle_device_verify(&device_claim_request(&user_code, &session.token), &ctx)
            .await
            .unwrap();

        let unauthenticated_request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/approve",
            None,
            Some(serde_json::json!({ "userCode": user_code.clone() })),
        );
        let unauthenticated_response = plugin
            .handle_device_approve(&unauthenticated_request, &ctx)
            .await
            .unwrap();
        let unauthenticated_body = json_body(&unauthenticated_response);
        assert_eq!(unauthenticated_response.status, 401);
        assert_eq!(
            (*(unauthenticated_body).get("error").unwrap_or(&Value::Null)),
            "unauthorized"
        );
        assert_eq!(
            (*(unauthenticated_body)
                .get("error_description")
                .unwrap_or(&Value::Null)),
            AUTHENTICATION_REQUIRED
        );

        let approve_request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/approve",
            Some(&session.token),
            Some(serde_json::json!({ "userCode": user_code.clone() })),
        );
        let first_response = plugin
            .handle_device_approve(&approve_request, &ctx)
            .await
            .unwrap();
        assert_eq!(
            (*(json_body(&first_response))
                .get("success")
                .unwrap_or(&Value::Null)),
            true
        );

        let second_response = plugin
            .handle_device_approve(&approve_request, &ctx)
            .await
            .unwrap();
        let second_body = json_body(&second_response);
        assert_eq!(second_response.status, 400);
        assert_eq!(
            (*(second_body).get("error").unwrap_or(&Value::Null)),
            "invalid_request"
        );
        assert_eq!(
            (*(second_body)
                .get("error_description")
                .unwrap_or(&Value::Null)),
            DEVICE_CODE_ALREADY_PROCESSED
        );
    }

    // Upstream source: packages/better-auth/src/plugins/device-authorization/device-authorization.test.ts :: client mismatch scenario.
    #[tokio::test]
    async fn test_device_token_rejects_client_id_mismatch() {
        let plugin = DeviceAuthorizationPlugin::new();
        let ctx = test_helpers::create_test_context().await;

        let create_request = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/device/code",
            None,
            Some(serde_json::json!({ "client_id": "client-a" })),
        );
        let create_response = plugin
            .handle_device_code(&create_request, &ctx)
            .await
            .unwrap();
        let create_body = json_body(&create_response);

        let response = plugin
            .handle_device_token(
                &device_token_request(
                    (*(create_body).get("device_code").unwrap_or(&Value::Null))
                        .as_str()
                        .unwrap(),
                    "client-b",
                ),
                &ctx,
            )
            .await
            .unwrap();
        let body = json_body(&response);

        assert_eq!(response.status, 400);
        assert_eq!(
            (*(body).get("error").unwrap_or(&Value::Null)),
            "invalid_grant"
        );
        assert_eq!(
            (*(body).get("error_description").unwrap_or(&Value::Null)),
            CLIENT_ID_MISMATCH
        );
    }
}
// LCOV_EXCL_STOP
