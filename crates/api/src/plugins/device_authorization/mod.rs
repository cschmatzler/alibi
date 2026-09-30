use chrono::{Duration, Utc};
use rand::RngCore;
use rand::distributions::{Alphanumeric, DistString};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use url::Url;

use crate::plugins::helpers::{SessionIssueError, issue_user_session};
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateDeviceCode, RequestMeta,
    UpdateDeviceCode,
};

pub(super) mod types;

#[cfg(test)]
mod tests;

use types::{
    DeviceActionRequest, DeviceActionResponse, DeviceCodeRequest, DeviceCodeResponse,
    DeviceErrorResponse, DeviceTokenRequest, DeviceTokenResponse, DeviceVerifyResponse,
};

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
    fn status(self) -> &'static str {
        match self {
            Self::Approve => DEVICE_STATUS_APPROVED,
            Self::Deny => DEVICE_STATUS_DENIED,
        }
    }

    fn forbidden_message(self) -> &'static str {
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

impl Default for DeviceAuthorizationPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceAuthorizationPlugin {
    /// Create the plugin with TS-aligned defaults.
    pub fn new() -> Self {
        Self {
            config: DeviceAuthorizationConfig::default(),
        }
    }

    /// Override the device-code expiration window.
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.config.expires_in = duration;
        self
    }

    /// Override the minimum polling interval enforced by `/device/token`.
    pub fn interval(mut self, duration: Duration) -> Self {
        self.config.interval = duration;
        self
    }

    /// Override the generated device-code length.
    pub fn device_code_length(mut self, length: usize) -> Self {
        self.config.device_code_length = length;
        self
    }

    /// Override the generated user-code length.
    pub fn user_code_length(mut self, length: usize) -> Self {
        self.config.user_code_length = length;
        self
    }

    /// Override the verification page URI returned to devices.
    pub fn verification_uri(mut self, uri: impl Into<String>) -> Self {
        self.config.verification_uri = Some(uri.into());
        self
    }

    /// Use a custom device-code generator.
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
    pub fn generate_device_code_async_with<F, Fut>(mut self, generator: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<String>> + Send + 'static,
    {
        self.config.generate_device_code = Some(Arc::new(move || Box::pin(generator())));
        self
    }

    /// Use an asynchronous user-code generator.
    pub fn generate_user_code_async_with<F, Fut>(mut self, generator: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<String>> + Send + 'static,
    {
        self.config.generate_user_code = Some(Arc::new(move || Box::pin(generator())));
        self
    }

    /// Validate the OAuth client identifier before issuing or redeeming codes.
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

    async fn handle_device_code(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: DeviceCodeRequest = match parse_device_body(req, DeviceRequestKind::Issuance)
            .and_then(deserialize_device_body)
        {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };

        self.issue_device_code(body, ctx).await.map(|response| {
            response
                .with_header("Cache-Control", "no-store")
                .with_header("Pragma", "no-cache")
        })
    }

    async fn issue_device_code(
        &self,
        mut body: DeviceCodeRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if body.client_id.is_empty() {
            return device_error_response(400, "invalid_request", "client_id is required");
        }
        body.user_id = body.user_id.filter(|value| !value.is_empty());
        body.scope = body.scope.filter(|value| !value.is_empty());

        if !self.validate_client_id(&body.client_id).await? {
            return device_error_response(400, "invalid_client", INVALID_CLIENT_ID);
        }

        if let Some(callback) = &self.config.on_device_auth_request {
            callback(body.client_id.clone(), body.scope.clone()).await?;
        }

        let expires_at = Utc::now() + self.config.expires_in;
        let polling_interval = self.config.interval.num_milliseconds();
        for _ in 0..3 {
            let device_code = self.generate_device_code().await?;
            if device_code.chars().count() > 191 {
                return device_error_response(
                    400,
                    "invalid_request",
                    "Generated device code must be at most 191 characters",
                );
            }
            let user_code = self.generate_user_code().await?;
            if user_code.chars().count() > 191 {
                return device_error_response(
                    400,
                    "invalid_request",
                    "Generated user code must be at most 191 characters",
                );
            }
            match ctx
                .database
                .create_device_code(CreateDeviceCode {
                    device_code: device_code.clone(),
                    user_code: user_code.clone(),
                    user_id: body.user_id.clone(),
                    expires_at,
                    status: DEVICE_STATUS_PENDING.to_string(),
                    last_polled_at: None,
                    polling_interval: Some(polling_interval),
                    client_id: Some(body.client_id.clone()),
                    scope: body.scope.clone(),
                })
                .await
            {
                Ok(_) => {}
                Err(error) if is_unique_constraint_error(&error) => continue,
                Err(error) => return Err(error),
            }

            let (verification_uri, verification_uri_complete) = build_verification_uris(
                self.config.verification_uri.as_deref(),
                &ctx.config.base_url,
                &user_code,
            )?;

            return Ok(AuthResponse::json(
                200,
                &DeviceCodeResponse {
                    device_code,
                    user_code,
                    verification_uri,
                    verification_uri_complete,
                    expires_in: self.config.expires_in.num_seconds(),
                    interval: self.config.interval.num_seconds(),
                },
            )?
            .with_header("Cache-Control", "no-store")
            .with_header("Pragma", "no-cache"));
        }
        device_error_response(
            500,
            "server_error",
            "Failed to generate a unique device code",
        )
    }

    async fn handle_device_token(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: DeviceTokenRequest = match parse_device_body(req, DeviceRequestKind::Token)
            .and_then(deserialize_device_body)
        {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };

        self.redeem_device_token(body, req, ctx)
            .await
            .map(|response| {
                response
                    .with_header("Cache-Control", "no-store")
                    .with_header("Pragma", "no-cache")
            })
    }

    async fn redeem_device_token(
        &self,
        body: DeviceTokenRequest,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if !self.validate_client_id(&body.client_id).await? {
            return device_error_response(400, "invalid_grant", INVALID_CLIENT_ID);
        }

        let Some(device_code) = ctx
            .database
            .get_device_code_by_device_code(&body.device_code)
            .await?
        else {
            return device_error_response(400, "invalid_grant", INVALID_DEVICE_CODE);
        };

        if let Some(client_id) = device_code.client_id.as_deref()
            && client_id != body.client_id
        {
            return device_error_response(400, "invalid_grant", CLIENT_ID_MISMATCH);
        }

        let now = Utc::now();
        if let (Some(last_polled_at), Some(polling_interval)) =
            (device_code.last_polled_at, device_code.polling_interval)
        {
            let elapsed = now.signed_duration_since(last_polled_at).num_milliseconds();
            if elapsed < polling_interval {
                return device_error_response(400, "slow_down", POLLING_TOO_FREQUENTLY);
            }
        }

        let _ = ctx
            .database
            .update_device_code(
                &device_code.id,
                UpdateDeviceCode {
                    last_polled_at: Some(Some(now)),
                    ..Default::default()
                },
            )
            .await?;

        if device_code.expires_at < now {
            ctx.database.delete_device_code(&device_code.id).await?;
            return device_error_response(400, "expired_token", EXPIRED_DEVICE_CODE);
        }

        if device_code.status == DEVICE_STATUS_PENDING {
            return device_error_response(400, "authorization_pending", AUTHORIZATION_PENDING);
        }

        if device_code.status == DEVICE_STATUS_DENIED {
            ctx.database.delete_device_code(&device_code.id).await?;
            return device_error_response(400, "access_denied", ACCESS_DENIED);
        }

        if device_code.status == DEVICE_STATUS_APPROVED {
            let Some(user_id) = device_code.user_id.as_deref() else {
                return device_error_response(500, "server_error", INVALID_DEVICE_CODE_STATUS);
            };

            let Some(user) = ctx.database.get_user_by_id(user_id).await? else {
                return device_error_response(500, "server_error", USER_NOT_FOUND);
            };

            if !ctx
                .database
                .delete_device_code_if_status(&device_code.id, DEVICE_STATUS_APPROVED)
                .await?
            {
                return device_error_response(400, "invalid_grant", INVALID_DEVICE_CODE);
            }

            let meta = RequestMeta::from_request(req);
            let session =
                match issue_user_session(ctx, &user.id(), meta.ip_address, meta.user_agent)
                    .await
                    .map_err(SessionIssueError::into_auth_error)
                {
                    Ok(issued) => issued.session,
                    Err(error) => {
                        tracing::error!(
                            error = %error,
                            device_code_id = %device_code.id,
                            user_id,
                            "failed to create session after device code redemption"
                        );
                        return device_error_response(
                            500,
                            "server_error",
                            FAILED_TO_CREATE_SESSION,
                        );
                    }
                };

            return Ok(AuthResponse::json(
                200,
                &DeviceTokenResponse {
                    access_token: session.token().to_string(),
                    token_type: "Bearer",
                    expires_in: (session.expires_at().timestamp_millis()
                        - Utc::now().timestamp_millis())
                    .div_euclid(1000)
                    .max(0),
                    scope: device_code.scope.unwrap_or_default(),
                },
            )?
            .with_header("Cache-Control", "no-store")
            .with_header("Pragma", "no-cache"));
        }

        device_error_response(500, "server_error", INVALID_DEVICE_CODE_STATUS)
    }

    async fn handle_device_verify(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let Some(user_code) = req.query.get("user_code").cloned() else {
            return device_error_response(400, "invalid_request", INVALID_REQUEST);
        };

        let Some(mut device_code) = find_device_code_by_user_code(ctx, &user_code).await? else {
            return device_error_response(400, "invalid_request", INVALID_USER_CODE);
        };

        if device_code.expires_at < Utc::now() {
            return device_error_response(400, "expired_token", EXPIRED_USER_CODE);
        }

        // A signed-in caller claims the code here; `/device/approve` and
        // `/device/deny` refuse to act on a code nobody has claimed. The
        // session is optional — anyone may look up the status.
        let user_id = match ctx.require_session(req).await {
            Ok((user, _)) => Some(user.id().into_owned()),
            Err(AuthError::Unauthenticated) | Err(AuthError::SessionNotFound) => None,
            Err(err) => return Err(err),
        };
        if device_code.user_id.is_none()
            && device_code.status == DEVICE_STATUS_PENDING
            && let Some(user_id) = user_id.as_deref()
            && ctx
                .database
                .claim_device_code(&device_code.id, user_id)
                .await?
        {
            device_code.user_id = Some(user_id.to_owned());
        }
        let can_review_request = user_id.is_some() && device_code.user_id == user_id;

        AuthResponse::json(
            200,
            &DeviceVerifyResponse {
                user_code,
                status: device_code.status,
                client_id: can_review_request.then_some(device_code.client_id),
                scope: can_review_request.then_some(device_code.scope),
            },
        )
        .map_err(AuthError::from)
    }

    async fn handle_device_approve(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        self.handle_device_decision(req, ctx, DeviceDecision::Approve)
            .await
    }

    async fn handle_device_deny(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        self.handle_device_decision(req, ctx, DeviceDecision::Deny)
            .await
    }

    async fn handle_device_decision(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        decision: DeviceDecision,
    ) -> AuthResult<AuthResponse> {
        if let Err(response) = validate_device_media(req, false) {
            return Ok(response);
        }
        let body: DeviceActionRequest = match parse_device_body(req, DeviceRequestKind::Decision)
            .and_then(deserialize_device_body)
        {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let user = match ctx.require_session(req).await {
            Ok((user, _session)) => user,
            Err(AuthError::Unauthenticated) | Err(AuthError::SessionNotFound) => {
                return device_error_response(401, "unauthorized", AUTHENTICATION_REQUIRED);
            }
            Err(error) => return Err(error),
        };

        let current_user_id = user.id().into_owned();

        let Some(device_code) = find_device_code_by_user_code(ctx, &body.user_code).await? else {
            return device_error_response(400, "invalid_request", INVALID_USER_CODE);
        };

        if device_code.expires_at < Utc::now() {
            return device_error_response(400, "expired_token", EXPIRED_USER_CODE);
        }

        if device_code.status != DEVICE_STATUS_PENDING {
            return device_error_response(400, "invalid_request", DEVICE_CODE_ALREADY_PROCESSED);
        }

        // The code must already be bound to a user by `GET /device`. Without
        // this, any signed-in caller who knows a user_code could approve a
        // device they never claimed.
        let Some(claimed_user_id) = device_code.user_id.as_deref() else {
            return device_error_response(400, "invalid_request", DEVICE_CODE_NOT_CLAIMED);
        };

        if claimed_user_id != current_user_id {
            return device_error_response(403, "access_denied", decision.forbidden_message());
        }

        let updated_user_id = claimed_user_id.to_string();

        let updated = ctx
            .database
            .update_device_code_if_status(
                &device_code.id,
                DEVICE_STATUS_PENDING,
                UpdateDeviceCode {
                    status: Some(decision.status().to_string()),
                    user_id: Some(Some(updated_user_id)),
                    ..Default::default()
                },
            )
            .await?;

        if !updated {
            return device_error_response(400, "invalid_request", DEVICE_CODE_ALREADY_PROCESSED);
        }

        AuthResponse::json(200, &DeviceActionResponse { success: true }).map_err(AuthError::from)
    }

    async fn validate_client_id(&self, client_id: &str) -> AuthResult<bool> {
        match &self.config.validate_client {
            Some(callback) => callback(client_id.to_string()).await,
            None => Ok(true),
        }
    }

    async fn generate_device_code(&self) -> AuthResult<String> {
        match &self.config.generate_device_code {
            Some(generator) => generator().await,
            None => {
                Ok(Alphanumeric
                    .sample_string(&mut rand::rngs::OsRng, self.config.device_code_length))
            }
        }
    }

    async fn generate_user_code(&self) -> AuthResult<String> {
        match &self.config.generate_user_code {
            Some(generator) => generator().await,
            None => Ok(default_generate_user_code(self.config.user_code_length)),
        }
    }
}

fn is_unique_constraint_error(error: &AuthError) -> bool {
    let AuthError::Database(better_auth_core::DatabaseError::Constraint(message)) = error else {
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
    serde_json::from_value(value).map_err(|_| AuthResponse::text(400, "Invalid request body"))
}

fn validate_device_media(req: &AuthRequest, issuance: bool) -> Result<bool, AuthResponse> {
    let content_type = req
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        });
    let is_form = content_type.as_deref() == Some("application/x-www-form-urlencoded");
    if content_type
        .as_deref()
        .is_some_and(|value| value != "application/json" && !(issuance && is_form))
    {
        let allowed = if issuance {
            "application/json, application/x-www-form-urlencoded"
        } else {
            "application/json"
        };
        return Err(AuthResponse::json(415, &serde_json::json!({
            "message": format!("Content-Type \"{}\" is not allowed. Allowed types: {allowed}", content_type.as_deref().unwrap_or_default()),
            "code": "UNSUPPORTED_MEDIA_TYPE",
        })).unwrap_or_else(|_| AuthResponse::text(415, "Unsupported media type")));
    }
    Ok(is_form)
}

enum DeviceRequestKind {
    Issuance,
    Token,
    Decision,
}

fn parse_device_body(
    req: &AuthRequest,
    kind: DeviceRequestKind,
) -> Result<serde_json::Value, AuthResponse> {
    let issuance = matches!(kind, DeviceRequestKind::Issuance);
    let is_form = validate_device_media(req, issuance)?;
    let pairs = if is_form {
        Some(
            url::form_urlencoded::parse(req.body.as_deref().unwrap_or_default())
                .into_owned()
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    let mut body = if let Some(pairs) = &pairs {
        let mut object = serde_json::Map::new();
        for (key, value) in pairs {
            let _ = object.insert(key.clone(), serde_json::Value::String(value.clone()));
        }
        serde_json::Value::Object(object)
    } else {
        req.body_as_json::<serde_json::Value>().map_err(|_| {
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
    if !body.is_object() {
        issues.push(format!(
            "[body] Invalid input: expected object, received {}",
            json_type(Some(&body))
        ));
    } else {
        for field in fields {
            let value = body.get(*field);
            if !issuance && *field == "grant_type" {
                if value.and_then(serde_json::Value::as_str) != Some(DEVICE_GRANT_TYPE) {
                    issues.push(format!(
                        "[body.grant_type] Invalid input: expected \"{DEVICE_GRANT_TYPE}\""
                    ));
                }
            } else if value.is_none() && issuance && matches!(*field, "user_id" | "scope") {
                continue;
            } else if !value.is_some_and(serde_json::Value::is_string) {
                issues.push(format!(
                    "[body.{field}] Invalid input: expected string, received {}",
                    json_type(value)
                ));
            }
        }
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
                let _ = object.insert(
                    (*field).to_owned(),
                    serde_json::Value::String((*value).clone()),
                );
            }
        }
    }
    Ok(body)
}

fn json_type(value: Option<&serde_json::Value>) -> &'static str {
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

better_auth_core::impl_auth_plugin! {
    DeviceAuthorizationPlugin, "device-authorization";
    routes {
        post "/device/code" => handle_device_code, "device_code";
        post "/device/token" => handle_device_token, "device_token";
        get "/device" => handle_device_verify, "device_verify";
        post "/device/approve" => handle_device_approve, "device_approve";
        post "/device/deny" => handle_device_deny, "device_deny";
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
    let verification_url = match Url::parse(uri) {
        Ok(url) => url,
        Err(_) => Url::parse(base_url)
            .map_err(|error| AuthError::config(format!("Invalid base URL: {error}")))?
            .join(uri)
            .map_err(|error| {
                AuthError::bad_request(format!("Invalid verification URI: {error}"))
            })?,
    };

    let mut verification_uri_complete = verification_url.clone();
    // URLSearchParams.set replaces the first matching key and removes any
    // later copies, preserving the surrounding query and fragment.
    let mut replaced = false;
    let mut pairs = Vec::new();
    for (key, value) in verification_uri_complete.query_pairs() {
        if key == "user_code" {
            if !replaced {
                pairs.push((key.into_owned(), user_code.to_string()));
                replaced = true;
            }
        } else {
            pairs.push((key.into_owned(), value.into_owned()));
        }
    }
    if !replaced {
        pairs.push(("user_code".to_string(), user_code.to_string()));
    }
    let _ = verification_uri_complete
        .query_pairs_mut()
        .clear()
        .extend_pairs(pairs);

    Ok((
        verification_url.to_string(),
        verification_uri_complete.to_string(),
    ))
}

async fn find_device_code_by_user_code(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user_code: &str,
) -> AuthResult<Option<better_auth_core::DeviceCode>> {
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
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
        .into_iter()
        .map(|byte| {
            let index = usize::from(byte) % DEFAULT_USER_CODE_CHARSET.len();
            DEFAULT_USER_CODE_CHARSET
                .get(index)
                .copied()
                .unwrap_or(b'A') as char
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
            error: error.to_string(),
            error_description: error_description.to_string(),
        },
    )
    .map_err(AuthError::from)
}
