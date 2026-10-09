//! Application-owned issuance and redemption of durable device grants.
use super::types::DeviceCodeRequest;
use super::{
    ACCESS_DENIED, AUTHORIZATION_PENDING, DEVICE_STATUS_APPROVED, DEVICE_STATUS_DENIED,
    DEVICE_STATUS_PENDING, DeviceAuthorizationPlugin, EXPIRED_DEVICE_CODE, INVALID_DEVICE_CODE,
    INVALID_DEVICE_CODE_STATUS, POLLING_TOO_FREQUENTLY, USER_NOT_FOUND, device_error_response,
    no_store, validate_device_media,
};
use crate::helpers::callback_failure;
use alibi_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, DeviceCode,
    UpdateDeviceCode,
};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Map, Value};
use std::sync::Arc;

#[derive(Debug)]
pub enum DeviceGrantFailure {
    OAuth {
        status: u16,
        error: String,
        description: String,
    },
    Application(AuthError),
}
impl From<AuthError> for DeviceGrantFailure {
    fn from(error: AuthError) -> Self {
        Self::Application(error)
    }
}
impl DeviceGrantFailure {
    pub fn oauth(status: u16, error: impl Into<String>, description: impl Into<String>) -> Self {
        Self::OAuth {
            status,
            error: error.into(),
            description: description.into(),
        }
    }
    pub fn into_response(self) -> AuthResult<AuthResponse> {
        match self {
            Self::OAuth {
                status,
                error,
                description,
            } => device_error_response(status, &error, &description),
            Self::Application(error) => Err(callback_failure(error)),
        }
    }
}
#[derive(Debug, Clone)]
pub struct DeviceGrantRecord {
    pub device_code: DeviceCode,
    pub fields: Map<String, Value>,
}
#[derive(Debug, Clone)]
pub struct DeviceGrantAuthorization {
    pub client_id: String,
    pub user_id: Option<String>,
    pub fields: Map<String, Value>,
}

/// Application protocol layered over the shared device-code lifecycle.
#[async_trait]
pub trait DeviceAuthorizationGrant: Send + Sync {
    /// Required string request fields and their JSON schemas, including minLength.
    fn request_schema_fields(&self) -> Map<String, Value> {
        Map::new()
    }
    fn on_request_validation_error(&self, issues: &[String]) -> DeviceGrantFailure {
        DeviceGrantFailure::oauth(400, "invalid_request", issues.join("; "))
    }
    async fn authorize_request(
        &self,
        request: &Map<String, Value>,
        original: &AuthRequest,
    ) -> Result<DeviceGrantAuthorization, DeviceGrantFailure>;
    async fn assert_session_redemption(
        &self,
        _record: &DeviceGrantRecord,
    ) -> Result<(), DeviceGrantFailure> {
        Ok(())
    }
    async fn verification_context(
        &self,
        _record: &DeviceGrantRecord,
    ) -> AuthResult<Map<String, Value>> {
        Ok(Map::new())
    }
    fn device_code_schema_fields(&self) -> Vec<alibi_core::OpenApiField> {
        Vec::new()
    }
    fn request_error_codes(&self) -> Vec<String> {
        Vec::new()
    }
    fn request_openapi_responses(&self) -> Map<String, Value> {
        Map::new()
    }
    fn verification_openapi_properties(&self) -> Map<String, Value> {
        Map::new()
    }
}
#[derive(Debug, Clone)]
pub struct DeviceRedemptionAuthorization {
    pub ownership: Map<String, Value>,
    pub context: Value,
}
/// Preparation runs before the atomic consume; rejection leaves the grant usable.
#[async_trait]
pub trait DeviceRedemptionPolicy: Send + Sync {
    async fn authorize(
        &self,
        record: &DeviceGrantRecord,
    ) -> AuthResult<DeviceRedemptionAuthorization>;
    async fn prepare(&self, record: &DeviceGrantRecord, authorization: &Value)
    -> AuthResult<Value>;
}
pub struct DeviceRedemptionResult<S: AuthSchema> {
    pub claimed_device_code: DeviceGrantRecord,
    pub user: S::User,
    pub authorization_context: Value,
    pub redemption_context: Value,
}

/// Redeem one approved grant using a storage-side ownership predicate.
pub async fn redeem_device_code<S: AuthSchema>(
    ctx: &AuthContext<S>,
    code: &str,
    policy: &dyn DeviceRedemptionPolicy,
) -> Result<DeviceRedemptionResult<S>, DeviceGrantFailure> {
    let row = ctx
        .database
        .get_device_code_by_device_code(code)
        .await?
        .ok_or_else(|| DeviceGrantFailure::oauth(400, "invalid_grant", INVALID_DEVICE_CODE))?;
    let record = DeviceGrantRecord {
        fields: ctx.database.device_code_fields(&row.id).await?,
        device_code: row,
    };
    let authorization = policy.authorize(&record).await?;
    let row = &record.device_code;
    let now = Utc::now();
    if let (Some(last), Some(interval)) = (row.last_polled_at, row.polling_interval)
        && interval != 0
        && now.signed_duration_since(last).num_milliseconds() < interval
    {
        return Err(DeviceGrantFailure::oauth(
            400,
            "slow_down",
            POLLING_TOO_FREQUENTLY,
        ));
    }
    _ = ctx
        .database
        .update_device_code(
            &row.id,
            UpdateDeviceCode {
                last_polled_at: Some(Some(now)),
                ..Default::default()
            },
        )
        .await?;
    if row.expires_at < now {
        ctx.database.delete_device_code(&row.id).await?;
        return Err(DeviceGrantFailure::oauth(
            400,
            "expired_token",
            EXPIRED_DEVICE_CODE,
        ));
    }
    match row.status.as_str() {
        DEVICE_STATUS_PENDING => {
            return Err(DeviceGrantFailure::oauth(
                400,
                "authorization_pending",
                AUTHORIZATION_PENDING,
            ));
        }
        DEVICE_STATUS_DENIED => {
            ctx.database.delete_device_code(&row.id).await?;
            return Err(DeviceGrantFailure::oauth(
                400,
                "access_denied",
                ACCESS_DENIED,
            ));
        }
        DEVICE_STATUS_APPROVED if row.user_id.is_some() => {}
        _ => {
            return Err(DeviceGrantFailure::oauth(
                500,
                "server_error",
                INVALID_DEVICE_CODE_STATUS,
            ));
        }
    }
    let redemption_context = policy.prepare(&record, &authorization.context).await?;
    let user = ctx
        .database
        .get_user_by_id(
            row.user_id
                .as_deref()
                .ok_or_else(|| DeviceGrantFailure::oauth(500, "server_error", USER_NOT_FOUND))?,
        )
        .await?
        .ok_or_else(|| DeviceGrantFailure::oauth(500, "server_error", USER_NOT_FOUND))?;
    let claimed = ctx
        .database
        .consume_device_code(&row.id, DEVICE_STATUS_APPROVED, &authorization.ownership)
        .await?
        .ok_or_else(|| DeviceGrantFailure::oauth(400, "invalid_grant", INVALID_DEVICE_CODE))?;
    Ok(DeviceRedemptionResult {
        claimed_device_code: DeviceGrantRecord {
            device_code: claimed,
            fields: record.fields,
        },
        user,
        authorization_context: authorization.context,
        redemption_context,
    })
}

impl DeviceAuthorizationPlugin {
    #[must_use]
    pub fn grant(mut self, grant: impl DeviceAuthorizationGrant + 'static) -> Self {
        self.config.grant = Some(Arc::new(grant));
        self
    }
    pub(super) async fn handle_application_issuance(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
        grant: &dyn DeviceAuthorizationGrant,
    ) -> AuthResult<AuthResponse> {
        let is_form = match validate_device_media(req, true) {
            Ok(form) => form,
            Err(response) => return Ok(response),
        };
        let body: Value = if is_form {
            Value::Object(
                url::form_urlencoded::parse(req.body.as_deref().unwrap_or_default())
                    .map(|(key, value)| (key.into_owned(), Value::String(value.into_owned())))
                    .collect(),
            )
        } else {
            req.body_as_json()?
        };
        let mut request = body.as_object().cloned().unwrap_or_default();
        let fields = grant.request_schema_fields();
        let mut issues = Vec::new();
        for (name, schema) in &fields {
            let value = request.get(name).and_then(Value::as_str);
            let minimum = schema.get("minLength").and_then(Value::as_u64).unwrap_or(0);
            if value.is_none_or(|value| {
                value.encode_utf16().count() < usize::try_from(minimum).unwrap_or(usize::MAX)
            }) {
                issues.push(name.clone());
            }
        }
        for field in ["scope", "client_id", "user_id"] {
            if request.get(field).is_some_and(|value| !value.is_string()) {
                issues.push(field.into());
            }
        }
        if !issues.is_empty() {
            return grant.on_request_validation_error(&issues).into_response();
        }
        request.retain(|name, _| {
            ["scope", "client_id", "user_id"].contains(&name.as_str()) || fields.contains_key(name)
        });
        let authorized = match grant.authorize_request(&request, req).await {
            Ok(value) => value,
            Err(error) => {
                return error.into_response().map(no_store);
            }
        };
        self.issue_device_code_with_fields(
            DeviceCodeRequest {
                client_id: authorized.client_id,
                user_id: authorized.user_id,
                scope: request
                    .get("scope")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            },
            authorized.fields,
            ctx,
        )
        .await
        .map(no_store)
    }
    pub(super) fn grant_openapi(
        &self,
        mut metadata: alibi_core::PluginOpenApiMetadata,
    ) -> alibi_core::PluginOpenApiMetadata {
        let Some(grant) = &self.config.grant else {
            return metadata;
        };
        metadata.models.push(alibi_core::OpenApiModel::new(
            "DeviceCode",
            grant.device_code_schema_fields(),
        ));
        let mut properties = grant.request_schema_fields();
        _ = properties.insert(
            "scope".into(),
            serde_json::json!({"type":"string","description":"Space-separated list of scopes"}),
        );
        _ = properties.insert("client_id".into(), serde_json::json!({"type":"string"}));
        _ = properties.insert("user_id".into(), serde_json::json!({"type":"string","description":"The user ID to which the device code should be pre-bound."}));
        let required = grant
            .request_schema_fields()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for (_, path, endpoint) in &mut metadata.endpoints {
            if path == "/device/code" {
                endpoint.request_body = Some(
                    serde_json::json!({"required":true,"content":{"application/json":{"schema":{"type":"object","properties":properties,"required":required}}}}),
                );
                if let Some(codes) = endpoint
                    .responses
                    .get_mut("400")
                    .and_then(|response| {
                        response
                            .pointer_mut("/content/application~1json/schema/properties/error/enum")
                    })
                    .and_then(Value::as_array_mut)
                {
                    codes.extend(grant.request_error_codes().into_iter().map(Value::String));
                }
                for (status, response) in grant.request_openapi_responses() {
                    _ = endpoint.responses.insert(status, response);
                }
            }
            if path == "/device" {
                let response=endpoint.responses.entry("200".into()).or_insert_with(||serde_json::json!({"description":"Success","content":{"application/json":{"schema":{"type":"object","properties":{}}}}}));
                if let Some(properties) = response
                    .pointer_mut("/content/application~1json/schema/properties")
                    .and_then(Value::as_object_mut)
                {
                    properties.extend(grant.verification_openapi_properties());
                }
            }
        }
        metadata
    }
}
