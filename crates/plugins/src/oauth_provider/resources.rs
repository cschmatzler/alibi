//! Durable resource administration and provider policy.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint};
use alibi_core::session::SessionRequest;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema};
use serde_json::{Value, json};
const ALGORITHMS: &[&str] = &["EdDSA", "ES256", "ES512", "PS256", "RS256"];
pub(super) fn validate_create(input: Option<&JsValue>) -> AuthResult<JsValue> {
    validate_body(input, true)
}
pub(super) fn validate_update(input: Option<&JsValue>) -> AuthResult<JsValue> {
    validate_body(input, false)
}
fn validate_body(input: Option<&JsValue>, require_identifier: bool) -> AuthResult<JsValue> {
    use crate::authentication_helpers::{JsonField, JsonFieldKind, field_issue, json_type};
    let mut output = crate::endpoint::validate_fields(
        input,
        "body",
        &[JsonField {
            name: "identifier",
            kind: JsonFieldKind::NonEmptyString,
            required: require_identifier,
        }],
    )?;
    let mut issues = Vec::new();
    for name in [
        "name",
        "accessTokenTtl",
        "refreshTokenTtl",
        "signingAlgorithm",
        "signingKeyId",
        "allowedScopes",
        "customClaims",
        "dpopBoundAccessTokensRequired",
        "disabled",
        "metadata",
    ] {
        let Some(value) = input.and_then(|input| input.get(name)) else {
            continue;
        };
        if matches!(value, JsValue::Null)
            && !["name", "dpopBoundAccessTokensRequired", "disabled"].contains(&name)
        {
            if let JsValue::Object(output) = &mut output {
                _ = output.insert(name.into(), value.clone());
            }
            continue;
        }
        let issue = match name {
            "name" | "signingKeyId" => {
                field_issue(JsonFieldKind::String, Some(value), json_type(Some(value)))
            }
            "dpopBoundAccessTokensRequired" | "disabled" => {
                field_issue(JsonFieldKind::Boolean, Some(value), json_type(Some(value)))
            }
            "customClaims" | "metadata" => {
                field_issue(JsonFieldKind::Record, Some(value), json_type(Some(value)))
            }
            "signingAlgorithm" => field_issue(
                JsonFieldKind::OneOf(ALGORITHMS),
                Some(value),
                json_type(Some(value)),
            ),
            "accessTokenTtl" | "refreshTokenTtl" => match value.as_f64() {
                None => Some(format!(
                    "Invalid input: expected number, received {}",
                    json_type(Some(value))
                )),
                Some(number) if number.fract() != 0.0 => {
                    Some("Invalid input: expected int, received number".into())
                }
                Some(number) if number > 9_007_199_254_740_991.0 => {
                    Some("Too big: expected int to be <=9007199254740991".into())
                }
                Some(number) if number <= 0.0 => Some("Too small: expected number to be >0".into()),
                Some(_) => None,
            },
            "allowedScopes" => {
                if let Some(values) = value.as_array() {
                    for (index, value) in values.iter().enumerate() {
                        if let Some(issue) =
                            field_issue(JsonFieldKind::String, Some(value), json_type(Some(value)))
                        {
                            issues.push(format!("[body.{name}.{index}] {issue}"));
                        }
                    }
                    None
                } else {
                    Some(format!(
                        "Invalid input: expected array, received {}",
                        json_type(Some(value))
                    ))
                }
            }
            _ => None,
        };
        if let Some(issue) = issue {
            issues.push(format!("[body.{name}] {issue}"));
        }
        if let JsValue::Object(output) = &mut output {
            _ = output.insert(name.into(), value.clone());
        }
    }
    if !issues.is_empty() {
        return Err(crate::endpoint::validation(issues.join("; ")));
    }
    Ok(output)
}
pub(super) fn resource_value(row: alibi_core::store::OAuthResource) -> AuthResult<Value> {
    let mut value: serde_json::Map<String, Value> = serde_json::from_value(row.metadata)?;
    _ = value.insert("id".into(), json!(row.id));
    _ = value.insert("identifier".into(), json!(row.identifier));
    _ = value.insert("createdAt".into(), json!(row.created_at));
    _ = value.insert("updatedAt".into(), json!(row.updated_at));
    Ok(Value::Object(value))
}
impl OAuthProviderPlugin {
    /// Create durable provider resource policy through the server-only administration API.
    pub fn admin_create_oauth_resource_endpoint(
        input: &impl serde::Serialize,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "adminCreateOAuthResource").with_body(input)
    }
    pub(super) async fn create_resource<S: AuthSchema>(
        &self,
        input: Value,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        if let Some(response) = Box::pin(self.resource_admission(req, ctx)).await? {
            return Ok(response);
        }
        let identifier = input
            .get("identifier")
            .and_then(Value::as_str)
            .unwrap_or("");
        let Ok(uri) = url::Url::parse(identifier) else {
            return super::clients::status_protocol_error(
                400,
                "invalid_target",
                &format!("resource identifier {identifier} must be an absolute URI (RFC 8707 §2)"),
            );
        };
        if uri.fragment().is_some_and(|fragment| !fragment.is_empty()) {
            return super::clients::status_protocol_error(
                400,
                "invalid_target",
                &format!(
                    "resource identifier {identifier} must not contain a URI fragment (RFC 8707 §2)"
                ),
            );
        }
        let mut metadata = input
            .as_object()
            .cloned()
            .ok_or_else(|| AuthError::internal("Invalid resource body"))?;
        _ = metadata.remove("identifier");
        _ = metadata.entry("name").or_insert_with(|| json!(identifier));
        for name in [
            "accessTokenTtl",
            "refreshTokenTtl",
            "signingAlgorithm",
            "signingKeyId",
            "allowedScopes",
            "customClaims",
            "metadata",
        ] {
            _ = metadata.entry(name).or_insert(Value::Null);
        }
        for name in ["dpopBoundAccessTokensRequired", "disabled"] {
            _ = metadata.entry(name).or_insert_with(|| json!(false));
        }
        _ = metadata.insert("policyVersion".into(), json!(1));
        let now = chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
            .ok_or_else(|| AuthError::internal("Invalid resource timestamp"))?;
        let result = ctx
            .database
            .create_oauth_resource(alibi_core::store::CreateOAuthResource {
                identifier: identifier.into(),
                metadata: Value::Object(metadata),
                created_at: now,
            })
            .await;
        let row = match result {
            Ok(row) => row,
            Err(error)
                if {
                    let message = error.to_string().to_ascii_lowercase();
                    message.contains("unique") || message.contains("duplicate")
                } =>
            {
                return super::clients::status_protocol_error(
                    400,
                    "invalid_request",
                    &format!("resource {identifier} already exists"),
                );
            }
            Err(error) => return Err(error),
        };
        EndpointResponse::json(&resource_value(row)?)
    }
    async fn resource_admission<S: AuthSchema>(
        &self,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<EndpointResponse>> {
        if Box::pin(ctx.require_cached_session(req)).await.is_err() {
            return Ok(Some(
                EndpointResponse::error(AuthError::Api {
                    status: 401,
                    code: None,
                    message: String::new(),
                })
                .without_error_body()
                .with_header("Content-Type", "application/json"),
            ));
        }
        if req
            .endpoint_call()
            .is_some_and(|call| call.headers().is_none())
        {
            return Ok(Some(
                EndpointResponse::error(AuthError::Api {
                    status: 400,
                    code: None,
                    message: String::new(),
                })
                .without_error_body()
                .with_header("Content-Type", "application/json"),
            ));
        }
        Ok(None)
    }
}

impl OAuthProviderPlugin {
    /// List the provider's complete resource catalog through its server-only API.
    #[must_use]
    pub fn admin_list_oauth_resources_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("oauth-provider", "adminListOAuthResources")
    }
    pub(super) async fn list_resources<S: AuthSchema>(
        &self,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        if let Some(response) = Box::pin(self.resource_admission(req, ctx)).await? {
            return Ok(response);
        }
        let rows = ctx.database.list_oauth_resources().await?;
        let values = rows
            .into_iter()
            .map(resource_value)
            .collect::<AuthResult<Vec<_>>>()?;
        EndpointResponse::json(&values)
    }
}

pub(super) fn decode_parameter(params: Option<&JsValue>, name: &str) -> AuthResult<String> {
    let raw = params.and_then(|params| params.get(name)).map_or_else(
        || Ok("undefined".to_owned()),
        |value| value.coerce_string().map_err(AuthError::internal),
    )?;
    for (index, byte) in raw.bytes().enumerate() {
        if byte == b'%'
            && (!raw
                .as_bytes()
                .get(index + 1)
                .is_some_and(u8::is_ascii_hexdigit)
                || !raw
                    .as_bytes()
                    .get(index + 2)
                    .is_some_and(u8::is_ascii_hexdigit))
        {
            return Ok(raw);
        }
    }
    Ok(urlencoding::decode(&raw).map_or_else(|_| raw.clone(), std::borrow::Cow::into_owned))
}
impl OAuthProviderPlugin {
    /// Read durable resource policy by a raw or URI-encoded identifier through the server-only API.
    pub fn admin_get_oauth_resource_endpoint(
        identifier: &str,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "adminGetOAuthResource")
            .with_params(&json!({"identifier":identifier}))
    }
    pub(super) async fn read_resource<S: AuthSchema>(
        &self,
        params: Option<&JsValue>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let identifier = decode_parameter(params, "identifier")?;
        if let Some(response) = Box::pin(self.resource_admission(req, ctx)).await? {
            return Ok(response);
        }
        let Some(row) = ctx.database.get_oauth_resource(&identifier).await? else {
            return super::clients::status_protocol_error(
                404,
                "not_found",
                &format!("resource {identifier} not found"),
            );
        };
        EndpointResponse::json(&resource_value(row)?)
    }
}

impl OAuthProviderPlugin {
    /// Patch the provider's durable resource policy without changing its identifier.
    pub fn admin_update_oauth_resource_endpoint(
        identifier: &str,
        patch: &impl serde::Serialize,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "adminUpdateOAuthResource")
            .with_params(&json!({"identifier":identifier}))?
            .with_body(patch)
    }
    pub(super) async fn update_resource<S: AuthSchema>(
        &self,
        params: Option<&JsValue>,
        input: Value,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let identifier = decode_parameter(params, "identifier")?;
        if let Some(response) = Box::pin(self.resource_admission(req, ctx)).await? {
            return Ok(response);
        }
        let Some(row) = ctx.database.get_oauth_resource(&identifier).await? else {
            return super::clients::status_protocol_error(
                404,
                "not_found",
                &format!("resource {identifier} not found"),
            );
        };
        let mut metadata = row
            .metadata
            .as_object()
            .cloned()
            .ok_or_else(|| AuthError::internal("Invalid resource metadata"))?;
        for (name, value) in input
            .as_object()
            .ok_or_else(|| AuthError::internal("Invalid resource update"))?
        {
            if name != "identifier" {
                _ = metadata.insert(name.clone(), value.clone());
            }
        }
        let now = chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
            .ok_or_else(|| AuthError::internal("Invalid resource update timestamp"))?;
        _ = ctx
            .database
            .update_oauth_resource(&identifier, Value::Object(metadata), now)
            .await?;
        let Some(row) = ctx.database.get_oauth_resource(&identifier).await? else {
            return super::clients::status_protocol_error(
                404,
                "not_found",
                &format!("resource {identifier} not found"),
            );
        };
        EndpointResponse::json(&resource_value(row)?)
    }
}

impl OAuthProviderPlugin {
    /// Remove durable provider resource policy through the server-only administration API.
    pub fn admin_delete_oauth_resource_endpoint(
        identifier: &str,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "adminDeleteOAuthResource")
            .with_params(&json!({"identifier":identifier}))
    }
    pub(super) async fn delete_resource<S: AuthSchema>(
        &self,
        params: Option<&JsValue>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let identifier = decode_parameter(params, "identifier")?;
        if let Some(response) = Box::pin(self.resource_admission(req, ctx)).await? {
            return Ok(response);
        }
        if ctx
            .database
            .get_oauth_resource(&identifier)
            .await?
            .is_none()
        {
            return super::clients::status_protocol_error(
                404,
                "not_found",
                &format!("resource {identifier} not found"),
            );
        }
        ctx.database.delete_oauth_resource(&identifier).await?;
        EndpointResponse::json(&json!({"deleted":true}))
    }
}

impl OAuthProviderPlugin {
    /// Grant a client durable membership in a provider resource through the server-only API.
    pub fn admin_link_client_resource_endpoint(
        identifier: &str,
        client_id: &str,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "adminLinkClientResource")
            .with_params(&json!({"identifier":identifier,"client_id":client_id}))
    }
    pub(super) async fn link_resource<S: AuthSchema>(
        &self,
        params: Option<&JsValue>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let identifier = decode_parameter(params, "identifier")?;
        let client_id = decode_parameter(params, "client_id")?;
        if let Some(response) = Box::pin(self.resource_admission(req, ctx)).await? {
            return Ok(response);
        }
        if ctx
            .database
            .get_oauth_resource(&identifier)
            .await?
            .is_none()
        {
            return super::clients::status_protocol_error(
                404,
                "not_found",
                &format!("resource {identifier} not found"),
            );
        }
        if ctx.database.get_oauth_client(&client_id).await?.is_none() {
            return super::clients::status_protocol_error(
                404,
                "not_found",
                &format!("client {client_id} not found"),
            );
        }
        let now = chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
            .ok_or_else(|| AuthError::internal("Invalid resource link timestamp"))?;
        match ctx
            .database
            .create_oauth_client_resource(alibi_core::store::CreateOAuthClientResource {
                client_id,
                resource_id: identifier,
                created_at: now,
            })
            .await
        {
            Ok(_) => EndpointResponse::json(&json!({"linked":true})),
            Err(error)
                if {
                    let message = error.to_string().to_ascii_lowercase();
                    message.contains("unique") || message.contains("duplicate")
                } =>
            {
                EndpointResponse::json(&json!({"linked":true,"alreadyLinked":true}))
            }
            Err(error) => Err(error),
        }
    }
}
