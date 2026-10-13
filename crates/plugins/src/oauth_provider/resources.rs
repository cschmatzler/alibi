//! Durable resource administration and provider policy.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint};
use alibi_core::session::SessionRequest;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema};
use serde_json::{Value, json};
const ALGORITHMS: &[&str] = &["EdDSA", "ES256", "ES512", "PS256", "RS256"];
pub(super) fn validate_create(input: Option<&JsValue>) -> AuthResult<JsValue> {
    use crate::authentication_helpers::{JsonField, JsonFieldKind, field_issue, json_type};
    let mut output = crate::endpoint::validate_fields(
        input,
        "body",
        &[JsonField {
            name: "identifier",
            kind: JsonFieldKind::NonEmptyString,
            required: true,
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
