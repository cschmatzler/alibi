//! Token retirement and guarded refresh-token family invalidation.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint, is_endpoint_api_error};
use alibi_core::session::SessionRequest;
use alibi_core::store::OAuthTokenKind;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthResult, AuthSchema};
use serde_json::{Value, json};
impl OAuthProviderPlugin {
    /// Revoke an issued token using its client's registered authentication method.
    pub fn oauth2_revoke_endpoint(
        input: &impl serde::Serialize,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "oauth2Revoke").with_body(input)
    }
    pub(super) async fn revoke<S: AuthSchema>(
        &self,
        input: Option<&JsValue>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let body = input
            .map(JsValue::to_json_value)
            .transpose()?
            .unwrap_or_else(|| json!({}));
        for (field, required) in [
            ("client_id", false),
            ("client_secret", false),
            ("client_assertion", false),
            ("client_assertion_type", false),
            ("token", true),
            ("token_type_hint", false),
        ] {
            if let Some(value) = body.get(field) {
                if !value.is_string() {
                    return error(
                        400,
                        "invalid_request",
                        &format!(
                            "{field} {}",
                            if value.is_array() {
                                "must not appear more than once"
                            } else {
                                "must be a string"
                            }
                        ),
                    );
                }
            } else if required {
                return error(400, "invalid_request", &format!("{field} is required"));
            }
        }
        let credentials = match super::credentials::extract(&body, req, ctx, self, "revoke").await?
        {
            Ok(credentials) => credentials,
            Err(response) => return Ok(response),
        };
        if credentials.client_id.is_empty() {
            return error(401, "invalid_client", "missing required credentials");
        }
        let raw = body
            .get("token")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let token = raw
            .strip_prefix("Bearer ")
            .or_else(|| raw.strip_prefix("DPoP "))
            .unwrap_or(raw);
        if token.is_empty() {
            return error(
                400,
                "invalid_request",
                "missing a required token for introspection",
            );
        }
        if let Err(response) = credentials.authenticate(ctx, self).await? {
            return Ok(response);
        }
        let hint = body
            .get("token_type_hint")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let kinds: &[OAuthTokenKind] = match hint {
            "access_token" => &[OAuthTokenKind::Access],
            "refresh_token" => &[OAuthTokenKind::Refresh],
            _ => &[OAuthTokenKind::Access, OAuthTokenKind::Refresh],
        };
        for kind in kinds {
            let Some(prefix_token) = self.decode_token_prefix(token, *kind) else {
                if matches!(kind, OAuthTokenKind::Refresh) && hint == "refresh_token" {
                    return error(400, "invalid_token", "refresh token not found");
                }
                continue;
            };
            let decoded = if matches!(kind, OAuthTokenKind::Refresh) {
                match self.decode_refresh_token(token).await {
                    Ok(Some(decoded)) => Some(decoded),
                    Ok(None) => continue,
                    Err(error) if is_endpoint_api_error(&error) => {
                        if hint != "refresh_token" {
                            continue;
                        }
                        return Ok(EndpointResponse::error(error));
                    }
                    Err(_) => {
                        return Ok(EndpointResponse::error(alibi_core::AuthError::Api {
                            status: 500,
                            code: None,
                            message: String::new(),
                        })
                        .without_error_body()
                        .with_header("content-type", "application/json"));
                    }
                }
            } else {
                None
            };
            let token = decoded
                .as_ref()
                .map_or(prefix_token, |decoded| decoded.token.as_str());
            let hash = self
                .hash_token(
                    token,
                    if matches!(kind, OAuthTokenKind::Refresh) {
                        "refresh_token"
                    } else {
                        "access_token"
                    },
                )
                .await?;
            let Some(row) = ctx.database.get_oauth_token(*kind, &hash).await? else {
                continue;
            };
            if matches!(kind, OAuthTokenKind::Refresh)
                && row.metadata.get("revoked").is_some_and(|v| !v.is_null())
            {
                ctx.database
                    .delete_oauth_refresh_family(
                        &credentials.client_id,
                        row.user_id.as_deref().unwrap_or("undefined"),
                    )
                    .await?;
                return error(400, "invalid_request", "refresh token revoked");
            }
            if row.client_id != credentials.client_id {
                return EndpointResponse::json(&Value::Null);
            }
            if matches!(kind, OAuthTokenKind::Access) {
                ctx.database.delete_oauth_token(*kind, &hash).await?;
            } else {
                let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
                    .ok_or_else(|| alibi_core::AuthError::internal("Invalid revocation time"))?;
                if !ctx.database.revoke_oauth_refresh_token(&hash, now).await? {
                    ctx.database
                        .delete_oauth_refresh_family(
                            &credentials.client_id,
                            row.user_id.as_deref().unwrap_or("undefined"),
                        )
                        .await?;
                    return error(400, "invalid_request", "refresh token revoked");
                }
                ctx.database
                    .delete_oauth_access_tokens_for_refresh(&row.id)
                    .await?;
            }
            return Ok(EndpointResponse::empty().with_header("Content-Type", "application/json"));
        }
        error(
            400,
            "invalid_request",
            match hint {
                "access_token" => "Invalid access token",
                _ => "token not found",
            },
        )
    }
}
fn error(status: u16, code: &str, description: &str) -> AuthResult<EndpointResponse> {
    super::clients::status_protocol_error(status, code, description)
}
