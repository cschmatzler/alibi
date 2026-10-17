//! RFC 7662 introspection over actually issued and protected durable tokens.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint};
use alibi_core::session::SessionRequest;
use alibi_core::store::OAuthTokenKind;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthSession};
use serde_json::{Value, json};
impl OAuthProviderPlugin {
    /// Inspect an access or refresh token using the introspecting client's credentials.
    pub fn oauth2_introspect_endpoint(
        input: &impl serde::Serialize,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "oauth2Introspect").with_body(input)
    }
    pub(super) async fn introspect<S: AuthSchema>(
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
        let credentials =
            match super::credentials::extract(&body, req, ctx, self, "introspect").await? {
                Ok(credentials) => credentials,
                Err(response) => return Ok(no_store(response)),
            };
        if credentials.client_id.is_empty()
            || (credentials.secret.is_empty() && !credentials.pre_verified)
        {
            return error(401, "invalid_client", "missing required credentials");
        }
        let raw = body
            .get("token")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let token = crate::oauth2::strip_access_token_authorization_scheme(raw);
        let token = token.as_str();
        if token.is_empty() {
            return error(
                400,
                "invalid_request",
                "missing a required token for introspection",
            );
        }
        let introspecting_client = match credentials.authenticate(ctx, self).await? {
            Ok(client) => client,
            Err(response) => return Ok(no_store(response)),
        };
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
            let refresh = matches!(kind, OAuthTokenKind::Refresh);
            if !refresh {
                match self
                    .validate_access_token(ctx, token, Some(&credentials.client_id))
                    .await
                {
                    Ok(payload) => {
                        let payload = self
                            .resolve_introspection_subject(ctx, payload, &introspecting_client)
                            .await?;
                        return Ok(no_store(EndpointResponse::json(&payload)?));
                    }
                    Err(failure) if matches!(&failure.error, AuthError::Api { .. }) => {
                        if hint != "access_token" {
                            continue;
                        }
                        let inactive_error = failure.error.status_code() == 400
                            || failure
                                .body
                                .as_deref()
                                .and_then(|body| body.get("error"))
                                .and_then(JsValue::as_str)
                                == Some("invalid_token");
                        if inactive_error {
                            return inactive();
                        }
                        let mut response = EndpointResponse::error(failure.error);
                        if failure.body_absent {
                            response = response.without_error_body();
                        } else if let Some(body) = failure.body {
                            response = response.with_error_body(*body);
                        }
                        if let Some(headers) = failure.headers {
                            response.merge_headers(headers);
                        }
                        return Ok(no_store(response));
                    }
                    Err(_) => {
                        return Ok(no_store(
                            EndpointResponse::error(AuthError::Api {
                                status: 500,
                                code: None,
                                message: String::new(),
                            })
                            .without_error_body()
                            .with_header("content-type", "application/json"),
                        ));
                    }
                }
            }
            let Some(token) = self.decode_token_prefix(token, OAuthTokenKind::Refresh) else {
                continue;
            };
            let row = ctx
                .database
                .get_oauth_token(*kind, &self.hash_token(token, "refresh_token").await?)
                .await?;
            let Some(row) = row else {
                continue;
            };
            if row.expires_at < chrono::Utc::now()
                || row.metadata.get("revoked").is_some_and(|v| !v.is_null())
            {
                return inactive();
            }
            let client = if row.client_id == introspecting_client.client_id {
                Some(introspecting_client.clone())
            } else {
                super::discovery::resolve(ctx, &row.client_id).await?
            };
            let Some(client) = client else {
                return inactive();
            };
            if client.metadata.get("disabled") == Some(&Value::Bool(true)) {
                return inactive();
            }
            if row.client_id != credentials.client_id {
                return inactive();
            }
            let user = if let Some(id) = row.user_id.as_deref() {
                ctx.database.get_user_by_id(id).await?
            } else {
                None
            };
            let user_view = user.as_ref().map(|user| ctx.user_view(user));
            let mut session_id = row.session_id.clone();
            if let Some(id) = session_id.as_deref() {
                let sessions = if let Some(user) = row.user_id.as_deref() {
                    ctx.database.get_user_sessions(user).await?
                } else {
                    Vec::new()
                };
                if !sessions.iter().any(|session| {
                    session.id().as_ref() == id && session.expires_at() >= chrono::Utc::now()
                }) {
                    session_id = None;
                }
            }
            let base = format!(
                "{}{}",
                ctx.config.base_url.trim_end_matches('/'),
                ctx.config.base_path
            );
            let jwt = ctx.extensions.get::<crate::jwt::JwtDiscoveryOptions>();
            let issuer = if self.config.disable_jwt_plugin {
                &base
            } else {
                jwt.as_ref()
                    .and_then(|options| options.issuer.as_ref())
                    .unwrap_or(&base)
            };
            let scopes = row
                .metadata
                .get("scopes")
                .and_then(Value::as_array)
                .map(|scopes| {
                    scopes
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" ")
                });
            let mut payload = json!({"active":true,"iss":issuer,"client_id":row.client_id,"exp":row.expires_at.timestamp(),"iat":row.created_at.timestamp(),"scope":scopes});
            let fields = payload
                .as_object_mut()
                .ok_or_else(|| alibi_core::AuthError::internal("Invalid introspection payload"))?;
            fields.extend(super::access_validation::confirmation_claims(
                row.metadata.get("confirmation"),
            ));
            if let Some(user) = user_view {
                _ = fields.insert("sub".into(), json!(user.id));
            }
            if let Some(id) = session_id {
                _ = fields.insert("sid".into(), json!(id));
            }
            let payload = self
                .resolve_introspection_subject(ctx, payload, &introspecting_client)
                .await?;
            return Ok(no_store(EndpointResponse::json(&payload)?));
        }
        inactive()
    }
}
fn no_store(response: EndpointResponse) -> EndpointResponse {
    response
        .with_header("Cache-Control", "no-store")
        .with_header("Pragma", "no-cache")
}
fn inactive() -> AuthResult<EndpointResponse> {
    Ok(no_store(EndpointResponse::json(&json!({"active":false}))?))
}
fn error(status: u16, code: &str, description: &str) -> AuthResult<EndpointResponse> {
    super::clients::status_protocol_error(status, code, description).map(no_store)
}
