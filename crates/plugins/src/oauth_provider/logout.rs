//! RP initiated logout binds signed ID-token hints to real stored sessions.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint};
use alibi_core::session::SessionRequest;
use alibi_core::utils::cookie_utils::{delete_session_cookie_headers, related_cookie_name};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthResult, AuthSchema, AuthSession};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
impl OAuthProviderPlugin {
    pub fn oauth2_end_session_endpoint(input: &Value) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "oauth2EndSession").with_query(input)
    }
    pub(super) async fn end_session<S: AuthSchema>(
        &self,
        query: Option<&JsValue>,
        body: Option<&JsValue>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let mut input = query
            .map(JsValue::to_json_value)
            .transpose()?
            .unwrap_or(json!({}));
        if let Some(body) = body {
            for (key, value) in body.to_json_value()?.as_object().into_iter().flatten() {
                if let Some(input) = input.as_object_mut() {
                    _ = input.insert(key.clone(), value.clone());
                }
            }
        }
        let manager = ctx.session_manager();
        let current = if let Some(token) = manager.extract_session_token(req) {
            manager.get_session(&token).await?
        } else {
            None
        };
        let hint = input.get("id_token_hint").and_then(Value::as_str);
        let decoded = hint
            .and_then(|token| token.split('.').nth(1))
            .and_then(|part| URL_SAFE_NO_PAD.decode(part).ok())
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
        let client_id = input
            .get("client_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                decoded.as_ref().and_then(|payload| {
                    payload
                        .get("aud")
                        .and_then(Value::as_str)
                        .filter(|value| !value.is_empty())
                        .or_else(|| {
                            payload
                                .get("azp")
                                .and_then(Value::as_str)
                                .filter(|value| !value.is_empty())
                        })
                        .or_else(|| {
                            payload
                                .get("aud")
                                .and_then(Value::as_array)
                                .filter(|values| values.len() == 1)
                                .and_then(|values| values.first().and_then(Value::as_str))
                        })
                })
            });
        let client = if let Some(id) = client_id {
            ctx.database.get_oauth_client(id).await?
        } else {
            None
        };
        if hint.is_some() || client_id.is_some() {
            let Some(client) = &client else {
                return protocol_error(400, "invalid_client", "The logout client does not exist");
            };
            if client.metadata.get("disabled") == Some(&Value::Bool(true)) {
                return protocol_error(400, "invalid_client", "The logout client is disabled");
            }
            if client.metadata.get("enable_end_session") != Some(&Value::Bool(true)) {
                return protocol_error(
                    401,
                    "invalid_client",
                    "The client is not allowed to initiate logout",
                );
            }
        }
        let Some(hint) = hint else {
            return protocol_error(
                400,
                "invalid_request",
                if current.is_some() {
                    "User confirmation is required to complete logout"
                } else {
                    "No active session is available for logout"
                },
            );
        };
        let Some(client) = client else {
            return protocol_error(400, "invalid_client", "The logout client does not exist");
        };
        let jwt = ctx.extensions.get::<crate::jwt::JwtPlugin>();
        let claims = if let Some(jwt) = jwt {
            jwt.verify_signed_payload(hint, req.physical_request(), ctx)
                .await
                .unwrap_or(None)
        } else {
            None
        };
        let base = format!(
            "{}{}",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path
        );
        let discovery = ctx.extensions.get::<crate::jwt::JwtDiscoveryOptions>();
        let issuer = discovery
            .as_ref()
            .and_then(|options| options.issuer.as_deref())
            .unwrap_or(&base);
        let Some(claims) = claims.filter(|claims| {
            claims.get("iss").and_then(Value::as_str) == Some(issuer)
                && claims.get("aud").is_some_and(|aud| {
                    aud.as_str() == Some(client.client_id.as_str())
                        || aud.as_array().is_some_and(|values| {
                            values
                                .iter()
                                .any(|value| value.as_str() == Some(client.client_id.as_str()))
                        })
                })
                && ["sub", "sid"].iter().all(|field| {
                    claims
                        .get(*field)
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                })
        }) else {
            return protocol_error(401, "invalid_token", "The id_token_hint is invalid");
        };
        let (Some(sid), Some(subject)) = (
            claims.get("sid").and_then(Value::as_str),
            claims.get("sub").and_then(Value::as_str),
        ) else {
            return protocol_error(401, "invalid_token", "The id_token_hint is invalid");
        };
        let matches = current
            .as_ref()
            .is_some_and(|session| session.id().as_ref() == sid);
        if current.is_some() && !matches {
            return protocol_error(
                400,
                "invalid_request",
                "User confirmation is required to complete logout",
            );
        }
        let sessions = ctx.database.get_user_sessions(subject).await?;
        if let Some(session) = sessions.iter().find(|session| session.id().as_ref() == sid) {
            ctx.database.delete_session(session.token()).await?;
        }
        let mut response = if let Some(uri) = input
            .get("post_logout_redirect_uri")
            .and_then(Value::as_str)
            .filter(|uri| !uri.is_empty())
            && client
                .metadata
                .get("post_logout_redirect_uris")
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(uri)))
        {
            let location = if let Some(state) = input
                .get("state")
                .and_then(Value::as_str)
                .filter(|state| !state.is_empty())
            {
                let mut url = url::Url::parse(uri)
                    .map_err(|_| alibi_core::AuthError::bad_request("Invalid logout redirect"))?;
                _ = url.query_pairs_mut().append_pair("state", state);
                url.to_string()
            } else {
                uri.to_owned()
            };
            EndpointResponse::redirect(location).with_header("content-type", "application/json")
        } else {
            EndpointResponse::json(&Value::Null)?
        };
        if matches {
            for header in delete_session_cookie_headers(&ctx.config)? {
                response = response.with_header("set-cookie", header);
            }
        }
        response=response.with_header("set-cookie",format!("{}.oauth_logout_confirmation=; Max-Age=0; Path={}/oauth2/end-session/confirm; HttpOnly; SameSite=Lax",related_cookie_name(&ctx.config,"session_token"),ctx.config.base_path));
        Ok(no_store(response))
    }
}
fn no_store(response: EndpointResponse) -> EndpointResponse {
    response
        .with_header("cache-control", "no-store")
        .with_header("pragma", "no-cache")
}
fn protocol_error(status: u16, error: &str, description: &str) -> AuthResult<EndpointResponse> {
    super::clients::status_protocol_error(status, error, description).map(no_store)
}
pub(super) fn validate(input: Option<&JsValue>, location: &str) -> AuthResult<Option<JsValue>> {
    input
        .map(|input| {
            crate::endpoint::validate_fields(
                Some(input),
                location,
                &[
                    crate::authentication_helpers::JsonField::string("id_token_hint", false),
                    crate::authentication_helpers::JsonField::string("client_id", false),
                    crate::authentication_helpers::JsonField::string(
                        "post_logout_redirect_uri",
                        false,
                    ),
                    crate::authentication_helpers::JsonField::string("state", false),
                ],
            )
        })
        .transpose()
}
