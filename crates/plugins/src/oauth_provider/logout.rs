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
    pub fn oauth2_end_session_confirmation_endpoint() -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "oauth2EndSessionConfirmation")
            .with_body(&json!({"action":"confirm"}))
    }
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
            super::discovery::resolve(ctx, id).await?
        } else {
            None
        };
        if hint.is_some() || client_id.is_some() {
            let Some(client) = &client else {
                if hint.is_some() && current.is_some() && browser(req) {
                    return confirmation(req, current.as_ref(), None, &json!({}), ctx);
                }
                return protocol_error(
                    req,
                    400,
                    "invalid_client",
                    "The logout client does not exist",
                );
            };
            if client.metadata.get("disabled") == Some(&Value::Bool(true)) {
                return protocol_error(req, 400, "invalid_client", "The logout client is disabled");
            }
            if client.metadata.get("enable_end_session") != Some(&Value::Bool(true)) {
                return protocol_error(
                    req,
                    401,
                    "invalid_client",
                    "The client is not allowed to initiate logout",
                );
            }
        }
        let Some(hint) = hint else {
            return confirmation(req, current.as_ref(), client.as_ref(), &input, ctx);
        };
        let Some(client) = client else {
            return protocol_error(
                req,
                400,
                "invalid_client",
                "The logout client does not exist",
            );
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
            if current.is_some() && browser(req) {
                let selected = if input
                    .get("client_id")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
                {
                    Some(&client)
                } else {
                    None
                };
                return confirmation(req, current.as_ref(), selected, &input, ctx);
            }
            return protocol_error(req, 401, "invalid_token", "The id_token_hint is invalid");
        };
        let Some(sid) = claims.get("sid").and_then(Value::as_str) else {
            return protocol_error(req, 401, "invalid_token", "The id_token_hint is invalid");
        };
        let matches = current
            .as_ref()
            .is_some_and(|session| session.id().as_ref() == sid);
        if current.is_some() && !matches {
            return confirmation(req, current.as_ref(), Some(&client), &input, ctx);
        }
        if let Some(session) = ctx.database.get_session_by_id(sid).await? {
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
        } else if browser(req) {
            success_page(false)
        } else {
            EndpointResponse::json(&Value::Null)?
        };
        if matches {
            for header in delete_session_cookie_headers(&ctx.config)? {
                response = response.with_header("set-cookie", header);
            }
        }
        response = response.with_header("set-cookie", confirmation_cookie(ctx, "", true)?);
        Ok(no_store(response))
    }
}
fn no_store(response: EndpointResponse) -> EndpointResponse {
    response
        .with_header("cache-control", "no-store")
        .with_header("pragma", "no-cache")
}
fn protocol_error(
    req: &impl SessionRequest,
    status: u16,
    error: &str,
    description: &str,
) -> AuthResult<EndpointResponse> {
    if browser(req) {
        return Ok(page(
            "Logout error",
            &format!(
                "<main><h1>Logout error</h1><p data-oidc-logout-state=\"error\">{}</p></main>",
                escape(description)
            ),
            status,
        ));
    }
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

fn browser(req: &impl SessionRequest) -> bool {
    let headers = req
        .physical_request()
        .map_or_else(|| req.session_headers(), |request| &request.headers);
    let header = |key: &str| {
        headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map_or("", |(_, value)| value.as_str())
    };
    header("sec-fetch-mode") != "cors"
        && (header("sec-fetch-mode") == "navigate"
            || header("accept").contains("text/html")
            || header("accept").contains("application/xhtml+xml"))
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn page(title: &str, body: &str, status: u16) -> EndpointResponse {
    let mut response = alibi_core::AuthResponse::new(status);
    response.body=format!("<!doctype html><html><head><meta charset=\"utf-8\"><title>{}</title></head><body>{body}</body></html>",escape(title)).into_bytes();
    _ = response
        .headers
        .insert("content-type", "text/html; charset=utf-8");
    _ = response.headers.insert(
        "content-security-policy",
        "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    _ = response.headers.insert("x-content-type-options", "nosniff");
    no_store(EndpointResponse::from_http_response(response))
}
fn success_page(invalid_redirect: bool) -> EndpointResponse {
    page(
        "Logged out",
        if invalid_redirect {
            "<main><p data-oidc-logout-state=\"logged-out\">Logged out. The requested post-logout redirect was not registered.</p></main>"
        } else {
            "<main><p data-oidc-logout-state=\"logged-out\">Logged out.</p></main>"
        },
        200,
    )
}
fn confirmation_cookie<S: AuthSchema>(
    ctx: &AuthContext<S>,
    value: &str,
    clear: bool,
) -> AuthResult<String> {
    use alibi_core::utils::cookie_utils::create_derived_session_cookie;
    let name = format!(
        "{}.oauth_logout_confirmation",
        related_cookie_name(&ctx.config, "session_token")
    );
    let raw = create_derived_session_cookie(&name, value, clear, &ctx.config)?;
    let mut cookie = cookie::Cookie::parse(raw)
        .map_err(|error| alibi_core::AuthError::internal(error.to_string()))?
        .into_owned();
    cookie.set_path(format!(
        "{}/oauth2/end-session/confirm",
        ctx.config.base_path
    ));
    cookie.set_max_age(cookie::time::Duration::seconds(if clear { 0 } else { 300 }));
    cookie.set_http_only(true);
    cookie.set_same_site(cookie::SameSite::Lax);
    Ok(cookie.to_string())
}
fn confirmation<S: AuthSchema>(
    req: &impl SessionRequest,
    current: Option<&S::Session>,
    client: Option<&alibi_core::store::OAuthClient>,
    input: &Value,
    ctx: &AuthContext<S>,
) -> AuthResult<EndpointResponse> {
    if !browser(req) {
        return protocol_error(
            req,
            400,
            "invalid_request",
            if current.is_some() {
                "User confirmation is required to complete logout"
            } else {
                "No active session is available for logout"
            },
        );
    }
    let mut state = serde_json::Map::from_iter([(
        "expiresAt".into(),
        json!(chrono::Utc::now().timestamp_millis() + 300_000),
    )]);
    if let Some(current) = current {
        _ = state.insert("sessionId".into(), json!(current.id()));
    }
    if let Some(client) = client
        && let Some(uri) = input
            .get("post_logout_redirect_uri")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    {
        if client
            .metadata
            .get("post_logout_redirect_uris")
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(uri)))
        {
            _ = state.insert("clientId".into(), json!(client.client_id));
            _ = state.insert("postLogoutRedirectUri".into(), json!(uri));
            if let Some(value) = input.get("state") {
                _ = state.insert("state".into(), value.clone());
            }
        } else {
            _ = state.insert("redirectInvalid".into(), json!(true));
        }
    }
    let signed = alibi_core::utils::cookie_utils::sign_cookie_value(
        &serde_json::to_string(&state)?,
        ctx.config.current_secret(),
    );
    let url = format!(
        "{}{}/oauth2/end-session/confirm",
        ctx.config.base_url.trim_end_matches('/'),
        ctx.config.base_path
    );
    Ok(page("Confirm logout",&format!("<main><h1>Confirm logout</h1><p>Do you want to log out of this account?</p><form method=\"post\" data-oidc-logout-confirmation action=\"{}\"><button type=\"submit\" name=\"action\" value=\"confirm\">Confirm logout</button></form></main>",escape(&url)),200).with_header("set-cookie",confirmation_cookie(ctx,&signed,false)?))
}
impl OAuthProviderPlugin {
    pub(super) async fn confirm_logout<S: AuthSchema>(
        &self,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let name = format!(
            "{}.oauth_logout_confirmation",
            related_cookie_name(&ctx.config, "session_token")
        );
        let value = req
            .session_headers()
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("cookie"))
            .and_then(|(_, header)| {
                header
                    .split(';')
                    .filter_map(|part| part.trim().split_once('='))
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value)
            });
        let state = value
            .and_then(|value| {
                alibi_core::utils::cookie_utils::verify_cookie_value(
                    value,
                    ctx.config.current_secret(),
                )
            })
            .and_then(|value| serde_json::from_str::<Value>(&value).ok());
        let Some(state) = state.filter(|state| {
            state
                .get("expiresAt")
                .and_then(Value::as_i64)
                .is_some_and(|time| time > chrono::Utc::now().timestamp_millis())
        }) else {
            return protocol_error(
                req,
                400,
                "invalid_request",
                "The logout confirmation is invalid or expired",
            );
        };
        let manager = ctx.session_manager();
        let current = if let Some(token) = manager.extract_session_token(req) {
            manager.get_session(&token).await?
        } else {
            None
        };
        if let Some(current) = &current
            && state
                .get("sessionId")
                .and_then(Value::as_str)
                .is_some_and(|id| id != current.id().as_ref())
        {
            return protocol_error(
                req,
                400,
                "invalid_request",
                "The logout confirmation is invalid or expired",
            );
        }
        let mut invalid_redirect = state.get("redirectInvalid") == Some(&Value::Bool(true));
        let mut redirect = None;
        if !invalid_redirect
            && let (Some(id), Some(uri)) = (
                state.get("clientId").and_then(Value::as_str),
                state.get("postLogoutRedirectUri").and_then(Value::as_str),
            )
        {
            let client = super::discovery::resolve(ctx, id).await?;
            if client.is_some_and(|client| {
                client.metadata.get("disabled") != Some(&Value::Bool(true))
                    && client.metadata.get("enable_end_session") == Some(&Value::Bool(true))
                    && client
                        .metadata
                        .get("post_logout_redirect_uris")
                        .and_then(Value::as_array)
                        .is_some_and(|values| {
                            values.iter().any(|value| value.as_str() == Some(uri))
                        })
            }) {
                let mut url = url::Url::parse(uri)
                    .map_err(|_| alibi_core::AuthError::bad_request("Invalid logout redirect"))?;
                if let Some(state) = state
                    .get("state")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                {
                    _ = url.query_pairs_mut().append_pair("state", state);
                }
                redirect = Some(url.to_string());
            } else {
                invalid_redirect = true;
            }
        }
        if let Some(current) = &current {
            ctx.database.delete_session(current.token()).await?;
        }
        let mut response = if let Some(uri) = redirect {
            EndpointResponse::redirect(uri).with_header("content-type", "application/json")
        } else if browser(req) {
            success_page(invalid_redirect)
        } else if current.is_none() {
            protocol_error(
                req,
                400,
                "invalid_request",
                "No active session is available for logout",
            )?
        } else {
            EndpointResponse::json(&Value::Null)?
        };
        if current.is_some() {
            for header in delete_session_cookie_headers(&ctx.config)? {
                response = response.with_header("set-cookie", header);
            }
        }
        response = response.with_header("set-cookie", confirmation_cookie(ctx, "", true)?);
        Ok(no_store(response))
    }
}
