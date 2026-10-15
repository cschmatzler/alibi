//! Authorization admission and signed browser interaction requests.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint};
use alibi_core::session::SessionRequest;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthUser};
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
impl OAuthProviderPlugin {
    /// Authorize an OAuth request with its genuine physical request attached.
    pub fn oauth2_authorize_endpoint(
        query: &impl serde::Serialize,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "oauth2Authorize").with_query(query)
    }
    pub(super) async fn authorize<S: AuthSchema>(
        &self,
        input: Option<JsValue>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        Box::pin(self.authorize_flow(input, req, ctx, true)).await
    }
    pub(super) async fn authorize_flow<S: AuthSchema>(
        &self,
        input: Option<JsValue>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
        initial: bool,
    ) -> AuthResult<EndpointResponse> {
        if !self
            .config
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
        {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 404,
                code: None,
                message: String::new(),
            })
            .without_error_body()
            .with_header("Content-Type", "application/json"));
        }
        if req.physical_request().is_none() {
            return super::clients::status_protocol_error(
                401,
                "invalid_request",
                "request not found",
            );
        }
        let mut query: serde_json::Map<String, Value> = input
            .and_then(|value| alibi_core::utils::json::from_value(value).ok())
            .unwrap_or_default();
        let text = |name: &str| {
            query
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let client_id = text("client_id");
        let redirect_uri = text("redirect_uri");
        let response_type = text("response_type");
        let state = text("state");
        let server_error = format!(
            "{}{}/error",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path
        );
        if text("prompt")
            .split(' ')
            .any(|prompt| prompt == "select_account")
            && self.config.select_account_page.is_none()
        {
            return browser_redirect(
                req,
                &error_url(
                    &server_error,
                    "unsupported_prompt_select_account",
                    "unsupported prompt type",
                    None,
                    None,
                )?,
            );
        }
        let client = super::discovery::resolve(ctx, &client_id).await?;
        let trusted = client.as_ref().is_some_and(|client| {
            client.metadata.get("disabled") != Some(&json!(true))
                && registered_redirect(&client.metadata, &redirect_uri)
        });
        let issuer = self
            .metadata(ctx)?
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let admission_error = |error: &str, description: &str| {
            let target = if trusted {
                redirect_uri.as_str()
            } else {
                server_error.as_str()
            };
            let url = error_url(
                target,
                error,
                description,
                if trusted { Some(state.as_str()) } else { None },
                if trusted { Some(issuer.as_str()) } else { None },
            )?;
            browser_redirect(req, &url)
        };
        if query.contains_key("request") && query.contains_key("request_uri") {
            return admission_error(
                "invalid_request",
                "request and request_uri cannot be used together",
            );
        }
        if query.contains_key("request") {
            return admission_error("request_not_supported", "request object not supported");
        }
        if query.contains_key("request_uri") {
            return admission_error("request_uri_not_supported", "request_uri not supported");
        }
        for name in [
            "response_type",
            "request",
            "request_uri",
            "redirect_uri",
            "scope",
            "state",
            "client_id",
            "prompt",
            "display",
            "ui_locales",
            "acr_values",
            "login_hint",
            "id_token_hint",
            "code_challenge",
            "code_challenge_method",
            "nonce",
            "dpop_jkt",
        ] {
            if let Some(value) = query.get(name)
                && !value.is_string()
            {
                let message = if value.is_array() {
                    format!("{name} must not appear more than once")
                } else {
                    format!("{name} must be a string")
                };
                return admission_error("invalid_request", &message);
            }
        }
        if client_id.is_empty() {
            return admission_error("invalid_request", "client_id is required");
        }
        if response_type.is_empty() {
            return admission_error("invalid_request", "response_type is required");
        }
        if response_type != "code" {
            return admission_error(
                "unsupported_response_type",
                "response_type must be one of: code",
            );
        }
        let Some(client) = client else {
            return browser_redirect(
                req,
                &error_url(
                    &server_error,
                    "invalid_client",
                    "client_id is required",
                    None,
                    None,
                )?,
            );
        };
        if client.metadata.get("disabled") == Some(&json!(true)) {
            return browser_redirect(
                req,
                &error_url(
                    &server_error,
                    "client_disabled",
                    "client is disabled",
                    None,
                    None,
                )?,
            );
        }
        if !client
            .metadata
            .get("grant_types")
            .and_then(Value::as_array)
            .is_some_and(|grants| grants.contains(&json!("authorization_code")))
        {
            return browser_redirect(
                req,
                &error_url(
                    &server_error,
                    "unauthorized_client",
                    "client is not authorized to use the authorization_code grant",
                    None,
                    None,
                )?,
            );
        }
        if !trusted {
            return browser_redirect(
                req,
                &error_url(
                    &server_error,
                    "invalid_redirect",
                    "invalid redirect uri",
                    None,
                    None,
                )?,
            );
        }
        let allowed = client
            .metadata
            .get("scope")
            .and_then(Value::as_str)
            .map_or_else(
                || self.config.scopes.clone(),
                |scope| scope.split(' ').map(str::to_owned).collect(),
            );
        let scope = query
            .get("scope")
            .and_then(Value::as_str)
            .map_or_else(|| allowed.join(" "), str::to_owned);
        let requested = scope
            .split(' ')
            .filter(|scope| !scope.is_empty())
            .collect::<Vec<_>>();
        let invalid = requested
            .iter()
            .filter(|scope| !allowed.iter().any(|allowed| allowed == **scope))
            .copied()
            .collect::<Vec<_>>();
        if !invalid.is_empty() {
            return admission_error(
                "invalid_scope",
                &format!("The following scopes are invalid: {}", invalid.join(", ")),
            );
        }
        if query
            .get("resource")
            .is_some_and(|value| !value.is_string() && !value.is_array())
        {
            return admission_error("invalid_request", "resource: Invalid input");
        }
        if let Err(error) = self
            .admit_resources(ctx, &client_id, &requested, query.get("resource"))
            .await
        {
            if let Some(body) = error.body {
                let body = body.to_json_value()?;
                return admission_error(
                    body.get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("server_error"),
                    body.get("error_description")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                );
            }
            return Err(error.error);
        }
        let challenge = text("code_challenge");
        let method = text("code_challenge_method");
        let public = client
            .metadata
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            == Some("none");
        let nonce = text("nonce");
        let pkce = if public {
            Some("pkce is required for public clients")
        } else if requested.contains(&"offline_access")
            && (!requested.contains(&"openid") || nonce.is_empty())
        {
            Some("pkce or OIDC nonce is required when requesting offline_access scope")
        } else if client.metadata.get("require_pkce") != Some(&json!(false)) {
            Some("pkce is required for this client")
        } else {
            None
        };
        if let Some(reason) = pkce
            && (challenge.is_empty() || method.is_empty())
        {
            return admission_error("invalid_request", reason);
        }
        if challenge.is_empty() != method.is_empty() {
            return admission_error(
                "invalid_request",
                "code_challenge and code_challenge_method must both be provided",
            );
        }
        if !method.is_empty() && method != "S256" {
            return admission_error(
                "invalid_request",
                "code_challenge_method must be one of: S256",
            );
        }
        let prompt = text("prompt");
        let prompts = prompt.split(' ').collect::<Vec<_>>();
        let session = Box::pin(ctx.require_cached_session(req)).await.ok();

        let force_login =
            session.is_none() || prompts.contains(&"login") || prompts.contains(&"create");
        _ = query.insert("scope".into(), json!(scope));
        if !force_login
            && initial
            && prompts.contains(&"select_account")
            && let Some(page) = &self.config.select_account_page
        {
            let params = self.sign_authorization_query(query, ctx)?;
            return browser_redirect(req, &format!("{page}?{params}"));
        }
        let remembered = if !force_login
            && !prompts.contains(&"consent")
            && client.metadata.get("skip_consent") != Some(&json!(true))
            && let Some((user, _)) = &session
        {
            ctx.database
                .list_oauth_consents_by_user(user.id().as_ref())
                .await?
                .into_iter()
                .any(|consent| {
                    consent.client_id == client_id
                        && scope.split(' ').all(|scope| {
                            consent
                                .metadata
                                .get("scopes")
                                .and_then(Value::as_array)
                                .is_some_and(|scopes| {
                                    scopes.iter().any(|value| value.as_str() == Some(scope))
                                })
                        })
                })
        } else {
            false
        };
        if !force_login
            && !prompts.contains(&"consent")
            && (client.metadata.get("skip_consent") == Some(&json!(true)) || remembered)
            && let Some((user, session)) = &session
        {
            let code = rand::RngExt::sample_iter(rand::rng(), rand::distr::Alphanumeric)
                .map(char::from)
                .take(32)
                .collect::<String>();
            let now = chrono::Utc::now().timestamp();
            let created = chrono::DateTime::from_timestamp(now, 0)
                .ok_or_else(|| AuthError::internal("Invalid authorization code issue time"))?;
            let seconds = json!(now)
                .as_f64()
                .ok_or_else(|| AuthError::internal("Invalid authorization code issue time"))?;
            let expires_ms = ((seconds + self.config.code_expires_in) * 1000.0)
                .trunc()
                .to_string()
                .parse::<i64>()
                .map_err(|_| AuthError::internal("Invalid authorization code expiration"))?;
            let expires = chrono::DateTime::from_timestamp_millis(expires_ms)
                .ok_or_else(|| AuthError::internal("Invalid authorization code expiration"))?;
            let identifier = self.hash_token(&code, "authorization_code").await?;
            let resources = query.get("resource").map_or_else(Vec::new, |value| {
                value
                    .as_array()
                    .cloned()
                    .unwrap_or_else(|| vec![value.clone()])
            });
            let value = serde_json::to_string(
                &json!({"type":"authorization_code","query":query,"userId":user.id().as_ref(),"sessionId":session.id,"authTime":session.created_at.timestamp_millis(),"resource":resources}),
            )?;
            _ = ctx
                .verifications()
                .create(alibi_core::verification::VerificationCreation {
                    id: None,
                    identifier,
                    value,
                    expires_at: expires,
                    created_at: created,
                    updated_at: created,
                })
                .await?;
            let mut target = url::Url::parse(&redirect_uri)
                .map_err(|error| AuthError::internal(error.to_string()))?;
            _ = target.query_pairs_mut().append_pair("code", &code);
            if !state.is_empty() {
                _ = target.query_pairs_mut().append_pair("state", &state);
            }
            _ = target.query_pairs_mut().append_pair("iss", &issuer);
            return browser_redirect(req, target.as_str());
        }
        if prompts.contains(&"none") {
            return admission_error(
                if force_login {
                    "login_required"
                } else {
                    "consent_required"
                },
                if force_login {
                    "authentication required"
                } else {
                    "End-User consent is required"
                },
            );
        }
        let page = if force_login {
            &self.config.login_page
        } else {
            &self.config.consent_page
        };
        let params = self.sign_authorization_query(query, ctx)?;
        browser_redirect(req, &format!("{page}?{params}"))
    }
    fn sign_authorization_query<S: AuthSchema>(
        &self,
        query: serde_json::Map<String, Value>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<String> {
        let now = chrono::Utc::now().timestamp_millis();
        let seconds = json!(now / 1000)
            .as_f64()
            .ok_or_else(|| AuthError::internal("Invalid authorization timestamp"))?;
        let mut pairs = Vec::new();
        for (name, value) in query {
            if ["sig", "exp", "ba_iat", "ba_param", "ba_pl"].contains(&name.as_str()) {
                continue;
            }
            match value {
                Value::Null => {}
                Value::Array(values) => {
                    for value in values {
                        pairs.push((name.clone(), parameter_text(&value)));
                    }
                }
                value => pairs.push((name, parameter_text(&value))),
            }
        }
        pairs.push((
            "exp".into(),
            (seconds + self.config.code_expires_in).to_string(),
        ));
        pairs.push(("ba_iat".into(), now.to_string()));
        let mut names = pairs
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        names.push("ba_param".into());
        names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        names.dedup();
        for name in names {
            pairs.push(("ba_param".into(), name));
        }
        let mut canonical = pairs.clone();
        canonical.sort_by(|(a, av), (b, bv)| {
            a.encode_utf16()
                .cmp(b.encode_utf16())
                .then_with(|| av.encode_utf16().cmp(bv.encode_utf16()))
        });
        let mut mac = Hmac::<Sha256>::new_from_slice(ctx.config.current_secret().as_bytes())
            .map_err(|_| AuthError::internal("Invalid authorization signing key"))?;
        mac.update(encode_pairs(&canonical).as_bytes());
        let signature =
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        pairs.push(("sig".into(), signature));
        Ok(encode_pairs(&pairs))
    }
}
fn parameter_text(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}
fn encode_pairs(pairs: &[(String, String)]) -> String {
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        _ = encoded.append_pair(name, value);
    }
    encoded.finish()
}
fn registered_redirect(metadata: &Value, requested: &str) -> bool {
    if requested.contains('#') {
        return false;
    }
    metadata
        .get("redirect_uris")
        .and_then(Value::as_array)
        .is_some_and(|uris| {
            uris.iter().filter_map(Value::as_str).any(|uri| {
                uri == requested || {
                    let parsed = url::Url::parse(uri)
                        .ok()
                        .zip(url::Url::parse(requested).ok());
                    parsed.is_some_and(|(mut registered, mut requested)| {
                        let loopback = registered.host_str().is_some_and(|host| {
                            ["localhost", "127.0.0.1", "[::1]"].contains(&host)
                        });
                        if registered.scheme() != "http"
                            || requested.scheme() != "http"
                            || !loopback
                        {
                            return false;
                        }
                        _ = registered.set_port(None);
                        _ = requested.set_port(None);
                        registered == requested
                    })
                }
            })
        })
}
fn error_url(
    target: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
    issuer: Option<&str>,
) -> AuthResult<String> {
    let mut url =
        url::Url::parse(target).map_err(|error| AuthError::internal(error.to_string()))?;
    {
        let mut params = url.query_pairs_mut();
        _ = params.append_pair("error", error);
        _ = params.append_pair("error_description", description);
        if let Some(state) = state.filter(|state| !state.is_empty()) {
            _ = params.append_pair("state", state);
        }
        if let Some(issuer) = issuer {
            _ = params.append_pair("iss", issuer);
        }
    }
    Ok(url.into())
}
fn browser_redirect(req: &impl SessionRequest, target: &str) -> AuthResult<EndpointResponse> {
    let json = req.session_headers().iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("accept") && value.contains("application/json")
    });
    let fetch = req.physical_request().is_some_and(|request| {
        request
            .header("sec-fetch-dest")
            .is_some_and(|value| value == "empty")
    });
    if json || fetch {
        EndpointResponse::json(&json!({"redirect":true,"url":target}))
    } else {
        Ok(EndpointResponse::redirect(target))
    }
}

pub(super) fn verify_authorization_query(query: &str, secret: &str) -> AuthResult<bool> {
    let pairs = url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect::<Vec<_>>();
    let signatures = pairs.iter().filter(|(k, _)| k == "sig").collect::<Vec<_>>();
    let [(_, signature_text)] = signatures.as_slice() else {
        return Ok(false);
    };
    if signature_text.is_empty() {
        return Ok(false);
    }
    let Some(exp) = pairs
        .iter()
        .find(|(k, _)| k == "exp")
        .and_then(|(_, v)| v.parse::<f64>().ok())
    else {
        return Ok(false);
    };
    if !exp.is_finite()
        || exp * 1000.0
            < json!(chrono::Utc::now().timestamp_millis())
                .as_f64()
                .ok_or_else(|| AuthError::internal("Invalid authorization timestamp"))?
    {
        return Ok(false);
    }
    let mut canonical = pairs
        .iter()
        .filter(|(k, _)| k != "sig")
        .cloned()
        .collect::<Vec<_>>();
    canonical.sort_by(|(a, av), (b, bv)| {
        a.encode_utf16()
            .cmp(b.encode_utf16())
            .then_with(|| av.encode_utf16().cmp(bv.encode_utf16()))
    });
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| AuthError::internal("Invalid authorization signing key"))?;
    mac.update(encode_pairs(&canonical).as_bytes());
    let Ok(signature) = base64::engine::general_purpose::STANDARD.decode(signature_text) else {
        return Ok(false);
    };
    if base64::engine::general_purpose::STANDARD.encode(&signature) != *signature_text {
        return Ok(false);
    }
    Ok(mac.verify_slice(&signature).is_ok())
}
