//! Popup OAuth entry and callback delivery, paired with the official popup client.
use super::oauth::OAuthConfig;
use alibi_core::error::codes;
use alibi_core::utils::cookie_utils::{
    create_clear_cookie, create_cookie, related_cookie_name, sign_cookie_value, verify_cookie_value,
};
use alibi_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, HttpMethod,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const SCRIPT: &str = include_str!("oauth_popup_script.js");
const CSP: &str = "default-src 'none'; script-src 'sha256-tIo2K8VBC9SnhvdZ+9GsGkQoZm+jm/JcxL+d+i8b8KQ='; base-uri 'none'";

/// Starts a popup in its first-party auth context and delivers callback results
/// to the trusted opener. Register alongside [`super::oauth::OAuthPlugin`] and
/// [`super::BearerPlugin`] for embedded clients.
#[derive(Clone, Debug, Default)]
pub struct OAuthPopupPlugin;

/// Provider and opener/redirect options for the public popup startup operation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthPopupStartInput {
    pub provider: String,
    pub popup_origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub popup_nonce: Option<String>,
    #[serde(rename = "callbackURL", skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL", skip_serializing_if = "Option::is_none")]
    pub error_callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL", skip_serializing_if = "Option::is_none")]
    pub new_user_callback_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_sign_up: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_data: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Marker {
    popup_origin: String,
    #[serde(default)]
    popup_nonce: String,
}

fn completion(origin: &str, message: &Value) -> AuthResult<AuthResponse> {
    let mut payload = json!({"type":"better-auth:oauth-popup", "targetOrigin":origin});
    if let (Some(payload), Some(message)) = (payload.as_object_mut(), message.as_object()) {
        payload.extend(message.clone());
    }
    let data = serde_json::to_string(&payload)?
        .replace('<', "\\u003c")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    Ok(AuthResponse::html(200, format!("<!doctype html>\n<html>\n<head><meta charset=\"utf-8\"><title>Completing sign-in</title></head>\n<body>\n<script type=\"application/json\" id=\"better-auth-oauth-popup\">{data}</script>\n<script>{SCRIPT}</script>\n</body>\n</html>"))
        .with_header("content-security-policy", CSP)
        .with_header("cache-control", "no-store").with_header("pragma", "no-cache"))
}

impl OAuthPopupPlugin {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Start popup authorization, returning a redirect error or an HTML response value.
    /// # Errors
    /// Returns an input serialization error.
    pub fn oauth_popup_start_endpoint(
        input: &OAuthPopupStartInput,
    ) -> AuthResult<alibi_core::endpoint::ServerEndpoint<Value>> {
        alibi_core::endpoint::ServerEndpoint::new("oauth-popup", "oauthPopupStart")
            .with_query(input)
    }

    async fn start<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        self.start_core(req, ctx, &req.query).await
    }

    async fn start_core<S: AuthSchema>(
        &self,
        req: &impl alibi_core::session::SessionRequest,
        ctx: &AuthContext<S>,
        query: &std::collections::HashMap<String, String>,
    ) -> AuthResult<AuthResponse> {
        let origin = query
            .get("popupOrigin")
            .ok_or_else(|| AuthError::bad_request("popupOrigin is required"))?;
        let provider = query
            .get("provider")
            .ok_or_else(|| AuthError::bad_request("provider is required"))?;
        if !ctx.config.is_origin_trusted(origin) {
            return Err(AuthError::Api {
                status: 403,
                code: Some(codes::INVALID_ORIGIN.into()),
                message: "Invalid origin".into(),
            });
        }
        let nonce = query.get("popupNonce").map_or("", String::as_str);
        let fail = |code: &str, description: String| {
            completion(
                origin,
                &json!({"nonce":nonce,"error":{"code":code,"description":description}}),
            )
        };
        for (key, code) in [
            ("callbackURL", "invalid_callback_url"),
            ("errorCallbackURL", "invalid_error_callback_url"),
            ("newUserCallbackURL", "invalid_new_user_callback_url"),
        ] {
            if let Some(url) = query.get(key).filter(|url| !url.is_empty())
                && !ctx.config.is_redirect_target_trusted(url)
            {
                return fail(code, format!("Untrusted URL: {url}"));
            }
        }
        let Some(config) = ctx
            .extensions
            .get::<OAuthConfig>()
            .filter(|config| config.providers.contains_key(provider))
        else {
            return fail(
                "provider_not_found",
                format!("Unknown provider: {provider}"),
            );
        };
        let mut body = serde_json::Map::new();
        _ = body.insert("provider".into(), json!(provider));
        _ = body.insert(
            "callbackURL".into(),
            json!(
                query
                    .get("callbackURL")
                    .filter(|v| !v.is_empty())
                    .cloned()
                    .unwrap_or_else(|| format!(
                        "{}{}",
                        ctx.config.base_url.trim_end_matches('/'),
                        ctx.config.base_path
                    ))
            ),
        );
        for key in ["errorCallbackURL", "newUserCallbackURL"] {
            if let Some(value) = query.get(key) {
                _ = body.insert(key.into(), json!(value));
            }
        }
        if query
            .get("requestSignUp")
            .is_some_and(|value| value == "true")
        {
            _ = body.insert("requestSignUp".into(), json!(true));
        }
        if let Some(scopes) = query.get("scopes").filter(|value| !value.is_empty()) {
            _ = body.insert(
                "scopes".into(),
                json!(scopes.split(',').collect::<Vec<_>>()),
            );
        }
        if let Some(data) = query
            .get("additionalData")
            .and_then(|value| serde_json::from_str::<Value>(value).ok())
            .filter(Value::is_object)
        {
            _ = body.insert(
                "additionalData".into(),
                Value::Object(
                    data.as_object()
                        .into_iter()
                        .flatten()
                        .filter(|(key, _)| {
                            !matches!(
                                key.as_str(),
                                "callbackURL"
                                    | "codeVerifier"
                                    | "errorURL"
                                    | "newUserURL"
                                    | "expiresAt"
                                    | "oauthState"
                                    | "link"
                                    | "requestSignUp"
                                    | "idTokenNonce"
                                    | "serverContext"
                            )
                        })
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect(),
                ),
            );
        }
        let body: super::oauth::OAuthSocialSignInRequest =
            serde_json::from_value(Value::Object(body))?;
        let Ok(mut response) =
            super::oauth::start_social_flow_response(&body, &config, req.physical_request(), ctx)
                .await
                .and_then(|response| response.to_response())
        else {
            return fail(
                "popup_sign_in_failed",
                "Failed to start the OAuth flow.".into(),
            );
        };
        if response.headers.get("location").is_none() {
            return fail(
                "popup_sign_in_failed",
                "Failed to start the OAuth flow.".into(),
            );
        }
        let marker = serde_json::to_string(&json!({"popupOrigin":origin,"popupNonce":nonce}))?;
        response.headers.append(
            "set-cookie",
            create_cookie(
                &related_cookie_name(&ctx.config, "oauth_popup"),
                &sign_cookie_value(&marker, ctx.config.current_secret()),
                600,
                &ctx.config,
            )?,
        );
        response.status = 302;
        response.body.clear();
        Ok(response)
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for OAuthPopupPlugin {
    route_openapi_metadata!(S);

    fn server_endpoints(&self) -> Vec<alibi_core::endpoint::EndpointDefinition> {
        vec![crate::endpoint::definition(
            "oauthPopupStart",
            "oauthPopupStart",
            Some("/oauth-popup/start"),
            HttpMethod::Get,
        )]
    }
    fn validate_endpoint(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<alibi_core::endpoint::EndpointInput> {
        use crate::authentication_helpers::JsonField;
        Ok(alibi_core::endpoint::EndpointInput {
            body: call.body().cloned(),
            query: Some(crate::endpoint::validate_fields(
                call.query(),
                "query",
                &[
                    JsonField::string("provider", true),
                    JsonField::string("popupOrigin", true),
                    JsonField::string("popupNonce", false),
                    JsonField::string("callbackURL", false),
                    JsonField::string("errorCallbackURL", false),
                    JsonField::string("newUserCallbackURL", false),
                    JsonField::string("scopes", false),
                    JsonField::string("requestSignUp", false),
                    JsonField::string("additionalData", false),
                ],
            )?),
        })
    }
    async fn on_endpoint(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<alibi_core::endpoint::EndpointResponse> {
        let output = self.start_core(call, ctx, &call.query_as()?).await?;
        if output.status == 302 {
            let mut response = alibi_core::endpoint::EndpointResponse::redirect(
                output.headers.get("location").cloned().unwrap_or_default(),
            );
            response.merge_headers(output.headers);
            return Ok(response);
        }
        Ok(alibi_core::endpoint::EndpointResponse::from_http_response(
            output,
        ))
    }
    fn name(&self) -> &'static str {
        "oauth-popup"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/oauth-popup/start", "oauthPopupStart")]
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if *req.method() == HttpMethod::Get && req.path() == "/oauth-popup/start" {
            return Ok(Some(self.start(req, ctx).await?));
        }
        Ok(None)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        if !(req.path().starts_with("/callback/") || req.path().starts_with("/oauth2/callback/")) {
            return Ok(response);
        }
        let Some(redirect) = response.headers.get("location").cloned() else {
            return Ok(response);
        };
        let name = related_cookie_name(&ctx.config, "oauth_popup");
        let marker = req
            .headers
            .get("cookie")
            .and_then(|header| {
                header.split(';').find_map(|part| {
                    let (key, value) = part.trim().split_once('=')?;
                    (key == name).then_some(value)
                })
            })
            .and_then(|value| verify_cookie_value(value, ctx.config.current_secret()));
        let Some(marker) = marker else {
            return Ok(response);
        };
        response
            .headers
            .append("set-cookie", create_clear_cookie(&name, &ctx.config)?);
        let Ok(marker) = serde_json::from_str::<Marker>(&marker) else {
            return Ok(response);
        };
        let token_name = related_cookie_name(&ctx.config, "session_token");
        let token = response.headers.get_all("set-cookie").find_map(|raw| {
            cookie::Cookie::parse(raw.clone())
                .ok()
                .filter(|cookie| cookie.name() == token_name)
                .map(|cookie| {
                    urlencoding::decode(cookie.value())
                        .map_or_else(|_| cookie.value().to_owned(), std::borrow::Cow::into_owned)
                })
        });
        let message = if let Some(token) = token.filter(|value| !value.is_empty()) {
            json!({"nonce":marker.popup_nonce,"token":token,"redirectTo":redirect})
        } else {
            let Ok(base) = url::Url::parse(&format!(
                "{}{}",
                ctx.config.base_url.trim_end_matches('/'),
                ctx.config.base_path
            )) else {
                return Ok(response);
            };
            let Ok(url) = base.join(&redirect) else {
                return Ok(response);
            };
            let Some(error) = url
                .query_pairs()
                .find(|(key, _)| key == "error")
                .map(|(_, value)| value.into_owned())
                .filter(|value| !value.is_empty())
            else {
                return Ok(response);
            };
            let mut error_data = serde_json::Map::new();
            _ = error_data.insert("code".into(), json!(error));
            if let Some(description) = url
                .query_pairs()
                .find(|(key, _)| key == "error_description")
                .map(|(_, value)| value.into_owned())
            {
                _ = error_data.insert("description".into(), json!(description));
            }
            json!({"nonce":marker.popup_nonce,"error":error_data})
        };
        let html = completion(&marker.popup_origin, &message)?;
        response.status = html.status;
        response.body = html.body;
        for (name, value) in html.headers.iter() {
            _ = response.headers.insert(name.clone(), value.clone());
        }
        Ok(response)
    }
}
