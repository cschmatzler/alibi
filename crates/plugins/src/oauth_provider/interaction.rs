use super::OAuthProviderPlugin;
use alibi_core::endpoint::{BeforeEndpointAction, EndpointCall, EndpointHook, EndpointResponse};
use alibi_core::session::SessionRequest;
use alibi_core::types::RequestExtensions;
use alibi_core::utils::cookie_utils::related_cookie_name;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema};
use alibi_core::{AuthRequest, AuthSession, Headers, HttpMethod, SessionView, UserView};
use async_trait::async_trait;
use std::collections::HashMap;

struct InteractionState {
    signed_query: String,
}

struct InteractionRequest<'a, R> {
    original: &'a R,
    headers: HashMap<String, String>,
    session: SessionView,
    logical: Option<EndpointCall>,
}

impl<R: SessionRequest> SessionRequest for InteractionRequest<'_, R> {
    fn endpoint_call(&self) -> Option<&EndpointCall> {
        self.logical.as_ref()
    }
    fn physical_request(&self) -> Option<&AuthRequest> {
        self.original.physical_request()
    }
    fn session_headers(&self) -> &HashMap<String, String> {
        &self.headers
    }
    fn session_method(&self) -> &HttpMethod {
        self.original.session_method()
    }
    fn session_query_truthy(&self, name: &str) -> bool {
        self.original.session_query_truthy(name)
    }
    fn extensions(&self) -> &RequestExtensions {
        self.original.extensions()
    }
    fn virtual_session<S: AuthSchema>(&self, _: &AuthContext<S>) -> Option<SessionView> {
        Some(self.session.clone())
    }
    fn take_response_headers(&self) -> Headers {
        self.original.take_response_headers()
    }
    fn queue_response_header(&self, name: impl Into<String>, value: impl Into<String>) {
        self.original.queue_response_header(name, value);
    }
    fn set_session_hook_snapshot(&self, user: UserView, session: SessionView) {
        self.original.set_session_hook_snapshot(user, session);
    }
}

fn query_text(input: &JsValue) -> AuthResult<String> {
    let ordinary =
        |message: &str| AuthError::CallbackFailure(Box::new(AuthError::internal(message)));
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    match input {
        JsValue::Object(fields) => {
            for (name, value) in fields {
                _ = query.append_pair(name, &value.coerce_string().map_err(ordinary)?);
            }
        }
        JsValue::Array(entries) => {
            for entry in entries {
                let JsValue::Array(pair) = entry else {
                    return Err(ordinary(
                        "Each query pair must be an iterable [name, value] tuple",
                    ));
                };
                let [name, value] = pair.as_slice() else {
                    return Err(ordinary(
                        "Each query pair must be an iterable [name, value] tuple",
                    ));
                };
                _ = query.append_pair(
                    &name.coerce_string().map_err(ordinary)?,
                    &value.coerce_string().map_err(ordinary)?,
                );
            }
        }
        value => return value.coerce_string().map_err(ordinary),
    }
    Ok(query.finish())
}

pub(super) fn admit(
    input: Option<&JsValue>,
    secret: &str,
    extensions: &RequestExtensions,
) -> AuthResult<Option<EndpointResponse>> {
    let Some(input) = input.filter(|value| value.is_truthy()) else {
        return Ok(None);
    };
    let query = query_text(input)?;
    if super::authorization::verify_authorization_query(&query, secret)? {
        extensions.insert(InteractionState {
            signed_query: query,
        });
        return Ok(None);
    }
    Ok(Some(
        EndpointResponse::error(AuthError::Api {
            status: 400,
            code: None,
            message: String::new(),
        })
        .with_error_body(alibi_core::utils::json::parse_value(
            r#"{"error":"invalid_signature"}"#,
        )?),
    ))
}

#[async_trait]
impl<S: AuthSchema> EndpointHook<S> for OAuthProviderPlugin {
    fn matches_before(&self, call: &EndpointCall, _: &AuthContext<S>) -> AuthResult<bool> {
        Ok(call
            .body()
            .and_then(|body| body.get("oauth_query"))
            .is_some_and(JsValue::is_truthy))
    }
    async fn before(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        Ok(admit(
            call.body().and_then(|body| body.get("oauth_query")),
            ctx.config.current_secret(),
            call.extensions(),
        )?
        .map(BeforeEndpointAction::Reject))
    }
    async fn after(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        let Some(mut resumed) = resume(self, call, response.headers(), ctx).await? else {
            return Ok(response);
        };
        resumed.merge_headers(response.headers().clone());
        Ok(resumed)
    }
}

pub(super) async fn resume<S: AuthSchema>(
    provider: &OAuthProviderPlugin,
    req: &impl SessionRequest,
    headers: &Headers,
    ctx: &AuthContext<S>,
) -> AuthResult<Option<EndpointResponse>> {
    let Some(state) = req.extensions().get::<InteractionState>() else {
        return Ok(None);
    };
    let cookie_name = related_cookie_name(&ctx.config, "session_token");
    let token = headers
        .get_all("set-cookie")
        .filter_map(|cookie| cookie.split(';').next()?.split_once('='))
        .filter(|(name, _)| *name == cookie_name)
        .map(|(_, value)| value.split('.').next().unwrap_or(""))
        .last()
        .unwrap_or("");
    if token.is_empty() {
        return Ok(None);
    }
    let Some(session) = ctx.database.get_session(token).await? else {
        return Ok(None);
    };
    let mut query = super::continuation::interaction_query(&state.signed_query);
    if let Some(prompt) = query.get("prompt").and_then(serde_json::Value::as_str) {
        let mut prompts = prompt.split(' ').collect::<Vec<_>>();
        if let Some(index) = prompts.iter().position(|prompt| *prompt == "login") {
            _ = prompts.remove(index);
            if prompts.is_empty() {
                _ = query.remove("prompt");
            } else {
                let value = prompts.join(" ");
                _ = query.insert("prompt".into(), serde_json::json!(value));
            }
        }
    }
    let issued_at = url::form_urlencoded::parse(state.signed_query.as_bytes())
        .find(|(name, _)| name == "ba_iat")
        .and_then(|(_, value)| alibi_core::utils::javascript::string_to_number(&value))
        .filter(|value| value.is_finite() && *value > 0.0 && *value <= 8_640_000_000_000_000.0)
        .and_then(|value| value.trunc().to_string().parse::<i64>().ok());
    if issued_at.is_some_and(|issued_at| session.created_at().timestamp_millis() >= issued_at) {
        _ = query.remove("max_age");
    }
    let mut headers = req.session_headers().clone();
    let navigation = req.physical_request().is_some_and(|physical| {
        let mode = physical
            .header("sec-fetch-mode")
            .map(|mode| mode.to_ascii_lowercase());
        let accept = physical
            .header("accept")
            .map_or_else(String::new, |accept| accept.to_ascii_lowercase());
        mode.as_deref() == Some("navigate")
            || mode.is_none()
                && (accept.contains("text/html") || accept.contains("application/xhtml+xml"))
    });
    if !navigation {
        _ = headers.insert("accept".into(), "application/json".into());
    }
    let session_view = SessionView::from(&session);
    let logical = if let Some(original) = req.endpoint_call() {
        let Some(user) = ctx.session_user(&session).await? else {
            return Ok(None);
        };
        let mut call = original.clone();
        call.replace_headers(headers.clone());
        call.establish_session::<S>(
            user.clone(),
            ctx.user_view(&user),
            session_view.clone(),
            ctx,
        );
        Some(call)
    } else {
        None
    };
    let request = InteractionRequest {
        original: req,
        headers,
        session: session_view,
        logical,
    };
    Ok(Some(
        Box::pin(provider.authorize_flow(
            Some(alibi_core::utils::json::parse_value(
                &serde_json::to_string(&query)?,
            )?),
            &request,
            ctx,
            super::authorization::AuthorizationSettings::default(),
        ))
        .await?,
    ))
}
