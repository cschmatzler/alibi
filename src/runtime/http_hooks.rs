use super::BetterAuth;
use super::endpoint::merge_headers;
use alibi_core::endpoint::{
    BeforeEndpointAction, EndpointCall, EndpointContextPatch, EndpointResponse,
    is_endpoint_api_error, with_endpoint_call_context,
};
use alibi_core::{AuthError, AuthSchema, Headers};
use std::sync::Arc;

type HttpEndpointError = (u16, Option<String>, String);

/// Frames retained by the real HTTP endpoint pipeline for configured hooks.
#[derive(Clone)]
pub(super) struct HttpEndpointFrame {
    pub call: EndpointCall,
    pub outer: EndpointCall,
    pub header_patch: Option<std::collections::HashMap<String, String>>,
    pub legacy_headers: Option<std::collections::HashMap<String, String>>,
    pub error: Arc<std::sync::Mutex<Option<HttpEndpointError>>>,
}

impl<S: AuthSchema> BetterAuth<S> {
    pub(super) async fn before_http_endpoint(
        &self,
        request: &mut alibi_core::AuthRequest,
        route: &alibi_core::AuthRoute,
        context: &alibi_core::AuthContext<S>,
    ) -> alibi_core::AuthResult<Option<alibi_core::AuthResponse>> {
        if self.endpoint_hooks.is_empty() {
            return Ok(None);
        }
        let mut call = EndpointCall::from_http_request(request, route);
        let mut outer = call.clone();
        let mut patch = EndpointContextPatch::default();
        let mut headers = Headers::new();
        for hook in &self.endpoint_hooks {
            let matches = with_endpoint_call_context(call.clone(), async { hook.matches_before(&call, context) }).await.map_err(|error| {
                tracing::error!(%error, "Endpoint before-hook matcher failed");
                AuthError::Api { status: 500, code: None, message: "An error occurred during hook matcher execution. Check the logs for more details.".into() }
            })?;
            if !matches {
                continue;
            }
            let middleware = call.middleware_context();
            let action =
                with_endpoint_call_context(call.clone(), hook.before(&middleware, context)).await;
            let emitted = call.take_response_headers();
            let action = match action {
                Ok(action) => action,
                Err(error) if is_endpoint_api_error(&error) => {
                    let mut response = error.to_auth_response();
                    merge_headers(&mut response.headers, emitted);
                    return Ok(Some(response));
                }
                Err(error) => return Err(ordinary_http_hook_error(error)),
            };
            let hook_headers = emitted.clone();
            merge_headers(&mut headers, emitted);
            match action {
                Some(BeforeEndpointAction::Patch(changes)) => patch.merge(*changes),
                Some(BeforeEndpointAction::Respond(mut response)) => {
                    response.merge_headers(headers);
                    return render_http_endpoint_response(&response).map(Some);
                }
                Some(BeforeEndpointAction::Reject(mut response)) => {
                    response.merge_headers(hook_headers);
                    return render_http_endpoint_response(&response).map(Some);
                }
                None => {}
            }
        }
        let header_patch = patch.headers.clone();
        patch.apply(&mut call);
        EndpointContextPatch {
            headers: call.headers().cloned(),
            ..Default::default()
        }
        .apply(&mut outer);
        for (name, value) in headers {
            request.queue_response_header(name, value);
        }
        request.extensions().insert(HttpEndpointFrame {
            call,
            outer,
            header_patch,
            legacy_headers: None,
            error: Arc::default(),
        });
        Ok(None)
    }

    pub(super) async fn after_http_endpoint(
        &self,
        request: &alibi_core::AuthRequest,
        context: &alibi_core::AuthContext<S>,
        mut response: alibi_core::AuthResponse,
    ) -> alibi_core::AuthResult<alibi_core::AuthResponse> {
        let Some(frame) = request.extensions().get::<HttpEndpointFrame>() else {
            return Ok(response);
        };
        if let Some((user, session)) = request.session_hook_snapshot() {
            frame
                .call
                .record_authenticated_session(user.clone(), session.clone());
            frame.call.set_session_hook_snapshot(user, session);
        }
        let original =
            alibi_core::utils::json::from_slice::<alibi_core::utils::json::JsValue>(&response.body)
                .unwrap_or(alibi_core::utils::json::JsValue::Null);
        let mut logical = if let Some((status, code, message)) = frame
            .error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            EndpointResponse::error(AuthError::Api {
                status,
                code,
                message,
            })
            .with_error_body(original.clone())
        } else {
            EndpointResponse::value(original.clone()).with_status(response.status)
        };
        logical.merge_headers(std::mem::take(&mut response.headers));
        for hook in &self.endpoint_hooks {
            if !with_endpoint_call_context(frame.outer.clone(), async {
                hook.matches_after(&frame.call, context, &logical)
            })
            .await
            .map_err(|error| {
                if is_endpoint_api_error(&error) {
                    error
                } else {
                    ordinary_http_hook_error(error)
                }
            })? {
                continue;
            }
            let middleware = frame.call.middleware_context();
            let prior_headers = logical.headers().clone();
            let status = logical.status();
            logical = match with_endpoint_call_context(
                frame.outer.clone(),
                hook.after(&middleware, context, logical),
            )
            .await
            {
                Ok(response) => response,
                Err(error) if is_endpoint_api_error(&error) => {
                    let mut response = EndpointResponse::error(error);
                    response.set_status(status);
                    response.merge_headers(prior_headers);
                    response
                }
                Err(error) => return Err(ordinary_http_hook_error(error)),
            };
            logical.merge_headers(frame.call.take_response_headers());
        }
        if matches!(logical.result(), Ok(value) if value == &original) {
            response.status = logical.status().unwrap_or(response.status);
            response.headers = logical.headers().clone();
            Ok(response)
        } else {
            render_http_endpoint_response(&logical)
        }
    }
}

pub(super) fn apply_http_endpoint_input(
    request: &mut alibi_core::AuthRequest,
) -> alibi_core::AuthResult<()> {
    let Some(frame) = request.extensions().get::<HttpEndpointFrame>() else {
        return Ok(());
    };
    let mut frame = (*frame).clone();
    if let Some(headers) = &frame.header_patch {
        request.headers.extend(headers.clone());
    }
    if let Some(headers) = &frame.legacy_headers {
        request.headers.extend(headers.clone());
    }
    frame.call.replace_headers(request.headers.clone());
    EndpointContextPatch {
        headers: Some(request.headers.clone()),
        ..Default::default()
    }
    .apply(&mut frame.outer);
    let call = &frame.call;
    if let Some(path) = call.path() {
        path.clone_into(&mut request.path);
    }
    if let Some(method) = call.method() {
        request.method = method.clone();
    }
    if let Some(body) = call.body() {
        request.body = Some(alibi_core::utils::json::to_vec(body)?);
        request
            .extensions()
            .insert(alibi_core::types::ParsedRequestBody::Value(body.clone()));
    }
    if let Some(alibi_core::utils::json::JsValue::Object(query)) = call.query() {
        request.set_query_pairs(query.iter().flat_map(|(name, value)| {
            let values = match value {
                alibi_core::utils::json::JsValue::Array(values) => values.clone(),
                value => vec![value.clone()],
            };
            values.into_iter().map(|value| {
                (
                    name.clone(),
                    match value {
                        alibi_core::utils::json::JsValue::String(value) => value,
                        value => alibi_core::utils::json::to_string(&value).unwrap_or_default(),
                    },
                )
            })
        }));
    }
    request.extensions().insert(frame);
    Ok(())
}

fn ordinary_http_hook_error(error: AuthError) -> AuthError {
    match error {
        AuthError::CallbackFailure(_) => error,
        error => AuthError::CallbackFailure(Box::new(error)),
    }
}

fn render_http_endpoint_response(
    response: &EndpointResponse,
) -> alibi_core::AuthResult<alibi_core::AuthResponse> {
    let mut rendered = match response.result() {
        Ok(value) => alibi_core::AuthResponse::json(response.status().unwrap_or(200), value)?,
        Err(error) => {
            let (status, code, message) = error.error_payload();
            let mut rendered = alibi_core::AuthResponse::json(
                status,
                &alibi_core::ErrorCodeMessageResponse { code, message },
            )?;
            if let Some(body) = response.error_body() {
                rendered.body = alibi_core::utils::json::to_vec(body)?;
            }
            rendered
        }
    };
    merge_headers(&mut rendered.headers, response.headers().clone());
    Ok(rendered)
}
