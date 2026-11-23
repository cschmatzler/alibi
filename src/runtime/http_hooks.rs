use super::Alibi;
use super::endpoint_hooks::{self, BeforeHooks, HookTransport};
use alibi_core::endpoint::{EndpointCall, EndpointResponse, is_endpoint_api_error};
use alibi_core::{AuthError, AuthSchema, Headers};
use std::sync::Arc;

type HttpEndpointError = (u16, Option<String>, String);

/// Frames retained by the real HTTP endpoint pipeline for configured hooks.
#[derive(Clone)]
pub(super) struct HttpEndpointFrame {
    pub call: EndpointCall,
    pub outer: EndpointCall,
    pub path_patch: Option<String>,
    pub body_patch: bool,
    pub header_patch: Option<std::collections::HashMap<String, String>>,
    pub legacy_headers: Option<std::collections::HashMap<String, String>>,
    pub error: Arc<std::sync::Mutex<Option<HttpEndpointError>>>,
    pub returned_response: Arc<std::sync::Mutex<Option<alibi_core::AuthResponse>>>,
}

impl<S: AuthSchema> Alibi<S> {
    pub(super) async fn before_http_endpoint(
        &self,
        request: &mut alibi_core::AuthRequest,
        route: &alibi_core::AuthRoute,
        context: &alibi_core::AuthContext<S>,
    ) -> alibi_core::AuthResult<Option<alibi_core::AuthResponse>> {
        // Retain the logical frame even without application endpoint hooks:
        // handlers publish renewed session cookies into this frame's extensions.
        let mut call = EndpointCall::from_http_request(request, route);
        call.extensions().insert((*context.config).clone());
        let mut outer = call.clone();
        let hooks: Vec<&dyn alibi_core::endpoint::EndpointHook<S>> =
            self.endpoint_hooks.iter().map(AsRef::as_ref).collect();
        let (patch, headers) = match Box::pin(endpoint_hooks::run_before(
            &hooks,
            &call,
            context,
            HookTransport::Http,
        ))
        .await
        {
            Ok(BeforeHooks::Continue { patch, headers }) => (patch, headers),
            Ok(BeforeHooks::Respond(response)) => {
                return render_http_endpoint_response(&response).map(Some);
            }
            Err(failure) => {
                if let Some(mut headers) = failure.headers {
                    // Explicit error headers override accumulated ones.
                    let mut response = failure.error.to_auth_response();
                    headers.merge(std::mem::take(&mut response.headers));
                    response.headers = headers;
                    return Ok(Some(response));
                }
                return Err(http_hook_error(failure.error));
            }
        };
        let path_patch = patch.path.clone();
        let body_patch = patch.body.is_some();
        let header_patch = patch.headers.clone();
        patch.apply(&mut call);
        endpoint_hooks::update_outer_headers(&mut outer, &call);
        for (name, value) in headers {
            request.queue_response_header(name, value);
        }
        request.extensions().insert(HttpEndpointFrame {
            call,
            outer,
            path_patch,
            body_patch,
            header_patch,
            legacy_headers: None,
            error: Arc::default(),
            returned_response: Arc::default(),
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
        let returned_response = frame
            .returned_response
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut logical = if let Some(raw) = returned_response.as_ref() {
            EndpointResponse::from_http_response(raw.clone())
        } else if let Some((status, code, message)) = frame
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
        let headers = std::mem::take(&mut response.headers);
        if let Some(raw) = returned_response.as_ref() {
            let mut metadata = Headers::new();
            for (name, value) in headers {
                if !raw.headers.iter().any(|(raw_name, raw_value)| {
                    raw_name.eq_ignore_ascii_case(&name) && raw_value == &value
                }) {
                    metadata.append(name, value);
                }
            }
            logical.merge_headers(metadata);
        } else {
            logical.merge_headers(headers);
        }
        let hooks: Vec<&dyn alibi_core::endpoint::EndpointHook<S>> =
            self.endpoint_hooks.iter().map(AsRef::as_ref).collect();
        let logical = Box::pin(endpoint_hooks::run_after(
            &hooks,
            &frame.call,
            &frame.outer,
            context,
            logical,
            HookTransport::Http,
        ))
        .await
        .map_err(http_hook_error)?;
        // Plugin HTTP response hooks run on the physical request, not the
        // logical frame where the handler completed its session publication.
        alibi_core::session::cookie_cache::runtime::retain_publication(&frame.call, request);
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
    endpoint_hooks::update_outer_headers(&mut frame.outer, &frame.call);
    let call = &frame.call;
    // Logical hook paths may be route templates; only explicit patches change dispatch input.
    if let Some(path) = &frame.path_patch {
        path.clone_into(&mut request.path);
    }
    if let Some(method) = call.method() {
        request.method = method.clone();
    }
    if frame.body_patch
        && let Some(body) = call.body()
    {
        request.body = Some(alibi_core::utils::json::to_vec(body)?);
        request
            .extensions()
            .insert(alibi_core::types::ParsedRequestBody::Value(body.clone()));
    }
    if let Some(alibi_core::utils::json::JsValue::Object(query)) = call.query() {
        let mut pairs = Vec::new();
        for (name, value) in query {
            let values = match value {
                alibi_core::utils::json::JsValue::Array(values) => values.as_slice(),
                value => std::slice::from_ref(value),
            };
            for value in values {
                let value = match value {
                    alibi_core::utils::json::JsValue::String(value) => {
                        value.require_str()?.to_owned()
                    }
                    value => alibi_core::utils::json::to_string(value)?,
                };
                pairs.push((name.require_str()?.to_owned(), value));
            }
        }
        request.set_query_pairs(pairs);
    }
    request.extensions().insert(frame);
    Ok(())
}

#[cfg(test)]
mod canonical_tests {
    use super::{HttpEndpointFrame, apply_http_endpoint_input};
    use alibi_core::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions};
    use alibi_core::utils::json::{JsObject, JsString, JsValue};
    use alibi_core::{AuthRequest, HttpMethod};
    use std::sync::{Arc, Mutex};

    fn request(query: JsObject) -> AuthRequest {
        let definition = EndpointDefinition {
            name: "canonical-query",
            operation_id: "canonicalQuery",
            path: Some("/query".into()),
            method: HttpMethod::Get,
        };
        let call = EndpointCall::new(
            &definition,
            None,
            Some(JsValue::Object(query)),
            EndpointOptions::default(),
        );
        let mut request = AuthRequest::new(HttpMethod::Get, "/query");
        request.set_query_pairs([("original", "retained")]);
        request.extensions().insert(HttpEndpointFrame {
            outer: call.clone(),
            call,
            path_patch: None,
            body_patch: false,
            header_patch: None,
            legacy_headers: None,
            error: Arc::new(Mutex::new(None)),
            returned_response: Arc::new(Mutex::new(None)),
        });
        request
    }

    #[test]
    fn canonical_query_mirror_retains_repeats_and_existing_json_projection() {
        let query = [
            (
                "tag".into(),
                JsValue::Array(vec![
                    JsValue::String("a".into()),
                    JsValue::String("b".into()),
                ]),
            ),
            ("unicode".into(), JsValue::String("é".into())),
            ("number".into(), JsValue::Number(42.0)),
            (
                "object".into(),
                JsValue::Object([("value".into(), JsValue::Bool(false))].into()),
            ),
        ]
        .into();
        let mut request = request(query);
        apply_http_endpoint_input(&mut request).unwrap();
        assert_eq!(request.query_values("tag").unwrap(), ["a", "b"]);
        assert_eq!(request.query.get("unicode").map(String::as_str), Some("é"));
        assert_eq!(request.query.get("number").map(String::as_str), Some("42"));
        assert_eq!(
            request.query.get("object").map(String::as_str),
            Some(r#"{"value":false}"#)
        );
        assert!(!request.query.contains_key("original"));
    }

    #[test]
    fn unsupported_query_projection_errors_without_empty_or_replacement_values() {
        for (name, value) in [
            (
                JsString::from_code_units(vec![0xd800]),
                JsValue::String("value".into()),
            ),
            (
                "name".into(),
                JsValue::String(JsString::from_code_units(vec![0xdfff])),
            ),
            ("name".into(), JsValue::Undefined),
        ] {
            let mut request = request(
                [
                    (
                        "preceding".into(),
                        JsValue::String("not partially written".into()),
                    ),
                    (name, value),
                ]
                .into(),
            );
            assert!(apply_http_endpoint_input(&mut request).is_err());
            assert_eq!(
                request.query,
                [("original".into(), "retained".into())].into()
            );
        }
    }
}

fn http_hook_error(error: AuthError) -> AuthError {
    if is_endpoint_api_error(&error) || matches!(error, AuthError::CallbackFailure(_)) {
        error
    } else {
        AuthError::CallbackFailure(Box::new(error))
    }
}

fn render_http_endpoint_response(
    response: &EndpointResponse,
) -> alibi_core::AuthResult<alibi_core::AuthResponse> {
    if response.result().is_ok() {
        return response.to_response();
    }
    let mut rendered = match response.result() {
        Ok(value) => alibi_core::AuthResponse::json(response.status().unwrap_or(200), value)?,
        Err(error) => {
            let (status, code, message) = error.error_payload();
            let mut rendered = alibi_core::AuthResponse::json(
                status,
                &alibi_core::ErrorCodeMessageResponse { code, message },
            )?;
            if response.error_body_is_absent() {
                rendered.body.clear();
            } else if let Some(body) = response.error_body() {
                rendered.body = alibi_core::utils::json::to_vec(body)?;
            }
            rendered
        }
    };
    rendered.headers.merge(response.headers().clone());
    Ok(rendered)
}
