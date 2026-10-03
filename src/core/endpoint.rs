use super::BetterAuth;
use better_auth_core::endpoint::{
    BeforeEndpointAction, EndpointCall, EndpointContextPatch, EndpointError, EndpointHook,
    EndpointOptions, EndpointOutput, EndpointResponse, ServerEndpoint, is_endpoint_api_error,
    with_endpoint_call_context,
};
use better_auth_core::{AuthError, AuthSchema, Headers};

impl<S: AuthSchema> BetterAuth<S> {
    /// Dispatch a trusted operation through configured hooks and its installed plugin.
    ///
    /// Logical headers and input remain independent of an optional actual HTTP
    /// request. Only verified credentials or installed plugin code can establish
    /// a session. Plain exported plugin functions retain their direct-call behavior.
    ///
    /// # Errors
    /// Returns actual endpoint/API errors or ordinary application failures.
    pub async fn dispatch_endpoint<T>(
        &self,
        endpoint: ServerEndpoint<T>,
        options: EndpointOptions,
    ) -> Result<EndpointOutput<T>, EndpointError> {
        let plugin = self.get_plugin(endpoint.plugin()).ok_or_else(|| {
            AuthError::not_found(format!("Plugin {} is not installed", endpoint.plugin()))
        })?;
        let definition = plugin
            .server_endpoints()
            .into_iter()
            .find(|definition| definition.name == endpoint.name())
            .ok_or_else(|| {
                AuthError::not_found(format!(
                    "Trusted endpoint {} is not registered",
                    endpoint.name()
                ))
            })?;
        let (body, query) = endpoint.input();
        let call = EndpointCall::new(&definition, body, query, options);
        if let Some(request) = call.request() {
            request
                .extensions()
                .insert(self.context.config.advanced.ip_address.clone());
        }
        with_endpoint_call_context(call.clone(), self.dispatch_endpoint_inner(call, plugin)).await
    }

    async fn dispatch_endpoint_inner<T>(
        &self,
        mut call: EndpointCall,
        plugin: &dyn better_auth_core::AuthPlugin<S>,
    ) -> Result<EndpointOutput<T>, EndpointError> {
        let hooks: Vec<&dyn EndpointHook<S>> = self
            .endpoint_hooks
            .iter()
            .map(AsRef::as_ref)
            .chain(
                self.plugins
                    .iter()
                    .flat_map(|plugin| plugin.endpoint_hooks()),
            )
            .collect();
        let mut patch = EndpointContextPatch::default();
        let mut before_headers = Headers::new();
        let mut outer = call.clone();
        for hook in &hooks {
            let matched = with_endpoint_call_context(call.clone(), async { hook.matches_before(&call, &self.context) }).await.map_err(|error| {
                tracing::error!(%error, "Endpoint before-hook matcher failed");
                AuthError::Api { status: 500, code: None, message: "An error occurred during hook matcher execution. Check the logs for more details.".into() }
            })?;
            if !matched {
                continue;
            }
            let middleware = call.middleware_context();
            let action =
                with_endpoint_call_context(call.clone(), hook.before(&middleware, &self.context))
                    .await;
            let headers = call.take_response_headers();
            let action = action.map_err(|error| EndpointError {
                body: None,
                headers: if is_endpoint_api_error(&error) {
                    Some(headers.clone())
                } else {
                    None
                },
                error,
            })?;
            let hook_headers = headers.clone();
            merge_headers(&mut before_headers, headers);
            match action {
                Some(BeforeEndpointAction::Patch(changes)) => patch.merge(*changes),
                Some(BeforeEndpointAction::Respond(mut response)) => {
                    response.merge_headers(before_headers);
                    return response.into_output();
                }
                Some(BeforeEndpointAction::Reject(mut response)) => {
                    response.merge_headers(hook_headers);
                    return response.into_output();
                }
                None => {}
            }
        }
        patch.apply(&mut call);
        // Source retains the original outer frame for hook task-local access.
        // Header patches update (or initialize) its Headers property in place;
        // other patched input and the optional Request belong to the active argument.
        EndpointContextPatch {
            headers: call.headers().cloned(),
            ..Default::default()
        }
        .apply(&mut outer);
        if let Some(request) = call.request() {
            request
                .extensions()
                .insert(self.context.config.advanced.ip_address.clone());
        }
        let response = match with_endpoint_call_context(call.clone(), async {
            plugin.validate_endpoint(&call, &self.context)
        })
        .await
        {
            Ok(input) => {
                let handler = call.handler_context(input.body, input.query);
                with_endpoint_call_context(
                    handler.clone(),
                    plugin.on_endpoint(&handler, &self.context),
                )
                .await
            }
            Err(error) => Err(error),
        };
        let mut response = match response {
            Ok(response) => response,
            Err(error) if is_endpoint_api_error(&error) => EndpointResponse::error(error),
            Err(error) => return Err(error.into()),
        };
        response.merge_headers(call.take_response_headers());
        let (cache_headers, ordinary_error) =
            better_auth_core::cache::runtime::take_issuance(call.extensions());
        if ordinary_error {
            return Err(AuthError::internal("Session cookie publication failed").into());
        }
        for header in cache_headers {
            response = response.with_header("set-cookie", header);
        }
        for hook in hooks {
            if !with_endpoint_call_context(outer.clone(), async {
                hook.matches_after(&call, &self.context, &response)
            })
            .await?
            {
                continue;
            }
            let middleware = call.middleware_context();
            // A throwing API after-hook replaces the value but keeps the handler's
            // actual status and accumulated headers; ordinary failures escape.
            let previous_headers = response.headers().clone();
            let previous_status = response.status();
            response = match with_endpoint_call_context(
                outer.clone(),
                hook.after(&middleware, &self.context, response),
            )
            .await
            {
                Ok(response) => response,
                Err(error) if is_endpoint_api_error(&error) => {
                    let mut response = EndpointResponse::error(error);
                    response.set_status(previous_status);
                    response.merge_headers(previous_headers);
                    response
                }
                Err(error) => return Err(error.into()),
            };
            response.merge_headers(call.take_response_headers());
        }
        response.into_output()
    }
}

fn merge_headers(target: &mut Headers, headers: Headers) {
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("set-cookie") {
            target.append(name, value);
        } else {
            drop(target.insert(name, value));
        }
    }
}

/// Frames retained by the real HTTP endpoint pipeline for configured hooks.
#[derive(Clone)]
pub(super) struct HttpEndpointFrame {
    pub call: EndpointCall,
    pub outer: EndpointCall,
}

impl<S: AuthSchema> BetterAuth<S> {
    pub(super) async fn before_http_endpoint(
        &self,
        request: &mut better_auth_core::AuthRequest,
        route: &better_auth_core::AuthRoute,
        context: &better_auth_core::AuthContext<S>,
    ) -> better_auth_core::AuthResult<Option<better_auth_core::AuthResponse>> {
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
                    return render_http_endpoint_response(response).map(Some);
                }
                Some(BeforeEndpointAction::Reject(mut response)) => {
                    response.merge_headers(hook_headers);
                    return render_http_endpoint_response(response).map(Some);
                }
                None => {}
            }
        }
        patch.apply(&mut call);
        EndpointContextPatch {
            headers: call.headers().cloned(),
            ..Default::default()
        }
        .apply(&mut outer);
        for (name, value) in headers {
            request.queue_response_header(name, value);
        }
        request
            .extensions()
            .insert(HttpEndpointFrame { call, outer });
        Ok(None)
    }

    pub(super) fn apply_http_endpoint_input(
        &self,
        request: &mut better_auth_core::AuthRequest,
    ) -> better_auth_core::AuthResult<()> {
        let Some(frame) = request.extensions().get::<HttpEndpointFrame>() else { return Ok(()); };
        let call = &frame.call;
        request.headers = call.headers().cloned().unwrap_or_default();
        if let Some(path) = call.path() {
            request.path = path.to_owned();
        }
        if let Some(method) = call.method() {
            request.method = method.clone();
        }
        if let Some(body) = call.body() {
            request.body = Some(better_auth_core::utils::json::to_vec(body)?);
            request
                .extensions()
                .insert(better_auth_core::types::ParsedRequestBody::Value(
                    body.clone(),
                ));
        }
        if let Some(better_auth_core::utils::json::JsValue::Object(query)) = call.query() {
            request.set_query_pairs(query.iter().flat_map(|(name, value)| {
                let values = match value {
                    better_auth_core::utils::json::JsValue::Array(values) => values.clone(),
                    value => vec![value.clone()],
                };
                values.into_iter().map(|value| {
                    (
                        name.clone(),
                        match value {
                            better_auth_core::utils::json::JsValue::String(value) => value,
                            value => {
                                better_auth_core::utils::json::to_string(&value).unwrap_or_default()
                            }
                        },
                    )
                })
            }));
        }
        Ok(())
    }

    pub(super) async fn after_http_endpoint(
        &self,
        request: &better_auth_core::AuthRequest,
        context: &better_auth_core::AuthContext<S>,
        mut response: better_auth_core::AuthResponse,
    ) -> better_auth_core::AuthResult<better_auth_core::AuthResponse> {
        let Some(frame) = request.extensions().get::<HttpEndpointFrame>() else {
            return Ok(response);
        };
        if let Some((user, session)) = request.session_hook_snapshot() {
            frame
                .call
                .record_authenticated_session(user.clone(), session.clone());
            frame.call.set_session_hook_snapshot(user, session);
        }
        let original = better_auth_core::utils::json::from_slice::<
            better_auth_core::utils::json::JsValue,
        >(&response.body)
        .unwrap_or(better_auth_core::utils::json::JsValue::Null);
        let mut logical = EndpointResponse::value(original.clone()).with_status(response.status);
        logical.merge_headers(std::mem::take(&mut response.headers));
        for hook in &self.endpoint_hooks {
            if !with_endpoint_call_context(frame.outer.clone(), async {
                hook.matches_after(&frame.call, context, &logical)
            })
            .await
            .map_err(ordinary_http_hook_error)?
            {
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
            render_http_endpoint_response(logical)
        }
    }
}

fn ordinary_http_hook_error(error: AuthError) -> AuthError {
    match error {
        AuthError::CallbackFailure(_) => error,
        error => AuthError::CallbackFailure(Box::new(error)),
    }
}

fn render_http_endpoint_response(
    response: EndpointResponse,
) -> better_auth_core::AuthResult<better_auth_core::AuthResponse> {
    let mut rendered = match response.result() {
        Ok(value) => better_auth_core::AuthResponse::json(response.status().unwrap_or(200), value)?,
        Err(error) => {
            let (status, code, message) = error.error_payload();
            let mut rendered = better_auth_core::AuthResponse::json(
                status,
                &better_auth_core::ErrorCodeMessageResponse { code, message },
            )?;
            if let Some(body) = response.error_body() {
                rendered.body = better_auth_core::utils::json::to_vec(body)?;
            }
            rendered
        }
    };
    merge_headers(&mut rendered.headers, response.headers().clone());
    Ok(rendered)
}
