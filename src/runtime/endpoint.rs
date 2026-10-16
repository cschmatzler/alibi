use super::Alibi;
use alibi_core::endpoint::{
    BeforeEndpointAction, EndpointCall, EndpointContextPatch, EndpointError, EndpointHook,
    EndpointOptions, EndpointOutput, EndpointResponse, ServerEndpoint, is_endpoint_api_error,
    with_endpoint_call_context,
};
use alibi_core::{AuthContext, AuthError, AuthRequest, AuthSchema, Headers, HttpMethod};
use std::sync::Arc;

const HOOK_MATCHER_FAILURE: &str =
    "An error occurred during hook matcher execution. Check the logs for more details.";

impl<S: AuthSchema> Alibi<S> {
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
        let builtin = alibi_plugins::user_management::BuiltinUserEndpoints;
        let plugin = self
            .get_plugin(endpoint.plugin())
            .or_else(|| {
                (endpoint.plugin() == "core").then_some(&builtin as &dyn alibi_core::AuthPlugin<S>)
            })
            .ok_or_else(|| {
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
        let params = endpoint.params().cloned();
        let (body, query) = endpoint.input();
        let mut call = EndpointCall::new(&definition, body, query, options);
        if let Some(params) = params {
            call = call.with_params_value(params);
        }
        if let Some(request) = call.request() {
            request
                .extensions()
                .insert(self.context.config.advanced.ip_address.clone());
        }
        let context = self.resolve_endpoint_context(&call).await?;
        with_endpoint_call_context(
            call.clone(),
            self.dispatch_endpoint_inner(call, plugin, context.as_ref().unwrap_or(&self.context)),
        )
        .await
    }

    async fn resolve_endpoint_context(
        &self,
        call: &EndpointCall,
    ) -> Result<Option<AuthContext<S>>, AuthError> {
        let Some(dynamic) = &self.config.dynamic_base_url else {
            return Ok(None);
        };
        // A real Request owns authority even when logical headers disagree.
        // Headers alone are a source only when they carry a host; they must not
        // become the endpoint's optional physical Request or confer credentials.
        let headers = call.headers().filter(|headers| {
            headers.contains_key("host") || headers.contains_key("x-forwarded-host")
        });
        let mut logical = AuthRequest::new(HttpMethod::Get, self.config.base_path.clone());
        if let Some(headers) = headers {
            logical.headers = headers.clone();
        }
        let source = call.request().or_else(|| headers.map(|_| &logical));
        if source.is_none() && dynamic.fallback.as_ref().is_none_or(String::is_empty) {
            return Err(AuthError::Api {
                status: 500,
                code: None,
                message: "Dynamic baseURL could not be resolved for this direct auth.api call. Pass `headers: request.headers` (or `request`) to the call, or add `fallback` to your baseURL config.".into(),
            });
        }
        let config = self
            .config
            .resolve_request(source.unwrap_or(&logical))
            .await
            .map_err(|error| match error {
                AuthError::Config(message) => AuthError::Api {
                    status: 500,
                    code: None,
                    message,
                },
                error => error,
            })?;
        let mut context = self.context.clone();
        context.config = Arc::new(config);
        Ok(Some(context))
    }

    async fn dispatch_endpoint_inner<T>(
        &self,
        mut call: EndpointCall,
        plugin: &dyn alibi_core::AuthPlugin<S>,
        context: &AuthContext<S>,
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
            let matched = with_endpoint_call_context(call.clone(), async {
                hook.matches_before(&call, context)
            })
            .await
            .map_err(|error| {
                tracing::error!(%error, "Endpoint before-hook matcher failed");
                AuthError::Api {
                    status: 500,
                    code: None,
                    message: HOOK_MATCHER_FAILURE.into(),
                }
            })?;
            if !matched {
                continue;
            }
            let middleware = call.middleware_context();
            let action =
                with_endpoint_call_context(call.clone(), hook.before(&middleware, context)).await;
            let headers = call.take_response_headers();
            let action = action.map_err(|error| EndpointError {
                body: None,
                body_absent: false,
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
            plugin.validate_endpoint(&call, context)
        })
        .await
        {
            Ok(input) => {
                let handler = call.handler_context(input.body, input.query);
                with_endpoint_call_context(handler.clone(), plugin.on_endpoint(&handler, context))
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
            alibi_core::session::cookie_cache::runtime::take_issuance(call.extensions());
        if ordinary_error {
            return Err(AuthError::internal("Session cookie publication failed").into());
        }
        for header in cache_headers {
            response = response.with_header("set-cookie", header);
        }
        for hook in hooks {
            if !with_endpoint_call_context(outer.clone(), async {
                hook.matches_after(&call, context, &response)
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
                hook.after(&middleware, context, response),
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

pub(super) fn merge_headers(target: &mut Headers, headers: Headers) {
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("set-cookie") {
            target.append(name, value);
        } else {
            _ = target.insert(name, value);
        }
    }
}
