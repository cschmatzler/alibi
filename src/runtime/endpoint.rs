use super::BetterAuth;
use alibi_core::endpoint::{
    BeforeEndpointAction, EndpointCall, EndpointContextPatch, EndpointError, EndpointHook,
    EndpointOptions, EndpointOutput, EndpointResponse, ServerEndpoint, is_endpoint_api_error,
    with_endpoint_call_context,
};
use alibi_core::{AuthError, AuthSchema, Headers};

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
        plugin: &dyn alibi_core::AuthPlugin<S>,
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
            alibi_core::session::cookie_cache::runtime::take_issuance(call.extensions());
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

pub(super) fn merge_headers(target: &mut Headers, headers: Headers) {
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("set-cookie") {
            target.append(name, value);
        } else {
            _ = target.insert(name, value);
        }
    }
}
