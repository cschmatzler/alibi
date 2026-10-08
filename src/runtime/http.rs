use super::*;
impl<S: AuthSchema> BetterAuth<S> {
    /// Handle an authentication request.
    ///
    /// Errors from plugins and core handlers are automatically converted
    /// into standardized JSON responses via [`AuthError::to_auth_response`],
    /// producing `{ "message": "..." }` with the appropriate HTTP status code.
    ///
    /// This future is owned by the caller: dropping or aborting it cancels
    /// unfinished dispatch without rolling back already committed writes.
    /// Independently owned background callbacks already launched can continue.
    /// Hosts that require continuation after disconnect must retain the future
    /// in an owned task. Dropping a Tokio task's `JoinHandle` does not cancel it.
    /// The Axum integration already supervises fully buffered requests this way.
    ///
    /// # Errors
    ///
    /// Propagates errors from after-response middleware and ordinary endpoint
    /// failures when `AuthConfig::throw_api_errors` is enabled. Explicit API errors
    /// retain their HTTP responses.
    pub async fn handle_request(&self, req: AuthRequest) -> AuthResult<AuthResponse> {
        // Incoming callers cannot carry trusted dispatch state into this instance.
        let mut req = fresh_http_request(req);
        req.extensions()
            .insert(self.config.advanced.ip_address.clone());

        let context = match self.config.resolve_request(&req).await {
            Ok(config) => AuthContext {
                config: Arc::new(config),
                database: Arc::clone(&self.context.database),
                email_provider: self.context.email_provider.clone(),
                metadata: self.context.metadata.clone(),
                extensions: self.context.extensions.clone(),
            },
            Err(AuthError::Config(_)) if self.config.dynamic_base_url.is_some() => {
                // Authority resolution fails outside the API router in the pinned host.
                return Ok(AuthResponse::text(500, "Something went wrong!"));
            }
            Err(error) => return Ok(error.to_auth_response()),
        };
        // Source resolves request-local configuration before physical HTTP hooks.
        // Replacements change routing, but do not resolve origins/providers again.
        if let Some(response) = self.prepare_http_request(&mut req, &context).await? {
            return middleware::run_after(&self.transport_middlewares, &req, response).await;
        }
        let request_context = RequestHookContext::from_request(&req);
        alibi_core::endpoint::without_endpoint_call_context(with_request_hook_context_value(
            request_context,
            async {
                let mut run_after_hooks = false;
                let mut ordinary_handler_error = false;
                // Keep the public request future bounded while scoped context
                // and route-specific authentication retain their actual state.
                let mut response = match Box::pin(self.handle_request_inner(
                    &mut req,
                    &mut run_after_hooks,
                    &context,
                ))
                .await
                {
                    Ok(response) => response,
                    Err(err) => {
                        if context.config.throw_api_errors
                            && !alibi_core::endpoint::is_endpoint_api_error(&err)
                        {
                            return Err(match err {
                                AuthError::CallbackFailure(cause) => *cause,
                                error => error,
                            });
                        }
                        if matches!(err, AuthError::CallbackFailure(_)) {
                            run_after_hooks = false;
                            ordinary_handler_error = true;
                        }
                        err.to_auth_response()
                    }
                };
                let (mut cache_headers, mut ordinary_cache_error) =
                    alibi_core::session::cookie_cache::runtime::take_issuance(req.extensions());
                // HTTP handlers publish into their logical frame; legacy paths
                // retain the physical request accumulator. Drain both owners.
                if let Some(frame) = req
                    .extensions()
                    .get::<super::http_hooks::HttpEndpointFrame>()
                {
                    let (headers, ordinary_error) =
                        alibi_core::session::cookie_cache::runtime::take_issuance(
                            frame.call.extensions(),
                        );
                    cache_headers.extend(headers);
                    ordinary_cache_error |= ordinary_error;
                }
                if ordinary_handler_error || ordinary_cache_error {
                    run_after_hooks = false;
                    response = AuthResponse::new(500);
                    // Ordinary exceptions escape upstream dispatch before its header
                    // accumulator is published. Committed writes remain untouched.
                    drop(req.take_response_headers());
                    cache_headers.clear();
                }
                if alibi_api::plugins::oauth_proxy::take_unhandled_error(&req) {
                    run_after_hooks = false;
                }
                let mut nested_headers = req.take_response_headers();
                for (name, value) in response.headers {
                    if name.eq_ignore_ascii_case("set-cookie") {
                        nested_headers.append(name, value);
                    } else {
                        drop(nested_headers.insert(name, value));
                    }
                }
                for header in cache_headers {
                    nested_headers.append("Set-Cookie", header);
                }
                response.headers = nested_headers;
                let mut hook_request = req.clone();
                let base_path = &self.config.base_path;
                if !base_path.is_empty() && base_path != "/" {
                    hook_request.path = req
                        .path()
                        .strip_prefix(base_path)
                        .unwrap_or_else(|| req.path())
                        .to_owned();
                }
                if let Some(frame) = req
                    .extensions()
                    .get::<super::http_hooks::HttpEndpointFrame>()
                {
                    if let Some(path) = frame.call.path() {
                        hook_request.path = path.to_owned();
                    }
                    if let Some(method) = frame.call.method() {
                        hook_request.method = method.clone();
                    }
                }
                if run_after_hooks {
                    response = match self
                        .after_http_endpoint(&hook_request, &context, response)
                        .await
                    {
                        Ok(response) => response,
                        Err(error) => {
                            if context.config.throw_api_errors
                                && !alibi_core::endpoint::is_endpoint_api_error(&error)
                            {
                                return Err(match error {
                                    AuthError::CallbackFailure(cause) => *cause,
                                    error => error,
                                });
                            }
                            run_after_hooks = false;
                            drop(req.take_response_headers());
                            error.to_auth_response()
                        }
                    };
                }
                for plugin in self.plugins.iter().filter(|_| run_after_hooks) {
                    let accumulated_headers = response.headers.clone();
                    response = match plugin
                        .after_request(&hook_request, &context, response)
                        .await
                    {
                        Ok(response) => response,
                        Err(error @ AuthError::CallbackFailure(_)) => {
                            if context.config.throw_api_errors {
                                return Err(match error {
                                    AuthError::CallbackFailure(cause) => *cause,
                                    error => error,
                                });
                            }
                            // An ordinary application exception aborts completed hooks.
                            // Source drops accumulated headers, including already-issued
                            // cookies, while preserving the committed authentication writes.
                            response = error.to_auth_response();
                            break;
                        }
                        Err(error) => {
                            let mut response_2 = error.to_auth_response();
                            for (name, value) in accumulated_headers {
                                if name.eq_ignore_ascii_case("set-cookie") {
                                    response_2.headers.append(name, value);
                                } else if !response_2.headers.contains_key(&name) {
                                    drop(response_2.headers.insert(name, value));
                                }
                            }
                            response_2
                        }
                    };
                    for (name, value) in req.take_response_headers() {
                        if name.eq_ignore_ascii_case("set-cookie") {
                            response.headers.append(name, value);
                        } else {
                            drop(response.headers.insert(name, value));
                        }
                    }
                }
                let mut response = middleware::run_after(&self.middlewares, &req, response).await?;
                for plugin in &self.plugins {
                    if let Some(replacement) =
                        plugin.on_http_response(&req, &context, &response).await?
                    {
                        response = replacement;
                        break;
                    }
                }
                let response = self.cors.after_request(&req, response).await?;
                middleware::run_after(&self.transport_middlewares, &req, response).await
            },
        ))
        .await
    }

    pub(in crate::runtime) async fn prepare_http_request(
        &self,
        req: &mut AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let base_path = self.config.base_path.trim_end_matches('/');
        let requested_path = req
            .path()
            .strip_prefix(base_path)
            .filter(|suffix| suffix.starts_with('/'))
            .unwrap_or_else(|| req.path());
        let disabled_path = requested_path.trim_end_matches('/');
        if self.config.is_path_disabled(disabled_path) {
            let mut response =
                AuthResponse::new(404).with_header("content-type", "text/plain;charset=utf-8");
            response.body = b"Not Found".to_vec();
            return Ok(Some(response));
        }

        // Run before-request middleware chain
        if let Some(response) = middleware::run_before(&self.transport_middlewares, req).await? {
            return Ok(Some(response));
        }

        for plugin in &self.plugins {
            if let Some(action) = plugin.on_http_request_action(req, context).await? {
                match action {
                    HttpRequestAction::Respond(response) => return Ok(Some(response)),
                    HttpRequestAction::ReplaceRequest(replacement) => {
                        *req = fresh_http_request(*replacement);
                        req.extensions()
                            .insert(context.config.advanced.ip_address.clone());
                    }
                }
            }
        }

        Ok(None)
    }

    /// Inner request handler that may return errors.
    pub(in crate::runtime) async fn handle_request_inner(
        &self,
        req: &mut AuthRequest,
        run_after_hooks: &mut bool,
        context: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        if let Some(response) = self.cors.before_request(req).await? {
            return Ok(response);
        }
        if let Some(response) = middleware::run_before(&self.middlewares, req).await? {
            return Ok(response);
        }

        // Strip base_path prefix from the request path for internal routing.
        // This happens BEFORE plugin hooks so that `before_request` sees the
        // same normalised path that `on_request` / core handlers use.
        // External callers send e.g. "/api/auth/sign-in/email"; internally
        // handlers match against "/sign-in/email".
        let base_path = &self.config.base_path;
        let stripped_path = if !base_path.is_empty() && base_path != "/" {
            req.path()
                .strip_prefix(base_path)
                .filter(|suffix| suffix.starts_with('/'))
                .unwrap_or_else(|| req.path())
        } else {
            req.path()
        };

        // Build a request with the stripped path for all subsequent dispatch
        let mut internal_req = if stripped_path == req.path() {
            req.clone()
        } else {
            let mut r = req.clone();
            stripped_path.clone_into(&mut r.path);
            r
        };

        if self.config.advanced.skip_trailing_slashes {
            internal_req.path = internal_req.path.trim_end_matches('/').to_owned();
        }

        // The pinned router resolves the endpoint before dispatching hooks.
        // An unknown path or method cannot trigger authentication side effects.
        let core_route = matches!(
            (internal_req.method(), internal_req.path()),
            (HttpMethod::Get, core_paths::OK | core_paths::ERROR)
                | (HttpMethod::Post, core_paths::UPDATE_USER)
        );
        let plugin_route = self.plugins.iter().find_map(|plugin| {
            plugin
                .routes()
                .into_iter()
                .find(|route| {
                    route.method == internal_req.method
                        && !self.openapi.is_server_only(plugin.name(), route)
                        && route_path_matches(&route.path, internal_req.path())
                })
                .map(|route| (plugin, route))
        });
        if (!core_route && plugin_route.is_none()) || internal_req.path().contains("//") {
            return Ok(AuthResponse::new(404));
        }
        let allowed_media_types = plugin_route.as_ref().map_or_else(
            || vec!["application/json"],
            |(plugin, route)| plugin.allowed_media_types(route),
        );
        parse_dispatch_body(&internal_req, &allowed_media_types).await?;
        self.request_protection
            .with_auth_config(Arc::clone(&context.config))
            .check_request_origin(&internal_req)?;

        let context_path = plugin_route
            .as_ref()
            .map(|(_, route)| route.context_path.as_deref().unwrap_or(&route.path))
            .unwrap_or_else(|| internal_req.path())
            .to_owned();
        let params = context_path
            .split('/')
            .zip(internal_req.path().split('/'))
            .filter_map(|(part, value)| {
                let name = part.strip_prefix(':').or_else(|| {
                    part.strip_prefix('{')
                        .and_then(|name| name.strip_suffix('}'))
                })?;
                Some((name.to_owned(), value.to_owned()))
            })
            .collect();
        internal_req
            .extensions()
            .insert(alibi_core::plugin::ResolvedEndpoint {
                path: context_path,
                params,
            });

        let global_route = plugin_route
            .as_ref()
            .map(|(_, route)| route.clone())
            .unwrap_or_else(|| {
                AuthRoute::new(
                    internal_req.method.clone(),
                    internal_req.path.clone(),
                    match internal_req.path() {
                        core_paths::OK => "ok",
                        core_paths::ERROR => "error",
                        _ => "updateUser",
                    },
                )
            });
        if let Some(response) = self
            .before_http_endpoint(&mut internal_req, &global_route, context)
            .await?
        {
            return Ok(response);
        }
        if let Some(frame) = internal_req
            .extensions()
            .get::<super::http_hooks::HttpEndpointFrame>()
        {
            req.extensions().insert((*frame).clone());
        }

        // Run plugin before_request hooks (e.g. API-key → session emulation)
        // Plugins now see the normalised (base_path-stripped) path.
        for plugin in &self.plugins {
            if let Some(action) = plugin.before_request(&internal_req, context).await? {
                match action {
                    BeforeRequestAction::Respond(response) => {
                        return Ok(response);
                    }
                    BeforeRequestAction::InjectSession { session } => {
                        // Completed-response hooks must retain the authenticated
                        // context established by before hooks.
                        req.set_virtual_session(session.clone());
                        internal_req.set_virtual_session(session);
                    }
                    BeforeRequestAction::ReplaceHeaders { headers } => {
                        if let Some(frame) = internal_req
                            .extensions()
                            .get::<super::http_hooks::HttpEndpointFrame>()
                        {
                            let mut frame = (*frame).clone();
                            frame.legacy_headers = Some(headers.clone());
                            internal_req.extensions().insert(frame);
                        }
                        req.headers.clone_from(&headers);
                        internal_req.headers = headers;
                    }
                }
            }
        }

        // Source accumulates returned context patches until all before hooks finish.
        self.apply_http_endpoint_input(&mut internal_req)?;
        req.headers.clone_from(&internal_req.headers);
        req.body.clone_from(&internal_req.body);
        req.set_query_pairs(internal_req.query.keys().flat_map(|name| {
            internal_req
                .query_values(name)
                .into_iter()
                .flatten()
                .map(|value| (name.clone(), value.clone()))
        }));

        // A before-hook response or rejection returns immediately upstream.
        // Only endpoint dispatch reaches the completed-response hook pipeline.
        *run_after_hooks = true;

        let handler = async {
            if let Some(response) = self.handle_core_request(&internal_req, context).await? {
                return Ok(response);
            }
            // Only the resolved installed HTTP endpoint can receive the call.
            if let Some((plugin, _route)) = plugin_route
                && let Some(response) = plugin
                    .on_http_endpoint(&internal_req, context)
                    .await
                    .map_err(|error| {
                        if alibi_core::endpoint::is_endpoint_api_error(&error)
                            || matches!(
                                error,
                                AuthError::CallbackFailure(_) | AuthError::Encryption(_)
                            )
                        {
                            error
                        } else {
                            AuthError::CallbackFailure(Box::new(error))
                        }
                    })?
            {
                return match response {
                    HttpEndpointResponse::Value(response) => Ok(response),
                    HttpEndpointResponse::Raw(response) => {
                        *run_after_hooks = false;
                        // A raw endpoint response bypasses the dispatch accumulator.
                        drop(internal_req.take_response_headers());
                        drop(alibi_core::session::cookie_cache::runtime::take_issuance(
                            internal_req.extensions(),
                        ));
                        if let Some(frame) = internal_req
                            .extensions()
                            .get::<super::http_hooks::HttpEndpointFrame>()
                        {
                            drop(alibi_core::session::cookie_cache::runtime::take_issuance(
                                frame.call.extensions(),
                            ));
                        }
                        Ok(response)
                    }
                };
            }
            Err(AuthError::not_found("No handler found for this request"))
        };
        if let Some(frame) = internal_req
            .extensions()
            .get::<super::http_hooks::HttpEndpointFrame>()
        {
            let result = alibi_core::endpoint::with_endpoint_call_context(
                frame.call.clone(),
                Box::pin(handler),
            )
            .await;
            if let Err(error) = &result
                && alibi_core::endpoint::is_endpoint_api_error(error)
            {
                *frame
                    .error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(error.error_payload());
            }
            result
        } else {
            handler.await
        }
    }
}

/// Retain only physical request data across public dispatch and HTTP replacements.
pub(in crate::runtime) fn fresh_http_request(request: AuthRequest) -> AuthRequest {
    let query_pairs = request
        .query
        .keys()
        .flat_map(|name| {
            request
                .query_values(name)
                .into_iter()
                .flatten()
                .map(|value| (name.clone(), value.clone()))
        })
        .collect::<Vec<_>>();
    let url = request.url().cloned();
    let mut fresh = AuthRequest::from_parts(
        request.method,
        request.path,
        request.headers,
        request.body,
        request.query,
    );
    if let Some(url) = url {
        fresh = fresh.with_url(url);
    }
    fresh.set_query_pairs(query_pairs);
    fresh
}
