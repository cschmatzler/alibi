use alibi_core::endpoint::{
    BeforeEndpointAction, EndpointCall, EndpointContextPatch, EndpointHook, EndpointResponse,
    is_endpoint_api_error, with_endpoint_call_context,
};
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, Headers};

#[derive(Clone, Copy)]
pub(super) enum HookTransport {
    Direct,
    Http,
}

impl HookTransport {
    async fn scope<T>(self, call: EndpointCall, future: impl Future<Output = T>) -> T {
        match self {
            Self::Direct => Box::pin(with_endpoint_call_context(call, future)).await,
            Self::Http => with_http_endpoint_call_context(call, future).await,
        }
    }
}

/// HTTP callbacks keep live dispatch state separate from a frame's owned
/// optional Request. Storing that physical context in the frame itself would
/// make its extension map own itself through `HttpEndpointFrame`.
pub(super) fn with_http_endpoint_call_context<T>(
    call: EndpointCall,
    future: impl Future<Output = T>,
) -> impl Future<Output = T> {
    let request = alibi_core::hooks::current_request_hook_context().map(|current| {
        let Some(request) = call.request() else {
            return current;
        };
        let mut scope = alibi_core::hooks::RequestHookContext::from_request(request);
        scope.extensions = current.extensions;
        scope
    });
    // Bound the HTTP dispatch future without increasing callers' stack sizes.
    Box::pin(with_endpoint_call_context(
        call,
        alibi_core::hooks::with_optional_request_hook_context(request, future),
    ))
}

pub(super) enum BeforeHooks {
    Continue {
        patch: Box<EndpointContextPatch>,
        headers: Headers,
    },
    Respond(EndpointResponse),
}

pub(super) struct BeforeHookFailure {
    pub error: AuthError,
    pub headers: Option<Headers>,
}

pub(super) async fn run_before<S: AuthSchema>(
    hooks: &[&dyn EndpointHook<S>],
    call: &EndpointCall,
    context: &AuthContext<S>,
    transport: HookTransport,
) -> Result<BeforeHooks, BeforeHookFailure> {
    let mut patch = EndpointContextPatch::default();
    let mut headers = Headers::new();
    for hook in hooks {
        let matched = transport
            .scope(call.clone(), async { hook.matches_before(call, context) })
            .await
            .map_err(|error| {
                tracing::error!(%error, "Endpoint before-hook matcher failed");
                BeforeHookFailure {
                    error: AuthError::Api {
                        status: 500,
                        code: None,
                        message: "An error occurred during hook matcher execution. Check the logs for more details.".into(),
                    },
                    headers: None,
                }
            })?;
        if !matched {
            continue;
        }
        let middleware = call.middleware_context();
        let action = transport
            .scope(call.clone(), hook.before(&middleware, context))
            .await;
        let emitted = call.take_response_headers();
        match action {
            Ok(Some(BeforeEndpointAction::Patch(changes))) => patch.merge(*changes),
            Ok(Some(BeforeEndpointAction::Respond(mut response))) => {
                headers.merge(emitted);
                response.merge_headers(headers);
                return Ok(BeforeHooks::Respond(response));
            }
            Ok(Some(BeforeEndpointAction::Reject(mut response))) => {
                response.merge_headers(emitted);
                return Ok(BeforeHooks::Respond(response));
            }
            Ok(None) => {}
            Err(error) => {
                return Err(BeforeHookFailure {
                    headers: is_endpoint_api_error(&error).then_some(emitted),
                    error,
                });
            }
        }
        headers.merge(emitted);
    }
    Ok(BeforeHooks::Continue {
        patch: Box::new(patch),
        headers,
    })
}

/// Better Auth keeps the outer task-local frame and updates only its headers.
pub(super) fn update_outer_headers(outer: &mut EndpointCall, call: &EndpointCall) {
    EndpointContextPatch {
        headers: call.headers().cloned(),
        ..Default::default()
    }
    .apply(outer);
}

pub(super) async fn run_after<S: AuthSchema>(
    hooks: &[&dyn EndpointHook<S>],
    call: &EndpointCall,
    outer: &EndpointCall,
    context: &AuthContext<S>,
    mut response: EndpointResponse,
    transport: HookTransport,
) -> AuthResult<EndpointResponse> {
    for hook in hooks {
        if !transport
            .scope(outer.clone(), async {
                hook.matches_after(call, context, &response)
            })
            .await?
        {
            continue;
        }
        let middleware = call.middleware_context();
        let previous_headers = response.headers().clone();
        let previous_status = response.status();
        response = match transport
            .scope(outer.clone(), hook.after(&middleware, context, response))
            .await
        {
            Ok(response) => response,
            Err(error) if is_endpoint_api_error(&error) => {
                let mut response = EndpointResponse::error(error);
                response.set_status(previous_status);
                response.merge_headers(previous_headers);
                response
            }
            Err(error) => return Err(error),
        };
        response.merge_headers(call.take_response_headers());
    }
    Ok(response)
}
