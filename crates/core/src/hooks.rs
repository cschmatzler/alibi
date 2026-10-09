use crate::types::{AuthRequest, HttpMethod, RequestExtensions, RequestMeta};

/// Request-derived data available to middleware, stores, and other hooks during request handling.
#[derive(Debug, Clone)]
pub struct RequestHookContext {
    /// Original native transport request, retained before endpoint transformations.
    pub request: AuthRequest,
    pub method: HttpMethod,
    pub path: String,
    /// Original transport URL, including the auth base path and query string.
    pub url: Option<url::Url>,
    pub headers: std::collections::HashMap<String, String>,
    pub query: std::collections::HashMap<String, String>,
    /// Original request body, available to application lifecycle callbacks.
    pub body: Option<Vec<u8>>,
    pub meta: RequestMeta,
    /// Typed request state shared with the trusted dispatch and its hooks.
    pub extensions: RequestExtensions,
}

impl RequestHookContext {
    /// Build a request hook context from an incoming auth request.
    #[must_use]
    pub fn from_request(request: &AuthRequest) -> Self {
        Self {
            request: request.clone(),
            method: request.method().clone(),
            path: request.path().to_owned(),
            url: request.url().cloned(),
            headers: request.headers.clone(),
            query: request.query.clone(),
            body: request.body.clone(),
            meta: RequestMeta::from_request(request),
            extensions: request.extensions().clone(),
        }
    }
}

tokio::task_local! {
    static REQUEST_HOOK_CONTEXT: Option<RequestHookContext>;
}

/// Run a future with request context available to downstream integrations.
pub async fn with_request_hook_context<T>(
    request: &AuthRequest,
    future: impl Future<Output = T>,
) -> T {
    with_request_hook_context_value(RequestHookContext::from_request(request), future).await
}

/// Run a future with an explicit request hook context.
pub async fn with_request_hook_context_value<T>(
    request_context: RequestHookContext,
    future: impl Future<Output = T>,
) -> T {
    with_optional_request_hook_context(Some(request_context), future).await
}

/// Scope an optional actual HTTP context, including absence for a trusted server call.
pub async fn with_optional_request_hook_context<T>(
    request_context: Option<RequestHookContext>,
    future: impl Future<Output = T>,
) -> T {
    REQUEST_HOOK_CONTEXT.scope(request_context, future).await
}

pub fn current_request_hook_context() -> Option<RequestHookContext> {
    REQUEST_HOOK_CONTEXT.try_with(Clone::clone).ok().flatten()
}

/// A trusted endpoint's parsed body for adapter callbacks. Completed response
/// callbacks still receive the original request body.
#[derive(Clone, Debug)]
pub struct ValidatedRequestBody(pub crate::utils::json::JsValue);

/// Request body after a plugin has transformed endpoint input. Original HTTP
/// bytes remain available on `AuthRequest` and `RequestHookContext`.
#[derive(Clone, Debug)]
pub struct TransformedRequestBody(pub crate::utils::json::JsValue);

/// Owned native context for application callbacks, including background delivery.
/// The schema accessor exposes the live instance and its hook-aware store; the
/// request and hook data retain the actual transport and admitted endpoint input.
#[derive(Clone)]
pub struct CallbackContext {
    pub request: Option<AuthRequest>,
    pub request_hook: Option<RequestHookContext>,
    pub endpoint: Option<crate::endpoint::EndpointCall>,
    context: std::sync::Arc<dyn std::any::Any + Send + Sync>,
}

impl CallbackContext {
    #[must_use]
    pub fn new<S: crate::AuthSchema>(
        context: &crate::AuthContext<S>,
        request: Option<&AuthRequest>,
    ) -> Self {
        let endpoint = crate::endpoint::current_endpoint_call_context();
        let request_hook = current_request_hook_context();
        Self {
            request: request
                .or_else(|| {
                    endpoint
                        .as_ref()
                        .and_then(crate::endpoint::EndpointCall::request)
                })
                .or_else(|| request_hook.as_ref().map(|hook| &hook.request))
                .cloned(),
            request_hook,
            endpoint,
            context: std::sync::Arc::new(context.clone()),
        }
    }

    /// Access the actual initialized instance using the application's schema.
    #[must_use]
    pub fn context<S: crate::AuthSchema>(&self) -> Option<&crate::AuthContext<S>> {
        self.context.downcast_ref()
    }
}
