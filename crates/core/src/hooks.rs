use crate::types::{AuthRequest, HttpMethod, RequestExtensions, RequestMeta};

/// Request-derived data available to middleware, stores, and other hooks during request handling.
#[derive(Debug, Clone)]
pub struct RequestHookContext {
    pub method: HttpMethod,
    pub path: String,
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
            method: request.method().clone(),
            path: request.path().to_owned(),
            headers: request.headers.clone(),
            query: request.query.clone(),
            body: request.body.clone(),
            meta: RequestMeta::from_request(request),
            extensions: request.extensions().clone(),
        }
    }
}

tokio::task_local! {
    static REQUEST_HOOK_CONTEXT: RequestHookContext;
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
    REQUEST_HOOK_CONTEXT.scope(request_context, future).await
}

pub fn current_request_hook_context() -> Option<RequestHookContext> {
    REQUEST_HOOK_CONTEXT.try_with(Clone::clone).ok()
}

/// A trusted endpoint's parsed body for adapter callbacks. Completed response
/// callbacks still receive the original request body.
#[derive(Clone, Debug)]
pub struct ValidatedRequestBody(pub crate::utils::json::JsValue);

/// Request body after a plugin has transformed endpoint input. Original HTTP
/// bytes remain available on `AuthRequest` and `RequestHookContext`.
#[derive(Clone, Debug)]
pub struct TransformedRequestBody(pub crate::utils::json::JsValue);
