#[cfg(feature = "axum")]
use axum::{
    Router,
    extract::{FromRef, FromRequestParts, Request, State},
    http::StatusCode,
    http::request::Parts,
    response::{IntoResponse, Response},
    routing::{get, post},
};
#[cfg(feature = "axum")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "axum")]
use tokio::{
    sync::{mpsc, oneshot},
    task::{Id, JoinSet},
};
#[cfg(feature = "axum")]
use tracing::{Instrument, instrument::WithSubscriber};

#[cfg(feature = "axum")]
use crate::BetterAuth;
#[cfg(feature = "axum")]
use better_auth_core::AuthSession;
#[cfg(feature = "axum")]
use better_auth_core::middleware::BodyLimitConfig;
use better_auth_core::{AuthError, AuthRequest, AuthResponse, AuthSchema, HttpMethod, core_paths};

#[cfg(feature = "axum")]
type AxumAuthHandlerFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>;

// The HTTP service future owns only its reply receiver. Once a complete body
// has been accepted, one router-owned supervisor owns the entire dispatch.
// Router construction stays valid outside a runtime; startup is lazy.
#[cfg(feature = "axum")]
type DispatchFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<AuthResponse, AuthError>> + Send>>;
#[cfg(feature = "axum")]
struct DispatchJob {
    future: DispatchFuture,
    reply: oneshot::Sender<Response>,
}
#[cfg(feature = "axum")]
#[derive(Clone, Default)]
struct AxumDispatchSupervisor(Arc<Mutex<Option<mpsc::UnboundedSender<DispatchJob>>>>);
#[cfg(feature = "axum")]
impl AxumDispatchSupervisor {
    async fn dispatch<S: AuthSchema>(
        &self,
        auth: Arc<BetterAuth<S>>,
        request: AuthRequest,
    ) -> Response {
        let runtime = match tokio::runtime::Handle::try_current() {
            Ok(runtime) => runtime,
            Err(_) => return dispatch_failure(),
        };
        let (reply, receive) = oneshot::channel();
        let future = Box::pin(
            async move { auth.handle_request(request).await }
                .instrument(tracing::Span::current())
                .with_current_subscriber(),
        );
        let submitted = match self.0.lock() {
            Ok(mut sender) => {
                // A router can outlive its first runtime. Only a definitively
                // closed receiver may be replaced; accepted jobs are never retried.
                if sender
                    .as_ref()
                    .is_some_and(mpsc::UnboundedSender::is_closed)
                {
                    *sender = None;
                }
                let sender = sender.get_or_insert_with(|| {
                    let (send, receive) = mpsc::unbounded_channel();
                    // The actor holds no sender or auth reference. Closing the
                    // router channel drains accepted jobs and then exits.
                    let _supervisor = runtime.spawn(supervise_dispatches(receive));
                    send
                });
                sender.send(DispatchJob { future, reply }).is_ok()
            }
            Err(_) => false,
        };
        if !submitted {
            return dispatch_failure();
        }
        receive.await.unwrap_or_else(|_| dispatch_failure())
    }
}
#[cfg(feature = "axum")]
fn dispatch_failure() -> Response {
    AuthError::internal("Authentication request failed").into_response()
}
#[cfg(feature = "axum")]
async fn supervise_dispatches(mut receive: mpsc::UnboundedReceiver<DispatchJob>) {
    let mut workers = JoinSet::new();
    let mut replies = std::collections::HashMap::<Id, oneshot::Sender<Response>>::new();
    let mut accepting = true;
    while accepting || !workers.is_empty() {
        tokio::select! {
            job = receive.recv(), if accepting => match job {
                Some(job) => {
                    let id = workers.spawn(job.future).id();
                    let _ = replies.insert(id, job.reply);
                }
                None => accepting = false,
            },
            completed = workers.join_next_with_id(), if !workers.is_empty() => {
                if let Some(completed) = completed {
                    let (id, response) = match completed {
                        Ok((id, Ok(response))) => (id, convert_auth_response(response)),
                        Ok((id, Err(error))) => (id, error.into_response()),
                        Err(error) => {
                            tracing::error!(panic = error.is_panic(), cancelled = error.is_cancelled(), "Authentication dispatch task failed");
                            (error.id(), dispatch_failure())
                        }
                    };
                    if let Some(reply) = replies.remove(&id) {
                        // A disconnected receiver cannot cancel completed work.
                        let _ = reply.send(response);
                    }
                }
            },
        }
    }
}

/// Integration trait for Axum web framework
#[cfg(feature = "axum")]
pub trait AxumIntegration {
    type Schema: AuthSchema;

    /// Create an Axum router with all authentication routes.
    /// Fully buffered requests continue dispatch after client disconnect. Router
    /// drop drains accepted work while its Tokio runtime remains alive. Server
    /// graceful shutdown alone need not await disconnected work; runtime/process
    /// shutdown can cancel it. Only the framework request context and tracing
    /// span are carried into dispatch, not arbitrary caller task-local values.
    fn axum_router(self) -> Router<Arc<BetterAuth<Self::Schema>>>;

    /// Create an Axum router that can be nested into an application using a
    /// custom state type.
    fn axum_router_with_state<S>(self) -> Router<S>
    where
        Self: Sized,
        Arc<BetterAuth<Self::Schema>>: FromRef<S>,
        S: Clone + Send + Sync + 'static;
}

#[cfg(feature = "axum")]
impl<T: AuthSchema> AxumIntegration for Arc<BetterAuth<T>> {
    type Schema = T;

    fn axum_router(self) -> Router<Arc<BetterAuth<T>>> {
        self.axum_router_with_state::<Arc<BetterAuth<T>>>()
    }

    fn axum_router_with_state<S>(self) -> Router<S>
    where
        Arc<BetterAuth<T>>: FromRef<S>,
        S: Clone + Send + Sync + 'static,
    {
        // NOTE: disabled_paths is checked here at route-registration time so
        // that disabled routes are never mounted in Axum at all.  The core
        // handler (`handle_request_inner`) performs the same check at
        // request-dispatch time for non-Axum integrations (direct
        // `handle_request` callers).  The duplication is intentional.
        let disabled_paths = self.config().disabled_paths.clone();

        let supervisor = AxumDispatchSupervisor::default();
        let mut router = Router::new();

        // Add status endpoints
        if !disabled_paths.contains(&core_paths::OK.to_string()) {
            router = router.route(
                core_paths::OK,
                get(create_plugin_handler::<T>(supervisor.clone())),
            );
        }
        if !disabled_paths.contains(&core_paths::ERROR.to_string()) {
            router = router.route(
                core_paths::ERROR,
                get(create_plugin_handler::<T>(supervisor.clone())),
            );
        }

        // Add OpenAPI spec endpoint
        if !disabled_paths.contains(&core_paths::OPENAPI_SPEC.to_string()) {
            router = router.route(
                core_paths::OPENAPI_SPEC,
                get(create_plugin_handler::<T>(supervisor.clone())),
            );
        }

        // Add core user management routes
        if !disabled_paths.contains(&core_paths::UPDATE_USER.to_string()) {
            router = router.route(
                core_paths::UPDATE_USER,
                post(create_plugin_handler::<T>(supervisor.clone())),
            );
        }
        // Register plugin routes
        for plugin in self.plugins() {
            for route in plugin.routes() {
                // Skip disabled paths
                if disabled_paths.contains(&route.path) {
                    continue;
                }

                let handler_fn = create_plugin_handler::<T>(supervisor.clone());
                match route.method {
                    HttpMethod::Get => {
                        router = router.route(&route.path, get(handler_fn.clone()));
                    }
                    HttpMethod::Post => {
                        router = router.route(&route.path, post(handler_fn.clone()));
                    }
                    HttpMethod::Put => {
                        router = router.route(&route.path, axum::routing::put(handler_fn.clone()));
                    }
                    HttpMethod::Delete => {
                        router =
                            router.route(&route.path, axum::routing::delete(handler_fn.clone()));
                    }
                    HttpMethod::Patch => {
                        router =
                            router.route(&route.path, axum::routing::patch(handler_fn.clone()));
                    }
                    _ => {} // Skip unsupported methods
                }
            }
        }

        router.method_not_allowed_fallback(|| async { StatusCode::NOT_FOUND })
    }
}

#[cfg(feature = "axum")]
fn create_plugin_handler<T: AuthSchema>(
    supervisor: AxumDispatchSupervisor,
) -> impl Fn(State<Arc<BetterAuth<T>>>, Request) -> AxumAuthHandlerFuture + Clone {
    move |State(auth): State<Arc<BetterAuth<T>>>, req: Request| {
        let supervisor = supervisor.clone();
        Box::pin(async move {
            match convert_axum_request(req, max_body_bytes(auth.body_limit())).await {
                Ok(auth_req) => supervisor.dispatch(auth, auth_req).await,
                Err(err) => err.into_response(),
            }
        })
    }
}

/// Effective pre-parse body cap: `usize::MAX` when the caller disabled the
/// limit, otherwise the configured maximum.
#[cfg(feature = "axum")]
fn max_body_bytes(config: &BodyLimitConfig) -> usize {
    if config.enabled {
        config.max_bytes
    } else {
        usize::MAX
    }
}

/// Whether an axum body error was caused by hitting the read limit, as opposed
/// to a transport failure (malformed chunked framing, client disconnect).
#[cfg(feature = "axum")]
fn is_body_length_limit_error(err: &axum::Error) -> bool {
    use std::error::Error;

    let mut source = err.source();
    while let Some(e) = source {
        if e.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        source = e.source();
    }
    false
}

#[cfg(feature = "axum")]
async fn convert_axum_request(
    req: Request,
    max_body_bytes: usize,
) -> Result<AuthRequest, AuthError> {
    use std::collections::HashMap;

    let (parts, body) = req.into_parts();

    // Convert method
    let method = match parts.method {
        axum::http::Method::GET => HttpMethod::Get,
        axum::http::Method::POST => HttpMethod::Post,
        axum::http::Method::PUT => HttpMethod::Put,
        axum::http::Method::DELETE => HttpMethod::Delete,
        axum::http::Method::PATCH => HttpMethod::Patch,
        axum::http::Method::OPTIONS => HttpMethod::Options,
        axum::http::Method::HEAD => HttpMethod::Head,
        _ => {
            return Err(AuthError::InvalidRequest(
                "Unsupported HTTP method".to_string(),
            ));
        }
    };

    // Convert headers
    let mut headers = HashMap::new();
    for (name, value) in parts.headers.iter() {
        if let Ok(value_str) = value.to_str() {
            let _ = headers.insert(name.to_string(), value_str.to_string());
        }
    }

    // Get path
    let path = parts.uri.path().to_string();

    // Convert query parameters
    let mut query = HashMap::new();
    if let Some(query_str) = parts.uri.query() {
        for (key, value) in url::form_urlencoded::parse(query_str.as_bytes()) {
            let _ = query.insert(key.to_string(), value.to_string());
        }
    }

    // Bound the body read at the caller-configured limit. `BodyLimitMiddleware`
    // runs on the already-buffered `AuthRequest` and only sees `Content-Length`,
    // so it cannot stop a `Transfer-Encoding: chunked` body from exhausting
    // memory — this pre-parse cap is the only defence on that path.
    if let Some(len) = parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        && len > max_body_bytes
    {
        return Err(AuthError::payload_too_large(format!(
            "Request body exceeds the {max_body_bytes}-byte limit"
        )));
    }

    // Convert body
    let body_bytes = match axum::body::to_bytes(body, max_body_bytes).await {
        Ok(bytes) => {
            if bytes.is_empty() {
                None
            } else {
                Some(bytes.to_vec())
            }
        }
        Err(err) => {
            if is_body_length_limit_error(&err) {
                return Err(AuthError::payload_too_large(format!(
                    "Request body exceeds the {max_body_bytes}-byte limit"
                )));
            }
            tracing::warn!(error = %err, "Failed to read request body");
            return Err(AuthError::bad_request("Failed to read request body"));
        }
    };

    Ok(AuthRequest::from_parts(
        method, path, headers, body_bytes, query,
    ))
}

#[cfg(feature = "axum")]
fn convert_auth_response(auth_response: AuthResponse) -> Response {
    let mut response = Response::builder().status(
        StatusCode::from_u16(auth_response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
    );

    // Add headers
    for (name, value) in auth_response.headers {
        if let (Ok(header_name), Ok(header_value)) = (
            axum::http::HeaderName::from_bytes(name.as_bytes()),
            axum::http::HeaderValue::from_str(&value),
        ) {
            response = response.header(header_name, header_value);
        }
    }

    match response.body(axum::body::Body::from(auth_response.body)) {
        Ok(resp) => resp,
        Err(_) => {
            let (mut parts, _) = Response::new(()).into_parts();
            parts.status = StatusCode::INTERNAL_SERVER_ERROR;
            Response::from_parts(parts, axum::body::Body::from("Internal server error"))
        }
    }
}

// ---------------------------------------------------------------------------
// Axum extractors
// ---------------------------------------------------------------------------

/// Authenticated session extractor.
///
/// Extracts and validates the current user and session from the request.
/// Returns `401 Unauthorized` if no valid session is found.
///
/// Requires `State<Arc<BetterAuth>>` to be present in the router.
///
/// # Example
///
/// ```rust,ignore
/// use better_auth::integrations::axum::CurrentSession;
///
/// async fn profile(session: CurrentSession<AppAuthSchema>) -> impl IntoResponse {
///     let user = &session.user;
///     let session = &session.session;
///     axum::Json(serde_json::json!({ "id": user.id() }))
/// }
/// ```
#[cfg(feature = "axum")]
#[derive(Debug, Clone)]
pub struct CurrentSession<T: AuthSchema> {
    pub user: T::User,
    pub session: T::Session,
}

/// Optional authenticated session extractor.
///
/// Like [`CurrentSession`] but returns `None` instead of a 401 error when
/// no valid session is found. Useful for routes that behave differently
/// for authenticated vs anonymous users.
///
/// # Example
///
/// ```rust,ignore
/// async fn home(session: OptionalSession<AppAuthSchema>) -> impl IntoResponse {
///     if let Some(session) = session.0 {
///         axum::Json(serde_json::json!({ "user": session.user.id() }))
///     } else {
///         axum::Json(serde_json::json!({ "user": null }))
///     }
/// }
/// ```
#[cfg(feature = "axum")]
#[derive(Debug, Clone)]
pub struct OptionalSession<T: AuthSchema>(pub Option<CurrentSession<T>>);

#[cfg(feature = "axum")]
impl<S, T> FromRequestParts<S> for CurrentSession<T>
where
    T: AuthSchema,
    Arc<BetterAuth<T>>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth = Arc::<BetterAuth<T>>::from_ref(state);
        let mut request = AuthRequest::new(HttpMethod::Get, parts.uri.path());
        for (name, value) in &parts.headers {
            if let Ok(value) = value.to_str() {
                _ = request.headers.insert(name.to_string(), value.to_string());
            }
        }
        let token = auth
            .session_manager()
            .extract_session_token(&request)
            .ok_or_else(|| AuthError::Unauthenticated.into_response())?;

        let session = auth
            .session_manager()
            .get_session(&token)
            .await
            .map_err(IntoResponse::into_response)?
            .ok_or_else(|| AuthError::SessionNotFound.into_response())?;

        let user = auth
            .store()
            .get_user_by_id(&session.user_id())
            .await
            .map_err(IntoResponse::into_response)?
            .ok_or_else(|| AuthError::UserNotFound.into_response())?;

        Ok(CurrentSession { user, session })
    }
}

#[cfg(feature = "axum")]
impl<S, T> FromRequestParts<S> for OptionalSession<T>
where
    T: AuthSchema,
    Arc<BetterAuth<T>>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match CurrentSession::<T>::from_request_parts(parts, state).await {
            Ok(session) => Ok(OptionalSession::<T>(Some(session))),
            Err(_) => Ok(OptionalSession::<T>(None)),
        }
    }
}
