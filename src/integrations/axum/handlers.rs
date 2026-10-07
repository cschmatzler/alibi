#[cfg(feature = "axum")]
use crate::BetterAuth;
#[cfg(feature = "axum")]
#[cfg(feature = "axum")]
use alibi_core::middleware::BodyLimitConfig;
use alibi_core::{AuthError, AuthRequest, AuthResponse, AuthSchema, HttpMethod, core_paths};
#[cfg(feature = "axum")]
use axum::{
    Router,
    extract::{FromRef, FromRequestParts, Request, State},
    http::StatusCode,
    http::request::Parts,
    response::{IntoResponse, Response},
    routing::any,
};
#[cfg(feature = "axum")]
use std::sync::Arc;

#[cfg(feature = "axum")]
type AxumAuthHandlerFuture = std::pin::Pin<Box<dyn Future<Output = Response> + Send>>;

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

    fn axum_router(self) -> Router<Self> {
        self.axum_router_with_state::<Self>()
    }

    fn axum_router_with_state<S>(self) -> Router<S>
    where
        Self: FromRef<S>,
        S: Clone + Send + Sync + 'static,
    {
        // Dispatch owns literal disabled paths, method matching and trailing-slash
        // policy. Axum's method router otherwise adds Allow/HEAD behavior that
        // the pinned auth router does not expose.
        let supervisor = AxumDispatchSupervisor::new(render_dispatch);
        let mut paths = std::collections::HashSet::from([
            core_paths::OK.to_owned(),
            core_paths::ERROR.to_owned(),
            core_paths::UPDATE_USER.to_owned(),
        ]);
        for plugin in self.plugins() {
            paths.extend(plugin.routes().into_iter().map(|route| route.path));
        }
        let mut router = Router::new();
        for path in paths {
            router = router.route(&path, any(create_plugin_handler::<T>(supervisor.clone())));
        }
        router.fallback(create_plugin_handler::<T>(supervisor))
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
/// ```rust,no_run
/// use alibi::{AuthSchema, prelude::AuthUser};
/// use alibi::integrations::axum::CurrentSession;
/// use axum::response::IntoResponse;
///
/// async fn profile<S: AuthSchema>(session: CurrentSession<S>) -> impl IntoResponse {
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
/// ```rust,no_run
/// use alibi::{AuthSchema, prelude::AuthUser};
/// use alibi::integrations::axum::OptionalSession;
/// use axum::response::IntoResponse;
///
/// async fn home<S: AuthSchema>(session: OptionalSession<S>) -> impl IntoResponse {
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
                drop(request.headers.insert(name.to_string(), value.to_owned()));
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
            .context()
            .session_user(&session)
            .await
            .map_err(IntoResponse::into_response)?
            .ok_or_else(|| AuthError::UserNotFound.into_response())?;

        Ok(Self { user, session })
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
        Ok(Self(
            CurrentSession::<T>::from_request_parts(parts, state)
                .await
                .ok(),
        ))
    }
}

#[cfg(feature = "axum")]
fn create_plugin_handler<T: AuthSchema>(
    supervisor: AxumDispatchSupervisor,
) -> impl Fn(State<Arc<BetterAuth<T>>>, Request) -> AxumAuthHandlerFuture + Clone {
    move |State(auth): State<Arc<BetterAuth<T>>>, req: Request| {
        let supervisor = supervisor.clone();
        Box::pin(async move {
            match convert_axum_request(
                req,
                max_body_bytes(auth.body_limit()),
                &auth.config().base_url,
            )
            .await
            {
                Ok(auth_req) => supervisor.dispatch(auth, auth_req).await,
                Err(err) => err.into_response(),
            }
        })
    }
}

/// Effective pre-parse body cap: `usize::MAX` when the caller disabled the
/// limit, otherwise the configured maximum.
#[cfg(feature = "axum")]
const fn max_body_bytes(config: &BodyLimitConfig) -> usize {
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
    base_url: &str,
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
                "Unsupported HTTP method".to_owned(),
            ));
        }
    };

    // Convert headers
    let mut headers: HashMap<String, String> = HashMap::new();
    for (name, value) in &parts.headers {
        if let Ok(value_str) = value.to_str() {
            // Headers.get joins repeated fields in wire order. Cookie uses
            // its semicolon separator; forwarding fields use commas so the
            // resolver validates the entire chain.
            let _ = headers
                .entry(name.to_string())
                .and_modify(|value| {
                    value.push_str(if name == "cookie" { "; " } else { ", " });
                    value.push_str(value_str);
                })
                .or_insert_with(|| value_str.to_owned());
        }
    }

    // HTTP origin comes from the received URI/Host. The configured deployment
    // scheme supplies relative HTTP URIs; forwarding headers do not choose it.
    let deployment = url::Url::parse(base_url).ok();
    let scheme = parts
        .uri
        .scheme_str()
        .unwrap_or_else(|| deployment.as_ref().map_or("http", url::Url::scheme));
    let authority = parts
        .uri
        .authority()
        .map(|value| value.as_str())
        .or_else(|| headers.get("host").map(String::as_str));
    let original_uri = parts
        .extensions
        .get::<axum::extract::OriginalUri>()
        .map_or(&parts.uri, |original| &original.0);
    let request_url = authority.and_then(|authority| {
        url::Url::parse(&format!(
            "{scheme}://{authority}{}",
            original_uri
                .path_and_query()
                .map_or("/", |value| value.as_str())
        ))
        .ok()
    });

    // Get path
    let path = parts.uri.path().to_owned();

    // Convert query parameters
    let query_pairs = parts
        .uri
        .query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

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

    let mut request = AuthRequest::from_parts(method, path, headers, body_bytes, HashMap::new());
    request.set_query_pairs(query_pairs);
    if let Some(url) = request_url {
        request = request.with_url(url);
    }
    Ok(request)
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

    response
        .body(axum::body::Body::from(auth_response.body))
        .unwrap_or_else(|_error| {
            let (mut parts, ()) = Response::new(()).into_parts();
            parts.status = StatusCode::INTERNAL_SERVER_ERROR;
            Response::from_parts(parts, axum::body::Body::from("Internal server error"))
        })
}
#[cfg(feature = "axum")]
type AxumDispatchSupervisor = crate::integrations::dispatch::DispatchSupervisor<Response>;

#[cfg(feature = "axum")]
fn render_dispatch(result: Result<AuthResponse, AuthError>) -> Response {
    match result {
        Ok(response) => convert_auth_response(response),
        Err(error) => error.into_response(),
    }
}
