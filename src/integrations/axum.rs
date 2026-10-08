//! Axum router and session extractors. Enable the `axum` feature.

use super::{
    CurrentSession, OptionalSession, dispatch::DispatchSupervisor, max_body_bytes,
    payload_too_large,
};
use crate::BetterAuth;
use alibi_core::{AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, core_paths};
use axum::{
    Router,
    extract::{FromRef, FromRequestParts, OriginalUri, Request, State},
    http::request::Parts,
    response::{IntoResponse, Response},
    routing::any,
};
use std::{collections::HashSet, future::Future, pin::Pin, sync::Arc};

/// Mount an initialized auth instance in an Axum application.
pub trait AxumIntegration {
    type Schema: AuthSchema;

    /// Create a router with every authentication route.
    ///
    /// Fully buffered requests continue dispatch after client disconnect. Router
    /// drop drains accepted work while its Tokio runtime remains alive. Server
    /// graceful shutdown alone need not await disconnected work; runtime/process
    /// shutdown can cancel it. Only the framework request context and tracing
    /// span are carried into dispatch, not arbitrary caller task-local values.
    fn axum_router(self) -> Router<Arc<BetterAuth<Self::Schema>>>;

    /// Create a router to nest into an application with its own state type.
    fn axum_router_with_state<S>(self) -> Router<S>
    where
        Self: Sized,
        Arc<BetterAuth<Self::Schema>>: FromRef<S>,
        S: Clone + Send + Sync + 'static;
}

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
        // Dispatch owns disabled paths, method matching and trailing-slash policy.
        // Axum's method router would add Allow/HEAD behavior upstream lacks.
        let supervisor = DispatchSupervisor::new(render);
        let mut paths = HashSet::from([
            core_paths::OK.to_owned(),
            core_paths::ERROR.to_owned(),
            core_paths::UPDATE_USER.to_owned(),
        ]);
        for plugin in self.plugins() {
            paths.extend(plugin.routes().into_iter().map(|route| route.path));
        }
        let mut router = Router::new();
        for path in paths {
            router = router.route(&path, any(handler::<T>(supervisor.clone())));
        }
        router.fallback(handler::<T>(supervisor))
    }
}

impl<S, T> FromRequestParts<S> for CurrentSession<T>
where
    T: AuthSchema,
    Arc<BetterAuth<T>>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth = Arc::<BetterAuth<T>>::from_ref(state);
        Self::resolve(&auth, parts.uri.path(), &parts.headers)
            .await
            .map_err(IntoResponse::into_response)
    }
}

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

type HandlerFuture = Pin<Box<dyn Future<Output = Response> + Send>>;

fn handler<T: AuthSchema>(
    supervisor: DispatchSupervisor<Response>,
) -> impl Fn(State<Arc<BetterAuth<T>>>, Request) -> HandlerFuture + Clone {
    move |State(auth): State<Arc<BetterAuth<T>>>, request: Request| {
        let supervisor = supervisor.clone();
        Box::pin(async move {
            match convert_request(&auth, request).await {
                Ok(request) => supervisor.dispatch(auth, request).await,
                Err(error) => error.into_response(),
            }
        })
    }
}

async fn convert_request<T: AuthSchema>(
    auth: &BetterAuth<T>,
    request: Request,
) -> AuthResult<AuthRequest> {
    let max_bytes = max_body_bytes(auth);
    let (parts, body) = request.into_parts();
    super::check_content_length(&parts.headers, max_bytes)?;
    let body = axum::body::to_bytes(body, max_bytes)
        .await
        .map_err(|error| {
            if is_length_limit_error(&error) {
                return payload_too_large(max_bytes);
            }
            tracing::warn!(%error, "Failed to read request body");
            AuthError::bad_request("Failed to read request body")
        })?;
    let original_uri = parts
        .extensions
        .get::<OriginalUri>()
        .map_or(&parts.uri, |original| &original.0);
    super::auth_request(
        &parts.method,
        &parts.uri,
        original_uri,
        &parts.headers,
        body.to_vec(),
        &auth.config().base_url,
    )
}

/// Distinguish the read limit from transport failures such as malformed
/// chunked framing or a client disconnect.
fn is_length_limit_error(error: &axum::Error) -> bool {
    std::iter::successors(std::error::Error::source(error), |source| source.source())
        .any(|source| source.is::<http_body_util::LengthLimitError>())
}

fn render(result: Result<AuthResponse, AuthError>) -> Response {
    result
        .unwrap_or_else(AuthError::to_auth_response)
        .into_response()
}
