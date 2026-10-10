//! Poem endpoint and session extractors. Enable the `poem` feature.

use super::dispatch::DispatchSupervisor;
use super::shared::{
    CurrentSession, OptionalSession, auth_request, check_content_length, max_body_bytes,
    payload_too_large,
};
use crate::Alibi;
use alibi_core::{AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema};
use poem::{Endpoint, FromRequest, Request, RequestBody, Response, http::StatusCode};
use std::sync::Arc;

/// Mount an initialized auth instance in a Poem application.
pub trait PoemIntegration {
    type Schema: AuthSchema;

    /// Create an endpoint to mount using `Route::nest` at the auth base path.
    ///
    /// Fully buffered requests continue after disconnect. Dropping the endpoint
    /// drains accepted work while the Tokio runtime remains alive; runtime or
    /// process shutdown can cancel it. Dispatch carries tracing and the auth
    /// request context, but not arbitrary caller task-local values.
    fn poem_endpoint(self) -> PoemAuthEndpoint<Self::Schema>;
}

impl<S: AuthSchema> PoemIntegration for Arc<Alibi<S>> {
    type Schema = S;

    fn poem_endpoint(self) -> PoemAuthEndpoint<S> {
        PoemAuthEndpoint {
            auth: self,
            supervisor: DispatchSupervisor::new(render),
        }
    }
}

/// A Poem endpoint that delegates routing and method policy to auth dispatch.
pub struct PoemAuthEndpoint<S: AuthSchema> {
    auth: Arc<Alibi<S>>,
    supervisor: DispatchSupervisor<Response>,
}

impl<S: AuthSchema> Clone for PoemAuthEndpoint<S> {
    fn clone(&self) -> Self {
        Self {
            auth: Arc::clone(&self.auth),
            supervisor: self.supervisor.clone(),
        }
    }
}

impl<S: AuthSchema> Endpoint for PoemAuthEndpoint<S> {
    type Output = Response;

    async fn call(&self, request: Request) -> poem::Result<Response> {
        Ok(match convert_request(&self.auth, request).await {
            Ok(request) => {
                self.supervisor
                    .dispatch(Arc::clone(&self.auth), request)
                    .await
            }
            Err(error) => render(Err(error)),
        })
    }
}

impl<'a, S: AuthSchema> FromRequest<'a> for CurrentSession<S> {
    async fn from_request(request: &'a Request, _body: &mut RequestBody) -> poem::Result<Self> {
        let auth = request
            .data::<Arc<Alibi<S>>>()
            .ok_or_else(|| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?;
        Self::resolve(auth, request.uri().path(), request.headers())
            .await
            .map_err(|error| poem::Error::from_response(render(Err(error))))
    }
}

impl<'a, S: AuthSchema> FromRequest<'a> for OptionalSession<S> {
    async fn from_request(request: &'a Request, body: &mut RequestBody) -> poem::Result<Self> {
        Ok(Self(
            CurrentSession::<S>::from_request(request, body).await.ok(),
        ))
    }
}

async fn convert_request<S: AuthSchema>(
    auth: &Alibi<S>,
    mut request: Request,
) -> AuthResult<AuthRequest> {
    let max_bytes = max_body_bytes(auth);
    check_content_length(request.headers(), max_bytes)?;
    let body = request
        .take_body()
        .into_bytes_limit(max_bytes)
        .await
        .map_err(|error| match error {
            poem::error::ReadBodyError::PayloadTooLarge => payload_too_large(max_bytes),
            _ => AuthError::bad_request("Failed to read request body"),
        })?;
    auth_request(
        request.method(),
        request.uri(),
        request.original_uri(),
        request.headers(),
        body.to_vec(),
        &auth.config().base_url,
    )
}

fn render(result: Result<AuthResponse, AuthError>) -> Response {
    let (parts, body) =
        http::Response::from(result.unwrap_or_else(AuthError::to_auth_response)).into_parts();
    let mut response = Response::from(body);
    response.set_status(parts.status);
    *response.headers_mut() = parts.headers;
    response
}
