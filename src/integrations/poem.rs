//! Poem endpoints and session extractors. Enable the `poem` feature.
use crate::BetterAuth;
use better_auth_core::{AuthError, AuthRequest, AuthResponse, AuthSchema, HttpMethod};
use poem::{Endpoint, FromRequest, Request, RequestBody, Response, http::StatusCode};
use std::sync::Arc;

/// Integration for an initialized auth instance.
pub trait PoemIntegration {
    type Schema: AuthSchema;
    /// Create an endpoint to mount using `Route::nest` at the auth base path.
    /// Fully buffered requests continue after disconnect. Dropping the endpoint
    /// drains accepted work while the Tokio runtime remains alive; runtime or
    /// process shutdown can cancel it. Dispatch carries tracing and the auth
    /// request context, but not arbitrary caller task-local values.
    fn poem_endpoint(self) -> PoemAuthEndpoint<Self::Schema>;
}
impl<S: AuthSchema> PoemIntegration for Arc<BetterAuth<S>> {
    type Schema = S;
    fn poem_endpoint(self) -> PoemAuthEndpoint<S> {
        PoemAuthEndpoint {
            auth: self,
            supervisor: PoemDispatchSupervisor::new(render_dispatch),
        }
    }
}

/// A Poem endpoint that delegates routing and method policy to auth dispatch.
pub struct PoemAuthEndpoint<S: AuthSchema> {
    auth: Arc<BetterAuth<S>>,
    supervisor: PoemDispatchSupervisor,
}
impl<S: AuthSchema> Clone for PoemAuthEndpoint<S> {
    fn clone(&self) -> Self {
        Self {
            auth: self.auth.clone(),
            supervisor: self.supervisor.clone(),
        }
    }
}
impl<S: AuthSchema> Endpoint for PoemAuthEndpoint<S> {
    type Output = Response;
    async fn call(&self, req: Request) -> poem::Result<Response> {
        let limit = self.auth.body_limit();
        let max_bytes = if limit.enabled {
            limit.max_bytes
        } else {
            usize::MAX
        };
        Ok(
            match convert_request(req, max_bytes, &self.auth.config().base_url).await {
                Ok(request) => self.supervisor.dispatch(self.auth.clone(), request).await,
                Err(error) => convert_auth_response(error.to_auth_response()),
            },
        )
    }
}

fn request_headers(req: &Request) -> std::collections::HashMap<String, String> {
    let mut headers = std::collections::HashMap::<String, String>::new();
    for (name, value) in req.headers() {
        if let Ok(value) = value.to_str() {
            let _ = headers
                .entry(name.to_string())
                .and_modify(|joined| {
                    joined.push_str(if name == "cookie" { "; " } else { ", " });
                    joined.push_str(value);
                })
                .or_insert_with(|| value.to_owned());
        }
    }
    headers
}

async fn convert_request(
    mut req: Request,
    max_bytes: usize,
    base_url: &str,
) -> Result<AuthRequest, AuthError> {
    let method = match req.method().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "PATCH" => HttpMethod::Patch,
        "OPTIONS" => HttpMethod::Options,
        "HEAD" => HttpMethod::Head,
        _ => {
            return Err(AuthError::InvalidRequest(
                "Unsupported HTTP method".to_owned(),
            ));
        }
    };
    let headers = request_headers(&req);
    let deployment = url::Url::parse(base_url).ok();
    let scheme = req
        .uri()
        .scheme_str()
        .unwrap_or_else(|| deployment.as_ref().map_or("http", url::Url::scheme));
    let authority = req
        .uri()
        .authority()
        .map(|v| v.as_str())
        .or_else(|| headers.get("host").map(String::as_str));
    let request_url = authority.and_then(|authority| {
        url::Url::parse(&format!(
            "{scheme}://{authority}{}",
            req.original_uri()
                .path_and_query()
                .map_or("/", |v| v.as_str())
        ))
        .ok()
    });
    let path = req.uri().path().to_owned();
    let query_pairs = req
        .uri()
        .query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let too_large =
        || AuthError::payload_too_large(format!("Request body exceeds the {max_bytes}-byte limit"));
    if req
        .header("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|len| len > max_bytes)
    {
        return Err(too_large());
    }
    let bytes = req
        .take_body()
        .into_bytes_limit(max_bytes)
        .await
        .map_err(|error| {
            if matches!(error, poem::error::ReadBodyError::PayloadTooLarge) {
                too_large()
            } else {
                AuthError::bad_request("Failed to read request body")
            }
        })?;
    let body = if bytes.is_empty() {
        None
    } else {
        Some(bytes.to_vec())
    };
    let mut request = AuthRequest::from_parts(
        method,
        path,
        headers,
        body,
        std::collections::HashMap::new(),
    );
    request.set_query_pairs(query_pairs);
    if let Some(url) = request_url {
        request = request.with_url(url);
    }
    Ok(request)
}

fn convert_auth_response(auth: AuthResponse) -> Response {
    let mut response = Response::builder()
        .status(StatusCode::from_u16(auth.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .body(auth.body);
    for (name, value) in auth.headers {
        if let (Ok(name), Ok(value)) = (
            poem::http::HeaderName::from_bytes(name.as_bytes()),
            poem::http::HeaderValue::from_str(&value),
        ) {
            let _ = response.headers_mut().append(name, value);
        }
    }
    response
}

/// Required authenticated session. Install `Arc<BetterAuth<S>>` using
/// `EndpointExt::data` on application routes that use this extractor.
#[derive(Debug, Clone)]
pub struct CurrentSession<S: AuthSchema> {
    pub user: S::User,
    pub session: S::Session,
}
/// Optional session; any extraction failure yields `None`, including missing
/// auth data or a storage error, matching the Axum integration. Use
/// [`CurrentSession`] when failures must be reported.
#[derive(Debug, Clone)]
pub struct OptionalSession<S: AuthSchema>(pub Option<CurrentSession<S>>);

impl<'a, S: AuthSchema> FromRequest<'a> for CurrentSession<S> {
    async fn from_request(req: &'a Request, _body: &mut RequestBody) -> poem::Result<Self> {
        let auth = req
            .data::<Arc<BetterAuth<S>>>()
            .ok_or_else(|| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?;
        let request = AuthRequest::from_parts(
            HttpMethod::Get,
            req.uri().path().to_owned(),
            request_headers(req),
            None,
            std::collections::HashMap::new(),
        );
        let result = async {
            let token = auth
                .session_manager()
                .extract_session_token(&request)
                .ok_or(AuthError::Unauthenticated)?;
            let session = auth
                .session_manager()
                .get_session(&token)
                .await?
                .ok_or(AuthError::SessionNotFound)?;
            let user = auth
                .context()
                .session_user(&session)
                .await?
                .ok_or(AuthError::UserNotFound)?;
            Ok::<_, AuthError>(Self { user, session })
        }
        .await;
        result.map_err(|error| {
            poem::Error::from_response(convert_auth_response(error.to_auth_response()))
        })
    }
}
impl<'a, S: AuthSchema> FromRequest<'a> for OptionalSession<S> {
    async fn from_request(req: &'a Request, body: &mut RequestBody) -> poem::Result<Self> {
        Ok(Self(
            CurrentSession::<S>::from_request(req, body).await.ok(),
        ))
    }
}
type PoemDispatchSupervisor = crate::integrations::dispatch::DispatchSupervisor<Response>;

fn render_dispatch(result: Result<AuthResponse, AuthError>) -> Response {
    match result {
        Ok(response) => convert_auth_response(response),
        Err(error) => convert_auth_response(error.to_auth_response()),
    }
}
