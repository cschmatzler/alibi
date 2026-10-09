use crate::BetterAuth;
use alibi_core::{AuthError, AuthRequest, AuthResult, AuthSchema, HttpMethod};
use std::collections::HashMap;

/// The authenticated user and session of a request; rejects with `401` when
/// no valid session is present.
///
/// Axum handlers need `Arc<BetterAuth<S>>` in the router state; Poem routes
/// install it with `EndpointExt::data`.
///
/// ```rust,no_run
/// use alibi::{AuthSchema, prelude::AuthUser};
/// use alibi::integrations::CurrentSession;
/// use axum::response::IntoResponse;
///
/// async fn profile<S: AuthSchema>(session: CurrentSession<S>) -> impl IntoResponse {
///     axum::Json(serde_json::json!({ "id": session.user.id() }))
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CurrentSession<S: AuthSchema> {
    pub user: S::User,
    pub session: S::Session,
}

/// [`CurrentSession`] that yields `None` on any extraction failure, including
/// missing auth state or a storage error.
#[derive(Debug, Clone)]
pub struct OptionalSession<S: AuthSchema>(pub Option<CurrentSession<S>>);

impl<S: AuthSchema> CurrentSession<S> {
    pub(super) async fn resolve(
        auth: &BetterAuth<S>,
        path: &str,
        headers: &http::HeaderMap,
    ) -> AuthResult<Self> {
        let request = AuthRequest::from_parts(
            HttpMethod::Get,
            path.to_owned(),
            request_headers(headers),
            None,
            HashMap::new(),
        );
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
        Ok(Self { user, session })
    }
}

/// Join repeated header fields in wire order, as `Headers.get` does. Cookies use
/// their `; ` separator; other fields, including forwarding chains, use `, `.
pub(super) fn request_headers(headers: &http::HeaderMap) -> HashMap<String, String> {
    let mut joined = HashMap::<String, String>::new();
    for (name, value) in headers {
        let Ok(value) = value.to_str() else {
            continue;
        };
        _ = joined
            .entry(name.to_string())
            .and_modify(|existing| {
                existing.push_str(if name == http::header::COOKIE {
                    "; "
                } else {
                    ", "
                });
                existing.push_str(value);
            })
            .or_insert_with(|| value.to_owned());
    }
    joined
}

/// The pre-parse body cap. Transports enforce it while reading, so chunked
/// bodies cannot exhaust memory before `BodyLimitMiddleware` sees them.
pub(super) fn max_body_bytes<S: AuthSchema>(auth: &BetterAuth<S>) -> usize {
    let limit = auth.body_limit();
    if limit.enabled {
        limit.max_bytes
    } else {
        usize::MAX
    }
}

pub(super) fn payload_too_large(max_bytes: usize) -> AuthError {
    AuthError::payload_too_large(format!("Request body exceeds the {max_bytes}-byte limit"))
}

pub(super) fn check_content_length(headers: &http::HeaderMap, max_bytes: usize) -> AuthResult<()> {
    let declared = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    match declared {
        Some(length) if length > max_bytes => Err(payload_too_large(max_bytes)),
        _ => Ok(()),
    }
}

/// Build the dispatch request. `original_uri` is the URI before framework
/// nesting stripped its prefix; `uri` is the path relative to the mount point.
/// The request origin comes from the received URI or `Host`; the configured
/// deployment scheme fills in relative URIs, and forwarding headers never do.
pub(super) fn auth_request(
    method: &http::Method,
    uri: &http::Uri,
    original_uri: &http::Uri,
    headers: &http::HeaderMap,
    body: Vec<u8>,
    base_url: &str,
) -> AuthResult<AuthRequest> {
    let method = match *method {
        http::Method::GET => HttpMethod::Get,
        http::Method::POST => HttpMethod::Post,
        http::Method::PUT => HttpMethod::Put,
        http::Method::DELETE => HttpMethod::Delete,
        http::Method::PATCH => HttpMethod::Patch,
        http::Method::OPTIONS => HttpMethod::Options,
        http::Method::HEAD => HttpMethod::Head,
        _ => {
            return Err(AuthError::InvalidRequest(
                "Unsupported HTTP method".to_owned(),
            ));
        }
    };
    let headers = request_headers(headers);
    let scheme = uri.scheme_str().map_or_else(
        || {
            url::Url::parse(base_url)
                .map_or_else(|_| "http".to_owned(), |url| url.scheme().to_owned())
        },
        str::to_owned,
    );
    let url = uri
        .authority()
        .map(http::uri::Authority::as_str)
        .or_else(|| headers.get("host").map(String::as_str))
        .and_then(|authority| {
            let path = original_uri
                .path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str);
            url::Url::parse(&format!("{scheme}://{authority}{path}")).ok()
        });
    let query = uri
        .query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let body = (!body.is_empty()).then_some(body);
    let mut request =
        AuthRequest::from_parts(method, uri.path().to_owned(), headers, body, HashMap::new());
    request.set_query_pairs(query);
    Ok(match url {
        Some(url) => request.with_url(url),
        None => request,
    })
}
