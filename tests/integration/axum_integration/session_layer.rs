use super::router::{
    TestSchema, create_test_auth_with_config, create_test_user, test_session_cookie,
};
use alibi::integrations::axum::{AxumIntegration, ResolvedSession, SessionLayer};
use alibi::plugins::GetSessionQuery;
use alibi::{Alibi, AuthConfig};
use axum::{
    Json, Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const SECRET: &str = "test-secret-key-that-is-at-least-32-characters-long";

/// Refresh on every read, so each authenticated request renews its session.
async fn refreshing_auth() -> Arc<Alibi<TestSchema>> {
    let mut config = AuthConfig::new(SECRET).base_url("http://localhost:3000");
    config.session.update_age = None;
    create_test_auth_with_config(config).await
}

async fn me(ResolvedSession(session): ResolvedSession) -> Response {
    (
        [(header::SET_COOKIE, "theme=dark; Path=/")],
        Json(json!({ "id": session.user.id })),
    )
        .into_response()
}

async fn guest(session: Option<ResolvedSession>) -> Json<Value> {
    Json(json!({ "authenticated": session.is_some() }))
}

fn app(auth: &Arc<Alibi<TestSchema>>, layer: SessionLayer<TestSchema>) -> Router {
    Router::new()
        .route("/me", get(me))
        .route("/guest", get(guest))
        .layer(layer)
        .nest("/auth", Arc::clone(auth).axum_router())
        .with_state(Arc::clone(auth))
}

async fn get_with_cookie(router: &Router, path: &str, cookie: &str) -> Response {
    let request = Request::builder()
        .uri(path)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    router.clone().oneshot(request).await.unwrap()
}

fn set_cookies(response: &Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect()
}

async fn body(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// Upstream source: packages/better-auth/src/api/routes/session.ts `getSessionFromCtx`,
// which runs get-session and forwards its headers except `cache-control`/`pragma`.
#[tokio::test]
async fn session_layer_renews_sessions_unless_refresh_is_disabled() {
    let disabled = GetSessionQuery {
        disable_refresh: true,
        ..GetSessionQuery::default()
    };
    for (query, renews) in [(None, true), (Some(disabled), false)] {
        let auth = refreshing_auth().await;
        let mut layer = SessionLayer::new(Arc::clone(&auth));
        if let Some(query) = query {
            layer = layer.query(query);
        }
        let router = app(&auth, layer);
        let (user, token) = create_test_user(router.clone()).await;

        let response = get_with_cookie(&router, "/me", &test_session_cookie(&token)).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::CACHE_CONTROL).is_none());
        let cookies = set_cookies(&response);
        assert_eq!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("better-auth.session_token=")
                    && !cookie.contains("Max-Age=0")),
            renews,
            "{cookies:?}"
        );
        assert_eq!(
            cookies.last().map(String::as_str),
            Some("theme=dark; Path=/"),
            "Handler cookies follow session cookies."
        );
        assert_eq!(body(response).await.get("id"), user.pointer("/user/id"));
    }
}

// Upstream source: packages/better-auth/src/api/routes/session.ts `sessionMiddleware`,
// whose `UNAUTHORIZED` error keeps the get-session cookie deletions.
#[tokio::test]
async fn session_layer_clears_ended_sessions() {
    let auth = refreshing_auth().await;
    let router = app(&auth, SessionLayer::new(Arc::clone(&auth)));
    let (_, token) = create_test_user(router.clone()).await;
    let cookie = test_session_cookie(&token);
    let sign_out = Request::builder()
        .method(Method::POST)
        .uri("/auth/sign-out")
        .header(header::COOKIE, &cookie)
        .header(header::ORIGIN, "http://localhost:3000")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router.clone().oneshot(sign_out).await.unwrap().status(),
        StatusCode::OK
    );

    for (path, status) in [
        ("/me", StatusCode::UNAUTHORIZED),
        ("/guest", StatusCode::OK),
    ] {
        let response = get_with_cookie(&router, path, &cookie).await;

        assert_eq!(response.status(), status, "{path}");
        let cookies = set_cookies(&response);
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("better-auth.session_token=;")
                    && cookie.contains("Max-Age=0")),
            "{path}: {cookies:?}"
        );
        let expected = if path == "/me" {
            json!({ "code": "UNAUTHORIZED", "message": "Unauthorized" })
        } else {
            json!({ "authenticated": false })
        };
        assert_eq!(body(response).await, expected);
    }
}

#[tokio::test]
async fn resolved_session_fails_closed_without_the_layer() {
    let auth = refreshing_auth().await;
    let router = Router::new()
        .route("/guest", get(guest))
        .nest("/auth", Arc::clone(&auth).axum_router())
        .with_state(Arc::clone(&auth));
    let (_, token) = create_test_user(router.clone()).await;

    let response = get_with_cookie(&router, "/guest", &test_session_cookie(&token)).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
