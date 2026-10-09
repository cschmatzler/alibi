//! Public transport contracts missing from direct-dispatch and Axum coverage:
//! nested Poem URI handling, wire headers/body, extraction, and cancellation.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "boundary assertions use known fixture values"
)]
use crate::storage::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::entity::AuthUser;
use alibi::integrations::{CurrentSession, OptionalSession, poem::PoemIntegration};
use alibi::middleware::{BodyLimitConfig, RateLimitConfig};
use alibi::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig};
use alibi::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    CreateUser, UpdateUser,
};
use async_trait::async_trait;
use poem::{
    Endpoint, FromRequest, Request, Route,
    http::{Method, StatusCode},
};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

struct Probe {
    entered: Arc<Notify>,
    release: Arc<Notify>,
    finished: Arc<Notify>,
}
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Probe {
    fn name(&self) -> &'static str {
        "poem-boundary"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::new(alibi::HttpMethod::Patch, "/wire", "wire"),
            AuthRoute::post("/persist", "persist"),
        ]
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.path() == "/persist" {
            let user = ctx
                .database
                .create_user(
                    CreateUser::new()
                        .with_email("disconnect@example.com")
                        .with_name("started"),
                )
                .await?;
            self.entered.notify_one();
            self.release.notified().await;
            let _ = ctx
                .database
                .update_user(
                    &user.id(),
                    UpdateUser {
                        name: Some("completed".into()),
                        ..Default::default()
                    },
                )
                .await?;
            self.finished.notify_one();
            return Ok(Some(AuthResponse::text(201, "saved")));
        }
        let mut response = AuthResponse::json(
            202,
            &json!({
                "path":req.path(), "method":format!("{:?}", req.method), "url":req.url().map(|v|v.as_str()),
                "query":req.query.get("value"), "cookie":req.headers.get("cookie"),
                "repeated":req.headers.get("x-repeated"), "body":req.body_as_json::<serde_json::Value>()?
            }),
        )?;
        response
            .headers
            .append("set-cookie", "a=one; Path=/; HttpOnly");
        response
            .headers
            .append("set-cookie", "b=two; Path=/; HttpOnly");
        Ok(Some(response))
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<S>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        if req.path() == "/wire" {
            response.headers.append("x-reply", "first");
            response.headers.append("x-reply", "second");
        }
        Ok(response)
    }
}
fn config() -> AuthConfig {
    AuthConfig::new("poem-test-secret-with-at-least-32-characters")
        .base_url("https://auth.example.com")
        .base_path("/auth")
}
fn request(method: Method, path: &str, body: impl Into<poem::Body>) -> Request {
    let req = poem::http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "auth.example.com")
        .header("origin", "https://auth.example.com")
        .header("content-type", "application/json")
        .body(body.into())
        .unwrap();
    let (parts, body) = req.into_parts();
    Request::from_parts(
        (
            parts,
            Default::default(),
            Default::default(),
            poem::http::uri::Scheme::HTTPS,
        )
            .into(),
        body,
    )
}

async fn wire_and_authority<B: Backend>(db: Db) -> TestResult {
    let (connection, store) = db.migrated::<B>(&config().secret).await?;
    let auth = Arc::new(
        AuthBuilder::<B::Schema>::new(config())
            .store(store)
            .rate_limit(RateLimitConfig {
                enabled: false,
                ..Default::default()
            })
            .body_limit(BodyLimitConfig {
                enabled: true,
                max_bytes: 128,
            })
            .plugin(Probe {
                entered: Arc::default(),
                release: Arc::default(),
                finished: Arc::default(),
            })
            .build()
            .await?,
    );
    let app = Route::new().nest("/auth", auth.clone().poem_endpoint());
    let mut req = request(
        Method::PATCH,
        "https://auth.example.com/auth/wire?value=first&value=a%2Bb",
        r#"{"hello":"world"}"#,
    );
    for (name, value) in [
        ("cookie", "one=1"),
        ("cookie", "two=2"),
        ("x-repeated", "one"),
        ("x-repeated", "two"),
    ] {
        let _ = req.headers_mut().append(name, value.parse()?);
    }
    let response = app.get_response(req).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["a=one; Path=/; HttpOnly", "b=two; Path=/; HttpOnly"]
    );
    assert_eq!(
        response
            .headers()
            .get_all("x-reply")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    let body: serde_json::Value = response.into_body().into_json().await?;
    assert_eq!(
        body,
        json!({"path":"/wire","method":"Patch","url":"https://auth.example.com/auth/wire?value=first&value=a%2Bb","query":"a+b","cookie":"one=1; two=2","repeated":"one, two","body":{"hello":"world"}})
    );
    assert_eq!(
        app.get_response(request(Method::POST, "/auth/wire", "{}"))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.get_response(request(Method::PATCH, "/auth/wire", "x".repeat(129)))
            .await
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut req = request(Method::PATCH, "/auth/wire", "{}");
    let _ = req
        .headers_mut()
        .insert("origin", "https://evil.example".parse()?);
    let _ = req.headers_mut().insert("cookie", "one=1; two=2".parse()?);
    assert_eq!(app.get_response(req).await.status(), StatusCode::FORBIDDEN);
    drop(app);
    drop(auth);
    B::close(connection).await
}

async fn denied_session<S: AuthSchema>(auth: &Arc<alibi::Alibi<S>>, cookie: &str) -> TestResult {
    let mut req = request(Method::GET, "/profile", ());
    let _ = req.headers_mut().insert("cookie", cookie.parse()?);
    req.set_data(auth.clone());
    let (req, mut body) = req.split();
    assert_eq!(
        CurrentSession::<S>::from_request(&req, &mut body)
            .await
            .err()
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        OptionalSession::<S>::from_request(&req, &mut body)
            .await?
            .0
            .is_none()
    );
    Ok(())
}

async fn sessions<B: Backend>(db: Db) -> TestResult {
    let (connection, store) = db.migrated::<B>(&config().secret).await?;
    let auth = Arc::new(
        AuthBuilder::<B::Schema>::new(config())
            .store(store)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?,
    );
    let app = Route::new().nest("/auth", auth.clone().poem_endpoint());
    let response = app
        .get_response(request(
            Method::POST,
            "/auth/sign-up/email",
            json!({"email":"poem@example.com","password":"password123","name":"Poem"}).to_string(),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("__Secure-better-auth.session_token="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let body: serde_json::Value = response.into_body().into_json().await?;
    let user_id = body["user"]["id"].as_str().unwrap();
    let token = body["token"].as_str().unwrap();
    denied_session(&auth, "__Secure-better-auth.session_token=bad-signature").await?;
    let foreign = alibi::utils::cookie_utils::sign_cookie_value(
        token,
        "foreign-secret-with-at-least-32-characters",
    );
    denied_session(
        &auth,
        &format!("__Secure-better-auth.session_token={foreign}"),
    )
    .await?;

    assert!(auth.store().get_user_by_id(user_id).await?.is_some());
    let mut req = request(Method::GET, "/profile", ());
    let _ = req.headers_mut().insert("cookie", cookie.parse()?);
    req.set_data(auth.clone());
    let (req, mut body) = req.split();
    let session = CurrentSession::<B::Schema>::from_request(&req, &mut body).await?;
    assert_eq!(session.user.id(), user_id);
    assert!(
        OptionalSession::<B::Schema>::from_request(&req, &mut body)
            .await?
            .0
            .is_some()
    );
    auth.store()
        .update_session_expiry(token, chrono::Utc::now() - chrono::Duration::seconds(60))
        .await?;
    denied_session(&auth, &cookie).await?;
    // Sign out a newly issued, unexpired session. Reusing the expired session
    // above would make this denial pass even if signout never revoked anything.
    let signed_in = app
        .get_response(request(
            Method::POST,
            "/auth/sign-in/email",
            json!({"email":"poem@example.com","password":"password123"}).to_string(),
        ))
        .await;
    assert_eq!(signed_in.status(), StatusCode::OK);
    let cookie = signed_in
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|header| header.to_str().ok())
        .find(|header| header.starts_with("__Secure-better-auth.session_token="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let fresh: serde_json::Value = signed_in.into_body().into_json().await?;
    let fresh_token = fresh["token"].as_str().unwrap();
    assert!(auth.store().get_session(fresh_token).await?.is_some());
    let mut req = request(Method::GET, "/profile", ());
    let _ = req.headers_mut().insert("cookie", cookie.parse()?);
    req.set_data(auth.clone());
    let (req, mut body) = req.split();
    assert_eq!(
        CurrentSession::<B::Schema>::from_request(&req, &mut body)
            .await?
            .user
            .id(),
        user_id
    );
    let mut req = request(Method::POST, "/auth/sign-out", "{}");
    let _ = req.headers_mut().insert("cookie", cookie.parse()?);
    assert_eq!(app.get_response(req).await.status(), StatusCode::OK);
    assert!(auth.store().get_session(fresh_token).await?.is_none());
    let mut req = request(Method::GET, "/profile", ());
    let _ = req.headers_mut().insert("cookie", cookie.parse()?);
    req.set_data(auth.clone());
    let (req, mut body) = req.split();
    assert_eq!(
        CurrentSession::<B::Schema>::from_request(&req, &mut body)
            .await
            .err()
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        OptionalSession::<B::Schema>::from_request(&req, &mut body)
            .await?
            .0
            .is_none()
    );
    drop(app);
    drop(auth);
    B::close(connection).await
}

async fn disconnect_continues_persistence<B: Backend>(db: Db) -> TestResult {
    let (connection, store) = db.migrated::<B>(&config().secret).await?;
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let finished = Arc::new(Notify::new());
    let auth = Arc::new(
        AuthBuilder::<B::Schema>::new(config())
            .store(store)
            .plugin(Probe {
                entered: entered.clone(),
                release: release.clone(),
                finished: finished.clone(),
            })
            .build()
            .await?,
    );
    let endpoint = auth.clone().poem_endpoint();
    let task = tokio::spawn(async move {
        endpoint
            .get_response(request(Method::POST, "/persist", "{}"))
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), entered.notified()).await?;
    task.abort();
    let _ = task.await;
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), finished.notified()).await?;
    assert_eq!(
        auth.store()
            .get_user_by_email("disconnect@example.com")
            .await?
            .unwrap()
            .name(),
        Some("completed")
    );
    drop(auth);
    B::close(connection).await
}
backend_tests!(
    wire_and_authority,
    sessions,
    disconnect_continues_persistence
);

postgres_tests!(
    wire_and_authority,
    sessions,
    disconnect_continues_persistence
);
