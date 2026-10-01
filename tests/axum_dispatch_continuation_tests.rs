//! Transport ownership is independent of plugin lifecycle ordering, proved by the SDK owners.
#![cfg(feature = "axum")]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "real transport/state assertions and deliberate application panic"
)]
use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::middleware::{BodyLimitConfig, CsrfConfig, RateLimitConfig};
use better_auth_core::store::UserStore;
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, CreateUser,
    UpdateUser,
};
use better_auth_seaorm::{Database, SeaOrmStore};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Notify, oneshot},
};
use tower::ServiceExt;
use tracing::{Instrument, instrument::WithSubscriber};
type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
#[derive(Default)]
struct Observations {
    entered: Notify,
    release: Notify,
    finished: Notify,
    dropped: Notify,
    calls: AtomicUsize,
    contexts: Mutex<Vec<(String, String, String)>>,
}
struct Application(Arc<Observations>);
#[async_trait]
impl AuthPlugin<Schema> for Application {
    fn name(&self) -> &'static str {
        "transport-application"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/transport", "transport"),
            AuthRoute::post("/panic", "panic"),
        ]
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<Schema>,
    ) -> AuthResult<Option<AuthResponse>> {
        let _previous = self.0.calls.fetch_add(1, Ordering::SeqCst);
        if req.path() == "/panic" {
            panic!("private application panic detail");
        }
        let body: serde_json::Value = req.body_as_json()?;
        let email = body.get("email").unwrap().as_str().unwrap();
        let user = ctx
            .database
            .create_user(CreateUser::new().with_email(email).with_name("started"))
            .await?;
        if req.query.get("pause").map(String::as_str) == Some("yes") {
            self.0.entered.notify_one();
            self.0.release.notified().await;
        }
        let context = better_auth_core::hooks::current_request_hook_context().unwrap();
        self.0.contexts.lock().unwrap().push((
            context.path,
            context.headers.get("user-agent").unwrap().clone(),
            tracing::Span::current()
                .metadata()
                .map(|m| m.name().to_owned())
                .unwrap_or_default(),
        ));
        let _ = ctx
            .database
            .update_user(
                &user.id,
                UpdateUser {
                    name: Some("completed".into()),
                    ..Default::default()
                },
            )
            .await?;
        req.queue_response_header("set-cookie", "first=one; Path=/; HttpOnly");
        Ok(Some(
            AuthResponse::json(201, &serde_json::json!({"email":email,"name":"completed"}))?
                .with_header("set-cookie", "second=two; Path=/; HttpOnly")
                .with_header("x-application", "actual"),
        ))
    }
    async fn after_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        self.0.finished.notify_one();
        Ok(response.with_header("x-after-hook", "complete"))
    }
}
async fn auth(
    observations: Arc<Observations>,
) -> (Arc<BetterAuth<Schema>>, Arc<SeaOrmStore<Schema>>) {
    auth_with_database(
        observations,
        Database::connect("sqlite::memory:").await.unwrap(),
    )
    .await
}
async fn auth_with_database(
    observations: Arc<Observations>,
    database: better_auth_seaorm::DatabaseConnection,
) -> (Arc<BetterAuth<Schema>>, Arc<SeaOrmStore<Schema>>) {
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let config =
        AuthConfig::new("native-transport-continuation-secret-32-chars").base_path("/auth");
    let store = Arc::new(SeaOrmStore::new(config.clone(), database));
    let auth = AuthBuilder::<Schema>::new(config)
        .store_arc(store.clone())
        .body_limit(BodyLimitConfig::new().max_bytes(256))
        .csrf(CsrfConfig::new().enabled(false))
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(Application(observations))
        .build()
        .await
        .unwrap();
    (Arc::new(auth), store)
}
struct DropReceipt {
    observations: Arc<Observations>,
    completed: bool,
}
impl Drop for DropReceipt {
    fn drop(&mut self) {
        if !self.completed {
            self.observations.dropped.notify_one();
        }
    }
}
async fn observe(
    State(observations): State<Arc<Observations>>,
    request: Request,
    next: Next,
) -> Response {
    let mut guard = DropReceipt {
        observations,
        completed: false,
    };
    let response = next.run(request).await;
    guard.completed = true;
    response
}
async fn bounded(notify: &Notify) {
    tokio::time::timeout(Duration::from_secs(2), notify.notified())
        .await
        .expect("actual event was not received");
}
fn request(path: &str, email: &str) -> Request {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("user-agent", "actual-native-agent")
        .body(Body::from(serde_json::json!({"email":email}).to_string()))
        .unwrap()
}
#[test]
fn router_construction_is_lazy_and_completed_router_can_move_between_runtimes() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    // SQLite memory databases can vanish when runtime shutdown closes the
    // final pooled connection. Keep this transport owner independent of that
    // database lifetime by using an isolated, persisted file.
    struct DatabaseFile(std::path::PathBuf);
    impl Drop for DatabaseFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let database_file = DatabaseFile(std::env::temp_dir().join(format!(
        "better-auth-router-runtime-{}.sqlite",
        uuid::Uuid::new_v4()
    )));
    let (auth, _store) = runtime.block_on(async {
        let database =
            Database::connect(format!("sqlite://{}?mode=rwc", database_file.0.display()))
                .await
                .unwrap();
        auth_with_database(Arc::default(), database).await
    });
    assert!(tokio::runtime::Handle::try_current().is_err());
    let router = Router::new()
        .nest("/auth", auth.clone().axum_router())
        .with_state(auth);
    let first = runtime
        .block_on(router.clone().oneshot(request(
            "/auth/transport",
            "first-runtime@transport.fixture.test",
        )))
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    drop(runtime);
    let next_runtime = tokio::runtime::Runtime::new().unwrap();
    let second = next_runtime
        .block_on(router.oneshot(request(
            "/auth/transport",
            "second-runtime@transport.fixture.test",
        )))
        .unwrap();
    let second_status = second.status();
    let second_body = next_runtime
        .block_on(axum::body::to_bytes(second.into_body(), 4096))
        .unwrap();
    assert_eq!(
        second_status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&second_body)
    );
    assert_eq!(
        next_runtime
            .block_on(_store.get_user_by_email("second-runtime@transport.fixture.test"))
            .unwrap()
            .unwrap()
            .name
            .as_deref(),
        Some("completed")
    );
}
#[tokio::test]
async fn accepted_dispatch_survives_real_disconnect_and_router_drop_then_releases_ownership() {
    let observations = Arc::new(Observations::default());
    let (auth, store) = auth(observations.clone()).await;
    let weak = Arc::downgrade(&auth);
    let router = auth.clone().axum_router().with_state(auth.clone());
    drop(auth);
    let router = Router::new()
        .nest("/auth", router)
        .layer(axum::middleware::from_fn_with_state(
            observations.clone(),
            observe,
        ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, stop) = oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stop.await;
            })
            .await
            .unwrap()
    });
    let mut socket = TcpStream::connect(address).await.unwrap();
    let body = r#"{"email":"disconnected@transport.fixture.test"}"#;
    socket.write_all(format!("POST /auth/transport?pause=yes HTTP/1.1\r\nHost: {address}\r\nUser-Agent: actual-native-agent\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
    bounded(&observations.entered).await;
    assert_eq!(
        store
            .get_user_by_email("disconnected@transport.fixture.test")
            .await
            .unwrap()
            .unwrap()
            .name
            .as_deref(),
        Some("started")
    );
    drop(socket);
    bounded(&observations.dropped).await;
    shutdown.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert!(
        weak.upgrade().is_some(),
        "accepted worker must retain auth after server/router drop"
    );
    observations.release.notify_one();
    bounded(&observations.finished).await;
    assert_eq!(
        store
            .get_user_by_email("disconnected@transport.fixture.test")
            .await
            .unwrap()
            .unwrap()
            .name
            .as_deref(),
        Some("completed")
    );
    assert_eq!(observations.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        observations.contexts.lock().unwrap().first().unwrap().0,
        "/transport"
    );
    assert_eq!(
        observations.contexts.lock().unwrap().first().unwrap().1,
        "actual-native-agent"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed dispatch retained an auth ownership cycle");
}
#[tokio::test]
async fn live_dispatch_keeps_repeated_headers_context_and_tracing_and_isolates_application_panic() {
    let observations = Arc::new(Observations::default());
    let (auth, store) = auth(observations.clone()).await;
    let router = Router::new()
        .nest("/auth", auth.clone().axum_router())
        .with_state(auth);
    let dispatch = tracing::Dispatch::new(tracing_subscriber::registry());
    let span =
        tracing::dispatcher::with_default(&dispatch, || tracing::info_span!("native-dispatch"));
    let response = router
        .clone()
        .oneshot(request(
            "/auth/transport?original=yes",
            "live@transport.fixture.test",
        ))
        .instrument(span)
        .with_subscriber(dispatch)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["x-application"], "actual");
    assert_eq!(response.headers()["x-after-hook"], "complete");
    assert_eq!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "first=one; Path=/; HttpOnly",
            "second=two; Path=/; HttpOnly"
        ]
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &axum::body::to_bytes(response.into_body(), 256)
                .await
                .unwrap()
        )
        .unwrap(),
        serde_json::json!({"email":"live@transport.fixture.test","name":"completed"})
    );
    assert_eq!(
        *observations.contexts.lock().unwrap().first().unwrap(),
        (
            "/transport".into(),
            "actual-native-agent".into(),
            "native-dispatch".into()
        )
    );
    let panic = router
        .clone()
        .oneshot(request("/auth/panic", "panic@transport.fixture.test"))
        .await
        .unwrap();
    assert_eq!(panic.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(panic.into_body(), 1024).await.unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("private application panic detail"));
    assert!(
        store
            .get_user_by_email("panic@transport.fixture.test")
            .await
            .unwrap()
            .is_none()
    );
    let next = router
        .oneshot(request("/auth/transport", "next@transport.fixture.test"))
        .await
        .unwrap();
    assert_eq!(next.status(), StatusCode::CREATED);
    assert_eq!(
        store
            .get_user_by_email("next@transport.fixture.test")
            .await
            .unwrap()
            .unwrap()
            .name
            .as_deref(),
        Some("completed")
    );
}
#[tokio::test]
async fn incomplete_and_over_limit_bodies_never_enter_supervised_dispatch() {
    let observations = Arc::new(Observations::default());
    let (auth, store) = auth(observations.clone()).await;
    let router = Router::new()
        .nest("/auth", auth.clone().axum_router())
        .with_state(auth)
        .layer(axum::middleware::from_fn_with_state(
            observations.clone(),
            observe,
        ));
    let over = Request::builder()
        .method("POST")
        .uri("/auth/transport")
        .body(Body::from(vec![b'x'; 257]))
        .unwrap();
    let response = router.clone().oneshot(over).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let control = router.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, stop) = oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stop.await;
            })
            .await
            .unwrap()
    });
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket
        .write_all(
            format!(
                "POST /auth/transport HTTP/1.1\r\nHost: {address}\r\nContent-Length: 100\r\n\r\n{{",
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    socket.shutdown().await.unwrap();
    let mut result = Vec::new();
    let _read = tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut result))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observations.calls.load(Ordering::SeqCst), 0);
    let valid = control
        .oneshot(request(
            "/auth/transport",
            "body-control@transport.fixture.test",
        ))
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::CREATED);
    assert_eq!(observations.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .get_user_by_email("body-control@transport.fixture.test")
            .await
            .unwrap()
            .unwrap()
            .name
            .as_deref(),
        Some("completed")
    );
    shutdown.send(()).unwrap();
    server.await.unwrap();
}
