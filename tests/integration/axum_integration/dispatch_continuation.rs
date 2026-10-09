//! Transport ownership is independent of plugin lifecycle ordering, proved by the SDK owners.

use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::{BodyLimitConfig, CsrfConfig, Middleware, RateLimitConfig};
use alibi::seaorm::{Database, SeaOrmStore};
use alibi::store::UserStore;
use alibi::{AuthBuilder, AuthConfig, BetterAuth};
use alibi::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, CreateUser,
    UpdateUser,
};
use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
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

type Schema = alibi::seaorm::store::__private_test_support::bundled_schema::BundledSchema;

#[derive(Default)]
struct Observations {
    entered: Notify,
    release: Notify,
    finished: Notify,
    dropped: Notify,
    calls: AtomicUsize,
    completions: AtomicUsize,
    phases: Mutex<Vec<&'static str>>,
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
        self.0.phases.lock().unwrap().push("handler");
        let _previous = self.0.calls.fetch_add(1, Ordering::SeqCst);
        assert!(req.path() != "/panic", "private application panic detail");
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
        let context = alibi::hooks::current_request_hook_context().unwrap();
        self.0.contexts.lock().unwrap().push((
            context.path,
            (*(context.headers)
                .get("user-agent")
                .expect("fixture contains the requested index"))
            .clone(),
            tracing::Span::current()
                .metadata()
                .map(|m| m.name().to_owned())
                .unwrap_or_default(),
        ));
        drop(
            ctx.database
                .update_user(
                    &user.id,
                    UpdateUser {
                        name: Some("completed".into()),
                        ..Default::default()
                    },
                )
                .await?,
        );
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
        self.0.phases.lock().unwrap().push("plugin-after");
        let _previous = self.0.completions.fetch_add(1, Ordering::SeqCst);
        self.0.finished.notify_one();
        Ok(response.with_header("x-after-hook", "complete"))
    }
}

struct OrderedMiddleware {
    observations: Arc<Observations>,
    before: &'static str,
    after: &'static str,
}

#[async_trait]
impl Middleware for OrderedMiddleware {
    fn name(&self) -> &'static str {
        self.before
    }
    async fn before_request(&self, req: &AuthRequest) -> AuthResult<Option<AuthResponse>> {
        self.observations.phases.lock().unwrap().push(self.before);
        if self.before == "first-before" {
            match req.header("x-middleware-policy").map(String::as_str) {
                Some("stop") => {
                    return Ok(Some(
                        AuthResponse::new(418).with_header("x-policy", "stopped"),
                    ));
                }
                Some("before-error") => {
                    return Err(alibi::AuthError::forbidden("middleware denied"));
                }
                _ => {}
            }
        }
        Ok(None)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        self.observations.phases.lock().unwrap().push(self.after);
        if self.after == "second-after"
            && req.header("x-middleware-policy").map(String::as_str) == Some("after-error")
        {
            return Err(alibi::AuthError::forbidden("middleware after failed"));
        }
        response.headers.append("x-middleware", self.after);
        Ok(response)
    }
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
    database: alibi::seaorm::DatabaseConnection,
) -> (Arc<BetterAuth<Schema>>, Arc<SeaOrmStore<Schema>>) {
    alibi::seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let config =
        AuthConfig::new("native-transport-continuation-secret-32-chars").base_path("/auth");
    let store = Arc::new(SeaOrmStore::new(config.clone(), database));
    let auth = AuthBuilder::<Schema>::new(config)
        .store_arc(Arc::<SeaOrmStore<_>>::clone(&store))
        .body_limit(BodyLimitConfig::new().max_bytes(256))
        .csrf(CsrfConfig::new().enabled(false))
        .rate_limit(RateLimitConfig::new().enabled(false))
        .middleware(OrderedMiddleware {
            observations: Arc::clone(&observations),
            before: "first-before",
            after: "first-after",
        })
        .middleware(OrderedMiddleware {
            observations: Arc::clone(&observations),
            before: "second-before",
            after: "second-after",
        })
        .plugin(Application(observations))
        .build()
        .await
        .unwrap();
    (Arc::new(auth), store)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_construction_is_lazy_and_completed_router_can_move_between_runtimes() {
        struct DatabaseFile(std::path::PathBuf);

        impl Drop for DatabaseFile {
            fn drop(&mut self) {
                drop(std::fs::remove_file(&self.0));
            }
        }

        let runtime = tokio::runtime::Runtime::new().unwrap();
        // SQLite memory databases can vanish when runtime shutdown closes the
        // final pooled connection. Keep this transport owner independent of that
        // database lifetime by using an isolated, persisted file.

        let database_file = DatabaseFile(std::env::temp_dir().join(format!(
            "better-auth-router-runtime-{}.sqlite",
            uuid::Uuid::new_v4()
        )));
        let (auth, evaluated_store) = runtime.block_on(async {
            let database =
                Database::connect(format!("sqlite://{}?mode=rwc", database_file.0.display()))
                    .await
                    .unwrap();
            auth_with_database(Arc::default(), database).await
        });
        assert!(tokio::runtime::Handle::try_current().is_err());
        let router = Router::new()
            .nest("/auth", Arc::clone(&auth).axum_router())
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
                .block_on(
                    evaluated_store.get_user_by_email("second-runtime@transport.fixture.test")
                )
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
        let (auth, store) = auth(Arc::clone(&observations)).await;
        let weak = Arc::downgrade(&auth);
        let router = Arc::clone(&auth)
            .axum_router()
            .with_state(Arc::clone(&auth));
        drop(auth);
        let router =
            Router::new()
                .nest("/auth", router)
                .layer(axum::middleware::from_fn_with_state(
                    Arc::clone(&observations),
                    observe,
                ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, stop) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    _ = stop.await;
                })
                .await
                .unwrap();
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
    async fn live_dispatch_keeps_repeated_headers_context_and_tracing_and_isolates_application_panic()
     {
        let observations = Arc::new(Observations::default());
        let (auth, store) = auth(Arc::clone(&observations)).await;
        let router = Router::new()
            .nest("/auth", Arc::clone(&auth).axum_router())
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
                .get_all("x-middleware")
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["second-after", "first-after"]
        );
        assert_eq!(
            *observations.phases.lock().unwrap(),
            vec![
                "first-before",
                "second-before",
                "handler",
                "plugin-after",
                "second-after",
                "first-after"
            ]
        );
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
        let (auth, store) = auth(Arc::clone(&observations)).await;
        let router = Router::new()
            .nest("/auth", Arc::clone(&auth).axum_router())
            .with_state(auth)
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&observations),
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
                    _ = stop.await;
                })
                .await
                .unwrap();
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

    #[tokio::test]
    async fn native_request_cancellation_and_detached_observer_preserve_actual_ownership() {
        use alibi::HttpMethod;

        for mode in ["cancel", "detach", "connected"] {
            let observations = Arc::new(Observations::default());
            let (auth, store) = auth(Arc::clone(&observations)).await;
            let email = format!("{mode}@example.test");
            let input = AuthRequest::from_parts(
                HttpMethod::Post,
                "/auth/transport".into(),
                std::collections::HashMap::from([
                    ("content-type".into(), "application/json".into()),
                    ("user-agent".into(), "actual-native-agent".into()),
                ]),
                Some(serde_json::json!({"email": email}).to_string().into_bytes()),
                std::collections::HashMap::from([("pause".into(), "yes".into())]),
            );
            let task = tokio::spawn(async move { auth.handle_request(input).await.unwrap() });
            bounded(&observations.entered).await;
            assert_eq!(
                store
                    .get_user_by_email(&email)
                    .await
                    .unwrap()
                    .unwrap()
                    .name
                    .as_deref(),
                Some("started")
            );
            if mode == "cancel" {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
                observations.release.notify_one();
                assert_eq!(
                    store
                        .get_user_by_email(&email)
                        .await
                        .unwrap()
                        .unwrap()
                        .name
                        .as_deref(),
                    Some("started")
                );
                assert_eq!(observations.completions.load(Ordering::SeqCst), 0);
                assert!(observations.contexts.lock().unwrap().is_empty());
                assert_eq!(
                    *observations.phases.lock().unwrap(),
                    vec!["first-before", "second-before", "handler"]
                );
            } else {
                if mode == "detach" {
                    // Dropping a real JoinHandle loses the observer, but retains the owned task.
                    drop(task);
                    observations.release.notify_one();
                } else {
                    observations.release.notify_one();
                    let response = task.await.unwrap();
                    assert_eq!(response.status, 201);
                    assert_eq!(
                        response.headers.get("x-after-hook").map(String::as_str),
                        Some("complete")
                    );
                    assert_eq!(
                        response.headers.get_all("set-cookie").collect::<Vec<_>>(),
                        vec![
                            "first=one; Path=/; HttpOnly",
                            "second=two; Path=/; HttpOnly"
                        ]
                    );
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&response.body).unwrap(),
                        serde_json::json!({"email": email, "name":"completed"})
                    );
                    assert_eq!(
                        *observations.phases.lock().unwrap(),
                        vec![
                            "first-before",
                            "second-before",
                            "handler",
                            "plugin-after",
                            "second-after",
                            "first-after"
                        ]
                    );
                }
                bounded(&observations.finished).await;
                assert_eq!(
                    store
                        .get_user_by_email(&email)
                        .await
                        .unwrap()
                        .unwrap()
                        .name
                        .as_deref(),
                    Some("completed")
                );
                assert_eq!(observations.completions.load(Ordering::SeqCst), 1);
                let context = observations.contexts.lock().unwrap();
                assert_eq!(context.first().unwrap().0, "/auth/transport");
                assert_eq!(context.first().unwrap().1, "actual-native-agent");
            }
        }
    }
}

#[tokio::test]
async fn application_middleware_short_circuits_and_errors_preserve_dispatch_effects() {
    for (mode, expected, written) in [
        ("stop", 418, false),
        ("before-error", 403, false),
        ("after-error", 403, true),
    ] {
        let observations = Arc::new(Observations::default());
        let (auth, store) = auth(observations.clone()).await;
        let router = Router::new()
            .nest("/auth", auth.clone().axum_router())
            .with_state(auth);
        let mut input = request("/auth/transport", "middleware@example.test");
        drop(
            input
                .headers_mut()
                .insert("x-middleware-policy", mode.parse().unwrap()),
        );
        let response = router.oneshot(input).await.unwrap();
        assert_eq!(response.status().as_u16(), expected);
        let stored = store
            .get_user_by_email("middleware@example.test")
            .await
            .unwrap();
        assert_eq!(stored.is_some(), written);
        if written {
            assert_eq!(stored.unwrap().name.as_deref(), Some("completed"));
            assert_eq!(
                *observations.phases.lock().unwrap(),
                [
                    "first-before",
                    "second-before",
                    "handler",
                    "plugin-after",
                    "second-after"
                ]
            );
            assert!(response.headers().get("set-cookie").is_none());
        } else {
            assert_eq!(
                *observations.phases.lock().unwrap(),
                ["first-before", "second-after", "first-after"]
            );
            assert_eq!(
                response
                    .headers()
                    .get_all("x-middleware")
                    .iter()
                    .map(|value| value.to_str().unwrap())
                    .collect::<Vec<_>>(),
                ["second-after", "first-after"]
            );
            if mode == "stop" {
                assert_eq!(response.headers()["x-policy"], "stopped");
            }
        }
    }
}
