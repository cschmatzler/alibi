#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
//! Transport ownership is independent of plugin lifecycle ordering, proved by the SDK owners.
#![cfg(feature = "axum")]

#[cfg(test)]
#[path = "axum_dispatch_continuation_tests/tests.rs"]
mod tests;

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
        let context = better_auth_core::hooks::current_request_hook_context().unwrap();
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
        self.0.finished.notify_one();
        Ok(response.with_header("x-after-hook", "complete"))
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
    database: better_auth_seaorm::DatabaseConnection,
) -> (Arc<BetterAuth<Schema>>, Arc<SeaOrmStore<Schema>>) {
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
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
