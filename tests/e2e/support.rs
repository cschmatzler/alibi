use async_trait::async_trait;
use axum::{Json, Router, routing::get};
use better_auth::integrations::axum::{AxumIntegration, CurrentSession};
use better_auth::plugins::{
    EmailPasswordPlugin, PasswordManagementPlugin, SessionManagementPlugin,
    password_management::SendResetPassword,
};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_core::{
    AuthSchema, AuthUser,
    store::{AuthStore, SchemaMigrator},
};
use better_auth_sqlx::{SqlxStore, sqlx::sqlite::SqlitePoolOptions};
use reqwest::{
    Client, RequestBuilder, Response, StatusCode,
    cookie::{CookieStore, Jar},
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

#[derive(Clone, Copy)]
pub(super) enum Backend {
    Sqlx,
    SeaOrm,
}
enum Connection {
    Sqlx(better_auth_sqlx::sqlx::SqlitePool),
    SeaOrm(better_auth_seaorm::DatabaseConnection),
}

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub(super) const PASSWORD: &str = "original-password-123";

pub(super) struct Delivery {
    pub(super) user: Value,
    pub(super) url: String,
}

struct Mailbox(mpsc::UnboundedSender<Delivery>);

#[async_trait]
impl SendResetPassword for Mailbox {
    async fn send(&self, user: &Value, url: &str, _token: &str) -> AuthResult<()> {
        self.0
            .send(Delivery {
                user: user.clone(),
                url: url.into(),
            })
            .map_err(|error| better_auth::AuthError::internal(error.to_string()))
    }
}

pub(super) struct Server {
    pub(super) origin: String,
    mailbox: mpsc::UnboundedReceiver<Delivery>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<std::io::Result<()>>>,
    pool: Connection,
}

impl Server {
    pub(super) async fn start(backend: Backend) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let config =
            AuthConfig::new("native-e2e-secret-with-at-least-32-characters").base_url(&origin);
        match backend {
            Backend::Sqlx => {
                type Schema =
                    better_auth_sqlx::store::__private_test_support::bundled_schema::BundledSchema;
                let pool = SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect("sqlite::memory:")
                    .await?;
                let store = SqlxStore::<Schema>::new(config.clone(), pool.clone());
                store.migrate().await?;
                Self::serve(listener, origin, config, store, Connection::Sqlx(pool)).await
            }
            Backend::SeaOrm => {
                type Schema=better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
                let pool = better_auth_seaorm::Database::connect("sqlite::memory:").await?;
                let store =
                    better_auth_seaorm::SeaOrmStore::<Schema>::new(config.clone(), pool.clone());
                store.migrate().await?;
                Self::serve(listener, origin, config, store, Connection::SeaOrm(pool)).await
            }
        }
    }
    async fn serve<S: AuthSchema>(
        listener: TcpListener,
        origin: String,
        config: AuthConfig,
        store: impl AuthStore<S> + 'static,
        pool: Connection,
    ) -> TestResult<Self> {
        let (send, mailbox) = mpsc::unbounded_channel();
        let auth = Arc::new(
            AuthBuilder::new(config)
                .store(store)
                .plugin(EmailPasswordPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(
                    PasswordManagementPlugin::new()
                        .send_reset_password(Arc::new(Mailbox(send)))
                        .revoke_sessions_on_password_reset(true),
                )
                .build()
                .await?,
        );
        async fn private<S: AuthSchema>(session: CurrentSession<S>) -> Json<Value> {
            Json(json!({"userId":session.user.id()}))
        }
        let router = Router::new()
            .nest("/api/auth", Arc::clone(&auth).axum_router())
            .route("/private", get(private::<S>))
            .with_state(auth);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
        });
        Ok(Self {
            origin,
            mailbox,
            stop: Some(stop),
            task: Some(task),
            pool,
        })
    }

    pub(super) async fn delivery(&mut self) -> TestResult<Delivery> {
        Ok(
            tokio::time::timeout(Duration::from_secs(5), self.mailbox.recv())
                .await?
                .ok_or("mailbox closed")?,
        )
    }

    pub(super) async fn shutdown(mut self) -> TestResult {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(mut task) = self.task.take() {
            match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
                Ok(result) => result??,
                Err(error) => {
                    task.abort();
                    return Err(error.into());
                }
            }
        }
        match &self.pool {
            Connection::Sqlx(pool) => pool.close().await,
            Connection::SeaOrm(pool) => pool.clone().close().await?,
        }
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // Also release the listener on a failed assertion; no detached test servers.
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub(super) struct Browser {
    pub(super) client: Client,
    origin: String,
    jar: Arc<Jar>,
}

impl Browser {
    pub(super) fn new(server: &Server) -> TestResult<Self> {
        let jar = Arc::new(Jar::default());
        let client = Client::builder()
            .no_proxy()
            .cookie_provider(Arc::clone(&jar))
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            origin: server.origin.clone(),
            jar,
        })
    }

    pub(super) fn get(&self, path: &str) -> RequestBuilder {
        self.client.get(format!("{}{path}", self.origin))
    }

    pub(super) fn post(&self, path: &str, body: Value) -> RequestBuilder {
        self.client
            .post(format!("{}{path}", self.origin))
            .header("origin", &self.origin)
            .json(&body)
    }

    pub(super) fn cookies(&self) -> TestResult<reqwest::header::HeaderValue> {
        Ok(self
            .jar
            .cookies(&url::Url::parse(&self.origin)?)
            .ok_or("no cookies")?)
    }

    pub(super) async fn json(response: Response, expected: StatusCode) -> TestResult<Value> {
        let status = response.status();
        let body = response.text().await?;
        assert_eq!(status, expected, "{body}");
        Ok(serde_json::from_str(&body)?)
    }

    pub(super) async fn signup(&self, email: &str) -> TestResult<Value> {
        Self::json(
            self.post(
                "/api/auth/sign-up/email",
                json!({"email":email, "password":PASSWORD, "name":"Native user"}),
            )
            .send()
            .await?,
            StatusCode::OK,
        )
        .await
    }

    pub(super) async fn profile(&self) -> TestResult<Value> {
        Self::json(self.get("/private").send().await?, StatusCode::OK).await
    }
}
