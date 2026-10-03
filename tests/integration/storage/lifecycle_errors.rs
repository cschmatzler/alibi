//! HTTP callback failures must not publish queued headers after a committed write.
use super::{Backend, Db, TestResult, backend_tests};
use async_trait::async_trait;
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, CreateUser, HttpMethod,
};
use std::sync::{Arc, Mutex};

backend_tests!(
    endpoint_callback_errors_drop_headers_without_reversing_writes,
    configured_endpoint_hooks_apply_to_http_before_plugin_hooks
);

struct Writer;

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Writer {
    fn name(&self) -> &'static str {
        "committing-writer"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/callback-error", "callbackError")]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let mode = req.headers.get("x-mode").map_or("success", String::as_str);
        if mode == "success" {
            return Ok(Some(AuthResponse::new(204)));
        }
        _ = ctx
            .database
            .create_user(CreateUser::new().with_email(format!("{mode}@lifecycle.fixture.test")))
            .await?;
        req.queue_response_header("x-queued", "private-header");
        req.queue_response_header("set-cookie", "queued=value; HttpOnly; Path=/");
        req.queue_response_header("set-cookie", "second=value; HttpOnly; Path=/");
        if mode == "api" {
            Err(AuthError::forbidden("explicit"))
        } else {
            Err(AuthError::CallbackFailure(Box::new(AuthError::internal(
                "private application cause",
            ))))
        }
    }
}

struct Observer(Arc<Mutex<Vec<u16>>>);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Observer {
    fn name(&self) -> &'static str {
        "completed-observer"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }

    async fn after_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        self.0.lock().expect("observer mutex").push(response.status);
        Ok(response)
    }
}

async fn endpoint_callback_errors_drop_headers_without_reversing_writes<B: Backend>(
    db: Db,
) -> TestResult {
    let secret = "lifecycle181-native-callback-secret-32";
    let (connection, store) = db.migrated::<B>(secret).await?;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let auth = AuthBuilder::<B::Schema>::new(AuthConfig::new(secret))
        .store(store)
        .plugin(Writer)
        .plugin(Observer(Arc::clone(&observed)))
        .build()
        .await?;
    for mode in ["api", "ordinary", "success"] {
        let mut req = AuthRequest::new(HttpMethod::Get, "/api/auth/callback-error");
        _ = req.headers.insert("x-mode".into(), mode.into());
        let response = auth.handle_request(req).await?;
        if mode != "success" {
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM users WHERE email = $1",
                    &[&format!("{mode}@lifecycle.fixture.test")]
                )
                .await?,
                1,
                "callback failure must not undo the committed user"
            );
        }
        eprintln!(
            "{}",
            serde_json::json!({
                "backend": std::any::type_name::<B>(), "mode": mode,
                "status": response.status, "headers": response.headers.clone().into_iter().collect::<Vec<_>>(),
                "body": String::from_utf8_lossy(&response.body), "users": db.count("users").await?,
                "after": *observed.lock().expect("observer mutex"),
            })
        );
        if mode == "api" {
            assert_eq!(response.status, 403);
            assert_eq!(
                response.headers.get("x-queued").map(String::as_str),
                Some("private-header")
            );
            assert_eq!(response.headers.get_all("set-cookie").count(), 2);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&response.body)?,
                serde_json::json!({"message":"explicit"})
            );
        } else {
            assert_eq!(response.status, if mode == "ordinary" { 500 } else { 204 });
            assert!(response.body.is_empty());
            assert!(
                response.headers.is_empty(),
                "{mode} must not publish queued headers: {:?}",
                response.headers
            );
        }
    }
    assert_eq!(*observed.lock().expect("observer mutex"), vec![403, 204]);
    B::close(connection).await
}

struct ConfiguredHook;
#[async_trait]
impl<S: AuthSchema> better_auth_core::endpoint::EndpointHook<S> for ConfiguredHook {
    async fn before(
        &self,
        call: &better_auth_core::endpoint::EndpointCall,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<better_auth_core::endpoint::BeforeEndpointAction>> {
        if call
            .headers()
            .and_then(|headers| headers.get("x-mode"))
            .map(String::as_str)
            == Some("ordinary")
        {
            return Ok(Some(
                better_auth_core::endpoint::BeforeEndpointAction::Respond(
                    better_auth_core::endpoint::EndpointResponse::json(
                        &serde_json::json!({"stopped":true}),
                    )?,
                ),
            ));
        }
        Ok(None)
    }
    async fn after(
        &self,
        _call: &better_auth_core::endpoint::EndpointCall,
        _ctx: &AuthContext<S>,
        response: better_auth_core::endpoint::EndpointResponse,
    ) -> AuthResult<better_auth_core::endpoint::EndpointResponse> {
        Ok(response.with_header("x-global", "observed"))
    }
}

async fn configured_endpoint_hooks_apply_to_http_before_plugin_hooks<B: Backend>(
    db: Db,
) -> TestResult {
    let secret = "close181-configured-hook-secret-32";
    let (connection, store) = db.migrated::<B>(secret).await?;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let auth = AuthBuilder::<B::Schema>::new(AuthConfig::new(secret))
        .store(store)
        .endpoint_hook(ConfiguredHook)
        .plugin(Writer)
        .plugin(Observer(Arc::clone(&observed)))
        .build()
        .await?;
    let mut req = AuthRequest::new(HttpMethod::Get, "/api/auth/callback-error");
    _ = req.headers.insert("x-mode".into(), "ordinary".into());
    let stopped = auth.handle_request(req).await?;
    assert_eq!(
        stopped.status, 200,
        "configured global before must prevent the endpoint write"
    );
    assert_eq!(db.count("users").await?, 0);
    assert!(observed.lock().expect("observer mutex").is_empty());
    let response = auth
        .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/ok"))
        .await?;
    assert_eq!(
        response.headers.get("x-global").map(String::as_str),
        Some("observed")
    );
    assert_eq!(*observed.lock().expect("observer mutex"), vec![200]);
    B::close(connection).await
}
