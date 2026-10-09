//! HTTP callback failures must not publish queued headers after a committed write.
use super::{Backend, Db, TestResult, backend_tests};
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema};
use alibi::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, CreateUser, HttpMethod,
};
use async_trait::async_trait;
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
        vec![
            AuthRoute::get("/callback-error", "callbackError"),
            AuthRoute::post("/sign-up/email", "signUpEmail"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.path() == "/sign-up/email" {
            return alibi::plugins::EmailPasswordPlugin::new()
                .on_request(req, ctx)
                .await;
        }
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

    async fn on_http_endpoint(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<alibi::HttpEndpointResponse>> {
        let response = self.on_request(req, ctx).await?;
        Ok(response.map(|response| {
            if req.headers.get("x-mode").map(String::as_str) == Some("cache-raw") {
                alibi::HttpEndpointResponse::Raw(response)
            } else {
                alibi::HttpEndpointResponse::Value(response)
            }
        }))
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
impl<S: AuthSchema> alibi::endpoint::EndpointHook<S> for ConfiguredHook {
    async fn before(
        &self,
        call: &alibi::endpoint::EndpointCall,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<alibi::endpoint::BeforeEndpointAction>> {
        if call
            .headers()
            .and_then(|headers| headers.get("x-mode"))
            .map(String::as_str)
            == Some("ordinary")
        {
            return Ok(Some(alibi::endpoint::BeforeEndpointAction::Respond(
                alibi::endpoint::EndpointResponse::json(&serde_json::json!({"stopped":true}))?,
            )));
        }
        Ok(None)
    }
    async fn after(
        &self,
        _call: &alibi::endpoint::EndpointCall,
        _ctx: &AuthContext<S>,
        response: alibi::endpoint::EndpointResponse,
    ) -> AuthResult<alibi::endpoint::EndpointResponse> {
        Ok(response.with_header("x-global", "observed"))
    }
}

struct CacheVersion(Arc<Mutex<Vec<String>>>);
#[async_trait]
impl alibi::CookieCacheVersionResolver for CacheVersion {
    async fn resolve(&self, context: &alibi::CacheVersionContext) -> AuthResult<String> {
        let email = context
            .user()
            .email
            .clone()
            .expect("actual created email user");
        self.0
            .lock()
            .expect("cache callback receipts")
            .push(email.clone());
        let call = alibi::endpoint::current_endpoint_call_context()
            .expect("issuance belongs to the HTTP handler frame");
        call.set_response_header("x-cache-stage", "version");
        if email.starts_with("cache-api@") {
            Err(AuthError::Api {
                status: 403,
                code: None,
                message: "cache version explicit".into(),
            })
        } else if email.starts_with("cache-ordinary@") {
            Err(AuthError::internal("private cache version cause"))
        } else {
            Ok("actual-handler-v1".into())
        }
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

    let versions = Arc::new(Mutex::new(Vec::new()));
    let config = AuthConfig::new(secret)
        .base_url("http://lifecycle.fixture.test")
        .session_cookie_cache(alibi::CookieCacheConfig {
            enabled: true,
            version: Some(alibi::CookieCacheVersion::Resolver(Arc::new(CacheVersion(
                Arc::clone(&versions),
            )))),
            ..Default::default()
        });
    let auth = AuthBuilder::<B::Schema>::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .endpoint_hook(ConfiguredHook)
        .plugin(Writer)
        .plugin(Observer(Arc::clone(&observed)))
        .build()
        .await?;
    for (index, mode) in ["cache-ordinary", "cache-api", "cache-raw", "cache-success"]
        .into_iter()
        .enumerate()
    {
        let users_before = db.table("users").await?;
        let sessions_before = db.table("sessions").await?;
        let accounts_before = db.table("accounts").await?;
        let after_before = observed.lock().expect("observer mutex").clone();
        let mut req = AuthRequest::new(HttpMethod::Post, "/api/auth/sign-up/email");
        req.headers = std::collections::HashMap::from([
            ("x-mode".into(), mode.into()),
            ("x-forwarded-for".into(), format!("192.0.2.{}", index + 1)),
            ("origin".into(), "http://lifecycle.fixture.test".into()),
            ("content-type".into(), "application/json".into()),
        ]);
        req.body = Some(serde_json::to_vec(&serde_json::json!({
            "name":mode, "email":format!("{mode}@lifecycle.fixture.test"),
            "password":"Password123!",
        }))?);
        let response = auth.handle_request(req).await?;
        assert_eq!(
            versions.lock().expect("cache receipts").last(),
            Some(&format!("{mode}@lifecycle.fixture.test"))
        );
        let cookies = response.headers.get_all("set-cookie").collect::<Vec<_>>();
        eprintln!(
            "{}",
            serde_json::json!({
                "backend":std::any::type_name::<B>(), "mode":mode,
                "status":response.status, "headers":response.headers.clone().into_iter().collect::<Vec<_>>(),
                "body":String::from_utf8_lossy(&response.body), "callbacks":*versions.lock().expect("cache receipts"),
                "before":{"users":users_before,"sessions":sessions_before,"accounts":accounts_before},
                "after":{"users":db.table("users").await?,"sessions":db.table("sessions").await?,"accounts":db.table("accounts").await?},
            })
        );
        if mode == "cache-ordinary" || mode == "cache-api" {
            assert_eq!(db.table("users").await?, users_before);
            assert_eq!(db.table("sessions").await?, sessions_before);
            assert_eq!(db.table("accounts").await?, accounts_before);
            if mode == "cache-ordinary" {
                assert_eq!(response.status, 500);
                assert!(response.body.is_empty());
                assert!(response.headers.is_empty());
                assert_eq!(*observed.lock().expect("observer mutex"), after_before);
            } else {
                assert_eq!(response.status, 403);
                assert_eq!(
                    response.headers.get("x-cache-stage").map(String::as_str),
                    Some("version")
                );
                assert_eq!(
                    response.headers.get("x-global").map(String::as_str),
                    Some("observed")
                );
                assert_eq!(cookies.len(), 1);
                assert!(cookies[0].starts_with("better-auth.session_token="));
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&response.body)?,
                    serde_json::json!({"message":"cache version explicit"})
                );
            }
        } else {
            assert_eq!(response.status, 200);
            let payload: serde_json::Value = serde_json::from_slice(&response.body)?;
            let id = payload["user"]["id"].as_str().expect("actual signup user");
            let token = payload["token"].as_str().expect("actual signup token");
            assert_eq!(
                db.text("SELECT user_id FROM sessions WHERE token = $1", &[token])
                    .await?
                    .as_deref(),
                Some(id)
            );
            for (table, before) in [
                ("users", users_before),
                ("sessions", sessions_before),
                ("accounts", accounts_before),
            ] {
                let before: Vec<serde_json::Value> = serde_json::from_str(&before)?;
                let after: Vec<serde_json::Value> = serde_json::from_str(&db.table(table).await?)?;
                assert_eq!(after.len(), before.len() + 1);
                assert!(
                    before.iter().all(|row| after.contains(row)),
                    "foreign {table} rows remain exact"
                );
            }
            assert!(
                cookies
                    .iter()
                    .any(|cookie| cookie.starts_with("better-auth.session_token="))
            );
            if mode == "cache-raw" {
                assert_eq!(
                    cookies.len(),
                    1,
                    "raw response bypasses queued compact cache issuance"
                );
                assert!(!response.headers.contains_key("x-cache-stage"));
                assert!(!response.headers.contains_key("x-global"));
                assert_eq!(*observed.lock().expect("observer mutex"), after_before);
            } else {
                assert_eq!(cookies.len(), 2);
                use base64::Engine as _;
                let cache = cookies
                    .iter()
                    .find_map(|cookie| cookie.strip_prefix("better-auth.session_data="))
                    .expect("actual compact cache issuance")
                    .split(';')
                    .next()
                    .expect("actual cache token");
                let envelope: serde_json::Value = serde_json::from_slice(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(cache)?,
                )?;
                assert_eq!(envelope["session"]["user"]["id"], id);
                assert_eq!(envelope["session"]["session"]["token"], token);
                assert_eq!(envelope["session"]["version"], "actual-handler-v1");
                assert_eq!(
                    response.headers.get("x-cache-stage").map(String::as_str),
                    Some("version")
                );
            }
        }
    }
    B::close(connection).await
}
