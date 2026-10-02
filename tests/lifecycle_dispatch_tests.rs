#![cfg(test)]
//! Pinned dispatch behavior: hooks share authenticated context and response headers.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(clippy::unwrap_used, reason = "regressions assert dispatch outcomes")]

use async_trait::async_trait;
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::wire::SessionView;
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    BeforeRequestAction, HttpMethod,
};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

struct Probe {
    session: Option<SessionView>,
    after_calls: Arc<AtomicUsize>,
    reject_after: bool,
}

#[async_trait]
impl AuthPlugin<Schema> for Probe {
    fn name(&self) -> &'static str {
        "lifecycle-probe"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/inspect", "inspect"),
            AuthRoute::get("/stop", "stop"),
            AuthRoute::get("/reject", "reject"),
        ]
    }
    async fn on_init(&self, ctx: &mut AuthInitContext<Schema>) -> AuthResult<()> {
        ctx.extensions.insert(String::from("registered"));
        Ok(())
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if req.path() == "/stop" {
            return Ok(Some(BeforeRequestAction::Respond(AuthResponse::json(
                200,
                &json!({"stopped":true}),
            )?)));
        }
        Ok(self
            .session
            .clone()
            .map(|session| BeforeRequestAction::InjectSession { session }))
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<Schema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.path() == "/reject" {
            return Err(better_auth::AuthError::bad_request("handler rejection"));
        }
        let mut response = AuthResponse::json(
            200,
            &json!({"session":req.virtual_session(),"setting":ctx.extensions.get::<String>().as_deref()}),
        )?;
        response
            .headers
            .append("set-cookie", "probe.cookie=value; HttpOnly; Path=/");
        Ok(Some(response))
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        _ = self.after_calls.fetch_add(1, Ordering::SeqCst);
        if self.reject_after {
            return Err(better_auth::AuthError::forbidden("after rejection"));
        }
        drop(
            response.headers.insert(
                "x-hook-session",
                req.virtual_session()
                    .map_or_else(|| "none".into(), |session| session.id.clone()),
            ),
        );
        Ok(response)
    }
}

struct NestedHeadersProbe;

#[async_trait]
impl AuthPlugin<Schema> for NestedHeadersProbe {
    fn name(&self) -> &'static str {
        "nested-headers-probe"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/headers", "headers"),
            AuthRoute::get("/headers-error", "headersError"),
            AuthRoute::get("/empty", "empty"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.path() == "/headers" || req.path() == "/headers-error" {
            let nested = req.clone();
            nested.queue_response_header("set-cookie", "renewed=value; HttpOnly; Path=/");
            nested.queue_response_header("set-cookie", "marker=value; HttpOnly; Path=/");
            nested.queue_response_header("x-nested", "forwarded");
        }
        if req.path() == "/headers-error" {
            return Err(better_auth::AuthError::forbidden("endpoint rejection"));
        }
        let mut response = AuthResponse::json(200, &json!({"ok": true}))?;
        if req.path() == "/headers" {
            response
                .headers
                .append("set-cookie", "endpoint=value; HttpOnly; Path=/");
        }
        Ok(Some(response))
    }

    async fn after_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        drop(response.headers.insert(
            "x-forwarded-cookie-count",
            response.headers.get_all("set-cookie").count().to_string(),
        ));
        if req.path() == "/headers" {
            req.queue_response_header("set-cookie", "after=value; HttpOnly; Path=/");
        }
        Ok(response)
    }
}

struct RouteBoundaryProbe(Arc<AtomicUsize>);

#[async_trait]
impl AuthPlugin<Schema> for RouteBoundaryProbe {
    fn name(&self) -> &'static str {
        "route-boundary-probe"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/known/{item}", "known")]
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        _ = self.0.fetch_add(1, Ordering::SeqCst);
        req.queue_response_header("x-before", "present");
        Ok(None)
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.path().starts_with("/known/") {
            Ok(Some(AuthResponse::json(200, &json!({"known":true}))?))
        } else {
            Ok(None)
        }
    }
    async fn after_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        drop(response.headers.insert("x-after", "present"));
        Ok(response)
    }
}

struct EmitNestedHeaders {
    reject: bool,
}

#[async_trait]
impl AuthPlugin<Schema> for EmitNestedHeaders {
    fn name(&self) -> &'static str {
        "emit-nested-headers"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        req.queue_response_header("x-nested-after", "forwarded");
        req.queue_response_header("set-cookie", "nested-after=value; HttpOnly; Path=/");
        if self.reject {
            Err(better_auth::AuthError::forbidden("first hook rejected"))
        } else {
            Ok(response)
        }
    }
}

struct ObserveNestedHeaders;

#[async_trait]
impl AuthPlugin<Schema> for ObserveNestedHeaders {
    fn name(&self) -> &'static str {
        "observe-nested-headers"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        assert_eq!(
            response.headers.get("x-nested-after").map(String::as_str),
            Some("forwarded")
        );
        assert_eq!(
            response.headers.get("set-cookie").map(String::as_str),
            Some("nested-after=value; HttpOnly; Path=/")
        );
        drop(
            response
                .headers
                .insert("x-observed-status", response.status.to_string()),
        );
        Ok(response)
    }
}

struct CaptureEmail(Arc<std::sync::Mutex<Vec<String>>>);

#[async_trait]
impl better_auth_core::EmailProvider for CaptureEmail {
    async fn send(&self, to: &str, subject: &str, html: &str, text: &str) -> AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push(format!("{to}|{subject}|{html}|{text}"));
        Ok(())
    }
}

struct InitializedEmail(Arc<std::sync::Mutex<Vec<String>>>);

#[async_trait]
impl AuthPlugin<Schema> for InitializedEmail {
    fn name(&self) -> &'static str {
        "initialized-email"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/mail", "mail")]
    }
    async fn on_init(&self, ctx: &mut AuthInitContext<Schema>) -> AuthResult<()> {
        ctx.email_provider = Some(Arc::new(CaptureEmail(Arc::clone(&self.0))));
        Ok(())
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<Schema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.path() != "/mail" {
            return Ok(None);
        }
        ctx.email_provider()?
            .send("fixture@example.com", "handler", "<p>body</p>", "body")
            .await?;
        Ok(Some(AuthResponse::json(200, &json!({"delivered":true}))?))
    }
}

async fn auth(probe: Probe) -> better_auth::BetterAuth<Schema> {
    let config = AuthConfig::new("dispatch-tests-only-secret-minimum-32-characters");
    let db = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
        .await
        .unwrap();
    AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, db))
        .plugin(probe)
        .build()
        .await
        .unwrap()
}

fn virtual_session() -> SessionView {
    let now = chrono::Utc::now();
    SessionView {
        omitted_fields: std::collections::BTreeSet::default(),
        id: "internal-session".into(),
        user_id: "internal-user".into(),
        token: "internal-token".into(),
        created_at: now,
        updated_at: now,
        expires_at: now + chrono::Duration::hours(1),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
        extension_fields: std::collections::BTreeMap::default(),
        active: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn after_hooks_keep_internal_session_and_ignore_forged_request_context() {
        let calls = Arc::new(AtomicUsize::new(0));
        let configured = auth(Probe {
            session: Some(virtual_session()),
            after_calls: Arc::clone(&calls),
            reject_after: false,
        })
        .await;
        let response = configured
            .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/inspect"))
            .await
            .unwrap();
        assert_eq!(
            response.headers.get("x-hook-session").map(String::as_str),
            Some("internal-session")
        );
        let value: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value.get("setting"), Some(&json!("registered")));
        assert_eq!(
            value.pointer("/session/id"),
            Some(&json!("internal-session"))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let configured_2 = auth(Probe {
            session: None,
            after_calls: Arc::clone(&calls),
            reject_after: false,
        })
        .await;
        let mut forged = AuthRequest::new(HttpMethod::Get, "/api/auth/inspect");
        forged.set_virtual_session(virtual_session());
        let response_2 = configured_2.handle_request(forged).await.unwrap();
        assert_eq!(
            response_2.headers.get("x-hook-session").map(String::as_str),
            Some("none")
        );
    }

    #[tokio::test]
    async fn before_responses_skip_after_hooks_and_handler_rejections_reach_them() {
        let calls = Arc::new(AtomicUsize::new(0));
        let configured = auth(Probe {
            session: None,
            after_calls: Arc::clone(&calls),
            reject_after: false,
        })
        .await;
        let response = configured
            .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/stop"))
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let response_2 = configured
            .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/reject"))
            .await
            .unwrap();
        assert_eq!(response_2.status, 400);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn after_rejections_preserve_cookies_already_issued_by_handler() {
        let configured = auth(Probe {
            session: None,
            after_calls: Arc::new(AtomicUsize::new(0)),
            reject_after: true,
        })
        .await;
        let response = configured
            .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/inspect"))
            .await
            .unwrap();
        assert_eq!(response.status, 403);
        assert_eq!(
            response.headers.get("set-cookie").map(String::as_str),
            Some("probe.cookie=value; HttpOnly; Path=/")
        );
        assert_eq!(
            response.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
    }

    #[tokio::test]
    async fn nested_headers_survive_endpoint_errors_and_remain_request_scoped() {
        let config = AuthConfig::new("nested-header-tests-secret-minimum-32-characters");
        let db = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
            .await
            .unwrap();
        let configured = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, db))
            .plugin(NestedHeadersProbe)
            .build()
            .await
            .unwrap();

        let forged = AuthRequest::new(HttpMethod::Get, "/api/auth/headers");
        forged.queue_response_header("set-cookie", "caller=value; Path=/");
        let response = configured.handle_request(forged).await.unwrap();
        assert_eq!(
            response
                .headers
                .get_all("set-cookie")
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![
                "renewed=value; HttpOnly; Path=/",
                "marker=value; HttpOnly; Path=/",
                "endpoint=value; HttpOnly; Path=/",
                "after=value; HttpOnly; Path=/"
            ]
        );
        assert_eq!(
            response
                .headers
                .get("x-forwarded-cookie-count")
                .map(String::as_str),
            Some("3")
        );

        let response_2 = configured
            .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/headers-error"))
            .await
            .unwrap();
        assert_eq!(response_2.status, 403);
        assert_eq!(response_2.headers.get_all("set-cookie").count(), 2);
        assert_eq!(
            response_2.headers.get("x-nested").map(String::as_str),
            Some("forwarded")
        );

        let response_3 = configured
            .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/empty"))
            .await
            .unwrap();
        assert_eq!(response_3.headers.get_all("set-cookie").count(), 0);
        assert!(!response_3.headers.contains_key("x-nested"));
    }

    #[tokio::test]
    async fn unknown_paths_and_methods_cannot_dispatch_plugin_hooks() {
        let config = AuthConfig::new("route-boundary-tests-secret-minimum-32-characters");
        let db = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
            .await
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let configured = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, db))
            .plugin(RouteBoundaryProbe(Arc::clone(&calls)))
            .build()
            .await
            .unwrap();
        for (method, path) in [
            (HttpMethod::Get, "/api/auth/unknown"),
            (HttpMethod::Post, "/api/auth/ok"),
            (HttpMethod::Get, "/api/auth/known/"),
        ] {
            let response = configured
                .handle_request(AuthRequest::new(method, path))
                .await
                .unwrap();
            assert_eq!(response.status, 404);
            assert_eq!(response.body.len(), 0);
            assert!(!response.headers.contains_key("x-before"));
            assert!(!response.headers.contains_key("x-after"));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let response = configured
            .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/known/member"))
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            response.headers.get("x-before").map(String::as_str),
            Some("present")
        );
        assert_eq!(
            response.headers.get("x-after").map(String::as_str),
            Some("present")
        );
    }

    #[tokio::test]
    async fn each_after_hook_observes_prior_nested_headers_and_rejections() {
        for reject in [false, true] {
            let config = AuthConfig::new("successive-header-tests-secret-minimum-32-characters");
            let db = Database::connect("sqlite::memory:").await.unwrap();
            better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
                .await
                .unwrap();
            let configured = AuthBuilder::new(config.clone())
                .store(SeaOrmStore::<Schema>::new(config, db))
                .plugin(EmitNestedHeaders { reject })
                .plugin(ObserveNestedHeaders)
                .build()
                .await
                .unwrap();
            let response = configured
                .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/ok"))
                .await
                .unwrap();
            let expected = if reject { "403" } else { "200" };
            assert_eq!(
                response
                    .headers
                    .get("x-observed-status")
                    .map(String::as_str),
                Some(expected)
            );
            assert_eq!(response.headers.get_all("set-cookie").count(), 1);
        }
    }

    #[tokio::test]
    async fn initialized_email_provider_is_shared_with_handlers_and_server_callers() {
        let config = AuthConfig::new("initialized-email-test-secret-minimum-32-characters");
        let db = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
            .await
            .unwrap();
        let original = Arc::new(std::sync::Mutex::new(Vec::new()));
        let initialized = Arc::new(std::sync::Mutex::new(Vec::new()));
        let configured = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, db))
            .email_provider(CaptureEmail(Arc::clone(&original)))
            .plugin(InitializedEmail(Arc::clone(&initialized)))
            .build()
            .await
            .unwrap();
        let response = configured
            .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/mail"))
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        configured
            .context()
            .email_provider()
            .unwrap()
            .send("fixture@example.com", "server", "", "proof")
            .await
            .unwrap();
        assert!(original.lock().unwrap().is_empty());
        assert_eq!(
            *initialized.lock().unwrap(),
            vec![
                "fixture@example.com|handler|<p>body</p>|body",
                "fixture@example.com|server||proof"
            ]
        );
    }

    // Upstream runtime: api/index.ts routes known methods through endpoint hooks.
    #[cfg(feature = "axum")]
    #[tokio::test]
    async fn axum_core_routes_share_hooks_and_unregistered_methods_are_empty() {
        use better_auth::integrations::axum::AxumIntegration;
        use tower::ServiceExt;
        let config = AuthConfig::new("axum-lifecycle-test-secret-minimum-32-characters");
        let db = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
            .await
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let configured = Arc::new(
            AuthBuilder::new(config.clone())
                .store(SeaOrmStore::<Schema>::new(config, db))
                .plugin(RouteBoundaryProbe(Arc::clone(&calls)))
                .build()
                .await
                .unwrap(),
        );
        let router = Arc::clone(&configured).axum_router().with_state(configured);
        for path in ["/ok", "/error"] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(path)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.headers().get("x-before").unwrap(), "present");
            assert_eq!(response.headers().get("x-after").unwrap(), "present");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        for path in ["/ok", "/unregistered"] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri(path)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), 404);
            assert!(response.headers().get("x-before").is_none());
            assert!(response.headers().get("x-after").is_none());
            assert!(
                axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[derive(Clone, Default)]
    struct CapturedTelemetry {
        events: Arc<std::sync::Mutex<Vec<better_auth::telemetry::TelemetryEvent>>>,
        reject: bool,
    }

    #[async_trait]
    impl better_auth::telemetry::TelemetrySink for CapturedTelemetry {
        async fn track(&self, event: better_auth::telemetry::TelemetryEvent) -> AuthResult<()> {
            self.events.lock().unwrap().push(event);
            if self.reject {
                Err(better_auth::AuthError::internal("synthetic sink failure"))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn initialization_telemetry_is_opt_in_bounded_and_nonfatal() {
        use better_auth::telemetry::{TelemetryConfig, TelemetryEvent};

        for (enabled, reject) in [(false, false), (true, false), (true, true)] {
            let capture = CapturedTelemetry {
                reject,
                ..CapturedTelemetry::default()
            };
            let config = AuthConfig::new("telemetry-secret-must-never-be-captured-32-characters");
            let db = Database::connect("sqlite::memory:").await.unwrap();
            better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
                .await
                .unwrap();
            use better_auth_core::store::UserStore;
            let store = SeaOrmStore::<Schema>::new(config.clone(), db);
            let seeded = store
                .create_user(
                    serde_json::from_value(json!({
                        "email":"telemetry@example.com", "name":"Synthetic telemetry owner"
                    }))
                    .unwrap(),
                )
                .await
                .unwrap();
            let original_user = serde_json::to_value(&seeded).unwrap();
            let configured = AuthBuilder::new(config.clone())
                .store(store)
                .plugin(Probe {
                    session: None,
                    after_calls: Arc::new(AtomicUsize::new(0)),
                    reject_after: false,
                })
                .telemetry(TelemetryConfig::new(capture.clone()).enabled(enabled))
                .build()
                .await
                .unwrap();
            configured
                .publish_telemetry(TelemetryEvent::new(
                    "application-ready",
                    json!({"ready":true}),
                ))
                .await;
            let events = capture.events.lock().unwrap().clone();
            if enabled {
                assert_eq!(events.len(), 2);
                let init = events.first().unwrap();
                assert_eq!(init.event_type, "init");
                assert_eq!(
                    init.payload,
                    json!({
                        "libraryVersion":env!("CARGO_PKG_VERSION"),
                        "runtime":"rust",
                        "platform":std::env::consts::OS,
                        "architecture":std::env::consts::ARCH,
                        "plugins":["lifecycle-probe", "session-management", "email-password", "password-management", "email-verification", "account-management", "oauth", "user-management"]
                    })
                );
                assert_eq!(
                    events.get(1).unwrap(),
                    &TelemetryEvent::new("application-ready", json!({"ready":true}))
                );
            } else {
                assert!(events.is_empty());
            }
            let response = configured
                .handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/inspect"))
                .await
                .unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&response.body)
                    .unwrap()
                    .get("setting"),
                Some(&json!("registered"))
            );
            let persisted = configured
                .store()
                .get_user_by_email("telemetry@example.com")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(serde_json::to_value(persisted).unwrap(), original_user);
            assert_eq!(capture.events.lock().unwrap().len(), events.len());
        }
    }

    #[tokio::test]
    async fn rejected_initialization_does_not_emit_telemetry() {
        let capture = CapturedTelemetry::default();
        let result = AuthBuilder::<Schema>::new(AuthConfig::new("short"))
            .telemetry(better_auth::telemetry::TelemetryConfig::new(
                capture.clone(),
            ))
            .build()
            .await;
        assert!(result.is_err());
        assert!(capture.events.lock().unwrap().is_empty());
    }

    struct RejectInitialization;

    #[async_trait]
    impl AuthPlugin<Schema> for RejectInitialization {
        fn name(&self) -> &'static str {
            "reject-initialization"
        }

        fn routes(&self) -> Vec<AuthRoute> {
            Vec::new()
        }

        async fn on_request(
            &self,
            _req: &AuthRequest,
            _ctx: &AuthContext<Schema>,
        ) -> AuthResult<Option<AuthResponse>> {
            Ok(None)
        }

        async fn on_init(&self, _ctx: &mut AuthInitContext<Schema>) -> AuthResult<()> {
            Err(better_auth::AuthError::config(
                "synthetic initialization rejection",
            ))
        }
    }

    #[tokio::test]
    async fn failed_plugin_initialization_does_not_emit_telemetry() {
        let capture = CapturedTelemetry::default();
        let config = AuthConfig::new("telemetry-failed-init-secret-at-least-32-characters");
        let db = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
            .await
            .unwrap();
        let result = AuthBuilder::<Schema>::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, db))
            .plugin(RejectInitialization)
            .telemetry(better_auth::telemetry::TelemetryConfig::new(
                capture.clone(),
            ))
            .build()
            .await;
        assert!(result.is_err());
        assert!(capture.events.lock().unwrap().is_empty());
    }
}
