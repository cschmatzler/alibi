#![cfg(test)]
//! Pinned dispatch behavior: hooks share authenticated context and response headers.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(clippy::unwrap_used, reason = "regressions assert dispatch outcomes")]

#[cfg(test)]
#[path = "lifecycle_dispatch_tests/tests.rs"]
mod tests;

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
