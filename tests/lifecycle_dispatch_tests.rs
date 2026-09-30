//! Pinned dispatch behavior: hooks share authenticated context and response headers.
#![allow(clippy::unwrap_used, reason = "regressions assert dispatch outcomes")]

use std::sync::{Arc, atomic::{AtomicUsize,Ordering}};
use async_trait::async_trait;
use better_auth::{AuthBuilder,AuthConfig};
use better_auth_core::{AuthContext,AuthInitContext,AuthPlugin,AuthRequest,AuthResponse,AuthResult,AuthRoute,BeforeRequestAction,HttpMethod};
use better_auth_core::wire::SessionView;
use better_auth_seaorm::{Database,SeaOrmStore};
use serde_json::json;

type Schema=better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

struct Probe {
    session: Option<SessionView>,
    after_calls: Arc<AtomicUsize>,
    reject_after: bool,
}

#[async_trait]
impl AuthPlugin<Schema> for Probe {
    fn name(&self)->&'static str {"lifecycle-probe"}
    fn routes(&self)->Vec<AuthRoute> {vec![AuthRoute::get("/inspect","inspect"),AuthRoute::get("/stop","stop"),AuthRoute::get("/reject","reject")]}
    async fn on_init(&self,ctx:&mut AuthInitContext<Schema>)->AuthResult<()> {
        ctx.extensions.insert(String::from("registered"));
        Ok(())
    }
    async fn before_request(&self,req:&AuthRequest,_ctx:&AuthContext<Schema>)->AuthResult<Option<BeforeRequestAction>> {
        if req.path()=="/stop" {return Ok(Some(BeforeRequestAction::Respond(AuthResponse::json(200,&json!({"stopped":true}))?)))}
        Ok(self.session.clone().map(|session|BeforeRequestAction::InjectSession {session}))
    }
    async fn on_request(&self,req:&AuthRequest,ctx:&AuthContext<Schema>)->AuthResult<Option<AuthResponse>> {
        if req.path()=="/reject" {return Err(better_auth::AuthError::bad_request("handler rejection"))}
        let mut response=AuthResponse::json(200,&json!({"session":req.virtual_session(),"setting":ctx.extensions.get::<String>().as_deref()}))?;
        response.headers.append("set-cookie","probe.cookie=value; HttpOnly; Path=/");
        Ok(Some(response))
    }
    async fn after_request(&self,req:&AuthRequest,_ctx:&AuthContext<Schema>,mut response:AuthResponse)->AuthResult<AuthResponse> {
        _ = self.after_calls.fetch_add(1,Ordering::SeqCst);
        if self.reject_after {return Err(better_auth::AuthError::forbidden("after rejection"))}
        _ = response.headers.insert("x-hook-session",req.virtual_session().map(|session|session.id.clone()).unwrap_or_else(||"none".into()));
        Ok(response)
    }
}

async fn auth(probe:Probe)->better_auth::BetterAuth<Schema> {
    let config=AuthConfig::new("dispatch-tests-only-secret-minimum-32-characters");
    let db=Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db).await.unwrap();
    AuthBuilder::new(config.clone()).store(SeaOrmStore::<Schema>::new(config,db)).plugin(probe).build().await.unwrap()
}

fn virtual_session()->SessionView {
    let now=chrono::Utc::now();
    SessionView {id:"internal-session".into(),user_id:"internal-user".into(),token:"internal-token".into(),created_at:now,updated_at:now,expires_at:now+chrono::Duration::hours(1),ip_address:None,user_agent:None,impersonated_by:None,active_organization_id:None,active:true}
}

#[tokio::test]
async fn after_hooks_keep_internal_session_and_ignore_forged_request_context() {
    let calls=Arc::new(AtomicUsize::new(0));
    let configured=auth(Probe {session:Some(virtual_session()),after_calls:calls.clone(),reject_after:false}).await;
    let response=configured.handle_request(AuthRequest::new(HttpMethod::Get,"/api/auth/inspect")).await.unwrap();
    assert_eq!(response.headers.get("x-hook-session").map(String::as_str),Some("internal-session"));
    let value:serde_json::Value=serde_json::from_slice(&response.body).unwrap();
    assert_eq!(value.get("setting"),Some(&json!("registered")));
    assert_eq!(value.pointer("/session/id"),Some(&json!("internal-session")));
    assert_eq!(calls.load(Ordering::SeqCst),1);
    let configured=auth(Probe {session:None,after_calls:calls.clone(),reject_after:false}).await;
    let mut forged=AuthRequest::new(HttpMethod::Get,"/api/auth/inspect");
    forged.set_virtual_session(virtual_session());
    let response=configured.handle_request(forged).await.unwrap();
    assert_eq!(response.headers.get("x-hook-session").map(String::as_str),Some("none"));
}

#[tokio::test]
async fn before_responses_skip_after_hooks_and_handler_rejections_reach_them() {
    let calls=Arc::new(AtomicUsize::new(0));
    let configured=auth(Probe {session:None,after_calls:calls.clone(),reject_after:false}).await;
    let response=configured.handle_request(AuthRequest::new(HttpMethod::Get,"/api/auth/stop")).await.unwrap();
    assert_eq!(response.status,200);
    assert_eq!(calls.load(Ordering::SeqCst),0);
    let response=configured.handle_request(AuthRequest::new(HttpMethod::Get,"/api/auth/reject")).await.unwrap();
    assert_eq!(response.status,400);
    assert_eq!(calls.load(Ordering::SeqCst),1);
}

#[tokio::test]
async fn after_rejections_preserve_cookies_already_issued_by_handler() {
    let configured=auth(Probe {session:None,after_calls:Arc::new(AtomicUsize::new(0)),reject_after:true}).await;
    let response=configured.handle_request(AuthRequest::new(HttpMethod::Get,"/api/auth/inspect")).await.unwrap();
    assert_eq!(response.status,403);
    assert_eq!(response.headers.get("set-cookie").map(String::as_str),Some("probe.cookie=value; HttpOnly; Path=/"));
    assert_eq!(response.headers.get("content-type").map(String::as_str),Some("application/json"));
}

struct NestedHeadersProbe;

#[async_trait]
impl AuthPlugin<Schema> for NestedHeadersProbe {
    fn name(&self) -> &'static str { "nested-headers-probe" }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/headers", "headers"), AuthRoute::get("/headers-error", "headersError"), AuthRoute::get("/empty", "empty")]
    }

    async fn on_request(&self, req: &AuthRequest, _ctx: &AuthContext<Schema>) -> AuthResult<Option<AuthResponse>> {
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
            response.headers.append("set-cookie", "endpoint=value; HttpOnly; Path=/");
        }
        Ok(Some(response))
    }

    async fn after_request(&self, req: &AuthRequest, _ctx: &AuthContext<Schema>, mut response: AuthResponse) -> AuthResult<AuthResponse> {
        _ = response.headers.insert("x-forwarded-cookie-count", response.headers.get_all("set-cookie").count().to_string());
        if req.path() == "/headers" {
            req.queue_response_header("set-cookie", "after=value; HttpOnly; Path=/");
        }
        Ok(response)
    }
}

#[tokio::test]
async fn nested_headers_survive_endpoint_errors_and_remain_request_scoped() {
    let config = AuthConfig::new("nested-header-tests-secret-minimum-32-characters");
    let db = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db).await.unwrap();
    let configured = AuthBuilder::new(config.clone()).store(SeaOrmStore::<Schema>::new(config, db)).plugin(NestedHeadersProbe).build().await.unwrap();

    let forged = AuthRequest::new(HttpMethod::Get, "/api/auth/headers");
    forged.queue_response_header("set-cookie", "caller=value; Path=/");
    let response = configured.handle_request(forged).await.unwrap();
    assert_eq!(response.headers.get_all("set-cookie").map(String::as_str).collect::<Vec<_>>(), vec!["renewed=value; HttpOnly; Path=/", "marker=value; HttpOnly; Path=/", "endpoint=value; HttpOnly; Path=/", "after=value; HttpOnly; Path=/"]);
    assert_eq!(response.headers.get("x-forwarded-cookie-count").map(String::as_str), Some("3"));

    let response = configured.handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/headers-error")).await.unwrap();
    assert_eq!(response.status, 403);
    assert_eq!(response.headers.get_all("set-cookie").count(), 2);
    assert_eq!(response.headers.get("x-nested").map(String::as_str), Some("forwarded"));

    let response = configured.handle_request(AuthRequest::new(HttpMethod::Get, "/api/auth/empty")).await.unwrap();
    assert_eq!(response.headers.get_all("set-cookie").count(), 0);
    assert!(!response.headers.contains_key("x-nested"));
}

struct RouteBoundaryProbe(Arc<AtomicUsize>);

#[async_trait]
impl AuthPlugin<Schema> for RouteBoundaryProbe {
    fn name(&self) -> &'static str { "route-boundary-probe" }
    fn routes(&self) -> Vec<AuthRoute> { vec![AuthRoute::get("/known/{item}", "known")] }
    async fn before_request(&self, req: &AuthRequest, _ctx: &AuthContext<Schema>) -> AuthResult<Option<BeforeRequestAction>> {
        _ = self.0.fetch_add(1, Ordering::SeqCst);
        req.queue_response_header("x-before", "present");
        Ok(None)
    }
    async fn on_request(&self, req: &AuthRequest, _ctx: &AuthContext<Schema>) -> AuthResult<Option<AuthResponse>> {
        if req.path().starts_with("/known/") { Ok(Some(AuthResponse::json(200, &json!({"known":true}))?)) } else { Ok(None) }
    }
    async fn after_request(&self, _req: &AuthRequest, _ctx: &AuthContext<Schema>, mut response: AuthResponse) -> AuthResult<AuthResponse> {
        _ = response.headers.insert("x-after", "present");
        Ok(response)
    }
}

#[tokio::test]
async fn unknown_paths_and_methods_cannot_dispatch_plugin_hooks() {
    let config = AuthConfig::new("route-boundary-tests-secret-minimum-32-characters");
    let db = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db).await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let configured = AuthBuilder::new(config.clone()).store(SeaOrmStore::<Schema>::new(config, db)).plugin(RouteBoundaryProbe(calls.clone())).build().await.unwrap();
    for (method, path) in [(HttpMethod::Get,"/api/auth/unknown"), (HttpMethod::Post,"/api/auth/ok"), (HttpMethod::Get,"/api/auth/known/")] {
        let response = configured.handle_request(AuthRequest::new(method, path)).await.unwrap();
        assert_eq!(response.status, 404);
        assert!(response.body.is_empty());
        assert!(!response.headers.contains_key("x-before"));
        assert!(!response.headers.contains_key("x-after"));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let response = configured.handle_request(AuthRequest::new(HttpMethod::Get,"/api/auth/known/member")).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(response.headers.get("x-before").map(String::as_str), Some("present"));
    assert_eq!(response.headers.get("x-after").map(String::as_str), Some("present"));
}

struct EmitNestedHeaders { reject: bool }
#[async_trait]
impl AuthPlugin<Schema> for EmitNestedHeaders {
    fn name(&self) -> &'static str { "emit-nested-headers" }
    fn routes(&self) -> Vec<AuthRoute> { Vec::new() }
    async fn on_request(&self, _req:&AuthRequest, _ctx:&AuthContext<Schema>) -> AuthResult<Option<AuthResponse>> { Ok(None) }
    async fn after_request(&self, req:&AuthRequest, _ctx:&AuthContext<Schema>, response:AuthResponse) -> AuthResult<AuthResponse> {
        req.queue_response_header("x-nested-after", "forwarded");
        req.queue_response_header("set-cookie", "nested-after=value; HttpOnly; Path=/");
        if self.reject { Err(better_auth::AuthError::forbidden("first hook rejected")) } else { Ok(response) }
    }
}

struct ObserveNestedHeaders;
#[async_trait]
impl AuthPlugin<Schema> for ObserveNestedHeaders {
    fn name(&self) -> &'static str { "observe-nested-headers" }
    fn routes(&self) -> Vec<AuthRoute> { Vec::new() }
    async fn on_request(&self, _req:&AuthRequest, _ctx:&AuthContext<Schema>) -> AuthResult<Option<AuthResponse>> { Ok(None) }
    async fn after_request(&self, _req:&AuthRequest, _ctx:&AuthContext<Schema>, mut response:AuthResponse) -> AuthResult<AuthResponse> {
        assert_eq!(response.headers.get("x-nested-after").map(String::as_str), Some("forwarded"));
        assert_eq!(response.headers.get("set-cookie").map(String::as_str), Some("nested-after=value; HttpOnly; Path=/"));
        _ = response.headers.insert("x-observed-status", response.status.to_string());
        Ok(response)
    }
}

#[tokio::test]
async fn each_after_hook_observes_prior_nested_headers_and_rejections() {
    for reject in [false, true] {
        let config = AuthConfig::new("successive-header-tests-secret-minimum-32-characters");
        let db = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db).await.unwrap();
        let configured = AuthBuilder::new(config.clone()).store(SeaOrmStore::<Schema>::new(config, db)).plugin(EmitNestedHeaders { reject }).plugin(ObserveNestedHeaders).build().await.unwrap();
        let response = configured.handle_request(AuthRequest::new(HttpMethod::Get,"/api/auth/ok")).await.unwrap();
        let expected = if reject { "403" } else { "200" };
        assert_eq!(response.headers.get("x-observed-status").map(String::as_str), Some(expected));
        assert_eq!(response.headers.get_all("set-cookie").count(), 1);
    }
}

struct CaptureEmail(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
#[async_trait]
impl better_auth_core::EmailProvider for CaptureEmail {
    async fn send(&self, to:&str, subject:&str, html:&str, text:&str) -> AuthResult<()> {
        self.0.lock().unwrap().push(format!("{to}|{subject}|{html}|{text}"));
        Ok(())
    }
}
struct InitializedEmail(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
#[async_trait]
impl AuthPlugin<Schema> for InitializedEmail {
    fn name(&self)->&'static str { "initialized-email" }
    fn routes(&self)->Vec<AuthRoute> { vec![AuthRoute::get("/mail", "mail")] }
    async fn on_init(&self,ctx:&mut AuthInitContext<Schema>)->AuthResult<()> {
        ctx.email_provider = Some(Arc::new(CaptureEmail(self.0.clone())));
        Ok(())
    }
    async fn on_request(&self,req:&AuthRequest,ctx:&AuthContext<Schema>)->AuthResult<Option<AuthResponse>> {
        if req.path() != "/mail" { return Ok(None); }
        ctx.email_provider()?.send("fixture@example.com", "handler", "<p>body</p>", "body").await?;
        Ok(Some(AuthResponse::json(200, &json!({"delivered":true}))?))
    }
}

#[tokio::test]
async fn initialized_email_provider_is_shared_with_handlers_and_server_callers() {
    let config = AuthConfig::new("initialized-email-test-secret-minimum-32-characters");
    let db = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db).await.unwrap();
    let original = Arc::new(std::sync::Mutex::new(Vec::new()));
    let initialized = Arc::new(std::sync::Mutex::new(Vec::new()));
    let configured = AuthBuilder::new(config.clone()).store(SeaOrmStore::<Schema>::new(config,db))
        .email_provider(CaptureEmail(original.clone())).plugin(InitializedEmail(initialized.clone())).build().await.unwrap();
    let response = configured.handle_request(AuthRequest::new(HttpMethod::Get,"/api/auth/mail")).await.unwrap();
    assert_eq!(response.status,200);
    configured.context().email_provider().unwrap().send("fixture@example.com", "server", "", "proof").await.unwrap();
    assert!(original.lock().unwrap().is_empty());
    assert_eq!(*initialized.lock().unwrap(), vec!["fixture@example.com|handler|<p>body</p>|body", "fixture@example.com|server||proof"]);
}
