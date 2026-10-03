//! Real HTTP plugin composition over both stores, with independent physical observers.
use super::{Backend, Db, TestResult, backend_tests};
use async_trait::async_trait;
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, AuthSchema};
use better_auth_core::endpoint::{
    BeforeEndpointAction, EndpointCall, EndpointContextPatch, EndpointHook, EndpointResponse,
};
use better_auth_core::entity::AuthUser;
use better_auth_core::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute,
    BeforeRequestAction, HttpEndpointResponse, HttpMethod, HttpRequestAction, UpdateUser,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<Value>>>;
fn record(events: &Events, value: Value) {
    events.lock().expect("events").push(value);
}
fn mode(req: &AuthRequest) -> &str {
    req.header("x-mode").map_or("", String::as_str)
}
#[derive(Clone)]
struct Authority(String);
#[derive(Clone)]
struct Global(Events);
#[async_trait]
impl<S: AuthSchema> EndpointHook<S> for Global {
    fn matches_before(&self, call: &EndpointCall, _: &AuthContext<S>) -> AuthResult<bool> {
        Ok(call.headers().is_some_and(|h| h.contains_key("x-mode")))
    }
    fn matches_after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        response: &EndpointResponse,
    ) -> AuthResult<bool> {
        if !call.headers().is_some_and(|h| h.contains_key("x-mode")) {
            return Ok(false);
        }
        record(
            &self.0,
            json!({"stage":"global-match-after","error":response.result().is_err()}),
        );
        Ok(true)
    }
    async fn before(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        record(
            &self.0,
            json!({"stage":"global-before","body":call.body(),"physical":call.request().map(AuthRequest::path)}),
        );
        let selected = call
            .headers()
            .and_then(|h| h.get("x-mode"))
            .map_or("", String::as_str);
        if selected == "stop" {
            return Ok(Some(BeforeEndpointAction::Respond(EndpointResponse::json(
                &json!({"stopped":true}),
            )?)));
        }
        if selected == "no-patch" {
            return Ok(None);
        }
        if selected == "context-request" {
            let request = AuthRequest::new(HttpMethod::Post, "/physical").with_url(
                url::Url::parse("http://patched.test/physical")
                    .map_err(|error| AuthError::internal(error.to_string()))?,
            );
            return Ok(Some(BeforeEndpointAction::Patch(Box::new(
                EndpointContextPatch {
                    request: Some(request),
                    path: Some("/logical-patched".into()),
                    body: Some(better_auth_core::utils::json::parse_value(
                        "{\"name\":\"patched\"}",
                    )?),
                    ..Default::default()
                },
            ))));
        }
        Ok(Some(BeforeEndpointAction::Patch(Box::new(
            EndpointContextPatch {
                body: Some(better_auth_core::utils::json::parse_value(
                    "{\"name\":\"patched\"}",
                )?),
                headers: Some(std::collections::HashMap::from([
                    ("x-winner".into(), "global".into()),
                    ("x-global-input".into(), "yes".into()),
                ])),
                ..Default::default()
            },
        ))))
    }
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        record(
            &self.0,
            json!({"stage":"global-after","path":call.path(),"body":call.body(),"winner":call.headers().and_then(|h|h.get("x-winner")),"error":response.result().is_err()}),
        );
        match call
            .headers()
            .and_then(|h| h.get("x-mode"))
            .map(String::as_str)
        {
            Some("after-ordinary") => Err(AuthError::internal("private after cause")),
            Some("after-api") => Err(AuthError::forbidden("after explicit")),
            _ => Ok(response.with_header("x-global", "after")),
        }
    }
}
struct Physical {
    events: Events,
    cookie_b: Arc<Mutex<String>>,
}
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Physical {
    fn name(&self) -> &'static str {
        "physical-first"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![]
    }
    async fn on_init(&self, c: &mut AuthInitContext<S>) -> AuthResult<()> {
        c.extensions.insert(String::from("first"));
        Ok(())
    }
    async fn on_http_request_action(
        &self,
        r: &AuthRequest,
        c: &AuthContext<S>,
    ) -> AuthResult<Option<HttpRequestAction>> {
        if mode(r).is_empty() {
            return Ok(None);
        }
        record(
            &self.events,
            json!({"stage":"http-first","path":r.path(),"base":c.config.base_url,"authority":r.extensions().get::<Authority>().is_some()}),
        );
        match mode(r) {
            "early" => {
                return Ok(Some(HttpRequestAction::Respond(
                    AuthResponse::json(200, &json!({"early":true}))?
                        .with_header("content-type", "application/json;charset=utf-8"),
                )));
            }
            "request-ordinary" => return Err(AuthError::internal("request ordinary")),
            "request-api" => return Err(AuthError::forbidden("request explicit")),
            "replace" => {
                let (user, _) = c.require_session(r).await?;
                r.extensions().insert(Authority(user.id().into_owned()));
                r.queue_response_header("set-cookie", "obsolete=yes");
                let mut replacement = r.clone();
                replacement.path = "/api/auth/write".into();
                replacement = replacement.with_url(
                    url::Url::parse("http://replacement.test/api/auth/write")
                        .map_err(|e| AuthError::internal(e.to_string()))?,
                );
                _ = replacement.headers.insert(
                    "cookie".into(),
                    self.cookie_b.lock().expect("cookie").clone(),
                );
                return Ok(Some(HttpRequestAction::ReplaceRequest(Box::new(
                    replacement,
                ))));
            }
            _ => {}
        }
        Ok(None)
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn on_http_response(
        &self,
        r: &AuthRequest,
        c: &AuthContext<S>,
        response: &AuthResponse,
    ) -> AuthResult<Option<AuthResponse>> {
        if mode(r).is_empty() {
            return Ok(None);
        }
        record(
            &self.events,
            json!({"stage":"http-response-first","status":response.status,"global":response.headers.get("x-global"),"base":c.config.base_url,"cors":response.headers.get("access-control-allow-origin")}),
        );
        match mode(r) {
            "response-ordinary" => Err(AuthError::internal("response ordinary")),
            "response-api" => Err(AuthError::forbidden("response explicit")),
            "response-replace" => Ok(Some(
                AuthResponse::text(202, "replacement").with_header("x-replaced-response", "yes"),
            )),
            _ => Ok(None),
        }
    }
}
struct Endpoint(Events);
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Endpoint {
    fn name(&self) -> &'static str {
        "physical-second"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/write", "write"),
            AuthRoute::post("/disabled", "disabledWrite"),
        ]
    }
    async fn on_init(&self, c: &mut AuthInitContext<S>) -> AuthResult<()> {
        assert_eq!(
            c.extensions.get::<String>().as_deref().map(String::as_str),
            Some("first")
        );
        c.extensions.insert(String::from("second"));
        Ok(())
    }
    async fn on_http_request(
        &self,
        r: &AuthRequest,
        c: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if !mode(r).is_empty() {
            record(
                &self.0,
                json!({"stage":"http-second","path":r.path(),"authority":r.extensions().get::<Authority>().is_some(),"base":c.config.base_url}),
            );
        }
        Ok(None)
    }
    async fn before_request(
        &self,
        r: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        if mode(r).is_empty() {
            return Ok(None);
        }
        record(
            &self.0,
            json!({"stage":"plugin-before","body":r.body_as_json::<Value>()?,"winner":r.header("x-winner")}),
        );
        let mut headers = r.headers.clone();
        _ = headers.insert("x-winner".into(), "plugin".into());
        Ok(Some(BeforeRequestAction::ReplaceHeaders { headers }))
    }
    async fn on_request(
        &self,
        r: &AuthRequest,
        c: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let (user, _) = c.require_session(r).await?;
        let body = r.body_as_json::<Value>()?;
        assert!(
            r.extensions().get::<Authority>().is_none(),
            "the old physical principal cannot survive replacement: {:?}",
            r.extensions().get::<Authority>().map(|a| a.0.clone())
        );
        record(
            &self.0,
            json!({"stage":"handler","path":r.path(),"principal":user.id(),"body":body,"winner":r.header("x-winner"),"setting":c.extensions.get::<String>().as_deref()}),
        );
        _ = c
            .database
            .update_user(
                &user.id(),
                UpdateUser {
                    name: body.get("name").and_then(Value::as_str).map(str::to_owned),
                    ..Default::default()
                },
            )
            .await?;
        r.queue_response_header("set-cookie", "issued=yes; Path=/");
        if mode(r) == "handler-ordinary" {
            return Err(AuthError::CallbackFailure(Box::new(AuthError::internal(
                "handler ordinary",
            ))));
        }
        if mode(r) == "handler-api" {
            return Err(AuthError::forbidden("handler explicit"));
        }
        Ok(Some(AuthResponse::json(
            200,
            &json!({"principal":user.id(),"name":body["name"]}),
        )?))
    }
    async fn on_http_endpoint(
        &self,
        r: &AuthRequest,
        c: &AuthContext<S>,
    ) -> AuthResult<Option<HttpEndpointResponse>> {
        let output = self.on_request(r, c).await?;
        Ok(output.map(|response| {
            if mode(r) == "raw" {
                HttpEndpointResponse::Raw(
                    response.with_header("content-type", "application/json;charset=utf-8"),
                )
            } else {
                HttpEndpointResponse::Value(response)
            }
        }))
    }
    async fn after_request(
        &self,
        r: &AuthRequest,
        _: &AuthContext<S>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        if !mode(r).is_empty() {
            record(
                &self.0,
                json!({"stage":"plugin-after","path":r.path(),"status":response.status,"body":r.body_as_json::<Value>()?,"winner":r.header("x-winner")}),
            );
        }
        Ok(response)
    }
    async fn on_http_response(
        &self,
        r: &AuthRequest,
        _: &AuthContext<S>,
        response: &AuthResponse,
    ) -> AuthResult<Option<AuthResponse>> {
        if !mode(r).is_empty() {
            record(
                &self.0,
                json!({"stage":"http-response-second","status":response.status}),
            );
        }
        Ok(None)
    }
}
struct StorageObserver(Events);
#[async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for StorageObserver {
    async fn before_update_user(
        &self,
        id: &str,
        _: &mut UpdateUser,
        c: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        record(
            &self.0,
            json!({"stage":"db-before","principal":id,"physical":c.request.as_ref().map(|r|r.path.as_str()),"url":c.request.as_ref().and_then(|r|r.url.as_ref()).map(url::Url::as_str),"authority":c.request.as_ref().and_then(|r|r.extensions.get::<Authority>()).is_some(),"logical":better_auth_core::endpoint::current_endpoint_call_context().and_then(|c|c.body().cloned())}),
        );
        Ok(HookControl::Continue)
    }
    async fn after_update_user(
        &self,
        u: &S::User,
        _: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        record(&self.0, json!({"stage":"db-after","principal":u.id()}));
        Ok(())
    }
}
backend_tests!(physical_http_composition_preserves_principals_and_committed_rows);
async fn physical_http_composition_preserves_principals_and_committed_rows<B: Backend>(
    db: Db,
) -> TestResult {
    let secret = "close181-real-composition-secret-32";
    let (connection, store) = db.migrated::<B>(secret).await?;
    let events = Events::default();
    let cookie_b = Arc::new(Mutex::new(String::new()));
    let mut config = AuthConfig::new(secret).base_url("http://original.test");
    config.disabled_paths = vec!["/disabled".into()];
    let auth = AuthBuilder::<B::Schema>::new(config)
        .store(B::hook(store, StorageObserver(events.clone())))
        .endpoint_hook(Global(events.clone()))
        .plugin(Physical {
            events: events.clone(),
            cookie_b: cookie_b.clone(),
        })
        .plugin(Endpoint(events.clone()))
        .plugin(better_auth::plugins::EmailPasswordPlugin::new())
        .build()
        .await?;
    let mut cookies = Vec::new();
    let mut ids = Vec::new();
    for actor in ["a", "b"] {
        let mut req = AuthRequest::new(HttpMethod::Post, "/api/auth/sign-up/email");
        req.body=Some(json!({"email":format!("{actor}@composition.test"),"password":"Password123!","name":actor}).to_string().into_bytes());
        _ = req
            .headers
            .insert("content-type".into(), "application/json".into());
        let response = auth.handle_request(req).await?;
        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        cookies.push(
            response
                .headers
                .get_all("set-cookie")
                .find(|c| c.starts_with("better-auth.session_token="))
                .expect("real signup cookie")
                .split(';')
                .next()
                .expect("cookie pair")
                .to_owned(),
        );
        let body: Value = serde_json::from_slice(&response.body)?;
        ids.push(body["user"]["id"].as_str().expect("user id").to_owned());
    }
    *cookie_b.lock().expect("cookie") = cookies[1].clone();
    let accounts_before = db.table("accounts").await?;
    let sessions_before = db.table("sessions").await?;
    let users_before: Value = serde_json::from_str(&db.table("users").await?)?;
    let actor_a_before = users_before
        .as_array()
        .expect("physical users")
        .iter()
        .find(|user| user["id"] == ids[0])
        .expect("actor A")
        .clone();

    for selected in [
        "context-request",
        "replace",
        "no-patch",
        "handler-api",
        "handler-ordinary",
        "after-api",
        "after-ordinary",
        "response-replace",
        "response-api",
        "response-ordinary",
        "request-api",
        "request-ordinary",
        "early",
        "stop",
        "raw",
        "unknown",
        "disabled",
    ] {
        events.lock().expect("events").clear();
        let path = match selected {
            "replace" | "unknown" => "/absent",
            "disabled" => "/disabled",
            _ => "/write",
        };
        let mut req = AuthRequest::new(HttpMethod::Post, format!("/api/auth{path}")).with_url(
            url::Url::parse(&format!("http://original.test/api/auth{path}"))?,
        );
        req.body = Some(
            json!({"name":format!("original-{selected}")})
                .to_string()
                .into_bytes(),
        );
        req.headers = std::collections::HashMap::from([
            ("content-type".into(), "application/json".into()),
            ("origin".into(), "http://original.test".into()),
            (
                "cookie".into(),
                if selected == "replace" {
                    cookies[0].clone()
                } else {
                    cookies[1].clone()
                },
            ),
            ("x-mode".into(), selected.into()),
        ]);
        req.extensions().insert(Authority(ids[0].clone()));
        req.queue_response_header("set-cookie", "forged=yes");
        let result = auth.handle_request(req).await;
        let trace = events.lock().expect("events").clone();
        let stages = trace
            .iter()
            .filter_map(|e| e["stage"].as_str())
            .collect::<Vec<_>>();
        let a = db
            .text("SELECT name FROM users WHERE id = $1", &[&ids[0]])
            .await?;
        let b = db
            .text("SELECT name FROM users WHERE id = $1", &[&ids[1]])
            .await?;
        let output = match &result {
            Ok(r) => {
                json!({"status":r.status,"headers":r.headers.clone().into_iter().collect::<Vec<_>>(),"body":String::from_utf8_lossy(&r.body)})
            }
            Err(e) => json!({"rejected":true,"status":e.status_code(),"message":e.to_string()}),
        };
        eprintln!(
            "{}",
            json!({"backend":std::any::type_name::<B>(),"mode":selected,"result":output,"events":trace,"actors":ids,"rows":{"a":a,"b":b},"physicalUsers":db.count("users").await?,"physicalSessions":db.count("sessions").await?,"physicalRows":{"users":serde_json::from_str::<Value>(&db.table("users").await?)?,"accounts":serde_json::from_str::<Value>(&db.table("accounts").await?)?,"sessions":serde_json::from_str::<Value>(&db.table("sessions").await?)?}})
        );
        assert_eq!(a.as_deref(), Some("a"));
        assert_eq!(db.table("accounts").await?, accounts_before);
        assert_eq!(db.table("sessions").await?, sessions_before);
        let users: Value = serde_json::from_str(&db.table("users").await?)?;
        assert_eq!(
            users
                .as_array()
                .expect("physical users")
                .iter()
                .find(|user| user["id"] == ids[0])
                .expect("actor A"),
            &actor_a_before
        );

        assert_eq!(db.count("users").await?, 2);
        assert_eq!(db.count("sessions").await?, 2);
        assert!(trace.iter().all(|e| e["authority"] != true));
        if selected.starts_with("request-") {
            assert!(result.is_err());
            assert_eq!(stages, vec!["http-first"]);
            continue;
        }
        if selected.starts_with("response-") && selected != "response-replace" {
            assert!(result.is_err());
            assert_eq!(stages.last(), Some(&"http-response-first"));
            assert_eq!(b.as_deref(), Some("patched"));
            continue;
        }
        let response = result?;
        assert!(
            !response
                .headers
                .get_all("set-cookie")
                .any(|c| c.contains("obsolete") || c.contains("forged"))
        );
        if selected == "disabled" {
            assert_eq!(response.status, 404);
            assert!(stages.is_empty());
            continue;
        }
        if selected == "early" {
            assert_eq!(stages, vec!["http-first"]);
            continue;
        }
        if selected == "unknown" {
            assert_eq!(response.status, 404);
            assert_eq!(
                stages,
                vec![
                    "http-first",
                    "http-second",
                    "http-response-first",
                    "http-response-second"
                ]
            );
            continue;
        }
        if selected == "stop" {
            assert_eq!(
                stages,
                vec![
                    "http-first",
                    "http-second",
                    "global-before",
                    "http-response-first",
                    "http-response-second"
                ]
            );
            continue;
        }
        assert_eq!(
            trace
                .iter()
                .find(|e| e["stage"] == "handler")
                .expect("handler")["principal"],
            ids[1]
        );
        assert_eq!(
            trace
                .iter()
                .find(|e| e["stage"] == "handler")
                .expect("handler")["winner"],
            "plugin"
        );
        assert_eq!(
            b.as_deref(),
            Some(if selected == "no-patch" {
                "original-no-patch"
            } else {
                "patched"
            })
        );
        if selected == "handler-api" {
            assert_eq!(response.status, 403);
            assert_eq!(
                trace
                    .iter()
                    .find(|e| e["stage"] == "global-match-after")
                    .expect("matcher")["error"],
                true
            );
            assert_eq!(response.headers.get_all("set-cookie").count(), 1);
        }
        if selected == "handler-ordinary" || selected == "after-ordinary" {
            assert_eq!(response.status, 500);
            assert!(response.body.is_empty());
            assert!(response.headers.is_empty());
            assert!(!stages.contains(&"plugin-after"));
        }
        if selected == "raw" {
            assert!(!stages.contains(&"global-after"));
            assert!(!stages.contains(&"plugin-after"));
            assert!(stages.contains(&"http-response-second"));
        }
        if selected == "response-replace" {
            assert_eq!(response.status, 202);
            assert_eq!(response.body, b"replacement");
            assert!(!stages.contains(&"http-response-second"));
            assert_eq!(response.headers.get_all("set-cookie").count(), 0);
        }
        if selected == "context-request" {
            assert_eq!(
                trace
                    .iter()
                    .find(|e| e["stage"] == "plugin-after")
                    .expect("after hook")["path"],
                "/logical-patched"
            );
            let observed = trace
                .iter()
                .find(|e| e["stage"] == "db-before")
                .expect("storage observer");
            assert_eq!(observed["physical"], "/physical");
            assert_eq!(observed["url"], "http://patched.test/physical");
        }
        if selected == "replace" {
            let observed = trace
                .iter()
                .find(|e| e["stage"] == "db-before")
                .expect("storage observer");
            assert_eq!(observed["physical"], "/api/auth/write");
            assert_eq!(observed["url"], "http://replacement.test/api/auth/write");
            assert_eq!(observed["logical"], json!({"name":"patched"}));
        }
    }
    // CORS is a native transport extension outside Source's endpoint response.
    // Its final headers must survive the first physical response replacement.
    events.lock().expect("events").clear();
    let config = AuthConfig::new(secret).base_url("http://original.test");
    let cors_auth = AuthBuilder::<B::Schema>::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .cors(
            better_auth_core::middleware::CorsConfig::new().allowed_origin("http://original.test"),
        )
        .plugin(Physical {
            events: events.clone(),
            cookie_b: cookie_b.clone(),
        })
        .plugin(Endpoint(events.clone()))
        .build()
        .await?;
    let mut request = AuthRequest::new(HttpMethod::Post, "/api/auth/write");
    request.body = Some(br#"{"name":"cors"}"#.to_vec());
    request.headers = std::collections::HashMap::from([
        ("content-type".into(), "application/json".into()),
        ("origin".into(), "http://original.test".into()),
        ("cookie".into(), cookies[1].clone()),
        ("x-mode".into(), "response-replace".into()),
    ]);
    let response = cors_auth.handle_request(request).await?;
    assert_eq!(response.status, 202);
    assert_eq!(
        response
            .headers
            .get("access-control-allow-origin")
            .map(String::as_str),
        Some("http://original.test")
    );
    {
        let trace = events.lock().expect("events");
        assert_eq!(
            trace
                .iter()
                .find(|event| event["stage"] == "http-response-first")
                .expect("physical hook")["cors"],
            Value::Null
        );
    }
    B::close(connection).await
}
