//! Request-local linking authority through real callbacks and both physical stores.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "endpoint regression setup and independent storage receipts fail fast"
)]
use crate::storage::{Backend, Db, Raw, TestResult, backend_tests, postgres_tests};
use alibi::config::{BaseUrlProtocol, DynamicBaseUrl, TrustedProvidersResolver};
use alibi::entity::{AuthAccount, AuthSession, AuthUser};
use alibi::plugins::{OAuthPlugin, oauth::OAuthProvider};
use alibi::{AuthBuilder, AuthConfig, BetterAuth};
use alibi::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, CreateAccount, CreateUser, HttpMethod, SessionManager,
};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
const SECRET: &str = "request-provider-fixture-secret-at-least-32";
backend_tests!(dynamic_provider_callbacks);
postgres_tests!(dynamic_provider_callbacks);

#[derive(Clone)]
struct TrustPolicy {
    calls: Arc<Mutex<Vec<String>>>,
    barrier: Arc<tokio::sync::Barrier>,
}
#[async_trait]
impl TrustedProvidersResolver for TrustPolicy {
    async fn resolve(&self, req: Option<&AuthRequest>) -> AuthResult<Vec<String>> {
        let Some(req) = req else {
            self.calls.lock().unwrap().push("init".into());
            return Ok(vec!["init-only".into()]);
        };
        assert!(req.url().is_some());
        self.calls.lock().unwrap().push(format!(
            "{}:{}",
            req.path(),
            req.header("x-trust").unwrap()
        ));
        if req.header("x-overlap").is_some() {
            let _ = self.barrier.wait().await;
        }
        match req.header("x-trust").map(String::as_str) {
            Some("allow") => Ok(vec!["gitlab".into(), String::new()]),
            Some("error") => Err(AuthError::internal("private-provider-policy-secret")),
            Some("api-error") => Err(AuthError::forbidden("private-provider-api-error")),
            _ => Ok(vec![]),
        }
    }
}
struct PolicyProbe;
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for PolicyProbe {
    fn name(&self) -> &'static str {
        "trust-policy-probe"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![]
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn on_http_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        let expected = if req.header("x-trust").map(String::as_str) == Some("allow") {
            vec!["gitlab"]
        } else {
            vec![]
        };
        assert_eq!(
            ctx.config.account.account_linking.trusted_providers,
            expected
        );
        assert_eq!(
            ctx.config.base_url,
            format!("https://{}", req.header("host").unwrap())
        );
        Ok(None)
    }
}
fn req(method: HttpMethod, path: &str, host: &str, trust: &str, body: Value) -> AuthRequest {
    let mut r = AuthRequest::new(method, format!("/api/auth{path}"));
    r.headers.extend([
        ("host".into(), host.into()),
        ("origin".into(), format!("https://{host}")),
        ("x-trust".into(), trust.into()),
        ("content-type".into(), "application/json".into()),
    ]);
    r.body = Some(body.to_string().into_bytes());
    r.with_url(url::Url::parse(&format!("https://{host}/api/auth{path}")).unwrap())
}
// Keep the composed callback scenario's polling frame small on the default
// test-thread stack; dispatch still executes the same public request boundary.
async fn dispatch<S: AuthSchema>(
    auth: &BetterAuth<S>,
    request: AuthRequest,
) -> AuthResult<AuthResponse> {
    Box::pin(auth.handle_request(request)).await
}
async fn issuer() -> (String, tokio::task::JoinHandle<()>, Arc<Mutex<Vec<Value>>>) {
    use axum::{
        Form, Json, Router,
        http::HeaderMap,
        routing::{get, post},
    };
    let receipts = Arc::new(Mutex::new(vec![]));
    let tokens = receipts.clone();
    let profiles = receipts.clone();
    let app = Router::new().route("/oauth/token", post(move |Form(form): Form<std::collections::HashMap<String,String>>| {
        let receipts = tokens.clone(); async move {
            receipts.lock().unwrap().push(json!({"tokenForm":form}));
            Json(json!({"access_token":form["code"],"token_type":"Bearer","scope":"read_user"}))
        }
    })).route("/api/v4/user", get(move |headers: HeaderMap| { let receipts = profiles.clone(); async move {
        let code = headers.get("authorization").unwrap().to_str().unwrap().strip_prefix("Bearer ").unwrap();
        let profile = json!({"id":code,"email":format!("{code}@example.test"),"name":code,"state":"active","locked":false,"email_verified":false});
        receipts.lock().unwrap().push(json!({"profile":profile})); Json(profile)
    }}));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, handle, receipts)
}
async fn start<S: AuthSchema>(
    auth: &BetterAuth<S>,
    code: &str,
    trust: &str,
    cookie: Option<&str>,
) -> (String, String, Value) {
    let path = if cookie.is_some() {
        "/link-social"
    } else {
        "/sign-in/social"
    };
    let mut r = req(
        HttpMethod::Post,
        path,
        "a.example.test",
        trust,
        json!({"provider":"gitlab","callbackURL":"https://a.example.test/done","errorCallbackURL":"https://a.example.test/failed","disableRedirect":true}),
    );
    if let Some(cookie) = cookie {
        _ = r.headers.insert("cookie".into(), cookie.into());
    }
    let response = dispatch(auth, r).await.unwrap();
    assert_eq!(
        response.status,
        200,
        "{code}: {:?}",
        String::from_utf8_lossy(&response.body)
    );
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    let u = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    assert!(u.path().ends_with("/oauth/authorize"));
    let params: std::collections::HashMap<String, String> = u.query_pairs().into_owned().collect();
    assert_eq!(params["scope"], "read_user");
    assert_eq!(params["client_id"], "fixture-client");
    assert_eq!(
        params["redirect_uri"],
        "https://a.example.test/api/auth/callback/gitlab"
    );
    let cookies = response
        .headers
        .get_all("set-cookie")
        .map(|v| v.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    (params["state"].clone(), cookies, body)
}
fn callback(code: &str, host: &str, trust: &str, state: &str, cookies: &str) -> AuthRequest {
    let mut r = req(
        HttpMethod::Get,
        "/callback/gitlab",
        host,
        trust,
        Value::Null,
    );
    r.query
        .extend([("state".into(), state.into()), ("code".into(), code.into())]);
    _ = r.headers.insert("cookie".into(), cookies.into());
    r
}
async fn physical_account(db: &Db, id: &str) -> TestResult<Value> {
    use alibi::sqlx::sqlx::{self, Row};
    Ok(crate::storage::on_raw!(&db.raw, |pool| {
        let row = sqlx::query(sqlx::AssertSqlSafe(String::from(
            "SELECT id, user_id, account_id, access_token, scope FROM accounts WHERE id=$1",
        )))
        .bind(id)
        .fetch_one(pool)
        .await?;
        json!({"id":row.try_get::<String,_>("id")?,
            "userId":row.try_get::<String,_>("user_id")?,
            "accountId":row.try_get::<String,_>("account_id")?,
            "accessToken":row.try_get::<String,_>("access_token")?,
            "scope":row.try_get::<String,_>("scope")?})
    }))
}
async fn dynamic_provider_callbacks<B: Backend>(db: Db) -> TestResult {
    struct InitFailure;
    #[async_trait]
    impl TrustedProvidersResolver for InitFailure {
        async fn resolve(&self, request: Option<&AuthRequest>) -> AuthResult<Vec<String>> {
            assert!(request.is_none());
            Err(AuthError::internal("initial trust failure"))
        }
    }
    let initialization = AuthBuilder::<B::Schema>::new(
        AuthConfig::new(SECRET).trusted_providers_resolver(InitFailure),
    )
    .build()
    .await;
    assert!(
        matches!(initialization, Err(AuthError::Internal(ref message)) if message == "initial trust failure")
    );
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = TrustPolicy {
        calls: Arc::new(Mutex::new(vec![])),
        barrier: Arc::new(tokio::sync::Barrier::new(2)),
    };
    let mut cfg = AuthConfig::new(SECRET)
        .dynamic_base_url(DynamicBaseUrl {
            allowed_hosts: vec!["*.example.test".into()],
            protocol: Some(BaseUrlProtocol::Https),
            fallback: None,
        })
        .trusted_providers_resolver(policy.clone());

    cfg.account.account_linking.trusted_providers = vec!["gitlab".into()]; // callback replaces, never extends
    let (issuer, server, provider_receipts) = issuer().await;
    let auth = AuthBuilder::<B::Schema>::new(cfg.clone())
        .store(B::store(Arc::new(cfg), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig {
            enabled: false,
            ..Default::default()
        })
        .plugin(PolicyProbe)
        .plugin(OAuthPlugin::new().add_provider(
            "gitlab",
            OAuthProvider::gitlab_with_issuer("fixture-client", "fixture-secret", &issuer),
        ))
        .build()
        .await?;
    assert_eq!(*policy.calls.lock().unwrap(), vec!["init"]);
    assert_eq!(
        auth.config().account.account_linking.trusted_providers,
        vec!["init-only"]
    );
    for code in [
        "deny",
        "allow",
        "parallel-deny",
        "parallel-allow",
        "actor",
        "foreign",
    ] {
        _ = auth
            .store()
            .create_user(
                CreateUser::new()
                    .with_email(format!("{code}@example.test"))
                    .with_name(code)
                    .with_email_verified(true),
            )
            .await?;
    }
    let mut receipts = vec![];
    for (code, start_trust, callback_trust, allowed) in [
        ("deny", "allow", "deny", false),
        ("allow", "deny", "allow", true),
    ] {
        let (state, cookies, start) = start(&auth, code, start_trust, None).await;
        let response = dispatch(
            &auth,
            callback(code, "a.example.test", callback_trust, &state, &cookies),
        )
        .await?;
        assert_eq!(response.status, 302);
        let location = response.headers.get("location").unwrap();
        assert_eq!(
            location,
            if allowed {
                "https://a.example.test/done"
            } else {
                "https://a.example.test/failed?error=account_not_linked"
            }
        );
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM accounts WHERE provider_id='gitlab' AND account_id=$1",
                &[code]
            )
            .await?,
            i64::from(allowed)
        );
        assert!(
            auth.store()
                .get_verification_by_identifier(&state)
                .await?
                .is_none()
        );
        let replay = dispatch(
            &auth,
            callback(code, "a.example.test", callback_trust, &state, &cookies),
        )
        .await?;
        assert!(!replay.headers.get("location").unwrap().ends_with("/done"));
        receipts.push(json!({"case":code,"start":start,"callbackLocation":location,"cookies":response.headers.get_all("set-cookie").collect::<Vec<_>>(),"replay":replay.headers.get("location")}));
    }
    let (ds, dc, _) = start(&auth, "parallel-deny", "allow", None).await;
    let (as_, ac, _) = start(&auth, "parallel-allow", "deny", None).await;
    let mut denied = callback("parallel-deny", "a.example.test", "deny", &ds, &dc);
    let mut allowed = callback("parallel-allow", "b.example.test", "allow", &as_, &ac);
    _ = denied.headers.insert("x-overlap".into(), "yes".into());
    _ = allowed.headers.insert("x-overlap".into(), "yes".into());
    let (denied, allowed) = tokio::join!(dispatch(&auth, denied), dispatch(&auth, allowed));
    assert_eq!(
        denied?.headers.get("location").unwrap(),
        "https://a.example.test/failed?error=account_not_linked"
    );
    assert_eq!(
        allowed?.headers.get("location").unwrap(),
        "https://a.example.test/done"
    );
    assert_eq!(db.count("accounts").await?, 2);
    assert_eq!(db.count("sessions").await?, 2);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM accounts WHERE account_id='parallel-deny'",
            &[]
        )
        .await?,
        0
    );
    // A trusted callback must not transfer a provider identity already owned by another actor.
    let foreign = auth
        .store()
        .get_user_by_email("foreign@example.test")
        .await?
        .unwrap();
    let foreign_account = auth
        .store()
        .create_account(CreateAccount {
            additional_fields: Default::default(),
            user_id: foreign.id().to_string(),
            account_id: "actor".into(),
            provider_id: "gitlab".into(),
            access_token: Some("foreign-token".into()),
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: Some("foreign-scope".into()),
            password: None,
        })
        .await?;
    let foreign_before = physical_account(&db, foreign_account.id().as_ref()).await?;
    let actor = auth
        .store()
        .get_user_by_email("actor@example.test")
        .await?
        .unwrap();
    let session = SessionManager::new(Arc::new(auth.config().clone()), auth.store().clone())
        .create_session(&actor, None, None)
        .await?;
    let session_cookie = format!(
        "__Secure-better-auth.session_token={}",
        alibi::utils::cookie_utils::sign_cookie_value(session.token(), SECRET)
    );
    let (state, cookies, start) = start(&auth, "actor", "allow", Some(&session_cookie)).await;
    let cookies = format!("{cookies}; {session_cookie}");
    let foreign_result = dispatch(
        &auth,
        callback("actor", "a.example.test", "allow", &state, &cookies),
    )
    .await?;
    assert_eq!(
        foreign_result.headers.get("location").unwrap(),
        "https://a.example.test/failed?error=account_already_linked_to_different_user"
    );
    let unchanged = auth.store().get_account("gitlab", "actor").await?.unwrap();
    assert_eq!(unchanged.id(), foreign_account.id());
    assert_eq!(unchanged.user_id(), foreign.id());
    assert_eq!(unchanged.access_token(), Some("foreign-token"));
    assert_eq!(unchanged.scope(), Some("foreign-scope"));
    let foreign_after = physical_account(&db, foreign_account.id().as_ref()).await?;
    assert_eq!(foreign_before, foreign_after);
    receipts.push(json!({"case":"foreign","start":start,"callbackLocation":foreign_result.headers.get("location"),"physicalBefore":foreign_before,"physicalAfter":foreign_after}));
    assert_eq!(db.count_where(
        "SELECT COUNT(*) FROM accounts WHERE id=$1 AND user_id=$2 AND access_token='foreign-token' AND scope='foreign-scope'",
        &[foreign_account.id().as_ref(), foreign.id().as_ref()],
    ).await?, 1);
    for mode in ["error", "api-error"] {
        let calls_before = policy.calls.lock().unwrap().len();
        let failed = dispatch(
            &auth,
            req(
                HttpMethod::Post,
                "/sign-in/social",
                "a.example.test",
                mode,
                json!({"provider":"gitlab"}),
            ),
        )
        .await?;
        assert_eq!(failed.status, 500);
        assert!(failed.body.is_empty());
        assert_eq!(policy.calls.lock().unwrap().len(), calls_before + 1);
    }
    assert_eq!(db.count("accounts").await?, 3);
    assert_eq!(db.count("sessions").await?, 3);
    assert_eq!(db.count("users").await?, 6);
    assert_eq!(
        auth.config().account.account_linking.trusted_providers,
        vec!["init-only"]
    );
    if let Ok(dir) = std::env::var("CLOSE178_EVIDENCE_DIR") {
        std::fs::write(
            format!(
                "{dir}/{}.json",
                std::any::type_name::<B>().rsplit("::").next().unwrap()
            ),
            serde_json::to_vec_pretty(
                &json!({"callbacks":receipts,"policyCalls":*policy.calls.lock().unwrap(),"providerHTTP":*provider_receipts.lock().unwrap(),"physical":{"users":db.count("users").await?,"accounts":db.count("accounts").await?,"sessions":db.count("sessions").await?}}),
            )?,
        )?;
    }
    server.abort();
    B::close(connection).await?;
    Ok(())
}
