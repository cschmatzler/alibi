//! Device authorization through real handlers and all three native stores.
use super::postgres_tests;
use super::{Backend, Db, TestResult, backend_tests};
use alibi::plugins::{DeviceAuthorizationPlugin, EmailPasswordPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthSchema, BetterAuth};
use alibi_core::{AuthRequest, AuthResponse, AuthSession, HttpMethod, UpdateDeviceCode};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::sync::Arc;

const SECRET: &str = "native-device-172-secret-at-least-32-characters";
const ORIGIN: &str = "http://localhost:43176";
backend_tests!(
    native_device_workflow,
    delayed_device_decisions,
    concurrent_device_redemption_issues_exactly_one_owned_session
);
postgres_tests!(
    native_device_workflow,
    concurrent_device_redemption_issues_exactly_one_owned_session
);

fn plugins<S: AuthSchema>(builder: AuthBuilder<S>) -> AuthBuilder<S> {
    builder
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(DeviceAuthorizationPlugin::new().interval(Duration::zero()))
}
fn body(response: &AuthResponse) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}
async fn call<S: AuthSchema>(
    auth: &BetterAuth<S>,
    trace: &mut Vec<Value>,
    path: &str,
    input: Option<Value>,
    cookie: &str,
    code: Option<&str>,
) -> TestResult<AuthResponse> {
    let mut req = AuthRequest::new(
        if input.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        path,
    );
    drop(req.headers.insert("origin".into(), ORIGIN.into()));
    drop(
        req.headers
            .insert("content-type".into(), "application/json".into()),
    );
    drop(req.headers.insert("cookie".into(), cookie.into()));
    req.body = input.map(|value| serde_json::to_vec(&value).unwrap());
    if let Some(code) = code {
        drop(req.query.insert("user_code".into(), code.into()));
    }
    let response = Box::pin(auth.handle_request(req)).await?;
    trace.push(json!({"path":path,"status":response.status,"body":String::from_utf8(response.body.clone())?}));
    Ok(response)
}
fn token(code: &str, client: &str) -> Value {
    json!({"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":code,"client_id":client})
}
async fn native_device_workflow<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session = config.session.stateless();
    let auth =
        plugins(AuthBuilder::new(config.clone()).store(B::store(Arc::new(config), &connection)))
            .build()
            .await?;
    drop(
        workflow(
            &auth,
            std::any::type_name::<B>().rsplit("::").next().unwrap(),
        )
        .await?,
    );
    assert_eq!(db.count("device_code").await?, 0);
    assert_eq!(db.count("sessions").await?, 0);
    B::close(connection).await
}
#[tokio::test]
async fn without_database_native_device_workflow() -> TestResult {
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = plugins(AuthBuilder::without_database(config.clone()))
        .build()
        .await?;
    let cookie = workflow(&auth, "without-database").await?;
    let mut trace = Vec::new();
    let issued = call(
        &auth,
        &mut trace,
        "/device/code",
        Some(json!({"client_id":"restart"})),
        "",
        None,
    )
    .await?;
    let code = body(&issued)["device_code"].as_str().unwrap().to_owned();
    let restarted = plugins(AuthBuilder::without_database(config))
        .build()
        .await?;
    let response = call(
        &restarted,
        &mut trace,
        "/device/token",
        Some(token(&code, "restart")),
        "",
        None,
    )
    .await?;
    assert_eq!(body(&response)["error"], "invalid_grant");
    assert!(
        auth.store()
            .get_device_code_by_device_code(&code)
            .await?
            .is_some()
    );
    let old = auth
        .store()
        .get_device_code_by_device_code(&code)
        .await?
        .unwrap();
    let review = call(
        &restarted,
        &mut trace,
        "/device",
        None,
        &cookie,
        Some(&old.user_code),
    )
    .await?;
    assert_eq!(body(&review)["error"], "invalid_request");
    let update = UpdateDeviceCode {
        status: Some("approved".into()),
        user_id: Some(Some("absent-owner".into())),
        ..Default::default()
    };
    assert!(matches!(
        restarted
            .store()
            .update_device_code(&old.id, update.clone())
            .await,
        Err(alibi_core::AuthError::NotFound(_))
    ));
    assert!(
        !restarted
            .store()
            .claim_device_code(&old.id, "absent-owner")
            .await?
    );
    assert!(
        !restarted
            .store()
            .update_device_code_if_status(&old.id, "pending", update)
            .await?
    );
    assert!(
        !restarted
            .store()
            .delete_device_code_if_status(&old.id, "approved")
            .await?
    );
    restarted.store().delete_device_code(&old.id).await?;
    assert!(
        restarted
            .store()
            .get_device_code_by_device_code(&code)
            .await?
            .is_none()
    );
    assert!(
        restarted
            .store()
            .get_device_code_by_user_code(&old.user_code)
            .await?
            .is_none()
    );
    if let Ok(dir) = std::env::var("DEVICE_172_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&dir).join("native-restart-workflow.json"),
            serde_json::to_vec_pretty(&trace)?,
        )?;
        std::fs::write(
            std::path::Path::new(&dir).join("native-record-effects.json"),
            serde_json::to_vec_pretty(
                &json!({"restartLost":true,"originalRetained":true,"missingUpdate":"NotFound","missingClaim":false,"missingDecision":false,"missingConsume":false,"freshRecord":null}),
            )?,
        )?;
    }
    Ok(())
}
async fn workflow<S: AuthSchema>(auth: &BetterAuth<S>, backend: &str) -> TestResult<String> {
    let mut trace = Vec::new();
    let mut cookies = Vec::new();
    for name in ["owner", "other"] {
        let signup = call(auth, &mut trace, "/sign-up/email", Some(json!({"email":format!("{name}@example.com"),"name":name,"password":"Password123!"})), "", None).await?;
        assert_eq!(signup.status, 200);
        cookies.push(
            signup
                .headers
                .get_all("set-cookie")
                .map(|value| value.split(';').next().unwrap())
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    for decision in ["approve", "deny"] {
        let issued = call(
            auth,
            &mut trace,
            "/device/code",
            Some(json!({"client_id":"console","scope":"profile raw"})),
            "",
            None,
        )
        .await?;
        assert_eq!(
            issued.status,
            200,
            "native device issuance must work: {}",
            body(&issued)
        );
        let issued = body(&issued);
        let device = issued["device_code"].as_str().unwrap();
        let user_code = issued["user_code"].as_str().unwrap();
        let row = auth
            .store()
            .get_device_code_by_device_code(device)
            .await?
            .unwrap();
        assert_eq!(row.scope.as_deref(), Some("profile raw"));
        assert_eq!(row.client_id.as_deref(), Some("console"));
        assert!(row.user_id.is_none());
        let wrong_client = call(
            auth,
            &mut trace,
            "/device/token",
            Some(token(device, "other")),
            "",
            None,
        )
        .await?;
        assert_eq!(body(&wrong_client)["error"], "invalid_grant");
        assert!(
            auth.store()
                .get_device_code_by_device_code(device)
                .await?
                .unwrap()
                .last_polled_at
                .is_none()
        );
        let pending = call(
            auth,
            &mut trace,
            "/device/token",
            Some(token(device, "console")),
            "",
            None,
        )
        .await?;
        assert_eq!(body(&pending)["error"], "authorization_pending");
        let anonymous = call(auth, &mut trace, "/device", None, "", Some(user_code)).await?;
        assert!(body(&anonymous).get("scope").is_none());
        let unclaimed = call(
            auth,
            &mut trace,
            "/device/approve",
            Some(json!({"userCode":user_code})),
            &cookies[0],
            None,
        )
        .await?;
        assert_eq!(body(&unclaimed)["error"], "invalid_request");
        let claimed = call(
            auth,
            &mut trace,
            "/device",
            None,
            &cookies[0],
            Some(user_code),
        )
        .await?;
        assert_eq!(body(&claimed)["scope"], "profile raw");
        let owner = auth
            .store()
            .get_device_code_by_user_code(user_code)
            .await?
            .unwrap()
            .user_id
            .unwrap();
        let other = call(
            auth,
            &mut trace,
            "/device",
            None,
            &cookies[1],
            Some(user_code),
        )
        .await?;
        assert!(body(&other).get("scope").is_none());
        let forbidden = call(
            auth,
            &mut trace,
            &format!("/device/{decision}"),
            Some(json!({"userCode":user_code})),
            &cookies[1],
            None,
        )
        .await?;
        assert_eq!(forbidden.status, 403);
        assert_eq!(
            auth.store()
                .get_device_code_by_user_code(user_code)
                .await?
                .unwrap()
                .user_id
                .as_deref(),
            Some(owner.as_str())
        );
        let decided = call(
            auth,
            &mut trace,
            &format!("/device/{decision}"),
            Some(json!({"userCode":user_code})),
            &cookies[0],
            None,
        )
        .await?;
        assert_eq!(decided.status, 200);
        let repeated = call(
            auth,
            &mut trace,
            "/device/deny",
            Some(json!({"userCode":user_code})),
            &cookies[0],
            None,
        )
        .await?;
        assert_eq!(body(&repeated)["error"], "invalid_request");
        let redeemed = call(
            auth,
            &mut trace,
            "/device/token",
            Some(token(device, "console")),
            "",
            None,
        )
        .await?;
        if decision == "approve" {
            assert_eq!(redeemed.status, 200);
            assert_eq!(body(&redeemed)["scope"], "profile raw");
            let access = body(&redeemed)["access_token"].as_str().unwrap().to_owned();
            assert_eq!(
                auth.store().get_session(&access).await?.unwrap().user_id(),
                owner
            );
        } else {
            assert_eq!(body(&redeemed)["error"], "access_denied");
        }
        assert!(
            auth.store()
                .get_device_code_by_device_code(device)
                .await?
                .is_none()
        );
        let replay = call(
            auth,
            &mut trace,
            "/device/token",
            Some(token(device, "console")),
            "",
            None,
        )
        .await?;
        assert_eq!(body(&replay)["error"], "invalid_grant");
    }
    // Seed an expired row through the public store, avoiding wall-clock sleeps.
    let expired = auth
        .store()
        .create_device_code(alibi_core::CreateDeviceCode {
            device_code: "expired-device".into(),
            user_code: "EXPIRED".into(),
            user_id: None,
            expires_at: Utc::now() - Duration::seconds(1),
            status: "pending".into(),
            last_polled_at: None,
            polling_interval: Some(5000),
            client_id: Some("console".into()),
            scope: None,
        })
        .await?;
    let expiry = call(
        auth,
        &mut trace,
        "/device",
        None,
        &cookies[0],
        Some("EXPIRED"),
    )
    .await?;
    assert_eq!(body(&expiry)["error"], "expired_token", "{}", body(&expiry));
    assert!(
        !auth
            .store()
            .delete_device_code_if_status(&expired.id, "approved")
            .await?
    );
    let expiry = call(
        auth,
        &mut trace,
        "/device/token",
        Some(token("expired-device", "console")),
        "",
        None,
    )
    .await?;
    assert_eq!(body(&expiry)["error"], "expired_token", "{}", body(&expiry));
    assert!(
        auth.store()
            .get_device_code_by_user_code("EXPIRED")
            .await?
            .is_none()
    );
    if let Ok(dir) = std::env::var("DEVICE_172_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&dir).join(format!("{backend}-workflow.json")),
            serde_json::to_vec_pretty(&trace)?,
        )?;
    }
    Ok(cookies.remove(0))
}

// A real SQLite writer lock delays decision writes, but does not order reads.
// The source custom-adapter barrier separately pins both reads to pending.
async fn delayed_device_decisions<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth =
        plugins(AuthBuilder::new(config.clone()).store(B::store(Arc::new(config), &connection)))
            .build()
            .await?;
    let mut trace = Vec::new();
    let signup = call(
        &auth,
        &mut trace,
        "/sign-up/email",
        Some(json!({
            "email":"decision-owner@example.com", "name":"Owner", "password":"Password123!"
        })),
        "",
        None,
    )
    .await?;
    assert_eq!(signup.status, 200);
    let owner = body(&signup)["user"]["id"].as_str().unwrap().to_owned();
    let cookie = signup
        .headers
        .get("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let original_users = db.raw.table("users").await?;
    let original_accounts = db.raw.table("accounts").await?;
    let mut effects = Vec::new();
    for reverse in [false, true] {
        let issued = call(
            &auth,
            &mut trace,
            "/device/code",
            Some(json!({"client_id":"console", "scope":"profile raw"})),
            "",
            None,
        )
        .await?;
        let issued = body(&issued);
        let device = issued["device_code"].as_str().unwrap();
        let user = issued["user_code"].as_str().unwrap();
        assert_eq!(
            call(&auth, &mut trace, "/device", None, &cookie, Some(user))
                .await?
                .status,
            200
        );
        let before = db
            .raw
            .tables(&["device_code", "users", "accounts", "sessions"])
            .await?;
        let session_count = db.count("sessions").await?;
        let super::Raw::Sqlite(pool) = &db.raw else {
            return Err("delayed writer probe requires SQLite".into());
        };
        let mut writer = pool.acquire().await?;
        _ = sqlx::query(sqlx::AssertSqlSafe("BEGIN IMMEDIATE"))
            .execute(&mut *writer)
            .await?;
        let mut approve_trace = Vec::new();
        let mut deny_trace = Vec::new();
        let (approve, deny) = {
            let approve = call(
                &auth,
                &mut approve_trace,
                "/device/approve",
                Some(json!({"userCode":user})),
                &cookie,
                None,
            );
            let deny = call(
                &auth,
                &mut deny_trace,
                "/device/deny",
                Some(json!({"userCode":user})),
                &cookie,
                None,
            );
            let decisions = async {
                if reverse {
                    let (deny, approve) = tokio::join!(deny, approve);
                    (approve, deny)
                } else {
                    tokio::join!(approve, deny)
                }
            };
            tokio::pin!(decisions);
            // A validation rejection would finish during this window. Neither write can
            // complete while the independent physical writer lock remains held.
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(250), &mut decisions)
                    .await
                    .is_err()
            );
            _ = sqlx::query(sqlx::AssertSqlSafe("COMMIT"))
                .execute(&mut *writer)
                .await?;
            drop(writer);
            tokio::time::timeout(std::time::Duration::from_secs(5), decisions).await?
        };
        let approve = approve?;
        let deny = deny?;
        trace.extend(approve_trace);
        trace.extend(deny_trace);
        let decided = db
            .raw
            .tables(&["device_code", "users", "accounts", "sessions"])
            .await?;
        effects.push(json!({"reverse":reverse,"heldMillis":250,"before":before,"decided":decided,"approve":approve.status,"deny":deny.status}));
        if let Ok(directory) = std::env::var("DEVICE_213_EVIDENCE") {
            std::fs::write(
                format!(
                    "{directory}/{}-decisions.json",
                    std::any::type_name::<B>().rsplit("::").next().unwrap()
                ),
                serde_json::to_vec_pretty(&json!({"trace":trace,"effects":effects}))?,
            )?;
        }
        // The writer lock delays mutations, but it is not a read barrier: under
        // load one request may fetch the row only after the other's write.
        // That request must reject the already-processed code, not overwrite it.
        assert!(
            matches!(
                (approve.status, deny.status),
                (200, 200) | (200, 400) | (400, 200)
            ),
            "approve: {:?}; deny: {:?}",
            body(&approve),
            body(&deny)
        );
        for response in [&approve, &deny] {
            assert_eq!(
                body(response),
                if response.status == 200 {
                    json!({"success":true})
                } else {
                    json!({"error":"invalid_request", "error_description":"Device code already processed"})
                }
            );
        }
        let row = auth
            .store()
            .get_device_code_by_device_code(device)
            .await?
            .unwrap();
        assert_eq!(row.user_id.as_deref(), Some(owner.as_str()));
        assert!(matches!(row.status.as_str(), "approved" | "denied"));
        if approve.status == 400 {
            assert_eq!(row.status, "denied");
        }
        if deny.status == 400 {
            assert_eq!(row.status, "approved");
        }
        assert_eq!(
            call(
                &auth,
                &mut trace,
                "/device/approve",
                Some(json!({"userCode":user})),
                &cookie,
                None
            )
            .await?
            .status,
            400
        );
        let redeemed = call(
            &auth,
            &mut trace,
            "/device/token",
            Some(token(device, "console")),
            "",
            None,
        )
        .await?;
        if row.status == "approved" {
            assert_eq!(redeemed.status, 200);
            assert_eq!(body(&redeemed)["scope"], "profile raw");
            let token = body(&redeemed)["access_token"].as_str().unwrap().to_owned();
            use alibi_core::AuthSession;
            assert_eq!(
                auth.store()
                    .get_session(&token)
                    .await?
                    .unwrap()
                    .user_id()
                    .as_ref(),
                owner
            );
        } else {
            assert_eq!(body(&redeemed)["error"], "access_denied");
        }
        assert_eq!(
            db.count("sessions").await?,
            session_count + i64::from(row.status == "approved")
        );
        assert_eq!(db.count("device_code").await?, 0);
        assert_eq!(db.raw.table("users").await?, original_users);
        assert_eq!(db.raw.table("accounts").await?, original_accounts);
        assert_eq!(
            body(
                &call(
                    &auth,
                    &mut trace,
                    "/device/token",
                    Some(token(device, "console")),
                    "",
                    None
                )
                .await?
            )["error"],
            "invalid_grant"
        );
        effects.push(
            json!({"after":db.raw.tables(&["device_code","users","accounts","sessions"]).await?}),
        );
    }
    if let Ok(directory) = std::env::var("DEVICE_213_EVIDENCE") {
        std::fs::write(
            format!(
                "{directory}/{}-decisions.json",
                std::any::type_name::<B>().rsplit("::").next().unwrap()
            ),
            serde_json::to_vec_pretty(&json!({"trace":trace,"effects":effects}))?,
        )?;
    }
    B::close(connection).await
}

#[tokio::test]
async fn device_form_admission_and_error_cache_headers_follow_handler_entry() -> TestResult {
    let auth = plugins(AuthBuilder::without_database(
        AuthConfig::new(SECRET).base_url(ORIGIN),
    ))
    .build()
    .await?;
    for (content_type, input, status, cache_header) in [
        (
            "application/x-www-form-urlencoded",
            "client_id=console&scope=profile+email",
            200,
            true,
        ),
        (
            "application/x-www-form-urlencoded",
            "client_id=console&client_id=",
            200,
            true,
        ),
        (
            "application/x-www-form-urlencoded",
            "client_id=console&client_id=other",
            400,
            true,
        ),
        (
            "application/x-www-form-urlencoded",
            "scope=profile",
            400,
            false,
        ),
        ("application/json", r#"{"client_id":17}"#, 400, false),
        ("text/plain", "client_id=console", 415, false),
        ("application/json", r#"{"client_id":""}"#, 400, true),
    ] {
        let mut req = AuthRequest::new(HttpMethod::Post, "/device/code");
        drop(
            req.headers
                .insert("content-type".into(), content_type.into()),
        );
        req.body = Some(input.as_bytes().to_vec());
        let response = Box::pin(auth.handle_request(req)).await?;
        assert_eq!(response.status, status, "{input}: {}", body(&response));
        assert_eq!(
            response.headers.get("cache-control").map(String::as_str),
            cache_header.then_some("no-store"),
            "{input}"
        );
        assert_eq!(
            response.headers.get("pragma").map(String::as_str),
            cache_header.then_some("no-cache"),
            "{input}"
        );
        if status == 200 {
            let result = body(&response);
            let code = result["device_code"].as_str().unwrap();
            let stored = auth
                .store()
                .get_device_code_by_device_code(code)
                .await?
                .unwrap();
            assert_eq!(stored.client_id.as_deref(), Some("console"));
            assert_eq!(
                stored.scope.as_deref(),
                input.contains("scope=").then_some("profile email")
            );
            assert_eq!(stored.user_code, result["user_code"]);
        }
    }
    for (content_type, input, header) in [
        (
            "application/json",
            token("unissued", "console").to_string(),
            true,
        ),
        (
            "application/json",
            json!({"grant_type":"wrong","device_code":"unissued","client_id":"console"})
                .to_string(),
            false,
        ),
        (
            "application/x-www-form-urlencoded",
            "grant_type=wrong&device_code=unissued&client_id=console".into(),
            false,
        ),
    ] {
        let mut req = AuthRequest::new(HttpMethod::Post, "/device/token");
        drop(
            req.headers
                .insert("content-type".into(), content_type.into()),
        );
        req.body = Some(input.into_bytes());
        let response = Box::pin(auth.handle_request(req)).await?;
        assert_eq!(
            response.status,
            if content_type == "application/json" {
                400
            } else {
                415
            }
        );
        assert_eq!(
            response.headers.get("cache-control").map(String::as_str),
            header.then_some("no-store")
        );
        assert_eq!(
            response.headers.get("pragma").map(String::as_str),
            header.then_some("no-cache")
        );
        if header {
            assert_eq!(body(&response)["error"], "invalid_grant");
        }
    }
    Ok(())
}

async fn concurrent_device_redemption_issues_exactly_one_owned_session<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth =
        plugins(AuthBuilder::new(config.clone()).store(B::store(Arc::new(config), &connection)))
            .build()
            .await?;
    let mut trace = Vec::new();
    let owner=call(&auth,&mut trace,"/sign-up/email",Some(json!({"email":"device-race@example.test","name":"Device owner","password":"Password123!"})),"",None).await?;
    assert_eq!(owner.status, 200);
    let cookie = owner
        .headers
        .get_all("set-cookie")
        .map(|cookie| cookie.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    let user = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let issued = call(
        &auth,
        &mut trace,
        "/device/code",
        Some(json!({"client_id":"console"})),
        "",
        None,
    )
    .await?;
    let issued = body(&issued);
    let user_code = issued["user_code"].as_str().unwrap();
    let device_code = issued["device_code"].as_str().unwrap();
    let claimed = call(&auth, &mut trace, "/device", None, &cookie, Some(user_code)).await?;
    assert_eq!(claimed.status, 200);
    let approved = call(
        &auth,
        &mut trace,
        "/device/approve",
        Some(json!({"userCode":user_code})),
        &cookie,
        None,
    )
    .await?;
    assert_eq!(body(&approved)["success"], true);
    let mut req = AuthRequest::new(HttpMethod::Post, "/device/token");
    drop(
        req.headers
            .insert("content-type".into(), "application/json".into()),
    );
    req.body = Some(serde_json::to_vec(&token(device_code, "console"))?);
    let (left, right) = tokio::join!(
        Box::pin(auth.handle_request(req.clone())),
        Box::pin(auth.handle_request(req.clone()))
    );
    let responses = [left?, right?];
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.status == 200)
            .count(),
        1
    );
    let denied = responses
        .iter()
        .find(|response| response.status != 200)
        .unwrap();
    assert_eq!(denied.status, 400);
    assert_eq!(body(denied)["error"], "invalid_grant");
    let issued = responses
        .iter()
        .find(|response| response.status == 200)
        .unwrap();
    let access = body(issued)["access_token"].as_str().unwrap().to_owned();
    assert_eq!(
        auth.store().get_session(&access).await?.unwrap().user_id(),
        user
    );
    assert_eq!(
        db.count("sessions").await?,
        2,
        "signup plus exactly one redeemed session"
    );
    assert_eq!(db.count("device_code").await?, 0);
    let persisted = db.table("sessions").await?;
    let replay = Box::pin(auth.handle_request(req)).await?;
    assert_eq!(body(&replay)["error"], "invalid_grant");
    assert_eq!(db.table("sessions").await?, persisted);
    B::close(connection).await
}
