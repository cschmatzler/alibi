//! Stateless lifecycle owner: actual adapters protect cookie-only and durable modes.
use super::{Backend, Db, TestResult, backend_tests};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::{AuthRequest, AuthResponse, CookieRefreshCache, HttpMethod};
use serde_json::{Value, json};
use std::sync::Arc;

const SECRET: &str = "stateless-172-secret-minimum-32-characters";
const ORIGIN: &str = "http://localhost:43172";
backend_tests!(stateless_session_lifecycle, stateless_policy_boundaries);

struct SkipRefresh;
#[async_trait::async_trait]
impl<S: better_auth::AuthSchema> better_auth_core::AuthPlugin<S> for SkipRefresh {
    fn name(&self) -> &'static str {
        "fixture-skip-refresh"
    }
    fn routes(&self) -> Vec<better_auth_core::AuthRoute> {
        Vec::new()
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        _ctx: &better_auth_core::AuthContext<S>,
    ) -> better_auth_core::AuthResult<Option<better_auth_core::BeforeRequestAction>> {
        if req
            .headers
            .get("x-fixture-skip-refresh")
            .is_some_and(|value| value == "1")
        {
            req.extensions()
                .insert(better_auth_core::session::SessionRefreshSuppressed);
        }
        Ok(None)
    }
    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &better_auth_core::AuthContext<S>,
    ) -> better_auth_core::AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn request(path: &str, body: Option<Value>, cookie: &str) -> AuthRequest {
    let mut req = AuthRequest::new(
        if body.is_some() {
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
    req.body = body.map(|value| serde_json::to_vec(&value).unwrap());
    req
}
fn body(response: &AuthResponse) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}
fn cookies(response: &AuthResponse) -> String {
    response
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}

async fn stateless_session_lifecycle<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session = config.session.stateless();
    config.session.defer_session_refresh = true;
    config.session.disable_session_refresh = true;
    // Force the cache renewal boundary immediately without sleeping or changing
    // production time. It must preserve both actual issued token and session expiry.
    config.session.cookie_refresh_cache = CookieRefreshCache::UpdateAge(700000.0);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config.clone()), &connection))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SkipRefresh)
        .build()
        .await?;
    let signup = auth.handle_request(request("/sign-up/email", Some(json!({"email":"native172@fixture.test","password":"Password123!","name":"Stateless"})), "")).await?;
    assert_eq!(signup.status, 200, "{}", body(&signup));
    let cookie = cookies(&signup);
    let issued = body(&signup)["token"].as_str().unwrap().to_owned();
    assert_eq!(db.count("sessions").await?, 0);
    let mut get = request("/get-session", None, &cookie);
    drop(get.query.insert("disableRefresh".into(), "true".into()));
    let first = auth.handle_request(get).await?;
    assert_eq!(first.status, 200, "{}", body(&first));
    let snapshot = body(&first);
    if let Ok(directory) = std::env::var("STATELESS_172_EVIDENCE") {
        std::fs::create_dir_all(&directory)?;
        let owner = std::any::type_name::<B>().rsplit("::").next().unwrap();
        std::fs::write(
            std::path::Path::new(&directory).join(format!("{owner}-issuance.json")),
            serde_json::to_vec_pretty(&json!({
                "signup": {"status":signup.status,"body":String::from_utf8_lossy(&signup.body),"cookies":signup.headers.get_all("set-cookie").collect::<Vec<_>>()},
                "renewed": {"status":first.status,"body":String::from_utf8_lossy(&first.body),"cookies":first.headers.get_all("set-cookie").collect::<Vec<_>>()},
            }))?,
        )?;
    }
    assert_eq!(snapshot["session"]["token"], issued);
    assert_eq!(snapshot["user"]["email"], "native172@fixture.test");
    assert!(snapshot.get("needsRefresh").is_none());
    let renewed = cookies(&first);
    assert!(renewed.contains("session_data="));
    assert!(renewed.contains("session_token="));
    let replay = auth
        .handle_request(request("/get-session", None, &cookie))
        .await?;
    assert_eq!(body(&replay), snapshot);
    let mut bypass_before = request("/get-session", None, &cookie);
    drop(
        bypass_before
            .query
            .insert("disableCookieCache".into(), "true".into()),
    );
    let physical = body(&auth.handle_request(bypass_before).await?);
    assert_eq!(physical["session"], snapshot["session"]);
    assert_eq!(physical["user"], snapshot["user"]);
    assert_eq!(physical["needsRefresh"], false);
    let mut skipped = request("/get-session", None, &cookie);
    drop(
        skipped
            .headers
            .insert("x-fixture-skip-refresh".into(), "1".into()),
    );
    assert!(cookies(&auth.handle_request(skipped).await?).is_empty());
    let logout = auth
        .handle_request(request("/sign-out", Some(json!({})), &cookie))
        .await?;
    assert_eq!(logout.status, 200);
    let replay = auth
        .handle_request(request("/get-session", None, &cookie))
        .await?;
    assert_eq!(body(&replay), snapshot);
    assert_eq!(db.count("sessions").await?, 0);
    let mut bypass = request("/get-session", None, &cookie);
    drop(
        bypass
            .query
            .insert("disableCookieCache".into(), "true".into()),
    );
    assert_eq!(body(&auth.handle_request(bypass).await?), Value::Null);
    // A changed deployment version invalidates captured cookies without any SQL authority.
    config.session.cookie_cache.as_mut().unwrap().version = Some(
        better_auth_core::CookieCacheVersion::Literal("retired".into()),
    );
    let versioned = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .build()
        .await?;
    assert_eq!(
        body(
            &versioned
                .handle_request(request("/get-session", None, &cookie))
                .await?
        ),
        Value::Null
    );
    // Historical database default still inserts and authoritatively revokes rows.
    let stateful = AuthConfig::new(SECRET).base_url(ORIGIN);
    let durable = AuthBuilder::new(stateful.clone())
        .store(B::store(Arc::new(stateful), &connection))
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await?;
    let login = durable
        .handle_request(request(
            "/sign-in/email",
            Some(json!({"email":"native172@fixture.test","password":"Password123!"})),
            "",
        ))
        .await?;
    assert_eq!(login.status, 200, "{}", body(&login));
    assert_eq!(db.count("sessions").await?, 1);
    let durable_cookie = cookies(&login);
    assert!(
        body(
            &durable
                .handle_request(request("/get-session", None, &durable_cookie))
                .await?
        )
        .is_object()
    );
    let logout = durable
        .handle_request(request("/sign-out", Some(json!({})), &durable_cookie))
        .await?;
    assert_eq!(logout.status, 200);
    assert_eq!(db.count("sessions").await?, 0);
    assert_eq!(
        body(
            &durable
                .handle_request(request("/get-session", None, &durable_cookie))
                .await?
        ),
        Value::Null
    );
    B::close(connection).await?;
    Ok(())
}

#[tokio::test]
async fn without_database_credential_issuance_and_restart() -> TestResult {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let field = better_auth_core::field_policy::FieldConfig::new(json!({"type":"string"}));
    drop(
        config
            .user
            .additional_fields
            .insert("tier".into(), field.clone().default_value(json!("starter"))),
    );
    drop(config.session.additional_fields.insert(
        "label".into(),
        field.clone().default_value(json!("browser")).read_only(),
    ));
    drop(
        config.session.additional_fields.insert(
            "private".into(),
            field
                .default_value(json!("private-value"))
                .read_only()
                .hidden(),
        ),
    );
    let auth = AuthBuilder::without_database(config.clone())
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await?;
    let signup = auth.handle_request(request("/sign-up/email", Some(json!({"email":"no-db172@fixture.test","password":"Password123!","name":"No database"})), "")).await?;
    assert_eq!(signup.status, 200, "{}", body(&signup));
    let cookie = cookies(&signup);
    let first = auth
        .handle_request(request("/get-session", None, &cookie))
        .await?;
    assert_eq!(body(&first)["user"]["email"], "no-db172@fixture.test");
    assert_eq!(body(&first)["user"]["tier"], "starter");
    assert!(body(&first)["user"].get("image").is_none());
    assert_eq!(body(&first)["session"]["label"], "browser");
    assert!(body(&first)["session"].get("private").is_none());
    assert!(
        signup
            .headers
            .get_all("set-cookie")
            .any(|value| value.contains("session_data=") && value.contains("Max-Age=604800"))
    );
    let mut bypass = request("/get-session", None, &cookie);
    drop(
        bypass
            .query
            .insert("disableCookieCache".into(), "true".into()),
    );
    assert_eq!(body(&auth.handle_request(bypass).await?), body(&first));
    let update = auth
        .handle_request(request(
            "/update-user",
            Some(json!({"name":"Updated locally"})),
            &cookie,
        ))
        .await?;
    assert_eq!(update.status, 200, "{}", body(&update));
    let login = auth
        .handle_request(request(
            "/sign-in/email",
            Some(json!({"email":"no-db172@fixture.test","password":"Password123!"})),
            "",
        ))
        .await?;
    assert_eq!(login.status, 200, "{}", body(&login));
    assert_ne!(body(&signup)["token"], body(&login)["token"]);
    let restarted = AuthBuilder::without_database(config)
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await?;
    assert_eq!(
        body(
            &restarted
                .handle_request(request("/get-session", None, &cookie))
                .await?
        ),
        body(&first)
    );
    let failed_login = restarted
        .handle_request(request(
            "/sign-in/email",
            Some(json!({"email":"no-db172@fixture.test","password":"Password123!"})),
            "",
        ))
        .await?;
    assert_ne!(failed_login.status, 200);
    Ok(())
}

/// Field/version/key/expiry policy shares this owner and runs on each real store.
async fn stateless_policy_boundaries<B: Backend>(db: Db) -> TestResult {
    use better_auth_core::utils::{cookie_utils::sign_cookie_value, jwe};
    use better_auth_core::{
        CookieCacheConfig, CookieCacheStrategy, CookieCacheVersion, ManagedSecrets,
    };
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for (index, strategy) in [
        CookieCacheStrategy::Compact,
        CookieCacheStrategy::Jwt,
        CookieCacheStrategy::Jwe,
    ]
    .into_iter()
    .enumerate()
    {
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.session = config.session.stateless();
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: true,
            max_age: 300.0,
            strategy,
            version: Some(CookieCacheVersion::Literal("schema-v1".into())),
        });
        config.session.cookie_refresh_cache = CookieRefreshCache::Disabled;
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .plugin(EmailPasswordPlugin::new())
            .plugin(better_auth::plugins::BearerPlugin::new())
            .build()
            .await?;
        let signup = auth.handle_request(request("/sign-up/email", Some(json!({"email":format!("mode{index}@fixture.test"),"password":"Password123!","name":"Policy"})), "")).await?;
        assert_eq!(signup.status, 200, "{}", body(&signup));
        let cookie = cookies(&signup);
        let read = auth
            .handle_request(request("/get-session", None, &cookie))
            .await?;
        assert!(body(&read).is_object());
        assert!(
            cookies(&read).is_empty(),
            "disabled refreshCache emits no cookies"
        );
        let token = body(&signup)["token"].as_str().unwrap().to_owned();
        let mut bearer = request("/get-session", None, "");
        drop(
            bearer
                .headers
                .insert("authorization".into(), format!("Bearer {token}")),
        );
        assert_eq!(
            body(&auth.handle_request(bearer).await?)["user"]["email"],
            format!("mode{index}@fixture.test")
        );
        // Bind cached identity to the separately authenticated token; an unknown
        // signed token cannot borrow the valid cached user's authority.
        let mismatch = cookie.replace(
            &sign_cookie_value(&token, SECRET),
            &sign_cookie_value("unknown-session-token", SECRET),
        );
        assert_eq!(
            body(
                &auth
                    .handle_request(request("/get-session", None, &mismatch))
                    .await?
            ),
            Value::Null
        );
        assert_eq!(db.count("sessions").await?, 0);
    }
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session = config.session.stateless();
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config.clone()), &connection))
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await?;
    let signup = auth
        .handle_request(request(
            "/sign-up/email",
            Some(json!({"email":"keys172@fixture.test","password":"Password123!","name":"Keys"})),
            "",
        ))
        .await?;
    assert_eq!(signup.status, 200, "{}", body(&signup));
    let cookie = cookies(&signup);
    let value = cookie
        .split("; ")
        .find_map(|part| part.strip_prefix("better-auth.session_data="))
        .unwrap();
    let original = jwe::decode(SECRET, "better-auth-session", value)?;
    let original_session = original["session"].clone();
    let token = body(&signup)["token"].as_str().unwrap().to_owned();
    let next = "stateless-172-next-secret-minimum-32-characters";
    config.managed_secrets = Some(ManagedSecrets::new(2, next).retain(1, SECRET));
    let retained = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config.clone()), &connection))
        .build()
        .await?;
    assert_eq!(
        body(
            &retained
                .handle_request(request("/get-session", None, &cookie))
                .await?
        ),
        Value::Null,
        "signed token uses current key only"
    );
    let rebound = cookie.replace(
        &sign_cookie_value(&token, SECRET),
        &sign_cookie_value(&token, next),
    );
    assert_eq!(
        body(
            &retained
                .handle_request(request("/get-session", None, &rebound))
                .await?
        )["session"],
        original_session
    );
    config.managed_secrets = Some(ManagedSecrets::new(2, next));
    let retired = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .build()
        .await?;
    assert_eq!(
        body(
            &retired
                .handle_request(request("/get-session", None, &rebound))
                .await?
        ),
        Value::Null
    );
    // Real logout removes the in-memory fallback. Authenticated but expired
    // snapshots must then reject both envelope and embedded-session expiry.
    _ = auth
        .handle_request(request("/sign-out", Some(json!({})), &cookie))
        .await?;
    let expired_envelope = jwe::encode(SECRET, "better-auth-session", &original, -60.0)?;
    let expired_cookie = cookie.replace(value, &expired_envelope);
    assert_eq!(
        body(
            &auth
                .handle_request(request("/get-session", None, &expired_cookie))
                .await?
        ),
        Value::Null
    );
    let mut expired_session = original.clone();
    expired_session["session"]["expiresAt"] = json!("2000-01-01T00:00:00.000Z");
    let expired_value = jwe::encode(SECRET, "better-auth-session", &expired_session, 300.0)?;
    assert_eq!(
        body(
            &auth
                .handle_request(request(
                    "/get-session",
                    None,
                    &cookie.replace(value, &expired_value)
                ))
                .await?
        ),
        Value::Null
    );
    B::close(connection).await?;
    Ok(())
}
