//! Stateless lifecycle owner: actual adapters protect cookie-only and durable modes.
use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::config::CookieRefreshCache;
use alibi::plugins::EmailPasswordPlugin;
use alibi::{AuthBuilder, AuthConfig};
use alibi::{AuthRequest, AuthResponse, HttpMethod};
use serde_json::{Value, json};
use std::sync::Arc;

const SECRET: &str = "stateless-172-secret-minimum-32-characters";
const ORIGIN: &str = "http://localhost:43172";
backend_tests!(
    stateless_session_lifecycle,
    stateless_policy_boundaries,
    stateless_ephemeral_mutation_and_deferred_refresh
);
postgres_tests!(
    stateless_session_lifecycle,
    stateless_policy_boundaries,
    stateless_ephemeral_mutation_and_deferred_refresh
);

struct SkipRefresh;
#[async_trait::async_trait]
impl<S: alibi::AuthSchema> alibi::AuthPlugin<S> for SkipRefresh {
    fn name(&self) -> &'static str {
        "fixture-skip-refresh"
    }
    fn routes(&self) -> Vec<alibi::AuthRoute> {
        Vec::new()
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        _ctx: &alibi::AuthContext<S>,
    ) -> alibi::AuthResult<Option<alibi::BeforeRequestAction>> {
        if req
            .headers
            .get("x-fixture-skip-refresh")
            .is_some_and(|value| value == "1")
        {
            req.extensions()
                .insert(alibi::session::SessionRefreshSuppressed);
        }
        Ok(None)
    }
    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &alibi::AuthContext<S>,
    ) -> alibi::AuthResult<Option<AuthResponse>> {
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
    let signup = Box::pin(auth.handle_request(request(
        "/sign-up/email",
        Some(
            json!({"email":"native172@fixture.test","password":"Password123!","name":"Stateless"}),
        ),
        "",
    )))
    .await?;
    assert_eq!(signup.status, 200, "{}", body(&signup));
    let cookie = cookies(&signup);
    let issued = body(&signup)["token"].as_str().unwrap().to_owned();
    assert_eq!(db.count("sessions").await?, 0);
    let mut get = request("/get-session", None, &cookie);
    drop(get.query.insert("disableRefresh".into(), "true".into()));
    let first = Box::pin(auth.handle_request(get)).await?;
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
    let replay = Box::pin(auth.handle_request(request("/get-session", None, &cookie))).await?;
    assert_eq!(body(&replay), snapshot);
    let mut bypass_before = request("/get-session", None, &cookie);
    drop(
        bypass_before
            .query
            .insert("disableCookieCache".into(), "true".into()),
    );
    let physical = body(&Box::pin(auth.handle_request(bypass_before)).await?);
    assert_eq!(physical["session"], snapshot["session"]);
    assert_eq!(physical["user"], snapshot["user"]);
    assert_eq!(physical["needsRefresh"], false);
    let mut skipped = request("/get-session", None, &cookie);
    drop(
        skipped
            .headers
            .insert("x-fixture-skip-refresh".into(), "1".into()),
    );
    assert!(cookies(&Box::pin(auth.handle_request(skipped)).await?).is_empty());
    let logout =
        Box::pin(auth.handle_request(request("/sign-out", Some(json!({})), &cookie))).await?;
    assert_eq!(logout.status, 200);
    let replay = Box::pin(auth.handle_request(request("/get-session", None, &cookie))).await?;
    assert_eq!(body(&replay), snapshot);
    assert_eq!(db.count("sessions").await?, 0);
    let mut bypass = request("/get-session", None, &cookie);
    drop(
        bypass
            .query
            .insert("disableCookieCache".into(), "true".into()),
    );
    assert_eq!(
        body(&Box::pin(auth.handle_request(bypass)).await?),
        Value::Null
    );
    // A changed deployment version invalidates captured cookies without any SQL authority.
    config.session.cookie_cache.as_mut().unwrap().version =
        Some(alibi::CookieCacheVersion::Literal("retired".into()));
    let versioned = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .build()
        .await?;
    assert_eq!(
        body(&Box::pin(versioned.handle_request(request("/get-session", None, &cookie))).await?),
        Value::Null
    );
    // Historical database default still inserts and authoritatively revokes rows.
    let stateful = AuthConfig::new(SECRET).base_url(ORIGIN);
    let durable = AuthBuilder::new(stateful.clone())
        .store(B::store(Arc::new(stateful), &connection))
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await?;
    let login = Box::pin(durable.handle_request(request(
        "/sign-in/email",
        Some(json!({"email":"native172@fixture.test","password":"Password123!"})),
        "",
    )))
    .await?;
    assert_eq!(login.status, 200, "{}", body(&login));
    assert_eq!(db.count("sessions").await?, 1);
    let durable_cookie = cookies(&login);
    assert!(
        body(
            &Box::pin(durable.handle_request(request("/get-session", None, &durable_cookie)))
                .await?
        )
        .is_object()
    );
    let logout =
        Box::pin(durable.handle_request(request("/sign-out", Some(json!({})), &durable_cookie)))
            .await?;
    assert_eq!(logout.status, 200);
    assert_eq!(db.count("sessions").await?, 0);
    assert_eq!(
        body(
            &Box::pin(durable.handle_request(request("/get-session", None, &durable_cookie)))
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
    let field = alibi::field_policy::FieldConfig::new(json!({"type":"string"}));
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
    let signup = Box::pin(auth.handle_request(request(
        "/sign-up/email",
        Some(
            json!({"email":"no-db172@fixture.test","password":"Password123!","name":"No database"}),
        ),
        "",
    )))
    .await?;
    assert_eq!(signup.status, 200, "{}", body(&signup));
    let cookie = cookies(&signup);
    let first = Box::pin(auth.handle_request(request("/get-session", None, &cookie))).await?;
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
    assert!(
        cookies(&first).is_empty(),
        "default refresh waits until the final 20% of cache lifetime"
    );
    let value = cookie
        .split("; ")
        .find_map(|part| part.strip_prefix("better-auth.session_data="))
        .unwrap();
    let claims = alibi::utils::jwe::decode(SECRET, "better-auth-session", value)?;
    let short_cache = alibi::utils::jwe::encode(SECRET, "better-auth-session", &claims, 30.0)?;
    let renewed = Box::pin(auth.handle_request(request(
        "/get-session",
        None,
        &cookie.replace(value, &short_cache),
    )))
    .await?;
    assert_eq!(
        body(&renewed),
        body(&first),
        "automatic renewal retains fields, omissions, token and embedded expiry"
    );
    assert!(cookies(&renewed).contains("session_data="));
    if let Ok(directory) = std::env::var("STATELESS_172_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&directory).join("without-database-issuance.json"),
            serde_json::to_vec_pretty(&json!({
                "signup": {"status":signup.status,"body":String::from_utf8_lossy(&signup.body),"cookies":signup.headers.get_all("set-cookie").collect::<Vec<_>>()},
                "cached": {"status":first.status,"body":String::from_utf8_lossy(&first.body),"cookies":first.headers.get_all("set-cookie").collect::<Vec<_>>()},
                "automaticRenewal": {"status":renewed.status,"body":String::from_utf8_lossy(&renewed.body),"cookies":renewed.headers.get_all("set-cookie").collect::<Vec<_>>()},
            }))?,
        )?;
    }
    let mut bypass = request("/get-session", None, &cookie);
    drop(
        bypass
            .query
            .insert("disableCookieCache".into(), "true".into()),
    );
    assert_eq!(
        body(&Box::pin(auth.handle_request(bypass)).await?),
        body(&first)
    );
    let update = Box::pin(auth.handle_request(request(
        "/update-user",
        Some(json!({"name":"Updated locally"})),
        &cookie,
    )))
    .await?;
    assert_eq!(update.status, 200, "{}", body(&update));
    let login = Box::pin(auth.handle_request(request(
        "/sign-in/email",
        Some(json!({"email":"no-db172@fixture.test","password":"Password123!"})),
        "",
    )))
    .await?;
    assert_eq!(login.status, 200, "{}", body(&login));
    assert_ne!(body(&signup)["token"], body(&login)["token"]);
    assert_eq!(body(&login)["user"]["name"], "Updated locally");
    let changed = Box::pin(auth.handle_request(request("/change-password", Some(json!({"currentPassword":"Password123!","newPassword":"Replacement123!","revokeOtherSessions":false})), &cookies(&login)))).await?;
    assert_eq!(changed.status, 200, "{}", body(&changed));
    for (password, expected) in [("Password123!", 401), ("Replacement123!", 200)] {
        let response = Box::pin(auth.handle_request(request(
            "/sign-in/email",
            Some(json!({"email":"no-db172@fixture.test","password":password})),
            "",
        )))
        .await?;
        assert_eq!(response.status, expected, "{}", body(&response));
    }

    config.session = config.session.stateless();
    config.session.cookie_refresh_cache = CookieRefreshCache::Disabled;
    let restarted = AuthBuilder::without_database(config)
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await?;
    assert_eq!(
        body(&Box::pin(restarted.handle_request(request("/get-session", None, &cookie))).await?),
        body(&first)
    );
    let disabled_renewal = Box::pin(restarted.handle_request(request(
        "/get-session",
        None,
        &cookie.replace(value, &short_cache),
    )))
    .await?;
    assert_eq!(body(&disabled_renewal), body(&first));
    assert!(
        cookies(&disabled_renewal).is_empty(),
        "no-database construction preserves explicit refreshCache=false"
    );
    let failed_login = Box::pin(restarted.handle_request(request(
        "/sign-in/email",
        Some(json!({"email":"no-db172@fixture.test","password":"Replacement123!"})),
        "",
    )))
    .await?;
    assert_ne!(failed_login.status, 200);
    Ok(())
}

/// Field/version/key/expiry policy shares this owner and runs on each real store.
async fn stateless_policy_boundaries<B: Backend>(db: Db) -> TestResult {
    use alibi::utils::{cookie_utils::sign_cookie_value, jwe};
    use alibi::{CookieCacheConfig, CookieCacheStrategy, CookieCacheVersion, ManagedSecrets};
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
            .plugin(alibi::plugins::BearerPlugin::new())
            .build()
            .await?;
        let signup = Box::pin(auth.handle_request(request("/sign-up/email", Some(json!({"email":format!("mode{index}@fixture.test"),"password":"Password123!","name":"Policy"})), ""))).await?;
        assert_eq!(signup.status, 200, "{}", body(&signup));
        let cookie = cookies(&signup);
        let read = Box::pin(auth.handle_request(request("/get-session", None, &cookie))).await?;
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
            body(&Box::pin(auth.handle_request(bearer)).await?)["user"]["email"],
            format!("mode{index}@fixture.test")
        );
        // Bind cached identity to the separately authenticated token; an unknown
        // signed token cannot borrow the valid cached user's authority.
        let mismatch = cookie.replace(
            &sign_cookie_value(&token, SECRET),
            &sign_cookie_value("unknown-session-token", SECRET),
        );
        assert_eq!(
            body(&Box::pin(auth.handle_request(request("/get-session", None, &mismatch))).await?),
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
    let signup = Box::pin(auth.handle_request(request(
        "/sign-up/email",
        Some(json!({"email":"keys172@fixture.test","password":"Password123!","name":"Keys"})),
        "",
    )))
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
        body(&Box::pin(retained.handle_request(request("/get-session", None, &cookie))).await?),
        Value::Null,
        "signed token uses current key only"
    );
    let rebound = cookie.replace(
        &sign_cookie_value(&token, SECRET),
        &sign_cookie_value(&token, next),
    );
    assert_eq!(
        body(&Box::pin(retained.handle_request(request("/get-session", None, &rebound))).await?)["session"],
        original_session
    );
    config.managed_secrets = Some(ManagedSecrets::new(2, next));
    let retired = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .build()
        .await?;
    assert_eq!(
        body(&Box::pin(retired.handle_request(request("/get-session", None, &rebound))).await?),
        Value::Null
    );
    // Real logout removes the in-memory fallback. Authenticated but expired
    // snapshots must then reject both envelope and embedded-session expiry.
    _ = Box::pin(auth.handle_request(request("/sign-out", Some(json!({})), &cookie))).await?;
    let expired_envelope = jwe::encode(SECRET, "better-auth-session", &original, -60.0)?;
    let expired_cookie = cookie.replace(value, &expired_envelope);
    assert_eq!(
        body(&Box::pin(auth.handle_request(request("/get-session", None, &expired_cookie))).await?),
        Value::Null
    );
    let mut expired_session = original.clone();
    expired_session["session"]["expiresAt"] = json!("2000-01-01T00:00:00.000Z");
    let expired_value = jwe::encode(SECRET, "better-auth-session", &expired_session, 300.0)?;
    assert_eq!(
        body(
            &Box::pin(auth.handle_request(request(
                "/get-session",
                None,
                &cookie.replace(value, &expired_value)
            )))
            .await?
        ),
        Value::Null
    );
    B::close(connection).await?;
    Ok(())
}

// Public mutation and deferred renewal must update ephemeral records, never SQL.
// Existing durable refresh tests cannot catch this policy-routing failure.
async fn stateless_ephemeral_mutation_and_deferred_refresh<B: Backend>(db: Db) -> TestResult {
    use alibi::AuthSession;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session = config.session.stateless();
    config.session.defer_session_refresh = true;
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await?;
    let signup = Box::pin(auth.handle_request(request(
        "/sign-up/email",
        Some(
            json!({"email":"deferred172@fixture.test","password":"Password123!","name":"Deferred"}),
        ),
        "",
    )))
    .await?;
    assert_eq!(signup.status, 200, "{}", body(&signup));
    let cookie = cookies(&signup);
    let token = body(&signup)["token"].as_str().unwrap().to_owned();
    let organization = auth
        .store()
        .update_session_active_organization(&token, Some("memory-org"))
        .await?;
    assert_eq!(
        alibi::SessionView::from(&organization)
            .active_organization_id
            .as_deref(),
        Some("memory-org")
    );
    let team = auth
        .store()
        .update_session_active_team(&token, Some("memory-team"))
        .await?;
    assert_eq!(
        alibi::SessionView::from(&team).active_team_id.as_deref(),
        Some("memory-team")
    );
    // Fixture state uses the real initialized store, as Source's internal adapter
    // does; no sleeps, fake clocks or test-only production interfaces.
    let near_expiry = chrono::Utc::now() + chrono::Duration::hours(1);
    auth.store()
        .update_session_expiry(&token, near_expiry)
        .await?;
    let mut get = request("/get-session", None, &cookie);
    drop(get.query.insert("disableCookieCache".into(), "true".into()));
    let deferred = Box::pin(auth.handle_request(get)).await?;
    assert_eq!(body(&deferred)["needsRefresh"], true);
    assert_eq!(
        auth.store()
            .get_session(&token)
            .await?
            .unwrap()
            .expires_at(),
        near_expiry
    );
    let mut post = request("/get-session", Some(json!({})), &cookie);
    drop(
        post.query
            .insert("disableCookieCache".into(), "true".into()),
    );
    let refreshed = Box::pin(auth.handle_request(post)).await?;
    assert_eq!(refreshed.status, 200, "{}", body(&refreshed));
    assert_eq!(body(&refreshed)["session"]["token"], token);
    assert!(
        auth.store()
            .get_session(&token)
            .await?
            .unwrap()
            .expires_at()
            > near_expiry + chrono::Duration::days(6)
    );
    assert!(cookies(&refreshed).contains("session_data="));
    let login = Box::pin(auth.handle_request(request(
        "/sign-in/email",
        Some(json!({"email":"deferred172@fixture.test","password":"Password123!"})),
        "",
    )))
    .await?;
    assert_eq!(login.status, 200, "{}", body(&login));
    let other_cookie = cookies(&login);
    let listed = Box::pin(auth.handle_request(request("/list-sessions", None, &cookie))).await?;
    assert_eq!(body(&listed).as_array().unwrap().len(), 2);
    let revoked =
        Box::pin(auth.handle_request(request("/revoke-other-sessions", Some(json!({})), &cookie)))
            .await?;
    assert_eq!(revoked.status, 200, "{}", body(&revoked));
    assert!(
        body(&Box::pin(auth.handle_request(request("/get-session", None, &other_cookie))).await?)
            .is_object(),
        "captured cached identity survives instance-local revocation"
    );
    let mut bypass = request("/get-session", None, &other_cookie);
    drop(
        bypass
            .query
            .insert("disableCookieCache".into(), "true".into()),
    );
    assert_eq!(
        body(&Box::pin(auth.handle_request(bypass)).await?),
        Value::Null
    );
    let revoke_all =
        Box::pin(auth.handle_request(request("/revoke-sessions", Some(json!({})), &cookie)))
            .await?;
    assert_eq!(revoke_all.status, 200, "{}", body(&revoke_all));
    assert!(
        auth.store()
            .get_user_sessions(body(&signup)["user"]["id"].as_str().unwrap())
            .await?
            .is_empty()
    );
    assert_eq!(db.count("sessions").await?, 0);
    B::close(connection).await?;
    Ok(())
}

#[tokio::test]
async fn without_database_account_authority_and_verification_generations() -> TestResult {
    use alibi::{AuthError, CreateAccount, CreateVerification, DatabaseError, UpdateAccount};
    let auth = AuthBuilder::without_database(AuthConfig::new(SECRET))
        .build()
        .await?;
    let store = auth.store();
    let input = |owner: &str| CreateAccount {
        user_id: owner.into(),
        provider_id: "oidc".into(),
        account_id: "shared".into(),
        access_token: Some("old-access".into()),
        refresh_token: Some("old-refresh".into()),
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: None,
        additional_fields: Default::default(),
    };
    let left = store.create_account(input("owner")).await?;
    let right = store.create_account(input("foreign")).await?;
    assert_ne!(left.id, right.id);
    assert!(matches!(
        store.get_account("oidc", "shared").await,
        Err(AuthError::Database(DatabaseError::AmbiguousAccount { .. }))
    ));
    assert_eq!(store.get_user_accounts("owner").await?.len(), 1);
    let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
    let updated = store
        .update_account(
            &left.id,
            UpdateAccount {
                access_token: Some("new-access".into()),
                refresh_token: Some("new-refresh".into()),
                id_token: Some("new-id".into()),
                access_token_expires_at: Some(expiry),
                refresh_token_expires_at: Some(expiry),
                scope: Some("read".into()),
                password: Some("new-password".into()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(updated.access_token.as_deref(), Some("new-access"));
    assert_eq!(updated.refresh_token.as_deref(), Some("new-refresh"));
    assert_eq!(updated.id_token.as_deref(), Some("new-id"));
    assert_eq!(updated.password.as_deref(), Some("new-password"));
    assert_eq!(updated.scope.as_deref(), Some("read"));
    assert_eq!(updated.access_token_expires_at, Some(expiry));
    assert_eq!(updated.refresh_token_expires_at, Some(expiry));
    assert_eq!(
        serde_json::to_value(store.get_user_accounts("foreign").await?)?,
        json!([right])
    );
    store.delete_account(&right.id).await?;
    assert_eq!(
        store.get_account("oidc", "shared").await?.unwrap().id,
        left.id
    );
    assert_eq!(
        serde_json::to_value(store.get_account("oidc", "shared").await?.unwrap())?,
        serde_json::to_value(&updated)?
    );
    assert!(store.get_user_accounts("foreign").await?.is_empty());
    assert!(matches!(
        store
            .update_account(&right.id, UpdateAccount::default())
            .await,
        Err(AuthError::NotFound(_))
    ));

    let proof = |identifier: &str, value: &str| CreateVerification {
        identifier: identifier.into(),
        value: value.into(),
        expires_at: expiry,
    };
    let old = store
        .create_verification(proof("generation", "old"))
        .await?;
    let latest = store
        .create_verification(proof("generation", "new"))
        .await?;
    let foreign = store.create_verification(proof("foreign", "new")).await?;
    assert!(
        store
            .consume_verification("generation", "wrong")
            .await?
            .is_none()
    );
    assert!(
        store
            .consume_verification("generation", "old")
            .await?
            .is_none()
    );
    assert_eq!(
        store
            .get_verification("generation", "old")
            .await?
            .unwrap()
            .id,
        old.id
    );
    assert_eq!(
        store
            .get_latest_verification_by_identifier("generation")
            .await?
            .unwrap()
            .id,
        latest.id
    );
    assert_eq!(
        store
            .consume_verification("generation", "new")
            .await?
            .unwrap()
            .id,
        latest.id
    );
    assert!(
        store
            .get_verification_by_identifier("generation")
            .await?
            .is_none()
    );
    assert_eq!(
        store
            .get_verification_by_identifier("foreign")
            .await?
            .unwrap()
            .id,
        foreign.id
    );
    let reserved = proof("reservation", "first");
    let (left, right) = tokio::join!(
        store.reserve_verification(reserved.clone()),
        store.reserve_verification(reserved)
    );
    assert_ne!(left?, right?);
    let reserved = store
        .get_verification_by_identifier("reservation")
        .await?
        .unwrap();
    assert!(
        !store
            .compare_and_swap_verification(&reserved.id, "wrong", "bad", expiry)
            .await?
    );
    let (left, right) = tokio::join!(
        store.compare_and_swap_verification(&reserved.id, "first", "left", expiry),
        store.compare_and_swap_verification(&reserved.id, "first", "right", expiry)
    );
    assert_ne!(left?, right?);
    let winner = store
        .get_verification_by_identifier("reservation")
        .await?
        .unwrap();
    assert!(matches!(winner.value.as_str(), "left" | "right"));
    assert_eq!(
        store
            .consume_verification_by_identifier("reservation")
            .await?
            .unwrap()
            .id,
        reserved.id
    );
    assert!(
        store
            .reserve_verification(proof("reservation", "reused"))
            .await?
    );
    assert!(
        !store
            .compare_and_swap_verification("missing", "first", "next", expiry)
            .await?
    );
    use alibi::{CreateUser, ListUsersParams, UpdateUser, UserFilterValue};
    for (email, banned) in [
        ("alpha@query.test", false),
        ("beta@query.test", true),
        ("gamma@query.test", true),
    ] {
        let user = store
            .create_user(CreateUser::new().with_email(email).with_name(email))
            .await?;
        let _ = store
            .update_user(
                &user.id,
                UpdateUser {
                    banned: Some(banned),
                    ban_expires: if banned { Some(Some(expiry)) } else { None },
                    ..Default::default()
                },
            )
            .await?;
    }
    for (field, operator, value, expected) in [
        (
            "banned",
            "eq",
            UserFilterValue::Scalar("true".into()),
            vec!["beta@query.test", "gamma@query.test"],
        ),
        (
            "banned",
            "ne",
            UserFilterValue::Scalar("true".into()),
            vec!["alpha@query.test"],
        ),
        (
            "banned",
            "eq",
            UserFilterValue::Scalar("invalid".into()),
            vec![],
        ),
        (
            "banExpires",
            "gte",
            UserFilterValue::Scalar(expiry.to_rfc3339()),
            vec!["beta@query.test", "gamma@query.test"],
        ),
        (
            "banExpires",
            "lt",
            UserFilterValue::Scalar(expiry.to_rfc3339()),
            vec![],
        ),
        (
            "email",
            "in",
            UserFilterValue::Multiple(vec!["alpha@query.test".into(), "gamma@query.test".into()]),
            vec!["alpha@query.test", "gamma@query.test"],
        ),
        (
            "email",
            "not_in",
            UserFilterValue::Multiple(vec!["alpha@query.test".into()]),
            vec!["beta@query.test", "gamma@query.test"],
        ),
    ] {
        let (users, total) = store
            .list_users(ListUsersParams {
                filter_field: Some(field.into()),
                filter_operator: Some(operator.into()),
                filter_value: Some(value),
                sort_by: Some("email".into()),
                ..Default::default()
            })
            .await?;
        assert_eq!(total, expected.len());
        assert_eq!(
            users
                .iter()
                .map(|u| u.email.as_deref().unwrap())
                .collect::<Vec<_>>(),
            expected
        );
    }
    for (operator, search, expected) in [
        ("starts_with", "alp", "alpha@query.test"),
        ("contains", "bet", "beta@query.test"),
        ("ends_with", "gamma@query.test", "gamma@query.test"),
    ] {
        let (users, total) = store
            .list_users(ListUsersParams {
                search_value: Some(search.into()),
                search_operator: Some(operator.into()),
                ..Default::default()
            })
            .await?;
        assert_eq!(total, 1);
        assert_eq!(users[0].email.as_deref(), Some(expected));
    }
    let (page, total) = store
        .list_users(ListUsersParams {
            sort_by: Some("banned".into()),
            sort_direction: Some("desc".into()),
            offset: Some(2),
            limit: Some(1),
            ..Default::default()
        })
        .await?;
    assert_eq!(total, 3);
    assert_eq!(page[0].email.as_deref(), Some("alpha@query.test"));
    let restarted = AuthBuilder::without_database(AuthConfig::new(SECRET))
        .build()
        .await?;
    assert!(
        restarted
            .store()
            .get_user_accounts("owner")
            .await?
            .is_empty()
    );
    assert!(
        restarted
            .store()
            .get_verification_by_identifier("foreign")
            .await?
            .is_none()
    );
    Ok(())
}
