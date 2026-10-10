//! Bearer headers, device-session limits, session management failures and
//! device-session projections.
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::custom_session::{CustomSessionPlugin, SessionTransform};
use alibi::plugins::multi_session::MultiSessionConfig;
use alibi::plugins::{BearerPlugin, MultiSessionPlugin};
use alibi::{AuthContext, AuthError, AuthResult, CookieCacheConfig, CookieCacheStrategy};
use std::collections::BTreeMap;

backend_tests!(
    bearer_authorization_matrix,
    multi_session_limits_and_revocation,
    session_management_failures,
    device_session_projection,
    multi_session_without_database_preserves_order_fallback_and_cache_replay_limits
);

fn merge(first: &str, second: &str) -> String {
    let mut jar = BTreeMap::new();
    for pair in first.split("; ").chain(second.split("; ")) {
        if let Some((name, value)) = pair.split_once('=') {
            if value.is_empty() {
                _ = jar.remove(name);
            } else {
                _ = jar.insert(name.to_owned(), value.to_owned());
            }
        }
    }
    jar.into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn builder_with<B: Backend>(
    connection: &B::Connection,
    config: AuthConfig,
) -> AuthBuilder<B::Schema> {
    AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(alibi::plugins::EmailPasswordPlugin::new())
}

fn raw(path: &str, text: &str, cookie: &str, content_type: &str) -> AuthRequest {
    let mut request = request(path, None, cookie);
    request.method = HttpMethod::Post;
    request.body = Some(text.as_bytes().to_vec());
    _ = request
        .headers
        .insert("content-type".into(), content_type.into());
    request
}

async fn bearer_authorization_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    for (label, require_signature) in [("signed only", true), ("signature optional", false)] {
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let auth = builder_with::<B>(&connection, config)
            .plugin(SessionManagementPlugin::new())
            .plugin(BearerPlugin::with_config(
                alibi::plugins::bearer::BearerConfig { require_signature },
            ))
            .build()
            .await?;
        let issued = signup(
            &auth,
            &format!("bearer-{}@example.com", label.replace(' ', "-")),
        )
        .await;
        let token = body(&issued)["token"].as_str().unwrap().to_owned();
        let signed = cookies(&issued)
            .split("; ")
            .find_map(|pair| {
                pair.strip_prefix("better-auth.session_token=")
                    .map(str::to_owned)
            })
            .unwrap();
        let decoded = signed
            .replace("%3D", "=")
            .replace("%2B", "+")
            .replace("%2F", "/");
        for (name, header) in [
            ("signed cookie value", format!("Bearer {signed}")),
            ("decoded signed value", format!("Bearer {decoded}")),
            ("lowercase scheme", format!("bearer {signed}")),
            ("padded token", format!("Bearer   {signed}  ")),
            ("unsigned token", format!("Bearer {token}")),
            ("empty token", "Bearer ".to_owned()),
            ("blank token", "Bearer    ".to_owned()),
            ("wrong scheme", format!("Basic {signed}")),
            ("no scheme", signed.clone()),
            ("malformed escape", format!("Bearer {token}.%zz")),
            ("tampered signature", format!("Bearer {token}.AAAA")),
            ("url-safe signature", format!("Bearer {token}.-_-_")),
            ("padded signature", format!("Bearer {token}.AAAA==")),
        ] {
            let mut read = request("/get-session", None, "");
            _ = read.headers.insert("authorization".into(), header);
            let response = Box::pin(auth.handle_request(read)).await?;
            trace.value(
                &format!("{label}: {name}"),
                json!({
                    "status": response.status,
                    "user": body(&response)["user"]["email"].is_string(),
                }),
            );
        }
    }
    trace.assert("session-plugins/bearer-matrix");
    B::close(connection).await
}

async fn multi_session_limits_and_revocation<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder_with::<B>(&connection, AuthConfig::new(SECRET).base_url(ORIGIN))
        .plugin(SessionManagementPlugin::new())
        .plugin(MultiSessionPlugin::with_config(MultiSessionConfig {
            maximum_sessions: 2.0,
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let mut jar = String::new();
    let mut tokens = Vec::new();
    for name in ["first", "second", "third"] {
        let response = call(
            &auth,
            request(
                "/sign-up/email",
                Some(json!({
                    "email": format!("device-{name}@example.com"),
                    "password": PASSWORD,
                    "name": name,
                })),
                &jar,
            ),
            200,
        )
        .await;
        tokens.push(body(&response)["token"].as_str().unwrap().to_owned());
        jar = merge(&jar, &cookies(&response));
        trace.value(
            &format!("device cookies after {name}"),
            json!(jar.matches("_multi-").count()),
        );
    }
    let listed = call(
        &auth,
        request("/multi-session/list-device-sessions", None, &jar),
        200,
    )
    .await;
    assert_eq!(body(&listed).as_array().unwrap().len(), 2);

    for (label, input) in [
        ("array body", json!([])),
        ("missing token", json!({})),
        ("numeric token", json!({"sessionToken": 5})),
        ("unknown device", json!({"sessionToken": "missing"})),
    ] {
        for path in ["/multi-session/set-active", "/multi-session/revoke"] {
            trace.response(
                &format!("{path} {label}"),
                &Box::pin(auth.handle_request(request(path, Some(input.clone()), &jar))).await?,
            );
        }
    }

    _ = signup(&auth, "device-fourth@example.com").await;
    let remembered = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email": "device-fourth@example.com", "password": PASSWORD, "rememberMe": false})),
            "",
        ),
        200,
    )
    .await;
    let dont_remember = cookies(&remembered)
        .split("; ")
        .find(|pair| pair.contains("dont_remember"))
        .unwrap()
        .to_owned();
    let remembering = merge(&jar, &dont_remember);
    let selected = call(
        &auth,
        request(
            "/multi-session/set-active",
            Some(json!({"sessionToken": tokens[0]})),
            &remembering,
        ),
        200,
    )
    .await;
    assert!(cookies(&selected).contains("dont_remember"));
    trace.response("select with remember-me proof", &selected);

    let active = merge(&jar, &cookies(&selected));
    let revoked = call(
        &auth,
        request(
            "/multi-session/revoke",
            Some(json!({"sessionToken": tokens[0]})),
            &active,
        ),
        200,
    )
    .await;
    trace.response("revoke the active device", &revoked);
    let rest = merge(&active, &cookies(&revoked));
    let revoked_second = call(
        &auth,
        request(
            "/multi-session/revoke",
            Some(json!({"sessionToken": tokens[1]})),
            &rest,
        ),
        200,
    )
    .await;
    trace.response("revoke the last active device", &revoked_second);
    let none_left = merge(&rest, &cookies(&revoked_second));
    trace.response(
        "list after revocation",
        &Box::pin(auth.handle_request(request(
            "/multi-session/list-device-sessions",
            None,
            &none_left,
        )))
        .await?,
    );
    trace.assert("session-plugins/multi-session-limits");
    B::close(connection).await
}

async fn session_management_failures<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            strategy: CookieCacheStrategy::Compact,
            ..Default::default()
        });
    let auth = builder_with::<B>(&connection, config)
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let mut trace = Trace::default();
    let owner = signup(&auth, "management@example.com").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let cookie = cookies(&owner);
    for (label, text, content_type) in [
        ("array", "[]", "application/json"),
        ("string", "\"text\"", "application/json"),
        ("number", "5", "application/json"),
        ("null", "null", "application/json"),
        ("invalid JSON", "{", "application/json"),
        ("wrong media type", "{}", "text/plain"),
    ] {
        trace.response(
            &format!("update-session {label}"),
            &Box::pin(auth.handle_request(raw("/update-session", text, &cookie, content_type)))
                .await?,
        );
    }
    for (path, text) in [
        ("/sign-out", "5"),
        ("/revoke-session", "[]"),
        ("/revoke-session", r#"{"token": 5}"#),
    ] {
        trace.response(
            &format!("{path} {text}"),
            &Box::pin(auth.handle_request(raw(path, text, &cookie, "application/json"))).await?,
        );
    }

    let other = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email": "management@example.com", "password": PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let other_token = body(&other)["token"].as_str().unwrap().to_owned();
    _ = db
        .execute(
            "CREATE TRIGGER fail_session_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, 'forced'); END",
            &[],
        )
        .await?;
    for (path, input) in [
        ("/revoke-other-sessions", json!({})),
        ("/revoke-sessions", json!({})),
        ("/revoke-session", json!({"token": other_token})),
    ] {
        trace.response(
            &format!("{path} storage failure"),
            &Box::pin(auth.handle_request(request(path, Some(input), &cookie))).await?,
        );
    }
    _ = db.execute("DROP TRIGGER fail_session_delete", &[]).await?;

    _ = db
        .execute("ALTER TABLE sessions RENAME TO sessions_unavailable", &[])
        .await?;
    trace.response(
        "list-sessions storage failure",
        &Box::pin(auth.handle_request(request("/list-sessions", None, &cookie))).await?,
    );
    _ = db
        .execute("ALTER TABLE sessions_unavailable RENAME TO sessions", &[])
        .await?;

    db.set_timestamp(
        "sessions",
        "created_at",
        ("user_id", &owner_id),
        chrono::Utc::now() - chrono::Duration::days(3),
    )
    .await?;
    let uncached = cookie
        .split("; ")
        .filter(|pair| pair.starts_with("better-auth.session_token="))
        .collect::<Vec<_>>()
        .join("; ");
    let fresh = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email": "management@example.com", "password": PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    trace.response(
        "list-sessions stale",
        &Box::pin(auth.handle_request(request("/list-sessions", None, &uncached))).await?,
    );
    trace.response(
        "list-sessions fresh",
        &Box::pin(auth.handle_request(request("/list-sessions", None, &cookies(&fresh)))).await?,
    );

    _ = db
        .execute(
            "DELETE FROM sessions WHERE token = $1",
            &[body(&owner)["token"].as_str().unwrap()],
        )
        .await?;
    trace.response(
        "sign-out of a vanished session",
        &Box::pin(auth.handle_request(request("/sign-out", Some(json!({})), &cookie))).await?,
    );
    trace.assert("session-plugins/management-failures");
    B::close(connection).await
}

struct Projection(Arc<Mutex<&'static str>>);

#[async_trait::async_trait]
impl<S: AuthSchema> SessionTransform<S> for Projection {
    async fn transform(
        &self,
        session: Value,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Value> {
        let mode = *self.0.lock().unwrap();
        match mode {
            "api" => Err(AuthError::Api {
                status: 418,
                code: Some("PROJECTION_DENIED".into()),
                message: "projection denied".into(),
            }),
            "internal" => Err(AuthError::internal("projection unavailable")),
            _ => Ok(json!({"email": session["user"]["email"], "projected": true})),
        }
    }
}

async fn device_session_projection<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mode = Arc::new(Mutex::new("ok"));
    let auth = builder_with::<B>(&connection, AuthConfig::new(SECRET).base_url(ORIGIN))
        .plugin(MultiSessionPlugin::new())
        .plugin(CustomSessionPlugin::new(Projection(mode.clone())).mutate_device_sessions(true))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let mut trace = Trace::default();
    let mut jar = String::new();
    for name in ["one", "two"] {
        let response = call(
            &auth,
            request(
                "/sign-up/email",
                Some(json!({"email": format!("projection-{name}@example.com"), "password": PASSWORD, "name": name})),
                &jar,
            ),
            200,
        )
        .await;
        jar = merge(&jar, &cookies(&response));
    }
    for name in ["ok", "api", "internal"] {
        *mode.lock().unwrap() = name;
        // Both sessions can share a creation instant, so their order is unspecified.
        let listed = Box::pin(auth.handle_request(request(
            "/multi-session/list-device-sessions",
            None,
            &jar,
        )))
        .await?;
        let mut sessions: Value = serde_json::from_slice(&listed.body).unwrap_or(Value::Null);
        if let Some(sessions) = sessions.as_array_mut() {
            sessions.sort_by_key(|session| session["email"].to_string());
        }
        trace.value(
            &format!("device sessions {name}"),
            json!({"status": listed.status, "body": sessions}),
        );
        trace.response(
            &format!("session {name}"),
            &Box::pin(auth.handle_request(request("/get-session", None, &jar))).await?,
        );
    }
    trace.response(
        "device sessions without a browser",
        &Box::pin(auth.handle_request(request("/multi-session/list-device-sessions", None, "")))
            .await?,
    );
    trace.assert("session-plugins/device-projection");
    B::close(connection).await
}

async fn multi_session_without_database_preserves_order_fallback_and_cache_replay_limits<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    fn apply(jar: &str, response: &AuthResponse) -> String {
        let wire = response
            .headers
            .get_all("set-cookie")
            .map(|raw| raw.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        merge(jar, &wire)
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = AuthBuilder::without_database(
        AuthConfig::new(SECRET)
            .base_url(ORIGIN)
            .trusted_origin(ORIGIN),
    )
    .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
    .plugin(super::auth_probe::fast_password())
    .plugin(SessionManagementPlugin::new())
    .plugin(MultiSessionPlugin::new())
    .build()
    .await?;
    let mut jar = String::new();
    let mut tokens = Vec::new();
    for index in 0..3 {
        let issued=call(&auth,request("/sign-up/email",Some(json!({"email":format!("no-db-{index}@example.test"),"password":PASSWORD,"name":"Owner"})),&jar),200).await;
        tokens.push(body(&issued)["token"].as_str().unwrap().to_owned());
        assert!(cookies(&issued).contains("session_data="));
        jar = apply(&jar, &issued);
    }
    let foreign = signup(&auth, "foreign@example.test").await;
    let listed = body(
        &call(
            &auth,
            request("/multi-session/list-device-sessions", None, &jar),
            200,
        )
        .await,
    );
    let ordered: Vec<_> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["session"]["token"].as_str().unwrap())
        .collect();
    assert_eq!(
        ordered,
        tokens.iter().map(String::as_str).collect::<Vec<_>>()
    );
    _ = call(
        &auth,
        request(
            "/multi-session/set-active",
            Some(json!({"sessionToken":tokens[0]})),
            &cookies(&foreign),
        ),
        401,
    )
    .await;
    let selected = call(
        &auth,
        request(
            "/multi-session/set-active",
            Some(json!({"sessionToken":tokens[0]})),
            &jar,
        ),
        200,
    )
    .await;
    jar = apply(&jar, &selected);
    authenticated(&auth, &jar, "no-db-0@example.test").await;
    let revoked = call(
        &auth,
        request(
            "/multi-session/revoke",
            Some(json!({"sessionToken":tokens[0]})),
            &jar,
        ),
        200,
    )
    .await;
    jar = apply(&jar, &revoked);
    authenticated(&auth, &jar, "no-db-1@example.test").await;
    let captured = cookies(&revoked);
    let listed = body(
        &call(
            &auth,
            request("/multi-session/list-device-sessions", None, &jar),
            200,
        )
        .await,
    );
    assert_eq!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["session"]["token"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![tokens[1].as_str(), tokens[2].as_str()]
    );
    let logout = call(&auth, request("/sign-out", Some(json!({})), &jar), 200).await;
    jar = apply(&jar, &logout);
    let after_logout = body(&call(&auth, request("/get-session", None, &jar), 200).await);
    assert!(after_logout.is_null());
    assert_eq!(
        body(
            &call(
                &auth,
                request("/multi-session/list-device-sessions", None, &jar),
                200
            )
            .await
        ),
        json!([])
    );
    let replay = call(&auth, request("/get-session", None, &captured), 200).await;
    assert_eq!(body(&replay)["session"]["token"], tokens[1]);
    let mut physical = request("/get-session", None, &captured);
    _ = physical
        .query
        .insert("disableCookieCache".into(), "true".into());
    assert!(body(&call(&auth, physical, 200).await).is_null());
    _ = call(
        &auth,
        request(
            "/multi-session/set-active",
            Some(json!({"sessionToken":tokens[1]})),
            &captured,
        ),
        401,
    )
    .await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    for table in ["users", "accounts", "sessions"] {
        assert_eq!(db.count(table).await?, 0);
    }
    B::close(connection).await
}
