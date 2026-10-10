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
    parallel_sibling_revocation_retains_owned_deletes_after_rejection
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

async fn parallel_sibling_revocation_retains_owned_deletes_after_rejection<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::AuthSession;
    use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
    struct Gates {
        modes: Mutex<BTreeMap<String, usize>>,
        started: [tokio::sync::Notify; 3],
        held_release: tokio::sync::Notify,
        failure_release: tokio::sync::Notify,
        success_committed: tokio::sync::Notify,
        held_committed: tokio::sync::Notify,
    }
    struct Hooks(Arc<Gates>);
    #[async_trait::async_trait]
    impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for Hooks {
        async fn before_delete_session(
            &self,
            session: &S::Session,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<HookControl> {
            let mode = self.0.modes.lock().unwrap().get(session.token()).copied();
            if let Some(mode) = mode {
                self.0.started[mode].notify_one();
                match mode {
                    0 => self.0.held_release.notified().await,
                    1 => {
                        self.0.failure_release.notified().await;
                        return Err(AuthError::internal("sibling application rejection"));
                    }
                    _ => {}
                }
            }
            Ok(HookControl::Continue)
        }
        async fn after_delete_session(
            &self,
            session: &S::Session,
            _: &DatabaseHookContext<'_, H>,
        ) -> AuthResult<()> {
            match self.0.modes.lock().unwrap().get(session.token()).copied() {
                Some(0) => self.0.held_committed.notify_one(),
                Some(2) => self.0.success_committed.notify_one(),
                _ => {}
            }
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let gates = Arc::new(Gates {
        modes: Mutex::new(BTreeMap::new()),
        started: std::array::from_fn(|_| tokio::sync::Notify::new()),
        held_release: tokio::sync::Notify::new(),
        failure_release: tokio::sync::Notify::new(),
        success_committed: tokio::sync::Notify::new(),
        held_committed: tokio::sync::Notify::new(),
    });
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let store = B::hook(
        B::store(Arc::new(config.clone()), &connection),
        Hooks(gates.clone()),
    );
    let auth = Arc::new(
        AuthBuilder::new(config)
            .store(store)
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?,
    );
    let owner = signup(&auth, "parallel-owner@example.test").await;
    let foreign = signup(&auth, "parallel-foreign@example.test").await;
    let mut siblings = Vec::new();
    for mode in 0..3 {
        let response = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"parallel-owner@example.test","password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        let token = body(&response)["token"].as_str().unwrap().to_owned();
        let _ = gates.modes.lock().unwrap().insert(token.clone(), mode);
        siblings.push((token, cookies(&response)));
    }
    let input = request("/revoke-other-sessions", Some(json!({})), &cookies(&owner));
    let worker = auth.clone();
    let response = tokio::spawn(async move { call(&worker, input, 500).await });
    for started in &gates.started {
        tokio::time::timeout(std::time::Duration::from_secs(2), started.notified()).await?;
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        gates.success_committed.notified(),
    )
    .await?;
    gates.failure_release.notify_one();
    let rejected = tokio::time::timeout(std::time::Duration::from_secs(2), response).await??;
    assert!(!rejected.headers.contains_key("set-cookie"));
    assert_eq!(db.count("sessions").await?, 4);
    for (index, (token, _)) in siblings.iter().enumerate() {
        assert_eq!(
            db.count_where("SELECT COUNT(*) FROM sessions WHERE token = $1", &[token])
                .await?,
            i64::from(index != 2)
        );
    }
    gates.held_release.notify_one();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        gates.held_committed.notified(),
    )
    .await?;
    assert_eq!(db.count("sessions").await?, 3);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM sessions WHERE token = $1",
            &[&siblings[0].0]
        )
        .await?,
        0
    );
    authenticated(&auth, &siblings[1].1, "parallel-owner@example.test").await;
    authenticated(&auth, &cookies(&owner), "parallel-owner@example.test").await;
    authenticated(&auth, &cookies(&foreign), "parallel-foreign@example.test").await;
    Ok(())
}
