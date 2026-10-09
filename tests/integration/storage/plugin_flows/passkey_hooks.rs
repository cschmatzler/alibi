//! Passkey registration ownership, application hooks, challenge reuse and
//! session freshness.
use super::passkey_attestation::{Shape, Signature, client};
use super::passkey_matrix::{
    ATTESTED, Authenticator, BACKUP_ELIGIBLE, USER_PRESENT, USER_VERIFIED,
};
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::PasskeyPlugin;
use alibi::plugins::passkey::{
    PasskeyAuthenticationAfterVerification, PasskeyAuthenticationConfig,
    PasskeyAuthenticationContext, PasskeyRegistrationAfterVerification, PasskeyRegistrationConfig,
    PasskeyRegistrationContext, PasskeyRegistrationOverride, PasskeyRegistrationUser,
    PasskeyUserResolver, VerifiedPasskeyAuthentication, VerifiedPasskeyRegistration,
};
use alibi::utils::json::JsValue;
use alibi::{AuthError, AuthResult};

backend_tests!(
    passkey_registration_ownership,
    passkey_authentication_hooks,
    passkey_session_freshness,
    passkey_input_types
);

type Observed = (usize, u32, bool, bool, bool);

#[derive(Default)]
struct Policy {
    mode: Mutex<&'static str>,
    resolved: Mutex<String>,
    other: Mutex<String>,
    registered: Mutex<Vec<(String, u64, bool)>>,
    authenticated: Mutex<Vec<Observed>>,
    url: Mutex<String>,
}

#[async_trait::async_trait]
impl PasskeyUserResolver for Policy {
    async fn resolve_user(
        &self,
        _: &PasskeyRegistrationContext<'_>,
        context: Option<&str>,
    ) -> AuthResult<Option<PasskeyRegistrationUser>> {
        assert_eq!(context, Some("signup"));
        Ok(Some(PasskeyRegistrationUser {
            id: self.resolved.lock().unwrap().clone(),
            name: "resolved".into(),
            display_name: None,
        }))
    }
}

#[async_trait::async_trait]
impl PasskeyRegistrationAfterVerification for Policy {
    async fn after_verification(
        &self,
        _: &PasskeyRegistrationContext<'_>,
        verification: &VerifiedPasskeyRegistration,
        _: &PasskeyRegistrationUser,
        _: &JsValue,
        stored_context: Option<&str>,
    ) -> AuthResult<Option<PasskeyRegistrationOverride>> {
        self.registered.lock().unwrap().push((
            verification.credential_id.clone(),
            verification.counter,
            verification.backed_up,
        ));
        assert_eq!(stored_context, Some("signup"));
        match *self.mode.lock().unwrap() {
            "other" => Ok(Some(PasskeyRegistrationOverride {
                user_id: Some(self.other.lock().unwrap().clone()),
                name: Some("  Override name  ".into()),
            })),
            "empty" => Ok(Some(PasskeyRegistrationOverride {
                user_id: Some(String::new()),
                name: Some(String::new()),
            })),
            "api" => Err(AuthError::forbidden("registration denied")),
            "internal" => Err(AuthError::internal("registration unavailable")),
            _ => Ok(None),
        }
    }
}

#[async_trait::async_trait]
impl PasskeyAuthenticationAfterVerification for Policy {
    async fn after_verification(
        &self,
        _: &PasskeyAuthenticationContext<'_>,
        verification: &VerifiedPasskeyAuthentication,
        _: &JsValue,
    ) -> AuthResult<()> {
        let result = &verification.result;
        self.authenticated.lock().unwrap().push((
            result.cred_id().as_slice().len(),
            result.counter(),
            result.user_verified(),
            result.backup_eligible(),
            result.backup_state(),
        ));
        assert_eq!(verification.origin, ORIGIN);
        assert_eq!(verification.rp_id, "localhost");
        let mode = *self.mode.lock().unwrap();
        match mode {
            "api" => Err(AuthError::forbidden("authentication denied")),
            "internal" => Err(AuthError::internal("authentication unavailable")),
            "delete" => {
                let url = self.url.lock().unwrap().clone();
                let pool = alibi::sqlx::sqlx::SqlitePool::connect(&url).await.unwrap();
                _ = alibi::sqlx::sqlx::query("DELETE FROM passkeys")
                    .execute(&pool)
                    .await
                    .unwrap();
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

fn plugin(policy: &Arc<Policy>) -> PasskeyPlugin {
    PasskeyPlugin::new()
        .origins(vec![ORIGIN.into()])
        .registration(PasskeyRegistrationConfig {
            require_session: false,
            resolve_user: Some(policy.clone()),
            after_verification: Some(policy.clone()),
            ..Default::default()
        })
        .authentication(PasskeyAuthenticationConfig {
            extensions: None,
            after_verification: Some(policy.clone()),
        })
}

fn proof(key: &Authenticator, shape: &Shape, challenge: &Value) -> Value {
    let client = client(challenge);
    let bytes = serde_json::to_vec(&client).unwrap();
    key.registration(&client, &shape.build(key, &bytes), false)
}

fn keyed(seed: u8) -> (Authenticator, Shape) {
    (
        Authenticator::new(seed, &format!("hook-key-{seed}")),
        Shape {
            flags: USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | ATTESTED,
            ..Default::default()
        },
    )
}

async fn passkey_registration_ownership<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(Policy::default());
    let auth = builder::<B>(&connection)
        .plugin(plugin(&policy))
        .build()
        .await?;
    let mut trace = Trace::default();
    let first = signup(&auth, "passkey-first@example.com").await;
    let second = signup(&auth, "passkey-second@example.com").await;
    let (first_id, second_id) = (
        body(&first)["user"]["id"].as_str().unwrap().to_owned(),
        body(&second)["user"]["id"].as_str().unwrap().to_owned(),
    );
    trace.mask(&first_id);
    trace.mask(&second_id);
    *policy.resolved.lock().unwrap() = second_id.clone();
    *policy.other.lock().unwrap() = first_id.clone();
    let session = cookies(&first);

    let options = async |cookie: &str| {
        call(
            &auth,
            {
                let mut request = request("/passkey/generate-register-options", None, cookie);
                request.set_query_pairs([("context", "signup")]);
                request
            },
            200,
        )
        .await
    };
    let verify = async |trace: &mut Trace,
                        label: &str,
                        options: &AuthResponse,
                        cookie: &str,
                        seed: u8,
                        extra: Value| {
        let (key, shape) = keyed(seed);
        let mut input = json!({"response": proof(&key, &shape, &body(options)["challenge"])});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let response = Box::pin(auth.handle_request(request(
            "/passkey/verify-registration",
            Some(input),
            &format!("{cookie}; {}", cookies(options)),
        )))
        .await
        .unwrap();
        trace.response(label, &response);
        response
    };

    let issued = options("").await;
    _ = verify(
        &mut trace,
        "someone else finishes the challenge",
        &issued,
        &session,
        70,
        json!({}),
    )
    .await;
    let issued = options("").await;
    let finished = verify(&mut trace, "resolved user", &issued, "", 71, json!({})).await;
    assert_eq!(body(&finished)["userId"], second_id);
    _ = verify(&mut trace, "replayed challenge", &issued, "", 71, json!({})).await;
    let mut request_without_cookie = request(
        "/passkey/verify-registration",
        Some(json!({"response": {}})),
        "",
    );
    request_without_cookie.method = HttpMethod::Post;
    trace.response(
        "missing challenge cookie",
        &Box::pin(auth.handle_request(request_without_cookie)).await?,
    );
    let authentication = call(
        &auth,
        request("/passkey/generate-authenticate-options", None, ""),
        200,
    )
    .await;
    _ = verify(
        &mut trace,
        "authentication challenge",
        &authentication,
        "",
        72,
        json!({}),
    )
    .await;
    let issued = options("").await;
    let (key, shape) = keyed(73);
    let mut cross = request(
        "/passkey/verify-authentication",
        Some(json!({"response": key.assertion(
            &json!({"type": "webauthn.get", "challenge": body(&issued)["challenge"], "origin": ORIGIN}),
            "localhost",
            USER_PRESENT,
            1,
        )})),
        &cookies(&issued),
    );
    cross.method = HttpMethod::Post;
    trace.response(
        "registration challenge for authentication",
        &Box::pin(auth.handle_request(cross)).await?,
    );
    drop(shape);

    for (index, mode) in ["other", "empty", "api", "internal"]
        .into_iter()
        .enumerate()
    {
        *policy.mode.lock().unwrap() = mode;
        *policy.other.lock().unwrap() = first_id.clone();
        let seed = 80 + 2 * u8::try_from(index)?;
        let issued = options("").await;
        _ = verify(
            &mut trace,
            &format!("anonymous hook {mode}"),
            &issued,
            "",
            seed,
            json!({}),
        )
        .await;
        *policy.other.lock().unwrap() = second_id.clone();
        let issued = options(&session).await;
        _ = verify(
            &mut trace,
            &format!("session hook {mode}"),
            &issued,
            &session,
            seed + 1,
            json!({"name": "  Given  "}),
        )
        .await;
    }
    *policy.mode.lock().unwrap() = "other";
    let issued = options("").await;
    let created = verify(
        &mut trace,
        "override with session creation",
        &issued,
        "",
        90,
        json!({"createSession": true}),
    )
    .await;
    assert!(cookies(&created).contains("session_token"));
    *policy.mode.lock().unwrap() = "";
    _ = db
        .execute(
            "CREATE TRIGGER fail_session_insert BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'forced'); END",
            &[],
        )
        .await?;
    let issued = options("").await;
    _ = verify(
        &mut trace,
        "session creation storage failure",
        &issued,
        "",
        91,
        json!({"createSession": true}),
    )
    .await;
    _ = db.execute("DROP TRIGGER fail_session_insert", &[]).await?;

    let shapes: Vec<(&str, Shape)> = vec![
        (
            "core packed corrupt signature",
            Shape {
                fmt: "packed",
                signature: Signature::Corrupt,
                ..keyed(0).1
            },
        ),
        (
            "core packed algorithm mismatch",
            Shape {
                fmt: "packed",
                statement_alg: Some(-7),
                ..keyed(0).1
            },
        ),
        (
            "core packed on another curve",
            Shape {
                fmt: "packed",
                curve: 7,
                ..keyed(0).1
            },
        ),
        (
            "core packed valid",
            Shape {
                fmt: "packed",
                ..keyed(0).1
            },
        ),
    ];
    for (index, (label, shape)) in shapes.into_iter().enumerate() {
        let issued = options("").await;
        let key = Authenticator::new(100 + u8::try_from(index)?, &format!("packed-{index}"));
        let response = Box::pin(auth.handle_request(request(
            "/passkey/verify-registration",
            Some(json!({"response": proof(&key, &shape, &body(&issued)["challenge"])})),
            &cookies(&issued),
        )))
        .await?;
        trace.response(label, &response);
    }
    assert!(!policy.registered.lock().unwrap().is_empty());
    trace.assert("passkey/registration-ownership");
    B::close(connection).await
}

async fn passkey_authentication_hooks<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let policy = Arc::new(Policy::default());
    *policy.url.lock().unwrap() = db.url.clone();
    let auth = builder::<B>(&connection)
        .plugin(plugin(&policy))
        .build()
        .await?;
    let mut trace = Trace::default();
    let owner = signup(&auth, "hooks-owner@example.com").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    trace.mask(&owner_id);
    let session = cookies(&owner);
    *policy.resolved.lock().unwrap() = owner_id;
    let core = Authenticator::new(7, "hooks-core");
    let raw = Authenticator::new(9, "hooks-raw");
    for (key, shape) in [
        (
            &core,
            Shape {
                flags: USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | ATTESTED,
                ..Default::default()
            },
        ),
        (
            &raw,
            Shape {
                fmt: "packed",
                alg: -7,
                flags: USER_PRESENT | BACKUP_ELIGIBLE | ATTESTED,
                ..Default::default()
            },
        ),
    ] {
        let options = call(
            &auth,
            {
                let mut request = request("/passkey/generate-register-options", None, &session);
                request.set_query_pairs([("context", "signup")]);
                request
            },
            200,
        )
        .await;
        _ = call(
            &auth,
            request(
                "/passkey/verify-registration",
                Some(json!({"response": proof(key, &shape, &body(&options)["challenge"])})),
                &format!("{session}; {}", cookies(&options)),
            ),
            200,
        )
        .await;
    }
    let mut counter = 1;
    for (label, key, mode, flags) in [
        (
            "core hook denies",
            &core,
            "api",
            USER_PRESENT | USER_VERIFIED,
        ),
        ("core hook fails", &core, "internal", USER_PRESENT),
        ("raw hook denies", &raw, "api", USER_PRESENT),
        ("raw hook fails", &raw, "internal", USER_PRESENT),
        (
            "raw hook observes",
            &raw,
            "",
            USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE,
        ),
        (
            "core hook observes",
            &core,
            "",
            USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE,
        ),
        ("raw hook removes the row", &raw, "delete", USER_PRESENT),
    ] {
        *policy.mode.lock().unwrap() = mode;
        counter += 1;
        let options = call(
            &auth,
            request("/passkey/generate-authenticate-options", None, ""),
            200,
        )
        .await;
        let client = json!({"type": "webauthn.get", "challenge": body(&options)["challenge"], "origin": ORIGIN});
        let response = Box::pin(auth.handle_request(request(
            "/passkey/verify-authentication",
            Some(json!({"response": key.assertion(&client, "localhost", flags, counter)})),
            &cookies(&options),
        )))
        .await?;
        trace.response(label, &response);
    }
    trace.value(
        "observed",
        json!(policy.authenticated.lock().unwrap().clone()),
    );
    trace.value("rows left", json!(db.count("passkeys").await?));
    trace.assert("passkey/authentication-hooks");
    B::close(connection).await
}

async fn passkey_session_freshness<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(PasskeyPlugin::new())
        .build()
        .await?;
    let signed_up = signup(&auth, "stale-passkey@example.com").await;
    let user_id = body(&signed_up)["user"]["id"].as_str().unwrap().to_owned();
    let cookie = cookies(&signed_up);
    _ = call(
        &auth,
        request("/passkey/generate-register-options", None, &cookie),
        200,
    )
    .await;
    db.set_timestamp(
        "sessions",
        "created_at",
        ("user_id", &user_id),
        chrono::Utc::now() - chrono::Duration::days(3),
    )
    .await?;
    let stale = call(
        &auth,
        request("/passkey/generate-register-options", None, &cookie),
        403,
    )
    .await;
    assert_eq!(body(&stale)["code"], "SESSION_NOT_FRESH");
    B::close(connection).await
}

async fn passkey_input_types<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(PasskeyPlugin::new())
        .build()
        .await?;
    let owner = cookies(&signup(&auth, "passkey-types@example.com").await);
    let mut trace = Trace::default();
    for (label, text) in [
        ("missing response", r#"{}"#),
        (
            "session flag null",
            r#"{"response":{},"createSession":null}"#,
        ),
        (
            "session flag array",
            r#"{"response":{},"createSession":[]}"#,
        ),
        (
            "session flag object",
            r#"{"response":{},"createSession":{}}"#,
        ),
        (
            "session flag string",
            r#"{"response":{},"createSession":"yes"}"#,
        ),
        (
            "session flag number",
            r#"{"response":{},"createSession":5}"#,
        ),
        ("name number", r#"{"response":{},"name":5}"#),
        ("name boolean", r#"{"response":{},"name":true}"#),
        ("name object", r#"{"response":{},"name":{}}"#),
        ("name array", r#"{"response":{},"name":[]}"#),
        ("name null", r#"{"response":{},"name":null}"#),
    ] {
        let mut register = request("/passkey/verify-registration", None, &owner);
        register.method = HttpMethod::Post;
        register.body = Some(text.as_bytes().to_vec());
        trace.response(
            &format!("registration {label}"),
            &Box::pin(auth.handle_request(register)).await?,
        );
    }
    for (label, text) in [
        ("missing", r#"{}"#),
        ("null", r#"{"response":null}"#),
        ("array", r#"{"response":[]}"#),
        ("string", r#"{"response":"x"}"#),
        ("number", r#"{"response":5}"#),
        ("boolean", r#"{"response":true}"#),
    ] {
        let mut authenticate = request("/passkey/verify-authentication", None, "");
        authenticate.method = HttpMethod::Post;
        authenticate.body = Some(text.as_bytes().to_vec());
        trace.response(
            &format!("authentication response {label}"),
            &Box::pin(auth.handle_request(authenticate)).await?,
        );
    }
    trace.assert("passkey/input-types");
    B::close(connection).await
}
