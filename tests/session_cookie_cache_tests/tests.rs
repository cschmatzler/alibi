use super::*;

#[tokio::test]
async fn successful_cached_reader_does_not_cross_auth_configuration_or_database() {
    type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    let db = Database::connect("sqlite::memory:").await.unwrap();
    run_migrations(&db).await.unwrap();
    let config = AuthConfig::new("cache-owner-instance-secret-at-least-32")
        .base_url("http://localhost:42594")
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            ..Default::default()
        });
    let auth = AuthBuilder::<Schema>::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, db))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await
        .unwrap();
    let signup = auth.handle_request(request(
        HttpMethod::Post,
        "/api/auth/sign-up/email",
        Some(json!({"name":"Instance Owner","email":"cache-instance@example.test","password":"password123"})),
        None,
    )).await.unwrap();
    assert_eq!(signup.status, 200);
    let body: Value = serde_json::from_slice(&signup.body).unwrap();
    let cookies = signup
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(cookies.contains("session_data="));
    let empty = Database::connect("sqlite::memory:").await.unwrap();
    run_migrations(&empty).await.unwrap();
    let empty_store: Arc<dyn better_auth_core::AuthStore<Schema>> =
        Arc::new(SeaOrmStore::<Schema>::new(auth.config().clone(), empty));
    let mut wrong_secret = auth.config().clone();
    wrong_secret.secret = "another-cache-instance-secret-at-least-32".into();
    let contexts = [
        better_auth_core::AuthContext::new(Arc::new(wrong_secret), Arc::clone(auth.store())),
        better_auth_core::AuthContext::new(Arc::clone(&auth.context().config), empty_store),
    ];
    let mut denied = Vec::new();
    for (index, other) in contexts.iter().enumerate() {
        let mut read = request(
            HttpMethod::Get,
            "/api/auth/get-session",
            None,
            Some(cookies.clone()),
        );
        if index == 1 {
            drop(
                read.query
                    .insert("disableCookieCache".into(), "true".into()),
            );
        }
        let (_, first) = auth.context().require_cached_session(&read).await.unwrap();
        assert_eq!(first.token, body["token"].as_str().unwrap());
        let (_, repeated) = auth.context().require_cached_session(&read).await.unwrap();
        assert_eq!(repeated, first);
        denied.push(matches!(
            other.require_cached_session(&read).await,
            Err(better_auth_core::AuthError::Unauthenticated)
        ));
        let (_, retained) = auth.context().require_cached_session(&read).await.unwrap();
        assert_eq!(retained, first);
    }
    assert_eq!(
        denied,
        [true, true],
        "changed secret and changed physical store must reject"
    );
    assert!(
        auth.store()
            .get_session(body["token"].as_str().unwrap())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn cache_version_retains_actual_custom_models_only_for_created_source_and_never_leaks_private_columns()
 {
    use better_auth::field_policy::FieldConfig;

    let db = Database::connect("sqlite::memory:").await.unwrap();
    run_migrations(&db).await.unwrap();
    for sql in [
        "ALTER TABLE sessions ADD COLUMN label TEXT",
        "ALTER TABLE sessions ADD COLUMN hidden TEXT",
        "ALTER TABLE sessions ADD COLUMN number REAL",
        "ALTER TABLE sessions ADD COLUMN server_only TEXT NOT NULL DEFAULT 'physical-private-sentinel'",
        "ALTER TABLE sessions ADD COLUMN transformed TEXT",
        "ALTER TABLE sessions ADD COLUMN validated TEXT",
        "ALTER TABLE sessions ADD COLUMN callback TEXT",
        "ALTER TABLE sessions ADD COLUMN payload JSON NOT NULL DEFAULT '{}'",
        "CREATE TABLE session_model_events (phase TEXT, label TEXT, is_insert BOOLEAN)",
    ] {
        _ = db
            .execute_raw(Statement::from_string(db.get_database_backend(), sql))
            .await
            .unwrap();
    }
    let version = Arc::new(Version(Mutex::new(Vec::new())));
    let mut config = AuthConfig::new("cache-real-custom-model-secret-at-least-32")
        .base_url("http://localhost:42594")
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            version: Some(CookieCacheVersion::Resolver(Arc::<Version>::clone(
                &version,
            ))),
            ..Default::default()
        });

    drop(
        config.session.additional_fields.insert(
            "hidden".into(),
            FieldConfig::new(json!({"type":"string"}))
                .default_value(json!("actual-hidden-default"))
                .hidden(),
        ),
    );
    drop(config.session.additional_fields.insert(
        "label".into(),
        FieldConfig::new(json!({"type":"string"})).default_value(json!("public-label")),
    ));
    let auth = AuthBuilder::<ApplicationSchema>::new(config.clone())
        .store(SeaOrmStore::<ApplicationSchema>::new(config, db.clone()))
        .plugin(EmailPasswordPlugin::new().enable_username(false))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await
        .unwrap();
    let signup = auth.handle_request(request(HttpMethod::Post,"/api/auth/sign-up/email",Some(json!({"name":"Actual Owner","email":"native-cache@example.test","password":"password123"})),None)).await.unwrap();
    assert_eq!(
        signup.status,
        200,
        "{}",
        String::from_utf8_lossy(&signup.body)
    );
    let body: Value = serde_json::from_slice(&signup.body).unwrap();
    let cookies = signup
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(cookies.contains("session_data="));
    let original = auth
        .store()
        .get_session(body["token"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(original.hidden.as_deref(), Some("actual-hidden-default"));
    assert_eq!(
        original.server_only.as_deref(),
        Some("physical-private-sentinel")
    );
    auth.store()
        .delete_session(body["token"].as_str().unwrap())
        .await
        .unwrap();
    let cached = auth
        .handle_request(request(
            HttpMethod::Get,
            "/api/auth/get-session",
            None,
            Some(cookies.clone()),
        ))
        .await
        .unwrap();
    assert_eq!(cached.status, 200);
    let payload: Value = serde_json::from_slice(&cached.body).unwrap();
    assert_eq!(payload["session"]["id"], original.id);
    assert_eq!(payload["session"]["label"], "public-label");
    assert!(payload["session"].get("hidden").is_none());
    assert!(payload["session"].get("server_only").is_none());
    assert_eq!(
        version.0.lock().unwrap().as_slice(),
        &[
            json!({"phase":"stored","id":original.id,"hidden":"actual-hidden-default","physical":"physical-private-sentinel"}),
            json!({"phase":"cached","id":original.id}),
        ]
    );
    let physical = auth
        .context()
        .require_session(&request(
            HttpMethod::Get,
            "/api/auth/get-session",
            None,
            Some(cookies),
        ))
        .await;
    assert!(matches!(
        physical,
        Err(better_auth_core::AuthError::Unauthenticated)
    ));
    assert!(
        auth.store()
            .get_session(body["token"].as_str().unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn unsupported_enabled_cache_strategies_fail_at_public_initialization_before_issuing_authority()
 {
    type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    let db = Database::connect("sqlite::memory:").await.unwrap();
    run_migrations(&db).await.unwrap();
    for strategy in [
        better_auth_core::CookieCacheStrategy::Jwt,
        better_auth_core::CookieCacheStrategy::Jwe,
    ] {
        let config = AuthConfig::new("cache-native-initialization-secret-at-least-32")
            .session_cookie_cache(CookieCacheConfig {
                enabled: true,
                strategy: strategy.clone(),
                ..Default::default()
            });
        let result = AuthBuilder::<Schema>::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, db.clone()))
            .plugin(EmailPasswordPlugin::new())
            .build()
            .await;
        assert!(matches!(
            result,
            Err(better_auth_core::AuthError::Config(_))
        ));
        let users = db
            .query_all_raw(Statement::from_string(
                db.get_database_backend(),
                "SELECT * FROM users",
            ))
            .await
            .unwrap();
        let sessions = db
            .query_all_raw(Statement::from_string(
                db.get_database_backend(),
                "SELECT * FROM sessions",
            ))
            .await
            .unwrap();
        assert!(users.is_empty());
        assert!(sessions.is_empty());
        let disabled = AuthConfig::new("cache-native-initialization-secret-at-least-32")
            .session_cookie_cache(CookieCacheConfig {
                enabled: false,
                strategy,
                ..Default::default()
            });
        assert!(
            AuthBuilder::<Schema>::new(disabled.clone())
                .store(SeaOrmStore::<Schema>::new(disabled, db.clone()))
                .plugin(EmailPasswordPlugin::new())
                .build()
                .await
                .is_ok()
        );
    }
}
