//! Generated application migrations must support the API key plugin's physical contract.
use better_auth::{AuthConfig, AuthSchema};
use better_auth_core::store::AuthStore;
use std::sync::Arc;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

// This application insert intentionally omits config_id so the generated database
// default is exercised independently of the plugin, which supplies it explicitly.
const DEFAULT_KEY_INSERT: &str = r#"INSERT INTO api_keys
    (id, key, reference_id, enabled, rate_limit_enabled, created_at, updated_at)
    VALUES ('application-key', 'application-hash', 'application-owner', TRUE, FALSE,
            '2026-10-04T00:00:00Z', '2026-10-04T00:00:00Z')"#;

#[cfg(feature = "sqlx")]
mod sqlx_schema {
    #![allow(
        unreachable_pub,
        dead_code,
        reason = "generated schema items are public for application consumers"
    )]
    include!("../../../fixtures/cli/sqlx_all.rs");

    #[tokio::test]
    async fn generated_sqlx_schema_supports_api_key_creation() -> super::TestResult {
        let pool = SqlxPool::connect("sqlite::memory:").await?;
        run_app_migrations(&pool).await?;
        let store = std::sync::Arc::new(better_auth::sqlx::SqlxStore::<AppAuthSchema>::new(
            super::config(),
            pool.clone(),
        ));
        super::exercise(store.clone()).await?;
        pool.execute_batch(&[super::DEFAULT_KEY_INSERT]).await?;
        super::assert_application_default(store.as_ref()).await
    }
}

#[cfg(feature = "seaorm")]
mod seaorm_schema {
    #![allow(
        unreachable_pub,
        dead_code,
        reason = "generated schema items are public for application consumers"
    )]
    include!("../../../fixtures/cli/seaorm_all.rs");

    #[tokio::test]
    async fn generated_seaorm_schema_supports_api_key_creation() -> super::TestResult {
        let database = better_auth::seaorm::Database::connect("sqlite::memory:").await?;
        run_app_migrations(&database).await?;
        let store = std::sync::Arc::new(better_auth::seaorm::SeaOrmStore::<AppAuthSchema>::new(
            super::config(),
            database.clone(),
        ));
        super::exercise(store.clone()).await?;
        let _ = database
            .execute_unprepared(super::DEFAULT_KEY_INSERT)
            .await?;
        super::assert_application_default(store.as_ref()).await
    }
}

fn config() -> AuthConfig {
    AuthConfig::new("generated-api-key-schema-secret-32-chars")
}

async fn exercise<S: AuthSchema>(store: Arc<dyn AuthStore<S>>) -> TestResult {
    use better_auth::prelude::{AuthRequest, HttpMethod};
    let auth = better_auth::BetterAuth::<S>::new(config())
        .store_arc(store)
        .plugin(better_auth::plugins::EmailPasswordPlugin::new())
        .plugin(better_auth::plugins::ApiKeyPlugin::with_config(
            better_auth::plugins::ApiKeyConfig::default(),
        ))
        .build()
        .await?;
    let signup = AuthRequest::from_parts(
        HttpMethod::Post,
        "/sign-up/email".into(),
        std::collections::HashMap::from([
            ("content-type".into(), "application/json".into()),
            ("origin".into(), "http://localhost:3000".into()),
        ]),
        Some(
            br#"{"email":"generated@fixture.test","password":"password123","name":"Generated"}"#
                .to_vec(),
        ),
        std::collections::HashMap::new(),
    );
    let response = auth.handle_request(signup).await?;
    assert_eq!(response.status, 200, "signup: {:?}", response.body);
    let signup: serde_json::Value = serde_json::from_slice(&response.body)?;
    let user_id = signup
        .pointer("/user/id")
        .and_then(serde_json::Value::as_str)
        .ok_or("signup lacks user id")?;
    let token = signup
        .get("token")
        .and_then(serde_json::Value::as_str)
        .ok_or("signup lacks token")?;
    let cookie = format!(
        "better-auth.session_token={}",
        better_auth_core::utils::cookie_utils::sign_cookie_value(token, &auth.config().secret)
    );
    let request = AuthRequest::from_parts(
        HttpMethod::Post,
        "/api-key/create".into(),
        std::collections::HashMap::from([
            ("content-type".into(), "application/json".into()),
            ("cookie".into(), cookie),
            ("origin".into(), "http://localhost:3000".into()),
        ]),
        Some(br#"{"name":"generated-schema-key"}"#.to_vec()),
        std::collections::HashMap::new(),
    );
    let response = auth.handle_request(request).await?;
    assert_eq!(
        response.status, 200,
        "API key creation: {:?}",
        response.body
    );
    let created: serde_json::Value = serde_json::from_slice(&response.body)?;
    assert!(
        created
            .get("key")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|key| !key.is_empty())
    );
    let id = created
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or("API key response lacks id")?;
    let persisted = auth
        .store()
        .get_api_key_by_id(id)
        .await?
        .ok_or("API key was not persisted")?;
    assert_eq!(persisted.reference_id, user_id);
    assert_eq!(persisted.config_id, "default");
    assert_eq!(persisted.name.as_deref(), Some("generated-schema-key"));
    Ok(())
}

async fn assert_application_default<S: AuthSchema>(store: &dyn AuthStore<S>) -> TestResult {
    let persisted = store
        .get_api_key_by_id("application-key")
        .await?
        .ok_or("application key missing")?;
    assert_eq!(persisted.reference_id, "application-owner");
    assert_eq!(persisted.config_id, "default");
    Ok(())
}
