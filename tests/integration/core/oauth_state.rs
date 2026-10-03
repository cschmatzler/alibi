//! State rejection restores the authenticated flow's redirect without consuming it.

use better_auth::plugins::OAuthPlugin;
use better_auth::plugins::oauth::OAuthProvider;
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::entity::AuthVerification;
use better_auth_core::store::AuthStore;
use better_auth_core::{AuthRequest, AuthSchema, HttpMethod, OAuthStateStrategy};
use serde_json::{Value, json};

const SECRET: &str = "oauth-state-fixture-secret-at-least-32-characters";
const ORIGIN: &str = "http://localhost:42619";

fn config(strategy: OAuthStateStrategy) -> AuthConfig {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.account.store_state_strategy = strategy;
    config
}

async fn rejection_restores_flow<S: AuthSchema>(
    config: AuthConfig,
    store: impl AuthStore<S> + 'static,
    adapter: &str,
) {
    let strategy = config.account.store_state_strategy;
    let auth = AuthBuilder::new(config)
        .store(store)
        .plugin(OAuthPlugin::new().add_provider(
            "google",
            OAuthProvider::google("local-client", "local-secret"),
        ))
        .build()
        .await
        .unwrap();
    let mut request = AuthRequest::new(HttpMethod::Post, "/api/auth/sign-in/social");
    drop(request.headers.insert("origin".into(), ORIGIN.into()));
    drop(
        request
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    request.body = Some(
        json!({
            "provider":"google", "callbackURL":"/completed", "disableRedirect":true,
            "errorCallbackURL":"/saved-error?flow=original"
        })
        .to_string()
        .into_bytes(),
    );
    let issued = auth.handle_request(request).await.unwrap();
    assert_eq!(issued.status, 200);
    let body: Value = serde_json::from_slice(&issued.body).unwrap();
    let url = url::Url::parse(body["url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let cookie = issued
        .headers
        .get_all("set-cookie")
        .find(|value| {
            value.starts_with("better-auth.state=") || value.starts_with("better-auth.oauth_state=")
        })
        .unwrap();
    let cookie_pair = cookie.split(';').next().unwrap().to_owned();
    let row_before = auth
        .store()
        .get_verification_by_identifier(&state)
        .await
        .unwrap();
    assert_eq!(
        row_before.is_some(),
        strategy == OAuthStateStrategy::Database
    );

    // Use an intact authenticated cookie with a different callback nonce. For
    // database state the actual row is found first, then its cookie is checked.
    let mut callback = AuthRequest::new(HttpMethod::Get, "/api/auth/callback/google");
    drop(callback.query.insert("state".into(), state.clone()));
    let rejected_cookie = match strategy {
        OAuthStateStrategy::Cookie => {
            drop(
                callback
                    .query
                    .insert("state".into(), "foreign-state".into()),
            );
            cookie_pair.clone()
        }
        OAuthStateStrategy::Database => format!(
            "better-auth.state={}",
            better_auth_core::utils::cookie_utils::sign_cookie_value("foreign-state", SECRET)
        ),
    };
    drop(callback.headers.insert("cookie".into(), rejected_cookie));
    let rejected = auth.handle_request(callback).await.unwrap();
    assert_eq!(rejected.status, 302);
    assert_eq!(
        rejected.headers.get("location").map(String::as_str),
        Some("http://localhost:42619/saved-error?flow=original&error=state_mismatch")
    );
    assert!(
        rejected.headers.get_all("set-cookie").next().is_none(),
        "nonce rejection must leave the originating flow usable"
    );
    assert_eq!(
        auth.store()
            .get_verification_by_identifier(&state)
            .await
            .unwrap()
            .is_some(),
        row_before.is_some(),
        "nonce rejection must not consume database state"
    );

    let mut callback = AuthRequest::new(HttpMethod::Get, "/api/auth/callback/google");
    drop(callback.query.insert("state".into(), state.clone()));
    drop(
        callback
            .headers
            .insert("cookie".into(), cookie_pair.clone()),
    );
    let admitted = auth.handle_request(callback).await.unwrap();
    assert_eq!(admitted.status, 302);
    assert_eq!(
        admitted.headers.get("location").map(String::as_str),
        Some("http://localhost:42619/saved-error?flow=original&error=no_code")
    );
    assert!(
        admitted
            .headers
            .get_all("set-cookie")
            .any(|value| value.contains("Max-Age=0"))
    );
    assert!(
        auth.store()
            .get_verification_by_identifier(&state)
            .await
            .unwrap()
            .is_none()
    );

    // Kept outside production: optional raw receipts for published-codec checks.
    if let Ok(directory) = std::env::var("STATE189_EVIDENCE_DIR") {
        std::fs::write(format!("{directory}/{adapter}-{strategy:?}.json"),
            serde_json::to_vec_pretty(&json!({"state":state,"cookie":cookie,"rowValue":row_before.as_ref().map(AuthVerification::value),
                "rejectedLocation":rejected.headers.get("location"),
                "admittedLocation":admitted.headers.get("location"),
                "clearedCookies":admitted.headers.get_all("set-cookie").collect::<Vec<_>>()})).unwrap()).unwrap();
    }
}

#[tokio::test]
async fn cookie_nonce_rejection_restores_saved_error_seaorm() {
    type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    for strategy in [OAuthStateStrategy::Cookie, OAuthStateStrategy::Database] {
        let config = config(strategy);
        let database = better_auth_seaorm::Database::connect("sqlite::memory:")
            .await
            .unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        rejection_restores_flow(
            config.clone(),
            better_auth_seaorm::SeaOrmStore::<Schema>::new(config, database),
            "seaorm",
        )
        .await;
    }
}

#[cfg(feature = "sqlx-sqlite")]
#[tokio::test]
async fn cookie_nonce_rejection_restores_saved_error_sqlx() {
    type Schema = better_auth_sqlx::store::__private_test_support::bundled_schema::BundledSchema;
    for strategy in [OAuthStateStrategy::Cookie, OAuthStateStrategy::Database] {
        let config = config(strategy);
        let pool: better_auth_sqlx::SqlxPool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
            .into();
        better_auth_sqlx::store::__private_test_support::migrator::run_migrations(&pool)
            .await
            .unwrap();
        rejection_restores_flow(
            config.clone(),
            better_auth_sqlx::SqlxStore::<Schema>::new(config, pool),
            "sqlx",
        )
        .await;
    }
}
