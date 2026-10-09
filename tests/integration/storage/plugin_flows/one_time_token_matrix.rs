//! One-time token generation policy, storage failures and redemption of damaged sessions.
use super::auth_probe::{Probe, fast_builder};
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::one_time_token::{
    GenerateOneTimeToken, HashOneTimeToken, OneTimeTokenConfig, OneTimeTokenPlugin,
    OneTimeTokenSession, OneTimeTokenStorage,
};
use alibi::{AuthError, AuthResult, CookieCacheConfig, CookieCacheStrategy};
use async_trait::async_trait;
use chrono::Duration;

backend_tests!(
    one_time_token_issuance_and_redemption_policies,
    one_time_token_server_endpoints_publish_cached_identity
);

struct Generator(&'static str);
#[async_trait]
impl GenerateOneTimeToken for Generator {
    async fn generate(
        &self,
        _: &OneTimeTokenSession,
        _: Option<&AuthRequest>,
    ) -> AuthResult<String> {
        match self.0 {
            "api" => Err(AuthError::forbidden("generation vetoed")),
            "internal" => Err(AuthError::internal("generator down")),
            _ => Ok("custom-generated-token".into()),
        }
    }
}

struct Hasher(&'static str);
#[async_trait]
impl HashOneTimeToken for Hasher {
    async fn hash(&self, token: &str) -> AuthResult<String> {
        match self.0 {
            "api" => Err(AuthError::forbidden("hash vetoed")),
            "internal" => Err(AuthError::internal("hasher down")),
            _ => Ok(format!("hashed-{token}")),
        }
    }
}

async fn one_time_token_issuance_and_redemption_policies<B: Backend>(db: Db) -> TestResult {
    let mut trace = crate::snapshot::Trace::default();
    for mode in [
        "default",
        "generator vetoes",
        "generator fails",
        "custom generator",
        "hasher vetoes",
        "hasher fails",
        "hashed",
        "client requests disabled",
        "cookie disabled",
        "short lived",
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let config = OneTimeTokenConfig {
            generator: match mode {
                "generator vetoes" => Some(Arc::new(Generator("api"))),
                "generator fails" => Some(Arc::new(Generator("internal"))),
                "custom generator" => Some(Arc::new(Generator("ok"))),
                _ => None,
            },
            storage: match mode {
                "hasher vetoes" => OneTimeTokenStorage::Custom(Arc::new(Hasher("api"))),
                "hasher fails" => OneTimeTokenStorage::Custom(Arc::new(Hasher("internal"))),
                "hashed" => OneTimeTokenStorage::Hashed,
                "custom generator" => OneTimeTokenStorage::Custom(Arc::new(Hasher("ok"))),
                _ => OneTimeTokenStorage::Plain,
            },
            disable_client_request: mode == "client requests disabled",
            disable_set_session_cookie: mode == "cookie disabled",
            expires_in: if mode == "short lived" {
                Duration::seconds(-5)
            } else {
                Duration::minutes(3)
            },
            ..Default::default()
        };
        let auth = fast_builder::<B>(&connection)
            .plugin(OneTimeTokenPlugin::with_config(config))
            .build()
            .await?;
        let mut probe = Probe::new(&auth);
        probe.trace = trace;
        probe.prefix = format!("{mode}: ");
        let owner = signup(&auth, "owner@example.test").await;
        let cookie = cookies(&owner);
        let generated = probe
            .send(
                "generate",
                request("/one-time-token/generate", None, &cookie),
            )
            .await;
        let token = serde_json::from_slice::<Value>(&generated.body)
            .ok()
            .and_then(|value| value["token"].as_str().map(str::to_owned));
        for text in [
            "[]",
            "null",
            "{}",
            r#"{"token":5}"#,
            r#"{"token":"unknown"}"#,
        ] {
            let _ = probe.post(text, "/one-time-token/verify", text, "").await;
        }
        if let Some(token) = token {
            let remember = format!(
                "better-auth.dont_remember={}",
                alibi::utils::cookie_utils::sign_cookie_value("true", SECRET)
            );
            let _ = probe
                .post(
                    "redeem",
                    "/one-time-token/verify",
                    &json!({"token":token}).to_string(),
                    &remember,
                )
                .await;
            probe
                .trace
                .value("sessions", json!(db.count("sessions").await?));
        }
        trace = probe.trace;
        B::close(connection).await?;
    }

    for mode in ["session removed", "session expired", "dont remember"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = fast_builder::<B>(&connection)
            .plugin(OneTimeTokenPlugin::new())
            .build()
            .await?;
        let mut probe = Probe::new(&auth);
        probe.trace = trace;
        probe.prefix = format!("{mode}: ");
        let owner = signup(&auth, "owner@example.test").await;
        let generated = probe
            .send(
                "generate",
                request("/one-time-token/generate", None, &cookies(&owner)),
            )
            .await;
        let token = body(&generated)["token"].as_str().unwrap().to_owned();
        match mode {
            "session removed" => {
                _ = db.execute("DELETE FROM sessions", &[]).await?;
            }
            "session expired" => {
                db.set_timestamp(
                    "sessions",
                    "expires_at",
                    ("user_id", body(&owner)["user"]["id"].as_str().unwrap()),
                    chrono::Utc::now() - Duration::hours(1),
                )
                .await?;
            }
            _ => {}
        }
        let remember = format!(
            "better-auth.dont_remember={}",
            alibi::utils::cookie_utils::sign_cookie_value("true", SECRET)
        );
        let _ = probe
            .post(
                "redeem",
                "/one-time-token/verify",
                &json!({"token":token}).to_string(),
                if mode == "dont remember" {
                    &remember
                } else {
                    ""
                },
            )
            .await;
        trace = probe.trace;
        B::close(connection).await?;
    }
    trace.assert("one-time-token/policies");
    Ok(())
}

async fn one_time_token_server_endpoints_publish_cached_identity<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            strategy: CookieCacheStrategy::Compact,
            max_age: 300.0,
            version: None,
        });
    let auth = alibi::AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(OneTimeTokenPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "cached@example.test").await;
    let cookie = cookies(&owner);
    assert!(cookie.contains("session_data"));
    let with_cookie = || EndpointOptions {
        headers: Some([("cookie".to_owned(), cookie.clone())].into()),
        ..Default::default()
    };
    let issued = auth
        .dispatch_endpoint(OneTimeTokenPlugin::generate_endpoint(), with_cookie())
        .await?
        .decode()?;
    let redeemed = auth
        .dispatch_endpoint(
            OneTimeTokenPlugin::verify_endpoint(issued.token),
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    assert_eq!(redeemed.user.email.as_deref(), Some("cached@example.test"));
    let denied = auth
        .dispatch_endpoint(
            OneTimeTokenPlugin::generate_endpoint(),
            EndpointOptions::default(),
        )
        .await;
    assert!(
        denied.is_err(),
        "anonymous server generation is unauthorized"
    );
    B::close(connection).await
}
