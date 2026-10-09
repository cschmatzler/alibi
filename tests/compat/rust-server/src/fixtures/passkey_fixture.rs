//! Equivalent passkey configurations and actual SQLite observations.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::{EmailPasswordPlugin, PasskeyPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi::seaorm::sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use axum::{
    Json, Router,
    extract::Query,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserQuery {
    user_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Clock {
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CurrentCounter {
    credential_id: String,
    counter: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CurrentPublicKey {
    credential_id: String,
    public_key: String,
}

struct ExtensionInputs {
    mode: String,
    registration: bool,
}
#[async_trait::async_trait]
impl alibi::plugins::passkey::PasskeyExtensionsResolver for ExtensionInputs {
    async fn resolve(
        &self,
        context: &alibi::plugins::passkey::PasskeyOptionsContext<'_>,
    ) -> AuthResult<Value> {
        if self.mode == "coded" {
            return Err(alibi::AuthError::Api {
                status: 403,
                code: Some("EXTENSIONS_DENIED".into()),
                message: "Application extensions rejected".into(),
            });
        }
        if self.mode == "ordinary" {
            return Err(alibi::AuthError::internal("Application extensions failed"));
        }
        let marker = context
            .request
            .headers
            .get("x-extension-marker")
            .map(String::as_str)
            .unwrap_or("null");
        if self.registration {
            if context.user.is_none() {
                return Err(alibi::AuthError::internal(
                    "actual registration session required",
                ));
            }
            Ok(json!({"credProps": false, "minPinLength": marker == "registration-marker"}))
        } else {
            let path = context.request.path().rsplit('/').next().unwrap();
            Ok(json!({"appid":format!("https://extensions.fixture.test/{marker}/{path}")}))
        }
    }
}

pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router> {
    let mut router = Router::new();
    for (name, age) in [
        ("passkey-fresh", 1),
        ("passkey-no-freshness", 0),
        ("passkey-acceptance", 0),
        ("passkey-extensions-static", 0),
        ("passkey-extensions-resolver", 0),
        ("passkey-extensions-coded", 0),
        ("passkey-extensions-ordinary", 0),
        ("passkey-rp-options", 0),
        ("passkey-origin-list", 0),
        ("passkey-origin-null", 0),
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut configured = config.clone().base_path(&path);
        configured.session.fresh_age = Some(chrono::Duration::seconds(age));
        let plugin = if name == "passkey-acceptance" {
            let roots = [
                "packed",
                "fido-u2f",
                "tpm",
                "android-key",
                "android-safetynet",
                "apple",
            ]
            .into_iter()
            .map(|format| {
                (
                    format.to_owned(),
                    vec![include_str!("../../../fixtures/passkey-attestation/ca.pem").to_owned()],
                )
            })
            .collect();
            PasskeyPlugin::new()
                .web_authn_challenge_cookie("ceremony-proof")
                .attestation_root_certificates(roots)
        } else if name == "passkey-rp-options" {
            PasskeyPlugin::new()
                .rp_name("Configured ceremony RP")
                .authenticator_selection(alibi::plugins::passkey::PasskeyAuthenticatorSelection {
                    resident_key: Some("required".into()),
                    user_verification: Some("required".into()),
                    authenticator_attachment: Some("platform".into()),
                })
        } else if let Some(mode) = name.strip_prefix("passkey-extensions-") {
            use alibi::plugins::passkey::{
                PasskeyAuthenticationConfig, PasskeyExtensions, PasskeyRegistrationConfig,
            };
            let input = |registration| {
                if mode == "static" {
                    PasskeyExtensions::Static(if registration {
                        json!({"credProps":true})
                    } else {
                        json!({"appid":"https://extensions.fixture.test/static"})
                    })
                } else {
                    PasskeyExtensions::Resolver(Arc::new(ExtensionInputs {
                        mode: mode.into(),
                        registration,
                    }))
                }
            };
            PasskeyPlugin::new()
                .registration(PasskeyRegistrationConfig {
                    extensions: Some(input(true)),
                    ..Default::default()
                })
                .authentication(PasskeyAuthenticationConfig {
                    extensions: Some(input(false)),
                    ..Default::default()
                })
        } else if name == "passkey-origin-list" {
            PasskeyPlugin::new().origins(vec![
                config.base_url.clone(),
                "http://localhost:4444".into(),
            ])
        } else {
            PasskeyPlugin::new()
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(configured.clone())
                .store(crate::backend::store::<TestSchema>(
                    configured,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new())
                .plugin(plugin)
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let state_database = database.clone();
    let counter_database = database.clone();
    let key_database = database.clone();
    Ok(router
        .route(
            "/__test/passkey-crl",
            get(|| async {
                include_bytes!("../../../fixtures/passkey-attestation/revoked.der").as_slice()
            }),
        )
        .route(
            "/__test/passkey-public-key",
            post(move |Json(input): Json<CurrentPublicKey>| {
                let database = key_database.clone();
                async move {
                    let result = database
                        .execute_raw(Statement::from_sql_and_values(
                            DbBackend::Sqlite,
                            "UPDATE passkeys SET public_key = ? WHERE credential_id = ?",
                            [input.public_key.into(), input.credential_id.into()],
                        ))
                        .await
                        .unwrap();
                    Json(json!({"updated": result.rows_affected()}))
                }
            }),
        )
        .route(
            "/__test/passkey-state",
            get(move |Query(query): Query<UserQuery>| {
                let database = state_database.clone();
                async move {
                    let rows = database
                        .query_all_raw(Statement::from_string(
                            DbBackend::Sqlite,
                            "SELECT user_id, counter, name FROM passkeys ORDER BY id",
                        ))
                        .await
                        .unwrap();
                    let passkeys: Vec<Value> = rows
                        .iter()
                        .map(|row| {
                            json!({
                                "userId": row.try_get::<String>("", "user_id").unwrap(),
                                "counter": row.try_get::<i64>("", "counter").unwrap(),
                                "name": row.try_get::<Option<String>>("", "name").unwrap(),
                            })
                        })
                        .collect();
                    let sessions = database
                        .query_one_raw(Statement::from_sql_and_values(
                            DbBackend::Sqlite,
                            "SELECT COUNT(*) AS count FROM sessions WHERE user_id = ?",
                            [query.user_id.into()],
                        ))
                        .await
                        .unwrap()
                        .unwrap();
                    let challenges = database
                        .query_one_raw(Statement::from_string(
                            DbBackend::Sqlite,
                            "SELECT COUNT(*) AS count FROM verifications",
                        ))
                        .await
                        .unwrap()
                        .unwrap();
                    Json(json!({ "passkeys": passkeys,
                "sessions": {"count": sessions.try_get::<i64>("", "count").unwrap()},
                "challenges": {"count": challenges.try_get::<i64>("", "count").unwrap()} }))
                }
            }),
        )
        .route(
            "/__test/passkey-current-counter",
            post(move |Json(input): Json<CurrentCounter>| {
                let database = counter_database.clone();
                async move {
                    let result = database
                        .execute_raw(Statement::from_sql_and_values(
                            DbBackend::Sqlite,
                            "UPDATE passkeys SET counter = ? WHERE credential_id = ?",
                            [i64::from(input.counter).into(), input.credential_id.into()],
                        ))
                        .await
                        .unwrap();
                    Json(json!({"updated": result.rows_affected()}))
                }
            }),
        )
        .route(
            "/__test/passkey-challenge-clock",
            post(move |Json(clock): Json<Clock>| {
                let database = database.clone();
                async move {
                    database
                        .execute_raw(Statement::from_sql_and_values(
                            DbBackend::Sqlite,
                            "UPDATE verifications SET expires_at = ?",
                            [clock.expires_at.into()],
                        ))
                        .await
                        .unwrap();
                    Json(json!({"updated": true}))
                }
            }),
        ))
}
