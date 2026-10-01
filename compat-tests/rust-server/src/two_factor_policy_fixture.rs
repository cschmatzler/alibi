use crate::TestSchema;
use axum::{body::Bytes, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use better_auth::{
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::{
        two_factor::{AccountLockoutConfig, SendTwoFactorOtp, TwoFactorConfig},
        EmailPasswordPlugin, SessionManagementPlugin, TwoFactorPlugin,
    },
    wire::UserView,
    AuthBuilder, AuthConfig, AuthResult, BetterAuth,
};
use better_auth_core::{
    store::{TwoFactorStore, VerificationStore},
    utils::json::{self, JsValue},
};
use better_auth_seaorm::{
    sea_orm::{ConnectionTrait, DatabaseBackend, Statement},
    DatabaseConnection, SeaOrmStore,
};
use chrono::{Duration, Utc};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
type Auth = Arc<BetterAuth<TestSchema>>;

struct RejectUserUpdate;
#[async_trait::async_trait]
impl better_auth_seaorm::SeaOrmHooks<TestSchema> for RejectUserUpdate {
    async fn before_update_user(
        &self,
        _id: &str,
        update: &mut better_auth_core::UpdateUser,
        _context: &better_auth_seaorm::SeaOrmHookContext<'_>,
    ) -> AuthResult<better_auth_seaorm::HookControl> {
        if update.two_factor_enabled == Some(true) {
            return Err(better_auth_core::AuthError::Upstream {
                status: 400,
                code: "USER_UPDATE_DENIED",
                message: "Configured user update denied",
            });
        }
        Ok(better_auth_seaorm::HookControl::Continue)
    }
}

struct RejectSessionCreate {
    cancel: bool,
    pending: bool,
}
#[async_trait::async_trait]
impl better_auth_seaorm::SeaOrmHooks<TestSchema> for RejectSessionCreate {
    async fn before_create_session(
        &self,
        _session: &mut better_auth_core::CreateSession,
        context: &better_auth_seaorm::SeaOrmHookContext<'_>,
    ) -> AuthResult<better_auth_seaorm::HookControl> {
        if context.request.as_ref().is_some_and(|request| {
            if self.pending {
                request.path.contains("/two-factor/verify-")
            } else {
                request.path.ends_with("/two-factor/enable")
            }
        }) {
            if self.cancel {
                return Ok(better_auth_seaorm::HookControl::Cancel);
            }
            return Err(better_auth_core::AuthError::forbidden(
                "session creation cancelled by database hook",
            ));
        }
        Ok(better_auth_seaorm::HookControl::Continue)
    }
}

#[derive(Clone, Default)]
struct Delivery(Arc<Mutex<HashMap<String, String>>>);
#[async_trait::async_trait]
impl SendTwoFactorOtp for Delivery {
    async fn send(&self, user: &UserView, otp: &str) -> AuthResult<()> {
        if let Some(email) = &user.email {
            self.0.lock().await.insert(email.clone(), otp.to_owned());
        }
        Ok(())
    }
}

pub(super) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router<Auth>> {
    let delivery = Delivery::default();
    let mut router = Router::new();
    for name in [
        "two-factor-lockout-fractional",
        "two-factor-lockout-zero",
        "two-factor-lockout-disabled",
        "two-factor-skip-verification",
        "two-factor-skip-user-hook",
        "two-factor-skip-session-cancel",
        "two-factor-skip-session-forbidden",
        "two-factor-pending-session-cancel",
        "two-factor-pending-session-forbidden",
        "two-factor-passwordless",
        "two-factor-passwordless-child-required",
        "two-factor-passwordless-child-optional",
    ] {
        let lockout = match name {
            "two-factor-lockout-fractional" => AccountLockoutConfig {
                max_failed_attempts: 2.5,
                duration_seconds: 600.25,
                ..Default::default()
            },
            "two-factor-lockout-zero" => AccountLockoutConfig {
                max_failed_attempts: 0.0,
                duration_seconds: 0.0,
                ..Default::default()
            },
            "two-factor-lockout-disabled" => AccountLockoutConfig {
                enabled: false,
                ..Default::default()
            },
            _ => AccountLockoutConfig::default(),
        };
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.app_name = "Fixture Auth".to_owned();
        let store = SeaOrmStore::<TestSchema>::new(config.clone(), database.clone());
        let store = if name == "two-factor-skip-user-hook" {
            store.with_hooks(vec![Arc::new(RejectUserUpdate)])
        } else if name.contains("-session-") {
            store.with_hooks(vec![Arc::new(RejectSessionCreate {
                cancel: name.ends_with("-cancel"),
                pending: name.starts_with("two-factor-pending-"),
            })])
        } else {
            store
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(store)
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(
                    EmailPasswordPlugin::new()
                        .enable_signup(true)
                        .enable_username(false),
                )
                .plugin(SessionManagementPlugin::new())
                .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                    allow_passwordless: matches!(
                        name,
                        "two-factor-passwordless" | "two-factor-passwordless-child-required"
                    ),
                    totp_allow_passwordless: match name {
                        "two-factor-passwordless-child-required" => Some(false),
                        "two-factor-passwordless-child-optional" => Some(true),
                        _ => None,
                    },
                    backup_allow_passwordless: match name {
                        "two-factor-passwordless-child-required" => Some(false),
                        "two-factor-passwordless-child-optional" => Some(true),
                        _ => None,
                    },
                    account_lockout: lockout,
                    skip_verification_on_enable: name.starts_with("two-factor-skip-")
                        || name.starts_with("two-factor-pending-"),
                    send_otp: Some(Arc::new(delivery.clone())),
                    ..Default::default()
                }))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let store = Arc::new(SeaOrmStore::<TestSchema>::new(
        base.clone(),
        database.clone(),
    ));
    Ok(router.route(
        "/__test/two-factor-policy",
        post(move |body: Bytes| control(body, store.clone(), database.clone(), delivery.clone())),
    ))
}

async fn control(
    body: Bytes,
    store: Arc<SeaOrmStore<TestSchema>>,
    database: DatabaseConnection,
    delivery: Delivery,
) -> axum::response::Response {
    let value = json::from_slice::<JsValue>(&body).ok();
    if let Some(email) = value
        .as_ref()
        .and_then(|value| value.get("deliveryEmail"))
        .and_then(JsValue::as_str)
    {
        return Json(
            delivery
                .0
                .lock()
                .await
                .get(email)
                .map(|otp| json!({"otp":otp})),
        )
        .into_response();
    }
    let Some(user_id) = value
        .as_ref()
        .and_then(|value| value.get("userId"))
        .and_then(JsValue::as_str)
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"message":"userId required"})),
        )
            .into_response();
    };
    let value = value.as_ref().unwrap();
    if value.get("pendingState").and_then(JsValue::as_bool) == Some(true) {
        let read=async {
        let key = if let Some(key) = value.get("pendingKey").and_then(JsValue::as_str) {
            Some(key.to_owned())
        } else {
            database.query_one_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,"SELECT identifier FROM verifications WHERE value=? AND identifier LIKE '2fa-%'",[user_id.into()])).await.map_err(|_|())?.map(|row|row.try_get::<String>("","identifier").map_err(|_|())).transpose()?
        };
        let (challenge, attempts, otp_exists) = if let Some(key) = key.as_ref() {
            let challenge = store
                .get_verification_by_identifier(key)
                .await
                .map_err(|_|())?
                .is_some();
            let attempts = store
                .get_verification_by_identifier(&format!("2fa-attempts-{key}"))
                .await
                .map_err(|_|())?
                .map(|row| row.value);
            let otp = store
                .get_verification_by_identifier(&format!("2fa-otp-{key}"))
                .await
                .map_err(|_|())?
                .is_some();
            (challenge, attempts, otp)
        } else {
            (false, None, false)
        };
        let trust_count=database.query_one_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,"SELECT count(*) AS n FROM verifications WHERE value=? AND identifier LIKE 'trust-device-%'",[user_id.into()])).await.map_err(|_|())?.ok_or(())?.try_get::<i64>("","n").map_err(|_|())?;
        Ok::<_,()>(json!({"key":key,"challenge":challenge,"attempts":attempts,"otpExists":otp_exists,"trustCount":trust_count}))
      }.await;
        return match read {
            Ok(value) => Json(value).into_response(),
            Err(()) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
    }
    if value
        .get("emptyCredentialPassword")
        .and_then(JsValue::as_bool)
        == Some(true)
        && database
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE accounts SET password='' WHERE user_id=? AND provider_id='credential'",
                [user_id.into()],
            ))
            .await
            .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if value.get("credentialState").and_then(JsValue::as_bool) == Some(true) {
        use better_auth_core::store::AccountStore;
        return match store.get_user_accounts(user_id).await {
            Ok(mut accounts) => {
                accounts.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
                Json(accounts.into_iter().map(|account|json!({"userId":account.user_id,"providerId":account.provider_id,"hasPassword":account.password.as_ref().is_some_and(|password|!password.is_empty())})).collect::<Vec<_>>()).into_response()
            }
            Err(error) => error.into_response(),
        };
    }
    if let Some(factor) = value.get("importFactor") {
        let (Some(secret), Some(backup_codes)) = (
            factor.get("secret").and_then(JsValue::as_str),
            factor.get("backupCodes").and_then(JsValue::as_str),
        ) else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message":"invalid factor import"})),
            )
                .into_response();
        };
        let imported = async {
            let row = store
                .get_two_factor_by_user_id(user_id)
                .await?
                .ok_or(better_auth::AuthError::SessionNotFound)?;
            store
                .update_two_factor(
                    &row.id,
                    better_auth_core::UpdateTwoFactor {
                        secret: Some(secret.into()),
                        backup_codes: Some(backup_codes.into()),
                        ..Default::default()
                    },
                )
                .await?;
            Ok::<_, better_auth::AuthError>(())
        }
        .await;
        if let Err(error) = imported {
            return error.into_response();
        }
    }
    let mutation = async {
        if let Some(count) = value.get("count") {
            let _ = database
                .execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE two_factor SET failed_verification_count=? WHERE user_id=?",
                    [count.as_f64().into(), user_id.into()],
                ))
                .await?;
        }
        if let Some(verified) = value.get("verified").and_then(JsValue::as_bool) {
            let _ = database
                .execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE two_factor SET verified=? WHERE user_id=?",
                    [verified.into(), user_id.into()],
                ))
                .await?;
        }
        if value.get("expireLock").and_then(JsValue::as_bool) == Some(true) {
            let _ = database
                .execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE two_factor SET locked_until=? WHERE user_id=?",
                    [(Utc::now() - Duration::seconds(1)).into(), user_id.into()],
                ))
                .await?;
        }
        Ok::<_, better_auth_seaorm::sea_orm::DbErr>(())
    }
    .await;
    if mutation.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    match store.get_two_factor_by_user_id(user_id).await {
        Ok(row) => Json(row.map(|row| json!({
            "id":row.id,"userId":row.user_id,"secret":row.secret,"backupCodes":row.backup_codes,
            "verified":row.verified,"failedVerificationCount":row.failed_verification_count,"lockedUntil":row.locked_until,
        }))).into_response(),
        Err(error) => error.into_response(),
    }
}
