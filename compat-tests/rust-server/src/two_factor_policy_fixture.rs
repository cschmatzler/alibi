use crate::TestSchema;
use axum::{body::Bytes, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use better_auth::{
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::{
        two_factor::{
            AccountLockoutConfig, SendTwoFactorOtp, TwoFactorBackupCipher, TwoFactorBackupStorage,
            TwoFactorConfig,
        },
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

#[derive(Clone, Default)]
pub(super) struct BackupReceipts(Arc<std::sync::Mutex<HashMap<String, Vec<serde_json::Value>>>>);
impl BackupReceipts {
    pub(super) fn reset(&self) {
        self.0.lock().unwrap().clear();
    }
    fn record(&self, profile: &str, phase: &str, input: &str) {
        self.0
            .lock()
            .unwrap()
            .entry(profile.into())
            .or_default()
            .push(json!({"phase":phase,"input":input}));
    }
}
struct BackupCipher {
    profile: String,
    receipts: BackupReceipts,
}
#[async_trait::async_trait]
impl TwoFactorBackupCipher for BackupCipher {
    async fn encrypt(&self, input: &str) -> AuthResult<String> {
        self.receipts.record(&self.profile, "encrypt", input);
        Ok(format!("backup-{input}"))
    }
    async fn decrypt(&self, input: &str) -> AuthResult<String> {
        self.receipts.record(&self.profile, "decrypt", input);
        Ok(input.strip_prefix("backup-").unwrap_or("").into())
    }
}
fn backup_config(name: &str, receipts: &BackupReceipts) -> TwoFactorConfig {
    let (amount, length, storage) = match name {
        "two-factor-backup-plain" => (2.5, 3.5, TwoFactorBackupStorage::Plain),
        "two-factor-backup-zero" => (0.0, 0.0, TwoFactorBackupStorage::Plain),
        "two-factor-backup-negative" => (-1.0, -2.0, TwoFactorBackupStorage::Plain),
        "two-factor-backup-invalid-length" => (2.0, 0.0, TwoFactorBackupStorage::Plain),
        "two-factor-backup-encrypted" => (3.0, 6.0, TwoFactorBackupStorage::Encrypted),
        "two-factor-backup-custom" => (
            10.0,
            10.0,
            TwoFactorBackupStorage::CustomCipher(Arc::new(BackupCipher {
                profile: name.into(),
                receipts: receipts.clone(),
            })),
        ),
        _ => (10.0, 10.0, TwoFactorBackupStorage::Encrypted),
    };
    let generator = if name == "two-factor-backup-custom" {
        let receipts = receipts.clone();
        let name = name.to_owned();
        Some(Arc::new(move || {
            let mut guard = receipts.0.lock().unwrap();
            let rows = guard.entry(name.clone()).or_default();
            rows.push(json!({"phase":"generate","input":""}));
            let count = rows
                .iter()
                .filter(|row| {
                    row.get("phase").and_then(serde_json::Value::as_str) == Some("generate")
                })
                .count();
            Ok(vec![
                format!("same-{count}"),
                format!("same-{count}"),
                format!("other-{count}"),
            ])
        })
            as Arc<dyn Fn() -> AuthResult<Vec<String>> + Send + Sync>)
    } else {
        None
    };
    TwoFactorConfig {
        backup_code_amount: amount,
        backup_code_length: length,
        backup_storage: storage,
        custom_backup_codes_generate: generator,
        ..Default::default()
    }
}

pub(super) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
    backup_receipts: BackupReceipts,
) -> AuthResult<Router<Auth>> {
    let delivery = Delivery::default();
    let mut backup_configs = HashMap::new();
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
        "two-factor-backup-plain",
        "two-factor-backup-zero",
        "two-factor-backup-negative",
        "two-factor-backup-encrypted",
        "two-factor-backup-invalid-length",
        "two-factor-backup-custom",
        "two-factor-trust-fractional",
        "two-factor-trust-zero-challenge",
        "two-factor-trust-negative-challenge",
        "two-factor-trust-zero",
        "two-factor-trust-negative",
        "two-factor-trust-cleanup-disabled",
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
        let backup = backup_config(name, &backup_receipts);
        backup_configs.insert(name.to_owned(), backup.clone());
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.app_name = "Fixture Auth".to_owned();
        if name == "two-factor-trust-cleanup-disabled" {
            config.verification.disable_cleanup = true;
        }
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
                    two_factor_cookie_max_age: match name {
                        "two-factor-trust-zero-challenge" => 0.0,
                        "two-factor-trust-negative-challenge" => -0.25,
                        name if name.starts_with("two-factor-trust-") => 600.75,
                        _ => TwoFactorConfig::default().two_factor_cookie_max_age,
                    },
                    trust_device_max_age: match name {
                        "two-factor-trust-zero" => 0.0,
                        "two-factor-trust-negative" => -0.25,
                        name if name.starts_with("two-factor-trust-") => 1200.875,
                        _ => TwoFactorConfig::default().trust_device_max_age,
                    },
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
                        || name.starts_with("two-factor-pending-")
                        || name.starts_with("two-factor-backup-")
                        || name.starts_with("two-factor-trust-"),
                    send_otp: Some(Arc::new(delivery.clone())),
                    ..backup
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
    let backup_configs = Arc::new(backup_configs);
    let control_config = Arc::new(base.clone());
    Ok(router.route(
        "/__test/two-factor-policy",
        post(move |body: Bytes| {
            control(
                body,
                store.clone(),
                database.clone(),
                delivery.clone(),
                backup_configs.clone(),
                backup_receipts.clone(),
                control_config.clone(),
            )
        }),
    ))
}

async fn control(
    body: Bytes,
    store: Arc<SeaOrmStore<TestSchema>>,
    database: DatabaseConnection,
    delivery: Delivery,
    backup_configs: Arc<HashMap<String, TwoFactorConfig>>,
    backup_receipts: BackupReceipts,
    config: Arc<AuthConfig>,
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
    if value.get("viewBackupCodes").and_then(JsValue::as_bool) == Some(true) {
        let Some(profile) = value.get("backupProfile").and_then(JsValue::as_str) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        let Some(options) = backup_configs.get(profile) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        let ctx = better_auth_core::AuthContext::new(config, store);
        return match TwoFactorPlugin::with_config(options.clone())
            .view_backup_codes(user_id, &ctx)
            .await
        {
            Ok(codes) => {
                let receipts = backup_receipts
                    .0
                    .lock()
                    .unwrap()
                    .get(profile)
                    .cloned()
                    .unwrap_or_default();
                Json(json!({"status":true,"backupCodes":codes,"receipts":receipts})).into_response()
            }
            Err(error) => error.into_response(),
        };
    }
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
