//! Application-owned authentication callbacks and callback-time persisted state.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{Json, Router, routing::get};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{
    EmailPasswordPlugin, PasskeyAuthenticationAfterVerification, PasskeyAuthenticationConfig,
    PasskeyAuthenticationContext, PasskeyPlugin, SessionManagementPlugin,
    VerifiedPasskeyAuthentication,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::{AuthPasskey, store::PasskeyStore, utils::json::JsValue, wire::PasskeyView};
use better_auth_seaorm::{
    DatabaseConnection, SeaOrmStore,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

pub(crate) type Events = Arc<Mutex<Vec<Value>>>;
fn database_error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(error.to_string())
}
struct Application {
    mode: &'static str,
    store: Arc<SeaOrmStore<TestSchema>>,
    database: DatabaseConnection,
    events: Events,
}
#[async_trait]
impl PasskeyAuthenticationAfterVerification for Application {
    async fn after_verification(
        &self,
        context: &PasskeyAuthenticationContext<'_>,
        verification: &VerifiedPasskeyAuthentication,
        client_data: &JsValue,
    ) -> AuthResult<()> {
        let credential_id = URL_SAFE_NO_PAD.encode(verification.result.cred_id().as_ref());
        let row = self
            .store
            .get_passkey_by_credential_id(&credential_id)
            .await?
            .ok_or_else(|| AuthError::internal("Actual verified stored credential required"))?;
        let sessions = self
            .database
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT COUNT(*) AS count FROM sessions WHERE user_id = ?",
                [row.user_id().into_owned().into()],
            ))
            .await
            .map_err(database_error)?
            .ok_or_else(|| AuthError::internal("Session count required"))?;
        let challenges = self
            .database
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT COUNT(*) AS count FROM verifications",
            ))
            .await
            .map_err(database_error)?
            .ok_or_else(|| AuthError::internal("Challenge count required"))?;
        self.events.lock().unwrap().push(json!({
            "profile":format!("passkey-auth-{}",self.mode), "path":context.request.path,
            "facts":{"newCounter":verification.result.counter(),"credentialID":credential_id,
                "userVerified":verification.result.user_verified(),
                "credentialDeviceType":if verification.result.backup_eligible(){"multiDevice"}else{"singleDevice"},
                "credentialBackedUp":verification.result.backup_state(),"origin":verification.origin,"rpID":verification.rp_id},
            "clientData":client_data.to_json_value()?, "storedPasskey":PasskeyView::from(&row),
            "sessions":{"count":sessions.try_get::<i64>("","count").map_err(database_error)?},
            "challenges":{"count":challenges.try_get::<i64>("","count").map_err(database_error)?}
        }));
        if matches!(self.mode, "deletion" | "failed-deletion") {
            if self.mode == "failed-deletion" {
                self.database.execute_raw(Statement::from_string(DbBackend::Sqlite,
                    "CREATE TEMP TRIGGER reject_callback_delete BEFORE DELETE ON passkeys BEGIN SELECT RAISE(ABORT, 'Application deletion failed'); END"))
                    .await.map_err(database_error)?;
            }
            let deleted = self.store.delete_passkey(row.id().as_ref()).await;
            if self.mode == "failed-deletion" {
                self.database
                    .execute_raw(Statement::from_string(
                        DbBackend::Sqlite,
                        "DROP TRIGGER reject_callback_delete",
                    ))
                    .await
                    .map_err(database_error)?;
            }
            deleted?;
            if self
                .store
                .get_passkey_by_id(row.id().as_ref())
                .await?
                .is_some()
            {
                return Err(AuthError::internal("Verified credential deletion required"));
            }
        }
        if self.mode == "mutation" {
            let foreign = self
                .database
                .query_one_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "SELECT id FROM users WHERE name = 'Foreign'",
                ))
                .await
                .map_err(database_error)?
                .ok_or_else(|| AuthError::internal("Actual foreign application user required"))?;
            let foreign_id = foreign
                .try_get::<String>("", "id")
                .map_err(database_error)?;
            self.database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
                "UPDATE passkeys SET user_id = ?, backed_up = 1, device_type = 'application-updated', name = 'Application updated' WHERE id = ?",
                [foreign_id.into(), row.id().into_owned().into()])).await.map_err(database_error)?;
        }
        match self.mode {
            "forbidden" => Err(AuthError::Api {
                status: 403,
                code: Some("PASSKEY_APPLICATION_DENIED".into()),
                message: "Application denied this verified authentication".into(),
            }),
            "public-error" => Err(AuthError::Api {
                status: 500,
                code: Some("PASSKEY_APPLICATION_ERROR".into()),
                message: "Application authentication service failed".into(),
            }),
            "internal-error" => Err(AuthError::internal("Private application failure")),
            _ => Ok(()),
        }
    }
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    events: Events,
) -> AuthResult<Router> {
    let mut router = Router::new();
    for mode in [
        "accept",
        "forbidden",
        "public-error",
        "internal-error",
        "mutation",
        "deletion",
        "failed-deletion",
    ] {
        let path = format!("/__test/profiles/passkey-auth-{mode}/api/auth");
        let configured = config.clone().base_path(&path);
        let store = Arc::new(SeaOrmStore::<TestSchema>::new(
            configured.clone(),
            database.clone(),
        ));
        let application = Arc::new(Application {
            mode,
            store: store.clone(),
            database: database.clone(),
            events: events.clone(),
        });
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(configured)
                .store_arc(store)
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(
                    PasskeyPlugin::new().authentication(PasskeyAuthenticationConfig {
                        after_verification: Some(application),
                    }),
                )
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router.route(
        "/__test/passkey-authentication-events",
        get(move || {
            let events = events.clone();
            async move { Json(events.lock().unwrap().clone()) }
        }),
    ))
}
