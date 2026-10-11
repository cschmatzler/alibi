//! Application session columns exercise each adapter's public derive and actual
//! HTTP field policy, independent physical persistence and cache publication.
#![allow(
    unreachable_pub,
    reason = "SeaORM entity associated types must be public"
)]
use super::super::{SeaOrm, Sqlx};
use super::*;
use alibi::config::CookieCacheConfig;
use alibi::field_policy::FieldConfig;
use alibi::utils::json::JsValue;
use chrono::{DateTime, Utc};

mod sqlx_model {
    use super::*;
    #[derive(alibi::sqlx::AuthEntity, Clone, Debug, serde::Serialize, sqlx::FromRow)]
    #[auth(role = "session", table = "sessions", secondary_storage)]
    pub struct Model {
        pub id: String,
        pub user_id: String,
        pub token: String,
        pub expires_at: DateTime<Utc>,
        pub created_at: DateTime<Utc>,
        pub updated_at: DateTime<Utc>,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub active: bool,
        pub label: Option<String>,
        pub hidden: Option<String>,
        pub transformed: Option<String>,
        pub validated: Option<String>,
        pub async_checked: Option<String>,
        pub adapter_value: Option<String>,
        pub payload: Option<alibi::sqlx::JsonMetadata>,
        pub fraction: Option<f64>,
        pub narrow: Option<f32>,
        pub flag: Option<bool>,
    }
    pub(super) struct Schema;
    impl AuthSchema for Schema {
        type User = <<Sqlx as Backend>::Schema as AuthSchema>::User;
        type Session = Model;
        type Account = <<Sqlx as Backend>::Schema as AuthSchema>::Account;
        type Verification = <<Sqlx as Backend>::Schema as AuthSchema>::Verification;
    }
}
mod seaorm_model {
    use super::*;
    use alibi::seaorm::sea_orm::{self, entity::prelude::*};
    use chrono::DateTime;
    #[derive(alibi::seaorm::AuthEntity, Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[auth(role = "session", secondary_storage)]
    #[sea_orm(table_name = "sessions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub user_id: String,
        pub token: String,
        pub expires_at: DateTime<Utc>,
        pub created_at: DateTime<Utc>,
        pub updated_at: DateTime<Utc>,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub active: bool,
        pub label: Option<String>,
        pub hidden: Option<String>,
        pub transformed: Option<String>,
        pub validated: Option<String>,
        pub async_checked: Option<String>,
        pub adapter_value: Option<String>,
        pub payload: Option<alibi::seaorm::JsonMetadata>,
        pub fraction: Option<f64>,
        pub narrow: Option<f32>,
        pub flag: Option<bool>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
    pub(super) struct Schema;
    impl AuthSchema for Schema {
        type User = <<SeaOrm as Backend>::Schema as AuthSchema>::User;
        type Session = Model;
        type Account = <<SeaOrm as Backend>::Schema as AuthSchema>::Account;
        type Verification = <<SeaOrm as Backend>::Schema as AuthSchema>::Verification;
    }
}
type AsyncObservation = Arc<(
    std::sync::atomic::AtomicUsize,
    std::sync::atomic::AtomicUsize,
)>;
fn config() -> (AuthConfig, AsyncObservation) {
    let asynchronous = Arc::new((
        std::sync::atomic::AtomicUsize::new(0),
        std::sync::atomic::AtomicUsize::new(0),
    ));
    let observed = asynchronous.clone();
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: true,
        ..Default::default()
    });
    config.session.additional_fields.extend([
        (
            "label".into(),
            FieldConfig::new(json!({"type":"string"}))
                .default_value(json!("initial"))
                .on_update(|| JsValue::String("application-update-default".into()))
                .transform_output(|value| async move {
                    if value.as_ref().and_then(JsValue::as_str) == Some("throw") {
                        return Err(alibi::AuthError::internal("application output failed"));
                    }
                    Ok(value)
                })
                .validate_output(|_| panic!("Output validator metadata must not execute")),
        ),
        (
            "hidden".into(),
            FieldConfig::new(json!({"type":"string"}))
                .default_value(json!("server-secret"))
                .read_only()
                .hidden(),
        ),
        (
            "validated".into(),
            FieldConfig::new(json!({"type":"string"})).validate(|value| {
                if value.as_str() == Some("admitted") {
                    Ok(value.clone())
                } else {
                    Err("application rejects this label".into())
                }
            }),
        ),
        (
            "transformed".into(),
            FieldConfig::new(json!({"type":"string"})).transform(|value| {
                let Some(value) = value else { return Ok(None) };
                if value.as_str() == Some("reject") {
                    return Err(alibi::AuthError::internal("private transform failure"));
                }
                if value.as_str() == Some("reject-at-binding") {
                    return Ok(Some(JsValue::String("reject".into())));
                }
                Ok(Some(JsValue::String(format!(
                    "stored:{}",
                    value.as_str().unwrap()
                ))))
            }),
        ),
        (
            "adapterValue".into(),
            FieldConfig::new(json!({"type":"string"})).transform_adapter_input(
                |value| async move {
                    let Some(value) = value else { return Ok(None) };
                    let value = value.as_str().unwrap();
                    if value.ends_with("adapter-reject") {
                        return Err(alibi::AuthError::internal("adapter callback veto"));
                    }
                    tokio::task::yield_now().await;
                    Ok(Some(JsValue::String(format!("adapter:{value}"))))
                },
            ),
        ),
        (
            "asyncChecked".into(),
            FieldConfig::new(json!({"type":"string"})).validate_async(move |value| {
                let _ = observed.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let observed = observed.clone();
                async move {
                    let _ = observed.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(value)
                }
            }),
        ),
    ]);
    for (name, kind) in [
        ("payload", "json"),
        ("fraction", "number"),
        ("narrow", "number"),
        ("flag", "boolean"),
    ] {
        drop(
            config
                .session
                .additional_fields
                .insert(name.into(), FieldConfig::new(json!({"type":kind}))),
        );
    }
    (config, asynchronous)
}
async fn columns(db: &Db) -> TestResult {
    for (column, kind) in [
        ("payload", if db.is_postgres() { "JSONB" } else { "TEXT" }),
        ("fraction", "DOUBLE PRECISION"),
        ("narrow", "REAL"),
        ("flag", "BOOLEAN"),
    ] {
        let _ = db
            .execute(
                &format!("ALTER TABLE sessions ADD COLUMN {column} {kind}"),
                &[],
            )
            .await?;
    }
    for column in [
        "label",
        "hidden",
        "transformed",
        "validated",
        "async_checked",
        "adapter_value",
    ] {
        let _ = db
            .execute(
                &format!("ALTER TABLE sessions ADD COLUMN {column} TEXT"),
                &[],
            )
            .await?;
    }
    Ok(())
}
async fn sqlx_case(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<Sqlx>(SECRET).await?;
    columns(&db).await?;
    let (config, asynchronous) = config();
    let auth = AuthBuilder::new(config.clone())
        .store(alibi::sqlx::SqlxStore::<sqlx_model::Schema>::new(
            config,
            connection.clone(),
        ))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    exercise(auth, &db, asynchronous).await?;
    Sqlx::close(connection).await
}
async fn seaorm_case(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<SeaOrm>(SECRET).await?;
    columns(&db).await?;
    let (config, asynchronous) = config();
    let auth = AuthBuilder::new(config.clone())
        .store(alibi::seaorm::SeaOrmStore::<seaorm_model::Schema>::new(
            config,
            connection.clone(),
        ))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    exercise(auth, &db, asynchronous).await?;
    SeaOrm::close(connection).await
}
#[tokio::test]
async fn custom_session_fields_sqlx_sqlite() -> TestResult {
    sqlx_case(Db::sqlite().await?).await
}
#[tokio::test]
async fn custom_session_fields_seaorm_sqlite() -> TestResult {
    seaorm_case(Db::sqlite().await?).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn custom_session_fields_sqlx_postgres() -> TestResult {
    sqlx_case(Db::postgres().await?).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn custom_session_fields_seaorm_postgres() -> TestResult {
    seaorm_case(Db::postgres().await?).await
}

async fn exercise<S: AuthSchema>(
    auth: Alibi<S>,
    db: &Db,
    asynchronous: AsyncObservation,
) -> TestResult {
    let owner = signup(&auth, "session-fields@example.test").await;
    let foreign = signup(&auth, "session-foreign@example.test").await;
    let token = body(&owner)["token"].as_str().unwrap().to_owned();
    let foreign_token = body(&foreign)["token"].as_str().unwrap().to_owned();
    let cookie = cookies(&owner);
    assert_eq!(
        db.text("SELECT label FROM sessions WHERE token=$1", &[&token])
            .await?
            .as_deref(),
        Some("initial")
    );
    // Generated bindings must preserve rich values through the actual adapter,
    // wire projection, and independent physical column reads on both engines.
    for (payload, number, flag) in [
        (
            json!({"__proto__":{"retained":true},"nested":[1,"two"]}),
            json!(7),
            json!(true),
        ),
        (json!([false, 3]), json!(1.25), json!(false)),
        (json!("scalar"), json!(2), json!(true)),
        (json!(true), json!(2.5), json!(false)),
        (json!(17), json!(3), json!(true)),
        (json!(1.5), json!(3.5), json!(false)),
        (Value::Null, Value::Null, Value::Null),
    ] {
        let updated = Box::pin(auth.handle_request(request(
            "/update-session",
            Some(json!({"payload":payload,"fraction":number,"narrow":number,"flag":flag})),
            &cookie,
        )))
        .await?;
        assert_eq!(
            updated.status,
            200,
            "payload={payload}, number={number}, flag={flag}: {}",
            body(&updated)
        );
        let session = &body(&updated)["session"];
        assert_eq!(session["payload"], payload);
        assert_eq!(session["fraction"].as_f64(), number.as_f64());
        assert_eq!(session["narrow"].as_f64(), number.as_f64());
        assert_eq!(session["flag"], flag);
        let physical = db
            .text(
                "SELECT CAST(payload AS TEXT) FROM sessions WHERE token=$1",
                &[&token],
            )
            .await?;
        assert_eq!(
            physical
                .map(|v| serde_json::from_str::<Value>(&v).unwrap())
                .unwrap_or(Value::Null),
            payload
        );
        for column in ["fraction", "narrow"] {
            let physical = db
                .text(
                    &format!("SELECT CAST({column} AS TEXT) FROM sessions WHERE token=$1"),
                    &[&token],
                )
                .await?;
            assert_eq!(physical.map(|v| v.parse::<f64>().unwrap()), number.as_f64());
        }
        let physical = db
            .text(
                "SELECT CAST(flag AS TEXT) FROM sessions WHERE token=$1",
                &[&token],
            )
            .await?;
        assert_eq!(
            physical.as_deref(),
            flag.as_bool().map(|v| if db.is_postgres() {
                if v { "true" } else { "false" }
            } else if v {
                "1"
            } else {
                "0"
            })
        );
        let foreign = db
            .text(
                "SELECT CAST(payload AS TEXT) FROM sessions WHERE token=$1",
                &[&foreign_token],
            )
            .await?;
        assert!(foreign.is_none());
    }
    // A structured value cannot bind to TEXT; failed binding is atomic.
    let before = db.table("sessions").await?;
    let _ = call(
        &auth,
        request(
            "/update-session",
            Some(json!({"label":{"invalid":"object"},"fraction":99})),
            &cookie,
        ),
        500,
    )
    .await;
    assert_eq!(db.table("sessions").await?, before);
    let original = db.table("sessions").await?;
    for (input, status) in [
        (json!({}), 400),
        (json!({"unknown":"value"}), 400),
        (json!({"hidden":"client-secret"}), 400),
        (json!({"validated":"denied","label":"must-not-save"}), 400),
        (json!({"transformed":"reject","label":"must-not-save"}), 500),
        (
            json!({"adapterValue":"adapter-reject","label":"must-not-save"}),
            500,
        ),
        (
            json!({"asyncChecked":"unpolled","label":"must-not-save"}),
            500,
        ),
        (
            json!({"transformed":"reject-at-binding","label":"must-not-save"}),
            500,
        ),
    ] {
        let denied = call(
            &auth,
            request("/update-session", Some(input), &cookie),
            status,
        )
        .await;
        assert!(!cookies(&denied).contains("session_data="));
        assert_eq!(db.table("sessions").await?, original);
    }
    let _ = call(
        &auth,
        request(
            "/update-session",
            Some(json!({"label":"unauthenticated"})),
            "",
        ),
        401,
    )
    .await;
    assert_eq!(db.table("sessions").await?, original);
    for (mode, preference, temporary) in [
        ("persistent", String::new(), false),
        (
            "forged",
            "; better-auth.dont_remember=true.forged".into(),
            false,
        ),
        (
            "temporary",
            format!(
                "; better-auth.dont_remember={}",
                alibi::utils::cookie_utils::sign_cookie_value("true", SECRET)
            ),
            true,
        ),
    ] {
        let updated = call(&auth,request("/update-session",Some(json!({"label":mode,"validated":"admitted","transformed":mode,"token":foreign_token,"userId":body(&foreign)["user"]["id"]})),&format!("{cookie}{preference}")),200).await;
        let projection = body(&updated);
        assert_eq!(projection["session"]["label"], mode);
        assert_eq!(
            projection["session"]["transformed"],
            format!("stored:stored:{mode}")
        );
        assert_eq!(projection["session"]["validated"], "admitted");
        assert_eq!(projection["session"]["token"], token);
        assert_eq!(projection["session"]["userId"], body(&owner)["user"]["id"]);
        assert!(projection["session"].get("hidden").is_none());
        assert_eq!(
            db.text("SELECT label FROM sessions WHERE token=$1", &[&token])
                .await?
                .as_deref(),
            Some(mode)
        );
        assert_eq!(
            db.text("SELECT transformed FROM sessions WHERE token=$1", &[&token])
                .await?,
            Some(format!("stored:stored:{mode}"))
        );
        assert_eq!(
            db.text("SELECT hidden FROM sessions WHERE token=$1", &[&token])
                .await?
                .as_deref(),
            Some("server-secret")
        );
        assert_eq!(
            db.text(
                "SELECT label FROM sessions WHERE token=$1",
                &[&foreign_token]
            )
            .await?
            .as_deref(),
            Some("initial")
        );
        let session_cookie = updated
            .headers
            .get_all("set-cookie")
            .find(|h| h.starts_with("better-auth.session_token="))
            .unwrap();
        assert_eq!(!session_cookie.contains("Max-Age="), temporary);
        assert!(cookies(&updated).contains("session_data="));
        // Change physical projection after issuance so a subsequent response
        // must actually come from the newly published signed cookie cache.
        let _ = db
            .execute(
                "UPDATE sessions SET label='physical-sentinel' WHERE token=$1",
                &[&token],
            )
            .await?;
        let cached = call(
            &auth,
            request("/get-session", None, &cookies(&updated)),
            200,
        )
        .await;
        assert_eq!(body(&cached)["session"]["label"], mode);
        assert_eq!(
            body(&cached)["user"]["email"],
            "session-fields@example.test"
        );
        let _ = db
            .execute(
                "UPDATE sessions SET label=$1 WHERE token=$2",
                &[mode, &token],
            )
            .await?;
    }
    assert_eq!(asynchronous.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(asynchronous.1.load(std::sync::atomic::Ordering::SeqCst), 0);
    let updated = call(
        &auth,
        request(
            "/update-session",
            Some(json!({"validated":"admitted","adapterValue":"accepted"})),
            &cookie,
        ),
        200,
    )
    .await;
    assert_eq!(
        body(&updated)["session"]["adapterValue"],
        "adapter:accepted"
    );
    assert_eq!(
        db.text(
            "SELECT adapter_value FROM sessions WHERE token=$1",
            &[&token]
        )
        .await?
        .as_deref(),
        Some("adapter:accepted")
    );
    assert_eq!(
        body(&updated)["session"]["label"],
        "application-update-default"
    );
    assert_eq!(
        db.text("SELECT label FROM sessions WHERE token=$1", &[&token])
            .await?
            .as_deref(),
        Some("application-update-default")
    );
    let _ = db.execute("UPDATE sessions SET label='physical-sentinel', adapter_value='physical-sentinel' WHERE token=$1", &[&token]).await?;
    let cached = call(
        &auth,
        request("/get-session", None, &cookies(&updated)),
        200,
    )
    .await;
    assert_eq!(body(&cached)["session"]["adapterValue"], "adapter:accepted");
    assert_eq!(
        body(&cached)["session"]["label"],
        "application-update-default"
    );
    Ok(())
}

struct SessionHooks {
    before: Arc<std::sync::atomic::AtomicUsize>,
    after: Arc<std::sync::atomic::AtomicUsize>,
}
#[async_trait::async_trait]
impl<S: AuthSchema, H: alibi::store::HookBackend> alibi::store::DatabaseHooks<S, H>
    for SessionHooks
{
    async fn before_update_session(
        &self,
        _: &str,
        fields: &mut alibi::field_policy::FieldValues,
        _: &alibi::store::DatabaseHookContext<'_, H>,
    ) -> alibi::AuthResult<alibi::store::HookControl> {
        let _ = self
            .before
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(
            if fields.get("label").and_then(JsValue::as_str) == Some("cancel") {
                alibi::store::HookControl::Cancel
            } else {
                alibi::store::HookControl::Continue
            },
        )
    }
    async fn after_update_session(
        &self,
        _: &S::Session,
        _: &alibi::store::DatabaseHookContext<'_, H>,
    ) -> alibi::AuthResult<()> {
        let _ = self.after.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

fn secondary_config() -> AuthConfig {
    let (mut config, _) = config();
    config.session.secondary_storage = Some(Arc::new(alibi::store::MemoryCacheAdapter::new()));
    config.session.store_in_database = false;
    config.session.cookie_cache = None;
    config
}

async fn secondary_exercise<S: AuthSchema>(
    auth: Alibi<S>,
    db: &Db,
    hooks: &SessionHooks,
) -> TestResult {
    use std::sync::atomic::Ordering::SeqCst;
    let owner = signup(&auth, "secondary-fields@example.test").await;
    assert_eq!(db.count("sessions").await?, 0);
    let cookie = cookies(&owner);
    let updated = call(
        &auth,
        request("/update-session", Some(json!({"label":"changed"})), &cookie),
        200,
    )
    .await;
    assert_eq!(body(&updated)["session"]["label"], "changed");
    assert_eq!(
        (hooks.before.load(SeqCst), hooks.after.load(SeqCst)),
        (1, 1)
    );
    let read = call(&auth, request("/get-session", None, &cookie), 200).await;
    assert_eq!(body(&read)["session"]["label"], "changed");
    let cancelled = Box::pin(auth.handle_request(request(
        "/update-session",
        Some(json!({"label":"cancel"})),
        &cookie,
    )))
    .await?;
    assert_ne!(
        cancelled.status,
        200,
        "{}",
        String::from_utf8_lossy(&cancelled.body)
    );
    assert_eq!(
        (hooks.before.load(SeqCst), hooks.after.load(SeqCst)),
        (2, 1)
    );
    let read = call(&auth, request("/get-session", None, &cookie), 200).await;
    assert_eq!(body(&read)["session"]["label"], "changed");
    Ok(())
}

#[tokio::test]
async fn secondary_sessions_run_update_hooks_sqlx_sqlite() -> TestResult {
    let db = Db::sqlite().await?;
    let (connection, _) = db.migrated::<Sqlx>(SECRET).await?;
    columns(&db).await?;
    let config = secondary_config();
    let hooks = SessionHooks {
        before: Arc::default(),
        after: Arc::default(),
    };
    let observed = SessionHooks {
        before: hooks.before.clone(),
        after: hooks.after.clone(),
    };
    let auth = AuthBuilder::new(config.clone())
        .store(
            alibi::sqlx::SqlxStore::<sqlx_model::Schema>::new(config, connection.clone())
                .hook(observed),
        )
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    secondary_exercise(auth, &db, &hooks).await?;
    Sqlx::close(connection).await
}

#[tokio::test]
async fn secondary_sessions_run_update_hooks_seaorm_sqlite() -> TestResult {
    let db = Db::sqlite().await?;
    let (connection, _) = db.migrated::<SeaOrm>(SECRET).await?;
    columns(&db).await?;
    let config = secondary_config();
    let hooks = SessionHooks {
        before: Arc::default(),
        after: Arc::default(),
    };
    let observed = SessionHooks {
        before: hooks.before.clone(),
        after: hooks.after.clone(),
    };
    let auth = AuthBuilder::new(config.clone())
        .store(
            alibi::seaorm::SeaOrmStore::<seaorm_model::Schema>::new(config, connection.clone())
                .hook(observed),
        )
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    secondary_exercise(auth, &db, &hooks).await?;
    SeaOrm::close(connection).await
}

// Compat owner: core/session/update-projection.test.ts, configured update
// ordinary-error and api-error callbacks. Store-level hook tests cannot prove
// HTTP error framing or prevent session cookie publication after rejection.
#[derive(Clone, Default)]
struct RejectSessionUpdate {
    receipts: Arc<Mutex<Vec<(String, String, String)>>>,
    after: Arc<std::sync::atomic::AtomicUsize>,
    after_records: Arc<Mutex<Vec<Value>>>,
    renewal_command: Arc<Mutex<Option<(String, String)>>>,
    renewal_inputs: Arc<Mutex<Vec<Value>>>,
    projected_updates: Arc<Mutex<Vec<Value>>>,
}
#[async_trait::async_trait]
impl<S: AuthSchema> alibi::store::AdapterAfterHook<S> for RejectSessionUpdate {
    async fn after_write(
        &self,
        event: &alibi::store::AdapterEvent<S>,
        _: &dyn alibi::store::AuthStore<S>,
    ) -> alibi::AuthResult<()> {
        if let alibi::store::AdapterEvent::SessionUpdated(record) = event {
            self.projected_updates
                .lock()
                .unwrap()
                .push(json!(record.raw_snapshot().values()));
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema> alibi::AuthPlugin<S> for RejectSessionUpdate {
    fn name(&self) -> &'static str {
        "session-projection-observer"
    }
    fn routes(&self) -> Vec<alibi::AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &alibi::AuthContext<S>,
    ) -> alibi::AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn on_init(&self, context: &mut alibi::AuthInitContext<S>) -> alibi::AuthResult<()> {
        context.register_adapter_after_hook(Arc::new(self.clone()));
        Ok(())
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema, H: alibi::store::HookBackend> alibi::store::DatabaseHooks<S, H>
    for RejectSessionUpdate
{
    async fn before_update_session(
        &self,
        token: &str,
        fields: &mut alibi::field_policy::FieldValues,
        context: &alibi::store::DatabaseHookContext<'_, H>,
    ) -> alibi::AuthResult<alibi::store::HookControl> {
        let renewal = self.renewal_command.lock().unwrap().clone();
        let label = if let Some((owner, command)) = renewal.filter(|(owner, _)| owner == token) {
            assert_eq!(owner, token);
            assert!(
                fields.is_empty(),
                "expiry renewal enters the hook with no configured input fields"
            );
            self.renewal_inputs
                .lock()
                .unwrap()
                .push(serde_json::to_value(&*fields)?);
            command
        } else {
            fields
                .get("label")
                .and_then(JsValue::as_str)
                .unwrap()
                .to_owned()
        };
        let label = label.as_str();
        let request = context
            .request
            .as_ref()
            .expect("HTTP application callback context");
        self.receipts.lock().unwrap().push((
            token.to_owned(),
            label.to_owned(),
            request.path.clone(),
        ));
        match label {
            "after-error" if fields.is_empty() => {
                let _ = fields.insert("label".into(), JsValue::String("after-error".into()));
                Ok(alibi::store::HookControl::Continue)
            }
            "renewal-cancel" => Ok(alibi::store::HookControl::Cancel),
            "mutate" => {
                let _ = fields.insert("label".into(), JsValue::String("hook-updated".into()));
                Ok(alibi::store::HookControl::Continue)
            }
            "cancel" => Ok(alibi::store::HookControl::Cancel),
            "ordinary-error" => Err(alibi::AuthError::internal("application before failed")),
            "api-error" => Err(alibi::AuthError::Api {
                status: 403,
                code: Some("APP_DENIED".into()),
                message: "Application denied".into(),
            }),
            _ => Ok(alibi::store::HookControl::Continue),
        }
    }
    async fn after_update_session(
        &self,
        session: &S::Session,
        context: &alibi::store::DatabaseHookContext<'_, H>,
    ) -> alibi::AuthResult<()> {
        let _ = self.after.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let record = serde_json::to_value(session)?;
        let request = context
            .request
            .as_ref()
            .expect("HTTP application callback context");
        self.after_records.lock().unwrap().push(json!({
            "record":record,
            "path":request.path
        }));
        if record["label"] == "after-error" {
            return Err(alibi::AuthError::internal("application after failed"));
        }
        Ok(())
    }
}

async fn rejected_session_update<S: AuthSchema>(
    auth: Alibi<S>,
    db: &Db,
    hooks: &RejectSessionUpdate,
) -> TestResult {
    let owner = signup(&auth, "rejected-session-owner@example.test").await;
    let sibling = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"rejected-session-owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let foreign = signup(&auth, "rejected-session-foreign@example.test").await;
    let token = body(&owner)["token"].as_str().unwrap().to_owned();
    let cookie = cookies(&owner);
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for (label, status) in [("ordinary-error", 500), ("api-error", 403)] {
        hooks.receipts.lock().unwrap().clear();
        let denied = call(
            &auth,
            request("/update-session", Some(json!({"label":label})), &cookie),
            status,
        )
        .await;
        if label == "ordinary-error" {
            assert!(denied.body.is_empty());
        } else {
            assert_eq!(
                body(&denied),
                json!({"code":"APP_DENIED","message":"Application denied"})
            );
        }
        assert!(denied.headers.get_all("set-cookie").next().is_none());
        assert_eq!(
            *hooks.receipts.lock().unwrap(),
            [(
                token.clone(),
                label.to_owned(),
                "/api/auth/update-session".to_owned()
            )]
        );
        assert_eq!(hooks.after.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
        for established in [&owner, &sibling, &foreign] {
            let read = call(
                &auth,
                request("/get-session", None, &cookies(established)),
                200,
            )
            .await;
            assert_eq!(body(&read)["session"]["token"], body(established)["token"]);
            assert_eq!(body(&read)["user"]["id"], body(established)["user"]["id"]);
        }
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
    }
    // Admit the same authenticated route after the rejected attempts to prove
    // the configured physical field and surviving cookie still authorize writes.
    let accepted = call(
        &auth,
        request(
            "/update-session",
            Some(json!({"label":"accepted"})),
            &cookie,
        ),
        200,
    )
    .await;
    assert_eq!(body(&accepted)["session"]["token"], token);
    assert_eq!(body(&accepted)["session"]["label"], "accepted");
    assert_eq!(
        db.text("SELECT label FROM sessions WHERE token=$1", &[&token])
            .await?
            .as_deref(),
        Some("accepted")
    );
    assert_eq!(hooks.after.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Compat owner: core/session/update-projection.test.ts configured update
    // after-error. A postcommit callback failure must not roll back the row or
    // publish a successful replacement cookie; store-only proofs miss framing.
    let stable_principals = db.tables(&["users", "accounts", "verifications"]).await?;
    let prior_sessions: Vec<Value> = serde_json::from_str(&db.table("sessions").await?)?;
    let unaffected: Vec<_> = prior_sessions
        .iter()
        .filter(|row| row["token"] != token)
        .cloned()
        .collect();
    hooks.after_records.lock().unwrap().clear();
    hooks.receipts.lock().unwrap().clear();
    let failed = call(
        &auth,
        request(
            "/update-session",
            Some(json!({"label":"after-error"})),
            &cookie,
        ),
        500,
    )
    .await;
    assert!(failed.body.is_empty());
    assert!(failed.headers.get_all("set-cookie").next().is_none());
    assert_eq!(
        *hooks.receipts.lock().unwrap(),
        [(
            token.clone(),
            "after-error".to_owned(),
            "/api/auth/update-session".to_owned()
        )]
    );
    let observed = hooks.after_records.lock().unwrap().clone();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0]["path"], "/api/auth/update-session");
    assert_eq!(observed[0]["record"]["token"], token);
    assert_eq!(observed[0]["record"]["user_id"], body(&owner)["user"]["id"]);
    assert_eq!(observed[0]["record"]["label"], "after-error");
    assert_eq!(hooks.after.load(std::sync::atomic::Ordering::SeqCst), 2);
    let committed: Vec<Value> = serde_json::from_str(&db.table("sessions").await?)?;
    assert_eq!(committed.len(), prior_sessions.len());
    assert_eq!(
        committed
            .iter()
            .filter(|row| row["token"] != token)
            .cloned()
            .collect::<Vec<_>>(),
        unaffected
    );
    assert_eq!(
        committed.iter().find(|row| row["token"] == token).unwrap()["label"],
        "after-error"
    );
    assert_eq!(
        db.tables(&["users", "accounts", "verifications"]).await?,
        stable_principals
    );
    let mut physical_read = request("/get-session", None, &cookie);
    _ = physical_read
        .query
        .insert("disableCookieCache".into(), "true".into());
    let current = call(&auth, physical_read, 200).await;
    assert_eq!(body(&current)["session"]["token"], token);
    assert_eq!(body(&current)["session"]["label"], "after-error");
    assert_eq!(body(&current)["user"]["id"], body(&owner)["user"]["id"]);
    for established in [&sibling, &foreign] {
        let read = call(
            &auth,
            request("/get-session", None, &cookies(established)),
            200,
        )
        .await;
        assert_eq!(body(&read)["session"]["token"], body(established)["token"]);
        assert_eq!(body(&read)["user"]["id"], body(established)["user"]["id"]);
    }
    assert_eq!(
        serde_json::from_str::<Vec<Value>>(&db.table("sessions").await?)?,
        committed
    );
    assert_eq!(
        db.tables(&["users", "accounts", "verifications"]).await?,
        stable_principals
    );
    // Compat owner: core/session/update-projection.test.ts configured cancel.
    // Unlike a before-hook error, cancellation reports a missing updated row
    // and clears browser authority while leaving the original physical token.
    let before_cancel = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    hooks.receipts.lock().unwrap().clear();
    hooks.after_records.lock().unwrap().clear();
    let cancelled = call(
        &auth,
        request("/update-session", Some(json!({"label":"cancel"})), &cookie),
        401,
    )
    .await;
    assert_eq!(
        body(&cancelled),
        json!({"code":"FAILED_TO_GET_SESSION","message":"Failed to get session"})
    );
    assert_eq!(
        *hooks.receipts.lock().unwrap(),
        [(
            token.clone(),
            "cancel".to_owned(),
            "/api/auth/update-session".to_owned()
        )]
    );
    assert_eq!(hooks.after.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(hooks.after_records.lock().unwrap().is_empty());
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before_cancel
    );
    let mut browser: std::collections::BTreeMap<_, _> = cookie
        .split("; ")
        .filter_map(|pair| pair.split_once('='))
        .collect();
    let deleted: Vec<_> = cancelled.headers.get_all("set-cookie").collect();
    assert_eq!(deleted.len(), 3);
    for name in [
        "better-auth.session_token",
        "better-auth.session_data",
        "better-auth.dont_remember",
    ] {
        let deletion = deleted
            .iter()
            .find(|value| value.starts_with(&format!("{name}=")))
            .unwrap();
        assert_eq!(
            deletion.split(';').next(),
            Some(format!("{name}=").as_str())
        );
        assert!(
            deletion
                .split(';')
                .any(|attribute| attribute.trim() == "Max-Age=0")
        );
        let _ = browser.remove(name);
    }
    let cleared_cookie = browser
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    let guest = call(&auth, request("/get-session", None, &cleared_cookie), 200).await;
    assert!(body(&guest).is_null());
    let mut physical = request("/get-session", None, &cookie);
    let _ = physical
        .query
        .insert("disableCookieCache".into(), "true".into());
    let surviving = call(&auth, physical, 200).await;
    assert_eq!(body(&surviving)["session"]["token"], token);
    assert_eq!(body(&surviving)["session"]["label"], "after-error");
    assert_eq!(body(&surviving)["user"]["id"], body(&owner)["user"]["id"]);
    for established in [&sibling, &foreign] {
        let read = call(
            &auth,
            request("/get-session", None, &cookies(established)),
            200,
        )
        .await;
        assert_eq!(body(&read)["session"]["token"], body(established)["token"]);
        assert_eq!(body(&read)["user"]["id"], body(established)["user"]["id"]);
    }
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before_cancel
    );
    assert_eq!(hooks.after.load(std::sync::atomic::Ordering::SeqCst), 2);
    // Compat owner: configured update throw in update-projection.test.ts.
    // Physical adapter callbacks run before output conversion; the public
    // after observer must remain silent when conversion fails after commit.
    let prior = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    hooks.receipts.lock().unwrap().clear();
    hooks.after_records.lock().unwrap().clear();
    hooks.projected_updates.lock().unwrap().clear();
    let after_before = hooks.after.load(std::sync::atomic::Ordering::SeqCst);
    let failed = call(
        &auth,
        request("/update-session", Some(json!({"label":"throw"})), &cookie),
        500,
    )
    .await;
    assert!(failed.body.is_empty());
    assert!(failed.headers.get_all("set-cookie").next().is_none());
    assert_eq!(
        *hooks.receipts.lock().unwrap(),
        [(
            token.clone(),
            "throw".to_owned(),
            "/api/auth/update-session".to_owned()
        )]
    );
    assert_eq!(
        hooks.after.load(std::sync::atomic::Ordering::SeqCst),
        after_before + 1
    );
    let physical_after = hooks.after_records.lock().unwrap().clone();
    assert_eq!(physical_after.len(), 1);
    assert_eq!(physical_after[0]["path"], "/api/auth/update-session");
    assert_eq!(physical_after[0]["record"]["token"], token);
    assert_eq!(physical_after[0]["record"]["label"], "throw");
    assert!(hooks.projected_updates.lock().unwrap().is_empty());
    let committed = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    assert_eq!(committed[0], prior[0]);
    assert_eq!(committed[1], prior[1]);
    assert_eq!(committed[3], prior[3]);
    let before_rows: Vec<Value> = serde_json::from_str(&prior[2])?;
    let after_rows: Vec<Value> = serde_json::from_str(&committed[2])?;
    assert_eq!(before_rows.len(), after_rows.len());
    assert_eq!(
        before_rows
            .iter()
            .filter(|row| row["token"] != token)
            .collect::<Vec<_>>(),
        after_rows
            .iter()
            .filter(|row| row["token"] != token)
            .collect::<Vec<_>>()
    );
    let physical = auth.store().get_session(&token).await?.unwrap();
    assert_eq!(alibi::AuthSession::token(&physical), token);
    assert_eq!(
        alibi::AuthSession::user_id(&physical).as_ref(),
        body(&owner)["user"]["id"].as_str().unwrap()
    );
    assert_eq!(
        after_rows.iter().find(|row| row["token"] == token).unwrap()["label"],
        "throw"
    );
    for established in [&owner, &sibling, &foreign] {
        let cached = call(
            &auth,
            request("/get-session", None, &cookies(established)),
            200,
        )
        .await;
        assert_eq!(
            body(&cached)["session"]["token"],
            body(established)["token"]
        );
        assert_eq!(body(&cached)["user"]["id"], body(established)["user"]["id"]);
    }
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        committed
    );
    assert!(hooks.projected_updates.lock().unwrap().is_empty());
    renewal_callback_cases(&auth, db, hooks).await?;
    Ok(())
}

// Compat owner: core/session/update-projection.test.ts expiry renewal callbacks.
// Store-only updates and SQL-trigger failures do not exercise application hook
// context or error identity from the public due-session read.
async fn renewal_callback_cases<S: AuthSchema>(
    auth: &Alibi<S>,
    db: &Db,
    hooks: &RejectSessionUpdate,
) -> TestResult {
    use std::sync::atomic::Ordering::SeqCst;
    for (command, status) in [
        ("ordinary-error", 500),
        ("api-error", 403),
        ("mutate", 200),
        ("renewal-cancel", 401),
        ("after-error", 500),
    ] {
        let email = format!("renewal-{command}-owner@example.test");
        let owner = signup(auth, &email).await;
        let sibling = call(
            auth,
            request(
                "/sign-in/email",
                Some(json!({"email":email,"password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        let foreign = signup(auth, &format!("renewal-{command}-foreign@example.test")).await;
        let token = body(&owner)["token"].as_str().unwrap().to_owned();
        let cookie = cookies(&owner);
        // Operator setup bypasses callbacks to make only this owner's real row due.
        db.set_timestamp(
            "sessions",
            "expires_at",
            ("token", &token),
            Utc::now() + chrono::Duration::hours(1),
        )
        .await?;
        assert_eq!(
            db.execute(
                "UPDATE sessions SET hidden=$1 WHERE token=$2",
                &[command, &token]
            )
            .await?,
            1
        );
        *hooks.renewal_command.lock().unwrap() = Some((token.clone(), command.to_owned()));
        hooks.receipts.lock().unwrap().clear();
        hooks.renewal_inputs.lock().unwrap().clear();
        hooks.after_records.lock().unwrap().clear();
        let after_before = hooks.after.load(SeqCst);
        let before = db
            .tables(&["users", "accounts", "sessions", "verifications"])
            .await?;
        let mut due_read = request("/get-session", None, &cookie);
        let _ = due_read
            .query
            .insert("disableCookieCache".into(), "true".into());
        let response = call(auth, due_read, status).await;
        assert_eq!(
            *hooks.receipts.lock().unwrap(),
            [(
                token.clone(),
                command.to_owned(),
                "/api/auth/get-session".to_owned()
            )]
        );
        assert_eq!(*hooks.renewal_inputs.lock().unwrap(), [json!({})]);
        // A real postcommit callback failure differs from a before rejection:
        // the expiry and hook-injected label are durable, without new cookies.
        if command == "after-error" {
            assert_eq!(
                body(&response),
                json!({"code":"FAILED_TO_GET_SESSION","message":"Failed to get session"})
            );
            assert!(response.headers.get_all("set-cookie").next().is_none());
            assert_eq!(hooks.after.load(SeqCst), after_before + 1);
            let observed = hooks.after_records.lock().unwrap().clone();
            assert_eq!(observed.len(), 1);
            assert_eq!(observed[0]["path"], "/api/auth/get-session");
            assert_eq!(observed[0]["record"]["token"], token);
            assert_eq!(observed[0]["record"]["user_id"], body(&owner)["user"]["id"]);
            assert_eq!(observed[0]["record"]["label"], "after-error");
            let committed = db
                .tables(&["users", "accounts", "sessions", "verifications"])
                .await?;
            assert_eq!(committed[0], before[0]);
            assert_eq!(committed[1], before[1]);
            assert_eq!(committed[3], before[3]);
            let prior: Vec<Value> = serde_json::from_str(&before[2])?;
            let updated: Vec<Value> = serde_json::from_str(&committed[2])?;
            assert_eq!(prior.len(), updated.len());
            assert_eq!(
                prior
                    .iter()
                    .filter(|row| row["token"] != token)
                    .collect::<Vec<_>>(),
                updated
                    .iter()
                    .filter(|row| row["token"] != token)
                    .collect::<Vec<_>>()
            );
            let stored = auth.store().get_session(&token).await?.unwrap();
            assert!(
                alibi::AuthSession::expires_at(&stored) > Utc::now() + chrono::Duration::days(6)
            );
            *hooks.renewal_command.lock().unwrap() = None;
            let mut physical = request("/get-session", None, &cookie);
            let _ = physical
                .query
                .insert("disableCookieCache".into(), "true".into());
            let _ = physical
                .query
                .insert("disableRefresh".into(), "true".into());
            let surviving = call(auth, physical, 200).await;
            assert_eq!(body(&surviving)["session"]["token"], token);
            assert_eq!(body(&surviving)["session"]["label"], "after-error");
            assert_eq!(body(&surviving)["user"]["id"], body(&owner)["user"]["id"]);
            for established in [&sibling, &foreign] {
                let read = call(
                    auth,
                    request("/get-session", None, &cookies(established)),
                    200,
                )
                .await;
                assert_eq!(body(&read)["session"]["token"], body(established)["token"]);
                assert_eq!(body(&read)["user"]["id"], body(established)["user"]["id"]);
            }
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "verifications"])
                    .await?,
                committed
            );
            assert_eq!(hooks.after.load(SeqCst), after_before + 1);
            continue;
        }
        if command == "mutate" {
            assert_eq!(body(&response)["session"]["token"], token);
            assert_eq!(body(&response)["session"]["label"], "hook-updated");
            assert_eq!(body(&response)["user"]["id"], body(&owner)["user"]["id"]);
            assert_eq!(hooks.after.load(SeqCst), after_before + 1);
            let observed = hooks.after_records.lock().unwrap().clone();
            assert_eq!(observed.len(), 1);
            assert_eq!(observed[0]["path"], "/api/auth/get-session");
            assert_eq!(observed[0]["record"]["token"], token);
            assert_eq!(observed[0]["record"]["label"], "hook-updated");
            let after = db
                .tables(&["users", "accounts", "sessions", "verifications"])
                .await?;
            assert_eq!(after[0], before[0]);
            assert_eq!(after[1], before[1]);
            assert_eq!(after[3], before[3]);
            let prior: Vec<Value> = serde_json::from_str(&before[2])?;
            let updated: Vec<Value> = serde_json::from_str(&after[2])?;
            assert_eq!(prior.len(), updated.len());
            assert_eq!(
                prior
                    .iter()
                    .filter(|row| row["token"] != token)
                    .collect::<Vec<_>>(),
                updated
                    .iter()
                    .filter(|row| row["token"] != token)
                    .collect::<Vec<_>>()
            );
            let stored = auth.store().get_session(&token).await?.unwrap();
            assert!(
                alibi::AuthSession::expires_at(&stored) > Utc::now() + chrono::Duration::days(6)
            );
            assert!(
                response
                    .headers
                    .get_all("set-cookie")
                    .any(|raw| raw.starts_with("better-auth.session_token=")
                        && !raw.contains("Max-Age=0"))
            );
            assert!(cookies(&response).contains("better-auth.session_data="));
            // Independent physical sentinel proves subsequent browser reads use
            // the freshly published transformed cache, rather than another DB read.
            assert_eq!(
                db.execute(
                    "UPDATE sessions SET label='renewal-physical-sentinel' WHERE token=$1",
                    &[&token]
                )
                .await?,
                1
            );
            let cached = call(
                auth,
                request("/get-session", None, &cookies(&response)),
                200,
            )
            .await;
            assert_eq!(body(&cached)["session"]["token"], token);
            assert_eq!(body(&cached)["session"]["label"], "hook-updated");
            assert_eq!(body(&cached)["user"]["id"], body(&owner)["user"]["id"]);
            assert_eq!(
                db.execute(
                    "UPDATE sessions SET label='hook-updated' WHERE token=$1",
                    &[&token]
                )
                .await?,
                1
            );
            for established in [&sibling, &foreign] {
                let read = call(
                    auth,
                    request("/get-session", None, &cookies(established)),
                    200,
                )
                .await;
                assert_eq!(body(&read)["session"]["token"], body(established)["token"]);
                assert_eq!(body(&read)["user"]["id"], body(established)["user"]["id"]);
            }
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "verifications"])
                    .await?,
                after
            );
            assert_eq!(hooks.after.load(SeqCst), after_before + 1);
            *hooks.renewal_command.lock().unwrap() = None;
            continue;
        }
        if command == "renewal-cancel" {
            assert_eq!(
                body(&response),
                json!({"code":"FAILED_TO_GET_SESSION","message":"Failed to get session"})
            );
            let deleted: Vec<_> = response.headers.get_all("set-cookie").collect();
            assert!(deleted.iter().all(|raw| {
                let (name, value) = raw.split(';').next().unwrap().split_once('=').unwrap();
                [
                    "better-auth.session_token",
                    "better-auth.session_data",
                    "better-auth.dont_remember",
                ]
                .contains(&name)
                    && value.is_empty()
                    && raw
                        .split(';')
                        .skip(1)
                        .any(|attribute| attribute.trim() == "Max-Age=0")
            }));
            let mut browser: std::collections::BTreeMap<_, _> = cookie
                .split("; ")
                .filter_map(|pair| pair.split_once('='))
                .collect();
            for name in [
                "better-auth.session_token",
                "better-auth.session_data",
                "better-auth.dont_remember",
            ] {
                let deletion = deleted
                    .iter()
                    .find(|cookie| cookie.starts_with(&format!("{name}=")))
                    .unwrap();
                assert_eq!(
                    deletion.split(';').next(),
                    Some(format!("{name}=").as_str())
                );
                assert!(
                    deletion
                        .split(';')
                        .skip(1)
                        .any(|attribute| attribute.trim() == "Max-Age=0")
                );
                let _ = browser.remove(name);
            }
            let cleared = browser
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            let guest = call(auth, request("/get-session", None, &cleared), 200).await;
            assert!(body(&guest).is_null());
        } else {
            assert_eq!(
                body(&response),
                if command == "api-error" {
                    json!({"code":"APP_DENIED","message":"Application denied"})
                } else {
                    json!({"code":"FAILED_TO_GET_SESSION","message":"Failed to get session"})
                }
            );
            assert!(response.headers.get_all("set-cookie").next().is_none());
        }
        assert_eq!(hooks.after.load(SeqCst), after_before);
        assert!(hooks.after_records.lock().unwrap().is_empty());
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
        *hooks.renewal_command.lock().unwrap() = None;
        let mut physical = request("/get-session", None, &cookie);
        let _ = physical
            .query
            .insert("disableCookieCache".into(), "true".into());
        let _ = physical
            .query
            .insert("disableRefresh".into(), "true".into());
        let original = call(auth, physical, 200).await;
        assert_eq!(body(&original)["session"]["token"], token);
        assert_eq!(body(&original)["user"]["id"], body(&owner)["user"]["id"]);
        for established in [&sibling, &foreign] {
            let read = call(
                auth,
                request("/get-session", None, &cookies(established)),
                200,
            )
            .await;
            assert_eq!(body(&read)["session"]["token"], body(established)["token"]);
            assert_eq!(body(&read)["user"]["id"], body(established)["user"]["id"]);
        }
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
    }
    Ok(())
}

#[tokio::test]
async fn session_before_hook_rejection_sqlx_sqlite() -> TestResult {
    let db = Db::sqlite().await?;
    let (connection, _) = db.migrated::<Sqlx>(SECRET).await?;
    columns(&db).await?;
    let (config, _) = config();
    let hooks = RejectSessionUpdate::default();
    let auth = AuthBuilder::new(config.clone())
        .store(
            alibi::sqlx::SqlxStore::<sqlx_model::Schema>::new(config, connection.clone())
                .hook(hooks.clone()),
        )
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(hooks.clone())
        .build()
        .await?;
    rejected_session_update(auth, &db, &hooks).await?;
    Sqlx::close(connection).await
}

#[tokio::test]
async fn session_before_hook_rejection_seaorm_sqlite() -> TestResult {
    let db = Db::sqlite().await?;
    let (connection, _) = db.migrated::<SeaOrm>(SECRET).await?;
    columns(&db).await?;
    let (config, _) = config();
    let hooks = RejectSessionUpdate::default();
    let auth = AuthBuilder::new(config.clone())
        .store(
            alibi::seaorm::SeaOrmStore::<seaorm_model::Schema>::new(config, connection.clone())
                .hook(hooks.clone()),
        )
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(hooks.clone())
        .build()
        .await?;
    rejected_session_update(auth, &db, &hooks).await?;
    SeaOrm::close(connection).await
}

struct TransactionProbe;
#[async_trait::async_trait]
impl<S: AuthSchema> alibi::store::DatabaseHooks<S, alibi::sqlx::SqlxBackend> for TransactionProbe {
    async fn before_create_account(
        &self,
        _: &mut alibi::CreateAccount,
        ctx: &alibi::store::DatabaseHookContext<'_, alibi::sqlx::SqlxBackend>,
    ) -> alibi::AuthResult<alibi::store::HookControl> {
        let transaction = ctx.tx.expect("signup writes inside one transaction");
        let mut guard = transaction.lock().await;
        let connection = guard.sqlite().expect("SQLite transaction");
        _ = alibi::sqlx::sqlx::query("UPDATE users SET name = 'rewritten-by-hook'")
            .execute(connection)
            .await
            .map_err(|error| alibi::AuthError::internal(error.to_string()))?;
        Ok(alibi::store::HookControl::Continue)
    }
}

#[tokio::test]
async fn sqlx_hooks_run_statements_inside_the_auth_transaction() -> TestResult {
    let db = Db::sqlite().await?;
    let (connection, _) = db.migrated::<Sqlx>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let store = Sqlx::hook(
        Sqlx::store(Arc::new(config.clone()), &connection),
        TransactionProbe,
    );
    let auth = AuthBuilder::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await?;
    let _ = signup(&auth, "probe@example.test").await;
    assert_eq!(
        db.text("SELECT name FROM users", &[]).await?.as_deref(),
        Some("rewritten-by-hook")
    );
    Sqlx::close(connection).await
}
