//! Application session columns exercise each adapter's public derive and actual
//! HTTP field policy, independent physical persistence and cache publication.
#![allow(
    unreachable_pub,
    reason = "SeaORM entity associated types must be public"
)]
use super::super::{SeaOrm, Sqlx};
use super::*;
use alibi_core::config::CookieCacheConfig;
use alibi_core::field_policy::FieldConfig;
use alibi_core::utils::json::JsValue;
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
                    return Err(alibi_core::AuthError::internal("private transform failure"));
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
                        return Err(alibi_core::AuthError::internal("adapter callback veto"));
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
    auth: BetterAuth<S>,
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
                alibi_core::utils::cookie_utils::sign_cookie_value("true", SECRET)
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
