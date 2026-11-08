#![allow(
    unreachable_pub,
    reason = "SeaORM derives public associated entities inside private test fixtures"
)]
use crate::storage::SeaOrm;
use super::*;
use alibi::seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};

mod session {
    use alibi::seaorm::sea_orm::{self, entity::prelude::*};
    use chrono::{DateTime, Utc};
    #[derive(alibi::seaorm::AuthEntity, Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[auth(role = "session")]
    #[sea_orm(table_name = "session", rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub expires_at: DateTime<Utc>,
        pub token: String,
        pub created_at: DateTime<Utc>,
        pub updated_at: DateTime<Utc>,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub user_id: String,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

type Bundled = <SeaOrm as Backend>::Schema;
struct Schema;
impl AuthSchema for Schema {
    type User = <Bundled as AuthSchema>::User;
    type Session = session::Model;
    type Account = <Bundled as AuthSchema>::Account;
    type Verification = <Bundled as AuthSchema>::Verification;
}

async fn check(asynchronous: bool, operation: &str, compatible: bool) -> TestResult {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../fixtures/session-timestamp-hooks-string-mysql.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    assert_eq!(fixture["backend"], "mysql");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    let case = cases
        .iter()
        .find(|case| case["operation"] == operation && case["compatible"] == compatible)
        .unwrap();
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = alibi::seaorm::Database::connect(base.clone()).await?;
    let database = format!("alibi_session_string_{}", uuid::Uuid::new_v4().simple());
    _ = admin
        .execute_unprepared(&format!(
            "CREATE DATABASE `{database}` CHARACTER SET utf8mb4"
        ))
        .await?;
    let mut url = url::Url::parse(&base)?;
    url.set_path(&format!("/{database}"));
    let connection = alibi::seaorm::Database::connect(url.as_str()).await?;
    for statement in fixture["schema_sql"]
        .as_str()
        .unwrap()
        .split(';')
        .filter(|sql| !sql.trim().is_empty())
    {
        _ = connection.execute_unprepared(statement).await?;
    }
    _ = connection.execute_unprepared("INSERT INTO `user` (`id`,`name`,`email`,`emailVerified`,`createdAt`,`updatedAt`) VALUES ('session-owner','String Result','session-string-result@example.com',false,'2020-01-01 00:00:00.123','2020-01-01 00:00:00.123')").await?;
    let events = Events::default();
    let inputs = events.clone();
    let applying_input = Arc::new(AtomicBool::new(false));
    let applying = applying_input.clone();
    let text = case["callback_result"].as_str().unwrap().to_owned();
    let field = alibi::field_policy::FieldConfig::new(json!({"type":"date"}));
    let field = if asynchronous {
        field.transform_adapter_input(move |value| {
            let inputs = inputs.clone();
            let applying = applying.clone();
            let text = text.clone();
            async move {
                event(&inputs, "input", value.as_ref())?;
                Ok(if applying.load(Ordering::SeqCst) {
                    Some(JsValue::String(text.into()))
                } else {
                    value
                })
            }
        })
    } else {
        field.transform(move |value| {
            event(&inputs, "input", value)?;
            Ok(if applying.load(Ordering::SeqCst) {
                Some(JsValue::String(text.clone().into()))
            } else {
                value.cloned()
            })
        })
    };
    let mut config = AuthConfig::new("session-string-result-probe-secret-at-least-32");
    _ = config
        .session
        .additional_fields
        .insert("expiresAt".into(), field);
    let store =
        alibi::seaorm::SeaOrmStore::<Schema>::new(Arc::new(config.clone()), connection.clone())
            .hook(SessionHooks(events.clone()));
    let auth = AuthBuilder::new(config).store(store).build().await?;
    let token = case["token"].as_str().unwrap();
    let mut create = CreateSession {
        additional_fields: Default::default(),
        user_id: "session-owner".into(),
        token: Some(token.into()),
        expires_at: "2031-02-03T04:05:06.123Z".parse()?,
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
    };
    let mut original_id = None;
    let result = if operation == "create" {
        applying_input.store(true, Ordering::SeqCst);
        events.lock().unwrap().clear();
        auth.store().create_session(create).await
    } else {
        assert_eq!(operation, "update");
        create.expires_at = "2031-01-01T00:00:00.123Z".parse()?;
        let original = auth.store().create_session(create).await?;
        original_id = Some(original.id().into_owned());
        applying_input.store(true, Ordering::SeqCst);
        events.lock().unwrap().clear();
        auth.store()
            .refresh_session(token, "2031-02-03T04:05:06.123Z".parse()?)
            .await
            .and_then(|session| {
                session.ok_or_else(|| alibi::AuthError::internal("MySQL refresh missing"))
            })
    };
    assert_eq!(
        json!(*events.lock().unwrap()),
        case["events"],
        "mysql/{operation}/{compatible} callback phases"
    );
    let returned_id = if let Some(expected) = case["outcome"].get("error") {
        let error = result
            .err()
            .ok_or("source MySQL string error became a successful session write")?;
        assert!(matches!(&error, alibi::AuthError::Database(_)));
        assert_eq!(expected["state"], "22007");
        assert!(
            error
                .to_string()
                .contains(expected["message"].as_str().unwrap()),
            "mysql/{operation}/{compatible}: {error}"
        );
        None
    } else {
        let session = result?;
        assert_eq!(
            native::to_value(&JsValue::Date(session.expires_at()))?,
            case["outcome"]["output"]
        );
        Some(session.id().into_owned())
    };
    let row = connection.query_one_raw(Statement::from_sql_and_values(DbBackend::MySql,"SELECT DATE_FORMAT(expiresAt,'%Y-%m-%dT%H:%i:%s.%fZ') AS value FROM session WHERE token = ?",[token.into()])).await?;
    assert_eq!(json!(usize::from(row.is_some())), case["rows"]);
    let stored: Option<String> = row
        .map(|row| row.try_get("", "value"))
        .transpose()?
        .flatten();
    assert_eq!(json!(stored), case["physical"]);
    let readback = auth.store().get_session(token).await?;
    assert_eq!(
        native::to_value(
            &readback
                .as_ref()
                .map(|session| JsValue::Date(session.expires_at()))
        )?,
        case["readback"]
    );
    if let Some(session) = readback {
        assert_eq!(Some(session.id().into_owned()), original_id.or(returned_id));
    }
    drop(auth);
    connection.close().await?;
    _ = admin
        .execute_unprepared(&format!("DROP DATABASE `{database}`"))
        .await?;
    admin.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn creation_sync_iso_string_is_rejected_by_driver() -> TestResult {
    check(false, "create", false).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn creation_async_iso_string_is_rejected_by_driver() -> TestResult {
    check(true, "create", false).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn refresh_sync_iso_string_is_rejected_by_driver() -> TestResult {
    check(false, "update", false).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn refresh_async_iso_string_is_rejected_by_driver() -> TestResult {
    check(true, "update", false).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn creation_sync_compatible_string_uses_driver_rounding() -> TestResult {
    check(false, "create", true).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn creation_async_compatible_string_uses_driver_rounding() -> TestResult {
    check(true, "create", true).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn refresh_sync_compatible_string_uses_driver_rounding() -> TestResult {
    check(false, "update", true).await
}
#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL"]
async fn refresh_async_compatible_string_uses_driver_rounding() -> TestResult {
    check(true, "update", true).await
}
