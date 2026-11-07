use super::{Backend, SeaOrm, TestResult};
use alibi::seaorm::sea_orm::ConnectionTrait;
use alibi::utils::json::{self as native, JsValue};
use alibi::{AuthBuilder, AuthConfig, CreateUser, UpdateUser};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_declared_user_writes_match_actual_readback() -> TestResult {
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = alibi::seaorm::Database::connect(base.clone()).await?;
    let database = format!("alibi_readback_{}", uuid::Uuid::new_v4().simple());
    _ = admin
        .execute_unprepared(&format!(
            "CREATE DATABASE `{database}` CHARACTER SET utf8mb4"
        ))
        .await?;
    let mut url = url::Url::parse(&base)?;
    url.set_path(&format!("/{database}"));
    let connection = alibi::seaorm::Database::connect(url.as_str()).await?;
    for statement in include_str!("../../fixtures/mysql-source-schema.sql")
        .split(';')
        .filter(|sql| !sql.trim().is_empty())
    {
        _ = connection.execute_unprepared(statement).await?;
    }
    let mut config = AuthConfig::new("mysql-user-readback-secret-at-least-32-characters");
    for field in ["name", "id"] {
        _ = config.user.additional_fields.insert(
            field.into(),
            alibi::field_policy::FieldConfig::new(json!({"type":"string"})),
        );
    }
    let auth = AuthBuilder::new(config.clone())
        .store(<SeaOrm as Backend>::store(Arc::new(config), &connection))
        .build()
        .await?;
    let fixture = native::parse_value(include_str!(
        "../../fixtures/mysql-user-write-readback.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    let date: chrono::DateTime<chrono::Utc> = "2026-01-01T00:00:00.123Z".parse()?;
    for (index, case) in cases.iter().enumerate() {
        let id = case["id"].as_str().unwrap();
        let created = auth
            .store()
            .create_user(CreateUser {
                id: Some(id.into()),
                name: Some("Owner".into()),
                email: Some(format!("mysql-readback-{index}@example.com")),
                created_at: Some(date),
                updated_at: Some(date),
                ..Default::default()
            })
            .await?;
        assert_eq!(
            native::parse_value(&native::to_string(
                &auth.context().trusted_user_view(&created)?
            )?)?,
            case["created"]
        );
        let mut update = UpdateUser {
            name: Some("Renamed".into()),
            ..Default::default()
        };
        _ = update
            .additional_fields
            .insert("id".into(), case["replacement"].clone());
        _ = update
            .additional_fields
            .insert("updatedAt".into(), JsValue::Date(date));
        let updated = auth.store().update_user_record(id, update).await?;
        assert_eq!(
            native::parse_value(&native::to_string(
                &auth.context().trusted_user_view(&updated)?
            )?)?,
            case["updated"]
        );
        let expected = case["updated"]["id"].as_str().unwrap();
        assert_eq!(
            auth.store().get_user_by_id(id).await?.is_none(),
            expected != id
        );
        assert!(auth.store().get_user_by_id(expected).await?.is_some());
    }
    drop(auth);
    connection.close().await?;
    _ = admin
        .execute_unprepared(&format!("DROP DATABASE `{database}`"))
        .await?;
    admin.close().await?;
    Ok(())
}
