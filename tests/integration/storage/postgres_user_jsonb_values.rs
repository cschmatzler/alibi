#![allow(unreachable_pub, reason = "SeaORM derives require public model fields")]

use super::{Backend, Db, SeaOrm, Sqlx, TestResult};
use alibi::{Alibi, AuthBuilder, AuthConfig, AuthSchema, AuthUser, CreateUser, UpdateUser};
use serde_json::{Value, json};

mod sqlx_user {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
    #[auth(role = "user", table = "applicationUser")]
    pub struct Model {
        pub id: String,
        pub name: String,
        pub email: String,
        #[sqlx(rename = "emailVerified")]
        pub email_verified: bool,
        pub image: Option<String>,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "updatedAt")]
        pub updated_at: chrono::DateTime<chrono::Utc>,
        pub metadata: Option<alibi::sqlx::JsonMetadata>,
    }
}

struct SqlxSchema;
impl AuthSchema for SqlxSchema {
    type User = sqlx_user::Model;
    type Session = alibi::sqlx::store::entities::session::Model;
    type Account = alibi::sqlx::store::entities::account::Model;
    type Verification = alibi::sqlx::store::entities::verification::Model;
}

mod seaorm_user {
    use alibi::seaorm::sea_orm::entity::prelude::*;
    use alibi::seaorm::{AuthEntity, sea_orm};
    #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "applicationUser")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: String,
        pub email: String,
        #[sea_orm(column_name = "emailVerified")]
        pub email_verified: bool,
        pub image: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: DateTimeUtc,
        #[sea_orm(column_type = "JsonBinary", nullable)]
        pub metadata: Option<alibi::seaorm::JsonMetadata>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

struct SeaOrmSchema;
impl AuthSchema for SeaOrmSchema {
    type User = seaorm_user::Model;
    type Session = alibi::seaorm::store::entities::session::Model;
    type Account = alibi::seaorm::store::entities::account::Model;
    type Verification = alibi::seaorm::store::entities::verification::Model;
}

async fn setup(db: &Db) -> TestResult<AuthConfig> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../fixtures/postgres-user-jsonb-values.json"
    ))?;
    for sql in fixture["schema_sql"]
        .as_str()
        .unwrap()
        .split(';')
        .filter(|sql| !sql.trim().is_empty())
    {
        _ = db.execute(sql, &[]).await?;
    }
    assert_eq!(json!(db.text("SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'applicationUser' AND column_name = 'metadata'", &[]).await?.unwrap()), fixture["physical_type"]);
    let mut config = AuthConfig::new("postgres-user-jsonb-values-secret-at-least-32");
    _ = config.user.additional_fields.insert(
        "metadata".into(),
        alibi::field_policy::FieldConfig::new(json!({"type":"json"})),
    );
    Ok(config)
}

#[derive(Clone, Copy)]
enum MetadataInput {
    Typed,
    Configured,
    Native,
}

fn create_input(email: &str, metadata: Value, input: MetadataInput) -> CreateUser {
    let mut user = CreateUser::new()
        .with_name("JSONB values")
        .with_email(email);
    match input {
        MetadataInput::Typed => user.metadata = Some(metadata),
        MetadataInput::Configured => {
            _ = user
                .additional_fields
                .insert("metadata".into(), metadata.into());
        }
        MetadataInput::Native => {
            _ = user
                .adapter_native_fields
                .insert("metadata".into(), metadata.into());
        }
    }
    user
}

async fn check<S: AuthSchema>(
    db: &Db,
    auth: &Alibi<S>,
    update: bool,
    input: MetadataInput,
) -> TestResult {
    let fixture: Value = serde_json::from_str(if update {
        include_str!("../../fixtures/postgres-user-jsonb-updates.json")
    } else {
        include_str!("../../fixtures/postgres-user-jsonb-values.json")
    })?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let email = format!("{name}@jsonb-values.example.com");
        let original = if update {
            Some(
                auth.store()
                    .create_user(
                        CreateUser::new()
                            .with_name("JSONB values")
                            .with_email(&email)
                            .with_metadata(json!({"original":true})),
                    )
                    .await?,
            )
        } else {
            None
        };
        let result = if let Some(original) = &original {
            auth.store()
                .update_user(
                    original.id().as_ref(),
                    UpdateUser {
                        metadata: Some(case["input"].clone()),
                        ..Default::default()
                    },
                )
                .await
        } else {
            auth.store()
                .create_user(create_input(&email, case["input"].clone(), input))
                .await
        };
        assert_eq!(
            result.is_err(),
            case["error_code"].is_string(),
            "{name}: {result:?}"
        );
        let output = match result {
            Ok(row) => {
                if let Some(original) = &original {
                    assert_eq!(row.id(), original.id(), "{name}");
                }
                json!({"metadata":serde_json::to_value(auth.context().trusted_user_view(&row)?)?["metadata"]})
            }
            Err(error) => {
                assert!(
                    error
                        .to_string()
                        .contains("invalid input syntax for type json"),
                    "{name}: {error}"
                );
                Value::Null
            }
        };
        assert_eq!(output, case["output"], "{name}");
        let readback = auth
            .store()
            .get_user_by_email(&email.as_str().into())
            .await?;
        let readback = readback.map(|row| -> TestResult<Value> { Ok(json!({"metadata":serde_json::to_value(auth.context().trusted_user_view(&row)?)?["metadata"]})) }).transpose()?.unwrap_or(Value::Null);
        assert_eq!(readback, case["readback"], "{name}");
        let stored: Value = serde_json::from_str(&db.text("SELECT json_build_object('row_count', count(*), 'stored', (jsonb_agg(jsonb_build_object('metadata', metadata, 'sql_null', metadata IS NULL))->0))::text FROM \"applicationUser\" WHERE email = $1", &[&email]).await?.unwrap())?;
        assert_eq!(stored["row_count"], case["row_count"], "{name}");
        assert_eq!(stored["stored"], case["stored"], "{name}");
    }
    Ok(())
}

async fn sqlx_case(update: bool, input: MetadataInput) -> TestResult {
    let db = Db::postgres().await?;
    let config = setup(&db).await?;
    let connection = Sqlx::connect(&db.url, None).await?;
    let auth = AuthBuilder::new(config.clone())
        .store(alibi::sqlx::SqlxStore::<SqlxSchema>::new(
            config,
            connection.clone(),
        ))
        .build()
        .await?;
    check(&db, &auth, update, input).await?;
    drop(auth);
    Sqlx::close(connection).await
}

async fn seaorm_case(update: bool, input: MetadataInput) -> TestResult {
    let db = Db::postgres().await?;
    let config = setup(&db).await?;
    let connection = SeaOrm::connect(&db.url, None).await?;
    let auth = AuthBuilder::new(config.clone())
        .store(alibi::seaorm::SeaOrmStore::<SeaOrmSchema>::new(
            config,
            connection.clone(),
        ))
        .build()
        .await?;
    check(&db, &auth, update, input).await?;
    drop(auth);
    SeaOrm::close(connection).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn sqlx_user_jsonb_values_match_actual_postgres_parameters() -> TestResult {
    sqlx_case(false, MetadataInput::Typed).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn seaorm_user_jsonb_values_match_actual_postgres_parameters() -> TestResult {
    seaorm_case(false, MetadataInput::Typed).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn sqlx_user_jsonb_updates_match_actual_postgres_parameters() -> TestResult {
    sqlx_case(true, MetadataInput::Typed).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn seaorm_user_jsonb_updates_match_actual_postgres_parameters() -> TestResult {
    seaorm_case(true, MetadataInput::Typed).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn sqlx_user_jsonb_configured_values_match_actual_postgres_parameters() -> TestResult {
    sqlx_case(false, MetadataInput::Configured).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn seaorm_user_jsonb_configured_values_match_actual_postgres_parameters() -> TestResult {
    seaorm_case(false, MetadataInput::Configured).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn sqlx_user_jsonb_native_values_match_actual_postgres_parameters() -> TestResult {
    sqlx_case(false, MetadataInput::Native).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn seaorm_user_jsonb_native_values_match_actual_postgres_parameters() -> TestResult {
    seaorm_case(false, MetadataInput::Native).await
}
