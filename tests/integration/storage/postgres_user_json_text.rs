use super::{Backend, Db, Sqlx, TestResult};
use alibi::sqlx::{JsonMetadata, SqlxStore};
use alibi::{AuthBuilder, AuthConfig, AuthSchema, AuthUser, CreateUser, UpdateUser};
use serde_json::{Value, json};

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
#[auth(role = "user", table = "applicationUser")]
struct ApplicationUser {
    id: String,
    name: String,
    email: String,
    #[sqlx(rename = "emailVerified")]
    email_verified: bool,
    image: Option<String>,
    #[sqlx(rename = "createdAt")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[sqlx(rename = "updatedAt")]
    updated_at: chrono::DateTime<chrono::Utc>,
    #[auth(column_type = "text")]
    metadata: Option<JsonMetadata>,
}

struct Schema;
impl AuthSchema for Schema {
    type User = ApplicationUser;
    type Session = alibi::sqlx::store::entities::session::Model;
    type Account = alibi::sqlx::store::entities::account::Model;
    type Verification = alibi::sqlx::store::entities::verification::Model;
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn postgres_owned_user_json_text_matches_actual_driver_values() -> TestResult {
    let db = Db::postgres().await?;
    let fixture: Value =
        serde_json::from_str(include_str!("../../fixtures/postgres-user-json-text.json"))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    _ = db
        .execute(fixture["table_sql"].as_str().unwrap(), &[])
        .await?;
    assert_eq!(json!(db.text("SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'applicationUser' AND column_name = 'metadata'", &[]).await?.unwrap()), fixture["physical_type"]);
    let connection = Sqlx::connect(&db.url, None).await?;
    let mut config = AuthConfig::new("postgres-user-json-text-secret-at-least-32");
    _ = config.user.additional_fields.insert(
        "metadata".into(),
        alibi::field_policy::FieldConfig::new(json!({"type":"json"})),
    );
    let auth = AuthBuilder::new(config.clone())
        .store(SqlxStore::<Schema>::new(config, connection.clone()))
        .build()
        .await?;
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 18);
    let mut id = String::new();
    for case in cases {
        let action = case["action"].as_str().unwrap();
        let row = match action {
            "create" => {
                auth.store()
                    .create_user(
                        CreateUser::new()
                            .with_name("Text JSON")
                            .with_email("text-json@example.com")
                            .with_metadata(case["input"].clone()),
                    )
                    .await?
            }
            "update" | "array" | "string" | "boolean" | "number" | "clear" => {
                auth.store()
                    .update_user(
                        &id,
                        UpdateUser {
                            metadata: Some(case["input"].clone()),
                            ..Default::default()
                        },
                    )
                    .await?
            }
            "operator-text" | "invalid-text" => {
                _ = db
                    .execute(
                        "UPDATE \"applicationUser\" SET metadata = $1 WHERE id = $2",
                        &[case["raw_input"].as_str().unwrap(), &id],
                    )
                    .await?;
                auth.store()
                    .get_user_by_id(&id)
                    .await?
                    .ok_or("source user must exist")?
            }
            "read" | "updated-read" | "array-read" | "string-read" | "boolean-read"
            | "number-read" | "operator-read" | "invalid-read" | "cleared-read" => auth
                .store()
                .get_user_by_id(&id)
                .await?
                .ok_or("source user must exist")?,
            _ => panic!("unexpected source user action: {action}"),
        };
        if action == "create" {
            id = row.id().into_owned();
        }
        assert_eq!(row.id().as_ref(), id, "{action}");
        let output = serde_json::to_value(auth.context().trusted_user_view(&row)?)?;
        assert_eq!(output["metadata"], case["output"], "{action}");
        assert_eq!(
            json!(
                db.text(
                    "SELECT metadata FROM \"applicationUser\" WHERE id = $1",
                    &[&id]
                )
                .await?
            ),
            case["stored"],
            "{action}"
        );
    }
    drop(auth);
    connection.close().await;
    Ok(())
}
