#![allow(unreachable_pub, reason = "SeaORM derives require public model fields")]

use super::{Backend, Db, SeaOrm, TestResult};
use alibi::seaorm::SeaOrmStore;
use alibi::{AuthBuilder, AuthConfig, AuthSchema, AuthUser, CreateUser, UpdateUser};
use serde_json::{Value, json};

mod application_user {
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
        #[sea_orm(column_type = "Text", nullable)]
        pub metadata: Option<alibi::seaorm::JsonMetadata>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

struct Schema;
impl AuthSchema for Schema {
    type User = application_user::Model;
    type Session = alibi::seaorm::store::entities::session::Model;
    type Account = alibi::seaorm::store::entities::account::Model;
    type Verification = alibi::seaorm::store::entities::verification::Model;
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn postgres_seaorm_owned_user_json_text_matches_actual_driver_values() -> TestResult {
    let db = Db::postgres().await?;
    let fixture: Value =
        serde_json::from_str(include_str!("../../fixtures/postgres-user-json-text.json"))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    _ = db
        .execute(fixture["table_sql"].as_str().unwrap(), &[])
        .await?;
    assert_eq!(json!(db.text("SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'applicationUser' AND column_name = 'metadata'", &[]).await?.unwrap()), fixture["physical_type"]);
    let connection = SeaOrm::connect(&db.url, None).await?;
    let mut config = AuthConfig::new("postgres-user-json-text-secret-at-least-32");
    _ = config.user.additional_fields.insert(
        "metadata".into(),
        alibi::field_policy::FieldConfig::new(json!({"type":"json"})),
    );
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, connection.clone()))
        .build()
        .await?;
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 28);
    let mut id = String::new();
    for case in cases {
        let action = case["action"].as_str().unwrap();
        let row = match action {
            "create" | "create-array" | "create-string" | "create-boolean" | "create-number"
            | "create-null" => {
                auth.store()
                    .create_user(
                        CreateUser::new()
                            .with_name("Text JSON")
                            .with_email(if action == "create" {
                                "text-json@example.com".to_owned()
                            } else {
                                format!("{action}@text-json.example.com")
                            })
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
            "read"
            | "updated-read"
            | "array-read"
            | "string-read"
            | "boolean-read"
            | "number-read"
            | "operator-read"
            | "invalid-read"
            | "cleared-read"
            | "created-array-read"
            | "created-string-read"
            | "created-boolean-read"
            | "created-number-read"
            | "created-null-read" => auth
                .store()
                .get_user_by_id(&id)
                .await?
                .ok_or("source user must exist")?,
            _ => panic!("unexpected source user action: {action}"),
        };
        if action == "create" || action.starts_with("create-") {
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
    SeaOrm::close(connection).await
}
