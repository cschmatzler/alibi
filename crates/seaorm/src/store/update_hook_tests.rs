#[path = "../../../../tests/integration/storage/plugin_flows/user_update_patch_cases.rs"]
mod cases;

mod renamed {
    use sea_orm::entity::prelude::*;
    #[derive(crate::AuthEntity, Clone, Debug, PartialEq, DeriveEntityModel, serde::Serialize)]
    #[sea_orm(table_name = "renamed_user")]
    #[auth(role = "user", secondary_storage)]
    pub(super) struct Model {
        #[sea_orm(primary_key, auto_increment = false, column_name = "pk")]
        pub id: String,
        #[sea_orm(column_name = "full_name")]
        pub name: String,
        pub email: String,
        #[sea_orm(column_name = "verified")]
        pub email_verified: bool,
        #[sea_orm(column_name = "avatar")]
        pub image: Option<String>,
        pub username: Option<String>,
        #[sea_orm(column_name = "display_name")]
        pub display_username: Option<String>,
        pub role: Option<String>,
        pub banned: Option<bool>,
        #[sea_orm(column_name = "reason")]
        pub ban_reason: Option<String>,
        #[sea_orm(column_name = "expiry")]
        pub ban_expires: Option<DateTimeUtc>,
        #[sea_orm(column_name = "login_method")]
        pub last_login_method: Option<String>,
        #[sea_orm(column_name = "created")]
        pub created_at: DateTimeUtc,
        #[sea_orm(column_name = "updated")]
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub(super) enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
struct RenamedSchema;
impl alibi_core::AuthSchema for RenamedSchema {
    type User = renamed::Model;
    type Session = <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Session;
    type Account = <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Account;
    type Verification =
        <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Verification;
}
#[tokio::test]
async fn original_input_update_patches_renamed_model_sqlite() {
    use sea_orm::ConnectionTrait;
    let effects = std::sync::Arc::new(cases::Effects::default());
    let config = cases::config(&effects, "display_name");
    let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
    super::migrator::run_migrations(&db).await.unwrap();
    _ = db.execute_unprepared("CREATE TABLE renamed_user (pk TEXT PRIMARY KEY, full_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, verified BOOLEAN NOT NULL, avatar TEXT, username TEXT, display_name TEXT, role TEXT, banned BOOLEAN, reason TEXT, expiry DATE, login_method TEXT, created DATE NOT NULL, updated DATE NOT NULL)").await.unwrap();
    let store = super::SeaOrmStore::<RenamedSchema>::new(config.clone(), db);
    cases::exercise(
        config,
        std::sync::Arc::new(
            store.with_hooks(vec![std::sync::Arc::new(cases::PhysicalHook(
                effects.clone(),
            ))]),
        ),
        effects,
    )
    .await;
}
#[tokio::test]
async fn original_input_update_patches_bind_and_rollback_on_real_sqlite() {
    let effects = std::sync::Arc::new(cases::Effects::default());
    let config = cases::config(&effects, "displayUsername");
    let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
    super::migrator::run_migrations(&db).await.unwrap();
    let store = super::SeaOrmStore::<super::bundled_schema::BundledSchema>::new(config.clone(), db);
    let store = store.with_hooks(vec![std::sync::Arc::new(cases::PhysicalHook(
        effects.clone(),
    ))]);
    cases::exercise(config, std::sync::Arc::new(store), effects).await;
}
