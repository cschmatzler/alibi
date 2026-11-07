#[path = "../../../../tests/integration/storage/plugin_flows/user_update_patch_cases.rs"]
mod cases;

#[derive(crate::AuthEntity, Clone, Debug, PartialEq, serde::Serialize, sqlx::FromRow)]
#[auth(role = "user", table = "renamed_user", secondary_storage)]
struct RenamedUser {
    #[sqlx(rename = "pk")]
    id: String,
    #[sqlx(rename = "full_name")]
    name: String,
    email: String,
    #[sqlx(rename = "verified")]
    email_verified: bool,
    #[sqlx(rename = "avatar")]
    image: Option<String>,
    username: Option<String>,
    #[sqlx(rename = "display_name")]
    display_username: Option<String>,
    role: Option<String>,
    banned: Option<bool>,
    #[sqlx(rename = "reason")]
    ban_reason: Option<String>,
    #[sqlx(rename = "expiry")]
    ban_expires: Option<chrono::DateTime<chrono::Utc>>,
    #[sqlx(rename = "login_method")]
    last_login_method: Option<String>,
    #[sqlx(rename = "created")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[sqlx(rename = "updated")]
    updated_at: chrono::DateTime<chrono::Utc>,
}
struct RenamedSchema;
impl alibi_core::AuthSchema for RenamedSchema {
    type User = RenamedUser;
    type Session = <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Session;
    type Account = <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Account;
    type Verification =
        <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Verification;
}
#[tokio::test]
async fn original_input_update_patches_renamed_model_sqlite() {
    let effects = std::sync::Arc::new(cases::Effects::default());
    let config = cases::config(&effects, "display_name");
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = super::SqlxStore::<RenamedSchema>::new(config.clone(), pool.clone());
    super::migrator::run_migrations(&store.pool).await.unwrap();
    _ = sqlx::query("CREATE TABLE renamed_user (pk TEXT PRIMARY KEY, full_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, verified BOOLEAN NOT NULL, avatar TEXT, username TEXT, display_name TEXT, role TEXT, banned BOOLEAN, reason TEXT, expiry DATE, login_method TEXT, created DATE NOT NULL, updated DATE NOT NULL)").execute(&pool).await.unwrap();
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
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = super::SqlxStore::<super::bundled_schema::BundledSchema>::new(config.clone(), pool);
    super::migrator::run_migrations(&store.pool).await.unwrap();
    let store = store.with_hooks(vec![std::sync::Arc::new(cases::PhysicalHook(
        effects.clone(),
    ))]);
    cases::exercise(config, std::sync::Arc::new(store), effects).await;
}
