//! Verifies that `AuthEntity` derive accepts extra fields beyond the core set.

#![cfg(feature = "seaorm2")]
#![allow(
    unreachable_pub,
    reason = "SeaORM DeriveEntityModel requires pub types"
)]

use better_auth::seaorm::AuthEntity;
use better_auth::seaorm::SeaOrmUserModel;
use better_auth::seaorm::sea_orm;
use better_auth::seaorm::sea_orm::entity::prelude::*;

mod user_with_extras {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "users_extra")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub username: Option<String>,
        pub display_username: Option<String>,
        pub two_factor_enabled: bool,
        pub role: Option<String>,
        pub banned: bool,
        pub ban_reason: Option<String>,
        pub ban_expires: Option<DateTimeUtc>,
        pub metadata: Json,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        // Extra fields — AuthEntity sets these to NotSet on creation
        pub locale: Option<String>,
        pub tenant_id: Option<i64>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[test]
fn extra_fields_get_not_set_in_new_active() {
    use better_auth::prelude::CreateUser;
    use chrono::Utc;
    use sea_orm::ActiveValue;

    let now = Utc::now();
    let create = CreateUser::new()
        .with_email("test@example.com")
        .with_name("Test");
    let active = user_with_extras::Model::new_active(None, create, now);

    // Core fields should be Set
    assert!(matches!(active.email, ActiveValue::Set(_)));
    assert!(matches!(active.name, ActiveValue::Set(_)));
    assert!(matches!(active.created_at, ActiveValue::Set(_)));

    // Extra fields should be NotSet
    assert!(matches!(active.locale, ActiveValue::NotSet));
    assert!(matches!(active.tenant_id, ActiveValue::NotSet));
}

#[tokio::test]
async fn boolean_custom_entities_keep_explicit_plugin_flags_through_persistence()
-> Result<(), Box<dyn std::error::Error>> {
    use better_auth::prelude::{AuthUser, CreateUser, UpdateUser};
    use sea_orm::{
        ActiveModelTrait, ConnectionTrait, Database, EntityTrait, IntoActiveModel, Schema,
    };
    let database = Database::connect("sqlite::memory:").await?;
    let schema = Schema::new(database.get_database_backend());
    let _ = database
        .execute(&schema.create_table_from_entity(user_with_extras::Entity))
        .await?;
    let user = user_with_extras::Model::new_active(
        Some("legacy-boolean-user".to_owned()),
        CreateUser {
            email: Some("legacy-boolean-user@example.com".to_owned()),
            two_factor_enabled: Some(true),
            banned: Some(true),
            ..Default::default()
        },
        chrono::Utc::now(),
    )
    .insert(&database)
    .await?;
    assert!(user.two_factor_enabled());
    assert!(user.banned());
    assert_eq!(user.two_factor_enabled_value(), Some(true));
    assert_eq!(user.banned_value(), Some(true));
    let mut active = user.into_active_model();
    user_with_extras::Model::apply_update(
        &mut active,
        UpdateUser {
            two_factor_enabled: Some(false),
            banned: Some(false),
            ..Default::default()
        },
        chrono::Utc::now(),
    );
    let _ = active.update(&database).await?;
    let persisted = user_with_extras::Entity::find_by_id("legacy-boolean-user")
        .one(&database)
        .await?
        .ok_or_else(|| std::io::Error::other("custom user disappeared"))?;
    assert_eq!(persisted.two_factor_enabled_value(), Some(false));
    assert_eq!(persisted.banned_value(), Some(false));
    Ok(())
}
