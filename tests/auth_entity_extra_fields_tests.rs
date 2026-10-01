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
        #[sea_orm(column_name = "preferred_locale", enum_name = "Language")]
        pub locale: Option<String>,
        #[sea_orm(enum_name = "TenantScope")]
        pub tenant_id: Option<i64>,
        #[sea_orm(column_name = "profile_kind")]
        pub r#type: Option<String>,
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

// The SDK's bundled model cannot exercise an application's physical column
// mapping. This owner queries the public generic store against a derived model.
#[tokio::test]
async fn custom_user_array_filters_bind_declared_physical_columns()
-> Result<(), Box<dyn std::error::Error>> {
    use better_auth::prelude::{AuthSchema, UserFilterValue};
    use better_auth::seaorm::{
        SeaOrmStore,
        sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectionTrait, Database, Schema},
    };
    use better_auth_core::{CreateUser, ListUsersParams, store::UserStore};
    type Bundled = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    struct ApplicationSchema;
    impl AuthSchema for ApplicationSchema {
        type User = user_with_extras::Model;
        type Session = <Bundled as AuthSchema>::Session;
        type Account = <Bundled as AuthSchema>::Account;
        type Verification = <Bundled as AuthSchema>::Verification;
    }
    let database = Database::connect("sqlite::memory:").await?;
    let schema = Schema::new(database.get_database_backend());
    let _ = database
        .execute(&schema.create_table_from_entity(user_with_extras::Entity))
        .await?;
    for (id, locale, verified, tenant) in [
        ("french", "fr", false, 1),
        ("german", "de", true, 2),
        ("english", "en", false, 3),
    ] {
        let mut active = user_with_extras::Model::new_active(
            Some(id.to_owned()),
            CreateUser {
                email: Some(format!("{id}@example.test")),
                name: Some(id.to_owned()),
                email_verified: Some(verified),
                ..Default::default()
            },
            chrono::Utc::now(),
        );
        active.locale = Set(Some(locale.to_owned()));
        active.r#type = Set(Some(format!("profile-{id}")));
        active.tenant_id = Set(Some(tenant));
        let _ = active.insert(&database).await?;
    }
    let store = SeaOrmStore::<ApplicationSchema>::new(
        better_auth::AuthConfig::new("custom-array-filter-application-secret32"),
        database.clone(),
    );
    let (users, total) = store
        .list_users(ListUsersParams {
            filter_field: Some("locale".into()),
            filter_operator: Some("in".into()),
            filter_value: Some(UserFilterValue::Multiple(vec![
                "fr".into(),
                "de".into(),
                "fr".into(),
            ])),
            sort_by: Some("name".into()),
            sort_direction: Some("asc".into()),
            limit: Some(1),
            offset: Some(1),
            ..Default::default()
        })
        .await?;
    assert_eq!(total, 2);
    assert_eq!(
        users
            .iter()
            .map(|user| user.id.as_str())
            .collect::<Vec<_>>(),
        vec!["german"]
    );
    let (users, total) = store
        .list_users(ListUsersParams {
            filter_field: Some("emailVerified".into()),
            filter_operator: Some("not_in".into()),
            filter_value: Some("true".into()),
            sort_by: Some("name".into()),
            sort_direction: Some("asc".into()),
            ..Default::default()
        })
        .await?;
    assert_eq!(total, 2);
    assert_eq!(
        users
            .iter()
            .map(|user| user.id.as_str())
            .collect::<Vec<_>>(),
        vec!["english", "french"]
    );
    let (users, total) = store
        .list_users(ListUsersParams {
            filter_field: Some("type".into()),
            filter_operator: Some("in".into()),
            filter_value: Some(UserFilterValue::Multiple(vec![
                "profile-french".into(),
                "profile-german".into(),
            ])),
            sort_by: Some("name".into()),
            sort_direction: Some("asc".into()),
            ..Default::default()
        })
        .await?;
    assert_eq!(total, 2);
    assert_eq!(
        users
            .iter()
            .map(|user| user.id.as_str())
            .collect::<Vec<_>>(),
        vec!["french", "german"]
    );
    let (users, total) = store
        .list_users(ListUsersParams {
            filter_field: Some("tenantId".into()),
            filter_operator: Some("in".into()),
            filter_value: Some(UserFilterValue::Multiple(vec!["1".into(), "2".into()])),
            sort_by: Some("name".into()),
            sort_direction: Some("asc".into()),
            ..Default::default()
        })
        .await?;
    assert_eq!(total, 2);
    assert_eq!(
        users
            .iter()
            .map(|user| user.id.as_str())
            .collect::<Vec<_>>(),
        vec!["french", "german"]
    );
    let all = user_with_extras::Entity::find().all(&database).await?;
    assert_eq!(all.len(), 3);
    assert!(all.iter().any(|user| user.id == "german"
        && user.email_verified
        && user.locale.as_deref() == Some("de")));
    Ok(())
}
