#![cfg(test)]
//! Verifies that `AuthEntity` derive accepts extra fields beyond the core set.

#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![cfg(feature = "seaorm2")]
#![allow(
    unreachable_pub,
    reason = "SeaORM DeriveEntityModel requires pub types"
)]

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

#[cfg(test)]
#[path = "auth_entity_extra_fields_tests/tests.rs"]
mod tests;

use better_auth::seaorm::AuthEntity;
use better_auth::seaorm::SeaOrmUserModel;
use better_auth::seaorm::sea_orm;
use better_auth::seaorm::sea_orm::entity::prelude::*;
