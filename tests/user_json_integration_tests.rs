#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
//! Native user metadata persistence must preserve valid application JSON keys.

#[cfg(feature = "seaorm2")]
#[expect(unreachable_pub, reason = "SeaORM derive requires public model fields")]
mod custom_user {
    use better_auth_seaorm::sea_orm::entity::prelude::*;
    use better_auth_seaorm::{AuthEntity, sea_orm};
    #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "custom_metadata_users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub metadata: better_auth_seaorm::JsonMetadata,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub tenant: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[cfg(test)]
#[path = "user_json_integration_tests/tests.rs"]
mod tests;

use better_auth::{AuthBuilder, AuthConfig};

use better_auth_core::{AuthUser, CreateUser, UpdateUser};

use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};

use better_auth_seaorm::{Database, SeaOrmStore};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

struct MetadataHook;

#[async_trait::async_trait]
impl better_auth_seaorm::SeaOrmHooks<Schema> for MetadataHook {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        _ctx: &better_auth_seaorm::SeaOrmHookContext<'_>,
    ) -> better_auth_core::AuthResult<better_auth_seaorm::HookControl> {
        user.metadata.as_mut().unwrap()["hookRounded"] =
            serde_json::Value::from(9_007_199_254_740_993_u64);
        Ok(better_auth_seaorm::HookControl::Continue)
    }
    async fn before_update_user(
        &self,
        _id: &str,
        update: &mut UpdateUser,
        _ctx: &better_auth_seaorm::SeaOrmHookContext<'_>,
    ) -> better_auth_core::AuthResult<better_auth_seaorm::HookControl> {
        if let Some(metadata) = &mut update.metadata {
            metadata["hookRounded"] = serde_json::Value::from(9_007_199_254_740_993_u64);
        }
        Ok(better_auth_seaorm::HookControl::Continue)
    }
}

#[cfg(feature = "seaorm2")]
struct CustomSchema;

#[cfg(feature = "seaorm2")]
impl better_auth_core::AuthSchema for CustomSchema {
    type User = custom_user::Model;
    type Session = better_auth_seaorm::store::entities::session::Model;
    type Account = better_auth_seaorm::store::entities::account::Model;
    type Verification = better_auth_seaorm::store::entities::verification::Model;
}
