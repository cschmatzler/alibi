use super::{
    SeaOrmStore,
    entities::sso_provider::{self, Column, Entity},
    map_db_err,
};
use crate::schema::AuthSchema;
use alibi_core::{
    AuthResult,
    store::{SsoProvider, SsoProviderStore},
};
use async_trait::async_trait;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, Set};
#[async_trait]
impl<S: AuthSchema> SsoProviderStore for SeaOrmStore<S> {
    async fn create_sso_provider(&self, row: SsoProvider) -> AuthResult<SsoProvider> {
        sso_provider::ActiveModel {
            id: Set(row.id),
            issuer: Set(row.issuer),
            domain: Set(row.domain),
            provider_id: Set(row.provider_id),
            user_id: Set(row.user_id),
            organization_id: Set(row.organization_id),
            oidc_config: Set(row.oidc_config),
            saml_config: Set(row.saml_config),
            domain_verified: Set(row.domain_verified),
        }
        .insert(self.scoped_connection())
        .await
        .map(Into::into)
        .map_err(map_db_err)
    }
    async fn get_sso_provider(&self, provider_id: &str) -> AuthResult<Option<SsoProvider>> {
        Entity::find()
            .filter(Column::ProviderId.eq(provider_id))
            .one(self.scoped_connection())
            .await
            .map(|row| row.map(Into::into))
            .map_err(map_db_err)
    }
    async fn list_sso_providers_by_user(&self, user_id: &str) -> AuthResult<Vec<SsoProvider>> {
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .limit(
                u64::try_from(self.config().advanced.database.default_find_many_limit)
                    .unwrap_or(u64::MAX),
            )
            .all(self.scoped_connection())
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
            .map_err(map_db_err)
    }
}
