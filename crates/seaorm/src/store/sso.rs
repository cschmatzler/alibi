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
impl<S: AuthSchema> SsoProviderStore for SeaOrmStore<S>
where
    S::Account: crate::schema::SeaOrmAccountModel,
{
    async fn delete_sso_provider_and_accounts(
        &self,
        id: &str,
        provider_id: &str,
    ) -> AuthResult<bool> {
        use crate::schema::SeaOrmAccountModel;
        use sea_orm::TransactionTrait;
        let tx = self.scoped_connection().begin().await.map_err(map_db_err)?;
        let outcome = async {
            let locked = Entity::update_many()
                .col_expr(
                    Column::ProviderId,
                    sea_orm::sea_query::Expr::value(provider_id),
                )
                .filter(Column::Id.eq(id))
                .filter(Column::ProviderId.eq(provider_id))
                .exec(&tx)
                .await
                .map_err(map_db_err)?;
            if locked.rows_affected == 0 {
                return Ok(false);
            }
            _ = <S::Account as SeaOrmAccountModel>::Entity::delete_many()
                .filter(S::Account::provider_id_column().eq(provider_id))
                .exec(&tx)
                .await
                .map_err(map_db_err)?;
            _ = Entity::delete_many()
                .filter(Column::Id.eq(id))
                .filter(Column::ProviderId.eq(provider_id))
                .exec(&tx)
                .await
                .map_err(map_db_err)?;
            Ok(true)
        }
        .await;
        match outcome {
            Ok(deleted) => {
                tx.commit().await.map_err(map_db_err)?;
                Ok(deleted)
            }
            Err(error) => {
                tx.rollback().await.map_err(map_db_err)?;
                Err(error)
            }
        }
    }
    async fn list_sso_providers(&self) -> AuthResult<Vec<SsoProvider>> {
        Entity::find()
            .limit(
                u64::try_from(self.config().advanced.database.default_find_many_limit)
                    .unwrap_or(u64::MAX),
            )
            .all(self.scoped_connection())
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
            .map_err(map_db_err)
    }
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
