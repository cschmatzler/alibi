use super::{SqlxStore, entities::sso_provider::Model};
use crate::{
    model::{self, ActiveRow, SqlxModel},
    schema::AuthSchema,
};
use alibi_core::{
    AuthResult,
    store::{SsoProvider, SsoProviderStore},
};
use async_trait::async_trait;
#[async_trait]
impl<S: AuthSchema> SsoProviderStore for SqlxStore<S> {
    async fn list_sso_providers(&self) -> AuthResult<Vec<SsoProvider>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        self.exec()
            .fetch_all::<Model>(sql)
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }
    async fn create_sso_provider(&self, row: SsoProvider) -> AuthResult<SsoProvider> {
        let mut active = ActiveRow::new();
        active.set("id", row.id);
        active.set("issuer", row.issuer);
        active.set("domain", row.domain);
        active.set("providerId", row.provider_id);
        active.set("userId", row.user_id);
        active.set("organizationId", row.organization_id);
        active.set("oidcConfig", row.oidc_config);
        active.set("samlConfig", row.saml_config);
        active.set("domainVerified", row.domain_verified);
        model::insert::<Model>(self.exec(), &active)
            .await
            .map(Into::into)
    }
    async fn get_sso_provider(&self, provider_id: &str) -> AuthResult<Option<SsoProvider>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "providerId", " = ", provider_id);
        self.exec()
            .fetch_optional::<Model>(sql)
            .await
            .map(|row| row.map(Into::into))
    }
    async fn list_sso_providers_by_user(&self, user_id: &str) -> AuthResult<Vec<SsoProvider>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "userId", " = ", user_id);
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        self.exec()
            .fetch_all::<Model>(sql)
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
    }
}
