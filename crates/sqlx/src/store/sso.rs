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
impl<S: AuthSchema> SsoProviderStore for SqlxStore<S>
where
    S::Account: crate::schema::SqlxAccountModel,
{
    async fn mark_sso_domain_verified(&self, id: &str, domain: &str) -> AuthResult<bool> {
        let mut sql = crate::sql::Sql::with(self.exec().engine(), "UPDATE ");
        sql.ident(Model::TABLE);
        sql.push(" SET ");
        sql.assign("domainVerified", true);
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "id", " = ", id);
        sql.push(" AND ");
        sql.compare(Model::TABLE, "domain", " = ", domain);
        self.exec().execute(sql).await.map(|changed| changed > 0)
    }
    async fn update_sso_provider(
        &self,
        id: &str,
        provider_id: &str,
        prepare: &alibi_core::store::SsoProviderUpdateWork,
    ) -> AuthResult<Option<SsoProvider>> {
        let tx = self.begin(true).await?;
        let exec = crate::pool::Exec::tx(&tx);
        let outcome = async {
            let Some(row) = self.lock_sso_provider_with(exec, id, provider_id).await? else {
                return Ok(None);
            };
            self.update_sso_provider_with(exec, prepare(&row)?).await
        }
        .await;
        match outcome {
            Ok(row) => {
                tx.commit().await?;
                Ok(row)
            }
            Err(error) => {
                tx.rollback().await?;
                Err(error)
            }
        }
    }
    async fn delete_sso_provider_and_accounts(
        &self,
        id: &str,
        provider_id: &str,
    ) -> AuthResult<bool> {
        let tx = self.begin(true).await?;
        let exec = crate::pool::Exec::tx(&tx);
        let outcome = self.delete_sso_provider_with(exec, id, provider_id).await;
        match outcome {
            Ok(value) => {
                tx.commit().await?;
                Ok(value)
            }
            Err(error) => {
                tx.rollback().await?;
                Err(error)
            }
        }
    }
    async fn list_sso_providers(&self) -> AuthResult<Vec<SsoProvider>> {
        let mut sql = provider_select(self.exec());
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
        insert_provider(self.exec(), &active).await.map(Into::into)
    }
    async fn get_sso_provider(&self, provider_id: &str) -> AuthResult<Option<SsoProvider>> {
        let mut sql = provider_select(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "providerId", " = ", provider_id);
        self.exec()
            .fetch_optional::<Model>(sql)
            .await
            .map(|row| row.map(Into::into))
    }
    async fn list_sso_providers_by_user(&self, user_id: &str) -> AuthResult<Vec<SsoProvider>> {
        let mut sql = provider_select(self.exec());
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

impl<S: AuthSchema> SqlxStore<S>
where
    S::Account: crate::schema::SqlxAccountModel,
{
    pub(super) async fn lock_sso_provider_with(
        &self,
        exec: crate::pool::Exec<'_>,
        id: &str,
        provider_id: &str,
    ) -> AuthResult<Option<SsoProvider>> {
        let mut lock = crate::sql::Sql::with(exec.engine(), "UPDATE ");
        lock.ident(Model::TABLE);
        lock.push(" SET ");
        lock.assign("providerId", provider_id);
        lock.push(" WHERE ");
        lock.compare(Model::TABLE, "id", " = ", id);
        lock.push(" AND ");
        lock.compare(Model::TABLE, "providerId", " = ", provider_id);
        if exec.execute(lock).await? == 0 {
            return Ok(None);
        }
        let mut read = provider_select(exec);
        read.push(" WHERE ");
        read.compare(Model::TABLE, "id", " = ", id);
        let row: SsoProvider = exec
            .fetch_optional::<Model>(read)
            .await?
            .ok_or_else(|| alibi_core::AuthError::not_found("Provider not found"))?
            .into();
        Ok(Some(row))
    }
    pub(super) async fn update_sso_provider_with(
        &self,
        exec: crate::pool::Exec<'_>,
        update: alibi_core::store::SsoProviderUpdate,
    ) -> AuthResult<Option<SsoProvider>> {
        use crate::schema::SqlxAccountModel;
        let id = update.provider.id.clone();
        let id = id.as_str();
        let provider_id = update.provider.provider_id.clone();
        let provider_id = provider_id.as_str();
        if update.identity_changed {
            let mut accounts = model::select_model::<S::Account>(exec);
            accounts.push(" WHERE ");
            accounts.compare_model::<S::Account>(
                <S::Account as SqlxModel>::TABLE,
                S::Account::provider_id_column(),
                " = ",
                provider_id,
            );
            accounts.push(" LIMIT 1");
            if exec.fetch_optional::<S::Account>(accounts).await?.is_some() {
                return Err(alibi_core::AuthError::Api {
                    status: 409,
                    code: None,
                    message:
                        "Cannot change SSO provider identity fields while linked accounts exist"
                            .into(),
                });
            }
        }
        let mut active = ActiveRow::new();
        active.set("id", id);
        active.set("issuer", update.provider.issuer);
        active.set("domain", update.provider.domain);
        active.set("oidcConfig", update.provider.oidc_config);
        active.set("samlConfig", update.provider.saml_config);
        active.set("domainVerified", update.provider.domain_verified);
        update_provider(exec, &active)
            .await
            .map(|row| row.map(Into::into))
    }
    pub(super) async fn delete_sso_provider_with(
        &self,
        exec: crate::pool::Exec<'_>,
        id: &str,
        provider_id: &str,
    ) -> AuthResult<bool> {
        use crate::schema::SqlxAccountModel;
        if self
            .lock_sso_provider_with(exec, id, provider_id)
            .await?
            .is_none()
        {
            return Ok(false);
        }
        let mut accounts = crate::sql::Sql::with(exec.engine(), "DELETE FROM ");
        accounts.ident(<S::Account as SqlxModel>::TABLE);
        accounts.push(" WHERE ");
        accounts.compare_model::<S::Account>(
            <S::Account as SqlxModel>::TABLE,
            S::Account::provider_id_column(),
            " = ",
            provider_id,
        );
        _ = exec.execute(accounts).await?;
        let mut provider = crate::sql::Sql::with(exec.engine(), "DELETE FROM ");
        provider.ident(Model::TABLE);
        provider.push(" WHERE ");
        provider.compare(Model::TABLE, "id", " = ", id);
        provider.push(" AND ");
        provider.compare(Model::TABLE, "providerId", " = ", provider_id);
        _ = exec.execute(provider).await?;
        Ok(true)
    }
}

fn provider_columns(sql: &mut crate::sql::Sql, qualified: bool) {
    for (index, column) in Model::COLUMN_NAMES.iter().enumerate() {
        if index > 0 {
            sql.push(", ");
        }
        if qualified {
            sql.column(Model::TABLE, column);
        } else {
            sql.ident(column);
        }
        sql.push(" AS ");
        sql.ident(column);
    }
}
fn provider_select(exec: crate::pool::Exec<'_>) -> crate::sql::Sql {
    let mut sql = crate::sql::Sql::with(exec.engine(), "SELECT ");
    provider_columns(&mut sql, true);
    sql.push(" FROM ");
    sql.ident(Model::TABLE);
    sql
}
async fn insert_provider(exec: crate::pool::Exec<'_>, active: &ActiveRow) -> AuthResult<Model> {
    let mut sql = crate::sql::Sql::with(exec.engine(), "INSERT INTO ");
    sql.ident(Model::TABLE);
    sql.push(" (");
    let fields = active.present().collect::<Vec<_>>();
    sql.column_list(&fields.iter().map(|(column, _)| *column).collect::<Vec<_>>());
    sql.push(") VALUES (");
    for (index, (column, value)) in fields.into_iter().enumerate() {
        if index > 0 {
            sql.push(", ");
        }
        model::bind_model_value::<Model>(&mut sql, column, value.clone());
    }
    sql.push(") RETURNING ");
    provider_columns(&mut sql, false);
    exec.fetch_optional::<Model>(sql)
        .await?
        .ok_or_else(|| alibi_core::AuthError::internal("Provider was not inserted"))
}
async fn update_provider(
    exec: crate::pool::Exec<'_>,
    active: &ActiveRow,
) -> AuthResult<Option<Model>> {
    let id = active
        .get("id")
        .and_then(crate::model::ActiveValue::value)
        .cloned()
        .ok_or_else(|| {
            alibi_core::AuthError::internal("Provider update requires its primary key")
        })?;
    let mut sql = crate::sql::Sql::with(exec.engine(), "UPDATE ");
    sql.ident(Model::TABLE);
    sql.push(" SET ");
    for (index, (column, value)) in active.changed().enumerate() {
        if index > 0 {
            sql.push(", ");
        }
        sql.ident(column);
        sql.push(" = ");
        model::bind_model_value::<Model>(&mut sql, column, value.clone());
    }
    sql.push(" WHERE ");
    sql.compare(Model::TABLE, "id", " = ", id);
    sql.push(" RETURNING ");
    provider_columns(&mut sql, false);
    exec.fetch_optional::<Model>(sql).await
}
