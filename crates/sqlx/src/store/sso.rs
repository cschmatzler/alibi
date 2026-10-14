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
        let field = self
            .config()
            .advanced
            .database
            .sso_provider
            .as_ref()
            .map_or("domain", |mapping| mapping.predicate_field("domain"));
        sql.compare(Model::TABLE, field, " = ", domain);
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
        let rows = self.exec().fetch_all::<ProviderRow>(sql).await?;
        project_rows(rows, self.exec()).await
    }
    async fn create_sso_provider(&self, row: SsoProvider) -> AuthResult<SsoProvider> {
        let extra = prepare_fields(self.exec(), &row.additional_fields, true).await?;
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
        insert_provider(self.exec(), &active, &extra).await
    }
    async fn get_sso_provider(&self, provider_id: &str) -> AuthResult<Option<SsoProvider>> {
        let mut sql = provider_select(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "providerId", " = ", provider_id);
        let row = self.exec().fetch_optional::<ProviderRow>(sql).await?;
        project_row(row, self.exec()).await
    }
    async fn list_sso_providers_by_user(&self, user_id: &str) -> AuthResult<Vec<SsoProvider>> {
        let mut sql = provider_select(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "userId", " = ", user_id);
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        let rows = self.exec().fetch_all::<ProviderRow>(sql).await?;
        project_rows(rows, self.exec()).await
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
            .fetch_optional::<ProviderRow>(read)
            .await?
            .ok_or_else(|| alibi_core::AuthError::not_found("Provider not found"))?
            .project(exec)
            .await?;
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
        let extra = prepare_fields(exec, &update.additional_field_changes, false).await?;
        let mut active = ActiveRow::new();
        active.set("id", id);
        active.set("issuer", update.provider.issuer);
        active.set("domain", update.provider.domain);
        active.set("oidcConfig", update.provider.oidc_config);
        active.set("samlConfig", update.provider.saml_config);
        active.set("domainVerified", update.provider.domain_verified);
        update_provider(exec, &active, &extra).await
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

#[derive(sqlx::FromRow)]
struct ProviderRow {
    #[sqlx(flatten)]
    model: Model,
    __alibi_sso_fields: String,
}
impl ProviderRow {
    async fn project(self, exec: crate::pool::Exec<'_>) -> AuthResult<SsoProvider> {
        let provider = self.into_provider()?;
        match exec.sso_fields() {
            Some(fields) => alibi_core::store::project_sso_provider(fields, provider).await,
            None => Ok(provider),
        }
    }
    fn into_provider(self) -> AuthResult<SsoProvider> {
        let mut provider: SsoProvider = self.model.into();
        provider.additional_fields = serde_json::from_str(&self.__alibi_sso_fields)?;
        Ok(provider)
    }
}
fn provider_columns(
    sql: &mut crate::sql::Sql,
    qualified: bool,
    fields: Option<&alibi_core::field_policy::SessionFields>,
) {
    use alibi_core::store::{SsoFieldType, sso_field_column};
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
    sql.push(", CAST(");
    let postgres = sql.engine() == crate::pool::Engine::Postgres;
    sql.push(if postgres {
        "jsonb_build_object("
    } else {
        "json_object("
    });
    if let Some(fields) = fields {
        for (index, (name, field)) in fields.0.iter().enumerate() {
            if index > 0 {
                sql.push(", ");
            }
            sql.bind(name);
            sql.push(", ");
            let kind = SsoFieldType::from_config(field);
            let emit = |sql: &mut crate::sql::Sql| {
                let column = sso_field_column(name, field);
                if qualified {
                    sql.column(Model::TABLE, column);
                } else {
                    sql.ident(column);
                }
            };
            if !postgres && kind == SsoFieldType::Boolean {
                sql.push("json(CASE WHEN ");
                emit(sql);
                sql.push(" IS NULL THEN 'null' WHEN ");
                emit(sql);
                sql.push(" THEN 'true' ELSE 'false' END)");
            } else if !postgres && kind == SsoFieldType::Json {
                sql.push("json(");
                emit(sql);
                sql.push(")");
            } else {
                emit(sql);
            }
        }
    }
    sql.push(") AS TEXT) AS ");
    sql.ident("__alibi_sso_fields");
}
fn provider_select(exec: crate::pool::Exec<'_>) -> crate::sql::Sql {
    let mut sql = crate::sql::Sql::with(exec.engine(), "SELECT ");
    provider_columns(&mut sql, true, exec.sso_fields());
    sql.push(" FROM ");
    sql.ident(Model::TABLE);
    sql
}
async fn extra_bindings(
    exec: crate::pool::Exec<'_>,
    extra: &serde_json::Map<String, serde_json::Value>,
) -> AuthResult<Vec<(String, crate::value::SqlValue)>> {
    use crate::value::ColumnKind;
    use alibi_core::store::{SsoFieldType, sso_field_column};
    let mut values = Vec::new();
    if let Some(fields) = exec.sso_fields() {
        for (name, field) in &fields.0 {
            if let Some(value) = extra.get(name) {
                if SsoFieldType::from_config(field) == SsoFieldType::Date {
                    let date = value
                        .as_str()
                        .map(|value| {
                            chrono::DateTime::parse_from_rfc3339(value)
                                .map(|date| date.with_timezone(&chrono::Utc))
                        })
                        .transpose()
                        .map_err(|error| alibi_core::AuthError::internal(error.to_string()))?;
                    values.push((
                        sso_field_column(name, field).to_owned(),
                        crate::value::SqlValue::Timestamp(date),
                    ));
                    continue;
                }
                let kind = match SsoFieldType::from_config(field) {
                    SsoFieldType::String => ColumnKind::Text,
                    SsoFieldType::Boolean => ColumnKind::Boolean,
                    SsoFieldType::Number => ColumnKind::Number,
                    SsoFieldType::Json => ColumnKind::Json,
                    SsoFieldType::Date => ColumnKind::Other,
                };
                let raw = crate::additional_fields::raw_value(
                    &alibi_core::utils::json::JsValue::from(value.clone()),
                )?;
                values.push((
                    sso_field_column(name, field).to_owned(),
                    crate::additional_fields::prepare_value(exec, kind, raw).await?,
                ));
            }
        }
    }
    Ok(values)
}
async fn insert_provider(
    exec: crate::pool::Exec<'_>,
    active: &ActiveRow,
    extra: &serde_json::Map<String, serde_json::Value>,
) -> AuthResult<SsoProvider> {
    let mut sql = crate::sql::Sql::with(exec.engine(), "INSERT INTO ");
    sql.ident(Model::TABLE);
    sql.push(" (");
    let mut fields = active
        .present()
        .map(|(column, value)| (column.to_owned(), value.clone()))
        .collect::<Vec<_>>();
    fields.extend(extra_bindings(exec, extra).await?);
    sql.column_list(
        &fields
            .iter()
            .map(|(column, _)| column.as_str())
            .collect::<Vec<_>>(),
    );
    sql.push(") VALUES (");
    for (index, (column, value)) in fields.into_iter().enumerate() {
        if index > 0 {
            sql.push(", ");
        }
        if Model::COLUMN_NAMES.contains(&column.as_str()) {
            model::bind_model_value::<Model>(&mut sql, &column, value);
        } else {
            sql.bind(value);
        }
    }
    sql.push(") RETURNING ");
    provider_columns(&mut sql, false, exec.sso_fields());
    exec.fetch_optional::<ProviderRow>(sql)
        .await?
        .ok_or_else(|| alibi_core::AuthError::internal("Provider was not inserted"))?
        .project(exec)
        .await
}
async fn update_provider(
    exec: crate::pool::Exec<'_>,
    active: &ActiveRow,
    extra: &serde_json::Map<String, serde_json::Value>,
) -> AuthResult<Option<SsoProvider>> {
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
    let mut fields = active
        .changed()
        .map(|(column, value)| (column.to_owned(), value.clone()))
        .collect::<Vec<_>>();
    fields.extend(extra_bindings(exec, extra).await?);
    for (index, (column, value)) in fields.into_iter().enumerate() {
        if index > 0 {
            sql.push(", ");
        }
        sql.ident(&column);
        sql.push(" = ");
        if Model::COLUMN_NAMES.contains(&column.as_str()) {
            model::bind_model_value::<Model>(&mut sql, &column, value);
        } else {
            sql.bind(value);
        }
    }
    sql.push(" WHERE ");
    sql.compare(Model::TABLE, "id", " = ", id);
    sql.push(" RETURNING ");
    provider_columns(&mut sql, false, exec.sso_fields());
    let row = exec.fetch_optional::<ProviderRow>(sql).await?;
    project_row(row, exec).await
}

async fn project_row(
    row: Option<ProviderRow>,
    exec: crate::pool::Exec<'_>,
) -> AuthResult<Option<SsoProvider>> {
    match row {
        Some(row) => Ok(Some(row.project(exec).await?)),
        None => Ok(None),
    }
}
async fn project_rows(
    rows: Vec<ProviderRow>,
    exec: crate::pool::Exec<'_>,
) -> AuthResult<Vec<SsoProvider>> {
    let mut providers = Vec::with_capacity(rows.len());
    for row in rows {
        providers.push(row.project(exec).await?);
    }
    Ok(providers)
}
async fn prepare_fields(
    exec: crate::pool::Exec<'_>,
    fields: &serde_json::Map<String, serde_json::Value>,
    create: bool,
) -> AuthResult<serde_json::Map<String, serde_json::Value>> {
    match exec.sso_fields() {
        Some(policy) => alibi_core::store::prepare_sso_fields(policy, fields, create).await,
        None => Ok(fields.clone()),
    }
}
