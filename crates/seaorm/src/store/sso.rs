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
use sea_orm::{
    ColumnTrait, EntityTrait, ExprTrait, Iterable, QueryFilter, QuerySelect, QueryTrait, Select,
    Set,
};
#[async_trait]
impl<S: AuthSchema> SsoProviderStore for SeaOrmStore<S>
where
    S::Account: crate::schema::SeaOrmAccountModel,
{
    async fn mark_sso_domain_verified(&self, id: &str, domain: &str) -> AuthResult<bool> {
        Entity::update_many()
            .col_expr(
                Column::DomainVerified,
                sea_orm::sea_query::Expr::value(true),
            )
            .filter(Column::Id.eq(id))
            .filter(Column::Domain.eq(domain))
            .exec(self.scoped_connection())
            .await
            .map(|result| result.rows_affected > 0)
            .map_err(map_db_err)
    }
    async fn update_sso_provider(
        &self,
        id: &str,
        provider_id: &str,
        prepare: &alibi_core::store::SsoProviderUpdateWork,
    ) -> AuthResult<Option<SsoProvider>> {
        use sea_orm::TransactionTrait;
        let tx = self.scoped_connection().begin().await.map_err(map_db_err)?;
        let outcome = async {
            let Some(row) = self.lock_sso_provider_with(&tx, id, provider_id).await? else {
                return Ok(None);
            };
            self.update_sso_provider_with(&tx, prepare(&row)?).await
        }
        .await;
        match outcome {
            Ok(row) => {
                tx.commit().await.map_err(map_db_err)?;
                Ok(row)
            }
            Err(error) => {
                tx.rollback().await.map_err(map_db_err)?;
                Err(error)
            }
        }
    }
    async fn delete_sso_provider_and_accounts(
        &self,
        id: &str,
        provider_id: &str,
    ) -> AuthResult<bool> {
        use sea_orm::TransactionTrait;
        let tx = self.scoped_connection().begin().await.map_err(map_db_err)?;
        let outcome = self.delete_sso_provider_with(&tx, id, provider_id).await;
        match outcome {
            Ok(value) => {
                tx.commit().await.map_err(map_db_err)?;
                Ok(value)
            }
            Err(error) => {
                tx.rollback().await.map_err(map_db_err)?;
                Err(error)
            }
        }
    }
    async fn list_sso_providers(&self) -> AuthResult<Vec<SsoProvider>> {
        let rows = provider_select(
            &self.config.advanced.database.sso_provider_fields,
            self.scoped_connection().get_database_backend(),
        )
        .limit(
            u64::try_from(self.config().advanced.database.default_find_many_limit)
                .unwrap_or(u64::MAX),
        )
        .into_model::<ProviderRow>()
        .all(self.scoped_connection())
        .await
        .map_err(map_db_err)?;
        project_rows(rows, &self.config.advanced.database.sso_provider_fields).await
    }
    async fn create_sso_provider(&self, row: SsoProvider) -> AuthResult<SsoProvider> {
        let extra = alibi_core::store::prepare_sso_fields(
            &self.config.advanced.database.sso_provider_fields,
            &row.additional_fields,
            true,
        )
        .await?;
        let backend = self.scoped_connection().get_database_backend();
        let mut columns = Column::iter()
            .map(|column| sea_orm::sea_query::Alias::new(sea_orm::IdenStatic::as_str(&column)))
            .collect::<Vec<_>>();
        let mut values: Vec<sea_orm::Value> = vec![
            row.id.into(),
            row.issuer.into(),
            row.domain.into(),
            row.provider_id.into(),
            row.user_id.into(),
            row.organization_id.into(),
            row.oidc_config.into(),
            row.saml_config.into(),
            row.domain_verified.into(),
        ];
        let bindings = extra_bindings(
            &self.config.advanced.database.sso_provider_fields,
            &extra,
            backend,
        )?;
        for (column, value) in bindings {
            columns.push(sea_orm::sea_query::Alias::new(column));
            values.push(value);
        }
        let mut query = sea_orm::sea_query::Query::insert();
        _ = query
            .into_table(Entity)
            .columns(columns)
            .values_panic(values.into_iter().map(sea_orm::sea_query::Expr::value))
            .returning(provider_returning(
                &self.config.advanced.database.sso_provider_fields,
                backend,
            ));
        Entity::find()
            .from_raw_sql(backend.build(&query))
            .into_model::<ProviderRow>()
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| alibi_core::AuthError::internal("Provider was not inserted"))?
            .project(&self.config.advanced.database.sso_provider_fields)
            .await
    }
    async fn get_sso_provider(&self, provider_id: &str) -> AuthResult<Option<SsoProvider>> {
        let row = provider_select(
            &self.config.advanced.database.sso_provider_fields,
            self.scoped_connection().get_database_backend(),
        )
        .filter(Column::ProviderId.eq(provider_id))
        .into_model::<ProviderRow>()
        .one(self.scoped_connection())
        .await
        .map_err(map_db_err)?;
        project_row(row, &self.config.advanced.database.sso_provider_fields).await
    }
    async fn list_sso_providers_by_user(&self, user_id: &str) -> AuthResult<Vec<SsoProvider>> {
        let rows = provider_select(
            &self.config.advanced.database.sso_provider_fields,
            self.scoped_connection().get_database_backend(),
        )
        .filter(Column::UserId.eq(user_id))
        .limit(
            u64::try_from(self.config().advanced.database.default_find_many_limit)
                .unwrap_or(u64::MAX),
        )
        .into_model::<ProviderRow>()
        .all(self.scoped_connection())
        .await
        .map_err(map_db_err)?;
        project_rows(rows, &self.config.advanced.database.sso_provider_fields).await
    }
}

impl<S: AuthSchema> SeaOrmStore<S>
where
    S::Account: crate::schema::SeaOrmAccountModel,
{
    pub(super) async fn lock_sso_provider_with<C: sea_orm::ConnectionTrait>(
        &self,
        connection: &C,
        id: &str,
        provider_id: &str,
    ) -> AuthResult<Option<SsoProvider>> {
        let locked = Entity::update_many()
            .col_expr(
                Column::ProviderId,
                sea_orm::sea_query::Expr::value(provider_id),
            )
            .filter(Column::Id.eq(id))
            .filter(Column::ProviderId.eq(provider_id))
            .exec(connection)
            .await
            .map_err(map_db_err)?;
        if locked.rows_affected == 0 {
            return Ok(None);
        }
        let row: SsoProvider = provider_select(
            &self.config.advanced.database.sso_provider_fields,
            self.scoped_connection().get_database_backend(),
        )
        .filter(Column::Id.eq(id))
        .into_model::<ProviderRow>()
        .one(connection)
        .await
        .map_err(map_db_err)?
        .ok_or_else(|| alibi_core::AuthError::not_found("Provider not found"))?
        .project(&self.config.advanced.database.sso_provider_fields)
        .await?;
        Ok(Some(row))
    }
    pub(super) async fn update_sso_provider_with<C: sea_orm::ConnectionTrait>(
        &self,
        connection: &C,
        update: alibi_core::store::SsoProviderUpdate,
    ) -> AuthResult<Option<SsoProvider>> {
        use crate::schema::SeaOrmAccountModel;
        let id = update.provider.id.clone();
        let id = id.as_str();
        let provider_id = update.provider.provider_id.clone();
        let provider_id = provider_id.as_str();
        if update.identity_changed
            && <S::Account as SeaOrmAccountModel>::Entity::find()
                .filter(S::Account::provider_id_column().eq(provider_id))
                .one(connection)
                .await
                .map_err(map_db_err)?
                .is_some()
        {
            return Err(alibi_core::AuthError::Api {
                status: 409,
                code: None,
                message: "Cannot change SSO provider identity fields while linked accounts exist"
                    .into(),
            });
        }
        let extra = alibi_core::store::prepare_sso_fields(
            &self.config.advanced.database.sso_provider_fields,
            &update.additional_field_changes,
            false,
        )
        .await?;
        let active = sso_provider::ActiveModel {
            id: Set(id.into()),
            issuer: Set(update.provider.issuer),
            domain: Set(update.provider.domain),
            oidc_config: Set(update.provider.oidc_config),
            saml_config: Set(update.provider.saml_config),
            domain_verified: Set(update.provider.domain_verified),
            ..Default::default()
        };
        let mut query = Entity::update_many().set(active).filter(Column::Id.eq(id));
        let backend = connection.get_database_backend();
        let bindings = extra_bindings(
            &self.config.advanced.database.sso_provider_fields,
            &extra,
            backend,
        )?;
        let statement = QueryTrait::query(&mut query);
        for (column, value) in bindings {
            _ = statement.value(sea_orm::sea_query::Alias::new(column), value);
        }
        _ = statement.returning(provider_returning(
            &self.config.advanced.database.sso_provider_fields,
            backend,
        ));
        let row = Entity::find()
            .from_raw_sql(query.build(connection.get_database_backend()))
            .into_model::<ProviderRow>()
            .one(connection)
            .await
            .map_err(map_db_err)?;
        project_row(row, &self.config.advanced.database.sso_provider_fields).await
    }
    pub(super) async fn delete_sso_provider_with<C: sea_orm::ConnectionTrait>(
        &self,
        connection: &C,
        id: &str,
        provider_id: &str,
    ) -> AuthResult<bool> {
        use crate::schema::SeaOrmAccountModel;
        if self
            .lock_sso_provider_with(connection, id, provider_id)
            .await?
            .is_none()
        {
            return Ok(false);
        }
        _ = <S::Account as SeaOrmAccountModel>::Entity::delete_many()
            .filter(S::Account::provider_id_column().eq(provider_id))
            .exec(connection)
            .await
            .map_err(map_db_err)?;
        _ = Entity::delete_many()
            .filter(Column::Id.eq(id))
            .filter(Column::ProviderId.eq(provider_id))
            .exec(connection)
            .await
            .map_err(map_db_err)?;
        Ok(true)
    }
}

#[derive(sea_orm::FromQueryResult)]
struct ProviderRow {
    #[sea_orm(nested)]
    model: sso_provider::Model,
    __alibi_sso_fields: String,
}
impl ProviderRow {
    async fn project(
        self,
        fields: &alibi_core::field_policy::SessionFields,
    ) -> AuthResult<SsoProvider> {
        alibi_core::store::project_sso_provider(fields, self.into_provider()?).await
    }
    fn into_provider(self) -> AuthResult<SsoProvider> {
        let mut provider: SsoProvider = self.model.into();
        provider.additional_fields = serde_json::from_str(&self.__alibi_sso_fields)?;
        Ok(provider)
    }
}
fn extra_projection(
    fields: &alibi_core::field_policy::SessionFields,
    backend: sea_orm::DbBackend,
    qualified: bool,
) -> sea_orm::sea_query::SimpleExpr {
    use alibi_core::store::{SsoFieldType, sso_field_column};
    let postgres = backend == sea_orm::DbBackend::Postgres;
    let quote = |name: &str| format!("\"{}\"", name.replace('"', "\"\""));
    let mut args = Vec::new();
    for (name, field) in &fields.0 {
        args.push(format!("'{}'", name.replace('\'', "''")));
        let column = quote(sso_field_column(name, field));
        let column = if qualified {
            format!("\"ssoProvider\".{column}")
        } else {
            column
        };
        let value = if !postgres && SsoFieldType::from_config(field) == SsoFieldType::Boolean {
            format!(
                "json(CASE WHEN {column} IS NULL THEN 'null' WHEN {column} THEN 'true' ELSE 'false' END)"
            )
        } else if !postgres && SsoFieldType::from_config(field) == SsoFieldType::Json {
            format!("json({column})")
        } else {
            column
        };
        args.push(value);
    }
    sea_orm::sea_query::Expr::cust(format!(
        "CAST({}({}) AS TEXT)",
        if postgres {
            "jsonb_build_object"
        } else {
            "json_object"
        },
        args.join(", ")
    ))
}
fn provider_select(
    fields: &alibi_core::field_policy::SessionFields,
    backend: sea_orm::DbBackend,
) -> Select<Entity> {
    use sea_orm::sea_query::Expr;
    let mut select = Entity::find().select_only();
    for column in Column::iter() {
        select = select.column_as(Expr::col((Entity, column)), column);
    }
    select.expr_as(
        extra_projection(fields, backend, true),
        "__alibi_sso_fields",
    )
}
fn provider_returning(
    fields: &alibi_core::field_policy::SessionFields,
    backend: sea_orm::DbBackend,
) -> sea_orm::sea_query::ReturningClause {
    use sea_orm::{
        IdenStatic,
        sea_query::{Expr, Query},
    };
    let mut expressions = Column::iter()
        .map(|column| {
            let name = column.as_str();
            Expr::cust(format!("\"{name}\" AS \"{name}\""))
        })
        .collect::<Vec<_>>();
    expressions.push(extra_projection(fields, backend, false).binary(
        sea_orm::sea_query::BinOper::As,
        Expr::cust("\"__alibi_sso_fields\""),
    ));
    Query::returning().exprs(expressions)
}
fn extra_bindings(
    fields: &alibi_core::field_policy::SessionFields,
    extra: &serde_json::Map<String, serde_json::Value>,
    backend: sea_orm::DbBackend,
) -> AuthResult<Vec<(String, sea_orm::Value)>> {
    use alibi_core::store::{SsoFieldType, sso_field_column};
    let mut bindings = Vec::new();
    for (name, field) in &fields.0 {
        if let Some(value) = extra.get(name) {
            let value = match SsoFieldType::from_config(field) {
                SsoFieldType::String | SsoFieldType::Date => {
                    sea_orm::Value::String(value.as_str().map(str::to_owned))
                }
                SsoFieldType::Boolean => sea_orm::Value::Bool(value.as_bool()),
                SsoFieldType::Number => sea_orm::Value::Double(value.as_f64()),
                SsoFieldType::Json => {
                    if backend == sea_orm::DbBackend::Sqlite {
                        sea_orm::Value::String(Some(alibi_core::utils::json::to_string(value)?))
                    } else {
                        sea_orm::Value::Json(Some(Box::new(value.clone())))
                    }
                }
            };
            bindings.push((sso_field_column(name, field).to_owned(), value));
        }
    }
    Ok(bindings)
}

async fn project_row(
    row: Option<ProviderRow>,
    fields: &alibi_core::field_policy::SessionFields,
) -> AuthResult<Option<SsoProvider>> {
    match row {
        Some(row) => Ok(Some(row.project(fields).await?)),
        None => Ok(None),
    }
}
async fn project_rows(
    rows: Vec<ProviderRow>,
    fields: &alibi_core::field_policy::SessionFields,
) -> AuthResult<Vec<SsoProvider>> {
    let mut providers = Vec::with_capacity(rows.len());
    for row in rows {
        providers.push(row.project(fields).await?);
    }
    Ok(providers)
}
