use super::entities::device_code::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err};
use crate::schema::AuthSchema;
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::store::DeviceCodeStore;
use alibi_core::types::{CreateDeviceCode, DeviceCode, UpdateDeviceCode};
use async_trait::async_trait;
use sea_orm::sea_query::{Alias, IntoIden, Query};
use sea_orm::sea_query::{Expr, ExprTrait};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter, Set,
    Statement,
};
use sea_orm::{IdenStatic, Iterable};
use uuid::Uuid;

#[async_trait]
impl<S> DeviceCodeStore for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        self.create_device_code_with_connection(
            self.scoped_connection(),
            input,
            serde_json::Map::new(),
        )
        .await
    }
    async fn create_device_code_with_fields(
        &self,
        input: CreateDeviceCode,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<DeviceCode> {
        self.create_device_code_with_connection(self.scoped_connection(), input, fields)
            .await
    }
    async fn device_code_fields(
        &self,
        id: &str,
    ) -> AuthResult<serde_json::Map<String, serde_json::Value>> {
        let connection = self.scoped_connection();
        let backend = connection.get_database_backend();
        let query = if backend == sea_orm::DbBackend::Postgres {
            "SELECT to_jsonb(t)::text AS fields FROM \"deviceCode\" t WHERE \"id\" = $1".to_owned()
        } else {
            let columns = connection
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT name FROM pragma_table_info('deviceCode')",
                ))
                .await
                .map_err(map_db_err)?;
            let columns = columns
                .into_iter()
                .map(|column| column.try_get::<String>("", "name"))
                .collect::<Result<Vec<_>, _>>()
                .map_err(map_db_err)?;
            let object = columns
                .iter()
                .map(|name| {
                    format!(
                        "'{}',\"{}\"",
                        name.replace('\'', "''"),
                        name.replace('"', "\"\"")
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("SELECT json_object({object}) AS fields FROM \"deviceCode\" WHERE \"id\" = ?")
        };
        let row = connection
            .query_one_raw(Statement::from_sql_and_values(
                backend,
                query,
                [id.to_owned().into()],
            ))
            .await
            .map_err(map_db_err)?;
        let mut fields = row
            .map(|row| {
                row.try_get::<String>("", "fields")
                    .map_err(map_db_err)
                    .and_then(|json| {
                        serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&json)
                            .map_err(Into::into)
                    })
            })
            .transpose()?
            .unwrap_or_default();
        fields.retain(|name, _| !Column::iter().any(|column| column.as_str() == name));
        Ok(fields)
    }
    async fn consume_device_code(
        &self,
        id: &str,
        status: &str,
        ownership: &serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<Option<DeviceCode>> {
        let backend = self.scoped_connection().get_database_backend();
        let mut query = Query::delete();
        _ = query
            .from_table(Entity)
            .and_where(Expr::col(Column::Id).eq(id))
            .and_where(Expr::col(Column::Status).eq(status));
        for (field, value) in ownership {
            let column = Expr::col(Alias::new(field));
            _ = query.and_where(if value.is_null() {
                column.is_null()
            } else {
                column.eq(device_field_expr(value.clone()))
            });
        }
        _ = query.returning(Query::returning().columns(Column::iter()));
        Entity::find()
            .from_raw_sql(backend.build(&query))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)
            .map(|row| row.as_ref().map(DeviceCode::from))
    }
    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        Entity::find()
            .filter(Column::DeviceCode.eq(device_code))
            .one(self.scoped_connection())
            .await
            .map(|model| model.map(|model| DeviceCode::from(&model)))
            .map_err(map_db_err)
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        Entity::find()
            .filter(Column::UserCode.eq(user_code))
            .one(self.scoped_connection())
            .await
            .map(|model| model.map(|model| DeviceCode::from(&model)))
            .map_err(map_db_err)
    }

    async fn update_device_code(
        &self,
        id: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::not_found("Device code not found"));
        };

        let mut active = model.into_active_model();
        if let Some(status) = update.status {
            active.status = Set(status);
        }
        if let Some(user_id) = update.user_id {
            active.user_id = Set(user_id);
        }
        if let Some(last_polled_at) = update.last_polled_at {
            active.last_polled_at = Set(last_polled_at);
        }

        active
            .update(self.scoped_connection())
            .await
            .map(|model| DeviceCode::from(&model))
            .map_err(map_db_err)
    }

    async fn update_device_code_if_status(
        &self,
        id: &str,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        let mut update_many = Entity::update_many();
        if let Some(status) = update.status {
            update_many = update_many.col_expr(Column::Status, Expr::value(status));
        }
        if let Some(user_id) = update.user_id {
            update_many = update_many.col_expr(Column::UserId, Expr::value(user_id));
        }
        if let Some(last_polled_at) = update.last_polled_at {
            update_many = update_many.col_expr(Column::LastPolledAt, Expr::value(last_polled_at));
        }

        update_many
            .filter(Column::Id.eq(id))
            .filter(Column::Status.eq(current_status))
            .exec(self.scoped_connection())
            .await
            .map(|result| result.rows_affected == 1)
            .map_err(map_db_err)
    }

    async fn claim_device_code(&self, id: &str, user_id: &str) -> AuthResult<bool> {
        Entity::update_many()
            .col_expr(Column::UserId, Expr::value(user_id))
            .filter(Column::Id.eq(id))
            .filter(Column::Status.eq("pending"))
            .filter(Column::UserId.is_null())
            .exec(self.scoped_connection())
            .await
            .map(|result| result.rows_affected == 1)
            .map_err(map_db_err)
    }

    async fn delete_device_code(&self, id: &str) -> AuthResult<()> {
        Entity::delete_by_id(id.to_owned())
            .exec(self.scoped_connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn delete_device_code_if_status(&self, id: &str, status: &str) -> AuthResult<bool> {
        Entity::delete_many()
            .filter(Column::Id.eq(id))
            .filter(Column::Status.eq(status))
            .exec(self.scoped_connection())
            .await
            .map(|result| result.rows_affected == 1)
            .map_err(map_db_err)
    }
}

impl<S: AuthSchema> SeaOrmStore<S> {
    async fn create_device_code_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        connection: &C,
        input: CreateDeviceCode,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<DeviceCode> {
        let active = ActiveModel {
            id: Set(self
                .generated_id(&self.db, "deviceCode", "deviceCode", "id")
                .await?
                .unwrap_or_else(|| Uuid::new_v4().to_string())),
            device_code: Set(input.device_code),
            user_code: Set(input.user_code),
            user_id: Set(input.user_id),
            expires_at: Set(input.expires_at),
            status: Set(input.status),
            last_polled_at: Set(input.last_polled_at),
            polling_interval: Set(input.polling_interval.map(crate::Integer::from)),
            client_id: Set(input.client_id),
            scope: Set(input.scope),
        };
        if fields.is_empty() {
            return active
                .insert(connection)
                .await
                .map(|model| DeviceCode::from(&model))
                .map_err(map_db_err);
        }
        if fields
            .keys()
            .any(|name| Column::iter().any(|column| column.as_str() == name))
        {
            return Err(AuthError::bad_request(
                "Application device fields cannot replace core columns",
            ));
        }
        let columns = Column::iter()
            .map(IntoIden::into_iden)
            .chain(fields.keys().map(|name| Alias::new(name).into_iden()))
            .collect::<Vec<_>>();
        let mut values = Column::iter()
            .map(|column| {
                active
                    .get(column)
                    .into_value()
                    .map(Expr::val)
                    .ok_or_else(|| AuthError::internal("Unstaged device column"))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        values.extend(fields.into_values().map(device_field_expr));
        let mut query = Query::insert();
        _ = query
            .into_table(Entity)
            .columns(columns)
            .values(values)
            .map_err(|error| AuthError::internal(error.to_string()))?
            .returning(Query::returning().columns(Column::iter()));
        Entity::find()
            .from_raw_sql(connection.get_database_backend().build(&query))
            .one(connection)
            .await
            .map_err(map_db_err)?
            .map(|model| DeviceCode::from(&model))
            .ok_or_else(|| AuthError::internal("Device code insertion returned no row"))
    }
}

fn device_field_expr(value: serde_json::Value) -> sea_orm::sea_query::Expr {
    match value {
        serde_json::Value::String(value) => Expr::val(value),
        serde_json::Value::Bool(value) => Expr::val(value),
        serde_json::Value::Number(value) => value.as_i64().map_or_else(
            || Expr::val(crate::Number(value.as_f64().unwrap_or_default())),
            Expr::val,
        ),
        serde_json::Value::Null => Expr::cust("NULL"),
        value => Expr::val(value),
    }
}
