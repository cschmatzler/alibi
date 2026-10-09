use super::entities::device_code::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err};
use crate::schema::AuthSchema;
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::store::DeviceCodeStore;
use alibi_core::types::{CreateDeviceCode, DeviceCode, UpdateDeviceCode};
use async_trait::async_trait;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter, Set,
    Statement, TransactionTrait,
};
use std::fmt::Write as _;
use uuid::Uuid;

#[async_trait]
impl<S> DeviceCodeStore for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        self.create_device_code_with_connection(self.scoped_connection(), input)
            .await
    }
    async fn create_device_code_with_fields(
        &self,
        input: CreateDeviceCode,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<DeviceCode> {
        if fields.is_empty() {
            return self.create_device_code(input).await;
        }
        let transaction = self.scoped_connection().begin().await.map_err(map_db_err)?;
        _ = transaction.execute_unprepared("CREATE TABLE IF NOT EXISTS device_code_fields (device_code_id TEXT PRIMARY KEY REFERENCES device_code(id) ON DELETE CASCADE, fields TEXT NOT NULL)").await.map_err(map_db_err)?;
        let row = self
            .create_device_code_with_connection(&transaction, input)
            .await?;
        let backend = transaction.get_database_backend();
        let sql = if backend == sea_orm::DbBackend::Postgres {
            "INSERT INTO device_code_fields (device_code_id, fields) VALUES ($1, $2)"
        } else {
            "INSERT INTO device_code_fields (device_code_id, fields) VALUES (?, ?)"
        };
        _ = transaction
            .execute_raw(Statement::from_sql_and_values(
                backend,
                sql,
                [
                    row.id.clone().into(),
                    serde_json::to_string(&fields)?.into(),
                ],
            ))
            .await
            .map_err(map_db_err)?;
        transaction.commit().await.map_err(map_db_err)?;
        Ok(row)
    }
    async fn device_code_fields(
        &self,
        id: &str,
    ) -> AuthResult<serde_json::Map<String, serde_json::Value>> {
        if !self
            .scoped_connection()
            .has_table("device_code_fields")
            .await
            .map_err(map_db_err)?
        {
            return Ok(serde_json::Map::new());
        }
        let backend = self.scoped_connection().get_database_backend();
        let sql = if backend == sea_orm::DbBackend::Postgres {
            "SELECT fields FROM device_code_fields WHERE device_code_id = $1"
        } else {
            "SELECT fields FROM device_code_fields WHERE device_code_id = ?"
        };
        let row = self
            .scoped_connection()
            .query_one_raw(Statement::from_sql_and_values(
                backend,
                sql,
                [id.to_owned().into()],
            ))
            .await
            .map_err(map_db_err)?;
        row.map(|row| {
            row.try_get::<String>("", "fields")
                .map_err(map_db_err)
                .and_then(|fields| serde_json::from_str(&fields).map_err(Into::into))
        })
        .transpose()
        .map(Option::unwrap_or_default)
    }
    async fn consume_device_code(
        &self,
        id: &str,
        status: &str,
        ownership: &serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<Option<DeviceCode>> {
        let backend = self.scoped_connection().get_database_backend();
        let mut values: Vec<sea_orm::Value> = Vec::new();
        let mut bind = |value: String| {
            values.push(value.into());
            if backend == sea_orm::DbBackend::Postgres {
                format!("${}", values.len())
            } else {
                "?".into()
            }
        };
        let mut sql = format!(
            "DELETE FROM device_code WHERE id = {} AND status = {}",
            bind(id.into()),
            bind(status.into())
        );
        for (field, value) in ownership {
            sql.push_str(" AND EXISTS (SELECT 1 FROM device_code_fields WHERE device_code_id = device_code.id AND ");
            if backend == sea_orm::DbBackend::Postgres {
                _ = write!(
                    sql,
                    "CAST(fields AS JSONB) -> {} = CAST({} AS JSONB)",
                    bind(field.clone()),
                    bind(value.to_string())
                );
            } else {
                _ = write!(
                    sql,
                    "json_extract(fields, {}) IS json_extract({}, '$')",
                    bind(format!("$.{}", serde_json::to_string(field)?)),
                    bind(value.to_string())
                );
            }
            sql.push(')');
        }
        sql.push_str(" RETURNING *");
        Entity::find()
            .from_raw_sql(Statement::from_sql_and_values(backend, sql, values))
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
    ) -> AuthResult<DeviceCode> {
        ActiveModel {
            id: Set(self
                .generated_id(&self.db, "deviceCode", "device_code", "id")
                .await?
                .unwrap_or_else(|| Uuid::new_v4().to_string())),
            device_code: Set(input.device_code),
            user_code: Set(input.user_code),
            user_id: Set(input.user_id),
            expires_at: Set(input.expires_at),
            status: Set(input.status),
            last_polled_at: Set(input.last_polled_at),
            polling_interval: Set(input.polling_interval),
            client_id: Set(input.client_id),
            scope: Set(input.scope),
        }
        .insert(connection)
        .await
        .map(|model| DeviceCode::from(&model))
        .map_err(map_db_err)
    }
}
