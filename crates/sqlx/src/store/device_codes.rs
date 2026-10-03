use super::SqlxStore;
use super::entities::device_code::Model;
use crate::error::record_not_updated;
use crate::model::{self, ActiveRow, SqlxModel};
use crate::schema::AuthSchema;
use crate::sql::Sql;
use crate::value::SqlValue;
use async_trait::async_trait;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::DeviceCodeStore;
use better_auth_core::types::{CreateDeviceCode, DeviceCode, UpdateDeviceCode};
use uuid::Uuid;

impl<S: AuthSchema + Send + Sync> SqlxStore<S> {
    async fn find_device_code(&self, column: &str, value: &str) -> AuthResult<Option<DeviceCode>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, column, " = ", value);
        model::limit_one(&mut sql);
        Ok(self
            .exec()
            .fetch_optional::<Model>(sql)
            .await?
            .map(|model| DeviceCode::from(&model)))
    }

    /// `UPDATE device_code SET ... WHERE id = ? AND ...`, returning the affected count.
    async fn update_device_codes(
        &self,
        sets: Vec<(&'static str, SqlValue)>,
        guards: Vec<(&'static str, Option<SqlValue>)>,
    ) -> AuthResult<u64> {
        let mut sql = Sql::with(self.exec().engine(), "UPDATE ");
        sql.ident(Model::TABLE);
        sql.push(" SET ");
        for (index, (column, value)) in sets.into_iter().enumerate() {
            if index > 0 {
                sql.push(", ");
            }
            sql.assign(column, value);
        }
        for (index, (column, value)) in guards.into_iter().enumerate() {
            sql.push(if index == 0 { " WHERE " } else { " AND " });
            sql.column(Model::TABLE, column);
            match value {
                Some(value) => {
                    sql.push(" = ");
                    sql.bind(value);
                }
                None => {
                    sql.push(" IS NULL");
                }
            }
        }
        self.exec().execute(sql).await
    }
}

#[async_trait]
impl<S> DeviceCodeStore for SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        let mut active = ActiveRow::new();
        active.set("id", Uuid::new_v4().to_string());
        active.set("device_code", input.device_code);
        active.set("user_code", input.user_code);
        active.set("user_id", input.user_id);
        active.set("expires_at", input.expires_at);
        active.set("status", input.status);
        active.set("last_polled_at", input.last_polled_at);
        active.set("polling_interval", input.polling_interval);
        active.set("client_id", input.client_id);
        active.set("scope", input.scope);
        model::insert::<Model>(self.exec(), &active)
            .await
            .map(|model| DeviceCode::from(&model))
    }

    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.find_device_code("device_code", device_code).await
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.find_device_code("user_code", user_code).await
    }

    async fn update_device_code(
        &self,
        id: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let mut sql = model::by_id::<Model>(self.exec(), id);
        model::limit_one(&mut sql);
        let Some(model) = self.exec().fetch_optional::<Model>(sql).await? else {
            return Err(AuthError::not_found("Device code not found"));
        };

        let mut active = model.into_active();
        if let Some(status) = update.status {
            active.set("status", status);
        }
        if let Some(user_id) = update.user_id {
            active.set("user_id", user_id);
        }
        if let Some(last_polled_at) = update.last_polled_at {
            active.set("last_polled_at", last_polled_at);
        }

        model::update::<Model>(self.exec(), &active)
            .await?
            .map(|model_2| DeviceCode::from(&model_2))
            .ok_or_else(record_not_updated)
    }

    async fn update_device_code_if_status(
        &self,
        id: &str,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        let mut sets = Vec::new();
        if let Some(status) = update.status {
            sets.push(("status", status.into()));
        }
        if let Some(user_id) = update.user_id {
            sets.push(("user_id", user_id.into()));
        }
        if let Some(last_polled_at) = update.last_polled_at {
            sets.push(("last_polled_at", last_polled_at.into()));
        }
        self.update_device_codes(
            sets,
            vec![
                ("id", Some(id.into())),
                ("status", Some(current_status.into())),
            ],
        )
        .await
        .map(|affected| affected == 1)
    }

    async fn claim_device_code(&self, id: &str, user_id: &str) -> AuthResult<bool> {
        self.update_device_codes(
            vec![("user_id", user_id.into())],
            vec![
                ("id", Some(id.into())),
                ("status", Some("pending".into())),
                ("user_id", None),
            ],
        )
        .await
        .map(|affected| affected == 1)
    }

    async fn delete_device_code(&self, id: &str) -> AuthResult<()> {
        self.exec()
            .execute(model::delete_by_id::<Model>(self.exec(), id))
            .await
            .map(drop)
    }

    async fn delete_device_code_if_status(&self, id: &str, status: &str) -> AuthResult<bool> {
        let mut sql = model::delete_by_id::<Model>(self.exec(), id);
        sql.push(" AND ");
        sql.compare(Model::TABLE, "status", " = ", status);
        self.exec().execute(sql).await.map(|affected| affected == 1)
    }
}
