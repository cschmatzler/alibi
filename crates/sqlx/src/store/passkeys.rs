use super::SqlxStore;
use super::entities::passkey::Model;
use crate::error::record_not_updated;
use crate::model::{self, ActiveRow, SqlxModel};
use crate::pool::Exec;
use crate::schema::AuthSchema;
use async_trait::async_trait;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::PasskeyStore;
use better_auth_core::types::{CreatePasskey, Passkey, UpdatePasskeyAuthentication};
use chrono::Utc;
use uuid::Uuid;

impl<S> SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
{
    pub(super) async fn create_passkey_with_connection(
        &self,
        exec: Exec<'_>,
        input: CreatePasskey,
    ) -> AuthResult<Passkey> {
        let counter = i64::try_from(input.counter)
            .map_err(|_error| AuthError::bad_request("Passkey counter exceeds i64 range"))?;

        let mut active = ActiveRow::new();
        active.set("id", Uuid::new_v4().to_string());
        active.set("name", input.name);
        active.set("public_key", input.public_key);
        active.set("user_id", input.user_id);
        active.set("credential_id", input.credential_id);
        active.set("counter", counter);
        active.set("device_type", input.device_type);
        active.set("backed_up", input.backed_up);
        active.set("transports", input.transports);
        active.set("credential", input.credential);
        active.set("aaguid", input.aaguid);
        active.set("created_at", Utc::now());
        active.set("updated_at", Utc::now());
        model::insert::<Model>(exec, &active)
            .await
            .map(|model| Passkey::from(&model))
    }

    async fn find_passkey(&self, id: &str) -> AuthResult<Option<Model>> {
        let mut sql = model::by_id::<Model>(self.exec(), id);
        model::limit_one(&mut sql);
        self.exec().fetch_optional(sql).await
    }
}

#[async_trait]
impl<S: AuthSchema + Send + Sync> PasskeyStore for SqlxStore<S> {
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        self.create_passkey_with_connection(self.exec(), input)
            .await
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        Ok(self
            .find_passkey(id)
            .await?
            .map(|model| Passkey::from(&model)))
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ")
            .column(Model::TABLE, "credential_id")
            .push(" = ")
            .bind(credential_id);
        model::limit_one(&mut sql);
        Ok(self
            .exec()
            .fetch_optional::<Model>(sql)
            .await?
            .map(|model| Passkey::from(&model)))
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ")
            .column(Model::TABLE, "user_id")
            .push(" = ")
            .bind(user_id)
            .push(" ORDER BY ")
            .column(Model::TABLE, "created_at")
            .push(" DESC");
        Ok(self
            .exec()
            .fetch_all::<Model>(sql)
            .await?
            .iter()
            .map(Passkey::from)
            .collect())
    }

    async fn update_passkey_authentication(
        &self,
        id: &str,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Option<Passkey>> {
        let Some(model) = self.find_passkey(id).await? else {
            return Ok(None);
        };

        let mut active = model.into_active();
        active.set(
            "counter",
            i64::try_from(update.counter)
                .map_err(|_error| AuthError::bad_request("Passkey counter exceeds i64 range"))?,
        );
        active.set("backed_up", update.backed_up);
        active.set("device_type", update.device_type);
        active.set("credential", update.credential);
        active.set("updated_at", Utc::now());
        model::update::<Model>(self.exec(), &active)
            .await?
            .map(|model_2| Some(Passkey::from(&model_2)))
            .ok_or_else(record_not_updated)
    }

    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey> {
        let Some(model) = self.find_passkey(id).await? else {
            return Err(AuthError::not_found("Passkey not found"));
        };

        let mut active = model.into_active();
        active.set("name", Some(name.to_owned()));
        active.set("updated_at", Utc::now());
        model::update::<Model>(self.exec(), &active)
            .await?
            .map(|model_2| Passkey::from(&model_2))
            .ok_or_else(record_not_updated)
    }

    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        self.exec()
            .execute(model::delete_by_id::<Model>(self.exec(), id))
            .await
            .map(drop)
    }
}
