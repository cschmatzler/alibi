use super::entities::passkey::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err};
use crate::schema::AuthSchema;
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::store::PasskeyStore;
use alibi_core::types::{CreatePasskey, Passkey, UpdatePasskeyAuthentication};
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter, Set,
};
use uuid::Uuid;

impl<S> SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
{
    pub(super) async fn create_passkey_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        input: CreatePasskey,
    ) -> AuthResult<Passkey> {
        let counter = i64::try_from(input.counter)
            .map_err(|_error| AuthError::bad_request("Passkey counter exceeds i64 range"))?;

        ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            name: Set(input.name),
            public_key: Set(input.public_key),
            user_id: Set(input.user_id),
            credential_id: Set(input.credential_id),
            counter: Set(counter),
            device_type: Set(input.device_type),
            backed_up: Set(input.backed_up),
            transports: Set(input.transports),
            credential: Set(input.credential),
            aaguid: Set(input.aaguid),
            created_at: Set(Utc::now()),
            updated_at: Set(Utc::now()),
        }
        .insert(db)
        .await
        .map(|model| Passkey::from(&model))
        .map_err(map_db_err)
    }
}

#[async_trait]
impl<S: AuthSchema + Send + Sync> PasskeyStore for SeaOrmStore<S> {
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        self.create_passkey_with_connection(self.connection(), input)
            .await
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Passkey::from(&model)))
            .map_err(map_db_err)
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        Entity::find()
            .filter(Column::CredentialId.eq(credential_id))
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Passkey::from(&model)))
            .map_err(map_db_err)
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .all(self.connection())
            .await
            .map(|models| models.iter().map(Passkey::from).collect())
            .map_err(map_db_err)
    }

    async fn update_passkey_authentication(
        &self,
        id: &str,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Option<Passkey>> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };

        let mut active = model.into_active_model();
        active.counter = Set(i64::try_from(update.counter)
            .map_err(|_error| AuthError::bad_request("Passkey counter exceeds i64 range"))?);
        active.backed_up = Set(update.backed_up);
        active.device_type = Set(update.device_type);
        active.credential = Set(update.credential);
        active.updated_at = Set(Utc::now());
        active
            .update(self.connection())
            .await
            .map(|model_2| Some(Passkey::from(&model_2)))
            .map_err(map_db_err)
    }

    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::not_found("Passkey not found"));
        };

        let mut active = model.into_active_model();
        active.name = Set(Some(name.to_owned()));
        active.updated_at = Set(Utc::now());
        active
            .update(self.connection())
            .await
            .map(|model_2| Passkey::from(&model_2))
            .map_err(map_db_err)
    }

    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        Entity::delete_by_id(id.to_owned())
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }
}
