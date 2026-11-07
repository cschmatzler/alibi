use super::entities::passkey::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err};
use crate::schema::AuthSchema;
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::store::PasskeyStore;
use alibi_core::types::{CreatePasskey, Passkey, UpdatePasskeyAuthentication};
use async_trait::async_trait;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter, Set,
};
use uuid::Uuid;

async fn optional_text<C: ConnectionTrait>(
    db: &C,
    value: alibi_core::utils::json::JsValue,
) -> AuthResult<sea_orm::ActiveValue<Option<String>>> {
    if value.is_undefined() {
        return Ok(sea_orm::NotSet);
    }
    Ok(Set(crate::additional_fields::prepare_string_value(
        db,
        if db.get_database_backend() == sea_orm::DbBackend::Sqlite {
            match &value {
                alibi_core::utils::json::JsValue::Date(_) => {
                    return Err(AuthError::internal(
                        "Date cannot bind to a SQLite text field",
                    ));
                }
                alibi_core::utils::json::JsValue::Number(value) => {
                    alibi_core::store::adapter::RawFieldValue::Number(*value)
                }
                alibi_core::utils::json::JsValue::Bool(value) => {
                    alibi_core::store::adapter::RawFieldValue::Number(f64::from(*value))
                }
                _ => crate::additional_fields::raw_value(&value)?,
            }
        } else {
            crate::additional_fields::raw_value(&value)?
        },
    )
    .await?))
}

impl<S> SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
{
    pub(super) async fn create_passkey_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        mut input: CreatePasskey,
    ) -> AuthResult<Passkey> {
        input.normalize_created_at()?;
        let counter = i64::try_from(input.counter)
            .map_err(|_error| AuthError::bad_request("Passkey counter exceeds i64 range"))?;

        ActiveModel {
            id: Set(self
                .generated_id(&self.db, "passkey", "passkey", "id")
                .await?
                .unwrap_or_else(|| Uuid::new_v4().to_string())),
            name: optional_text(db, input.name).await?,
            public_key: Set(input.public_key),
            user_id: Set(input.user_id),
            credential_id: Set(input.credential_id),
            counter: Set(crate::Integer(counter)),
            device_type: Set(input.device_type),
            backed_up: Set(input.backed_up),
            transports: optional_text(db, input.transports).await?,

            aaguid: optional_text(db, input.aaguid).await?,
            created_at: match input.created_at {
                alibi_core::utils::json::JsValue::Undefined => sea_orm::NotSet,
                alibi_core::utils::json::JsValue::Null => Set(None),
                alibi_core::utils::json::JsValue::Date(value) => Set(Some(value)),
                _ => {
                    return Err(AuthError::not_implemented(
                        "Non-date passkey SQL timestamps are unsupported",
                    ));
                }
            },
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
        self.create_passkey_with_connection(self.scoped_connection(), input)
            .await
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        Entity::find_by_id(id.to_owned())
            .one(self.scoped_connection())
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
            .one(self.scoped_connection())
            .await
            .map(|model| model.map(|model| Passkey::from(&model)))
            .map_err(map_db_err)
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .all(self.scoped_connection())
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
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };

        let mut active = model.into_active_model();
        active.counter = Set(crate::Integer(i64::try_from(update.counter).map_err(
            |_error| AuthError::bad_request("Passkey counter exceeds i64 range"),
        )?));
        active.backed_up = Set(update.backed_up);
        active.device_type = Set(update.device_type);

        active
            .update(self.scoped_connection())
            .await
            .map(|model| Some(Passkey::from(&model)))
            .map_err(map_db_err)
    }

    async fn update_passkey_name(
        &self,
        id: &str,
        name: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Passkey> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::not_found("Passkey not found"));
        };

        let mut active = model.into_active_model();
        active.name = Set(Some(name.to_utf8_binding()));

        active
            .update(self.scoped_connection())
            .await
            .map(|model| Passkey::from(&model))
            .map_err(map_db_err)
    }

    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        Entity::delete_by_id(id.to_owned())
            .exec(self.scoped_connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }
}
