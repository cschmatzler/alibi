use super::SqlxStore;
use super::entities::passkey::Model;
use crate::error::record_not_updated;
use crate::model::{self, ActiveRow, SqlxModel};
use crate::pool::Exec;
use crate::schema::AuthSchema;
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::store::PasskeyStore;
use alibi_core::types::{CreatePasskey, Passkey, UpdatePasskeyAuthentication};
use async_trait::async_trait;
use uuid::Uuid;

impl<S> SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
{
    pub(super) async fn create_passkey_with_connection(
        &self,
        exec: Exec<'_>,
        mut input: CreatePasskey,
    ) -> AuthResult<Passkey> {
        input.normalize_created_at()?;
        let counter = i64::try_from(input.counter)
            .map_err(|_error| AuthError::bad_request("Passkey counter exceeds i64 range"))?;

        let mut active = ActiveRow::new();
        active.set(
            "id",
            self.generated_id(self.exec(), "passkey", "passkey", "id")
                .await?
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
        );
        for (field, value) in [
            ("name", &input.name),
            ("transports", &input.transports),
            ("aaguid", &input.aaguid),
        ] {
            if !value.is_undefined() {
                active.set(
                    field,
                    crate::additional_fields::prepare_string_value(
                        exec,
                        if exec.engine() == crate::pool::Engine::Postgres {
                            alibi_core::store::postgres_parameter::text_parameter(value)?.map_or(
                                alibi_core::store::adapter::RawFieldValue::Null,
                                alibi_core::store::adapter::RawFieldValue::Text,
                            )
                        } else if exec.engine() == crate::pool::Engine::Sqlite {
                            match value {
                                alibi_core::utils::json::JsValue::Date(_) => {
                                    return Err(AuthError::internal(
                                        "Date cannot bind to a SQLite text field",
                                    ));
                                }
                                alibi_core::utils::json::JsValue::Number(value) => {
                                    alibi_core::store::adapter::RawFieldValue::Number(*value)
                                }
                                alibi_core::utils::json::JsValue::Bool(value) => {
                                    alibi_core::store::adapter::RawFieldValue::Number(f64::from(
                                        *value,
                                    ))
                                }
                                _ => crate::additional_fields::raw_value(value)?,
                            }
                        } else {
                            crate::additional_fields::raw_value(value)?
                        },
                    )
                    .await?,
                );
            }
        }
        active.set("publicKey", input.public_key);
        active.set("userId", input.user_id);
        active.set("credentialID", input.credential_id);
        active.set("counter", counter);
        active.set("deviceType", input.device_type);
        active.set("backedUp", input.backed_up);
        match input.created_at {
            alibi_core::utils::json::JsValue::Undefined => {}
            alibi_core::utils::json::JsValue::Null => {
                active.set("createdAt", None::<chrono::DateTime<chrono::Utc>>)
            }
            alibi_core::utils::json::JsValue::Date(value) => active.set("createdAt", Some(value)),
            _ => {
                return Err(AuthError::not_implemented(
                    "Non-date passkey SQL timestamps are unsupported",
                ));
            }
        }

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
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "credentialID", " = ", credential_id);
        model::limit_one(&mut sql);
        Ok(self
            .exec()
            .fetch_optional::<Model>(sql)
            .await?
            .map(|model| Passkey::from(&model)))
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "userId", " = ", user_id);
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
        active.set("backedUp", update.backed_up);
        active.set("deviceType", update.device_type);

        model::update::<Model>(self.exec(), &active)
            .await?
            .map(|model| Some(Passkey::from(&model)))
            .ok_or_else(record_not_updated)
    }

    async fn update_passkey_name(
        &self,
        id: &str,
        name: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Passkey> {
        let Some(model) = self.find_passkey(id).await? else {
            return Err(AuthError::not_found("Passkey not found"));
        };

        let mut active = model.into_active();
        active.set("name", Some(name.to_utf8_binding()));

        model::update::<Model>(self.exec(), &active)
            .await?
            .map(|model| Passkey::from(&model))
            .ok_or_else(record_not_updated)
    }

    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        self.exec()
            .execute(model::delete_by_id::<Model>(self.exec(), id))
            .await
            .map(|_| ())
    }
}
