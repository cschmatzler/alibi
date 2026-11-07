use crate::SqlxModel;
use alibi_core::Passkey;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, SqlxModel)]
#[auth(table = "passkey")]
pub struct Model {
    pub id: String,
    pub name: Option<String>,
    #[sqlx(rename = "publicKey")]
    pub public_key: String,
    #[sqlx(rename = "userId")]
    pub user_id: String,
    #[sqlx(rename = "credentialID")]
    pub credential_id: String,
    pub counter: i64,
    #[sqlx(rename = "deviceType")]
    pub device_type: String,
    #[sqlx(rename = "backedUp")]
    pub backed_up: bool,
    pub transports: Option<String>,
    pub aaguid: Option<String>,
    #[sqlx(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
}

impl From<&Model> for Passkey {
    fn from(model: &Model) -> Self {
        Self {
            id: model.id.clone(),
            name: model
                .name
                .clone()
                .map_or(alibi_core::utils::json::JsValue::Null, |value| {
                    alibi_core::utils::json::JsValue::String(value.into())
                }),
            public_key: model.public_key.clone(),
            user_id: model.user_id.clone(),
            credential_id: model.credential_id.clone(),
            counter: u64::try_from(model.counter).unwrap_or_default(),
            device_type: model.device_type.clone(),
            backed_up: model.backed_up,
            transports: model
                .transports
                .clone()
                .map_or(alibi_core::utils::json::JsValue::Null, |value| {
                    alibi_core::utils::json::JsValue::String(value.into())
                }),
            created_at: model.created_at.map_or(
                alibi_core::utils::json::JsValue::Null,
                alibi_core::utils::json::JsValue::Date,
            ),

            aaguid: model
                .aaguid
                .clone()
                .map_or(alibi_core::utils::json::JsValue::Null, |value| {
                    alibi_core::utils::json::JsValue::String(value.into())
                }),
        }
    }
}
