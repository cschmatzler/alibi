use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, crate::SqlxModel)]
#[auth(table = "passkeys")]
pub struct Model {
    pub id: String,
    pub name: Option<String>,
    pub public_key: String,
    pub user_id: String,
    pub credential_id: String,
    pub counter: i64,
    pub device_type: String,
    pub backed_up: bool,
    pub transports: Option<String>,
    pub credential: String,
    pub aaguid: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&Model> for better_auth_core::Passkey {
    fn from(model: &Model) -> Self {
        Self {
            id: model.id.clone(),
            name: model.name.clone(),
            public_key: model.public_key.clone(),
            user_id: model.user_id.clone(),
            credential_id: model.credential_id.clone(),
            counter: u64::try_from(model.counter).unwrap_or_default(),
            device_type: model.device_type.clone(),
            backed_up: model.backed_up,
            transports: model.transports.clone(),
            created_at: model.created_at,
            updated_at: model.updated_at,
            aaguid: model.aaguid.clone(),
            credential: model.credential.clone(),
        }
    }
}
