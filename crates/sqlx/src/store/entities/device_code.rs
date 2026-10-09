use crate::SqlxModel;
use alibi_core::DeviceCode;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, SqlxModel)]
#[auth(table = "device_code")]
pub struct Model {
    pub id: String,
    pub device_code: String,
    pub user_code: String,
    pub user_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub status: String,
    pub last_polled_at: Option<DateTime<Utc>>,
    pub polling_interval: Option<i64>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
}

impl From<&Model> for DeviceCode {
    fn from(model: &Model) -> Self {
        Self {
            id: model.id.clone(),
            device_code: model.device_code.clone(),
            user_code: model.user_code.clone(),
            user_id: model.user_id.clone(),
            expires_at: model.expires_at,
            status: model.status.clone(),
            last_polled_at: model.last_polled_at,
            polling_interval: model.polling_interval,
            client_id: model.client_id.clone(),
            scope: model.scope.clone(),
        }
    }
}
