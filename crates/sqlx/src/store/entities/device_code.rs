use crate::SqlxModel;
use alibi_core::DeviceCode;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, SqlxModel)]
#[auth(table = "deviceCode")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "deviceCode")]
    pub device_code: String,
    #[sqlx(rename = "userCode")]
    pub user_code: String,
    #[sqlx(rename = "userId")]
    pub user_id: Option<String>,
    #[sqlx(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    pub status: String,
    #[sqlx(rename = "lastPolledAt")]
    pub last_polled_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "pollingInterval")]
    pub polling_interval: Option<i64>,
    #[sqlx(rename = "clientId")]
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
