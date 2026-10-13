use crate::SqlxModel;
use chrono::{DateTime, Utc};
#[derive(Clone, Debug, PartialEq, serde::Serialize, sqlx::FromRow, SqlxModel)]
#[auth(table = "oauthClientAssertion")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "expiresAt")]
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
}
