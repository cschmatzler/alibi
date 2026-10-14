use crate::SqlxModel;
use chrono::{DateTime, Utc};
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow, SqlxModel)]
#[auth(table = "scimGroupMember")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "connectionId")]
    #[serde(rename = "connectionId")]
    pub connection_id: String,
    #[sqlx(rename = "groupId")]
    #[serde(rename = "groupId")]
    pub group_id: String,
    #[sqlx(rename = "scimUserId")]
    #[serde(rename = "scimUserId")]
    pub scim_user_id: String,
    #[sqlx(rename = "membershipKey")]
    #[serde(rename = "membershipKey")]
    pub membership_key: String,
    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}
