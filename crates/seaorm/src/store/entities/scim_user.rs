use chrono::{DateTime, Utc};
use sea_orm::entity::prelude::*;
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sea_orm::DeriveEntityModel,
)]
#[sea_orm(table_name = "scimUser")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "connectionId")]
    #[serde(rename = "connectionId")]
    pub connection_id: String,
    #[sea_orm(column_name = "provisioningDomainId")]
    #[serde(rename = "provisioningDomainId")]
    pub provisioning_domain_id: String,
    #[sea_orm(column_name = "userId")]
    #[serde(rename = "userId")]
    pub user_id: String,
    #[sea_orm(column_name = "connectionUserKey")]
    #[serde(rename = "connectionUserKey")]
    pub connection_user_key: String,
    #[sea_orm(column_name = "userName")]
    #[serde(rename = "userName")]
    pub user_name: String,
    #[sea_orm(column_name = "userNameKey")]
    #[serde(rename = "userNameKey")]
    pub user_name_key: String,
    #[sea_orm(column_name = "primaryEmail")]
    #[serde(rename = "primaryEmail")]
    pub primary_email: String,
    #[sea_orm(column_name = "workEmailValueIndex")]
    #[serde(rename = "workEmailValueIndex")]
    pub work_email_value_index: String,
    #[sea_orm(column_name = "emailValueIndex")]
    #[serde(rename = "emailValueIndex")]
    pub email_value_index: String,
    #[sea_orm(column_name = "displayName")]
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[sea_orm(column_name = "formattedName")]
    #[serde(rename = "formattedName")]
    pub formatted_name: String,
    #[sea_orm(column_name = "givenName")]
    #[serde(rename = "givenName")]
    pub given_name: Option<String>,
    #[sea_orm(column_name = "familyName")]
    #[serde(rename = "familyName")]
    pub family_name: Option<String>,
    #[sea_orm(column_name = "serializedEmails")]
    #[serde(rename = "serializedEmails")]
    pub serialized_emails: String,
    #[sea_orm(column_name = "serializedAttributes")]
    #[serde(rename = "serializedAttributes")]
    pub serialized_attributes: Option<String>,
    #[sea_orm(column_name = "externalId")]
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
    #[sea_orm(column_name = "externalIdKey")]
    #[serde(rename = "externalIdKey")]
    pub external_id_key: Option<String>,
    pub active: bool,
    #[sea_orm(column_name = "orderKey")]
    #[serde(rename = "orderKey")]
    pub order_key: String,
    #[sea_orm(column_name = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sea_orm(column_name = "updatedAt")]
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}
#[derive(Copy, Clone, Debug, sea_orm::EnumIter, sea_orm::DeriveRelation)]
pub enum Relation {}
impl sea_orm::ActiveModelBehavior for ActiveModel {}
