use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "apikey")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub start: Option<super::api_key_start::ApiKeyStart>,
    pub prefix: Option<String>,
    #[sea_orm(column_name = "key")]
    pub key_hash: String,
    #[sea_orm(column_name = "referenceId")]
    pub reference_id: String,
    #[sea_orm(column_name = "configId")]
    pub config_id: String,
    #[sea_orm(column_name = "refillInterval")]
    pub refill_interval: Option<crate::Number>,
    #[sea_orm(column_name = "refillAmount")]
    pub refill_amount: Option<crate::Number>,
    #[sea_orm(column_name = "lastRefillAt")]
    pub last_refill_at: Option<DateTimeUtc>,
    pub enabled: Option<bool>,
    #[sea_orm(column_name = "rateLimitEnabled")]
    pub rate_limit_enabled: Option<bool>,
    #[sea_orm(column_name = "rateLimitTimeWindow")]
    pub rate_limit_time_window: Option<crate::Number>,
    #[sea_orm(column_name = "rateLimitMax")]
    pub rate_limit_max: Option<crate::Number>,
    #[sea_orm(column_name = "requestCount")]
    pub request_count: Option<crate::Number>,
    pub remaining: Option<crate::Number>,
    #[sea_orm(column_name = "lastRequest")]
    pub last_request: Option<DateTimeUtc>,
    #[sea_orm(column_name = "expiresAt")]
    pub expires_at: Option<DateTimeUtc>,
    #[sea_orm(column_name = "createdAt")]
    pub created_at: DateTimeUtc,
    #[sea_orm(column_name = "updatedAt")]
    pub updated_at: DateTimeUtc,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
