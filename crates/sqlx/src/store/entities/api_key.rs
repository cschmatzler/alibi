use super::api_key_start::ApiKeyStart;
use crate::SqlxModel;
use alibi_core::ApiKey;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, sqlx::FromRow, SqlxModel)]
#[auth(table = "apikey")]
pub struct Model {
    pub id: String,
    pub name: Option<String>,
    pub start: Option<ApiKeyStart>,
    pub prefix: Option<String>,
    #[sqlx(rename = "key")]
    pub key_hash: String,
    #[sqlx(rename = "referenceId")]
    pub reference_id: String,
    #[sqlx(rename = "configId")]
    pub config_id: String,
    #[sqlx(rename = "refillInterval")]
    pub refill_interval: Option<crate::Number>,
    #[sqlx(rename = "refillAmount")]
    pub refill_amount: Option<crate::Number>,
    #[sqlx(rename = "lastRefillAt")]
    pub last_refill_at: Option<DateTime<Utc>>,
    pub enabled: Option<bool>,
    #[sqlx(rename = "rateLimitEnabled")]
    pub rate_limit_enabled: Option<bool>,
    #[sqlx(rename = "rateLimitTimeWindow")]
    pub rate_limit_time_window: Option<crate::Number>,
    #[sqlx(rename = "rateLimitMax")]
    pub rate_limit_max: Option<crate::Number>,
    #[sqlx(rename = "requestCount")]
    pub request_count: Option<crate::Number>,
    pub remaining: Option<crate::Number>,
    #[sqlx(rename = "lastRequest")]
    pub last_request: Option<DateTime<Utc>>,
    #[sqlx(rename = "expiresAt")]
    pub expires_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
}

fn to_rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}

impl From<&Model> for ApiKey {
    fn from(model: &Model) -> Self {
        Self {
            id: model.id.clone(),
            name: model.name.clone(),
            start: model.start.as_ref().map(|start| start.as_str().to_owned()),
            prefix: model.prefix.clone(),
            key_hash: model.key_hash.clone(),
            reference_id: model.reference_id.clone(),
            config_id: model.config_id.clone(),
            refill_interval: model.refill_interval.map(|value| value.0),
            refill_amount: model.refill_amount.map(|value| value.0),
            last_refill_at: model.last_refill_at.map(to_rfc3339),
            enabled: model.enabled.unwrap_or(false),
            rate_limit_enabled: model.rate_limit_enabled.unwrap_or(false),
            rate_limit_time_window: model.rate_limit_time_window.map(|value| value.0),
            rate_limit_max: model.rate_limit_max.map(|value| value.0),
            request_count: model.request_count.map(|value| value.0),
            remaining: model.remaining.map(|value| value.0),
            last_request: model.last_request.map(to_rfc3339),
            expires_at: model.expires_at.map(to_rfc3339),
            created_at: to_rfc3339(model.created_at),
            updated_at: to_rfc3339(model.updated_at),
            permissions: model.permissions.clone(),
            metadata: model.metadata.clone(),
        }
    }
}
