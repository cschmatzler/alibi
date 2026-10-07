use super::api_key_start::ApiKeyStart;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, PartialEq, sqlx::FromRow, crate::SqlxModel)]
#[auth(table = "api_keys")]
pub struct Model {
    pub id: String,
    pub name: Option<String>,
    pub start: Option<ApiKeyStart>,
    pub prefix: Option<String>,
    #[sqlx(rename = "key")]
    pub key_hash: String,
    pub reference_id: String,
    pub config_id: String,
    pub refill_interval: Option<f64>,
    pub refill_amount: Option<f64>,
    pub last_refill_at: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub rate_limit_enabled: bool,
    pub rate_limit_time_window: Option<f64>,
    pub rate_limit_max: Option<f64>,
    pub request_count: Option<f64>,
    pub remaining: Option<f64>,
    pub last_request: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub permissions: Option<String>,
    pub metadata: Option<String>,
}

fn to_rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}

impl From<&Model> for alibi_core::ApiKey {
    fn from(model: &Model) -> Self {
        Self {
            id: model.id.clone(),
            name: model.name.clone(),
            start: model.start.as_ref().map(|start| start.as_str().to_owned()),
            prefix: model.prefix.clone(),
            key_hash: model.key_hash.clone(),
            reference_id: model.reference_id.clone(),
            config_id: model.config_id.clone(),
            refill_interval: model.refill_interval,
            refill_amount: model.refill_amount,
            last_refill_at: model.last_refill_at.map(to_rfc3339),
            enabled: model.enabled,
            rate_limit_enabled: model.rate_limit_enabled,
            rate_limit_time_window: model.rate_limit_time_window,
            rate_limit_max: model.rate_limit_max,
            request_count: model.request_count,
            remaining: model.remaining,
            last_request: model.last_request.map(to_rfc3339),
            expires_at: model.expires_at.map(to_rfc3339),
            created_at: to_rfc3339(model.created_at),
            updated_at: to_rfc3339(model.updated_at),
            permissions: model.permissions.clone(),
            metadata: model.metadata.clone(),
        }
    }
}
