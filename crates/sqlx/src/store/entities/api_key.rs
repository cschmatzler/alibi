use super::api_key_start::ApiKeyStart;
use chrono::{DateTime, Utc};

bundled_model! {
    table = "api_keys", primary_key = "id";
    #[derive(Clone, Debug, PartialEq)]
    pub struct Model {
        pub id: String = "id",
        pub name: Option<String> = "name",
        pub start: Option<ApiKeyStart> = "start",
        pub prefix: Option<String> = "prefix",
        pub key_hash: String = "key",
        pub reference_id: String = "reference_id",
        pub config_id: String = "config_id",
        pub refill_interval: Option<f64> = "refill_interval",
        pub refill_amount: Option<f64> = "refill_amount",
        pub last_refill_at: Option<DateTime<Utc>> = "last_refill_at",
        pub enabled: bool = "enabled",
        pub rate_limit_enabled: bool = "rate_limit_enabled",
        pub rate_limit_time_window: Option<f64> = "rate_limit_time_window",
        pub rate_limit_max: Option<f64> = "rate_limit_max",
        pub request_count: Option<f64> = "request_count",
        pub remaining: Option<f64> = "remaining",
        pub last_request: Option<DateTime<Utc>> = "last_request",
        pub expires_at: Option<DateTime<Utc>> = "expires_at",
        pub created_at: DateTime<Utc> = "created_at",
        pub updated_at: DateTime<Utc> = "updated_at",
        pub permissions: Option<String> = "permissions",
        pub metadata: Option<String> = "metadata",
    }
}

fn to_rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}

impl From<&Model> for better_auth_core::ApiKey {
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
