use super::storage::{read_storage, timestamp, write_storage};
use super::{ApiKeyConfig, ApiKeyErrorCode, ApiKeyPlugin, ApiKeyVerificationError};
use better_auth_core::{ApiKey, AuthContext, AuthSchema};
use chrono::Utc;

impl ApiKeyPlugin {
    pub(super) async fn consume_secondary_usage(
        key: &ApiKey,
        config: &ApiKeyConfig,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> Result<ApiKey, ApiKeyVerificationError> {
        let now = Utc::now();
        let mut mutations = key.clone();
        let count_mutated = config.rate_limit.enabled
            && key.rate_limit_enabled
            && key.rate_limit_time_window.is_some()
            && key.rate_limit_max.is_some();
        let request_mutated =
            !config.rate_limit.enabled || !key.rate_limit_enabled || count_mutated;
        if let Some(mut remaining) = key.remaining {
            if let (Some(interval), Some(amount)) = (key.refill_interval, key.refill_amount) {
                let last = chrono::DateTime::parse_from_rfc3339(
                    key.last_refill_at.as_deref().unwrap_or(&key.created_at),
                )
                .map_err(|error| better_auth_core::AuthError::internal(error.to_string()))?;
                if interval != 0.0
                    && amount != 0.0
                    && milliseconds(now.signed_duration_since(last)) > interval
                {
                    remaining = amount;
                    mutations.last_refill_at = Some(timestamp());
                }
            }
            if remaining == 0.0 {
                return Err(ApiKeyErrorCode::UsageExceeded.into());
            }
            mutations.remaining = Some(remaining - 1.0);
        }
        if !config.rate_limit.enabled || !key.rate_limit_enabled {
            mutations.last_request = Some(timestamp());
        } else if let (Some(window), Some(max)) = (key.rate_limit_time_window, key.rate_limit_max) {
            let elapsed = key
                .last_request
                .as_deref()
                .map(chrono::DateTime::parse_from_rfc3339)
                .transpose()
                .map_err(|error| better_auth_core::AuthError::internal(error.to_string()))?
                .map(|last| milliseconds(now.signed_duration_since(last)));
            if elapsed.is_none_or(|elapsed| elapsed > window) {
                mutations.request_count = Some(1.0);
            } else if key.request_count.unwrap_or(0.0) >= max {
                let mut error = super::ApiKeyValidationError::new(ApiKeyErrorCode::RateLimited);
                error.details = Some(super::ApiKeyErrorDetails {
                    try_again_in: (window - elapsed.unwrap_or_default()).ceil(),
                });
                return Err(ApiKeyVerificationError::Validation(error));
            } else {
                mutations.request_count = Some(key.request_count.unwrap_or(0.0) + 1.0);
            }
            mutations.last_request = Some(timestamp());
        }
        mutations.updated_at = timestamp();
        let storage = config.secondary().ok_or_else(|| {
            better_auth_core::AuthError::internal("Secondary storage is required")
        })?;
        let result = mutations.clone();
        let operation = async move {
            let Some(mut fresh) = read_storage(storage.as_ref(), &mutations.key_hash, true).await?
            else {
                return Ok(None);
            };
            fresh.remaining = mutations.remaining;
            fresh.last_refill_at = mutations.last_refill_at;
            if count_mutated {
                fresh.request_count = mutations.request_count;
            }
            if request_mutated {
                fresh.last_request = mutations.last_request;
            }
            fresh.updated_at = mutations.updated_at;
            write_storage(storage.as_ref(), &fresh, false).await?;
            Ok::<_, better_auth_core::AuthError>(Some(fresh))
        };
        if config.defer_updates {
            let completion = Self::start_background_work(async move {
                if let Err(error) = operation.await {
                    tracing::error!(%error, "Failed to update API key");
                }
                Ok(())
            })
            .await?;
            if let Some(handler) = &ctx.config.background_tasks {
                handler.handle(completion)?;
            } else {
                drop(completion);
            }
            Ok(result)
        } else {
            operation
                .await?
                .ok_or_else(|| ApiKeyErrorCode::FailedToUpdateApiKey.into())
        }
    }
}

fn milliseconds(duration: chrono::Duration) -> f64 {
    // JavaScript dates use integral milliseconds; string conversion avoids narrowing.
    duration
        .num_milliseconds()
        .to_string()
        .parse()
        .unwrap_or_default()
}
