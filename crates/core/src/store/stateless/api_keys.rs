//! Instance-local API-key rows. Each Source write phase locks independently.
use super::*;
use crate::ApiKeyStartText;

#[async_trait]
impl ApiKeyStore for StatelessStore {
    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey> {
        let now = Utc::now().to_rfc3339();
        let start = input.start.map(|start| match start.storage_text() {
            ApiKeyStartText::Utf8(text) => Ok(text),
            ApiKeyStartText::Wtf8(_) => Err(AuthError::internal(
                "Unpaired UTF-16 API-key starting characters cannot be represented by the native String schema",
            )),
        }).transpose()?;
        let row = ApiKey {
            id: uuid::Uuid::new_v4().to_string(),
            name: input.name,
            start,
            prefix: input.prefix,
            key_hash: input.key_hash,
            reference_id: input.reference_id,
            config_id: input.config_id,
            refill_interval: input.refill_interval,
            refill_amount: input.refill_amount,
            last_refill_at: None,
            enabled: input.enabled,
            rate_limit_enabled: input.rate_limit_enabled,
            rate_limit_time_window: input.rate_limit_time_window,
            rate_limit_max: input.rate_limit_max,
            request_count: Some(0.0),
            remaining: input.remaining,
            last_request: None,
            expires_at: validated_date(input.expires_at)?,
            created_at: now.clone(),
            updated_at: now,
            permissions: input.permissions,
            metadata: input.metadata,
        };
        drop(self.lock()?.api_keys.insert(row.id.clone(), row.clone()));
        Ok(row)
    }
    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        Ok(self.lock()?.api_keys.get(id).cloned())
    }
    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        Ok(self
            .lock()?
            .api_keys
            .values()
            .find(|row| row.key_hash == hash)
            .cloned())
    }
    async fn list_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<Vec<ApiKey>> {
        Ok(self
            .lock()?
            .api_keys
            .values()
            .filter(|row| row.reference_id == reference_id)
            .cloned()
            .collect())
    }
    async fn update_api_key(&self, id: &str, mut update: UpdateApiKey) -> AuthResult<ApiKey> {
        // Validate before writing: a bad later field cannot leave a partial update.
        update.expires_at = update.expires_at.map(validated_date).transpose()?;
        update.last_request = update.last_request.map(validated_date).transpose()?;
        update.last_refill_at = update.last_refill_at.map(validated_date).transpose()?;
        let mut state = self.lock()?;
        let row = state.api_keys.get_mut(id).ok_or_else(missing_key)?;
        macro_rules! optional {
            ($($field:ident),*) => { $(if let Some(value) = update.$field { row.$field = Some(value); })* };
        }
        optional!(
            name,
            remaining,
            rate_limit_time_window,
            rate_limit_max,
            refill_interval,
            refill_amount,
            permissions,
            metadata,
            request_count
        );
        macro_rules! direct {
            ($($field:ident),*) => { $(if let Some(value) = update.$field { row.$field = value; })* };
        }
        direct!(
            enabled,
            rate_limit_enabled,
            expires_at,
            last_request,
            last_refill_at
        );
        row.updated_at = Utc::now().to_rfc3339();
        Ok(row.clone())
    }
    async fn delete_api_key(&self, id: &str) -> AuthResult<()> {
        drop(self.lock()?.api_keys.shift_remove(id));
        Ok(())
    }
    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        let mut state = self.lock()?;
        let now = Utc::now();
        let before = state.api_keys.len();
        // All stored dates were validated at the write boundary.
        state.api_keys.retain(|_, row| {
            row.expires_at
                .as_deref()
                .is_none_or(|value| stored_date(value).is_ok_and(|date| date >= now))
        });
        Ok(before - state.api_keys.len())
    }
    async fn consume_api_key_usage(
        &self,
        id: &str,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        let mut state = self.lock()?;
        let stored = state.api_keys.get_mut(id).ok_or_else(missing_key)?;
        let mut row = stored.clone();
        let observed = row.clone();
        if observed.remaining.is_some() && !consume_remaining(&mut row, &observed, Utc::now())? {
            return Ok(ConsumeApiKeyResult::UsageExhausted);
        }
        // Commit the combined operation only on success or policy denial.
        loop {
            let observed = row.clone();
            match consume_rate(&mut row, &observed, global_rate_limit_enabled, Utc::now())? {
                RateClaim::Denied(delay) => {
                    *stored = row;
                    return Ok(ConsumeApiKeyResult::RateLimited {
                        try_again_in: delay,
                    });
                }
                RateClaim::Written => break,
                RateClaim::Retry => {}
            }
        }
        row.updated_at = Utc::now().to_rfc3339();
        *stored = row.clone();
        Ok(ConsumeApiKeyResult::Allowed(Box::new(row)))
    }

    async fn consume_api_key_usage_from_snapshot(
        &self,
        observed: &ApiKey,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        let mut row = if observed.remaining.is_some() {
            let mut state = self.lock()?;
            let Some(current) = state.api_keys.get_mut(&observed.id) else {
                return Ok(ConsumeApiKeyResult::UsageExhausted);
            };
            if !consume_remaining(current, observed, Utc::now())? {
                return Ok(ConsumeApiKeyResult::UsageExhausted);
            }
            current.clone()
        } else {
            observed.clone()
        };
        loop {
            let mut state = self.lock()?;
            let Some(current) = state.api_keys.get_mut(&row.id) else {
                return Err(invalid_key());
            };
            match consume_rate(current, &row, global_rate_limit_enabled, Utc::now())? {
                RateClaim::Denied(delay) => {
                    return Ok(ConsumeApiKeyResult::RateLimited {
                        try_again_in: delay,
                    });
                }
                RateClaim::Written => break,
                RateClaim::Retry => row = current.clone(),
            }
        }
        // A separate final write returns genuine current fields, never the snapshot.
        let mut state = self.lock()?;
        let current = state.api_keys.get_mut(&row.id).ok_or_else(invalid_key)?;
        current.updated_at = Utc::now().to_rfc3339();
        Ok(ConsumeApiKeyResult::Allowed(Box::new(current.clone())))
    }
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "Match JavaScript millisecond arithmetic"
)]
fn consume_remaining(
    current: &mut ApiKey,
    observed: &ApiKey,
    now: DateTime<Utc>,
) -> AuthResult<bool> {
    if let (Some(interval), Some(amount)) = (observed.refill_interval, observed.refill_amount)
        && interval != 0.0
        && amount != 0.0
        && (now.timestamp_millis()
            - stored_date(
                observed
                    .last_refill_at
                    .as_deref()
                    .unwrap_or(&observed.created_at),
            )?
            .timestamp_millis()) as f64
            > interval
        && same_date(
            current.last_refill_at.as_deref(),
            observed.last_refill_at.as_deref(),
        )?
    {
        current.remaining = Some(amount - 1.0);
        current.last_refill_at = Some(now.to_rfc3339());
        return Ok(true);
    }
    if let Some(remaining) = current.remaining
        && remaining > 0.0
    {
        current.remaining = Some(remaining - 1.0);
        return Ok(true);
    }
    Ok(false)
}

enum RateClaim {
    Written,
    Retry,
    Denied(f64),
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "Match JavaScript millisecond arithmetic and Date TimeClip"
)]
fn consume_rate(
    current: &mut ApiKey,
    observed: &ApiKey,
    enabled: bool,
    now: DateTime<Utc>,
) -> AuthResult<RateClaim> {
    if !enabled || !observed.rate_limit_enabled {
        current.last_request = Some(now.to_rfc3339());
        return Ok(RateClaim::Written);
    }
    let (Some(window), Some(max)) = (observed.rate_limit_time_window, observed.rate_limit_max)
    else {
        return Ok(RateClaim::Written);
    };
    let previous = observed
        .last_request
        .as_deref()
        .map(stored_date)
        .transpose()?;
    let current_previous = current
        .last_request
        .as_deref()
        .map(stored_date)
        .transpose()?;
    let elapsed = previous.map(|last| (now.timestamp_millis() - last.timestamp_millis()) as f64);
    let window_start = (now.timestamp_millis() as f64 - window).trunc();
    if !window_start.is_finite() || window_start.abs() > 8_640_000_000_000_000.0 {
        return Err(AuthError::internal(
            "Invalid API key rate-limit window date",
        ));
    }
    let guard = current_previous.map(|date| date.timestamp_millis() as f64);
    match elapsed {
        None if current_previous.is_none() => current.request_count = Some(1.0),
        Some(elapsed) if elapsed > window && guard.is_some_and(|last| last <= window_start) => {
            current.request_count = Some(1.0)
        }
        Some(elapsed) if elapsed <= window => {
            if observed.request_count.unwrap_or(0.0) >= max {
                return Ok(RateClaim::Denied((window - elapsed).ceil()));
            }
            if !guard.is_some_and(|last| last > window_start)
                || current.request_count.unwrap_or(0.0) >= max
            {
                return Ok(RateClaim::Retry);
            }
            // Memory incrementOne treats null as zero. SQL NULL arithmetic is separate.
            current.request_count = Some(current.request_count.unwrap_or(0.0) + 1.0);
        }
        _ => return Ok(RateClaim::Retry),
    }
    current.last_request = Some(now.to_rfc3339());
    Ok(RateClaim::Written)
}

fn same_date(left: Option<&str>, right: Option<&str>) -> AuthResult<bool> {
    match (left, right) {
        (None, None) => Ok(true),
        (Some(left), Some(right)) => {
            Ok(stored_date(left)?.timestamp_millis() == stored_date(right)?.timestamp_millis())
        }
        _ => Ok(false),
    }
}
fn validated_date(value: Option<String>) -> AuthResult<Option<String>> {
    value
        .map(|value| stored_date(&value).map(|_| value))
        .transpose()
}
fn stored_date(value: &str) -> AuthResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|date| date.with_timezone(&Utc))
        .map_err(|error| AuthError::internal(format!("Invalid stored API key date: {error}")))
}
fn missing_key() -> AuthError {
    AuthError::not_found("API Key not found")
}
const fn invalid_key() -> AuthError {
    AuthError::Upstream {
        status: 401,
        code: "INVALID_API_KEY",
        message: "Invalid API key.",
    }
}
