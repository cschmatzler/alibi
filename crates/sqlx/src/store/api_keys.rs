use super::entities::api_key::Model;
use super::entities::api_key_start::ApiKeyStart;
use super::{SqlxStore, lock_exclusive};
use crate::error::{record_not_inserted, record_not_updated};
use crate::model::{self, ActiveRow, SqlxModel};
use crate::pool::Exec;
use crate::schema::AuthSchema;
use crate::sql::Sql;
use crate::value::SqlxValue;
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::store::adapter::parse_optional_rfc3339;
use alibi_core::store::{ApiKeyStore, ConsumeApiKeyResult};
use alibi_core::types::{ApiKey, CreateApiKey, UpdateApiKey};
use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

#[async_trait]
impl<S> ApiKeyStore for SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn consume_api_key_usage_from_snapshot(
        &self,
        observed: &ApiKey,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        self.consume_usage_phases(observed, global_rate_limit_enabled)
            .await
    }

    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey> {
        let now = Utc::now();
        let start = input
            .start
            .map(|start| ApiKeyStart::prepare(start, self.exec().engine()))
            .transpose()?;
        let sqlite_cast = start
            .as_ref()
            .is_some_and(ApiKeyStart::requires_sqlite_cast);
        let mut active = ActiveRow::new();
        active.set(
            "id",
            self.generated_id(self.exec(), "apikey", "api_keys", "id")
                .await?
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
        );
        active.set("name", input.name);
        active.set("start", start.into_sql_value());
        active.set("prefix", input.prefix);
        active.set("key", input.key_hash);
        active.set("reference_id", input.reference_id);
        active.set("config_id", input.config_id);
        active.set("refill_interval", input.refill_interval);
        active.set("refill_amount", input.refill_amount);
        active.set("last_refill_at", None::<chrono::DateTime<Utc>>);
        active.set("enabled", input.enabled);
        active.set("rate_limit_enabled", input.rate_limit_enabled);
        active.set("rate_limit_time_window", input.rate_limit_time_window);
        active.set("rate_limit_max", input.rate_limit_max);
        active.set("request_count", Some(0.0_f64));
        active.set("remaining", input.remaining);
        active.set("last_request", None::<chrono::DateTime<Utc>>);
        active.set(
            "expires_at",
            parse_optional_rfc3339(input.expires_at.as_deref(), "expires_at")?,
        );
        active.set("created_at", now);
        active.set("updated_at", now);
        active.set("permissions", input.permissions);
        active.set("metadata", input.metadata);
        let inserted = if sqlite_cast {
            // Keep one bound INSERT with every ordinary model value. Only the
            // invalid-surrogate SQLite start needs a bytes-to-TEXT expression;
            // other engines and valid strings retain the ordinary insert path.
            let mut sql = Sql::with(self.exec().engine(), "INSERT INTO ");
            sql.ident(Model::TABLE);
            sql.push(" (");
            let present = active.present().collect::<Vec<_>>();
            sql.column_list(&present.iter().map(|(name, _)| *name).collect::<Vec<_>>());
            sql.push(") SELECT ");
            for (index, (name, value)) in present.into_iter().enumerate() {
                if index > 0 {
                    sql.push(", ");
                }
                if name == "start" {
                    sql.push("CAST(");
                    sql.bind(value.clone());
                    sql.push(" AS text)");
                } else {
                    sql.bind(value.clone());
                }
            }
            model::returning::<Model>(&mut sql);
            self.exec()
                .fetch_optional::<Model>(sql)
                .await?
                .ok_or_else(record_not_inserted)?
        } else {
            model::insert::<Model>(self.exec(), &active).await?
        };
        Ok(ApiKey::from(&inserted))
    }

    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        let mut sql = model::by_id::<Model>(self.exec(), id);
        model::limit_one(&mut sql);
        Ok(self
            .exec()
            .fetch_optional::<Model>(sql)
            .await?
            .map(|model| ApiKey::from(&model)))
    }

    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "key", " = ", hash);
        model::limit_one(&mut sql);
        Ok(self
            .exec()
            .fetch_optional::<Model>(sql)
            .await?
            .map(|model| ApiKey::from(&model)))
    }

    async fn list_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<Vec<ApiKey>> {
        // Explicit ASC order matches TS insertion-order behavior and avoids
        // nondeterministic results across database backends.
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "reference_id", " = ", reference_id);
        sql.push(" ORDER BY ");
        sql.column(Model::TABLE, "created_at");
        sql.push(" ASC");
        Ok(self
            .exec()
            .fetch_all::<Model>(sql)
            .await?
            .iter()
            .map(ApiKey::from)
            .collect())
    }

    async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<ApiKey> {
        let mut sql = model::by_id::<Model>(self.exec(), id);
        model::limit_one(&mut sql);
        let Some(model) = self.exec().fetch_optional::<Model>(sql).await? else {
            return Err(AuthError::not_found("API Key not found"));
        };

        let active = apply_update_fields(model.into_active(), update)?;
        model::update::<Model>(self.exec(), &active)
            .await?
            .map(|model_2| ApiKey::from(&model_2))
            .ok_or_else(record_not_updated)
    }

    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    async fn consume_api_key_usage(
        &self,
        id: &str,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        // SQLite must acquire its write reservation before reading usage counters.
        let transaction = self.begin(true).await?;
        let exec = Exec::tx(&transaction);
        let id = id.to_owned();
        let result = async {
            let mut select = model::by_id::<Model>(exec, id.as_str());
            model::limit_one(&mut select);
            lock_exclusive(&mut select);
            let Some(model) = exec.fetch_optional::<Model>(select).await? else {
                return Err(AuthError::not_found("API Key not found"));
            };

            let now = Utc::now();
            let mut update = UpdateApiKey::default();

            if let Some(remaining) = model.remaining {
                if let (Some(interval), Some(amount)) = (model.refill_interval, model.refill_amount)
                    && interval != 0.0
                    && amount != 0.0
                    && (now.timestamp_millis()
                        - model
                            .last_refill_at
                            .unwrap_or(model.created_at)
                            .timestamp_millis()) as f64
                        > interval
                {
                    update.remaining = Some(amount - 1.0);
                    update.last_refill_at = Some(Some(now.to_rfc3339()));
                } else if remaining > 0.0 {
                    update.remaining = Some(remaining - 1.0);
                } else {
                    return Ok(ConsumeApiKeyResult::UsageExhausted);
                }
            }

            if global_rate_limit_enabled && model.rate_limit_enabled {
                if let (Some(window), Some(max)) =
                    (model.rate_limit_time_window, model.rate_limit_max)
                {
                    let elapsed = model
                        .last_request
                        .map(|last| (now.timestamp_millis() - last.timestamp_millis()) as f64);
                    if let Some(elapsed) = elapsed
                        && elapsed <= window
                        && model.request_count.unwrap_or(0.0) >= max
                    {
                        // TS consumes quota before rejecting a rate-limited request.
                        // A rejection preserves the rate-limit window and updated_at.
                        if update.remaining.is_some() {
                            let updated_at = model.updated_at;
                            let mut active = apply_update_fields(model.into_active(), update)?;
                            active.set("updated_at", updated_at);
                            _ = model::update::<Model>(exec, &active)
                                .await?
                                .ok_or_else(record_not_updated)?;
                        }
                        return Ok(ConsumeApiKeyResult::RateLimited {
                            try_again_in: (window - elapsed).ceil(),
                        });
                    }

                    update.request_count =
                        Some(if elapsed.is_none_or(|elapsed| elapsed > window) {
                            1.0
                        } else {
                            model.request_count.unwrap_or(0.0) + 1.0
                        });
                    update.last_request = Some(Some(now.to_rfc3339()));
                }
            } else {
                update.last_request = Some(Some(now.to_rfc3339()));
            }

            let active = apply_update_fields(model.into_active(), update)?;
            let updated = model::update::<Model>(exec, &active)
                .await?
                .ok_or_else(record_not_updated)?;
            Ok(ConsumeApiKeyResult::Allowed(Box::new(ApiKey::from(
                &updated,
            ))))
        }
        .await;
        if result.is_ok() {
            transaction.commit().await?;
        } else {
            transaction.rollback().await?;
        }
        result
    }

    async fn delete_api_key(&self, id: &str) -> AuthResult<()> {
        self.exec()
            .execute(model::delete_by_id::<Model>(self.exec(), id))
            .await
            .map(|_| ())
    }

    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        // Single query: DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at < NOW()
        // Matches TS: adapter.deleteMany({ where: [{ field: "expiresAt", operator: "lt", value: new Date() }, ...] })
        let mut sql = Sql::with(self.exec().engine(), "DELETE FROM ");
        sql.ident(Model::TABLE);
        sql.push(" WHERE ");
        sql.column(Model::TABLE, "expires_at");
        sql.push(" IS NOT NULL AND ");
        sql.compare(Model::TABLE, "expires_at", " < ", Utc::now());
        let deleted = self.exec().execute(sql).await?;
        usize::try_from(deleted)
            .map_err(|_error| AuthError::internal("Affected row count exceeds usize"))
    }
}

/// Apply `UpdateApiKey` fields to an API key row.
fn apply_update_fields(mut active: ActiveRow, update: UpdateApiKey) -> AuthResult<ActiveRow> {
    if let Some(name) = update.name {
        active.set("name", Some(name));
    }
    if let Some(enabled) = update.enabled {
        active.set("enabled", enabled);
    }
    if let Some(remaining) = update.remaining {
        active.set("remaining", Some(remaining));
    }
    if let Some(rate_limit_enabled) = update.rate_limit_enabled {
        active.set("rate_limit_enabled", rate_limit_enabled);
    }
    if let Some(rate_limit_time_window) = update.rate_limit_time_window {
        active.set("rate_limit_time_window", Some(rate_limit_time_window));
    }
    if let Some(rate_limit_max) = update.rate_limit_max {
        active.set("rate_limit_max", Some(rate_limit_max));
    }
    if let Some(refill_interval) = update.refill_interval {
        active.set("refill_interval", Some(refill_interval));
    }
    if let Some(refill_amount) = update.refill_amount {
        active.set("refill_amount", Some(refill_amount));
    }
    if let Some(permissions) = update.permissions {
        active.set("permissions", Some(permissions));
    }
    if let Some(metadata) = update.metadata {
        active.set("metadata", Some(metadata));
    }
    if let Some(expires_at) = update.expires_at {
        active.set(
            "expires_at",
            parse_optional_rfc3339(expires_at.as_deref(), "expires_at")?,
        );
    }
    if let Some(last_request) = update.last_request {
        active.set(
            "last_request",
            parse_optional_rfc3339(last_request.as_deref(), "last_request")?,
        );
    }
    if let Some(request_count) = update.request_count {
        active.set("request_count", Some(request_count));
    }
    if let Some(last_refill_at) = update.last_refill_at {
        active.set(
            "last_refill_at",
            parse_optional_rfc3339(last_refill_at.as_deref(), "last_refill_at")?,
        );
    }
    active.set("updated_at", Utc::now());
    Ok(active)
}
