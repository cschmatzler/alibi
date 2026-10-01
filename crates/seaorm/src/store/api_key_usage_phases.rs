//! Source database usage writes are guarded separately, not one transaction.
use better_auth_core::store::ConsumeApiKeyResult;

use chrono::{DateTime, Utc};

use sea_orm::{
    ColumnTrait, DbBackend, EntityTrait, QueryFilter,
    sea_query::{Expr, ExprTrait},
};

use super::{
    SeaOrmStore,
    entities::api_key::{Column, Entity},
    map_db_err,
};

use better_auth_core::{ApiKey, AuthError, AuthResult};

use crate::schema::AuthSchema;

impl<S: AuthSchema> SeaOrmStore<S> {
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep separately guarded refill, usage, and rate-limit writes in reference adapter order"
    )]
    pub(super) async fn consume_usage_phases(
        &self,
        observed: &ApiKey,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        let database = self.connection();
        if !matches!(
            database.get_database_backend(),
            DbBackend::Sqlite | DbBackend::Postgres
        ) {
            return Err(AuthError::internal(
                "snapshot-aware API key consumption requires UPDATE RETURNING",
            ));
        }
        let mut row = if observed.remaining.is_some() {
            let now = Utc::now();
            let refilled = if let (Some(interval), Some(amount)) =
                (observed.refill_interval, observed.refill_amount)
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
            {
                let mut update = Entity::update_many()
                    .col_expr(Column::Remaining, Expr::value(amount - 1.0))
                    .col_expr(Column::LastRefillAt, Expr::value(now))
                    .filter(Column::Id.eq(&observed.id));
                update = match observed.last_refill_at.as_deref() {
                    Some(value) => update.filter(Column::LastRefillAt.eq(stored_date(value)?)),
                    None => update.filter(Column::LastRefillAt.is_null()),
                };
                update
                    .exec_with_returning(database)
                    .await
                    .map_err(map_db_err)?
                    .pop()
            } else {
                None
            };
            let consumed = match refilled {
                Some(value) => Some(value),
                None => Entity::update_many()
                    .col_expr(Column::Remaining, Expr::col(Column::Remaining).sub(1.0))
                    .filter(Column::Id.eq(&observed.id))
                    .filter(Column::Remaining.gt(0.0))
                    .exec_with_returning(database)
                    .await
                    .map_err(map_db_err)?
                    .pop(),
            };
            let Some(consumed) = consumed else {
                return Ok(ConsumeApiKeyResult::UsageExhausted);
            };
            ApiKey::from(&consumed)
        } else {
            observed.clone()
        };
        loop {
            let now = Utc::now();
            if !global_rate_limit_enabled || !row.rate_limit_enabled {
                if let Some(updated) = Entity::update_many()
                    .col_expr(Column::LastRequest, Expr::value(now))
                    .filter(Column::Id.eq(&row.id))
                    .exec_with_returning(database)
                    .await
                    .map_err(map_db_err)?
                    .pop()
                {
                    row = ApiKey::from(&updated);
                }
                break;
            }
            let (Some(window), Some(max)) = (row.rate_limit_time_window, row.rate_limit_max) else {
                break;
            };
            let previous = row.last_request.as_deref().map(stored_date).transpose()?;
            let elapsed =
                previous.map(|last| (now.timestamp_millis() - last.timestamp_millis()) as f64);
            let mut update = Entity::update_many()
                .filter(Column::Id.eq(&row.id))
                .col_expr(Column::LastRequest, Expr::value(now));
            update = if let Some(elapsed) = elapsed {
                if elapsed > window {
                    update
                        .col_expr(Column::RequestCount, Expr::value(1.0))
                        .filter(Column::LastRequest.lte(window_start(now, window)?))
                } else {
                    if row.request_count.unwrap_or(0.0) >= max {
                        return Ok(ConsumeApiKeyResult::RateLimited {
                            try_again_in: (window - elapsed).ceil(),
                        });
                    }
                    update
                        .col_expr(
                            Column::RequestCount,
                            Expr::col(Column::RequestCount).add(1.0),
                        )
                        .filter(Column::LastRequest.gt(window_start(now, window)?))
                        .filter(Column::RequestCount.lt(max))
                }
            } else {
                update
                    .col_expr(Column::RequestCount, Expr::value(1.0))
                    .filter(Column::LastRequest.is_null())
            };
            if let Some(updated) = update
                .exec_with_returning(database)
                .await
                .map_err(map_db_err)?
                .pop()
            {
                row = ApiKey::from(&updated);
                break;
            }
            row = Entity::find_by_id(&row.id)
                .one(database)
                .await
                .map_err(map_db_err)?
                .map(|model| ApiKey::from(&model))
                .ok_or_else(invalid_key)?;
        }
        // A real final UPDATE RETURNING observes current quota/counter fields,
        // including claims committed by concurrent verifications before this write.
        let updated = Entity::update_many()
            .col_expr(Column::UpdatedAt, Expr::value(Utc::now()))
            .filter(Column::Id.eq(&row.id))
            .exec_with_returning(database)
            .await
            .map_err(map_db_err)?
            .pop()
            .ok_or_else(invalid_key)?;
        Ok(ConsumeApiKeyResult::Allowed(Box::new(ApiKey::from(
            &updated,
        ))))
    }
}

const fn invalid_key() -> AuthError {
    AuthError::Upstream {
        status: 401,
        code: "INVALID_API_KEY",
        message: "Invalid API key.",
    }
}

fn stored_date(value: &str) -> AuthResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| AuthError::internal(format!("Invalid stored API key date: {error}")))
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
fn window_start(now: DateTime<Utc>, window: f64) -> AuthResult<DateTime<Utc>> {
    // JS Date subtraction applies TimeClip (truncate toward zero) to milliseconds.
    let millis = (now.timestamp_millis() as f64 - window).trunc();
    if !millis.is_finite() || millis.abs() > 8_640_000_000_000_000.0 {
        return Err(AuthError::internal(
            "Invalid API key rate-limit window date",
        ));
    }
    DateTime::from_timestamp_millis(millis as i64)
        .ok_or_else(|| AuthError::internal("Unsupported API key rate-limit window date"))
}
