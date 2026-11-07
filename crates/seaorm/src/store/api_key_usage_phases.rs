//! Source database usage writes are guarded separately, not one transaction.
use super::{
    SeaOrmStore,
    entities::api_key::{Column, Entity, Model},
    map_db_err,
};
use crate::schema::AuthSchema;
use alibi_core::store::ConsumeApiKeyResult;
use alibi_core::{ApiKey, AuthError, AuthResult};
use chrono::{DateTime, Utc};
use sea_orm::{
    ColumnTrait, DbBackend, EntityTrait, QueryFilter, UpdateMany,
    sea_query::{Condition, Expr, ExprTrait},
};

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
        let database = self.scoped_connection();
        if !matches!(
            database.get_database_backend(),
            DbBackend::Sqlite | DbBackend::Postgres | DbBackend::MySql
        ) {
            return Err(AuthError::internal(
                "API key consumption does not support this database backend",
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
                let update = Entity::update_many()
                    .col_expr(Column::Remaining, Expr::value(amount - 1.0))
                    .col_expr(Column::LastRefillAt, Expr::value(now));
                let guard = Condition::all().add(Column::Id.eq(&observed.id));
                let guard = match observed.last_refill_at.as_deref() {
                    Some(value) => guard.add(Column::LastRefillAt.eq(stored_date(value)?)),
                    None => guard.add(Column::LastRefillAt.is_null()),
                };
                self.increment_api_key_snapshot(&observed.id, update, guard)
                    .await?
            } else {
                None
            };
            let consumed = match refilled {
                Some(value) => Some(value),
                None => {
                    self.increment_api_key_snapshot(
                        &observed.id,
                        Entity::update_many()
                            .col_expr(Column::Remaining, Expr::col(Column::Remaining).sub(1.0)),
                        Condition::all()
                            .add(Column::Id.eq(&observed.id))
                            .add(Column::Remaining.gt(0.0)),
                    )
                    .await?
                }
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
                if let Some(updated) = self
                    .update_api_key_snapshot(
                        &row.id,
                        Entity::update_many()
                            .col_expr(Column::LastRequest, Expr::value(now))
                            .filter(Column::Id.eq(&row.id)),
                    )
                    .await?
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
            let mut update = Entity::update_many().col_expr(Column::LastRequest, Expr::value(now));
            let guard = Condition::all().add(Column::Id.eq(&row.id));
            let guard = if let Some(elapsed) = elapsed {
                if elapsed > window {
                    update = update.col_expr(Column::RequestCount, Expr::value(1.0));
                    guard.add(Column::LastRequest.lte(window_start(now, window)?))
                } else {
                    if row.request_count.unwrap_or(0.0) >= max {
                        return Ok(ConsumeApiKeyResult::RateLimited {
                            try_again_in: (window - elapsed).ceil(),
                        });
                    }
                    update = update.col_expr(
                        Column::RequestCount,
                        Expr::col(Column::RequestCount).add(1.0),
                    );
                    guard
                        .add(Column::LastRequest.gt(window_start(now, window)?))
                        .add(Column::RequestCount.lt(max))
                }
            } else {
                update = update.col_expr(Column::RequestCount, Expr::value(1.0));
                guard.add(Column::LastRequest.is_null())
            };
            if let Some(updated) = self
                .increment_api_key_snapshot(&row.id, update, guard)
                .await?
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
        // A real final UPDATE observes current quota/counter fields,
        // including claims committed by concurrent verifications before this write.
        let updated = self
            .update_api_key_snapshot(
                &row.id,
                Entity::update_many()
                    .col_expr(Column::UpdatedAt, Expr::value(Utc::now()))
                    .filter(Column::Id.eq(&row.id)),
            )
            .await?
            .ok_or_else(invalid_key)?;
        Ok(ConsumeApiKeyResult::Allowed(Box::new(ApiKey::from(
            &updated,
        ))))
    }

    async fn increment_api_key_snapshot(
        &self,
        id: &str,
        query: UpdateMany<Entity>,
        guard: Condition,
    ) -> AuthResult<Option<Model>> {
        let database = self.scoped_connection();
        if database.get_database_backend() == DbBackend::MySql {
            return super::mysql_snapshot::update(
                database,
                Entity::find().filter(guard.clone()),
                Entity::find_by_id(id),
                query.filter(guard),
            )
            .await;
        }
        query
            .filter(guard)
            .exec_with_returning(database)
            .await
            .map_err(map_db_err)
            .map(|mut rows| rows.pop())
    }

    async fn update_api_key_snapshot(
        &self,
        id: &str,
        query: UpdateMany<Entity>,
    ) -> AuthResult<Option<Model>> {
        let database = self.scoped_connection();
        if database.get_database_backend() == DbBackend::MySql {
            if query
                .exec(database)
                .await
                .map_err(map_db_err)?
                .rows_affected
                == 0
            {
                return Ok(None);
            }
            return Entity::find_by_id(id)
                .one(database)
                .await
                .map_err(map_db_err);
        }
        query
            .exec_with_returning(database)
            .await
            .map_err(map_db_err)
            .map(|mut rows| rows.pop())
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
