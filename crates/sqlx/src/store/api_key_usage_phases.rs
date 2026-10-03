//! Source database usage writes are guarded separately, not one transaction.
use super::SqlxStore;
use super::entities::api_key::Model;
use crate::model::{self, SqlxModel};
use crate::schema::AuthSchema;
use crate::sql::Sql;
use crate::value::SqlValue;
use better_auth_core::store::ConsumeApiKeyResult;
use better_auth_core::{ApiKey, AuthError, AuthResult};
use chrono::{DateTime, Utc};

/// One `SET` assignment of a guarded usage write.
enum Set {
    Value(&'static str, SqlValue),
    /// `column = column <op> value`.
    Offset(&'static str, &'static str, f64),
}

/// One `WHERE` predicate of a guarded usage write.
enum Guard {
    Compare(&'static str, &'static str, SqlValue),
    IsNull(&'static str),
}

impl<S: AuthSchema> SqlxStore<S> {
    /// `UPDATE api_keys SET ... WHERE ... RETURNING *`, keeping the last returned row.
    async fn guarded_update(
        &self,
        sets: Vec<Set>,
        guards: Vec<Guard>,
    ) -> AuthResult<Option<Model>> {
        let mut sql = Sql::with(self.exec().engine(), "UPDATE ");
        sql.ident(Model::TABLE);
        sql.push(" SET ");
        for (index, set) in sets.into_iter().enumerate() {
            if index > 0 {
                sql.push(", ");
            }
            match set {
                Set::Value(column, value) => {
                    sql.assign(column, value);
                }
                Set::Offset(column, operator, value) => {
                    sql.ident(column);
                    sql.push(" = ");
                    sql.ident(column);
                    sql.push(operator);
                    sql.bind(value);
                }
            }
        }
        for (index, guard) in guards.into_iter().enumerate() {
            sql.push(if index == 0 { " WHERE " } else { " AND " });
            match guard {
                Guard::Compare(column, operator, value) => {
                    sql.column(Model::TABLE, column);
                    sql.push(operator);
                    sql.bind(value);
                }
                Guard::IsNull(column) => {
                    sql.column(Model::TABLE, column);
                    sql.push(" IS NULL");
                }
            }
        }
        model::returning::<Model>(&mut sql);
        Ok(self.exec().fetch_all::<Model>(sql).await?.pop())
    }

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
                let refill_guard = match observed.last_refill_at.as_deref() {
                    Some(value) => {
                        Guard::Compare("last_refill_at", " = ", stored_date(value)?.into())
                    }
                    None => Guard::IsNull("last_refill_at"),
                };
                self.guarded_update(
                    vec![
                        Set::Value("remaining", (amount - 1.0).into()),
                        Set::Value("last_refill_at", now.into()),
                    ],
                    vec![
                        Guard::Compare("id", " = ", observed.id.as_str().into()),
                        refill_guard,
                    ],
                )
                .await?
            } else {
                None
            };
            let consumed = match refilled {
                Some(value) => Some(value),
                None => {
                    self.guarded_update(
                        vec![Set::Offset("remaining", " - ", 1.0)],
                        vec![
                            Guard::Compare("id", " = ", observed.id.as_str().into()),
                            Guard::Compare("remaining", " > ", 0.0_f64.into()),
                        ],
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
                    .guarded_update(
                        vec![Set::Value("last_request", now.into())],
                        vec![Guard::Compare("id", " = ", row.id.as_str().into())],
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
            let mut sets = vec![Set::Value("last_request", now.into())];
            let mut guards = vec![Guard::Compare("id", " = ", row.id.as_str().into())];
            if let Some(elapsed) = elapsed {
                if elapsed > window {
                    sets.push(Set::Value("request_count", 1.0_f64.into()));
                    guards.push(Guard::Compare(
                        "last_request",
                        " <= ",
                        window_start(now, window)?.into(),
                    ));
                } else {
                    if row.request_count.unwrap_or(0.0) >= max {
                        return Ok(ConsumeApiKeyResult::RateLimited {
                            try_again_in: (window - elapsed).ceil(),
                        });
                    }
                    sets.push(Set::Offset("request_count", " + ", 1.0));
                    guards.push(Guard::Compare(
                        "last_request",
                        " > ",
                        window_start(now, window)?.into(),
                    ));
                    guards.push(Guard::Compare("request_count", " < ", max.into()));
                }
            } else {
                sets.push(Set::Value("request_count", 1.0_f64.into()));
                guards.push(Guard::IsNull("last_request"));
            }
            if let Some(updated) = self.guarded_update(sets, guards).await? {
                row = ApiKey::from(&updated);
                break;
            }
            let mut current = model::by_id::<Model>(self.exec(), row.id.as_str());
            model::limit_one(&mut current);
            row = self
                .exec()
                .fetch_optional::<Model>(current)
                .await?
                .map(|model| ApiKey::from(&model))
                .ok_or_else(invalid_key)?;
        }
        // A real final UPDATE RETURNING observes current quota/counter fields,
        // including claims committed by concurrent verifications before this write.
        let updated = self
            .guarded_update(
                vec![Set::Value("updated_at", Utc::now().into())],
                vec![Guard::Compare("id", " = ", row.id.as_str().into())],
            )
            .await?
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
