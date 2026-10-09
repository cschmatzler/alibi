use super::SqlxStore;
use super::entities::two_factor::Model;
use crate::model::{self, ActiveRow, SqlxModel};
use crate::schema::AuthSchema;
use crate::sql::Sql;
use crate::value::SqlValue;
use alibi_core::error::AuthResult;
use alibi_core::store::TwoFactorStore;
use alibi_core::types::{CreateTwoFactor, TwoFactor, UpdateTwoFactor};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// One assignment in a factor update: a bound value or a SQL expression.
enum Assignment {
    Value(&'static str, SqlValue),
    Increment,
}

/// Every factor column; SQLite INTEGER affinity retains integral storage, so the
/// counter is projected as REAL for the typed `f64` decoder under its own name.
fn factor_columns(sql: &mut Sql, qualified: bool) {
    for (index, column) in Model::COLUMN_NAMES.iter().copied().enumerate() {
        if index > 0 {
            sql.push(", ");
        }
        if column == "failed_verification_count" {
            if qualified {
                sql.push("CAST(");
                sql.column(Model::TABLE, column);
                sql.push(" AS DOUBLE PRECISION) AS ");
                sql.ident(column);
            } else {
                sql.push("CAST(\"failed_verification_count\" AS DOUBLE PRECISION) AS \"failed_verification_count\"");
            }
        } else if qualified {
            sql.column(Model::TABLE, column);
            sql.push(" AS ");
            sql.ident(column);
        } else {
            sql.ident(column);
            sql.push(" AS ");
            sql.ident(column);
        }
    }
}

fn factor_select(sql: &mut Sql) {
    sql.push("SELECT ");
    factor_columns(sql, true);
    sql.push(" FROM ");
    sql.ident(Model::TABLE);
}

impl<S: AuthSchema + Send + Sync> SqlxStore<S> {
    /// RETURNING captures the row in the conditional atomic write, rather
    /// than a later read that can observe another request's reset/rotation.
    async fn apply_factor_update(
        &self,
        assignments: Vec<Assignment>,
        filters: Vec<(&'static str, &'static str, SqlValue)>,
    ) -> AuthResult<Option<TwoFactor>> {
        let mut sql = Sql::with(self.exec().engine(), "UPDATE ");
        sql.ident(Model::TABLE);
        sql.push(" SET ");
        for (index, assignment) in assignments.into_iter().enumerate() {
            if index > 0 {
                sql.push(", ");
            }
            match assignment {
                Assignment::Value(column, value) => {
                    sql.assign(column, value);
                }
                Assignment::Increment => {
                    sql.ident("failed_verification_count");
                    sql.push(" = \"failed_verification_count\" + 1");
                }
            }
        }
        for (index, (column, operator, value)) in filters.into_iter().enumerate() {
            sql.push(if index == 0 { " WHERE " } else { " AND " });
            sql.column(Model::TABLE, column);
            sql.push(operator);
            sql.bind(value);
        }
        sql.push(" RETURNING ");
        factor_columns(&mut sql, false);
        Ok(self
            .exec()
            .fetch_optional::<Model>(sql)
            .await?
            .map(|row| TwoFactor::from(&row)))
    }

    async fn find_factor(&self, column: &str, value: &str) -> AuthResult<Option<Model>> {
        let mut sql = Sql::new(self.exec().engine());
        factor_select(&mut sql);
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, column, " = ", value);
        model::limit_one(&mut sql);
        self.exec().fetch_optional(sql).await
    }
}

#[async_trait]
impl<S> TwoFactorStore for SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<TwoFactor> {
        let now = Utc::now();
        let mut active = ActiveRow::new();
        active.set(
            "id",
            self.generated_id(self.exec(), "twoFactor", "two_factor", "id")
                .await?
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
        );
        active.set("secret", two_factor.secret);
        active.set("backup_codes", two_factor.backup_codes);
        active.set("user_id", two_factor.user_id);
        active.set("verified", two_factor.verified);
        active.set(
            "failed_verification_count",
            two_factor.failed_verification_count,
        );
        active.set("locked_until", two_factor.locked_until);
        active.set("created_at", now);
        active.set("updated_at", now);
        let mut sql = Sql::with(self.exec().engine(), "INSERT INTO ");
        sql.ident(Model::TABLE);
        sql.push(" (");
        let present = active.present().collect::<Vec<_>>();
        sql.column_list(&present.iter().map(|(name, _)| *name).collect::<Vec<_>>());
        sql.push(") VALUES ");
        sql.bind_list(present.into_iter().map(|(_, value)| value.clone()));
        sql.push(" RETURNING ");
        factor_columns(&mut sql, false);
        self.exec()
            .fetch_optional::<Model>(sql)
            .await?
            .map(|model| TwoFactor::from(&model))
            .ok_or_else(|| {
                alibi_core::error::AuthError::internal("Factor insertion returned no row")
            })
    }

    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        Ok(self
            .find_factor("user_id", user_id)
            .await?
            .map(|model| TwoFactor::from(&model)))
    }

    async fn update_two_factor(
        &self,
        id: &str,
        update: UpdateTwoFactor,
    ) -> AuthResult<Option<TwoFactor>> {
        let unchanged =
            update.secret.is_none() && update.backup_codes.is_none() && update.verified.is_none();
        let mut assignments = Vec::new();
        if let Some(secret) = update.secret {
            assignments.push(Assignment::Value("secret", secret.into()));
        }
        if let Some(codes) = update.backup_codes {
            assignments.push(Assignment::Value("backup_codes", codes.into()));
        }
        if let Some(verified) = update.verified {
            assignments.push(Assignment::Value("verified", verified.into()));
        }
        if unchanged {
            return Ok(self
                .find_factor("id", id)
                .await?
                .map(|row| TwoFactor::from(&row)));
        }
        self.apply_factor_update(assignments, vec![("id", " = ", id.into())])
            .await
    }

    async fn increment_two_factor_failure(&self, id: &str) -> AuthResult<Option<TwoFactor>> {
        self.apply_factor_update(vec![Assignment::Increment], vec![("id", " = ", id.into())])
            .await
    }

    async fn set_two_factor_lock_if_count_at_least(
        &self,
        id: &str,
        threshold: f64,
        until: DateTime<Utc>,
    ) -> AuthResult<Option<TwoFactor>> {
        self.apply_factor_update(
            vec![Assignment::Value("locked_until", until.into())],
            vec![
                ("id", " = ", id.into()),
                ("failed_verification_count", " >= ", threshold.into()),
            ],
        )
        .await
    }

    async fn clear_expired_two_factor_lock(
        &self,
        id: &str,
        now: DateTime<Utc>,
    ) -> AuthResult<Option<TwoFactor>> {
        self.apply_factor_update(
            vec![
                Assignment::Value("failed_verification_count", 0.0_f64.into()),
                Assignment::Value("locked_until", None::<DateTime<Utc>>.into()),
            ],
            vec![
                ("id", " = ", id.into()),
                ("locked_until", " <= ", now.into()),
            ],
        )
        .await
    }

    async fn reset_two_factor_failures(&self, id: &str) -> AuthResult<()> {
        _ = self
            .apply_factor_update(
                vec![
                    Assignment::Value("failed_verification_count", 0.0_f64.into()),
                    Assignment::Value("locked_until", None::<DateTime<Utc>>.into()),
                ],
                vec![("id", " = ", id.into())],
            )
            .await?;
        Ok(())
    }

    async fn compare_and_swap_two_factor_backup_codes(
        &self,
        id: &str,
        expected: &str,
        replacement: &str,
    ) -> AuthResult<bool> {
        self.apply_factor_update(
            vec![Assignment::Value("backup_codes", replacement.into())],
            vec![
                ("id", " = ", id.into()),
                ("backup_codes", " = ", expected.into()),
            ],
        )
        .await
        .map(|row| row.is_some())
    }

    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        let Some(model) = self.find_factor("user_id", user_id).await? else {
            return Err(alibi_core::error::AuthError::not_found(
                "Two-factor settings not found",
            ));
        };

        self.apply_factor_update(
            vec![
                Assignment::Value("backup_codes", backup_codes.into()),
                Assignment::Value("updated_at", Utc::now().into()),
            ],
            vec![("id", " = ", model.id.into())],
        )
        .await?
        .ok_or_else(|| alibi_core::error::AuthError::not_found("Two-factor settings not found"))
    }

    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        let mut sql = Sql::with(self.exec().engine(), "DELETE FROM ");
        sql.ident(Model::TABLE);
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "user_id", " = ", user_id);
        self.exec().execute(sql).await.map(drop)
    }
}
