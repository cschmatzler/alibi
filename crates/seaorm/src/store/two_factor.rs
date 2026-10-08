use super::entities::two_factor::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err};
use crate::schema::AuthSchema;
use alibi_core::error::AuthResult;
use alibi_core::store::TwoFactorStore;
use alibi_core::types::{CreateTwoFactor, TwoFactor, UpdateTwoFactor};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::sea_query::{Alias, Expr, ExprTrait, Query};
use sea_orm::{
    ColumnTrait, EntityTrait, Iterable, QueryFilter, QuerySelect, QueryTrait, Select, Set,
    UpdateMany,
};
use uuid::Uuid;

#[async_trait]
impl<S> TwoFactorStore for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<TwoFactor> {
        let now = Utc::now();
        let active = ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            secret: Set(two_factor.secret),
            backup_codes: Set(two_factor.backup_codes),
            user_id: Set(two_factor.user_id),
            verified: Set(two_factor.verified),
            failed_verification_count: Set(two_factor.failed_verification_count),
            locked_until: Set(two_factor.locked_until),
            created_at: Set(now),
            updated_at: Set(now),
        };
        let backend = self.scoped_connection().get_database_backend();
        if !matches!(
            backend,
            sea_orm::DatabaseBackend::Sqlite | sea_orm::DatabaseBackend::Postgres
        ) {
            return Err(alibi_core::error::AuthError::not_implemented(
                "Atomic factor insertion requires SQLite or PostgreSQL",
            ));
        }
        let mut query = Entity::insert(active);
        let _ignored_returning = QueryTrait::query(&mut query).returning(factor_returning(backend));
        Entity::find()
            .from_raw_sql(query.build(backend))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .map(|model| TwoFactor::from(&model))
            .ok_or_else(|| {
                alibi_core::error::AuthError::internal("Factor insertion returned no row")
            })
    }

    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        factor_select()
            .filter(Column::UserId.eq(user_id))
            .one(self.scoped_connection())
            .await
            .map(|model| model.map(|model| TwoFactor::from(&model)))
            .map_err(map_db_err)
    }

    async fn update_two_factor(
        &self,
        id: &str,
        update: UpdateTwoFactor,
    ) -> AuthResult<Option<TwoFactor>> {
        let unchanged =
            update.secret.is_none() && update.backup_codes.is_none() && update.verified.is_none();
        let mut query = Entity::update_many().filter(Column::Id.eq(id));
        if let Some(secret) = update.secret {
            query = query.col_expr(Column::Secret, Expr::value(secret));
        }
        if let Some(codes) = update.backup_codes {
            query = query.col_expr(Column::BackupCodes, Expr::value(codes));
        }
        if let Some(verified) = update.verified {
            query = query.col_expr(Column::Verified, Expr::value(verified));
        }
        if unchanged {
            return factor_select()
                .filter(Column::Id.eq(id))
                .one(self.scoped_connection())
                .await
                .map(|row| row.map(|row| TwoFactor::from(&row)))
                .map_err(map_db_err);
        }
        self.apply_factor_update(query).await
    }

    async fn increment_two_factor_failure(&self, id: &str) -> AuthResult<Option<TwoFactor>> {
        self.apply_factor_update(Entity::update_many().filter(Column::Id.eq(id)).col_expr(
            Column::FailedVerificationCount,
            Expr::cust("\"failed_verification_count\" + 1"),
        ))
        .await
    }

    async fn set_two_factor_lock_if_count_at_least(
        &self,
        id: &str,
        threshold: f64,
        until: DateTime<Utc>,
    ) -> AuthResult<Option<TwoFactor>> {
        self.apply_factor_update(
            Entity::update_many()
                .filter(Column::Id.eq(id))
                .filter(Column::FailedVerificationCount.gte(threshold))
                .col_expr(Column::LockedUntil, Expr::value(until)),
        )
        .await
    }

    async fn clear_expired_two_factor_lock(
        &self,
        id: &str,
        now: DateTime<Utc>,
    ) -> AuthResult<Option<TwoFactor>> {
        self.apply_factor_update(
            Entity::update_many()
                .filter(Column::Id.eq(id))
                .filter(Column::LockedUntil.lte(now))
                .col_expr(Column::FailedVerificationCount, Expr::value(0.0))
                .col_expr(Column::LockedUntil, Expr::value(None::<DateTime<Utc>>)),
        )
        .await
    }

    async fn reset_two_factor_failures(&self, id: &str) -> AuthResult<()> {
        drop(
            self.apply_factor_update(
                Entity::update_many()
                    .filter(Column::Id.eq(id))
                    .col_expr(Column::FailedVerificationCount, Expr::value(0.0))
                    .col_expr(Column::LockedUntil, Expr::value(None::<DateTime<Utc>>)),
            )
            .await?,
        );
        Ok(())
    }

    async fn compare_and_swap_two_factor_backup_codes(
        &self,
        id: &str,
        expected: &str,
        replacement: &str,
    ) -> AuthResult<bool> {
        self.apply_factor_update(
            Entity::update_many()
                .filter(Column::Id.eq(id))
                .filter(Column::BackupCodes.eq(expected))
                .col_expr(Column::BackupCodes, Expr::value(replacement)),
        )
        .await
        .map(|row| row.is_some())
    }

    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        let Some(model) = factor_select()
            .filter(Column::UserId.eq(user_id))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(alibi_core::error::AuthError::not_found(
                "Two-factor settings not found",
            ));
        };

        self.apply_factor_update(
            Entity::update_many()
                .filter(Column::Id.eq(model.id))
                .col_expr(Column::BackupCodes, Expr::value(backup_codes))
                .col_expr(Column::UpdatedAt, Expr::value(Utc::now())),
        )
        .await?
        .ok_or_else(|| alibi_core::error::AuthError::not_found("Two-factor settings not found"))
    }

    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        Entity::delete_many()
            .filter(Column::UserId.eq(user_id))
            .exec(self.scoped_connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }
}

impl<S: AuthSchema + Send + Sync> SeaOrmStore<S> {
    async fn apply_factor_update(
        &self,
        mut query: UpdateMany<Entity>,
    ) -> AuthResult<Option<TwoFactor>> {
        let backend = self.scoped_connection().get_database_backend();
        if !matches!(
            backend,
            sea_orm::DatabaseBackend::Sqlite | sea_orm::DatabaseBackend::Postgres
        ) {
            return Err(alibi_core::error::AuthError::not_implemented(
                "Atomic factor updates require SQLite or PostgreSQL",
            ));
        }
        // RETURNING captures the row in the conditional atomic write, rather
        // than a later read that can observe another request's reset/rotation.
        let _ignored_returning_2 =
            QueryTrait::query(&mut query).returning(factor_returning(backend));
        Entity::find()
            .from_raw_sql(query.build(backend))
            .one(self.scoped_connection())
            .await
            .map(|row| row.map(|row| TwoFactor::from(&row)))
            .map_err(map_db_err)
    }
}

fn factor_select() -> Select<Entity> {
    let mut select = Entity::find().select_only();
    for column in Column::iter() {
        let expression = Expr::col((Entity, column));
        select = if matches!(column, Column::FailedVerificationCount) {
            select.column_as(expression.cast_as(Alias::new("DOUBLE PRECISION")), column)
        } else {select.column_as(expression, column)};
    }
    select
}

fn factor_returning(_backend: sea_orm::DatabaseBackend) -> sea_orm::sea_query::ReturningClause {
    use sea_orm::IdenStatic;
    Query::returning().exprs(Column::iter().map(|column| {
        let name = column.as_str();
        if matches!(column, Column::FailedVerificationCount) {
            Expr::cust(format!("CAST(\"{name}\" AS DOUBLE PRECISION) AS \"{name}\""))
        } else {Expr::cust(format!("\"{name}\" AS \"{name}\""))}
    }))
}
