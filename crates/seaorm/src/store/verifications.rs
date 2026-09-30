use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, Iterable,
    QueryFilter, QueryOrder, QuerySelect, QueryTrait, SqliteTransactionMode, TransactionOptions,
    TransactionTrait,
};

use better_auth_core::store::{VerificationStore, verification_reservation_key};

use crate::entity::AuthVerification;
use crate::error::{AuthError, AuthResult};
use crate::schema::{AuthSchema, SeaOrmVerificationModel};
use crate::types::{CreateVerification, UpdateVerification};

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::Verification: SeaOrmVerificationModel,
{
    async fn create_verification_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        tx: Option<&DatabaseTransaction>,
        mut verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_create_verification(&mut verification, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("verification creation"));
            }
        }
        let verification = S::Verification::new_active(None, verification, Utc::now())
            .insert(connection)
            .await
            .map_err(map_db_err)?;
        if tx.is_none() {
            for hook in self.hooks() {
                hook.after_create_verification(&verification, &hook_context)
                    .await?;
            }
        }
        Ok(verification)
    }

    pub(crate) async fn create_verification_in_tx(
        &self,
        tx: &DatabaseTransaction,
        verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        self.create_verification_with_connection(tx, Some(tx), verification)
            .await
    }
    async fn consume_verification_generation(
        &self,
        identifier: &str,
        expected_value: Option<&str>,
    ) -> AuthResult<Option<S::Verification>> {
        // SQLite acquires its writer reservation before reading so racers
        // cannot all hold read locks and fail when upgrading to a write.
        // PostgreSQL locks the selected row; the affected-row gate still
        // protects against another consumer using a separate store/process.
        let transaction = self
            .connection()
            .begin_with_options(TransactionOptions {
                sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        let outcome = async {
            let Some(model) = <S::Verification as SeaOrmVerificationModel>::Entity::find()
                .filter(S::Verification::identifier_column().eq(identifier))
                .order_by_desc(S::Verification::created_at_column())
                .lock_exclusive()
                .one(&transaction)
                .await
                .map_err(map_db_err)?
            else {
                return Ok(None);
            };
            if expected_value.is_some_and(|expected| model.value() != expected) {
                return Ok(None);
            }
            let hook_context = self.hook_context(Some(&transaction));
            for hook in self.hooks() {
                if hook
                    .before_delete_verification(&model, &hook_context)
                    .await?
                    .is_cancelled()
                {
                    // The upstream consume hook returns null when cancelled.
                    return Ok(None);
                }
            }
            let id = S::Verification::parse_id(model.id().as_ref())?;
            let deleted = <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
                .filter(S::Verification::id_column().eq(id))
                .filter(S::Verification::value_column().eq(model.value()))
                .exec(&transaction)
                .await
                .map_err(map_db_err)?;
            if deleted.rows_affected != 1 {
                return Ok(None);
            }
            let _ = <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
                .filter(S::Verification::identifier_column().eq(identifier))
                .exec(&transaction)
                .await
                .map_err(map_db_err)?;
            Ok(Some(model))
        }
        .await;
        let consumed = match outcome {
            Ok(consumed) => {
                transaction.commit().await.map_err(map_db_err)?;
                consumed
            }
            Err(error) => {
                transaction.rollback().await.map_err(map_db_err)?;
                return Err(error);
            }
        };
        if let Some(model) = &consumed {
            let hook_context = self.hook_context(None);
            for hook in self.hooks() {
                hook.after_delete_verification(model, &hook_context).await?;
            }
        }
        // Even an expired generation is removed. Older generations cannot
        // become valid again when the newest token expires.
        Ok(consumed.filter(|model| model.expires_at() >= Utc::now()))
    }
}

#[cfg(test)]
#[path = "verification_tests.rs"]
mod tests;

#[async_trait]
impl<S> VerificationStore<S> for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
    S::Verification: SeaOrmVerificationModel,
{
    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        self.create_verification_with_connection(self.connection(), None, verification)
            .await
    }

    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>> {
        <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(
                <S::Verification as SeaOrmVerificationModel>::identifier_column().eq(identifier),
            )
            .filter(<S::Verification as SeaOrmVerificationModel>::value_column().eq(value))
            .filter(
                <S::Verification as SeaOrmVerificationModel>::expires_at_column().gt(Utc::now()),
            )
            .order_by_desc(S::Verification::created_at_column())
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<S::Verification>> {
        <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(<S::Verification as SeaOrmVerificationModel>::value_column().eq(value))
            .filter(
                <S::Verification as SeaOrmVerificationModel>::expires_at_column().gt(Utc::now()),
            )
            .order_by_desc(S::Verification::created_at_column())
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(
                <S::Verification as SeaOrmVerificationModel>::identifier_column().eq(identifier),
            )
            .filter(
                <S::Verification as SeaOrmVerificationModel>::expires_at_column().gt(Utc::now()),
            )
            .order_by_desc(S::Verification::created_at_column())
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.consume_verification_generation(identifier, Some(value))
            .await
    }

    async fn get_latest_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(S::Verification::identifier_column().eq(identifier))
            .order_by_desc(S::Verification::created_at_column())
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.consume_verification_generation(identifier, None).await
    }

    async fn delete_verifications_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        let Some(model) = <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(S::Verification::identifier_column().eq(identifier))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(());
        };
        // Upstream deleteVerificationByIdentifier uses deleteWithHooks, not
        // deleteManyWithHooks: one snapshot drives the lifecycle callbacks,
        // while the identifier predicate invalidates every matching row.
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_delete_verification(&model, &hook_context)
                .await?
                .is_cancelled()
            {
                return Ok(());
            }
        }
        let _ = <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
            .filter(S::Verification::identifier_column().eq(identifier))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_delete_verification(&model, &hook_context)
                .await?;
        }
        Ok(())
    }

    async fn compare_and_swap_verification(
        &self,
        id: &str,
        expected_value: &str,
        value: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<bool> {
        let updated_at_column = S::Verification::updated_at_column().ok_or_else(|| {
            AuthError::internal("the verification schema has no update timestamp binding")
        })?;
        let parsed_id = S::Verification::parse_id(id)?;
        let mut update = UpdateVerification {
            value: Some(value.to_owned()),
            expires_at: Some(expires_at),
        };
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_update_verification(id, &mut update, &hook_context)
                .await?
                .is_cancelled()
            {
                return Ok(false);
            }
        }
        let mut query = <S::Verification as SeaOrmVerificationModel>::Entity::update_many()
            .filter(S::Verification::id_column().eq(parsed_id))
            .filter(S::Verification::value_column().eq(expected_value))
            .col_expr(
                updated_at_column,
                sea_orm::sea_query::Expr::value(Utc::now()),
            );
        if let Some(value) = update.value {
            query = query.col_expr(
                S::Verification::value_column(),
                sea_orm::sea_query::Expr::value(value),
            );
        }
        if let Some(expires_at) = update.expires_at {
            query = query.col_expr(
                S::Verification::expires_at_column(),
                sea_orm::sea_query::Expr::value(expires_at),
            );
        }
        let backend = self.connection().get_database_backend();
        if !matches!(
            backend,
            sea_orm::DbBackend::Sqlite | sea_orm::DbBackend::Postgres
        ) {
            return Err(AuthError::NotImplemented(
                "Atomic verification update snapshots require SQLite or PostgreSQL".to_owned(),
            ));
        }
        // RETURNING preserves the winning snapshot in the update itself. A
        // second SELECT can lose the row to consumption or observe a later
        // mutation, including changes made by application database triggers.
        let returning = sea_orm::sea_query::Query::returning().exprs(
            <<S::Verification as SeaOrmVerificationModel>::Entity as EntityTrait>::Column::iter()
                .map(|column| column.select_as(column.into_returning_expr(backend))),
        );
        let _ = QueryTrait::query(&mut query).returning(returning);
        let Some(model) = <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .from_raw_sql(query.build(backend))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(false);
        };
        for hook in self.hooks() {
            hook.after_update_verification(&model, &hook_context)
                .await?;
        }
        Ok(true)
    }

    async fn reserve_verification(&self, verification: CreateVerification) -> AuthResult<bool> {
        let (encoded, digest) = verification_reservation_key(&verification.identifier);
        let id = S::Verification::parse_reservation_id(&encoded, digest)?;
        let insert = S::Verification::new_active(Some(id.clone()), verification, Utc::now())
            .insert(self.connection())
            .await;
        match insert {
            Ok(_) => Ok(true),
            Err(error) => {
                // Re-read the deterministic primary key to distinguish an
                // existing reservation from unrelated database failures.
                if <S::Verification as SeaOrmVerificationModel>::Entity::find()
                    .filter(S::Verification::id_column().eq(id))
                    .one(self.connection())
                    .await
                    .map_err(map_db_err)?
                    .is_some()
                {
                    Ok(false)
                } else {
                    Err(map_db_err(error))
                }
            }
        }
    }

    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        let verification_id = <S::Verification as SeaOrmVerificationModel>::parse_id(id)?;
        let verification = <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(
                <S::Verification as SeaOrmVerificationModel>::id_column()
                    .eq(verification_id.clone()),
            )
            .one(self.connection())
            .await
            .map_err(map_db_err)?;
        let hook_context = self.hook_context(None);
        if let Some(verification) = &verification {
            for hook in self.hooks() {
                if hook
                    .before_delete_verification(verification, &hook_context)
                    .await?
                    .is_cancelled()
                {
                    return Err(cancelled_by_hook("verification deletion"));
                }
            }
        }
        let _ = <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
            .filter(<S::Verification as SeaOrmVerificationModel>::id_column().eq(verification_id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        if let Some(verification) = &verification {
            for hook in self.hooks() {
                hook.after_delete_verification(verification, &hook_context)
                    .await?;
            }
        }
        Ok(())
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        let deadline = Utc::now();
        let snapshots = <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .filter(S::Verification::expires_at_column().lt(deadline))
            .limit(self.config().advanced.database.default_find_many_limit as u64)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
        let hook_context = self.hook_context(None);
        // deleteManyWithHooks snapshots a findMany page before mutation.
        // Any before-hook veto cancels the entire batch, including rows whose
        // callbacks already ran; after hooks receive those original snapshots.
        for model in &snapshots {
            for hook in self.hooks() {
                if hook
                    .before_delete_verification(model, &hook_context)
                    .await?
                    .is_cancelled()
                {
                    return Ok(0);
                }
            }
        }
        let deleted = <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
            .filter(S::Verification::expires_at_column().lt(deadline))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        for model in &snapshots {
            for hook in self.hooks() {
                hook.after_delete_verification(model, &hook_context).await?;
            }
        }
        usize::try_from(deleted.rows_affected)
            .map_err(|_| AuthError::internal("Verification cleanup count overflow"))
    }
}
