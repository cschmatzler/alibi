#[cfg(test)]
#[path = "verification_tests.rs"]
mod tests;

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};
use crate::schema::{AuthSchema, SeaOrmVerificationModel};
use async_trait::async_trait;
use better_auth_core::entity::AuthVerification;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::{VerificationStore, verification_reservation_key};
use better_auth_core::types::{CreateVerification, UpdateVerification};
use better_auth_core::verification::{
    VerificationCreation, VerificationPublication, VerificationSnapshot,
};
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, IdenStatic,
    Iterable, QueryFilter, QueryOrder, QuerySelect, QueryTrait, SqliteTransactionMode,
    TransactionOptions, TransactionTrait,
};

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::Verification: SeaOrmVerificationModel,
{
    pub(crate) async fn create_verification_record_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        tx: Option<&DatabaseTransaction>,
        mut data: VerificationCreation,
        publication: VerificationPublication,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_create_verification_record(&mut data, &hook_context)
                .await?
                .is_cancelled()
            {
                return Ok(None);
            }
        }
        let snapshot = if publication.store_in_database {
            let id = data
                .id
                .as_deref()
                .map(S::Verification::parse_id)
                .transpose()?;
            let mut active = S::Verification::new_active(id, data.data(), data.created_at);
            if let Some(updated) = S::Verification::updated_at_column() {
                let column = <<S::Verification as SeaOrmVerificationModel>::Entity as EntityTrait>::Column::iter()
                    .find(|column| column.as_str() == updated.as_str())
                    .ok_or_else(|| AuthError::internal("the verification update timestamp binding has no column"))?;
                active.set(column, data.updated_at.into());
            } else if data.updated_at != data.created_at {
                return Err(AuthError::internal(
                    "the verification schema cannot preserve a distinct update timestamp",
                ));
            }
            let model = active.insert(connection).await.map_err(map_db_err)?;
            VerificationSnapshot::from_model(&model)
        } else {
            data.snapshot()
        };
        publication.publish(&snapshot).await?;
        if tx.is_none() {
            for hook in self.hooks() {
                hook.after_create_verification_record(&snapshot, &hook_context)
                    .await?;
            }
        }
        Ok(Some(snapshot))
    }

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
            let _ignored_map_err =
                <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
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
        Ok(consumed)
    }
}

#[async_trait]
impl<S> VerificationStore<S> for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
    S::Verification: SeaOrmVerificationModel,
{
    async fn create_verification_record(
        &self,
        data: VerificationCreation,
        publication: VerificationPublication,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        self.create_verification_record_with_connection(self.connection(), None, data, publication)
            .await
    }

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
        Ok(self
            .consume_verification_generation(identifier, Some(value))
            .await?
            .filter(|model| model.expires_at() >= Utc::now()))
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
        Ok(self
            .consume_verification_generation(identifier, None)
            .await?
            .filter(|model| model.expires_at() >= Utc::now()))
    }

    async fn consume_verification_snapshot(
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
        let _ignored_map_err_2 =
            <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
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
        if let Some(value_2) = update.value {
            query = query.col_expr(
                S::Verification::value_column(),
                sea_orm::sea_query::Expr::value(value_2),
            );
        }
        if let Some(expires_at_2) = update.expires_at {
            query = query.col_expr(
                S::Verification::expires_at_column(),
                sea_orm::sea_query::Expr::value(expires_at_2),
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
        let _ignored_returning = QueryTrait::query(&mut query).returning(returning);
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
        let logical = verification.identifier.clone();
        Ok(self
            .reserve_verification_record(&logical, verification)
            .await?
            .is_some())
    }

    async fn reserve_verification_record(
        &self,
        logical_identifier: &str,
        verification: CreateVerification,
    ) -> AuthResult<Option<S::Verification>> {
        let (encoded, digest) = verification_reservation_key(logical_identifier);
        let id = S::Verification::parse_reservation_id(&encoded, digest)?;
        let insert = S::Verification::new_active(Some(id.clone()), verification, Utc::now())
            .insert(self.connection())
            .await;
        match insert {
            Ok(model) => Ok(Some(model)),
            Err(error) => {
                if <S::Verification as SeaOrmVerificationModel>::Entity::find()
                    .filter(S::Verification::id_column().eq(id))
                    .one(self.connection())
                    .await
                    .map_err(map_db_err)?
                    .is_some()
                {
                    Ok(None)
                } else {
                    Err(map_db_err(error))
                }
            }
        }
    }

    async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        data: UpdateVerification,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        let hook_context = self.hook_context(None);
        let mut admitted = data.clone();
        for hook in self.hooks() {
            // Source gives every before-update hook the original patch, then
            // merges each returned mutation into the admitted patch.
            let mut candidate = data.clone();
            if hook
                .before_update_verification(identifier, &mut candidate, &hook_context)
                .await?
                .is_cancelled()
            {
                return Ok(None);
            }
            if candidate.value.is_some() {
                admitted.value = candidate.value;
            }
            if candidate.expires_at.is_some() {
                admitted.expires_at = candidate.expires_at;
            }
        }
        let mut query = <S::Verification as SeaOrmVerificationModel>::Entity::update_many()
            .filter(S::Verification::identifier_column().eq(identifier));
        if let Some(value) = admitted.value {
            query = query.col_expr(
                S::Verification::value_column(),
                sea_orm::sea_query::Expr::value(value),
            );
        }
        if let Some(expires) = admitted.expires_at {
            query = query.col_expr(
                S::Verification::expires_at_column(),
                sea_orm::sea_query::Expr::value(expires),
            );
        }
        let backend = self.connection().get_database_backend();
        if !matches!(
            backend,
            sea_orm::DbBackend::Sqlite | sea_orm::DbBackend::Postgres
        ) {
            return Err(AuthError::NotImplemented(
                "Verification update snapshots require SQLite or PostgreSQL".into(),
            ));
        }
        let returning = sea_orm::sea_query::Query::returning().exprs(
            <<S::Verification as SeaOrmVerificationModel>::Entity as EntityTrait>::Column::iter()
                .map(|column| column.select_as(column.into_returning_expr(backend))),
        );
        let _returning = QueryTrait::query(&mut query).returning(returning);
        let model = <S::Verification as SeaOrmVerificationModel>::Entity::find()
            .from_raw_sql(query.build(backend))
            .one(self.connection())
            .await
            .map_err(map_db_err)?;
        let snapshot = model.as_ref().map(VerificationSnapshot::from_model);
        for hook in self.hooks() {
            hook.after_update_verification_record(snapshot.as_ref(), &hook_context)
                .await?;
        }
        Ok(snapshot)
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
        let _ignored_map_err_3 =
            <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
                .filter(
                    <S::Verification as SeaOrmVerificationModel>::id_column().eq(verification_id),
                )
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
            .map_err(|_error| AuthError::internal("Verification cleanup count overflow"))
    }
}
