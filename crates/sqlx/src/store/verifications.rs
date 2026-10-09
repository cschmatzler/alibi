use super::{SqlxStore, lock_exclusive};
use crate::model::{self, SqlxModel};
use crate::pool::{Exec, SqlxTransaction};
use crate::schema::{AuthSchema, SqlxVerificationModel};
use crate::sql::Sql;
use crate::value::SqlValue;
use alibi_core::entity::AuthVerification;
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::store::adapter::cancelled_by_hook;
use alibi_core::store::{VerificationStore, verification_reservation_key};
use alibi_core::types::{CreateVerification, UpdateVerification};
use alibi_core::verification::{
    VerificationCreation, VerificationPublication, VerificationSnapshot,
};
use async_trait::async_trait;
use chrono::{DateTime, SubsecRound, Utc};

impl<S> SqlxStore<S>
where
    S: AuthSchema,
    S::Verification: SqlxVerificationModel,
{
    fn verification_table() -> &'static str {
        <S::Verification as SqlxModel>::TABLE
    }

    /// `newest_generation` filter keeping only unexpired rows.
    fn unexpired() -> (&'static str, &'static str, SqlValue) {
        (
            S::Verification::expires_at_column(),
            " > ",
            S::Verification::timestamp_value(S::Verification::expires_at_column(), Utc::now()),
        )
    }

    pub(crate) async fn create_verification_record_with_connection(
        &self,
        exec: Exec<'_>,
        tx: Option<&SqlxTransaction>,
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
            if data.id.is_none() {
                data.id = self
                    .generated_id(
                        exec,
                        "verification",
                        Self::verification_table(),
                        S::Verification::id_column(),
                    )
                    .await?;
            }
            let id = data
                .id
                .as_deref()
                .map(S::Verification::parse_id)
                .transpose()?;
            let mut active = S::Verification::new_active(id, data.data(), data.created_at);
            if let Some(updated) = S::Verification::updated_at_column() {
                let column = <S::Verification as SqlxModel>::COLUMNS
                    .iter()
                    .find(|column| column.name == updated)
                    .ok_or_else(|| {
                        AuthError::internal(
                            "the verification update timestamp binding has no column",
                        )
                    })?;
                active.set(
                    column.name,
                    S::Verification::timestamp_value(column.name, data.updated_at),
                );
            } else if data.updated_at != data.created_at {
                return Err(AuthError::internal(
                    "the verification schema cannot preserve a distinct update timestamp",
                ));
            }
            let model = model::insert::<S::Verification>(exec, &active).await?;
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

    async fn create_verification_with_connection(
        &self,
        exec: Exec<'_>,
        tx: Option<&SqlxTransaction>,
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
        let generated_id = self
            .generated_id(
                exec,
                "verification",
                Self::verification_table(),
                S::Verification::id_column(),
            )
            .await?;
        let id = generated_id
            .as_deref()
            .map(S::Verification::parse_id)
            .transpose()?;
        let active = S::Verification::new_active(id, verification, Utc::now());
        let verification = model::insert::<S::Verification>(exec, &active).await?;
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
        tx: &SqlxTransaction,
        verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        self.create_verification_with_connection(Exec::tx(tx), Some(tx), verification)
            .await
    }

    /// `SELECT ... WHERE identifier = ? [AND ...] ORDER BY created_at DESC LIMIT 1`.
    fn newest_generation(
        exec: Exec<'_>,
        filters: &[(&'static str, &'static str, SqlValue)],
    ) -> Sql {
        let table = Self::verification_table();
        let mut sql = model::select_model::<S::Verification>(exec);
        for (index, (column, operator, value)) in filters.iter().enumerate() {
            sql.push(if index == 0 { " WHERE " } else { " AND " });
            sql.column(table, column);
            sql.push(operator);
            sql.bind(S::Verification::column_value(column, value.clone()));
        }
        sql.push(" ORDER BY ");
        sql.column(table, S::Verification::created_at_column());
        sql.push(" DESC LIMIT 1");
        sql
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
        let transaction = self.begin(true).await?;
        let outcome = async {
            let exec = Exec::tx(&transaction);
            let mut select = Self::newest_generation(
                exec,
                &[(
                    S::Verification::identifier_column(),
                    " = ",
                    identifier.into(),
                )],
            );
            lock_exclusive(&mut select);
            let Some(model) = exec.fetch_optional::<S::Verification>(select).await? else {
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
            let table = Self::verification_table();
            let id = S::Verification::parse_id(model.id().as_ref())?;
            let mut delete = Sql::with(exec.engine(), "DELETE FROM ");
            delete.ident(table);
            delete.push(" WHERE ");
            delete.compare_model::<S::Verification>(table, S::Verification::id_column(), " = ", id);
            delete.push(" AND ");
            delete.compare_model::<S::Verification>(
                table,
                S::Verification::value_column(),
                " = ",
                model.value(),
            );
            if exec.execute(delete).await? != 1 {
                return Ok(None);
            }
            let mut siblings = Sql::with(exec.engine(), "DELETE FROM ");
            siblings.ident(table);
            siblings.push(" WHERE ");
            siblings.compare_model::<S::Verification>(
                table,
                S::Verification::identifier_column(),
                " = ",
                identifier,
            );
            _ = exec.execute(siblings).await?;
            Ok(Some(model))
        }
        .await;
        let consumed = match outcome {
            Ok(consumed) => {
                transaction.commit().await?;
                consumed
            }
            Err(error) => {
                transaction.rollback().await?;
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

    /// `UPDATE ... RETURNING` every verification column; the winning snapshot
    /// is captured by the update itself, not a later read.
    async fn update_verifications_returning(
        &self,
        filters: &[(&'static str, SqlValue)],
        value: Option<String>,
        expires_at: Option<DateTime<Utc>>,
        updated_at_column: &'static str,
    ) -> AuthResult<Option<S::Verification>> {
        let table = Self::verification_table();
        let mut sql = Sql::with(self.exec().engine(), "UPDATE ");
        sql.ident(table);
        sql.push(" SET ");
        sql.assign(
            updated_at_column,
            S::Verification::timestamp_value(updated_at_column, Utc::now()),
        );
        if let Some(value) = value {
            sql.push(", ");
            sql.assign(
                S::Verification::value_column(),
                S::Verification::column_value(S::Verification::value_column(), value.into()),
            );
        }
        if let Some(expires_at) = expires_at {
            sql.push(", ");
            sql.assign(
                S::Verification::expires_at_column(),
                S::Verification::timestamp_value(S::Verification::expires_at_column(), expires_at),
            );
        }
        for (index, (column, value)) in filters.iter().enumerate() {
            sql.push(if index == 0 { " WHERE " } else { " AND " });
            sql.compare_model::<S::Verification>(table, column, " = ", value.clone());
        }
        model::returning::<S::Verification>(&mut sql);
        self.exec().fetch_optional::<S::Verification>(sql).await
    }
}

#[async_trait]
impl<S> VerificationStore<S> for SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
    S::Verification: SqlxVerificationModel,
{
    async fn create_verification_record(
        &self,
        data: VerificationCreation,
        publication: VerificationPublication,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        self.create_verification_record_with_connection(self.exec(), None, data, publication)
            .await
    }

    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        self.create_verification_with_connection(self.exec(), None, verification)
            .await
    }

    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>> {
        let sql = Self::newest_generation(
            self.exec(),
            &[
                (
                    S::Verification::identifier_column(),
                    " = ",
                    identifier.into(),
                ),
                (S::Verification::value_column(), " = ", value.into()),
                Self::unexpired(),
            ],
        );
        self.exec().fetch_optional(sql).await
    }

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<S::Verification>> {
        let sql = Self::newest_generation(
            self.exec(),
            &[
                (S::Verification::value_column(), " = ", value.into()),
                Self::unexpired(),
            ],
        );
        self.exec().fetch_optional(sql).await
    }

    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        let sql = Self::newest_generation(
            self.exec(),
            &[
                (
                    S::Verification::identifier_column(),
                    " = ",
                    identifier.into(),
                ),
                Self::unexpired(),
            ],
        );
        self.exec().fetch_optional(sql).await
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
        let sql = Self::newest_generation(
            self.exec(),
            &[(
                S::Verification::identifier_column(),
                " = ",
                identifier.into(),
            )],
        );
        self.exec().fetch_optional(sql).await
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
        let table = Self::verification_table();
        let mut select = model::select_model::<S::Verification>(self.exec());
        select.push(" WHERE ");
        select.compare_model::<S::Verification>(
            table,
            S::Verification::identifier_column(),
            " = ",
            identifier,
        );
        select.push(" LIMIT 1");
        let Some(model) = self
            .exec()
            .fetch_optional::<S::Verification>(select)
            .await?
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
        let mut delete = Sql::with(self.exec().engine(), "DELETE FROM ");
        delete.ident(table);
        delete.push(" WHERE ");
        delete.compare_model::<S::Verification>(
            table,
            S::Verification::identifier_column(),
            " = ",
            identifier,
        );
        _ = self.exec().execute(delete).await?;
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
        // RETURNING captures the winning snapshot; a second SELECT could lose
        // the row to consumption or observe a later mutation.
        let Some(model) = self
            .update_verifications_returning(
                &[
                    (S::Verification::id_column(), parsed_id),
                    (S::Verification::value_column(), expected_value.into()),
                ],
                update.value,
                update.expires_at,
                updated_at_column,
            )
            .await?
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
        let active = S::Verification::new_active(Some(id.clone()), verification, Utc::now());
        match model::insert::<S::Verification>(self.exec(), &active).await {
            Ok(model) => Ok(Some(model)),
            Err(error) => {
                let table = Self::verification_table();
                let mut existing = model::select_model::<S::Verification>(self.exec());
                existing.push(" WHERE ");
                existing.compare_model::<S::Verification>(
                    table,
                    S::Verification::id_column(),
                    " = ",
                    id,
                );
                existing.push(" LIMIT 1");
                if self
                    .exec()
                    .fetch_optional::<S::Verification>(existing)
                    .await?
                    .is_some()
                {
                    Ok(None)
                } else {
                    Err(error)
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
        let updated_at = S::Verification::updated_at_column().ok_or_else(|| {
            AuthError::NotImplemented(
                "Verification update snapshots require an updatedAt column".into(),
            )
        })?;
        let model = self
            .update_verifications_returning(
                &[(S::Verification::identifier_column(), identifier.into())],
                admitted.value,
                admitted.expires_at,
                updated_at,
            )
            .await?;
        let snapshot = model.as_ref().map(VerificationSnapshot::from_model);
        for hook in self.hooks() {
            hook.after_update_verification_record(snapshot.as_ref(), &hook_context)
                .await?;
        }
        Ok(snapshot)
    }

    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        let verification_id = <S::Verification as SqlxVerificationModel>::parse_id(id)?;
        let table = Self::verification_table();
        let mut select = model::select_model::<S::Verification>(self.exec());
        select.push(" WHERE ");
        select.compare_model::<S::Verification>(
            table,
            S::Verification::id_column(),
            " = ",
            verification_id.clone(),
        );
        select.push(" LIMIT 1");
        let verification = self
            .exec()
            .fetch_optional::<S::Verification>(select)
            .await?;
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
        let mut delete = Sql::with(self.exec().engine(), "DELETE FROM ");
        delete.ident(table);
        delete.push(" WHERE ");
        delete.compare_model::<S::Verification>(
            table,
            S::Verification::id_column(),
            " = ",
            verification_id,
        );
        _ = self.exec().execute(delete).await?;
        if let Some(verification) = &verification {
            for hook in self.hooks() {
                hook.after_delete_verification(verification, &hook_context)
                    .await?;
            }
        }
        Ok(())
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        // Source's strict `expiresAt < new Date()` cleanup keeps proofs whose
        // deadline equals the current millisecond, including zero-TTL OTPs.
        let deadline = Utc::now().trunc_subsecs(3);
        let table = Self::verification_table();
        let mut select = model::select_model::<S::Verification>(self.exec());
        select.push(" WHERE ");
        select.compare_model::<S::Verification>(
            table,
            S::Verification::expires_at_column(),
            " < ",
            S::Verification::timestamp_value(S::Verification::expires_at_column(), deadline),
        );
        select.push(" LIMIT ");
        select.bind(self.find_many_limit());
        let snapshots: Vec<S::Verification> = self.exec().fetch_all(select).await?;
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
        let mut delete = Sql::with(self.exec().engine(), "DELETE FROM ");
        delete.ident(table);
        delete.push(" WHERE ");
        delete.compare_model::<S::Verification>(
            table,
            S::Verification::expires_at_column(),
            " < ",
            S::Verification::timestamp_value(S::Verification::expires_at_column(), deadline),
        );
        let deleted = self.exec().execute(delete).await?;
        for model in &snapshots {
            for hook in self.hooks() {
                hook.after_delete_verification(model, &hook_context).await?;
            }
        }
        usize::try_from(deleted)
            .map_err(|_error| AuthError::internal("Verification cleanup count overflow"))
    }
}
