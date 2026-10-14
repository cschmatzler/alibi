use super::{
    SeaOrmStore,
    entities::{scim_connection_binding as binding, scim_subject as subject, scim_user as user},
    map_db_err,
};
use alibi_core::{
    AuthError, AuthResult, AuthSchema,
    store::{ScimConnectionBinding, ScimProjectionCandidate},
};
use chrono::SubsecRound;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, ExprTrait, QueryFilter, QueryOrder, QuerySelect,
    sea_query::Expr,
};
impl<S: AuthSchema> SeaOrmStore<S> {
    pub(super) async fn get_scim_connection_binding_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        id: &str,
    ) -> AuthResult<Option<ScimConnectionBinding>> {
        Ok(binding::Entity::find_by_id(id)
            .one(db)
            .await
            .map_err(map_db_err)?
            .map(Into::into))
    }
    pub(super) async fn scim_projection_candidates_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        domain: &str,
        cursor: Option<&str>,
    ) -> AuthResult<Vec<ScimProjectionCandidate>> {
        let mut query = user::Entity::find().filter(user::Column::ProvisioningDomainId.eq(domain));
        if let Some(cursor) = cursor {
            query = query.filter(user::Column::UserId.gt(cursor));
        }
        Ok(query
            .order_by_asc(user::Column::UserId)
            .limit(51)
            .all(db)
            .await
            .map_err(map_db_err)?
            .into_iter()
            .map(|user| ScimProjectionCandidate {
                id: user.id,
                user_id: user.user_id,
            })
            .collect())
    }
    pub(super) async fn renew_scim_decommission_lease_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        binding: &ScimConnectionBinding,
        lease: &str,
    ) -> AuthResult<bool> {
        let revision = i32::try_from(binding.decommission_revision)
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let result = binding::Entity::update_many()
            .col_expr(
                binding::Column::DecommissionLeaseExpiresAt,
                Expr::value(chrono::Utc::now().trunc_subsecs(3) + chrono::Duration::minutes(5)),
            )
            .filter(binding::Column::Id.eq(binding.id.clone()))
            .filter(binding::Column::DecommissionRevision.eq(revision))
            .filter(binding::Column::DecommissionStatus.eq("reconciling"))
            .filter(binding::Column::DecommissionLeaseId.eq(lease))
            .exec(db)
            .await
            .map_err(map_db_err)?;
        Ok(result.rows_affected > 0)
    }
    pub(super) async fn advance_scim_decommission_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        binding: &ScimConnectionBinding,
        lease: &str,
        cursor: Option<&str>,
        count: usize,
        more: bool,
    ) -> AuthResult<Option<ScimConnectionBinding>> {
        let now = chrono::Utc::now().trunc_subsecs(3);
        let revision = i32::try_from(binding.decommission_revision)
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let mut update = binding::Entity::update_many().col_expr(
            binding::Column::DecommissionRevision,
            Expr::col(binding::Column::DecommissionRevision).add(1),
        );
        if let Some(cursor) = cursor {
            update = update
                .col_expr(
                    binding::Column::DecommissionCursorUserId,
                    Expr::value(cursor),
                )
                .col_expr(
                    binding::Column::DecommissionReconciledUserCount,
                    Expr::col(binding::Column::DecommissionReconciledUserCount).add(
                        i32::try_from(count)
                            .map_err(|error| AuthError::internal(error.to_string()))?,
                    ),
                )
                .col_expr(
                    binding::Column::DecommissionBatchCount,
                    Expr::col(binding::Column::DecommissionBatchCount).add(1),
                );
        }
        if more {
            update = update.col_expr(
                binding::Column::DecommissionLeaseExpiresAt,
                Expr::value(now + chrono::Duration::minutes(5)),
            );
        } else {
            update = update
                .col_expr(binding::Column::DecommissionStatus, Expr::value("complete"))
                .col_expr(binding::Column::DecommissionCompletedAt, Expr::value(now))
                .col_expr(
                    binding::Column::DecommissionLeaseId,
                    Expr::value(None::<String>),
                )
                .col_expr(
                    binding::Column::DecommissionLeaseExpiresAt,
                    Expr::value(None::<chrono::DateTime<chrono::Utc>>),
                );
        }
        let result = update
            .filter(binding::Column::Id.eq(binding.id.clone()))
            .filter(binding::Column::DecommissionRevision.eq(revision))
            .filter(binding::Column::DecommissionLeaseId.eq(lease))
            .exec(db)
            .await
            .map_err(map_db_err)?;
        if result.rows_affected == 0 {
            return Ok(None);
        }
        self.get_scim_connection_binding_with_connection(db, &binding.id)
            .await
    }
    pub(super) async fn reconcile_scim_identity_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        user_id: &str,
    ) -> AuthResult<bool> {
        let limit = u64::try_from(self.config.advanced.database.default_find_many_limit)
            .unwrap_or(u64::MAX);
        let users = user::Entity::find()
            .filter(user::Column::UserId.eq(user_id))
            .limit(limit)
            .all(db)
            .await
            .map_err(map_db_err)?;
        let connections = users
            .iter()
            .map(|user| user.connection_id.clone())
            .collect::<std::collections::HashSet<_>>();
        let retired = if connections.is_empty() {
            std::collections::HashSet::new()
        } else {
            binding::Entity::find()
                .filter(binding::Column::ConnectionId.is_in(connections))
                .limit(limit)
                .all(db)
                .await
                .map_err(map_db_err)?
                .into_iter()
                .filter(|binding| binding.decommission_status != "active")
                .map(|binding| binding.connection_id)
                .collect()
        };
        let participating = users
            .iter()
            .filter(|user| !retired.contains(&user.connection_id))
            .collect::<Vec<_>>();
        if let Some(subject) = subject::Entity::find()
            .filter(subject::Column::UserId.eq(user_id))
            .one(db)
            .await
            .map_err(map_db_err)?
            && let Some(profile) = &subject.profile_source_id
            && !participating.iter().any(|source| source.id == *profile)
        {
            let result = subject::Entity::update_many()
                .col_expr(
                    subject::Column::ProfileSourceId,
                    Expr::value(None::<String>),
                )
                .col_expr(
                    subject::Column::Revision,
                    Expr::col(subject::Column::Revision).add(1),
                )
                .col_expr(
                    subject::Column::UpdatedAt,
                    Expr::value(chrono::Utc::now().trunc_subsecs(3)),
                )
                .filter(subject::Column::Id.eq(subject.id))
                .filter(subject::Column::Revision.eq(subject.revision))
                .filter(subject::Column::ProfileSourceId.eq(profile.clone()))
                .exec(db)
                .await
                .map_err(map_db_err)?;
            if result.rows_affected == 0 {
                return Err(AuthError::internal(
                    "The SCIM User identity changed concurrently; retry the request.",
                ));
            }
        }
        Ok(participating.iter().any(|source| source.active))
    }
}
