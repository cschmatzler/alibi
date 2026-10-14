use super::{
    SeaOrmStore,
    entities::{
        scim_connection_binding as binding, scim_projection_grant as grant,
        scim_subject as subject, scim_user as user,
    },
    map_db_err,
};
use alibi_core::{
    AuthError, AuthResult, AuthSchema,
    store::{ScimIdentitySource, ScimProjectedUserState, ScimProjectionPreparedUser},
};
use chrono::SubsecRound;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, ExprTrait, QueryFilter, QuerySelect, sea_query::Expr,
};
impl<S: AuthSchema> SeaOrmStore<S> {
    pub(super) async fn prepare_scim_projection_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        domain: &str,
        ids: &[String],
    ) -> AuthResult<Vec<ScimProjectionPreparedUser>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let limit = u64::try_from(self.config.advanced.database.default_find_many_limit)
            .unwrap_or(u64::MAX);
        let requested = user::Entity::find()
            .filter(user::Column::Id.is_in(ids.iter().cloned()))
            .filter(user::Column::ProvisioningDomainId.eq(domain))
            .limit(limit)
            .all(db)
            .await
            .map_err(map_db_err)?;
        let mut user_ids = Vec::new();
        for id in ids {
            if let Some(user) = requested.iter().find(|user| user.id == *id)
                && !user_ids.contains(&user.user_id)
            {
                user_ids.push(user.user_id.clone());
            }
        }
        if user_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut sorted = user_ids.clone();
        sorted.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
        let subjects = subject::Entity::find()
            .filter(subject::Column::UserId.is_in(sorted.iter().cloned()))
            .limit(limit)
            .all(db)
            .await
            .map_err(map_db_err)?;
        if subjects.len() != sorted.len() {
            return Err(AuthError::internal(
                "A SCIM User selected for projection has no subject aggregate.",
            ));
        }
        let updated_at = chrono::Utc::now().trunc_subsecs(3);
        for user_id in sorted {
            let subject = subjects
                .iter()
                .find(|subject| subject.user_id == user_id)
                .ok_or_else(|| {
                    AuthError::internal(
                        "A SCIM User selected for projection has no subject aggregate.",
                    )
                })?;
            let updated = subject::Entity::update_many()
                .col_expr(
                    subject::Column::Revision,
                    Expr::col(subject::Column::Revision).add(1),
                )
                .col_expr(subject::Column::UpdatedAt, Expr::value(updated_at))
                .filter(subject::Column::Id.eq(subject.id.clone()))
                .filter(subject::Column::Revision.eq(subject.revision))
                .exec(db)
                .await
                .map_err(map_db_err)?;
            if updated.rows_affected == 0 {
                return Err(AuthError::internal(
                    "The SCIM projection subject changed concurrently; retry the request.",
                ));
            }
        }
        let users = user::Entity::find()
            .filter(user::Column::UserId.is_in(user_ids.iter().cloned()))
            .filter(user::Column::ProvisioningDomainId.eq(domain))
            .limit(limit)
            .all(db)
            .await
            .map_err(map_db_err)?;
        let connections = users
            .iter()
            .map(|user| user.connection_id.clone())
            .collect::<std::collections::HashSet<_>>();
        let retired = binding::Entity::find()
            .filter(binding::Column::ConnectionId.is_in(connections))
            .limit(limit)
            .all(db)
            .await
            .map_err(map_db_err)?
            .into_iter()
            .filter(|binding| binding.decommission_status != "active")
            .map(|binding| binding.connection_id)
            .collect::<std::collections::HashSet<_>>();
        let grants = grant::Entity::find()
            .filter(grant::Column::UserId.is_in(user_ids.iter().cloned()))
            .filter(grant::Column::ProvisioningDomainId.eq(domain))
            .limit(limit)
            .all(db)
            .await
            .map_err(map_db_err)?;
        Ok(user_ids
            .into_iter()
            .map(|user_id| {
                let mut sources = users
                    .iter()
                    .filter(|user| {
                        user.user_id == user_id && !retired.contains(&user.connection_id)
                    })
                    .map(|user| ScimIdentitySource {
                        id: user.id.clone(),
                        connection_id: user.connection_id.clone(),
                        provisioning_domain_id: user.provisioning_domain_id.clone(),
                        active: user.active,
                    })
                    .collect::<Vec<_>>();
                sources.sort_by(|left, right| left.id.cmp(&right.id));
                let removed_grant_ids = grants
                    .iter()
                    .filter(|grant| grant.user_id == user_id)
                    .map(|grant| grant.id.clone())
                    .collect();
                ScimProjectionPreparedUser {
                    state: ScimProjectedUserState {
                        provisioning_domain_id: domain.into(),
                        user_id,
                        active: sources.iter().any(|source| source.active),
                        sources,
                        grants: Vec::new(),
                    },
                    removed_grant_ids,
                }
            })
            .collect())
    }
    pub(super) async fn remove_scim_projection_grants_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        domain: &str,
        user_id: &str,
        ids: &[String],
    ) -> AuthResult<()> {
        if ids.is_empty() {
            return Ok(());
        }
        _ = grant::Entity::delete_many()
            .filter(grant::Column::Id.is_in(ids.iter().cloned()))
            .filter(grant::Column::UserId.eq(user_id))
            .filter(grant::Column::ProvisioningDomainId.eq(domain))
            .exec(db)
            .await
            .map_err(map_db_err)?;
        Ok(())
    }
}
