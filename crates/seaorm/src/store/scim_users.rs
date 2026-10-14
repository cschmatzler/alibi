//! Atomic User retirement, identity tombstones, and membership fences.
use super::{
    SeaOrmStore,
    entities::{
        scim_group as group, scim_group_member as member, scim_identity_tombstone as tombstone,
        scim_projection_grant as grant, scim_subject as subject, scim_user as user,
    },
    map_db_err,
};
use alibi_core::{AuthError, AuthResult, AuthSchema, store::ScimProjectionPreparedUser};
use chrono::SubsecRound;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, ExprTrait, QueryFilter,
    QuerySelect, Set, sea_query::Expr,
};
fn missing() -> AuthError {
    AuthError::Api {
        status: 404,
        code: None,
        message: "SCIM User not found".into(),
    }
}
fn identity_conflict() -> AuthError {
    AuthError::internal("The SCIM identity changed concurrently; retry the request")
}
fn group_conflict() -> AuthError {
    AuthError::internal("The SCIM Group changed concurrently; retry the request.")
}
impl<S: AuthSchema> SeaOrmStore<S> {
    async fn scim_user_owned_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        id: &str,
        connection: &str,
        domain: &str,
    ) -> AuthResult<user::Model> {
        let source = user::Entity::find()
            .filter(user::Column::Id.eq(id))
            .filter(user::Column::ConnectionId.eq(connection))
            .one(db)
            .await
            .map_err(map_db_err)?
            .ok_or_else(missing)?;
        if source.provisioning_domain_id != domain {
            return Err(AuthError::Api {
                status: 409,
                code: None,
                message: "The connection provisioningDomainId changed after resources were created"
                    .into(),
            });
        }
        Ok(source)
    }
    async fn scim_user_memberships_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        id: &str,
        connection: &str,
    ) -> AuthResult<Vec<member::Model>> {
        member::Entity::find()
            .filter(member::Column::ConnectionId.eq(connection))
            .filter(member::Column::ScimUserId.eq(id))
            .limit(
                u64::try_from(self.config.advanced.database.default_find_many_limit)
                    .unwrap_or(u64::MAX),
            )
            .all(db)
            .await
            .map_err(map_db_err)
    }
    pub(super) async fn delete_scim_user_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        id: &str,
        connection: &str,
        domain: &str,
        roles: bool,
    ) -> AuthResult<(String, Vec<ScimProjectionPreparedUser>)> {
        let before = self
            .scim_user_owned_with_connection(db, id, connection, domain)
            .await?;
        let subject = subject::Entity::find()
            .filter(subject::Column::UserId.eq(&before.user_id))
            .one(db)
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| AuthError::Api {
                status: 500,
                code: None,
                message: "The SCIM User subject is missing".into(),
            })?;
        let memberships = self
            .scim_user_memberships_with_connection(db, id, connection)
            .await?;
        let mut group_ids = memberships
            .into_iter()
            .map(|member| member.group_id)
            .collect::<Vec<_>>();
        group_ids.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
        group_ids.dedup();
        let mut groups = Vec::new();
        for id in &group_ids {
            groups.push(
                self.lock_scim_group_with_connection(db, id, connection, domain)
                    .await
                    .map_err(|error| match error {
                        AuthError::Api { status: 404, .. } => group_conflict(),
                        error => error,
                    })?,
            );
        }
        let now = chrono::Utc::now().trunc_subsecs(3);
        if subject::Entity::update_many()
            .col_expr(
                subject::Column::Revision,
                Expr::col(subject::Column::Revision).add(1),
            )
            .col_expr(subject::Column::UpdatedAt, Expr::value(now))
            .filter(subject::Column::Id.eq(&subject.id))
            .filter(subject::Column::Revision.eq(subject.revision))
            .exec(db)
            .await
            .map_err(map_db_err)?
            .rows_affected
            == 0
        {
            return Err(identity_conflict());
        }
        let subject = subject::Entity::find_by_id(&subject.id)
            .one(db)
            .await
            .map_err(map_db_err)?
            .ok_or_else(identity_conflict)?;
        let source = self
            .scim_user_owned_with_connection(db, id, connection, domain)
            .await?;
        if source.user_id != before.user_id {
            return Err(AuthError::Api {
                status: 409,
                code: None,
                message: "The SCIM User identity changed concurrently".into(),
            });
        }
        let after = self
            .scim_user_memberships_with_connection(db, id, connection)
            .await?;
        let after = after
            .into_iter()
            .map(|member| member.group_id)
            .collect::<std::collections::BTreeSet<_>>();
        if after.len() != group_ids.len() || !group_ids.iter().all(|id| after.contains(id)) {
            return Err(group_conflict());
        }
        if let (Some(external), Some(key)) = (&source.external_id, &source.external_id_key)
            && !external.is_empty()
            && !key.is_empty()
        {
            let profile = if subject.profile_source_id.as_deref() == Some(id) {
                "manage"
            } else {
                "preserve"
            };
            if let Some(existing) = tombstone::Entity::find()
                .filter(tombstone::Column::ExternalIdKey.eq(key))
                .one(db)
                .await
                .map_err(map_db_err)?
            {
                _ = tombstone::Entity::update_many()
                    .col_expr(
                        tombstone::Column::UserId,
                        Expr::value(source.user_id.clone()),
                    )
                    .col_expr(tombstone::Column::Profile, Expr::value(profile))
                    .col_expr(tombstone::Column::DeletedAt, Expr::value(now))
                    .filter(tombstone::Column::Id.eq(existing.id))
                    .exec(db)
                    .await
                    .map_err(map_db_err)?;
            } else {
                _ = tombstone::ActiveModel {
                    id: Set(self
                        .generated_id(db, "scimIdentityTombstone", "scimIdentityTombstone", "id")
                        .await?
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                    connection_id: Set(source.connection_id.clone()),
                    provisioning_domain_id: Set(source.provisioning_domain_id.clone()),
                    external_id: Set(external.clone()),
                    external_id_key: Set(key.clone()),
                    user_id: Set(source.user_id.clone()),
                    profile: Set(profile.into()),
                    deleted_at: Set(now),
                }
                .insert(db)
                .await
                .map_err(map_db_err)?;
            }
        }
        _ = member::Entity::delete_many()
            .filter(member::Column::ConnectionId.eq(connection))
            .filter(member::Column::ScimUserId.eq(id))
            .exec(db)
            .await
            .map_err(map_db_err)?;
        for group in groups {
            let revision = group.revision.checked_add(1).ok_or_else(group_conflict)?;
            if group::Entity::update_many()
                .col_expr(group::Column::UpdatedAt, Expr::value(now))
                .filter(group::Column::Id.eq(group.id))
                .filter(group::Column::ConnectionId.eq(connection))
                .filter(group::Column::Revision.eq(revision))
                .exec(db)
                .await
                .map_err(map_db_err)?
                .rows_affected
                == 0
            {
                return Err(group_conflict());
            }
        }
        _ = grant::Entity::delete_many()
            .filter(grant::Column::ScimUserId.eq(id))
            .exec(db)
            .await
            .map_err(map_db_err)?;
        _ = user::Entity::delete_many()
            .filter(user::Column::Id.eq(id))
            .filter(user::Column::ConnectionId.eq(connection))
            .exec(db)
            .await
            .map_err(map_db_err)?;
        if subject.profile_source_id.as_deref() == Some(id)
            && subject::Entity::update_many()
                .col_expr(
                    subject::Column::ProfileSourceId,
                    Expr::value(Option::<String>::None),
                )
                .col_expr(
                    subject::Column::Revision,
                    Expr::col(subject::Column::Revision).add(1),
                )
                .col_expr(subject::Column::UpdatedAt, Expr::value(now))
                .filter(subject::Column::Id.eq(subject.id))
                .filter(subject::Column::Revision.eq(subject.revision))
                .filter(subject::Column::ProfileSourceId.eq(id))
                .exec(db)
                .await
                .map_err(map_db_err)?
                .rows_affected
                == 0
        {
            return Err(identity_conflict());
        }
        let states = self
            .prepare_scim_projection_for_users_with_connection(
                db,
                domain,
                vec![source.user_id.clone()],
                roles,
            )
            .await?;
        Ok((source.user_id, states))
    }
}
