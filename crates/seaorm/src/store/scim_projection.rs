use super::entities::{scim_group as group, scim_group_member as membership};
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
    ColumnTrait, ConnectionTrait, EntityTrait, ExprTrait, QueryFilter, QuerySelect, Select,
    sea_query::Expr,
};
/// Ids per `IN` list, like the reference's `chunkSCIMIds`; stays under legacy SQLite's 999 bound values.
pub(super) const SCIM_ID_CHUNK_SIZE: usize = 500;
/// Reads every row matching one `IN` predicate per id chunk. A bounded read caps each chunk at
/// its length (the reference's `limit: chunk.length`); otherwise no limit applies, matching its
/// `SCIM_UNBOUNDED_ROW_LIMIT` reads that bypass `defaultFindManyLimit`.
pub(super) async fn find_scim_chunks<E: EntityTrait, C: ConnectionTrait>(
    db: &C,
    ids: &[String],
    bounded: bool,
    query: impl Fn(&[String]) -> Select<E>,
) -> AuthResult<Vec<E::Model>> {
    let mut rows = Vec::new();
    for chunk in ids.chunks(SCIM_ID_CHUNK_SIZE) {
        let mut select = query(chunk);
        if bounded {
            select = select.limit(
                u64::try_from(chunk.len())
                    .map_err(|error| AuthError::internal(error.to_string()))?,
            );
        }
        rows.extend(select.all(db).await.map_err(map_db_err)?);
    }
    Ok(rows)
}
/// Connections among `connections` whose binding is no longer active.
pub(super) async fn retired_scim_connections<C: ConnectionTrait>(
    db: &C,
    connections: impl IntoIterator<Item = String>,
) -> AuthResult<std::collections::HashSet<String>> {
    let connections = connections
        .into_iter()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(find_scim_chunks(db, &connections, true, |chunk| {
        binding::Entity::find().filter(binding::Column::ConnectionId.is_in(chunk.iter().cloned()))
    })
    .await?
    .into_iter()
    .filter(|binding| binding.decommission_status != "active")
    .map(|binding| binding.connection_id)
    .collect())
}
impl<S: AuthSchema> SeaOrmStore<S> {
    pub(super) async fn scim_projection_user_ids_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        domain: &str,
        ids: &[String],
        lock: bool,
    ) -> AuthResult<Vec<String>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let requested = find_scim_chunks(db, ids, true, |chunk| {
            user::Entity::find()
                .filter(user::Column::Id.is_in(chunk.iter().cloned()))
                .filter(user::Column::ProvisioningDomainId.eq(domain))
        })
        .await?;
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
        if lock {
            let mut sorted = user_ids.clone();
            sorted.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            let subjects = find_scim_chunks(db, &sorted, true, |chunk| {
                subject::Entity::find().filter(subject::Column::UserId.is_in(chunk.iter().cloned()))
            })
            .await?;
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
        }
        Ok(user_ids)
    }
    pub(super) async fn prepare_scim_projection_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        domain: &str,
        ids: &[String],
        roles: bool,
    ) -> AuthResult<Vec<ScimProjectionPreparedUser>> {
        self.prepare_scim_projection_after_lock_with_connection(db, domain, ids, roles, false)
            .await
    }
    pub(super) async fn prepare_scim_projection_after_lock_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        domain: &str,
        ids: &[String],
        roles: bool,
        locked: bool,
    ) -> AuthResult<Vec<ScimProjectionPreparedUser>> {
        let user_ids = self
            .scim_projection_user_ids_with_connection(db, domain, ids, !locked)
            .await?;
        if user_ids.is_empty() {
            return Ok(Vec::new());
        }
        self.prepare_scim_projection_for_users_with_connection(db, domain, user_ids, roles)
            .await
    }
    pub(super) async fn prepare_scim_projection_for_users_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        domain: &str,
        user_ids: Vec<String>,
        roles: bool,
    ) -> AuthResult<Vec<ScimProjectionPreparedUser>> {
        if user_ids.is_empty() {
            return Ok(Vec::new());
        }
        let users = find_scim_chunks(db, &user_ids, false, |chunk| {
            user::Entity::find()
                .filter(user::Column::UserId.is_in(chunk.iter().cloned()))
                .filter(user::Column::ProvisioningDomainId.eq(domain))
        })
        .await?;
        let retired =
            retired_scim_connections(db, users.iter().map(|user| user.connection_id.clone()))
                .await?;
        let grants = find_scim_chunks(db, &user_ids, false, |chunk| {
            grant::Entity::find()
                .filter(grant::Column::UserId.is_in(chunk.iter().cloned()))
                .filter(grant::Column::ProvisioningDomainId.eq(domain))
        })
        .await?;
        let active_ids = users
            .iter()
            .filter(|user| user.active && !retired.contains(&user.connection_id))
            .map(|user| user.id.clone())
            .collect::<Vec<_>>();
        let memberships = if roles {
            find_scim_chunks(db, &active_ids, false, |chunk| {
                membership::Entity::find()
                    .filter(membership::Column::ScimUserId.is_in(chunk.iter().cloned()))
            })
            .await?
        } else {
            Vec::new()
        };
        let group_ids = memberships
            .iter()
            .map(|member| member.group_id.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let groups = find_scim_chunks(db, &group_ids, true, |chunk| {
            group::Entity::find().filter(group::Column::Id.is_in(chunk.iter().cloned()))
        })
        .await?;
        user_ids
            .into_iter()
            .map(|user_id| -> AuthResult<ScimProjectionPreparedUser> {
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
                alibi_core::store::scim::sort_scim_sources(&mut sources)?;
                let removed_grant_ids = grants
                    .iter()
                    .filter(|grant| grant.user_id == user_id)
                    .map(|grant| grant.id.clone())
                    .collect();
                let existing_grants = grants
                    .iter()
                    .filter(|grant| grant.user_id == user_id)
                    .map(|grant| (grant.id.clone(), grant.grant_key.clone()))
                    .collect();
                let mut role_sources = Vec::new();
                for member in &memberships {
                    let Some(user) = users.iter().find(|user| {
                        user.id == member.scim_user_id
                            && user.user_id == user_id
                            && user.active
                            && !retired.contains(&user.connection_id)
                    }) else {
                        continue;
                    };
                    let Some(group) = groups.iter().find(|group| {
                        group.id == member.group_id
                            && group.connection_id == user.connection_id
                            && group.provisioning_domain_id == domain
                    }) else {
                        continue;
                    };
                    role_sources.push(alibi_core::store::ScimRoleMappingInput {
                        connection_id: user.connection_id.clone(),
                        provisioning_domain_id: domain.into(),
                        scim_user_id: user.id.clone(),
                        user_id: user.user_id.clone(),
                        source: alibi_core::store::ScimAuthorizationSource::Group {
                            id: group.id.clone(),
                            external_id: group
                                .external_id
                                .clone()
                                .filter(|value| !value.is_empty()),
                            display_name: group.display_name.clone(),
                        },
                    });
                }
                Ok(ScimProjectionPreparedUser {
                    state: ScimProjectedUserState {
                        provisioning_domain_id: domain.into(),
                        user_id,
                        active: sources.iter().any(|source| source.active),
                        sources,
                        grants: Vec::new(),
                    },
                    removed_grant_ids,
                    existing_grants,
                    role_sources,
                })
            })
            .collect()
    }
    pub(super) async fn create_scim_projection_grant_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        data: alibi_core::store::CreateScimProjectionGrant,
    ) -> AuthResult<()> {
        use sea_orm::{ActiveModelTrait, Set};
        _ = grant::ActiveModel {
            id: Set(self
                .generated_id(db, "scimProjectionGrant", "scimProjectionGrant", "id")
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
            connection_id: Set(data.connection_id),
            provisioning_domain_id: Set(data.provisioning_domain_id),
            scim_user_id: Set(data.scim_user_id),
            user_id: Set(data.user_id),
            source_kind: Set("group".into()),
            source_id: Set(data.source_id),
            source_value: Set(Some(data.source_value)),
            role: Set(data.role),
            grant_key: Set(data.grant_key),
            created_at: Set(data.created_at),
            updated_at: Set(data.created_at),
        }
        .insert(db)
        .await
        .map_err(map_db_err)?;
        Ok(())
    }
    pub(super) async fn remove_scim_projection_grants_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        domain: &str,
        user_id: &str,
        ids: &[String],
    ) -> AuthResult<()> {
        for chunk in ids.chunks(SCIM_ID_CHUNK_SIZE) {
            _ = grant::Entity::delete_many()
                .filter(grant::Column::Id.is_in(chunk.iter().cloned()))
                .filter(grant::Column::UserId.eq(user_id))
                .filter(grant::Column::ProvisioningDomainId.eq(domain))
                .exec(db)
                .await
                .map_err(map_db_err)?;
        }
        Ok(())
    }
}
