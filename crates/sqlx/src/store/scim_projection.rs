use super::entities::{scim_group as group, scim_group_member as membership};
use super::{
    SqlxStore,
    entities::{
        scim_connection_binding as binding, scim_projection_grant as grant,
        scim_subject as subject, scim_user as user,
    },
};
use crate::{model, pool::Exec, sql::Sql};
use alibi_core::{
    AuthError, AuthResult, AuthSchema,
    store::{ScimIdentitySource, ScimProjectedUserState, ScimProjectionPreparedUser},
};
use chrono::SubsecRound;
/// Ids per `IN` list, like the reference's `chunkSCIMIds`; stays under legacy SQLite's 999 bound values.
pub(super) const SCIM_ID_CHUNK_SIZE: usize = 500;
/// Reads every row matching one `IN` predicate per id chunk. A bounded read caps each chunk at
/// its length (the reference's `limit: chunk.length`); otherwise no limit applies, matching its
/// `SCIM_UNBOUNDED_ROW_LIMIT` reads that bypass `defaultFindManyLimit`.
pub(super) async fn fetch_scim_chunks<M: model::SqlxModel>(
    exec: Exec<'_>,
    ids: &[String],
    bounded: bool,
    predicates: impl Fn(&mut Sql, &[String]),
) -> AuthResult<Vec<M>> {
    let mut rows = Vec::new();
    for chunk in ids.chunks(SCIM_ID_CHUNK_SIZE) {
        let mut sql = model::select_model::<M>(exec);
        sql.push(" WHERE ");
        predicates(&mut sql, chunk);
        if bounded {
            sql.push(" LIMIT ");
            sql.bind(
                i64::try_from(chunk.len())
                    .map_err(|error| AuthError::internal(error.to_string()))?,
            );
        }
        rows.extend(exec.fetch_all::<M>(sql).await?);
    }
    Ok(rows)
}
impl<S: AuthSchema> SqlxStore<S> {
    pub(super) async fn scim_projection_user_ids_with_exec(
        &self,
        exec: Exec<'_>,
        domain: &str,
        ids: &[String],
        lock: bool,
    ) -> AuthResult<Vec<String>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let requested = fetch_scim_chunks::<user::Model>(exec, ids, true, |sql, chunk| {
            sql.compare("scimUser", "provisioningDomainId", " = ", domain);
            sql.push(" AND ");
            sql.column("scimUser", "id");
            sql.push(" IN ");
            sql.bind_list(chunk.iter().cloned());
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
            let subjects =
                fetch_scim_chunks::<subject::Model>(exec, &sorted, true, |sql, chunk| {
                    sql.column("scimSubject", "userId");
                    sql.push(" IN ");
                    sql.bind_list(chunk.iter().cloned());
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
                let mut sql = Sql::with(exec.engine(), "UPDATE ");
                sql.ident("scimSubject");
                sql.push(" SET ");
                sql.ident("revision");
                sql.push(" = ");
                sql.ident("revision");
                sql.push(" + 1, ");
                sql.ident("updatedAt");
                sql.push(" = ");
                sql.bind(updated_at);
                sql.push(" WHERE ");
                sql.compare("scimSubject", "id", " = ", subject.id.clone());
                sql.push(" AND ");
                sql.compare("scimSubject", "revision", " = ", subject.revision);
                if exec.execute(sql).await? == 0 {
                    return Err(AuthError::internal(
                        "The SCIM projection subject changed concurrently; retry the request.",
                    ));
                }
            }
        }
        Ok(user_ids)
    }
    pub(super) async fn prepare_scim_projection_with_exec(
        &self,
        exec: Exec<'_>,
        domain: &str,
        ids: &[String],
        roles: bool,
    ) -> AuthResult<Vec<ScimProjectionPreparedUser>> {
        self.prepare_scim_projection_after_lock_with_exec(exec, domain, ids, roles, false)
            .await
    }
    pub(super) async fn prepare_scim_projection_after_lock_with_exec(
        &self,
        exec: Exec<'_>,
        domain: &str,
        ids: &[String],
        roles: bool,
        locked: bool,
    ) -> AuthResult<Vec<ScimProjectionPreparedUser>> {
        let user_ids = self
            .scim_projection_user_ids_with_exec(exec, domain, ids, !locked)
            .await?;
        if user_ids.is_empty() {
            return Ok(Vec::new());
        }
        self.prepare_scim_projection_for_users_with_exec(exec, domain, user_ids, roles)
            .await
    }
    pub(super) async fn prepare_scim_projection_for_users_with_exec(
        &self,
        exec: Exec<'_>,
        domain: &str,
        user_ids: Vec<String>,
        roles: bool,
    ) -> AuthResult<Vec<ScimProjectionPreparedUser>> {
        if user_ids.is_empty() {
            return Ok(Vec::new());
        }
        let users = fetch_scim_chunks::<user::Model>(exec, &user_ids, false, |sql, chunk| {
            sql.compare("scimUser", "provisioningDomainId", " = ", domain);
            sql.push(" AND ");
            sql.column("scimUser", "userId");
            sql.push(" IN ");
            sql.bind_list(chunk.iter().cloned());
        })
        .await?;
        let retired =
            retired_scim_connections(exec, users.iter().map(|user| user.connection_id.clone()))
                .await?;
        let grants = fetch_scim_chunks::<grant::Model>(exec, &user_ids, false, |sql, chunk| {
            sql.compare("scimProjectionGrant", "provisioningDomainId", " = ", domain);
            sql.push(" AND ");
            sql.column("scimProjectionGrant", "userId");
            sql.push(" IN ");
            sql.bind_list(chunk.iter().cloned());
        })
        .await?;
        let active_ids = users
            .iter()
            .filter(|user| user.active && !retired.contains(&user.connection_id))
            .map(|user| user.id.clone())
            .collect::<Vec<_>>();
        let memberships = if roles {
            fetch_scim_chunks::<membership::Model>(exec, &active_ids, false, |sql, chunk| {
                sql.column("scimGroupMember", "scimUserId");
                sql.push(" IN ");
                sql.bind_list(chunk.iter().cloned());
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
        let groups = fetch_scim_chunks::<group::Model>(exec, &group_ids, true, |sql, chunk| {
            sql.column("scimGroup", "id");
            sql.push(" IN ");
            sql.bind_list(chunk.iter().cloned());
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
    pub(super) async fn create_scim_projection_grant_with_exec(
        &self,
        exec: Exec<'_>,
        data: alibi_core::store::CreateScimProjectionGrant,
    ) -> AuthResult<()> {
        use crate::model::ActiveRow;
        let mut row = ActiveRow::new();
        row.set(
            "id",
            self.generated_id(exec, "scimProjectionGrant", "scimProjectionGrant", "id")
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        );
        row.set("connectionId", data.connection_id);
        row.set("provisioningDomainId", data.provisioning_domain_id);
        row.set("scimUserId", data.scim_user_id);
        row.set("userId", data.user_id);
        row.set("sourceKind", "group");
        row.set("sourceId", data.source_id);
        row.set("sourceValue", Some(data.source_value));
        row.set("role", data.role);
        row.set("grantKey", data.grant_key);
        row.set("createdAt", data.created_at);
        row.set("updatedAt", data.created_at);
        _ = model::insert::<grant::Model>(exec, &row).await?;
        Ok(())
    }
    pub(super) async fn remove_scim_projection_grants_with_exec(
        &self,
        exec: Exec<'_>,
        domain: &str,
        user_id: &str,
        ids: &[String],
    ) -> AuthResult<()> {
        for chunk in ids.chunks(SCIM_ID_CHUNK_SIZE) {
            let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
            sql.ident("scimProjectionGrant");
            sql.push(" WHERE ");
            sql.compare("scimProjectionGrant", "provisioningDomainId", " = ", domain);
            sql.push(" AND ");
            sql.compare("scimProjectionGrant", "userId", " = ", user_id);
            sql.push(" AND ");
            sql.column("scimProjectionGrant", "id");
            sql.push(" IN ");
            sql.bind_list(chunk.iter().cloned());
            _ = exec.execute(sql).await?;
        }
        Ok(())
    }
}
/// Connections among `connections` whose binding is no longer active.
pub(super) async fn retired_scim_connections(
    exec: Exec<'_>,
    connections: impl IntoIterator<Item = String>,
) -> AuthResult<std::collections::HashSet<String>> {
    let connections = connections
        .into_iter()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(
        fetch_scim_chunks::<binding::Model>(exec, &connections, true, |sql, chunk| {
            sql.column("scimConnectionBinding", "connectionId");
            sql.push(" IN ");
            sql.bind_list(chunk.iter().cloned());
        })
        .await?
        .into_iter()
        .filter(|binding| binding.decommission_status != "active")
        .map(|binding| binding.connection_id)
        .collect(),
    )
}
