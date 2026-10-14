//! Atomic User retirement, identity tombstones, and membership fences.
use super::{
    SqlxStore,
    entities::{
        scim_group_member as member, scim_identity_tombstone as tombstone, scim_subject as subject,
        scim_user as user,
    },
};
use crate::{
    model::{self, ActiveRow},
    pool::Exec,
    sql::Sql,
};
use alibi_core::{AuthError, AuthResult, AuthSchema, store::ScimProjectionPreparedUser};
use chrono::SubsecRound;
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
impl<S: AuthSchema> SqlxStore<S> {
    async fn scim_user_owned_with_exec(
        &self,
        exec: Exec<'_>,
        id: &str,
        connection: &str,
        domain: &str,
    ) -> AuthResult<user::Model> {
        let mut sql = model::select_model::<user::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimUser", "id", " = ", id);
        sql.push(" AND ");
        sql.compare("scimUser", "connectionId", " = ", connection);
        model::limit_one(&mut sql);
        let source = exec
            .fetch_optional::<user::Model>(sql)
            .await?
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
    async fn scim_user_memberships_with_exec(
        &self,
        exec: Exec<'_>,
        id: &str,
        connection: &str,
    ) -> AuthResult<Vec<member::Model>> {
        let mut sql = model::select_model::<member::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimGroupMember", "connectionId", " = ", connection);
        sql.push(" AND ");
        sql.compare("scimGroupMember", "scimUserId", " = ", id);
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        exec.fetch_all::<member::Model>(sql).await
    }
    pub(super) async fn delete_scim_user_with_exec(
        &self,
        exec: Exec<'_>,
        id: &str,
        connection: &str,
        domain: &str,
        roles: bool,
    ) -> AuthResult<(String, Vec<ScimProjectionPreparedUser>)> {
        let before = self
            .scim_user_owned_with_exec(exec, id, connection, domain)
            .await?;
        let mut sql = model::select_model::<subject::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimSubject", "userId", " = ", before.user_id.clone());
        model::limit_one(&mut sql);
        let subject = exec
            .fetch_optional::<subject::Model>(sql)
            .await?
            .ok_or_else(|| AuthError::Api {
                status: 500,
                code: None,
                message: "The SCIM User subject is missing".into(),
            })?;
        let memberships = self
            .scim_user_memberships_with_exec(exec, id, connection)
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
                self.lock_scim_group_with_exec(exec, id, connection, domain)
                    .await
                    .map_err(|error| match error {
                        AuthError::Api { status: 404, .. } => group_conflict(),
                        error => error,
                    })?,
            );
        }
        let now = chrono::Utc::now().trunc_subsecs(3);
        let mut sql = Sql::with(exec.engine(), "UPDATE ");
        sql.ident("scimSubject");
        sql.push(" SET ");
        sql.ident("revision");
        sql.push(" = ");
        sql.ident("revision");
        sql.push(" + 1, ");
        sql.ident("updatedAt");
        sql.push(" = ");
        sql.bind(now);
        sql.push(" WHERE ");
        sql.compare("scimSubject", "id", " = ", subject.id.clone());
        sql.push(" AND ");
        sql.compare("scimSubject", "revision", " = ", subject.revision);
        model::returning::<subject::Model>(&mut sql);
        let subject = exec
            .fetch_optional::<subject::Model>(sql)
            .await?
            .ok_or_else(identity_conflict)?;
        let source = self
            .scim_user_owned_with_exec(exec, id, connection, domain)
            .await?;
        if source.user_id != before.user_id {
            return Err(AuthError::Api {
                status: 409,
                code: None,
                message: "The SCIM User identity changed concurrently".into(),
            });
        }
        let after = self
            .scim_user_memberships_with_exec(exec, id, connection)
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
            let mut sql = model::select_model::<tombstone::Model>(exec);
            sql.push(" WHERE ");
            sql.compare("scimIdentityTombstone", "externalIdKey", " = ", key.clone());
            model::limit_one(&mut sql);
            if let Some(existing) = exec.fetch_optional::<tombstone::Model>(sql).await? {
                let mut sql = Sql::with(exec.engine(), "UPDATE ");
                sql.ident("scimIdentityTombstone");
                sql.push(" SET ");
                sql.ident("userId");
                sql.push(" = ");
                sql.bind(source.user_id.clone());
                sql.push(", ");
                sql.ident("profile");
                sql.push(" = ");
                sql.bind(profile);
                sql.push(", ");
                sql.ident("deletedAt");
                sql.push(" = ");
                sql.bind(now);
                sql.push(" WHERE ");
                sql.compare("scimIdentityTombstone", "id", " = ", existing.id);
                _ = exec.execute(sql).await?;
            } else {
                let mut row = ActiveRow::new();
                row.set(
                    "id",
                    self.generated_id(exec, "scimIdentityTombstone", "scimIdentityTombstone", "id")
                        .await?
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                );
                row.set("connectionId", source.connection_id.clone());
                row.set(
                    "provisioningDomainId",
                    source.provisioning_domain_id.clone(),
                );
                row.set("externalId", external.clone());
                row.set("externalIdKey", key.clone());
                row.set("userId", source.user_id.clone());
                row.set("profile", profile);
                row.set("deletedAt", now);
                _ = model::insert::<tombstone::Model>(exec, &row).await?;
            }
        }
        let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
        sql.ident("scimGroupMember");
        sql.push(" WHERE ");
        sql.compare("scimGroupMember", "connectionId", " = ", connection);
        sql.push(" AND ");
        sql.compare("scimGroupMember", "scimUserId", " = ", id);
        _ = exec.execute(sql).await?;
        for group in groups {
            let revision = group.revision.checked_add(1).ok_or_else(group_conflict)?;
            let mut sql = Sql::with(exec.engine(), "UPDATE ");
            sql.ident("scimGroup");
            sql.push(" SET ");
            sql.ident("updatedAt");
            sql.push(" = ");
            sql.bind(now);
            sql.push(" WHERE ");
            sql.compare("scimGroup", "id", " = ", group.id);
            sql.push(" AND ");
            sql.compare("scimGroup", "connectionId", " = ", connection);
            sql.push(" AND ");
            sql.compare("scimGroup", "revision", " = ", revision);
            if exec.execute(sql).await? == 0 {
                return Err(group_conflict());
            }
        }
        let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
        sql.ident("scimProjectionGrant");
        sql.push(" WHERE ");
        sql.compare("scimProjectionGrant", "scimUserId", " = ", id);
        _ = exec.execute(sql).await?;
        let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
        sql.ident("scimUser");
        sql.push(" WHERE ");
        sql.compare("scimUser", "id", " = ", id);
        sql.push(" AND ");
        sql.compare("scimUser", "connectionId", " = ", connection);
        _ = exec.execute(sql).await?;
        if subject.profile_source_id.as_deref() == Some(id) {
            let mut sql = Sql::with(exec.engine(), "UPDATE ");
            sql.ident("scimSubject");
            sql.push(" SET ");
            sql.ident("profileSourceId");
            sql.push(" = NULL, ");
            sql.ident("revision");
            sql.push(" = ");
            sql.ident("revision");
            sql.push(" + 1, ");
            sql.ident("updatedAt");
            sql.push(" = ");
            sql.bind(now);
            sql.push(" WHERE ");
            sql.compare("scimSubject", "id", " = ", subject.id);
            sql.push(" AND ");
            sql.compare("scimSubject", "revision", " = ", subject.revision);
            sql.push(" AND ");
            sql.compare("scimSubject", "profileSourceId", " = ", id);
            if exec.execute(sql).await? == 0 {
                return Err(identity_conflict());
            }
        }
        let states = self
            .prepare_scim_projection_for_users_with_exec(
                exec,
                domain,
                vec![source.user_id.clone()],
                roles,
            )
            .await?;
        Ok((source.user_id, states))
    }
}
