//! Atomic canonical Group creation and connection fencing.
use super::{
    SqlxStore,
    entities::{scim_group as group, scim_group_member as member, scim_user as user},
};
use crate::{
    model::{self, ActiveRow},
    pool::Exec,
    sql::Sql,
};
use alibi_core::{
    AuthError, AuthResult, AuthSchema,
    store::{CreateScimGroup, ScimGroupRecord, ScimProjectionPreparedUser},
};
impl<S: AuthSchema> SqlxStore<S> {
    pub(super) async fn replace_scim_group_with_exec(
        &self,
        exec: Exec<'_>,
        id: &str,
        data: alibi_core::store::ReplaceScimGroup,
        roles: bool,
    ) -> AuthResult<(ScimGroupRecord, Vec<ScimProjectionPreparedUser>)> {
        use chrono::SubsecRound;
        let current = self
            .lock_scim_group_with_exec(exec, id, &data.connection_id, &data.provisioning_domain_id)
            .await?;
        let now = chrono::Utc::now().trunc_subsecs(3);
        self.assert_scim_group_keys_with_exec(
            exec,
            &data.connection_id,
            &data.display_name_key,
            data.external_id_key.as_deref(),
            Some(id),
        )
        .await?;
        let mut sql = model::select_model::<member::Model>(exec);
        sql.push(" WHERE ");
        sql.compare(
            "scimGroupMember",
            "connectionId",
            " = ",
            data.connection_id.clone(),
        );
        sql.push(" AND ");
        sql.compare("scimGroupMember", "groupId", " = ", id);
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        let existing = exec.fetch_all::<member::Model>(sql).await?;
        let mut affected = data.member_ids.clone();
        for membership in &existing {
            if !affected.contains(&membership.scim_user_id) {
                affected.push(membership.scim_user_id.clone());
            }
        }
        _ = self
            .scim_projection_user_ids_with_exec(exec, &data.provisioning_domain_id, &affected, true)
            .await?;
        if !data.member_ids.is_empty() {
            let mut sql = model::select_model::<user::Model>(exec);
            sql.push(" WHERE ");
            sql.compare(
                "scimUser",
                "connectionId",
                " = ",
                data.connection_id.clone(),
            );
            sql.push(" AND ");
            sql.column("scimUser", "id");
            sql.push(" IN ");
            sql.bind_list(data.member_ids.iter().cloned());
            sql.push(" LIMIT ");
            sql.bind(self.find_many_limit());
            if exec.fetch_all::<user::Model>(sql).await?.len() != data.member_ids.len() {
                return Err(AuthError::Api {
                    status: 400,
                    code: None,
                    message: "One or more Group members are invalid".into(),
                });
            }
        }
        let removed = existing
            .iter()
            .filter(|member| !data.member_ids.contains(&member.scim_user_id))
            .map(|member| member.scim_user_id.clone())
            .collect::<Vec<_>>();
        if !removed.is_empty() {
            let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
            sql.ident("scimGroupMember");
            sql.push(" WHERE ");
            sql.compare(
                "scimGroupMember",
                "connectionId",
                " = ",
                data.connection_id.clone(),
            );
            sql.push(" AND ");
            sql.compare("scimGroupMember", "groupId", " = ", id);
            sql.push(" AND ");
            sql.column("scimGroupMember", "scimUserId");
            sql.push(" IN ");
            sql.bind_list(removed);
            _ = exec.execute(sql).await?;
        }
        for member_id in &data.member_ids {
            if existing
                .iter()
                .any(|member| member.scim_user_id == *member_id)
            {
                continue;
            }
            let mut row = ActiveRow::new();
            row.set(
                "id",
                self.generated_id(exec, "scimGroupMember", "scimGroupMember", "id")
                    .await?
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            );
            row.set("connectionId", data.connection_id.clone());
            row.set("groupId", id.to_owned());
            row.set("scimUserId", member_id.clone());
            row.set(
                "membershipKey",
                alibi_core::store::scim_group_membership_key(&data.connection_id, id, member_id)?,
            );
            row.set("createdAt", now);
            _ = model::insert::<member::Model>(exec, &row).await?;
        }
        let mut sql = Sql::with(exec.engine(), "UPDATE ");
        sql.ident("scimGroup");
        sql.push(" SET ");
        sql.ident("displayName");
        sql.push(" = ");
        sql.bind(data.display_name.clone());
        sql.push(", ");
        sql.ident("displayNameKey");
        sql.push(" = ");
        sql.bind(data.display_name_key);
        sql.push(", ");
        sql.ident("externalId");
        sql.push(" = ");
        sql.bind(data.external_id.clone());
        sql.push(", ");
        sql.ident("externalIdKey");
        sql.push(" = ");
        sql.bind(data.external_id_key);
        sql.push(", ");
        sql.ident("updatedAt");
        sql.push(" = ");
        sql.bind(now);
        sql.push(" WHERE ");
        sql.compare("scimGroup", "id", " = ", id);
        sql.push(" AND ");
        sql.compare(
            "scimGroup",
            "connectionId",
            " = ",
            data.connection_id.clone(),
        );
        model::returning::<group::Model>(&mut sql);
        let updated = exec
            .fetch_optional::<group::Model>(sql)
            .await?
            .ok_or_else(|| AuthError::Api {
                status: 404,
                code: None,
                message: "SCIM Group not found".into(),
            })?;
        let states = self
            .prepare_scim_projection_after_lock_with_exec(
                exec,
                &data.provisioning_domain_id,
                &affected,
                roles,
                true,
            )
            .await?;
        Ok((
            ScimGroupRecord {
                id: updated.id,
                connection_id: updated.connection_id,
                provisioning_domain_id: updated.provisioning_domain_id,
                display_name: updated.display_name,
                external_id: updated.external_id,
                created_at: current.created_at,
                updated_at: updated.updated_at,
            },
            states,
        ))
    }
    async fn lock_scim_group_with_exec(
        &self,
        exec: Exec<'_>,
        id: &str,
        connection: &str,
        domain: &str,
    ) -> AuthResult<group::Model> {
        let mut sql = model::select_model::<group::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimGroup", "id", " = ", id);
        sql.push(" AND ");
        sql.compare("scimGroup", "connectionId", " = ", connection);
        model::limit_one(&mut sql);
        let current = exec
            .fetch_optional::<group::Model>(sql)
            .await?
            .ok_or_else(|| AuthError::Api {
                status: 404,
                code: None,
                message: "SCIM Group not found".into(),
            })?;
        if current.provisioning_domain_id != domain {
            return Err(AuthError::Api {
                status: 409,
                code: None,
                message: "The connection provisioningDomainId changed after resources were created"
                    .into(),
            });
        }
        let mut sql = Sql::with(exec.engine(), "UPDATE ");
        sql.ident("scimGroup");
        sql.push(" SET ");
        sql.ident("revision");
        sql.push(" = ");
        sql.ident("revision");
        sql.push(" + 1 WHERE ");
        sql.compare("scimGroup", "id", " = ", id);
        sql.push(" AND ");
        sql.compare("scimGroup", "connectionId", " = ", connection);
        sql.push(" AND ");
        sql.compare("scimGroup", "revision", " = ", current.revision);
        if exec.execute(sql).await? == 0 {
            return Err(AuthError::internal(
                "The SCIM Group changed concurrently; retry the request.",
            ));
        }
        Ok(current)
    }
    async fn assert_scim_group_keys_with_exec(
        &self,
        exec: Exec<'_>,
        connection: &str,
        name_key: &str,
        external_key: Option<&str>,
        exclude: Option<&str>,
    ) -> AuthResult<()> {
        for (field, key, label) in [
            ("displayNameKey", Some(name_key), "displayName"),
            ("externalIdKey", external_key, "externalId"),
        ] {
            if let Some(key) = key {
                let mut sql = model::select_model::<group::Model>(exec);
                sql.push(" WHERE ");
                sql.compare("scimGroup", "connectionId", " = ", connection.to_owned());
                sql.push(" AND ");
                sql.compare("scimGroup", field, " = ", key);
                model::limit_one(&mut sql);
                if exec
                    .fetch_optional::<group::Model>(sql)
                    .await?
                    .is_some_and(|row| Some(row.id.as_str()) != exclude)
                {
                    return Err(AuthError::Api {
                        status: 409,
                        code: None,
                        message: format!("SCIM Group {label} already exists"),
                    });
                }
            }
        }
        Ok(())
    }
    pub(super) async fn delete_scim_group_with_exec(
        &self,
        exec: Exec<'_>,
        id: &str,
        connection: &str,
        domain: &str,
        roles: bool,
    ) -> AuthResult<Vec<ScimProjectionPreparedUser>> {
        _ = self
            .lock_scim_group_with_exec(exec, id, connection, domain)
            .await?;
        let mut sql = model::select_model::<member::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimGroupMember", "connectionId", " = ", connection);
        sql.push(" AND ");
        sql.compare("scimGroupMember", "groupId", " = ", id);
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        let members = exec
            .fetch_all::<member::Model>(sql)
            .await?
            .into_iter()
            .map(|member| member.scim_user_id)
            .collect::<Vec<_>>();
        _ = self
            .scim_projection_user_ids_with_exec(exec, domain, &members, true)
            .await?;
        let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
        sql.ident("scimGroupMember");
        sql.push(" WHERE ");
        sql.compare("scimGroupMember", "connectionId", " = ", connection);
        sql.push(" AND ");
        sql.compare("scimGroupMember", "groupId", " = ", id);
        _ = exec.execute(sql).await?;
        let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
        sql.ident("scimGroup");
        sql.push(" WHERE ");
        sql.compare("scimGroup", "id", " = ", id);
        sql.push(" AND ");
        sql.compare("scimGroup", "connectionId", " = ", connection);
        _ = exec.execute(sql).await?;
        self.prepare_scim_projection_after_lock_with_exec(exec, domain, &members, roles, true)
            .await
    }
    pub(super) async fn create_scim_group_with_exec(
        &self,
        exec: Exec<'_>,
        data: CreateScimGroup,
        roles: bool,
    ) -> AuthResult<(ScimGroupRecord, Vec<ScimProjectionPreparedUser>)> {
        self.assert_scim_group_keys_with_exec(
            exec,
            &data.connection_id,
            &data.display_name_key,
            data.external_id_key.as_deref(),
            None,
        )
        .await?;
        let id = self
            .generated_id(exec, "scimGroup", "scimGroup", "id")
            .await?
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let mut row = ActiveRow::new();
        row.set("id", id.clone());
        row.set("connectionId", data.connection_id.clone());
        row.set("provisioningDomainId", data.provisioning_domain_id.clone());
        row.set("revision", 0_i64);
        row.set("displayName", data.display_name.clone());
        row.set("displayNameKey", data.display_name_key);
        row.set("externalId", data.external_id.clone());
        row.set("externalIdKey", data.external_id_key);
        row.set("orderKey", data.order_key);
        row.set("createdAt", data.created_at);
        row.set("updatedAt", data.created_at);
        let stored = model::insert::<group::Model>(exec, &row).await?;
        _ = self
            .scim_projection_user_ids_with_exec(
                exec,
                &data.provisioning_domain_id,
                &data.member_ids,
                true,
            )
            .await?;
        if !data.member_ids.is_empty() {
            let mut sql = model::select_model::<user::Model>(exec);
            sql.push(" WHERE ");
            sql.compare(
                "scimUser",
                "connectionId",
                " = ",
                data.connection_id.clone(),
            );
            sql.push(" AND ");
            sql.column("scimUser", "id");
            sql.push(" IN ");
            sql.bind_list(data.member_ids.iter().cloned());
            sql.push(" LIMIT ");
            sql.bind(self.find_many_limit());
            if exec.fetch_all::<user::Model>(sql).await?.len() != data.member_ids.len() {
                return Err(AuthError::Api {
                    status: 400,
                    code: None,
                    message: "One or more Group members are invalid".into(),
                });
            }
        }
        for member_id in &data.member_ids {
            let mut row = ActiveRow::new();
            row.set(
                "id",
                self.generated_id(exec, "scimGroupMember", "scimGroupMember", "id")
                    .await?
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            );
            row.set("connectionId", data.connection_id.clone());
            row.set("groupId", id.clone());
            row.set("scimUserId", member_id.clone());
            row.set(
                "membershipKey",
                alibi_core::store::scim_group_membership_key(&data.connection_id, &id, member_id)?,
            );
            row.set("createdAt", data.created_at);
            _ = model::insert::<member::Model>(exec, &row).await?;
        }
        let states = self
            .prepare_scim_projection_after_lock_with_exec(
                exec,
                &data.provisioning_domain_id,
                &data.member_ids,
                roles,
                true,
            )
            .await?;
        Ok((
            ScimGroupRecord {
                id: stored.id,
                connection_id: stored.connection_id,
                provisioning_domain_id: stored.provisioning_domain_id,
                display_name: stored.display_name,
                external_id: stored.external_id,
                created_at: stored.created_at,
                updated_at: stored.updated_at,
            },
            states,
        ))
    }
    pub(super) async fn fence_scim_connection_with_exec(
        &self,
        exec: Exec<'_>,
        id: &str,
        key: &str,
    ) -> AuthResult<()> {
        let mut sql = Sql::with(exec.engine(), "UPDATE ");
        sql.ident("scimConnectionBinding");
        sql.push(" SET ");
        sql.ident("decommissionRevision");
        sql.push(" = ");
        sql.ident("decommissionRevision");
        sql.push(" + 1 WHERE ");
        sql.compare("scimConnectionBinding", "connectionId", " = ", id);
        sql.push(" AND ");
        sql.compare("scimConnectionBinding", "connectionKey", " = ", key);
        sql.push(" AND ");
        sql.compare(
            "scimConnectionBinding",
            "decommissionStatus",
            " = ",
            "active",
        );
        if exec.execute(sql).await? == 0 {
            return Err(AuthError::Api {
                status: 401,
                code: None,
                message: "SCIM connection is decommissioned".into(),
            });
        }
        Ok(())
    }
}
