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
        let current = self
            .lock_scim_group_with_exec(exec, id, &data.connection_id, &data.provisioning_domain_id)
            .await?;
        self.assert_scim_group_keys_with_exec(
            exec,
            &data.connection_id,
            &data.display_name_key,
            data.external_id_key.as_deref(),
            Some(id),
        )
        .await?;
        let existing = self
            .group_memberships_with_exec(exec, &current, None)
            .await?;
        self.apply_full_group_with_exec(exec, current, data, existing, roles, false)
            .await
    }
    async fn validate_group_members_with_exec(
        &self,
        exec: Exec<'_>,
        connection: &str,
        ids: &[String],
    ) -> AuthResult<()> {
        if !ids.is_empty() {
            let mut sql = model::select_model::<user::Model>(exec);
            sql.push(" WHERE ");
            sql.compare("scimUser", "connectionId", " = ", connection.to_owned());
            sql.push(" AND ");
            sql.column("scimUser", "id");
            sql.push(" IN ");
            sql.bind_list(ids.iter().cloned());
            sql.push(" LIMIT ");
            sql.bind(self.find_many_limit());
            if exec.fetch_all::<user::Model>(sql).await?.len() != ids.len() {
                return Err(AuthError::Api {
                    status: 400,
                    code: None,
                    message: "One or more Group members are invalid".into(),
                });
            }
        }
        Ok(())
    }
    async fn member_delta_with_exec(
        &self,
        exec: Exec<'_>,
        group: &group::Model,
        desired: &[String],
        existing: &[member::Model],
        now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<(Vec<String>, Vec<String>)> {
        let added = desired
            .iter()
            .filter(|id| !existing.iter().any(|member| member.scim_user_id == **id))
            .cloned()
            .collect::<Vec<_>>();
        let removed = existing
            .iter()
            .filter(|member| !desired.contains(&member.scim_user_id))
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
                group.connection_id.clone(),
            );
            sql.push(" AND ");
            sql.compare("scimGroupMember", "groupId", " = ", group.id.clone());
            sql.push(" AND ");
            sql.column("scimGroupMember", "scimUserId");
            sql.push(" IN ");
            sql.bind_list(removed.iter().cloned());
            _ = exec.execute(sql).await?;
        }
        for member_id in desired {
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
            row.set("connectionId", group.connection_id.clone());
            row.set("groupId", group.id.clone());
            row.set("scimUserId", member_id.clone());
            row.set(
                "membershipKey",
                alibi_core::store::scim_group_membership_key(
                    &group.connection_id,
                    &group.id,
                    member_id,
                )?,
            );
            row.set("createdAt", now);
            _ = model::insert::<member::Model>(exec, &row).await?;
        }
        Ok((added, removed))
    }
    async fn apply_full_group_with_exec(
        &self,
        exec: Exec<'_>,
        current: group::Model,
        data: alibi_core::store::ReplaceScimGroup,
        existing: Vec<member::Model>,
        roles: bool,
        patch: bool,
    ) -> AuthResult<(ScimGroupRecord, Vec<ScimProjectionPreparedUser>)> {
        use chrono::SubsecRound;
        let id = current.id.clone();
        let id = id.as_str();
        let now = chrono::Utc::now().trunc_subsecs(3);
        let metadata_changed =
            data.display_name != current.display_name || data.external_id != current.external_id;
        let mut locks = data.member_ids.clone();
        for member in &existing {
            if !locks.contains(&member.scim_user_id) {
                locks.push(member.scim_user_id.clone());
            }
        }
        _ = self
            .scim_projection_user_ids_with_exec(exec, &data.provisioning_domain_id, &locks, true)
            .await?;
        if patch {
            self.assert_scim_group_keys_with_exec(
                exec,
                &data.connection_id,
                &data.display_name_key,
                data.external_id_key.as_deref(),
                Some(id),
            )
            .await?;
        }
        self.validate_group_members_with_exec(exec, &data.connection_id, &data.member_ids)
            .await?;
        let (added, removed) = self
            .member_delta_with_exec(exec, &current, &data.member_ids, &existing, now)
            .await?;
        if patch && !metadata_changed && added.is_empty() && removed.is_empty() {
            return Ok((group_record(&current), Vec::new()));
        }
        let mut affected = if !patch || metadata_changed {
            data.member_ids.clone()
        } else {
            Vec::new()
        };
        for id in added.into_iter().chain(removed) {
            if !affected.contains(&id) {
                affected.push(id);
            }
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
        Ok((group_record(&updated), states))
    }
    async fn group_memberships_with_exec(
        &self,
        exec: Exec<'_>,
        group: &group::Model,
        targets: Option<&[String]>,
    ) -> AuthResult<Vec<member::Model>> {
        let mut sql = model::select_model::<member::Model>(exec);
        sql.push(" WHERE ");
        sql.compare(
            "scimGroupMember",
            "connectionId",
            " = ",
            group.connection_id.clone(),
        );
        sql.push(" AND ");
        sql.compare("scimGroupMember", "groupId", " = ", group.id.clone());
        if let Some(targets) = targets {
            sql.push(" AND ");
            sql.column("scimGroupMember", "scimUserId");
            sql.push(" IN ");
            sql.bind_list(targets.iter().cloned());
        }
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        exec.fetch_all::<member::Model>(sql).await
    }
    pub(super) async fn patch_scim_group_with_exec(
        &self,
        exec: Exec<'_>,
        id: &str,
        connection: &str,
        domain: &str,
        patch: alibi_core::store::ScimGroupPatch,
        roles: bool,
    ) -> AuthResult<(ScimGroupRecord, Vec<ScimProjectionPreparedUser>)> {
        use alibi_core::store::{
            ScimGroupPatch, apply_scim_group_patch, check_scim_group_cardinality,
        };
        use chrono::SubsecRound;
        let current = self
            .lock_scim_group_with_exec(exec, id, connection, domain)
            .await?;
        match patch {
            ScimGroupPatch::Full(operations) => {
                let existing = self
                    .group_memberships_with_exec(exec, &current, None)
                    .await?;
                let ids = existing
                    .iter()
                    .map(|member| member.scim_user_id.clone())
                    .collect::<Vec<_>>();
                let data = apply_scim_group_patch(&group_record(&current), &ids, &operations)?;
                self.apply_full_group_with_exec(exec, current, data, existing, roles, true)
                    .await
            }
            ScimGroupPatch::Incremental { desired, validate } => {
                let now = chrono::Utc::now().trunc_subsecs(3);
                let targets = desired.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>();
                _ = self
                    .scim_projection_user_ids_with_exec(exec, domain, &targets, true)
                    .await?;
                self.validate_group_members_with_exec(exec, connection, &validate)
                    .await?;
                if targets.is_empty() {
                    return Ok((group_record(&current), Vec::new()));
                }
                let existing = self
                    .group_memberships_with_exec(exec, &current, Some(&targets))
                    .await?;
                let wanted = desired
                    .into_iter()
                    .filter_map(|(id, wanted)| wanted.then_some(id))
                    .collect::<Vec<_>>();
                let added = wanted
                    .iter()
                    .filter(|id| !existing.iter().any(|member| member.scim_user_id == **id))
                    .count();
                let removed = existing
                    .iter()
                    .filter(|member| !wanted.contains(&member.scim_user_id))
                    .count();
                let mut count = Sql::with(exec.engine(), "SELECT COUNT(*) FROM ");
                count.ident("scimGroupMember");
                count.push(" WHERE ");
                count.compare("scimGroupMember", "connectionId", " = ", connection);
                count.push(" AND ");
                count.compare("scimGroupMember", "groupId", " = ", id);
                let count = exec.fetch_scalar::<i64>(count).await?.unwrap_or_default();
                let count = usize::try_from(count)
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                check_scim_group_cardinality(count.saturating_add(added).saturating_sub(removed))?;
                let (added, removed) = self
                    .member_delta_with_exec(exec, &current, &wanted, &existing, now)
                    .await?;
                if added.is_empty() && removed.is_empty() {
                    return Ok((group_record(&current), Vec::new()));
                }
                let mut sql = Sql::with(exec.engine(), "UPDATE ");
                sql.ident("scimGroup");
                sql.push(" SET ");
                sql.ident("updatedAt");
                sql.push(" = ");
                sql.bind(now);
                sql.push(" WHERE ");
                sql.compare("scimGroup", "id", " = ", id);
                sql.push(" AND ");
                sql.compare("scimGroup", "connectionId", " = ", connection);
                model::returning::<group::Model>(&mut sql);
                let updated = exec
                    .fetch_optional::<group::Model>(sql)
                    .await?
                    .ok_or_else(|| AuthError::Api {
                        status: 404,
                        code: None,
                        message: "SCIM Group not found".into(),
                    })?;
                let mut affected = added;
                for id in removed {
                    if !affected.contains(&id) {
                        affected.push(id);
                    }
                }
                let states = self
                    .prepare_scim_projection_after_lock_with_exec(
                        exec, domain, &affected, roles, true,
                    )
                    .await?;
                Ok((group_record(&updated), states))
            }
        }
    }
    pub(super) async fn lock_scim_group_with_exec(
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

fn group_record(group: &group::Model) -> ScimGroupRecord {
    ScimGroupRecord {
        id: group.id.clone(),
        connection_id: group.connection_id.clone(),
        provisioning_domain_id: group.provisioning_domain_id.clone(),
        display_name: group.display_name.clone(),
        external_id: group.external_id.clone(),
        created_at: group.created_at,
        updated_at: group.updated_at,
    }
}
