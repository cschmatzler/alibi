//! Atomic canonical Group creation and connection fencing.
use super::{
    SeaOrmStore,
    entities::{
        scim_connection_binding as binding, scim_group as group, scim_group_member as member,
        scim_user as user,
    },
    map_db_err,
};
use alibi_core::{
    AuthError, AuthResult, AuthSchema,
    store::{CreateScimGroup, ScimGroupRecord, ScimProjectionPreparedUser},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, ExprTrait, QueryFilter,
    QuerySelect, Set, sea_query::Expr,
};
impl<S: AuthSchema> SeaOrmStore<S> {
    pub(super) async fn replace_scim_group_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        id: &str,
        data: alibi_core::store::ReplaceScimGroup,
        roles: bool,
    ) -> AuthResult<(ScimGroupRecord, Vec<ScimProjectionPreparedUser>)> {
        use chrono::SubsecRound;
        use sea_orm::IntoActiveModel;
        let current = self
            .lock_scim_group_with_connection(
                db,
                id,
                &data.connection_id,
                &data.provisioning_domain_id,
            )
            .await?;
        let now = chrono::Utc::now().trunc_subsecs(3);
        self.assert_scim_group_keys_with_connection(
            db,
            &data.connection_id,
            &data.display_name_key,
            data.external_id_key.as_deref(),
            Some(id),
        )
        .await?;
        let limit = u64::try_from(self.config.advanced.database.default_find_many_limit)
            .unwrap_or(u64::MAX);
        let existing = member::Entity::find()
            .filter(member::Column::ConnectionId.eq(&data.connection_id))
            .filter(member::Column::GroupId.eq(id))
            .limit(limit)
            .all(db)
            .await
            .map_err(map_db_err)?;
        let mut affected = data.member_ids.clone();
        for membership in &existing {
            if !affected.contains(&membership.scim_user_id) {
                affected.push(membership.scim_user_id.clone());
            }
        }
        _ = self
            .scim_projection_user_ids_with_connection(
                db,
                &data.provisioning_domain_id,
                &affected,
                true,
            )
            .await?;
        if !data.member_ids.is_empty()
            && user::Entity::find()
                .filter(user::Column::ConnectionId.eq(&data.connection_id))
                .filter(user::Column::Id.is_in(data.member_ids.iter().cloned()))
                .limit(limit)
                .all(db)
                .await
                .map_err(map_db_err)?
                .len()
                != data.member_ids.len()
        {
            return Err(AuthError::Api {
                status: 400,
                code: None,
                message: "One or more Group members are invalid".into(),
            });
        }
        let removed = existing
            .iter()
            .filter(|member| !data.member_ids.contains(&member.scim_user_id))
            .map(|member| member.scim_user_id.clone())
            .collect::<Vec<_>>();
        if !removed.is_empty() {
            _ = member::Entity::delete_many()
                .filter(member::Column::ConnectionId.eq(&data.connection_id))
                .filter(member::Column::GroupId.eq(id))
                .filter(member::Column::ScimUserId.is_in(removed))
                .exec(db)
                .await
                .map_err(map_db_err)?;
        }
        for member_id in &data.member_ids {
            if existing
                .iter()
                .any(|member| member.scim_user_id == *member_id)
            {
                continue;
            }
            _ = member::ActiveModel {
                id: Set(self
                    .generated_id(db, "scimGroupMember", "scimGroupMember", "id")
                    .await?
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                connection_id: Set(data.connection_id.clone()),
                group_id: Set(id.to_owned()),
                scim_user_id: Set(member_id.clone()),
                membership_key: Set(alibi_core::store::scim_group_membership_key(
                    &data.connection_id,
                    id,
                    member_id,
                )?),
                created_at: Set(now),
            }
            .insert(db)
            .await
            .map_err(map_db_err)?;
        }
        let mut updated = current.into_active_model();
        updated.display_name = Set(data.display_name);
        updated.display_name_key = Set(data.display_name_key);
        updated.external_id = Set(data.external_id);
        updated.external_id_key = Set(data.external_id_key);
        updated.updated_at = Set(now);
        let updated = updated.update(db).await.map_err(map_db_err)?;
        let states = self
            .prepare_scim_projection_after_lock_with_connection(
                db,
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
                created_at: updated.created_at,
                updated_at: updated.updated_at,
            },
            states,
        ))
    }
    async fn lock_scim_group_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        id: &str,
        connection: &str,
        domain: &str,
    ) -> AuthResult<group::Model> {
        let current = group::Entity::find()
            .filter(group::Column::Id.eq(id))
            .filter(group::Column::ConnectionId.eq(connection))
            .one(db)
            .await
            .map_err(map_db_err)?
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
        let locked = group::Entity::update_many()
            .col_expr(
                group::Column::Revision,
                Expr::col(group::Column::Revision).add(1),
            )
            .filter(group::Column::Id.eq(id))
            .filter(group::Column::ConnectionId.eq(connection))
            .filter(group::Column::Revision.eq(current.revision))
            .exec(db)
            .await
            .map_err(map_db_err)?;
        if locked.rows_affected == 0 {
            return Err(AuthError::internal(
                "The SCIM Group changed concurrently; retry the request.",
            ));
        }
        Ok(current)
    }
    async fn assert_scim_group_keys_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        connection: &str,
        name_key: &str,
        external_key: Option<&str>,
        exclude: Option<&str>,
    ) -> AuthResult<()> {
        for (column, key, label) in [
            (group::Column::DisplayNameKey, Some(name_key), "displayName"),
            (group::Column::ExternalIdKey, external_key, "externalId"),
        ] {
            if let Some(key) = key
                && group::Entity::find()
                    .filter(group::Column::ConnectionId.eq(connection))
                    .filter(column.eq(key))
                    .one(db)
                    .await
                    .map_err(map_db_err)?
                    .is_some_and(|row| Some(row.id.as_str()) != exclude)
            {
                return Err(AuthError::Api {
                    status: 409,
                    code: None,
                    message: format!("SCIM Group {label} already exists"),
                });
            }
        }
        Ok(())
    }
    pub(super) async fn delete_scim_group_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        id: &str,
        connection: &str,
        domain: &str,
        roles: bool,
    ) -> AuthResult<Vec<ScimProjectionPreparedUser>> {
        _ = self
            .lock_scim_group_with_connection(db, id, connection, domain)
            .await?;
        let limit = u64::try_from(self.config.advanced.database.default_find_many_limit)
            .unwrap_or(u64::MAX);
        let members = member::Entity::find()
            .filter(member::Column::ConnectionId.eq(connection))
            .filter(member::Column::GroupId.eq(id))
            .limit(limit)
            .all(db)
            .await
            .map_err(map_db_err)?
            .into_iter()
            .map(|member| member.scim_user_id)
            .collect::<Vec<_>>();
        _ = self
            .scim_projection_user_ids_with_connection(db, domain, &members, true)
            .await?;
        _ = member::Entity::delete_many()
            .filter(member::Column::ConnectionId.eq(connection))
            .filter(member::Column::GroupId.eq(id))
            .exec(db)
            .await
            .map_err(map_db_err)?;
        _ = group::Entity::delete_many()
            .filter(group::Column::Id.eq(id))
            .filter(group::Column::ConnectionId.eq(connection))
            .exec(db)
            .await
            .map_err(map_db_err)?;
        self.prepare_scim_projection_after_lock_with_connection(db, domain, &members, roles, true)
            .await
    }
    pub(super) async fn create_scim_group_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        data: CreateScimGroup,
        roles: bool,
    ) -> AuthResult<(ScimGroupRecord, Vec<ScimProjectionPreparedUser>)> {
        self.assert_scim_group_keys_with_connection(
            db,
            &data.connection_id,
            &data.display_name_key,
            data.external_id_key.as_deref(),
            None,
        )
        .await?;
        let id = self
            .generated_id(db, "scimGroup", "scimGroup", "id")
            .await?
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let stored = group::ActiveModel {
            id: Set(id.clone()),
            connection_id: Set(data.connection_id.clone()),
            provisioning_domain_id: Set(data.provisioning_domain_id.clone()),
            revision: Set(0),
            display_name: Set(data.display_name.clone()),
            display_name_key: Set(data.display_name_key),
            external_id: Set(data.external_id.clone()),
            external_id_key: Set(data.external_id_key),
            order_key: Set(data.order_key),
            created_at: Set(data.created_at),
            updated_at: Set(data.created_at),
        }
        .insert(db)
        .await
        .map_err(map_db_err)?;
        _ = self
            .scim_projection_user_ids_with_connection(
                db,
                &data.provisioning_domain_id,
                &data.member_ids,
                true,
            )
            .await?;
        if !data.member_ids.is_empty() {
            let limit = u64::try_from(self.config.advanced.database.default_find_many_limit)
                .unwrap_or(u64::MAX);
            if user::Entity::find()
                .filter(user::Column::ConnectionId.eq(&data.connection_id))
                .filter(user::Column::Id.is_in(data.member_ids.iter().cloned()))
                .limit(limit)
                .all(db)
                .await
                .map_err(map_db_err)?
                .len()
                != data.member_ids.len()
            {
                return Err(AuthError::Api {
                    status: 400,
                    code: None,
                    message: "One or more Group members are invalid".into(),
                });
            }
        }
        for member_id in &data.member_ids {
            _ = member::ActiveModel {
                id: Set(self
                    .generated_id(db, "scimGroupMember", "scimGroupMember", "id")
                    .await?
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                connection_id: Set(data.connection_id.clone()),
                group_id: Set(id.clone()),
                scim_user_id: Set(member_id.clone()),
                membership_key: Set(alibi_core::store::scim_group_membership_key(
                    &data.connection_id,
                    &id,
                    member_id,
                )?),
                created_at: Set(data.created_at),
            }
            .insert(db)
            .await
            .map_err(map_db_err)?;
        }
        let states = self
            .prepare_scim_projection_after_lock_with_connection(
                db,
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
    pub(super) async fn fence_scim_connection_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        id: &str,
        key: &str,
    ) -> AuthResult<()> {
        if binding::Entity::update_many()
            .col_expr(
                binding::Column::DecommissionRevision,
                Expr::col(binding::Column::DecommissionRevision).add(1),
            )
            .filter(binding::Column::ConnectionId.eq(id))
            .filter(binding::Column::ConnectionKey.eq(key))
            .filter(binding::Column::DecommissionStatus.eq("active"))
            .exec(db)
            .await
            .map_err(map_db_err)?
            .rows_affected
            == 0
        {
            return Err(AuthError::Api {
                status: 401,
                code: None,
                message: "SCIM connection is decommissioned".into(),
            });
        }
        Ok(())
    }
}
