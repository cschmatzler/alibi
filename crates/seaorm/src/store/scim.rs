use super::map_db_err;
use super::{
    SeaOrmStore,
    entities::{
        scim_managed_connection as connection, scim_managed_connection_event as event,
        scim_managed_credential as credential,
    },
};
use alibi_core::{
    AuthResult, AuthSchema,
    store::{CreateScimManagedConnection, ScimManagedCreation, ScimManagedStore},
};
use async_trait::async_trait;
use chrono::SubsecRound;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ExprTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Set, TransactionTrait, sea_query::Expr,
};
#[async_trait]
impl<S: AuthSchema> ScimManagedStore for SeaOrmStore<S> {
    async fn scim_group_domain_stable(&self, connection: &str, domain: &str) -> AuthResult<bool> {
        use super::entities::scim_group as group;
        Ok(group::Entity::find()
            .filter(group::Column::ConnectionId.eq(connection))
            .filter(group::Column::ProvisioningDomainId.ne(domain))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .is_none())
    }
    async fn list_scim_groups(
        &self,
        connection: &str,
        filters: &[(String, String)],
        offset: i64,
        count: i64,
    ) -> AuthResult<alibi_core::store::ScimGroupPage> {
        use super::entities::scim_group as group;
        let mut query = group::Entity::find().filter(group::Column::ConnectionId.eq(connection));
        for (field, value) in filters {
            let field = match field.as_str() {
                "id" => group::Column::Id,
                "displayNameKey" => group::Column::DisplayNameKey,
                "externalIdKey" => group::Column::ExternalIdKey,
                _ => {
                    return Err(alibi_core::AuthError::internal(
                        "Unsupported SCIM group predicate",
                    ));
                }
            };
            query = query.filter(field.eq(value));
        }
        let total_results = i64::try_from(
            query
                .clone()
                .count(self.scoped_connection())
                .await
                .map_err(map_db_err)?,
        )
        .map_err(|error| alibi_core::AuthError::internal(error.to_string()))?;
        let groups = if count == 0 {
            Vec::new()
        } else {
            query
                .order_by_asc(group::Column::OrderKey)
                .limit(
                    u64::try_from(count)
                        .map_err(|error| alibi_core::AuthError::internal(error.to_string()))?,
                )
                .offset(
                    u64::try_from(offset)
                        .map_err(|error| alibi_core::AuthError::internal(error.to_string()))?,
                )
                .all(self.scoped_connection())
                .await
                .map_err(map_db_err)?
        };
        Ok(alibi_core::store::ScimGroupPage {
            total_results,
            groups: groups
                .into_iter()
                .map(|row| alibi_core::store::ScimGroupRecord {
                    id: row.id,
                    connection_id: row.connection_id,
                    provisioning_domain_id: row.provisioning_domain_id,
                    display_name: row.display_name,
                    external_id: row.external_id,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                })
                .collect(),
        })
    }

    async fn get_scim_user(
        &self,
        id: &str,
        connection: &str,
    ) -> AuthResult<Option<alibi_core::store::ScimUserRecord>> {
        use super::entities::scim_user as user;
        let row = user::Entity::find()
            .filter(user::Column::Id.eq(id))
            .filter(user::Column::ConnectionId.eq(connection))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        Ok(row.map(|row| alibi_core::store::ScimUserRecord {
            id: row.id,
            connection_id: row.connection_id,
            provisioning_domain_id: row.provisioning_domain_id,
            user_name: row.user_name,
            display_name: row.display_name,
            active: row.active,
            external_id: row.external_id,
            formatted_name: row.formatted_name,
            given_name: row.given_name,
            family_name: row.family_name,
            serialized_emails: row.serialized_emails,
            serialized_attributes: row.serialized_attributes,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }))
    }

    async fn find_scim_managed_credential(
        &self,
        id: &str,
    ) -> AuthResult<Option<alibi_core::store::ScimManagedCredential>> {
        Ok(credential::Entity::find()
            .filter(credential::Column::CredentialId.eq(id))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .map(Into::into))
    }
    async fn find_scim_active_managed_connection(
        &self,
        id: &str,
    ) -> AuthResult<Option<alibi_core::store::ScimManagedConnection>> {
        Ok(connection::Entity::find()
            .filter(connection::Column::Id.eq(id))
            .filter(connection::Column::Status.eq("active"))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .map(Into::into))
    }
    async fn record_scim_credential_use(
        &self,
        id: &str,
        previous: Option<chrono::DateTime<chrono::Utc>>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<()> {
        let query = credential::Entity::update_many()
            .col_expr(credential::Column::LastUsedAt, Expr::value(at))
            .filter(credential::Column::Id.eq(id))
            .filter(credential::Column::Status.eq("active"));
        let query = if let Some(previous) = previous {
            query.filter(credential::Column::LastUsedAt.eq(previous))
        } else {
            query.filter(credential::Column::LastUsedAt.is_null())
        };
        _ = query
            .exec(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        Ok(())
    }

    async fn get_scim_group(
        &self,
        id: &str,
        connection: &str,
    ) -> AuthResult<Option<alibi_core::store::ScimGroupRecord>> {
        use super::entities::scim_group as group;
        let row = group::Entity::find()
            .filter(group::Column::Id.eq(id))
            .filter(group::Column::ConnectionId.eq(connection))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        Ok(row.map(|row| alibi_core::store::ScimGroupRecord {
            id: row.id,
            connection_id: row.connection_id,
            provisioning_domain_id: row.provisioning_domain_id,
            display_name: row.display_name,
            external_id: row.external_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }))
    }
    async fn scim_group_members(
        &self,
        id: &str,
        connection: &str,
    ) -> AuthResult<alibi_core::store::ScimGroupMemberships> {
        use super::entities::{scim_group_member as membership, scim_user as user};
        let memberships = membership::Entity::find()
            .filter(membership::Column::GroupId.eq(id))
            .filter(membership::Column::ConnectionId.eq(connection))
            .order_by_asc(membership::Column::CreatedAt)
            .limit(1001)
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        let persisted_count = memberships.len();
        if persisted_count > 1000 {
            return Ok(alibi_core::store::ScimGroupMemberships {
                persisted_count,
                members: Vec::new(),
            });
        }
        let mut ids = Vec::new();
        for membership in &memberships {
            if !ids.contains(&membership.scim_user_id) {
                ids.push(membership.scim_user_id.clone());
            }
        }
        let mut users = std::collections::HashMap::new();
        for chunk in ids.chunks(500) {
            let rows = user::Entity::find()
                .filter(user::Column::ConnectionId.eq(connection))
                .filter(user::Column::Id.is_in(chunk.iter().cloned()))
                .limit(
                    u64::try_from(chunk.len())
                        .map_err(|error| alibi_core::AuthError::internal(error.to_string()))?,
                )
                .all(self.scoped_connection())
                .await
                .map_err(map_db_err)?;
            for row in rows {
                _ = users.insert(row.id, row.display_name);
            }
        }
        let members = memberships
            .into_iter()
            .filter_map(|membership| {
                users.get(&membership.scim_user_id).map(|display| {
                    alibi_core::store::ScimGroupMemberRecord {
                        id: membership.scim_user_id.clone(),
                        display_name: display.clone(),
                    }
                })
            })
            .collect();
        Ok(alibi_core::store::ScimGroupMemberships {
            persisted_count,
            members,
        })
    }
    async fn scim_projection_candidates(
        &self,
        domain: &str,
        cursor: Option<&str>,
    ) -> AuthResult<Vec<alibi_core::store::ScimProjectionCandidate>> {
        use super::entities::scim_user;
        let mut select =
            scim_user::Entity::find().filter(scim_user::Column::ProvisioningDomainId.eq(domain));
        if let Some(cursor) = cursor {
            select = select.filter(scim_user::Column::UserId.gt(cursor));
        }
        Ok(select
            .order_by_asc(scim_user::Column::UserId)
            .limit(51)
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .into_iter()
            .map(|row| alibi_core::store::ScimProjectionCandidate {
                id: row.id,
                user_id: row.user_id,
            })
            .collect())
    }

    async fn acquire_scim_decommission_lease(
        &self,
        binding: alibi_core::store::ScimConnectionBinding,
    ) -> AuthResult<Option<alibi_core::store::ScimConnectionBinding>> {
        use super::entities::scim_connection_binding as record;
        let lease = uuid::Uuid::new_v4().simple().to_string();
        let now = chrono::Utc::now().trunc_subsecs(3);
        let revision = i32::try_from(binding.decommission_revision)
            .map_err(|error| alibi_core::AuthError::internal(error.to_string()))?;
        let claimed = record::Entity::update_many()
            .col_expr(
                record::Column::DecommissionRevision,
                Expr::col(record::Column::DecommissionRevision).add(1),
            )
            .col_expr(
                record::Column::DecommissionStatus,
                Expr::value("reconciling"),
            )
            .col_expr(
                record::Column::DecommissionedAt,
                Expr::value(binding.decommissioned_at.unwrap_or(now)),
            )
            .col_expr(
                record::Column::DecommissionCompletedAt,
                Expr::value(None::<chrono::DateTime<chrono::Utc>>),
            )
            .col_expr(
                record::Column::DecommissionLeaseId,
                Expr::value(lease.clone()),
            )
            .col_expr(
                record::Column::DecommissionLeaseExpiresAt,
                Expr::value(now + chrono::Duration::minutes(5)),
            )
            .filter(record::Column::Id.eq(binding.id.clone()))
            .filter(record::Column::DecommissionRevision.eq(revision))
            .filter(record::Column::DecommissionStatus.eq(binding.decommission_status))
            .exec(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        if claimed.rows_affected == 0 {
            return Ok(None);
        }
        self.get_scim_connection_binding_with_connection(self.scoped_connection(), &binding.id)
            .await
    }
    async fn release_scim_decommission_lease(&self, id: &str, lease: &str) -> AuthResult<()> {
        use super::entities::scim_connection_binding as record;
        for _ in 0..3 {
            let Ok(Some(current)) = record::Entity::find_by_id(id.to_string())
                .one(self.scoped_connection())
                .await
            else {
                break;
            };
            if current.decommission_status == "complete"
                || current.decommission_lease_id.as_deref() != Some(lease)
            {
                break;
            }
            let released = record::Entity::update_many()
                .col_expr(
                    record::Column::DecommissionRevision,
                    Expr::col(record::Column::DecommissionRevision).add(1),
                )
                .col_expr(
                    record::Column::DecommissionLeaseId,
                    Expr::value(None::<String>),
                )
                .col_expr(
                    record::Column::DecommissionLeaseExpiresAt,
                    Expr::value(None::<chrono::DateTime<chrono::Utc>>),
                )
                .filter(record::Column::Id.eq(id.to_string()))
                .filter(record::Column::DecommissionRevision.eq(current.decommission_revision))
                .filter(record::Column::DecommissionLeaseId.eq(lease.to_string()))
                .exec(self.scoped_connection())
                .await;
            match released {
                Ok(result) if result.rows_affected == 0 => {}
                _ => break,
            }
        }
        Ok(())
    }
    async fn terminal_scim_connection_binding(
        &self,
        id: &str,
        domain: Option<&str>,
        key: &str,
    ) -> AuthResult<alibi_core::store::ScimConnectionBinding> {
        self.ensure_scim_binding(id, domain, key, true).await
    }
    async fn active_scim_connection_binding(
        &self,
        id: &str,
        domain: &str,
        key: &str,
    ) -> AuthResult<alibi_core::store::ScimConnectionBinding> {
        self.ensure_scim_binding(id, Some(domain), key, false).await
    }

    async fn list_scim_managed_connection_events(
        &self,
        id: &str,
        domain: &str,
    ) -> AuthResult<Option<Vec<alibi_core::store::ScimManagedConnectionEvent>>> {
        let Some(connection) = connection::Entity::find()
            .filter(connection::Column::ConnectionId.eq(id))
            .filter(connection::Column::ProvisioningDomainId.eq(domain))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };
        let mut events = event::Entity::find()
            .filter(event::Column::ConnectionRecordId.eq(connection.id))
            .order_by_desc(event::Column::Sequence)
            .limit(100)
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        events.reverse();
        Ok(Some(
            events
                .into_iter()
                .map(|event| alibi_core::store::ScimManagedConnectionEvent {
                    sequence: i64::from(event.sequence),
                    kind: event.kind,
                    actor_id: event.actor_id,
                    credential_id: event.credential_id,
                    created_at: event.created_at,
                })
                .collect(),
        ))
    }

    async fn decommission_scim_managed_connection(
        &self,
        data: alibi_core::store::DecommissionScimManagedConnection,
        complete: bool,
    ) -> AuthResult<Option<alibi_core::store::ScimManagedConnection>> {
        let tx = self.scoped_connection().begin().await.map_err(map_db_err)?;
        let result = async {
            let mut select = connection::Entity::find()
                .filter(connection::Column::ConnectionId.eq(data.connection_id))
                .filter(connection::Column::ProvisioningDomainId.eq(data.provisioning_domain_id));
            if tx.get_database_backend() == sea_orm::DbBackend::Postgres {
                select = select.lock_exclusive();
            }
            let mut connection = select.one(&tx).await.map_err(map_db_err)?.ok_or_else(|| {
                alibi_core::AuthError::Api {
                    status: 404,
                    code: None,
                    message: "Managed SCIM connection not found".into(),
                }
            })?;
            if connection.status == "decommissioned"
                || (!complete && connection.status == "decommissioning")
            {
                return Ok(Some(connection.into()));
            }
            if complete && connection.status != "decommissioning" {
                return Err(alibi_core::store::scim::scim_managed_conflict(
                    "Managed SCIM connection did not begin decommissioning",
                ));
            }
            let now = chrono::Utc::now().trunc_subsecs(3);
            let expected = if complete {
                "decommissioning"
            } else {
                "active"
            };
            let target = if complete {
                "decommissioned"
            } else {
                "decommissioning"
            };
            let updated = connection::Entity::update_many()
                .col_expr(
                    connection::Column::Revision,
                    Expr::col(connection::Column::Revision).add(1),
                )
                .col_expr(connection::Column::Status, Expr::value(target))
                .col_expr(
                    if complete {
                        connection::Column::DecommissionedAt
                    } else {
                        connection::Column::DecommissionStartedAt
                    },
                    Expr::value(now),
                )
                .col_expr(
                    if complete {
                        connection::Column::DecommissionedBy
                    } else {
                        connection::Column::DecommissionStartedBy
                    },
                    Expr::value(data.actor_id.clone()),
                )
                .filter(connection::Column::Id.eq(connection.id.clone()))
                .filter(connection::Column::Status.eq(expected))
                .filter(connection::Column::Revision.eq(connection.revision))
                .exec(&tx)
                .await
                .map_err(map_db_err)?;
            if updated.rows_affected == 0 {
                return Ok(None);
            }
            connection.revision += 1;
            connection.status = target.into();
            if complete {
                connection.decommissioned_at = Some(now);
                connection.decommissioned_by = Some(data.actor_id.clone());
            } else {
                connection.decommission_started_at = Some(now);
                connection.decommission_started_by = Some(data.actor_id.clone());
            }
            if !complete {
                let active = credential::Entity::find()
                    .filter(credential::Column::ConnectionRecordId.eq(connection.id.clone()))
                    .filter(credential::Column::Status.eq("active"))
                    .limit(100)
                    .all(&tx)
                    .await
                    .map_err(map_db_err)?;
                for credential in active {
                    _ = credential::Entity::update_many()
                        .col_expr(credential::Column::Status, Expr::value("decommissioned"))
                        .col_expr(
                            credential::Column::ActiveSlotKey,
                            Expr::value(format!("{}:inactive", credential.credential_id)),
                        )
                        .col_expr(credential::Column::DecommissionedAt, Expr::value(now))
                        .filter(credential::Column::Id.eq(credential.id))
                        .filter(credential::Column::Status.eq("active"))
                        .filter(credential::Column::ActiveSlotKey.eq(credential.active_slot_key))
                        .exec(&tx)
                        .await
                        .map_err(map_db_err)?;
                }
            }
            _ = event::ActiveModel {
                id: Set(self
                    .generated_id(
                        &tx,
                        "scimManagedConnectionEvent",
                        "scimManagedConnectionEvent",
                        "id",
                    )
                    .await?
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                connection_record_id: Set(connection.id.clone()),
                event_key: Set(format!("{}:{}", connection.id, connection.revision)),
                sequence: Set(connection.revision),
                kind: Set((if complete {
                    "connection.decommissioned"
                } else {
                    "connection.decommissioning"
                })
                .into()),
                actor_id: Set(data.actor_id),
                credential_id: Set(None::<String>),
                created_at: Set(now),
            }
            .insert(&tx)
            .await
            .map_err(map_db_err)?;
            Ok(Some(connection.into()))
        }
        .await;
        match result {
            Ok(result) => {
                tx.commit().await.map_err(map_db_err)?;
                Ok(result)
            }
            Err(error) => {
                tx.rollback().await.map_err(map_db_err)?;
                Err(error)
            }
        }
    }

    async fn revoke_scim_managed_credential(
        &self,
        data: alibi_core::store::RevokeScimManagedCredential,
    ) -> AuthResult<Option<alibi_core::store::ScimManagedConnection>> {
        let tx = self.scoped_connection().begin().await.map_err(map_db_err)?;
        let result = async {
            let mut select = connection::Entity::find()
                .filter(connection::Column::ConnectionId.eq(data.connection_id))
                .filter(connection::Column::ProvisioningDomainId.eq(data.provisioning_domain_id));
            if tx.get_database_backend() == sea_orm::DbBackend::Postgres {
                select = select.lock_exclusive();
            }
            let mut connection = select.one(&tx).await.map_err(map_db_err)?.ok_or_else(|| {
                alibi_core::AuthError::Api {
                    status: 404,
                    code: None,
                    message: "Managed SCIM connection not found".into(),
                }
            })?;
            let credential = credential::Entity::find()
                .filter(credential::Column::CredentialId.eq(data.credential_id.clone()))
                .filter(credential::Column::ConnectionRecordId.eq(connection.id.clone()))
                .one(&tx)
                .await
                .map_err(map_db_err)?
                .ok_or_else(|| alibi_core::AuthError::Api {
                    status: 404,
                    code: None,
                    message: "Managed SCIM connection not found".into(),
                })?;
            if credential.status == "revoked" {
                return Ok(Some(connection.into()));
            }
            if connection.status != "active" || credential.status != "active" {
                return Err(alibi_core::store::scim::scim_managed_conflict(
                    "Managed SCIM credential is not active",
                ));
            }
            let claimed = connection::Entity::update_many()
                .col_expr(
                    connection::Column::Revision,
                    Expr::col(connection::Column::Revision).add(1),
                )
                .filter(connection::Column::Id.eq(connection.id.clone()))
                .filter(connection::Column::Status.eq("active"))
                .filter(connection::Column::Revision.eq(connection.revision))
                .exec(&tx)
                .await
                .map_err(map_db_err)?;
            if claimed.rows_affected == 0 {
                return Ok(None);
            }
            connection.revision += 1;
            let revoked_at = chrono::Utc::now().trunc_subsecs(3);
            let updated = credential::Entity::update_many()
                .col_expr(credential::Column::Status, Expr::value("revoked"))
                .col_expr(
                    credential::Column::ActiveSlotKey,
                    Expr::value(format!("{}:inactive", credential.credential_id)),
                )
                .col_expr(credential::Column::RevokedAt, Expr::value(revoked_at))
                .col_expr(
                    credential::Column::RevokedBy,
                    Expr::value(data.actor_id.clone()),
                )
                .filter(credential::Column::Id.eq(credential.id))
                .filter(credential::Column::Status.eq("active"))
                .filter(credential::Column::ActiveSlotKey.eq(credential.active_slot_key))
                .exec(&tx)
                .await
                .map_err(map_db_err)?;
            if updated.rows_affected == 0 {
                return Ok(None);
            }
            _ = event::ActiveModel {
                id: Set(self
                    .generated_id(
                        &tx,
                        "scimManagedConnectionEvent",
                        "scimManagedConnectionEvent",
                        "id",
                    )
                    .await?
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                connection_record_id: Set(connection.id.clone()),
                event_key: Set(format!("{}:{}", connection.id, connection.revision)),
                sequence: Set(connection.revision),
                kind: Set("credential.revoked".into()),
                actor_id: Set(data.actor_id),
                credential_id: Set(Some(data.credential_id)),
                created_at: Set(revoked_at),
            }
            .insert(&tx)
            .await
            .map_err(map_db_err)?;
            Ok(Some(connection.into()))
        }
        .await;
        match result {
            Ok(result) => {
                tx.commit().await.map_err(map_db_err)?;
                Ok(result)
            }
            Err(error) => {
                tx.rollback().await.map_err(map_db_err)?;
                Err(error)
            }
        }
    }

    async fn rotate_scim_managed_credential(
        &self,
        data: alibi_core::store::RotateScimManagedCredential,
    ) -> AuthResult<Option<ScimManagedCreation>> {
        let tx = self.scoped_connection().begin().await.map_err(map_db_err)?;
        let result = async {
            let mut select = connection::Entity::find()
                .filter(connection::Column::ConnectionId.eq(data.connection_id))
                .filter(connection::Column::ProvisioningDomainId.eq(data.provisioning_domain_id));
            if tx.get_database_backend() == sea_orm::DbBackend::Postgres {
                select = select.lock_exclusive();
            }
            let mut connection = select.one(&tx).await.map_err(map_db_err)?.ok_or_else(|| {
                alibi_core::AuthError::Api {
                    status: 404,
                    code: None,
                    message: "Managed SCIM connection not found".into(),
                }
            })?;
            if connection.status != "active" {
                return Err(alibi_core::store::scim::scim_managed_conflict(
                    "Managed SCIM connection is not active",
                ));
            }
            let claimed = connection::Entity::update_many()
                .col_expr(
                    connection::Column::Revision,
                    Expr::col(connection::Column::Revision).add(1),
                )
                .filter(connection::Column::Id.eq(connection.id.clone()))
                .filter(connection::Column::Status.eq("active"))
                .filter(connection::Column::Revision.eq(connection.revision))
                .exec(&tx)
                .await
                .map_err(map_db_err)?;
            if claimed.rows_affected == 0 {
                return Ok(None);
            }
            connection.revision += 1;
            let active = credential::Entity::find()
                .filter(credential::Column::ConnectionRecordId.eq(connection.id.clone()))
                .filter(credential::Column::Status.eq("active"))
                .limit(101)
                .all(&tx)
                .await
                .map_err(map_db_err)?;
            let mut slots = std::collections::HashSet::new();
            for credential in active {
                if credential.expires_at <= data.created_at {
                    let mut row: credential::ActiveModel = credential.clone().into();
                    row.status = Set("expired".into());
                    row.active_slot_key = Set(format!("{}:inactive", credential.credential_id));
                    _ = row.update(&tx).await.map_err(map_db_err)?;
                } else {
                    _ = slots.insert(credential.active_slot_key);
                }
            }
            if slots.len() >= data.max_active_credentials {
                return Err(alibi_core::store::scim::scim_managed_conflict(
                    "Managed SCIM connection has the maximum number of active credentials",
                ));
            }
            let slot = (0..data.max_active_credentials)
                .find(|slot| !slots.contains(&format!("{}:active:{slot}", connection.id)))
                .ok_or_else(|| {
                    alibi_core::store::scim::scim_managed_conflict(
                        "Managed SCIM connection has the maximum number of active credentials",
                    )
                })?;
            let credential = credential::ActiveModel {
                id: Set(self
                    .generated_id(&tx, "scimManagedCredential", "scimManagedCredential", "id")
                    .await?
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                connection_record_id: Set(connection.id.clone()),
                credential_id: Set(data.credential_id.clone()),
                token_digest: Set(data.token_digest),
                hash_version: Set("v1".into()),
                active_slot_key: Set(format!("{}:active:{slot}", connection.id)),
                status: Set("active".into()),
                serialized_scopes: Set(data.serialized_scopes),
                expires_at: Set(data.expires_at),
                created_at: Set(data.created_at),
                created_by: Set(data.actor_id.clone()),
                ..Default::default()
            }
            .insert(&tx)
            .await
            .map_err(map_db_err)?;
            _ = event::ActiveModel {
                id: Set(self
                    .generated_id(
                        &tx,
                        "scimManagedConnectionEvent",
                        "scimManagedConnectionEvent",
                        "id",
                    )
                    .await?
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                connection_record_id: Set(connection.id.clone()),
                event_key: Set(format!("{}:{}", connection.id, connection.revision)),
                sequence: Set(connection.revision),
                kind: Set("credential.rotated".into()),
                actor_id: Set(data.actor_id),
                credential_id: Set(Some(data.credential_id)),
                created_at: Set(data.created_at),
            }
            .insert(&tx)
            .await
            .map_err(map_db_err)?;
            Ok(Some(ScimManagedCreation {
                connection: connection.into(),
                credential: credential.into(),
            }))
        }
        .await;
        match result {
            Ok(result) => {
                tx.commit().await.map_err(map_db_err)?;
                Ok(result)
            }
            Err(error) => {
                tx.rollback().await.map_err(map_db_err)?;
                Err(error)
            }
        }
    }

    async fn get_scim_managed_connection(
        &self,
        id: &str,
        domain: &str,
    ) -> AuthResult<Option<alibi_core::store::ScimManagedConnectionState>> {
        let Some(connection) = connection::Entity::find()
            .filter(connection::Column::ConnectionId.eq(id))
            .filter(connection::Column::ProvisioningDomainId.eq(domain))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };
        let credentials = credential::Entity::find()
            .filter(credential::Column::ConnectionRecordId.eq(connection.id.clone()))
            .order_by_desc(credential::Column::CreatedAt)
            .limit(
                u64::try_from(self.config.advanced.database.default_find_many_limit)
                    .unwrap_or(u64::MAX),
            )
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok(Some(alibi_core::store::ScimManagedConnectionState {
            connection: connection.into(),
            credentials,
        }))
    }

    async fn list_scim_managed_connections(
        &self,
        domain: &str,
    ) -> AuthResult<Vec<alibi_core::store::ScimManagedConnection>> {
        Ok(connection::Entity::find()
            .filter(connection::Column::ProvisioningDomainId.eq(domain))
            .order_by_desc(connection::Column::CreatedAt)
            .limit(
                u64::try_from(self.config.advanced.database.default_find_many_limit)
                    .unwrap_or(u64::MAX),
            )
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    async fn create_scim_managed_connection(
        &self,
        data: CreateScimManagedConnection,
    ) -> AuthResult<ScimManagedCreation> {
        let request_id = data.creation_request_id.clone();
        let tx = self.scoped_connection().begin().await.map_err(map_db_err)?;
        let result = async {
            let connection = connection::ActiveModel {
                id: Set(self
                    .generated_id(&tx, "scimManagedConnection", "scimManagedConnection", "id")
                    .await?
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                creation_request_id: Set(data.creation_request_id),
                connection_id: Set(data.connection_id),
                provisioning_domain_id: Set(data.provisioning_domain_id),
                status: Set("active".into()),
                revision: Set(2),
                created_at: Set(data.created_at),
                created_by: Set(data.actor_id.clone()),
                ..Default::default()
            }
            .insert(&tx)
            .await
            .map_err(map_db_err)?;
            let credential = credential::ActiveModel {
                id: Set(self
                    .generated_id(&tx, "scimManagedCredential", "scimManagedCredential", "id")
                    .await?
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                connection_record_id: Set(connection.id.clone()),
                credential_id: Set(data.credential_id.clone()),
                token_digest: Set(data.token_digest),
                hash_version: Set("v1".into()),
                active_slot_key: Set(format!("{}:active:0", connection.id)),
                status: Set("active".into()),
                serialized_scopes: Set(data.serialized_scopes),
                expires_at: Set(data.expires_at),
                created_at: Set(data.created_at),
                created_by: Set(data.actor_id.clone()),
                ..Default::default()
            }
            .insert(&tx)
            .await
            .map_err(map_db_err)?;
            for (sequence, kind) in [(1_i32, "connection.created"), (2_i32, "credential.issued")] {
                _ = event::ActiveModel {
                    id: Set(self
                        .generated_id(
                            &tx,
                            "scimManagedConnectionEvent",
                            "scimManagedConnectionEvent",
                            "id",
                        )
                        .await?
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                    connection_record_id: Set(connection.id.clone()),
                    event_key: Set(format!("{}:{sequence}", connection.id)),
                    sequence: Set(sequence),
                    kind: Set(kind.into()),
                    actor_id: Set(data.actor_id.clone()),
                    credential_id: Set(if sequence == 2 {
                        Some(data.credential_id.clone())
                    } else {
                        None
                    }),
                    created_at: Set(data.created_at),
                }
                .insert(&tx)
                .await
                .map_err(map_db_err)?;
            }
            Ok(ScimManagedCreation {
                connection: connection.into(),
                credential: credential.into(),
            })
        }
        .await;
        match result {
            Ok(result) => {
                tx.commit().await.map_err(map_db_err)?;
                Ok(result)
            }
            Err(error) => {
                tx.rollback().await.map_err(map_db_err)?;
                if connection::Entity::find()
                    .filter(connection::Column::CreationRequestId.eq(request_id))
                    .count(self.scoped_connection())
                    .await
                    .map_err(map_db_err)?
                    > 0
                {
                    return Err(alibi_core::store::scim::scim_creation_conflict());
                }
                Err(error)
            }
        }
    }
}

impl<S: AuthSchema> SeaOrmStore<S> {
    async fn ensure_scim_binding(
        &self,
        id: &str,
        domain: Option<&str>,
        key: &str,
        terminal: bool,
    ) -> AuthResult<alibi_core::store::ScimConnectionBinding> {
        use super::entities::scim_connection_binding as binding;
        let find = async || {
            binding::Entity::find()
                .filter(binding::Column::ConnectionKey.eq(key))
                .one(self.scoped_connection())
                .await
                .map_err(map_db_err)
        };
        if let Some(row) = find().await? {
            let binding = row.into();
            if terminal {
                alibi_core::store::scim::validate_scim_binding_domain(&binding, domain)?;
            }
            return Ok(binding);
        }
        let domain = domain.ok_or_else(|| {
            alibi_core::AuthError::internal(format!(
                "SCIM connection \"{id}\" has no persisted binding."
            ))
        })?;
        let now = chrono::Utc::now().trunc_subsecs(3);
        let row = binding::ActiveModel {
            id: Set(self
                .generated_id(
                    self.scoped_connection(),
                    "scimConnectionBinding",
                    "scimConnectionBinding",
                    "id",
                )
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
            connection_id: Set(id.into()),
            connection_key: Set(key.into()),
            provisioning_domain_id: Set(domain.into()),
            created_at: Set(now),
            decommission_status: Set(if terminal { "complete" } else { "active" }.into()),
            decommissioned_at: Set(terminal.then_some(now)),
            decommission_completed_at: Set(terminal.then_some(now)),
            decommission_reconciled_user_count: Set(0),
            decommission_batch_count: Set(0),
            decommission_revision: Set(0),
            ..Default::default()
        };
        match row
            .insert(self.scoped_connection())
            .await
            .map_err(map_db_err)
        {
            Ok(row) => Ok(row.into()),
            Err(error) => {
                if let Some(row) = find().await? {
                    let binding = row.into();
                    if terminal {
                        alibi_core::store::scim::validate_scim_binding_domain(
                            &binding,
                            Some(domain),
                        )?;
                    }
                    Ok(binding)
                } else {
                    Err(error)
                }
            }
        }
    }
}
