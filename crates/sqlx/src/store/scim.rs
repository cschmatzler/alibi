use super::{
    SqlxStore,
    entities::{
        scim_managed_connection as connection, scim_managed_connection_event as event,
        scim_managed_credential as credential,
    },
};
use crate::{
    model::{self, ActiveRow},
    pool::Exec,
    sql::Sql,
};
use alibi_core::{
    AuthResult, AuthSchema,
    store::{CreateScimManagedConnection, ScimManagedCreation, ScimManagedStore},
};
use async_trait::async_trait;
use chrono::SubsecRound;
#[async_trait]
impl<S: AuthSchema> ScimManagedStore for SqlxStore<S> {
    async fn scim_projection_candidates(
        &self,
        domain: &str,
        cursor: Option<&str>,
    ) -> AuthResult<Vec<alibi_core::store::ScimProjectionCandidate>> {
        use super::entities::scim_user;
        let mut sql = model::select_model::<scim_user::Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare("scimUser", "provisioningDomainId", " = ", domain);
        if let Some(cursor) = cursor {
            sql.push(" AND ");
            sql.compare("scimUser", "userId", " > ", cursor);
        }
        sql.push(" ORDER BY ");
        sql.ident("userId");
        sql.push(" ASC LIMIT 51");
        Ok(self
            .exec()
            .fetch_all::<scim_user::Model>(sql)
            .await?
            .into_iter()
            .map(|row| alibi_core::store::ScimProjectionCandidate {
                id: row.id,
                user_id: row.user_id,
            })
            .collect())
    }

    async fn recover_empty_scim_decommission(
        &self,
        mut binding: alibi_core::store::ScimConnectionBinding,
    ) -> AuthResult<Option<alibi_core::store::ScimConnectionBinding>> {
        let lease = uuid::Uuid::new_v4().simple().to_string();
        let now = chrono::Utc::now().trunc_subsecs(3);
        let mut sql = Sql::with(self.exec().engine(), "UPDATE ");
        sql.ident("scimConnectionBinding");
        sql.push(" SET ");
        sql.ident("decommissionRevision");
        sql.push(" = ");
        sql.ident("decommissionRevision");
        sql.push(" + 1, ");
        for (index, (column, value)) in [
            ("decommissionStatus", "reconciling".to_string()),
            ("decommissionLeaseId", lease.clone()),
        ]
        .into_iter()
        .enumerate()
        {
            if index > 0 {
                sql.push(", ");
            }
            sql.ident(column);
            sql.push(" = ");
            sql.bind(value);
        }
        sql.push(", ");
        sql.ident("decommissionedAt");
        sql.push(" = ");
        sql.bind(binding.decommissioned_at.unwrap_or(now));
        sql.push(", ");
        sql.ident("decommissionCompletedAt");
        sql.push(" = NULL, ");
        sql.ident("decommissionLeaseExpiresAt");
        sql.push(" = ");
        sql.bind(now + chrono::Duration::minutes(5));
        sql.push(" WHERE ");
        sql.compare("scimConnectionBinding", "id", " = ", binding.id.clone());
        sql.push(" AND ");
        sql.compare(
            "scimConnectionBinding",
            "decommissionRevision",
            " = ",
            binding.decommission_revision,
        );
        sql.push(" AND ");
        sql.compare(
            "scimConnectionBinding",
            "decommissionStatus",
            " = ",
            binding.decommission_status.clone(),
        );
        if self.exec().execute(sql).await? == 0 {
            return Ok(None);
        }
        binding.decommission_revision += 1;
        let result=self.in_transaction(true,async |tx| {
            let exec=Exec::tx(tx);let mut sql=model::select_model::<super::entities::scim_connection_binding::Model>(exec);sql.push(" WHERE ");sql.compare("scimConnectionBinding","id"," = ",binding.id.clone());model::limit_one(&mut sql);
            let stored=exec.fetch_optional::<super::entities::scim_connection_binding::Model>(sql).await?.ok_or_else(||alibi_core::AuthError::internal(format!("SCIM connection \"{}\" binding disappeared during decommissioning.",binding.connection_id)))?;
            if stored.decommission_status=="complete"{return Ok(stored.into());}
            if stored.decommission_lease_id.as_deref()!=Some(&lease){return Err(alibi_core::AuthError::internal(format!("SCIM connection \"{}\" decommission lease was taken over by another worker.",binding.connection_id)));}
            let mut sql=model::select_model::<super::entities::scim_user::Model>(exec);sql.push(" WHERE ");sql.compare("scimUser","provisioningDomainId"," = ",stored.provisioning_domain_id.clone());
            if let Some(cursor)=&stored.decommission_cursor_user_id{sql.push(" AND ");sql.compare("scimUser","userId"," > ",cursor.clone());}
            sql.push(" LIMIT 101");
            if !exec.fetch_all::<super::entities::scim_user::Model>(sql).await?.is_empty(){return Err(alibi_core::AuthError::config("SCIM projection reconciliation is not supported by this store"));}
            let mut sql=Sql::with(exec.engine(),"UPDATE ");sql.ident("scimConnectionBinding");sql.push(" SET ");sql.ident("decommissionLeaseExpiresAt");sql.push(" = ");sql.bind(chrono::Utc::now().trunc_subsecs(3)+chrono::Duration::minutes(5));sql.push(" WHERE ");sql.compare("scimConnectionBinding","id"," = ",stored.id.clone());sql.push(" AND ");sql.compare("scimConnectionBinding","decommissionRevision"," = ",stored.decommission_revision);sql.push(" AND ");sql.compare("scimConnectionBinding","decommissionStatus"," = ","reconciling");sql.push(" AND ");sql.compare("scimConnectionBinding","decommissionLeaseId"," = ",lease.clone());
            if exec.execute(sql).await?==0{return Err(alibi_core::AuthError::internal(format!("SCIM connection \"{}\" decommission lease changed before reconciliation.",binding.connection_id)));}
            let mut sql=Sql::with(exec.engine(),"UPDATE ");sql.ident("scimConnectionBinding");sql.push(" SET ");sql.ident("decommissionRevision");sql.push(" = ");sql.ident("decommissionRevision");sql.push(" + 1, ");sql.ident("decommissionStatus");sql.push(" = ");sql.bind("complete");sql.push(", ");sql.ident("decommissionCompletedAt");sql.push(" = ");let completed=chrono::Utc::now().trunc_subsecs(3);sql.bind(completed);sql.push(", ");sql.ident("decommissionLeaseId");sql.push(" = NULL, ");sql.ident("decommissionLeaseExpiresAt");sql.push(" = NULL WHERE ");sql.compare("scimConnectionBinding","id"," = ",stored.id.clone());sql.push(" AND ");sql.compare("scimConnectionBinding","decommissionRevision"," = ",stored.decommission_revision);sql.push(" AND ");sql.compare("scimConnectionBinding","decommissionLeaseId"," = ",lease.clone());
            if exec.execute(sql).await?==0{return Err(alibi_core::AuthError::internal(format!("SCIM connection \"{}\" decommission checkpoint changed concurrently.",binding.connection_id)));}
            let mut stored=stored;stored.decommission_revision+=1;stored.decommission_status="complete".into();stored.decommission_completed_at=Some(completed);stored.decommission_lease_id=None;stored.decommission_lease_expires_at=None;Ok(stored.into())
        }).await;
        if result.is_err() {
            for _ in 0..3 {
                let mut query = model::select_model::<
                    super::entities::scim_connection_binding::Model,
                >(self.exec());
                query.push(" WHERE ");
                query.compare("scimConnectionBinding", "id", " = ", binding.id.clone());
                model::limit_one(&mut query);
                let Ok(Some(current)) = self
                    .exec()
                    .fetch_optional::<super::entities::scim_connection_binding::Model>(query)
                    .await
                else {
                    break;
                };
                if current.decommission_status == "complete"
                    || current.decommission_lease_id.as_deref() != Some(&lease)
                {
                    break;
                }
                let mut sql = Sql::with(self.exec().engine(), "UPDATE ");
                sql.ident("scimConnectionBinding");
                sql.push(" SET ");
                sql.ident("decommissionRevision");
                sql.push(" = ");
                sql.ident("decommissionRevision");
                sql.push(" + 1, ");
                sql.ident("decommissionLeaseId");
                sql.push(" = NULL, ");
                sql.ident("decommissionLeaseExpiresAt");
                sql.push(" = NULL WHERE ");
                sql.compare("scimConnectionBinding", "id", " = ", binding.id.clone());
                sql.push(" AND ");
                sql.compare(
                    "scimConnectionBinding",
                    "decommissionRevision",
                    " = ",
                    current.decommission_revision,
                );
                sql.push(" AND ");
                sql.compare(
                    "scimConnectionBinding",
                    "decommissionLeaseId",
                    " = ",
                    lease.clone(),
                );
                match self.exec().execute(sql).await {
                    Ok(0) => {}
                    _ => break,
                }
            }
        }
        result.map(Some)
    }

    async fn terminal_scim_connection_binding(
        &self,
        id: &str,
        domain: Option<&str>,
        key: &str,
    ) -> AuthResult<alibi_core::store::ScimConnectionBinding> {
        use super::entities::scim_connection_binding as binding;
        let find = async || {
            let mut sql = model::select_model::<binding::Model>(self.exec());
            sql.push(" WHERE ");
            sql.compare("scimConnectionBinding", "connectionKey", " = ", key);
            model::limit_one(&mut sql);
            self.exec().fetch_optional::<binding::Model>(sql).await
        };
        if let Some(row) = find().await? {
            let binding = row.into();
            alibi_core::store::scim::validate_scim_binding_domain(&binding, domain)?;
            return Ok(binding);
        }
        let domain = domain.ok_or_else(|| {
            alibi_core::AuthError::internal(format!(
                "SCIM connection \"{id}\" has no persisted binding."
            ))
        })?;
        let now = chrono::Utc::now().trunc_subsecs(3);
        let mut row = ActiveRow::new();
        row.set(
            "id",
            self.generated_id(
                self.exec(),
                "scimConnectionBinding",
                "scimConnectionBinding",
                "id",
            )
            .await?
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        );
        row.set("connectionId", id);
        row.set("connectionKey", key);
        row.set("provisioningDomainId", domain);
        row.set("createdAt", now);
        row.set("decommissionStatus", "complete");
        row.set("decommissionedAt", now);
        row.set("decommissionCompletedAt", now);
        row.set("decommissionReconciledUserCount", 0_i64);
        row.set("decommissionBatchCount", 0_i64);
        row.set("decommissionRevision", 0_i64);
        match model::insert::<binding::Model>(self.exec(), &row).await {
            Ok(row) => Ok(row.into()),
            Err(error) => {
                if let Some(row) = find().await? {
                    let binding = row.into();
                    alibi_core::store::scim::validate_scim_binding_domain(&binding, Some(domain))?;
                    Ok(binding)
                } else {
                    Err(error)
                }
            }
        }
    }

    async fn list_scim_managed_connection_events(
        &self,
        id: &str,
        domain: &str,
    ) -> AuthResult<Option<Vec<alibi_core::store::ScimManagedConnectionEvent>>> {
        let exec = self.exec();
        let mut sql = model::select_model::<connection::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimManagedConnection", "connectionId", " = ", id);
        sql.push(" AND ");
        sql.compare(
            "scimManagedConnection",
            "provisioningDomainId",
            " = ",
            domain,
        );
        model::limit_one(&mut sql);
        let Some(connection) = exec.fetch_optional::<connection::Model>(sql).await? else {
            return Ok(None);
        };
        let mut sql = model::select_model::<event::Model>(exec);
        sql.push(" WHERE ");
        sql.compare(
            "scimManagedConnectionEvent",
            "connectionRecordId",
            " = ",
            connection.id,
        );
        sql.push(" ORDER BY ");
        sql.ident("sequence");
        sql.push(" DESC LIMIT 100");
        let mut events = exec.fetch_all::<event::Model>(sql).await?;
        events.reverse();
        Ok(Some(
            events
                .into_iter()
                .map(|event| alibi_core::store::ScimManagedConnectionEvent {
                    sequence: event.sequence,
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
        self.in_transaction(true, async move |tx| {
            let exec = Exec::tx(tx);
            let mut sql = model::select_model::<connection::Model>(exec);
            sql.push(" WHERE ");
            sql.compare(
                "scimManagedConnection",
                "connectionId",
                " = ",
                data.connection_id,
            );
            sql.push(" AND ");
            sql.compare(
                "scimManagedConnection",
                "provisioningDomainId",
                " = ",
                data.provisioning_domain_id,
            );
            model::limit_one(&mut sql);
            if exec.engine() == crate::pool::Engine::Postgres {
                sql.push(" FOR UPDATE");
            }
            let mut connection = exec
                .fetch_optional::<connection::Model>(sql)
                .await?
                .ok_or_else(|| alibi_core::AuthError::Api {
                    status: 404,
                    code: None,
                    message: "Managed SCIM connection not found".into(),
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
            let mut sql = Sql::with(exec.engine(), "UPDATE ");
            sql.ident("scimManagedConnection");
            sql.push(" SET ");
            sql.ident("revision");
            sql.push(" = ");
            sql.ident("revision");
            sql.push(" + 1, ");
            sql.ident("status");
            sql.push(" = ");
            sql.bind(target);
            sql.push(", ");
            sql.ident(if complete {
                "decommissionedAt"
            } else {
                "decommissionStartedAt"
            });
            sql.push(" = ");
            sql.bind(now);
            sql.push(", ");
            sql.ident(if complete {
                "decommissionedBy"
            } else {
                "decommissionStartedBy"
            });
            sql.push(" = ");
            sql.bind(data.actor_id.clone());
            sql.push(" WHERE ");
            sql.compare("scimManagedConnection", "id", " = ", connection.id.clone());
            sql.push(" AND ");
            sql.compare("scimManagedConnection", "status", " = ", expected);
            sql.push(" AND ");
            sql.compare(
                "scimManagedConnection",
                "revision",
                " = ",
                connection.revision,
            );
            if exec.execute(sql).await? == 0 {
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
                let mut sql = model::select_model::<credential::Model>(exec);
                sql.push(" WHERE ");
                sql.compare(
                    "scimManagedCredential",
                    "connectionRecordId",
                    " = ",
                    connection.id.clone(),
                );
                sql.push(" AND ");
                sql.compare("scimManagedCredential", "status", " = ", "active");
                sql.push(" LIMIT 100");
                for credential in exec.fetch_all::<credential::Model>(sql).await? {
                    let mut sql = Sql::with(exec.engine(), "UPDATE ");
                    sql.ident("scimManagedCredential");
                    sql.push(" SET ");
                    sql.ident("status");
                    sql.push(" = ");
                    sql.bind("decommissioned");
                    sql.push(", ");
                    sql.ident("activeSlotKey");
                    sql.push(" = ");
                    sql.bind(format!("{}:inactive", credential.credential_id));
                    sql.push(", ");
                    sql.ident("decommissionedAt");
                    sql.push(" = ");
                    sql.bind(now);
                    sql.push(" WHERE ");
                    sql.compare("scimManagedCredential", "id", " = ", credential.id);
                    sql.push(" AND ");
                    sql.compare("scimManagedCredential", "status", " = ", "active");
                    sql.push(" AND ");
                    sql.compare(
                        "scimManagedCredential",
                        "activeSlotKey",
                        " = ",
                        credential.active_slot_key,
                    );
                    _ = exec.execute(sql).await?;
                }
            }
            let mut row = ActiveRow::new();
            row.set(
                "id",
                self.generated_id(
                    exec,
                    "scimManagedConnectionEvent",
                    "scimManagedConnectionEvent",
                    "id",
                )
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            );
            row.set("connectionRecordId", connection.id.clone());
            row.set(
                "eventKey",
                format!("{}:{}", connection.id, connection.revision),
            );
            row.set("sequence", connection.revision);
            row.set(
                "type",
                if complete {
                    "connection.decommissioned"
                } else {
                    "connection.decommissioning"
                },
            );
            row.set("actorId", data.actor_id);
            row.set("credentialId", None::<String>);
            row.set("createdAt", now);
            _ = model::insert::<event::Model>(exec, &row).await?;
            Ok(Some(connection.into()))
        })
        .await
    }

    async fn revoke_scim_managed_credential(
        &self,
        data: alibi_core::store::RevokeScimManagedCredential,
    ) -> AuthResult<Option<alibi_core::store::ScimManagedConnection>> {
        self.in_transaction(true, async move |tx| {
            let exec = Exec::tx(tx);
            let mut sql = model::select_model::<connection::Model>(exec);
            sql.push(" WHERE ");
            sql.compare(
                "scimManagedConnection",
                "connectionId",
                " = ",
                data.connection_id,
            );
            sql.push(" AND ");
            sql.compare(
                "scimManagedConnection",
                "provisioningDomainId",
                " = ",
                data.provisioning_domain_id,
            );
            model::limit_one(&mut sql);
            if exec.engine() == crate::pool::Engine::Postgres {
                sql.push(" FOR UPDATE");
            }
            let mut connection = exec
                .fetch_optional::<connection::Model>(sql)
                .await?
                .ok_or_else(|| alibi_core::AuthError::Api {
                    status: 404,
                    code: None,
                    message: "Managed SCIM connection not found".into(),
                })?;
            let mut sql = model::select_model::<credential::Model>(exec);
            sql.push(" WHERE ");
            sql.compare(
                "scimManagedCredential",
                "credentialId",
                " = ",
                data.credential_id.clone(),
            );
            sql.push(" AND ");
            sql.compare(
                "scimManagedCredential",
                "connectionRecordId",
                " = ",
                connection.id.clone(),
            );
            model::limit_one(&mut sql);
            let credential = exec
                .fetch_optional::<credential::Model>(sql)
                .await?
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
            let mut sql = Sql::with(exec.engine(), "UPDATE ");
            sql.ident("scimManagedConnection");
            sql.push(" SET ");
            sql.ident("revision");
            sql.push(" = ");
            sql.ident("revision");
            sql.push(" + 1 WHERE ");
            sql.compare("scimManagedConnection", "id", " = ", connection.id.clone());
            sql.push(" AND ");
            sql.compare("scimManagedConnection", "status", " = ", "active");
            sql.push(" AND ");
            sql.compare(
                "scimManagedConnection",
                "revision",
                " = ",
                connection.revision,
            );
            if exec.execute(sql).await? == 0 {
                return Ok(None);
            }
            connection.revision += 1;
            let revoked_at = chrono::Utc::now().trunc_subsecs(3);
            let mut sql = Sql::with(exec.engine(), "UPDATE ");
            sql.ident("scimManagedCredential");
            sql.push(" SET ");
            for (index, (column, value)) in [
                ("status", "revoked".to_string()),
                (
                    "activeSlotKey",
                    format!("{}:inactive", credential.credential_id),
                ),
                ("revokedBy", data.actor_id.clone()),
            ]
            .into_iter()
            .enumerate()
            {
                if index > 0 {
                    sql.push(", ");
                }
                sql.ident(column);
                sql.push(" = ");
                sql.bind(value);
            }
            sql.push(", ");
            sql.ident("revokedAt");
            sql.push(" = ");
            sql.bind(revoked_at);
            sql.push(" WHERE ");
            sql.compare("scimManagedCredential", "id", " = ", credential.id);
            sql.push(" AND ");
            sql.compare("scimManagedCredential", "status", " = ", "active");
            sql.push(" AND ");
            sql.compare(
                "scimManagedCredential",
                "activeSlotKey",
                " = ",
                credential.active_slot_key,
            );
            if exec.execute(sql).await? == 0 {
                return Ok(None);
            }
            let mut row = ActiveRow::new();
            row.set(
                "id",
                self.generated_id(
                    exec,
                    "scimManagedConnectionEvent",
                    "scimManagedConnectionEvent",
                    "id",
                )
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            );
            row.set("connectionRecordId", connection.id.clone());
            row.set(
                "eventKey",
                format!("{}:{}", connection.id, connection.revision),
            );
            row.set("sequence", connection.revision);
            row.set("type", "credential.revoked");
            row.set("actorId", data.actor_id);
            row.set("credentialId", Some(data.credential_id));
            row.set("createdAt", revoked_at);
            _ = model::insert::<event::Model>(exec, &row).await?;
            Ok(Some(connection.into()))
        })
        .await
    }

    async fn rotate_scim_managed_credential(
        &self,
        data: alibi_core::store::RotateScimManagedCredential,
    ) -> AuthResult<Option<ScimManagedCreation>> {
        self.in_transaction(true, async move |tx| {
            let exec = Exec::tx(tx);
            let mut sql = model::select_model::<connection::Model>(exec);
            sql.push(" WHERE ");
            sql.compare(
                "scimManagedConnection",
                "connectionId",
                " = ",
                data.connection_id,
            );
            sql.push(" AND ");
            sql.compare(
                "scimManagedConnection",
                "provisioningDomainId",
                " = ",
                data.provisioning_domain_id,
            );
            model::limit_one(&mut sql);
            if exec.engine() == crate::pool::Engine::Postgres {
                sql.push(" FOR UPDATE");
            }
            let mut connection = exec
                .fetch_optional::<connection::Model>(sql)
                .await?
                .ok_or_else(|| alibi_core::AuthError::Api {
                    status: 404,
                    code: None,
                    message: "Managed SCIM connection not found".into(),
                })?;
            if connection.status != "active" {
                return Err(alibi_core::store::scim::scim_managed_conflict(
                    "Managed SCIM connection is not active",
                ));
            }
            let mut sql = Sql::with(exec.engine(), "UPDATE ");
            sql.ident("scimManagedConnection");
            sql.push(" SET ");
            sql.ident("revision");
            sql.push(" = ");
            sql.ident("revision");
            sql.push(" + 1 WHERE ");
            sql.compare("scimManagedConnection", "id", " = ", connection.id.clone());
            sql.push(" AND ");
            sql.compare("scimManagedConnection", "status", " = ", "active");
            sql.push(" AND ");
            sql.compare(
                "scimManagedConnection",
                "revision",
                " = ",
                connection.revision,
            );
            if exec.execute(sql).await? == 0 {
                return Ok(None);
            }
            connection.revision += 1;
            let mut sql = model::select_model::<credential::Model>(exec);
            sql.push(" WHERE ");
            sql.compare(
                "scimManagedCredential",
                "connectionRecordId",
                " = ",
                connection.id.clone(),
            );
            sql.push(" AND ");
            sql.compare("scimManagedCredential", "status", " = ", "active");
            sql.push(" LIMIT 101");
            let active = exec.fetch_all::<credential::Model>(sql).await?;
            let mut slots = std::collections::HashSet::new();
            for credential in active {
                if credential.expires_at <= data.created_at {
                    let mut row = ActiveRow::new();
                    row.set("id", credential.id);
                    row.set("status", "expired");
                    row.set(
                        "activeSlotKey",
                        format!("{}:inactive", credential.credential_id),
                    );
                    _ = model::update::<credential::Model>(exec, &row).await?;
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
            let mut row = ActiveRow::new();
            row.set(
                "id",
                self.generated_id(exec, "scimManagedCredential", "scimManagedCredential", "id")
                    .await?
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            );
            row.set("connectionRecordId", connection.id.clone());
            row.set("credentialId", data.credential_id.clone());
            row.set("tokenDigest", data.token_digest);
            row.set("hashVersion", "v1");
            row.set("activeSlotKey", format!("{}:active:{slot}", connection.id));
            row.set("status", "active");
            row.set("serializedScopes", data.serialized_scopes);
            row.set("expiresAt", data.expires_at);
            row.set("createdAt", data.created_at);
            row.set("createdBy", data.actor_id.clone());
            let credential = model::insert::<credential::Model>(exec, &row).await?;
            let mut row = ActiveRow::new();
            row.set(
                "id",
                self.generated_id(
                    exec,
                    "scimManagedConnectionEvent",
                    "scimManagedConnectionEvent",
                    "id",
                )
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            );
            row.set("connectionRecordId", connection.id.clone());
            row.set(
                "eventKey",
                format!("{}:{}", connection.id, connection.revision),
            );
            row.set("sequence", connection.revision);
            row.set("type", "credential.rotated");
            row.set("actorId", data.actor_id);
            row.set("credentialId", Some(data.credential_id));
            row.set("createdAt", data.created_at);
            _ = model::insert::<event::Model>(exec, &row).await?;
            Ok(Some(ScimManagedCreation {
                connection: connection.into(),
                credential: credential.into(),
            }))
        })
        .await
    }

    async fn get_scim_managed_connection(
        &self,
        id: &str,
        domain: &str,
    ) -> AuthResult<Option<alibi_core::store::ScimManagedConnectionState>> {
        let exec = self.exec();
        let mut sql = model::select_model::<connection::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimManagedConnection", "connectionId", " = ", id);
        sql.push(" AND ");
        sql.compare(
            "scimManagedConnection",
            "provisioningDomainId",
            " = ",
            domain,
        );
        model::limit_one(&mut sql);
        let Some(connection) = exec.fetch_optional::<connection::Model>(sql).await? else {
            return Ok(None);
        };
        let mut sql = model::select_model::<credential::Model>(exec);
        sql.push(" WHERE ");
        sql.compare(
            "scimManagedCredential",
            "connectionRecordId",
            " = ",
            connection.id.clone(),
        );
        sql.push(" ORDER BY ");
        sql.ident("createdAt");
        sql.push(" DESC LIMIT ");
        sql.bind(self.find_many_limit());
        let credentials = exec
            .fetch_all::<credential::Model>(sql)
            .await?
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
        let mut sql = model::select_model::<connection::Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(
            "scimManagedConnection",
            "provisioningDomainId",
            " = ",
            domain,
        );
        sql.push(" ORDER BY ");
        sql.ident("createdAt");
        sql.push(" DESC LIMIT ");
        sql.bind(self.find_many_limit());
        Ok(self
            .exec()
            .fetch_all::<connection::Model>(sql)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    async fn create_scim_managed_connection(
        &self,
        data: CreateScimManagedConnection,
    ) -> AuthResult<ScimManagedCreation> {
        let request_id = data.creation_request_id.clone();
        let result = self
            .in_transaction(true, async move |tx| {
                let exec = Exec::tx(tx);
                let mut row = ActiveRow::new();
                row.set(
                    "id",
                    self.generated_id(exec, "scimManagedConnection", "scimManagedConnection", "id")
                        .await?
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                );
                row.set("creationRequestId", data.creation_request_id);
                row.set("connectionId", data.connection_id);
                row.set("provisioningDomainId", data.provisioning_domain_id);
                row.set("status", "active");
                row.set("revision", 2_i64);
                row.set("createdAt", data.created_at);
                row.set("createdBy", data.actor_id.clone());
                let connection = model::insert::<connection::Model>(exec, &row).await?;
                let mut row = ActiveRow::new();
                row.set(
                    "id",
                    self.generated_id(exec, "scimManagedCredential", "scimManagedCredential", "id")
                        .await?
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                );
                row.set("connectionRecordId", connection.id.clone());
                row.set("credentialId", data.credential_id.clone());
                row.set("tokenDigest", data.token_digest);
                row.set("hashVersion", "v1");
                row.set("activeSlotKey", format!("{}:active:0", connection.id));
                row.set("status", "active");
                row.set("serializedScopes", data.serialized_scopes);
                row.set("expiresAt", data.expires_at);
                row.set("createdAt", data.created_at);
                row.set("createdBy", data.actor_id.clone());
                let credential = model::insert::<credential::Model>(exec, &row).await?;
                for (sequence, kind) in
                    [(1_i64, "connection.created"), (2_i64, "credential.issued")]
                {
                    let mut row = ActiveRow::new();
                    row.set(
                        "id",
                        self.generated_id(
                            exec,
                            "scimManagedConnectionEvent",
                            "scimManagedConnectionEvent",
                            "id",
                        )
                        .await?
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                    );
                    row.set("connectionRecordId", connection.id.clone());
                    row.set("eventKey", format!("{}:{sequence}", connection.id));
                    row.set("sequence", sequence);
                    row.set("type", kind);
                    row.set("actorId", data.actor_id.clone());
                    row.set(
                        "credentialId",
                        if sequence == 2 {
                            Some(data.credential_id.clone())
                        } else {
                            None
                        },
                    );
                    row.set("createdAt", data.created_at);
                    _ = model::insert::<event::Model>(exec, &row).await?;
                }
                Ok(ScimManagedCreation {
                    connection: connection.into(),
                    credential: credential.into(),
                })
            })
            .await;
        if result.is_err() {
            let mut sql = Sql::with(self.exec().engine(), "SELECT COUNT(*) FROM ");
            sql.ident("scimManagedConnection");
            sql.push(" WHERE ");
            sql.compare(
                "scimManagedConnection",
                "creationRequestId",
                " = ",
                request_id,
            );
            if self.exec().fetch_scalar::<i64>(sql).await?.unwrap_or(0) > 0 {
                return Err(alibi_core::store::scim::scim_creation_conflict());
            }
        }
        result
    }
}
