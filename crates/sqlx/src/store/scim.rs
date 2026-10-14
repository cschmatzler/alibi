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
#[async_trait]
impl<S: AuthSchema> ScimManagedStore for SqlxStore<S> {
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
