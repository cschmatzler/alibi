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
