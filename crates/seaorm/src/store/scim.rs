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
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, Set, TransactionTrait,
};
#[async_trait]
impl<S: AuthSchema> ScimManagedStore for SeaOrmStore<S> {
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
