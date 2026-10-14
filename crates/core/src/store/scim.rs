//! Durable, atomic framework-managed provisioning credentials.
use crate::{AuthError, AuthResult};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimManagedConnection {
    pub id: String,
    pub creation_request_id: String,
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub status: String,
    pub revision: i64,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub decommission_started_at: Option<DateTime<Utc>>,
    pub decommission_started_by: Option<String>,
    pub decommissioned_at: Option<DateTime<Utc>>,
    pub decommissioned_by: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimManagedCredential {
    pub id: String,
    pub connection_record_id: String,
    pub credential_id: String,
    pub token_digest: String,
    pub hash_version: String,
    pub active_slot_key: String,
    pub status: String,
    pub serialized_scopes: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
    pub decommissioned_at: Option<DateTime<Utc>>,
}
pub struct CreateScimManagedConnection {
    pub creation_request_id: String,
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub actor_id: String,
    pub credential_id: String,
    pub token_digest: String,
    pub serialized_scopes: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
pub struct ScimManagedCreation {
    pub connection: ScimManagedConnection,
    pub credential: ScimManagedCredential,
}
#[async_trait]
pub trait ScimManagedStore: Send + Sync {
    async fn list_scim_managed_connections(
        &self,
        _domain: &str,
    ) -> AuthResult<Vec<ScimManagedConnection>> {
        Err(AuthError::config(
            "Managed SCIM persistence is not supported by this store",
        ))
    }

    /// Insert one connection, its credential, and both ordered events in one transaction.
    /// # Errors
    /// Returns a conflict when the creation request was already consumed.
    async fn create_scim_managed_connection(
        &self,
        _data: CreateScimManagedConnection,
    ) -> AuthResult<ScimManagedCreation> {
        Err(AuthError::config(
            "Managed SCIM persistence is not supported by this store",
        ))
    }
}
pub fn scim_creation_conflict() -> AuthError {
    AuthError::Api {
        status: 409,
        code: Some("SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT".into()),
        message: "Managed SCIM connection creation request ID already exists".into(),
    }
}
