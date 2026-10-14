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
#[derive(Clone)]
pub struct RotateScimManagedCredential {
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub actor_id: String,
    pub credential_id: String,
    pub token_digest: String,
    pub serialized_scopes: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub max_active_credentials: usize,
}
#[derive(Clone)]
pub struct RevokeScimManagedCredential {
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub credential_id: String,
    pub actor_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimManagedConnectionEvent {
    pub sequence: i64,
    #[serde(rename = "type")]
    pub kind: String,
    pub actor_id: String,
    pub credential_id: Option<String>,
    pub created_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimConnectionBinding {
    pub id: String,
    pub connection_id: String,
    pub connection_key: String,
    pub provisioning_domain_id: String,
    pub created_at: DateTime<Utc>,
    pub decommission_status: String,
    pub decommission_cursor_user_id: Option<String>,
    pub decommission_reconciled_user_count: i64,
    pub decommission_batch_count: i64,
    pub decommission_revision: i64,
    pub decommissioned_at: Option<DateTime<Utc>>,
    pub decommission_completed_at: Option<DateTime<Utc>>,
    pub decommission_lease_id: Option<String>,
    pub decommission_lease_expires_at: Option<DateTime<Utc>>,
}
#[derive(Clone)]
pub struct DecommissionScimManagedConnection {
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub actor_id: String,
}
pub struct ScimManagedConnectionState {
    pub connection: ScimManagedConnection,
    pub credentials: Vec<ScimManagedCredential>,
}
pub struct ScimManagedCreation {
    pub connection: ScimManagedConnection,
    pub credential: ScimManagedCredential,
}
/// Canonical connection-owned User fields required for protocol serialization.
pub struct ScimUserRecord {
    pub id: String,
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub user_name: String,
    pub display_name: String,
    pub active: bool,
    pub external_id: Option<String>,
    pub formatted_name: String,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub serialized_emails: String,
    pub serialized_attributes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
/// Canonical connection-owned group metadata.
pub struct ScimGroupRecord {
    pub id: String,
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub display_name: String,
    pub external_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
pub struct ScimGroupMemberRecord {
    pub id: String,
    pub display_name: String,
}
pub struct ScimUserPage {
    pub total_results: i64,
    pub users: Vec<ScimUserRecord>,
}
pub struct ScimGroupPage {
    pub total_results: i64,
    pub groups: Vec<ScimGroupRecord>,
}
pub struct ScimGroupMemberships {
    pub persisted_count: usize,
    pub members: Vec<ScimGroupMemberRecord>,
}
#[async_trait]
pub trait ScimManagedStore: Send + Sync {
    async fn scim_user_domain_stable(&self, _connection: &str, _domain: &str) -> AuthResult<bool> {
        Err(AuthError::config(
            "SCIM resource persistence is not supported by this store",
        ))
    }
    async fn list_scim_users(
        &self,
        _connection: &str,
        _filters: &[(String, String)],
        _offset: i64,
        _count: i64,
    ) -> AuthResult<ScimUserPage> {
        Err(AuthError::config(
            "SCIM resource persistence is not supported by this store",
        ))
    }

    async fn scim_group_domain_stable(&self, _connection: &str, _domain: &str) -> AuthResult<bool> {
        Err(AuthError::config(
            "SCIM resource persistence is not supported by this store",
        ))
    }
    async fn list_scim_groups(
        &self,
        _connection: &str,
        _filters: &[(String, String)],
        _offset: i64,
        _count: i64,
    ) -> AuthResult<ScimGroupPage> {
        Err(AuthError::config(
            "SCIM resource persistence is not supported by this store",
        ))
    }

    async fn get_scim_user(
        &self,
        _id: &str,
        _connection: &str,
    ) -> AuthResult<Option<ScimUserRecord>> {
        Err(AuthError::config(
            "SCIM resource persistence is not supported by this store",
        ))
    }

    async fn find_scim_managed_credential(
        &self,
        _credential_id: &str,
    ) -> AuthResult<Option<ScimManagedCredential>> {
        Err(AuthError::config(
            "Managed SCIM persistence is not supported by this store",
        ))
    }
    async fn find_scim_active_managed_connection(
        &self,
        _id: &str,
    ) -> AuthResult<Option<ScimManagedConnection>> {
        Err(AuthError::config(
            "Managed SCIM persistence is not supported by this store",
        ))
    }
    async fn record_scim_credential_use(
        &self,
        _id: &str,
        _previous: Option<DateTime<Utc>>,
        _at: DateTime<Utc>,
    ) -> AuthResult<()> {
        Err(AuthError::config(
            "Managed SCIM persistence is not supported by this store",
        ))
    }

    async fn active_scim_connection_binding(
        &self,
        _id: &str,
        _domain: &str,
        _key: &str,
    ) -> AuthResult<ScimConnectionBinding> {
        Err(AuthError::config(
            "SCIM binding persistence is not supported by this store",
        ))
    }
    async fn get_scim_group(
        &self,
        _id: &str,
        _connection: &str,
    ) -> AuthResult<Option<ScimGroupRecord>> {
        Err(AuthError::config(
            "SCIM resource persistence is not supported by this store",
        ))
    }
    async fn scim_group_members(
        &self,
        _id: &str,
        _connection: &str,
    ) -> AuthResult<ScimGroupMemberships> {
        Err(AuthError::config(
            "SCIM resource persistence is not supported by this store",
        ))
    }

    async fn acquire_scim_decommission_lease(
        &self,
        _binding: ScimConnectionBinding,
    ) -> AuthResult<Option<ScimConnectionBinding>> {
        Err(AuthError::config(
            "SCIM binding persistence is not supported by this store",
        ))
    }
    async fn release_scim_decommission_lease(&self, _id: &str, _lease: &str) -> AuthResult<()> {
        Err(AuthError::config(
            "SCIM binding persistence is not supported by this store",
        ))
    }

    async fn scim_projection_candidates(
        &self,
        _domain: &str,
        _cursor: Option<&str>,
    ) -> AuthResult<Vec<ScimProjectionCandidate>> {
        Err(AuthError::config(
            "SCIM projection persistence is not supported by this store",
        ))
    }

    async fn decommission_scim_managed_connection(
        &self,
        _data: DecommissionScimManagedConnection,
        _complete: bool,
    ) -> AuthResult<Option<ScimManagedConnection>> {
        Err(AuthError::config(
            "Managed SCIM persistence is not supported by this store",
        ))
    }

    async fn terminal_scim_connection_binding(
        &self,
        _id: &str,
        _domain: Option<&str>,
        _key: &str,
    ) -> AuthResult<ScimConnectionBinding> {
        Err(AuthError::config(
            "SCIM binding persistence is not supported by this store",
        ))
    }

    async fn list_scim_managed_connection_events(
        &self,
        _id: &str,
        _domain: &str,
    ) -> AuthResult<Option<Vec<ScimManagedConnectionEvent>>> {
        Err(AuthError::config(
            "Managed SCIM persistence is not supported by this store",
        ))
    }

    async fn revoke_scim_managed_credential(
        &self,
        _data: RevokeScimManagedCredential,
    ) -> AuthResult<Option<ScimManagedConnection>> {
        Err(AuthError::config(
            "Managed SCIM persistence is not supported by this store",
        ))
    }

    async fn rotate_scim_managed_credential(
        &self,
        _data: RotateScimManagedCredential,
    ) -> AuthResult<Option<ScimManagedCreation>> {
        Err(AuthError::config(
            "Managed SCIM persistence is not supported by this store",
        ))
    }

    async fn get_scim_managed_connection(
        &self,
        _id: &str,
        _domain: &str,
    ) -> AuthResult<Option<ScimManagedConnectionState>> {
        Err(AuthError::config(
            "Managed SCIM persistence is not supported by this store",
        ))
    }

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

pub fn scim_managed_conflict(message: &str) -> AuthError {
    AuthError::Api {
        status: 409,
        code: None,
        message: message.into(),
    }
}

pub fn validate_scim_binding_domain(
    binding: &ScimConnectionBinding,
    domain: Option<&str>,
) -> AuthResult<()> {
    if let Some(domain) = domain
        && domain != binding.provisioning_domain_id
    {
        return Err(AuthError::internal(format!(
            "SCIM connection \"{}\" is already bound to provisioning domain \"{}\".",
            binding.connection_id, binding.provisioning_domain_id
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimIdentitySource {
    pub id: String,
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub active: bool,
}
/// Order callback sources like the reference's `String.localeCompare`.
///
/// # Errors
/// Returns an error if the compiled collation data cannot be loaded.
pub fn sort_scim_sources(sources: &mut [ScimIdentitySource]) -> AuthResult<()> {
    let collator = icu_collator::Collator::try_new(
        icu_collator::CollatorPreferences::default(),
        icu_collator::options::CollatorOptions::default(),
    )
    .map_err(|error| AuthError::internal(error.to_string()))?;
    sources.sort_by(|left, right| collator.compare(&left.id, &right.id));
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimProjectedUserState {
    pub provisioning_domain_id: String,
    pub user_id: String,
    pub active: bool,
    pub sources: Vec<ScimIdentitySource>,
    pub grants: Vec<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct ScimProjectionCandidate {
    pub id: String,
    pub user_id: String,
}
pub struct ScimProjectionPreparedUser {
    pub state: ScimProjectedUserState,
    pub removed_grant_ids: Vec<String>,
    pub existing_grants: Vec<(String, String)>,
    pub role_sources: Vec<ScimRoleMappingInput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ScimAuthorizationSource {
    Group {
        id: String,
        #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
        external_id: Option<String>,
        #[serde(rename = "displayName")]
        display_name: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimRoleMappingInput {
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub scim_user_id: String,
    pub user_id: String,
    pub source: ScimAuthorizationSource,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimRoleExistenceInput {
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub role: String,
}

#[derive(Clone)]
pub struct CreateScimProjectionGrant {
    pub connection_id: String,
    pub provisioning_domain_id: String,
    pub scim_user_id: String,
    pub user_id: String,
    pub source_id: String,
    pub source_value: String,
    pub role: String,
    pub grant_key: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimIdentityState {
    pub user_id: String,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_source_id: Option<String>,
    pub sources: Vec<ScimIdentitySource>,
}
