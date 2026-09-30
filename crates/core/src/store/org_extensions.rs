//! Optional organization team and persisted-role storage contracts.
use crate::error::{AuthError, AuthResult};
use crate::types_org::{
    AddTeamMemberResult, CreateOrganizationRole, CreateTeam, OrganizationRole,
    OrganizationRoleSelector, Team, TeamMember, UpdateOrganizationRole, UpdateTeam,
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

fn unsupported() -> AuthError {
    AuthError::NotImplemented(
        "Organization extension storage is not supported by this store".to_owned(),
    )
}

pub fn team_membership_key(team_id: &str, user_id: &str) -> AuthResult<String> {
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&[team_id, user_id])?)))
}

#[async_trait]
pub trait TeamStore: Send + Sync {
    async fn create_team(&self, _data: CreateTeam) -> AuthResult<Team> {
        Err(unsupported())
    }
    async fn get_team(
        &self,
        _organization_id: Option<&str>,
        _team_id: &str,
    ) -> AuthResult<Option<Team>> {
        Err(unsupported())
    }
    async fn list_teams(&self, _organization_id: &str) -> AuthResult<Vec<Team>> {
        Err(unsupported())
    }
    async fn update_team(
        &self,
        _organization_id: &str,
        _team_id: &str,
        _update: UpdateTeam,
    ) -> AuthResult<Team> {
        Err(unsupported())
    }
    /// Remove the scoped team, its memberships, and its IDs from pending invitations atomically.
    async fn delete_team(&self, _organization_id: &str, _team_id: &str) -> AuthResult<bool> {
        Err(unsupported())
    }
    async fn get_team_member(
        &self,
        _team_id: &str,
        _user_id: &str,
    ) -> AuthResult<Option<TeamMember>> {
        Err(unsupported())
    }
    /// Existing membership is idempotent, including when the capacity has since been reached.
    async fn add_team_member(
        &self,
        _team_id: &str,
        _user_id: &str,
        _maximum: Option<usize>,
    ) -> AuthResult<AddTeamMemberResult> {
        Err(unsupported())
    }
    async fn remove_team_member(&self, _team_id: &str, _user_id: &str) -> AuthResult<usize> {
        Err(unsupported())
    }
    async fn list_team_members(&self, _team_id: &str) -> AuthResult<Vec<TeamMember>> {
        Err(unsupported())
    }
    async fn list_user_teams(&self, _user_id: &str) -> AuthResult<Vec<Team>> {
        Err(unsupported())
    }
}

#[async_trait]
pub trait OrganizationRoleStore: Send + Sync {
    async fn create_organization_role(
        &self,
        _data: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        Err(unsupported())
    }
    async fn get_organization_role(
        &self,
        _organization_id: &str,
        _selector: &OrganizationRoleSelector,
    ) -> AuthResult<Option<OrganizationRole>> {
        Err(unsupported())
    }
    async fn list_organization_roles(
        &self,
        _organization_id: &str,
    ) -> AuthResult<Vec<OrganizationRole>> {
        Err(unsupported())
    }
    /// Count all roles in the organization independently of the list query limit.
    async fn count_organization_roles(&self, _organization_id: &str) -> AuthResult<usize> {
        Err(unsupported())
    }
    async fn update_organization_role(
        &self,
        _organization_id: &str,
        _selector: &OrganizationRoleSelector,
        _update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        Err(unsupported())
    }
    async fn delete_organization_role(
        &self,
        _organization_id: &str,
        _selector: &OrganizationRoleSelector,
    ) -> AuthResult<bool> {
        Err(unsupported())
    }
}
