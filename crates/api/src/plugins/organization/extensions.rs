//! Configurable teams and persisted organization access control.
use async_trait::async_trait;
use better_auth_core::store::TeamStore;
use better_auth_core::types::{
    CreateTeam, Organization, OrganizationPermissions, Team, TeamMember, UpdateTeam,
};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{AuthRequest, AuthResult};
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct TeamLimitContext {
    pub organization_id: String,
    pub team_id: Option<String>,
    pub session: Option<SessionView>,
    pub user: Option<UserView>,
    /// The endpoint request supplied to the upstream maximum-teams callback.
    pub request: Option<AuthRequest>,
}

#[async_trait]
pub trait OrganizationLimitResolver: std::fmt::Debug + Send + Sync {
    async fn maximum_teams(&self, _context: &TeamLimitContext) -> AuthResult<Option<usize>> {
        Ok(None)
    }
    async fn maximum_team_members(&self, _context: &TeamLimitContext) -> AuthResult<Option<usize>> {
        Ok(None)
    }
    async fn maximum_roles(&self, _organization_id: &str) -> AuthResult<Option<usize>> {
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct TeamHookContext {
    pub organization: Organization,
    pub user: Option<UserView>,
}

#[async_trait]
pub trait OrganizationTeamHooks: std::fmt::Debug + Send + Sync {
    async fn before_create(
        &self,
        _data: &mut CreateTeam,
        _context: &TeamHookContext,
    ) -> AuthResult<()> {
        Ok(())
    }
    async fn after_create(&self, _team: &Team, _context: &TeamHookContext) -> AuthResult<()> {
        Ok(())
    }
    async fn before_update(
        &self,
        _team: &Team,
        _updates: &mut UpdateTeam,
        _context: &TeamHookContext,
    ) -> AuthResult<()> {
        Ok(())
    }
    async fn after_update(&self, _team: &Team, _context: &TeamHookContext) -> AuthResult<()> {
        Ok(())
    }
    async fn before_delete(&self, _team: &Team, _context: &TeamHookContext) -> AuthResult<()> {
        Ok(())
    }
    async fn after_delete(&self, _team: &Team, _context: &TeamHookContext) -> AuthResult<()> {
        Ok(())
    }
    async fn before_add_member(
        &self,
        _team: &Team,
        _user: &UserView,
        _context: &TeamHookContext,
    ) -> AuthResult<()> {
        Ok(())
    }
    async fn after_add_member(
        &self,
        _member: &TeamMember,
        _team: &Team,
        _user: &UserView,
        _context: &TeamHookContext,
    ) -> AuthResult<()> {
        Ok(())
    }
    async fn before_remove_member(
        &self,
        _member: &TeamMember,
        _team: &Team,
        _user: &UserView,
        _context: &TeamHookContext,
    ) -> AuthResult<()> {
        Ok(())
    }
    async fn after_remove_member(
        &self,
        _member: &TeamMember,
        _team: &Team,
        _user: &UserView,
        _context: &TeamHookContext,
    ) -> AuthResult<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct DefaultTeamContext {
    pub request: Option<AuthRequest>,
    pub user: UserView,
    pub session: Option<SessionView>,
    pub config: Arc<better_auth_core::AuthConfig>,
}

impl std::fmt::Debug for DefaultTeamContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultTeamContext").finish_non_exhaustive()
    }
}

#[async_trait]
pub trait DefaultTeamFactory: std::fmt::Debug + Send + Sync {
    async fn create(
        &self,
        organization: &Organization,
        context: &DefaultTeamContext,
        store: &dyn TeamStore,
    ) -> AuthResult<Option<Team>>;
}

#[derive(Debug, Clone)]
pub struct TeamsConfig {
    pub enabled: bool,
    pub create_default_team: bool,
    pub allow_removing_all_teams: bool,
    pub maximum_teams: Option<usize>,
    pub maximum_members_per_team: Option<usize>,
    pub limit_resolver: Option<Arc<dyn OrganizationLimitResolver>>,
    pub hooks: Option<Arc<dyn OrganizationTeamHooks>>,
    pub default_team_factory: Option<Arc<dyn DefaultTeamFactory>>,
}
impl Default for TeamsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            create_default_team: true,
            allow_removing_all_teams: false,
            maximum_teams: None,
            maximum_members_per_team: None,
            limit_resolver: None,
            hooks: None,
            default_team_factory: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DynamicAccessControlConfig {
    pub enabled: bool,
    pub maximum_roles_per_organization: Option<usize>,
    pub limit_resolver: Option<Arc<dyn OrganizationLimitResolver>>,
}

#[must_use]
pub fn default_organization_statements() -> OrganizationPermissions {
    [
        ("organization", vec!["update", "delete"]),
        ("member", vec!["create", "update", "delete"]),
        ("invitation", vec!["create", "cancel"]),
        ("team", vec!["create", "update", "delete"]),
        ("ac", vec!["create", "read", "update", "delete"]),
    ]
    .into_iter()
    .map(|(resource, actions)| {
        (
            resource.to_owned(),
            actions.into_iter().map(str::to_owned).collect(),
        )
    })
    .collect()
}
