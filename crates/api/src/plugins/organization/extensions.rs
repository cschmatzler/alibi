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

/// Application quota callbacks use raw ECMAScript Number policies.
///
/// Migration from integer callbacks: return `AuthResult<Option<f64>>` and
/// `Some(3.0)` instead of `AuthResult<Option<usize>>` and `Some(3)`.
/// `None` means no quota; it does not model a JavaScript callback returning
/// non-numeric values. Callbacks keep the actual existing contexts and follow each Source endpoint
/// ordering contract.
#[async_trait]
pub trait OrganizationLimitResolver: std::fmt::Debug + Send + Sync {
    async fn maximum_teams(&self, _context: &TeamLimitContext) -> AuthResult<Option<f64>> {
        Ok(None)
    }
    async fn maximum_team_members(&self, _context: &TeamLimitContext) -> AuthResult<Option<f64>> {
        Ok(None)
    }
    async fn maximum_roles(&self, _organization_id: &str) -> AuthResult<Option<f64>> {
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
    /// Raw team quota. Zero and NaN disable this quota; negative values deny
    /// creation. Fractional values are compared to the Source adapter's list
    /// length without rounding. `None` leaves the quota unset.
    /// Integer configuration migrates from `Some(3)` to `Some(3.0)`.
    pub maximum_teams: Option<f64>,
    /// Raw durable seat quota, bound to the adapter's `member_count < maximum`
    /// predicate. In SQLite zero, negative values, NaN and negative infinity
    /// deny new seats; positive infinity admits them. Existing seats are retries.
    /// Integer configuration migrates from `Some(3)` to `Some(3.0)`.
    pub maximum_members_per_team: Option<f64>,
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
    /// Raw role quota, compared to the full persisted count. `None` is the
    /// Source nullish default of positive infinity; zero/negative values deny,
    /// NaN/positive infinity admit, and fractions are never rounded.
    /// Integer configuration migrates from `Some(3)` to `Some(3.0)`.
    pub maximum_roles_per_organization: Option<f64>,
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
