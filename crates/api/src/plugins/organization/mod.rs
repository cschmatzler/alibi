pub mod creation_policy;

pub mod extensions;

pub mod handlers;

pub mod lifecycle;

pub mod invitation_acceptance_lifecycle;

pub mod membership_policy;

pub mod member_addition_lifecycle;

pub mod member_removal_lifecycle;

pub mod member_role_lifecycle;

pub mod rbac;

pub mod types;

pub mod update_lifecycle;

#[cfg(test)]
mod extension_tests;

#[cfg(test)]
mod dynamic_role_tests;

use async_trait::async_trait;
use better_auth_core::error::AuthResult;
use better_auth_core::plugin::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::types::{AuthRequest, AuthResponse, HttpMethod};
pub use creation_policy::OrganizationCreationPolicy;
pub use extensions::{
    DefaultTeamContext, DefaultTeamFactory, DynamicAccessControlConfig, OrganizationLimitResolver,
    OrganizationTeamHooks, TeamsConfig, default_organization_statements,
};
pub use invitation_acceptance_lifecycle::{
    OrganizationInvitationAcceptanceContext, OrganizationInvitationAcceptanceHooks,
    OrganizationInvitationAcceptedContext,
};
pub use lifecycle::{
    OrganizationCreatePatch, OrganizationCreatedContext, OrganizationCreationHooks,
    OrganizationDeleteContext, OrganizationDeletionHooks, OrganizationDraftContext,
    OrganizationMemberCreatePatch, OrganizationMemberDraftContext,
};
pub use member_addition_lifecycle::{
    OrganizationMemberAddedContext, OrganizationMemberAdditionContext,
    OrganizationMemberAdditionDraft, OrganizationMemberAdditionHooks,
};
pub use member_removal_lifecycle::{
    OrganizationMemberRemovalContext, OrganizationMemberRemovalHooks,
};
pub use member_role_lifecycle::{
    OrganizationMemberRoleContext, OrganizationMemberRoleHooks, OrganizationMemberRolePatch,
    OrganizationMemberRoleUpdatedContext,
};
pub use membership_policy::{MembershipLimit, OrganizationMembershipLimitResolver};
use std::collections::HashMap;
pub use update_lifecycle::{
    OrganizationUpdateContext, OrganizationUpdateHooks, OrganizationUpdateInput,
    OrganizationUpdatePatch, OrganizationUpdatedContext,
};

/// Permission definitions for a role
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RolePermissions {
    pub organization: Vec<String>,
    pub member: Vec<String>,
    pub invitation: Vec<String>,
    /// Actions this role may perform on organization-owned API keys. Upstream's
    /// default statements define none, so only the creator role can manage them
    /// until an application grants this explicitly.
    pub api_key: Vec<String>,
    #[serde(default)]
    pub team: Vec<String>,
    #[serde(default)]
    pub ac: Vec<String>,
    #[serde(flatten)]
    pub additional: better_auth_core::types::OrganizationPermissions,
}

/// Configuration for the Organization plugin
#[derive(Debug, Clone, better_auth_core::PluginConfig)]
#[plugin(name = "OrganizationPlugin")]
pub struct OrganizationConfig {
    /// Allow users to create organizations (default: true)
    #[config(default = true)]
    pub allow_user_to_create_organization: bool,
    /// Maximum organization memberships per user (`None` = unlimited).
    /// Uses JavaScript Number comparisons: fractional, negative, NaN and infinite
    /// limits retain their upstream meanings.
    #[config(default = None)]
    pub organization_limit: Option<f64>,
    /// Optional asynchronous policy overrides, evaluated against the actual user.
    #[config(default = None, skip)]
    pub creation_policy: Option<std::sync::Arc<dyn OrganizationCreationPolicy>>,
    /// Awaited creation callbacks with immutable authority and persisted snapshots.
    #[config(default = None, skip)]
    pub creation_hooks: Option<std::sync::Arc<dyn OrganizationCreationHooks>>,
    /// Awaited deletion callbacks over raw rows and original authority snapshots.
    #[config(default = None, skip)]
    pub deletion_hooks: Option<std::sync::Arc<dyn OrganizationDeletionHooks>>,
    /// Awaited update callbacks over validated input and original authority.
    #[config(default = None, skip)]
    pub update_hooks: Option<std::sync::Arc<dyn OrganizationUpdateHooks>>,
    /// Awaited member role callbacks with immutable target snapshots.
    #[config(default = None, skip)]
    pub member_role_hooks: Option<std::sync::Arc<dyn OrganizationMemberRoleHooks>>,
    /// Awaited member removal callbacks over immutable original target rows.
    #[config(default = None, skip)]
    pub member_removal_hooks: Option<std::sync::Arc<dyn OrganizationMemberRemovalHooks>>,
    /// Awaited server-only addition callbacks over the target and raw organization.
    #[config(default = None, skip)]
    pub member_addition_hooks: Option<std::sync::Arc<dyn OrganizationMemberAdditionHooks>>,
    /// Awaited acceptance callbacks around conditional claim and membership transaction.
    #[config(default = None, skip)]
    pub invitation_acceptance_hooks:
        Option<std::sync::Arc<dyn OrganizationInvitationAcceptanceHooks>>,
    /// Admission policy. Absent or falsy fixed numbers use 100; resolver results
    /// retain JavaScript Number comparison semantics without a second fallback.
    /// Read pages use only a fixed number, and never call an admission resolver.
    #[config(default = Some(MembershipLimit::Fixed(100.0)), skip)]
    pub membership_limit: Option<MembershipLimit>,
    /// Role assigned to organization creator (default: "owner")
    #[config(default = "owner".to_owned())]
    pub creator_role: String,
    /// Invitation expiration in seconds (default: 48 hours)
    #[config(default = 60 * 60 * 48)]
    pub invitation_expires_in: u64,
    /// Maximum pending invitations per organization (None = unlimited)
    #[config(default = Some(100))]
    pub invitation_limit: Option<usize>,
    /// Disable organization deletion (default: false)
    #[config(default = false)]
    pub disable_organization_deletion: bool,
    /// Static role definitions. None uses the upstream default roles; an
    /// explicitly empty map grants no static permissions.
    #[config(default = None, skip)]
    pub roles: Option<HashMap<String, RolePermissions>>,
    /// Require verified email to view, accept, or reject an invitation by ID.
    /// None requires it when the configured database uses numeric IDs.
    #[config(default = None)]
    pub require_email_verification_on_invitation: Option<bool>,
    #[config(default = TeamsConfig::default(), skip)]
    pub teams: TeamsConfig,
    #[config(default = DynamicAccessControlConfig::default(), skip)]
    pub dynamic_access_control: DynamicAccessControlConfig,
    #[config(default = None, skip)]
    pub access_control: Option<better_auth_core::types::OrganizationPermissions>,
}

impl OrganizationConfig {
    /// The pinned creator-role option uses JavaScript's nonempty-string fallback.
    #[must_use]
    pub fn effective_creator_role(&self) -> &str {
        if self.creator_role.is_empty() {
            "owner"
        } else {
            &self.creator_role
        }
    }
}

/// Organization plugin for multi-tenancy support
pub struct OrganizationPlugin {
    config: OrganizationConfig,
}

impl OrganizationPlugin {
    /// Trusted server-only member admission. Explicit organization and target IDs
    /// do not require a caller session; optional signed headers provide active
    /// organization fallback and authority for a functional team-limit callback.
    /// This helper never registers a public authentication route and does not run
    /// builder-wide dispatch hooks or API-key virtual-session injection.
    ///
    /// # Errors
    ///
    /// Returns an error if membership validation, permission checks, admission hooks, or persistence fail.
    pub async fn add_member_with_headers<S: better_auth_core::AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        headers: &HashMap<String, String>,
        body: &types::AddOrganizationMemberRequest,
    ) -> AuthResult<types::BasicMemberResponse> {
        handlers::member_addition::add_member(body, headers, &self.config, ctx).await
    }

    /// Remove through a real signed-cookie session supplied by the application.
    /// This low-level helper shares HTTP business logic but does not execute
    /// builder-wide before/after dispatch hooks or API-key session injection.
    ///
    /// # Errors
    ///
    /// Returns an error if membership authorization, removal hooks, or persistence fail.
    pub async fn remove_member_with_headers<S: better_auth_core::AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        headers: &HashMap<String, String>,
        body: &types::RemoveMemberRequest,
    ) -> AuthResult<types::RemovedMemberResponse<types::OrganizationMemberRemovalSnapshot>> {
        let mut resolution = AuthRequest::new(HttpMethod::Post, "/organization/remove-member");
        resolution.headers = headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect();
        let (user, session) = handlers::extension_common::session(&resolution, ctx).await?;
        handlers::member::remove_member_core(body, &user, &session, &self.config, ctx).await
    }

    /// Delete using an actual signed-cookie session from supplied headers, without
    /// manufacturing an HTTP request for lifecycle callbacks. This low-level
    /// plugin helper does not execute builder-wide before/after dispatch hooks;
    /// API-key-only session injection requires normal authenticated dispatch.
    /// None represents a missing organization after its membership was resolved.
    ///
    /// # Errors
    ///
    /// Returns an error if organization authorization, deletion hooks, or persistence fail.
    pub async fn delete_organization_with_headers<S: better_auth_core::AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        headers: &HashMap<String, String>,
        body: &types::DeleteOrganizationRequest,
    ) -> AuthResult<Option<types::OrganizationResponse>> {
        if self.config.disable_organization_deletion {
            return Err(handlers::extension_common::org_error(
                404,
                "ORGANIZATION_DELETION_DISABLED",
            ));
        }
        let mut resolution = AuthRequest::new(HttpMethod::Post, "/organization/delete");
        resolution.headers = headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect();
        let (user, session) = handlers::require_session(&resolution, ctx).await?;
        handlers::org::delete_organization_core(
            body,
            &user,
            &session,
            lifecycle::DeleteInvocation {
                headers,
                request: None,
            },
            &self.config,
            ctx,
        )
        .await
    }

    /// Trusted server operation. The supplied user ID is resolved from storage;
    /// HTTP creation always uses the authenticated principal instead.
    /// Like upstream's server-only body.userId branch, this bypasses an allow-policy
    /// denial while still evaluating that policy and enforcing organization limits.
    ///
    /// # Errors
    ///
    /// Returns an error if creation policies, organization hooks, or persistence reject the operation.
    pub async fn create_organization_for_user<S: better_auth_core::AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        user_id: &str,
        body: &types::CreateOrganizationRequest,
    ) -> AuthResult<
        types::CreateOrganizationResponse<
            types::CreatedOrganizationResponse,
            types::BasicMemberResponse,
        >,
    > {
        handlers::org_input::validate_trusted_create(body)?;
        let user = ctx
            .database
            .get_user_by_id(user_id)
            .await?
            .ok_or(better_auth_core::AuthError::Unauthenticated)?;
        handlers::org::create_organization_core(body, &user, None, None, &self.config, ctx).await
    }
}

/// Metadata key announcing that the organization plugin is installed.
pub(in crate::plugins) const METADATA_ENABLED: &str = "organization.enabled";

/// Metadata key carrying the configured custom roles, so other plugins can run
/// the organization's access control without depending on this plugin's config.
pub(in crate::plugins) const METADATA_ROLES: &str = "organization.roles";

/// Metadata key carrying the creator role, which is allowed every action.
pub(in crate::plugins) const METADATA_CREATOR_ROLE: &str = "organization.creator_role";

#[async_trait]
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for OrganizationPlugin {
    fn name(&self) -> &'static str {
        "organization"
    }

    fn session_fields(&self) -> better_auth_core::field_policy::FieldConfigs {
        let mut fields = better_auth_core::field_policy::FieldConfigs::new();
        drop(
            fields.insert(
                "activeOrganizationId".into(),
                better_auth_core::field_policy::FieldConfig::new(
                    serde_json::json!({"type":"string"}),
                )
                .read_only(),
            ),
        );
        if self.config.teams.enabled {
            drop(
                fields.insert(
                    "activeTeamId".into(),
                    better_auth_core::field_policy::FieldConfig::new(
                        serde_json::json!({"type":"string"}),
                    )
                    .read_only(),
                ),
            );
        }
        fields
    }

    async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
        ctx.set_metadata(METADATA_ENABLED, serde_json::Value::Bool(true));
        ctx.set_metadata(
            "organization.teams.enabled",
            serde_json::Value::Bool(self.config.teams.enabled),
        );
        ctx.set_metadata(
            "organization.dynamic_roles.enabled",
            serde_json::Value::Bool(self.config.dynamic_access_control.enabled),
        );
        ctx.set_metadata(
            "organization.access_control",
            serde_json::to_value(&self.config.access_control)?,
        );
        ctx.set_metadata(
            METADATA_ROLES,
            serde_json::to_value(&self.config.roles).unwrap_or_default(),
        );
        ctx.set_metadata(
            METADATA_CREATOR_ROLE,
            serde_json::Value::String(self.config.effective_creator_role().to_owned()),
        );
        Ok(())
    }

    fn routes(&self) -> Vec<AuthRoute> {
        let mut routes = vec![
            // Organization CRUD
            AuthRoute::post("/organization/create", "create_organization"),
            AuthRoute::post("/organization/update", "update_organization"),
            AuthRoute::post("/organization/delete", "delete_organization"),
            AuthRoute::get("/organization/list", "list_organizations"),
            AuthRoute::get("/organization/get-organization", "get_organization"),
            AuthRoute::get(
                "/organization/get-full-organization",
                "get_full_organization",
            ),
            AuthRoute::post("/organization/check-slug", "check_slug"),
            AuthRoute::post("/organization/set-active", "set_active_organization"),
            AuthRoute::post("/organization/leave", "leave_organization"),
            // Member management
            AuthRoute::get("/organization/get-active-member", "get_active_member"),
            AuthRoute::get(
                "/organization/get-active-member-role",
                "get_active_member_role",
            ),
            AuthRoute::get("/organization/list-members", "list_members"),
            AuthRoute::post("/organization/remove-member", "remove_member"),
            AuthRoute::post("/organization/update-member-role", "update_member_role"),
            // Invitations
            AuthRoute::post("/organization/invite-member", "invite_member"),
            AuthRoute::get("/organization/get-invitation", "get_invitation"),
            AuthRoute::get("/organization/list-invitations", "list_invitations"),
            AuthRoute::get(
                "/organization/list-user-invitations",
                "list_user_invitations",
            ),
            AuthRoute::post("/organization/accept-invitation", "accept_invitation"),
            AuthRoute::post("/organization/reject-invitation", "reject_invitation"),
            AuthRoute::post("/organization/cancel-invitation", "cancel_invitation"),
            // Permission check
            AuthRoute::post("/organization/has-permission", "has_permission"),
        ];
        if self.config.teams.enabled {
            routes.extend([
                AuthRoute::post("/organization/create-team", "create_team"),
                AuthRoute::post("/organization/update-team", "update_team"),
                AuthRoute::post("/organization/remove-team", "remove_team"),
                AuthRoute::get("/organization/list-teams", "list_teams"),
                AuthRoute::get("/organization/list-user-teams", "list_user_teams"),
                AuthRoute::get("/organization/list-team-members", "list_team_members"),
                AuthRoute::post("/organization/set-active-team", "set_active_team"),
                AuthRoute::post("/organization/add-team-member", "add_team_member"),
                AuthRoute::post("/organization/remove-team-member", "remove_team_member"),
            ]);
        }
        if self.config.dynamic_access_control.enabled {
            routes.extend([
                AuthRoute::post("/organization/create-role", "create_role"),
                AuthRoute::post("/organization/update-role", "update_role"),
                AuthRoute::post("/organization/delete-role", "delete_role"),
                AuthRoute::get("/organization/get-role", "get_role"),
                AuthRoute::get("/organization/list-roles", "list_roles"),
            ]);
        }
        routes
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            // Organization CRUD
            (HttpMethod::Post, "/organization/create") => Ok(Some(
                handlers::org::handle_create_organization(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/update") => Ok(Some(
                handlers::org::handle_update_organization(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/delete") => Ok(Some(
                handlers::org::handle_delete_organization(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Get, "/organization/list") => Ok(Some(
                handlers::org::handle_list_organizations(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/get-organization") => Ok(Some(
                handlers::org::handle_get_organization(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/get-full-organization") => Ok(Some(
                handlers::org::handle_get_full_organization(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/check-slug") => {
                Ok(Some(handlers::org::handle_check_slug(req, ctx).await?))
            }
            (HttpMethod::Post, "/organization/set-active") => Ok(Some(
                handlers::org::handle_set_active_organization(req, ctx).await?,
            )),
            (HttpMethod::Post, "/organization/leave") => Ok(Some(
                handlers::org::handle_leave_organization(req, ctx, &self.config).await?,
            )),
            // Member management
            (HttpMethod::Get, "/organization/get-active-member") => Ok(Some(
                handlers::member::handle_get_active_member(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/get-active-member-role") => Ok(Some(
                handlers::member::handle_get_active_member_role(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/list-members") => Ok(Some(
                handlers::member::handle_list_members(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/remove-member") => Ok(Some(
                handlers::member::handle_remove_member(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/update-member-role") => Ok(Some(
                handlers::member::handle_update_member_role(req, ctx, &self.config).await?,
            )),
            // Invitations
            (HttpMethod::Post, "/organization/invite-member") => Ok(Some(
                handlers::invitation::handle_invite_member(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Get, "/organization/get-invitation") => Ok(Some(
                handlers::invitation::handle_get_invitation(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Get, "/organization/list-invitations") => Ok(Some(
                handlers::invitation::handle_list_invitations(req, ctx).await?,
            )),
            (HttpMethod::Get, "/organization/list-user-invitations") => Ok(Some(
                handlers::invitation::handle_list_user_invitations(req, ctx).await?,
            )),
            (HttpMethod::Post, "/organization/accept-invitation") => Ok(Some(
                handlers::invitation::handle_accept_invitation(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/reject-invitation") => Ok(Some(
                handlers::invitation::handle_reject_invitation(req, ctx, &self.config).await?,
            )),
            (HttpMethod::Post, "/organization/cancel-invitation") => Ok(Some(
                handlers::invitation::handle_cancel_invitation(req, ctx, &self.config).await?,
            )),
            // Permission check
            (HttpMethod::Post, "/organization/has-permission") => Ok(Some(
                handlers::handle_has_permission(req, ctx, &self.config).await?,
            )),
            _ => {
                if let Some(response) =
                    handlers::team::handle_team_request(req, ctx, &self.config).await?
                {
                    return Ok(Some(response));
                }
                handlers::role::handle_role_request(req, ctx, &self.config).await
            }
        }
    }
}

impl std::fmt::Debug for OrganizationPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrganizationPlugin").finish_non_exhaustive()
    }
}
