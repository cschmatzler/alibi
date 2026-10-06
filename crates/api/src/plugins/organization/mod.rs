mod endpoint;
pub mod hooks;
mod native;

pub mod policy;

pub mod extensions;

pub mod handlers;

pub use hooks::invitation::{
    InvitationLimit, OrganizationInvitationContext, OrganizationInvitationCreatePatch,
    OrganizationInvitationCreationContext, OrganizationInvitationDelivery,
    OrganizationInvitationDraft, OrganizationInvitationEmailSender, OrganizationInvitationHooks,
    OrganizationInvitationLimitContext, OrganizationInvitationLimitResolver,
};

pub mod rbac;

pub mod types;

use async_trait::async_trait;
use better_auth_core::error::AuthResult;
use better_auth_core::plugin::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::types::{AuthRequest, AuthResponse, HttpMethod};
pub use extensions::{
    DefaultTeamContext, DefaultTeamFactory, DynamicAccessControlConfig, OrganizationLimitResolver,
    OrganizationTeamHooks, TeamsConfig, default_organization_statements,
};
pub use hooks::invitation::{
    OrganizationInvitationAcceptanceContext, OrganizationInvitationAcceptanceHooks,
    OrganizationInvitationAcceptedContext,
};
pub use hooks::member::{
    OrganizationMemberAddedContext, OrganizationMemberAdditionContext,
    OrganizationMemberAdditionDraft, OrganizationMemberAdditionHooks,
};
pub use hooks::member::{OrganizationMemberRemovalContext, OrganizationMemberRemovalHooks};
pub use hooks::member::{
    OrganizationMemberRoleContext, OrganizationMemberRoleHooks, OrganizationMemberRolePatch,
    OrganizationMemberRoleUpdatedContext,
};
pub use hooks::organization::{
    OrganizationCreatePatch, OrganizationCreatedContext, OrganizationCreationHooks,
    OrganizationDeleteContext, OrganizationDeletionHooks, OrganizationDraftContext,
    OrganizationMemberCreatePatch, OrganizationMemberDraftContext,
};
pub use hooks::organization::{
    OrganizationUpdateContext, OrganizationUpdateHooks, OrganizationUpdateInput,
    OrganizationUpdatePatch, OrganizationUpdatedContext,
};
pub use policy::OrganizationCreationPolicy;
pub use policy::{MembershipLimit, OrganizationMembershipLimitResolver};
use std::collections::HashMap;

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
    /// Input policies for additional organization model fields.
    #[config(default = Default::default(), skip)]
    pub organization_fields: better_auth_core::field_policy::SessionFields,
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
    #[config(default = Some(172_800.0))]
    pub invitation_expires_in: Option<f64>,
    /// Pending admission limit: None uses 100; every numeric value is compared raw.
    #[config(default = Some(InvitationLimit::Fixed(100.0)), skip)]
    pub invitation_limit: Option<InvitationLimit>,
    /// Cancel the first prior pending invitation before later admission checks.
    #[config(default = false)]
    pub cancel_pending_invitations_on_reinvite: bool,
    #[config(default = None, skip)]
    pub invitation_hooks: Option<std::sync::Arc<dyn OrganizationInvitationHooks>>,
    #[config(default = None, skip)]
    pub send_invitation_email: Option<std::sync::Arc<dyn OrganizationInvitationEmailSender>>,
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
            hooks::organization::DeleteInvocation {
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
    fn static_openapi_metadata(&self) -> better_auth_core::PluginOpenApiMetadata {
        crate::metadata::plugin_metadata(
            <Self as better_auth_core::AuthPlugin<S>>::name(self),
            &<Self as better_auth_core::AuthPlugin<S>>::routes(self),
        )
    }

    fn openapi_metadata(
        &self,
        ctx: &better_auth_core::AuthInitContext<S>,
    ) -> better_auth_core::PluginOpenApiMetadata {
        crate::metadata::instance_plugin_metadata(
            <Self as better_auth_core::AuthPlugin<S>>::name(self),
            &<Self as better_auth_core::AuthPlugin<S>>::routes(self),
            ctx,
        )
    }

    fn server_endpoints(&self) -> Vec<better_auth_core::endpoint::EndpointDefinition> {
        endpoint::definitions()
    }
    fn validate_endpoint(
        &self,
        call: &better_auth_core::endpoint::EndpointCall,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<better_auth_core::endpoint::EndpointInput> {
        endpoint::validate(call)
    }
    async fn on_endpoint(
        &self,
        call: &better_auth_core::endpoint::EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<better_auth_core::endpoint::EndpointResponse> {
        self.call_endpoint(call, ctx).await
    }

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
                Box::pin(handlers::org::handle_create_organization(
                    req,
                    ctx,
                    &self.config,
                ))
                .await?,
            )),
            (HttpMethod::Post, "/organization/update") => Ok(Some(
                Box::pin(handlers::org::handle_update_organization(
                    req,
                    ctx,
                    &self.config,
                ))
                .await?,
            )),
            (HttpMethod::Post, "/organization/delete") => Ok(Some(
                Box::pin(handlers::org::handle_delete_organization(
                    req,
                    ctx,
                    &self.config,
                ))
                .await?,
            )),
            (HttpMethod::Get, "/organization/list") => Ok(Some(
                Box::pin(handlers::org::handle_list_organizations(req, ctx)).await?,
            )),
            (HttpMethod::Get, "/organization/get-organization") => Ok(Some(
                Box::pin(handlers::org::handle_get_organization(req, ctx)).await?,
            )),
            (HttpMethod::Get, "/organization/get-full-organization") => Ok(Some(
                Box::pin(handlers::org::handle_get_full_organization(
                    req,
                    ctx,
                    &self.config,
                ))
                .await?,
            )),
            (HttpMethod::Post, "/organization/check-slug") => Ok(Some(
                Box::pin(handlers::org::handle_check_slug(req, ctx)).await?,
            )),
            (HttpMethod::Post, "/organization/set-active") => Ok(Some(
                Box::pin(handlers::org::handle_set_active_organization(req, ctx)).await?,
            )),
            (HttpMethod::Post, "/organization/leave") => Ok(Some(
                Box::pin(handlers::org::handle_leave_organization(
                    req,
                    ctx,
                    &self.config,
                ))
                .await?,
            )),
            // Member management
            (HttpMethod::Get, "/organization/get-active-member") => Ok(Some(
                Box::pin(handlers::member::handle_get_active_member(req, ctx)).await?,
            )),
            (HttpMethod::Get, "/organization/get-active-member-role") => Ok(Some(
                Box::pin(handlers::member::handle_get_active_member_role(req, ctx)).await?,
            )),
            (HttpMethod::Get, "/organization/list-members") => Ok(Some(
                Box::pin(handlers::member::handle_list_members(
                    req,
                    ctx,
                    &self.config,
                ))
                .await?,
            )),
            (HttpMethod::Post, "/organization/remove-member") => Ok(Some(
                Box::pin(handlers::member::handle_remove_member(
                    req,
                    ctx,
                    &self.config,
                ))
                .await?,
            )),
            (HttpMethod::Post, "/organization/update-member-role") => Ok(Some(
                Box::pin(handlers::member::handle_update_member_role(
                    req,
                    ctx,
                    &self.config,
                ))
                .await?,
            )),
            // Invitations
            (HttpMethod::Post, "/organization/invite-member") => Ok(Some(
                Box::pin(handlers::invitation::handle_invite_member(
                    req,
                    ctx,
                    &self.config,
                ))
                .await?,
            )),
            (HttpMethod::Get, "/organization/get-invitation") => Ok(Some(
                Box::pin(handlers::invitation::handle_get_invitation(
                    req,
                    ctx,
                    &self.config,
                ))
                .await?,
            )),
            (HttpMethod::Get, "/organization/list-invitations") => Ok(Some(
                Box::pin(handlers::invitation::handle_list_invitations(req, ctx)).await?,
            )),
            (HttpMethod::Get, "/organization/list-user-invitations") => Ok(Some(
                Box::pin(handlers::invitation::handle_list_user_invitations(req, ctx)).await?,
            )),
            (HttpMethod::Post, "/organization/accept-invitation") => Ok(Some(
                Box::pin(handlers::invitation::handle_accept_invitation(
                    req,
                    ctx,
                    &self.config,
                ))
                .await?,
            )),
            (HttpMethod::Post, "/organization/reject-invitation") => Ok(Some(
                Box::pin(handlers::invitation::handle_reject_invitation(
                    req,
                    ctx,
                    &self.config,
                ))
                .await?,
            )),
            (HttpMethod::Post, "/organization/cancel-invitation") => Ok(Some(
                Box::pin(handlers::invitation::handle_cancel_invitation(
                    req,
                    ctx,
                    &self.config,
                ))
                .await?,
            )),
            // Permission check
            (HttpMethod::Post, "/organization/has-permission") => Ok(Some(
                Box::pin(handlers::handle_has_permission(req, ctx, &self.config)).await?,
            )),
            _ => {
                if let Some(response) =
                    Box::pin(handlers::team::handle_team_request(req, ctx, &self.config)).await?
                {
                    return Ok(Some(response));
                }
                Box::pin(handlers::role::handle_role_request(req, ctx, &self.config)).await
            }
        }
    }
}

impl std::fmt::Debug for OrganizationPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrganizationPlugin").finish_non_exhaustive()
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod extension_tests {
    use super::*;
    use crate::plugins::test_helpers::{create_test_config, create_user_and_session};
    use better_auth_core::types::{CreateMember, CreateTeam, Team, TeamMember};
    use better_auth_core::wire::{SessionView, UserView};
    use better_auth_core::{AuthError, AuthInitContext, AuthSession, CreateUser};
    use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    use chrono::Duration;
    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[derive(Debug)]
    struct RequestTeamLimits;

    #[async_trait]
    impl OrganizationLimitResolver for RequestTeamLimits {
        async fn maximum_teams(
            &self,
            context: &extensions::TeamLimitContext,
        ) -> AuthResult<Option<f64>> {
            let authenticated = context
                .user
                .as_ref()
                .zip(context.session.as_ref())
                .is_some_and(|(user, session)| {
                    user.id == session.user_id && user.name.as_deref() == Some("limit-owner")
                });
            let expanded = context
                .request
                .as_ref()
                .and_then(|request| request.header("x-team-policy").map(String::as_str))
                == Some("expanded");
            Ok(Some(if authenticated && expanded { 3.0 } else { 1.0 }))
        }

        async fn maximum_team_members(
            &self,
            context: &extensions::TeamLimitContext,
        ) -> AuthResult<Option<f64>> {
            let authenticated = context
                .user
                .as_ref()
                .zip(context.session.as_ref())
                .is_some_and(|(user, session)| {
                    user.id == session.user_id && user.name.as_deref() == Some("limit-owner")
                });
            Ok(Some(f64::from(authenticated && context.team_id.is_some())))
        }
    }

    #[derive(Debug)]
    struct LifecycleHooks {
        events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl LifecycleHooks {
        fn record(&self, name: &str) -> AuthResult<()> {
            self.events
                .lock()
                .map_err(|_error| AuthError::internal("Hook event lock poisoned"))?
                .push(name.to_owned());
            Ok(())
        }
    }

    #[async_trait]
    impl OrganizationTeamHooks for LifecycleHooks {
        async fn before_create(
            &self,
            data: &mut CreateTeam,
            _context: &extensions::TeamHookContext,
        ) -> AuthResult<()> {
            self.record("before-create")?;
            data.name = format!("hook:{}", data.name);
            Ok(())
        }
        async fn after_create(
            &self,
            _team: &Team,
            _context: &extensions::TeamHookContext,
        ) -> AuthResult<()> {
            self.record("after-create")
        }
        async fn before_update(
            &self,
            _team: &Team,
            update: &mut better_auth_core::types::UpdateTeam,
            _context: &extensions::TeamHookContext,
        ) -> AuthResult<()> {
            self.record("before-update")?;
            update.name = update.name.take().map(|name| format!("updated:{name}"));
            Ok(())
        }
        async fn after_update(
            &self,
            _team: &Team,
            _context: &extensions::TeamHookContext,
        ) -> AuthResult<()> {
            self.record("after-update")
        }
        async fn before_add_member(
            &self,
            _team: &Team,
            user: &UserView,
            _context: &extensions::TeamHookContext,
        ) -> AuthResult<()> {
            self.record("before-add")?;
            if user.email.as_deref() == Some("hook-denied@example.com") {
                return Err(AuthError::forbidden("Callback refused team membership"));
            }
            Ok(())
        }
        async fn after_add_member(
            &self,
            _member: &TeamMember,
            _team: &Team,
            _user: &UserView,
            _context: &extensions::TeamHookContext,
        ) -> AuthResult<()> {
            self.record("after-add")
        }
        async fn before_remove_member(
            &self,
            _member: &TeamMember,
            _team: &Team,
            _user: &UserView,
            _context: &extensions::TeamHookContext,
        ) -> AuthResult<()> {
            self.record("before-remove")
        }
        async fn after_remove_member(
            &self,
            _member: &TeamMember,
            _team: &Team,
            _user: &UserView,
            _context: &extensions::TeamHookContext,
        ) -> AuthResult<()> {
            self.record("after-remove")
        }
        async fn before_delete(
            &self,
            _team: &Team,
            _context: &extensions::TeamHookContext,
        ) -> AuthResult<()> {
            self.record("before-delete")
        }
        async fn after_delete(
            &self,
            _team: &Team,
            _context: &extensions::TeamHookContext,
        ) -> AuthResult<()> {
            self.record("after-delete")
        }
    }

    #[derive(Debug)]
    struct CustomDefaultTeam;

    #[async_trait]
    impl DefaultTeamFactory for CustomDefaultTeam {
        async fn create(
            &self,
            organization: &better_auth_core::types::Organization,
            context: &DefaultTeamContext,
            store: &dyn better_auth_core::store::TeamStore,
        ) -> AuthResult<Option<Team>> {
            let request = context.request.as_ref().ok_or_else(|| {
                AuthError::bad_request(
                    "Default team callback did not receive the organization request",
                )
            })?;
            if context
                .session
                .as_ref()
                .map(|session| session.user_id.as_str())
                != Some(context.user.id.as_str())
            {
                return Err(AuthError::bad_request(
                    "Factory did not receive the authenticated principal",
                ));
            }
            if context.config.base_path != "/api/auth" {
                return Err(AuthError::bad_request(
                    "Factory did not receive the configured base path",
                ));
            }
            if request.path() != "/organization/create" {
                return Err(AuthError::bad_request("Unexpected default team request"));
            }
            store
                .create_team(CreateTeam {
                    name: format!("Factory:{}", organization.name),
                    organization_id: organization.id.clone(),
                    updated_at: None,
                })
                .await
                .map(Some)
        }
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn asynchronous_team_limits_use_the_actual_request_and_session_principal() -> TestResult {
        let plugin = OrganizationPlugin::with_config(OrganizationConfig {
            teams: TeamsConfig {
                enabled: true,
                maximum_teams: Some(99.0),
                maximum_members_per_team: Some(99.0),
                limit_resolver: Some(std::sync::Arc::new(RequestTeamLimits)),
                ..Default::default()
            },
            ..Default::default()
        });
        let ctx = context(&plugin).await?;
        let (_, owner_session) = actor(&ctx, "limit-owner").await;
        let created = call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/create",
            Some(json!({"name":"Limited","slug":"native-async-limits"})),
            &[],
        )
        .await?;
        let organization: Value = body(&created)?;
        let organization_id = id(&organization)?;
        assert_eq!(ctx.database.list_teams(organization_id).await?.len(), 1);
        for (name, expanded, expected) in [
            ("Default denied", false, 400),
            ("Expanded first", true, 200),
            ("Expanded second", true, 200),
            ("Expanded full", true, 400),
        ] {
            let mut request = AuthRequest::new(HttpMethod::Post, "/organization/create-team");
            let cookie = better_auth_core::utils::cookie_utils::create_session_cookie(
                &owner_session.token,
                &ctx.config,
            )
            .unwrap();
            request.headers.insert(
                "cookie".to_owned(),
                cookie
                    .split(';')
                    .next()
                    .ok_or("Session cookie pair missing")?
                    .to_owned(),
            );
            if expanded {
                request
                    .headers
                    .insert("x-team-policy".to_owned(), "expanded".to_owned());
            }
            request.body = Some(serde_json::to_vec(
                &json!({"organizationId":organization_id,"name":name}),
            )?);
            let response = match plugin.on_request(&request, &ctx).await {
                Ok(Some(response)) => response,
                Ok(None) => return Err("Team route was not handled".into()),
                Err(error) => error.to_auth_response(),
            };
            assert_eq!(response.status, expected);
            if expected == 400 {
                assert_error(
                    &response,
                    400,
                    "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS",
                )?;
            }
        }
        let teams = ctx.database.list_teams(organization_id).await?;
        assert_eq!(teams.len(), 3);
        let team = teams
            .iter()
            .find(|team| team.name == "Expanded first")
            .ok_or("Allowed team was not persisted")?;
        let (first, _) = actor(&ctx, "limit-first").await;
        let (second, _) = actor(&ctx, "limit-second").await;
        for user in [&first, &second] {
            ctx.database
                .create_member(CreateMember {
                    organization_id: organization_id.to_owned(),
                    user_id: user.id.clone(),
                    role: "member".to_owned(),
                })
                .await?;
        }
        let added = call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/add-team-member",
            Some(json!({"organizationId":organization_id,"teamId":team.id,"userId":first.id})),
            &[],
        )
        .await?;
        assert_eq!(added.status, 200);
        assert_error(
            &call(
                &plugin,
                &ctx,
                Some(&owner_session.token),
                HttpMethod::Post,
                "/organization/add-team-member",
                Some(json!({"organizationId":organization_id,"teamId":team.id,"userId":second.id})),
                &[],
            )
            .await?,
            403,
            "TEAM_MEMBER_LIMIT_REACHED",
        )?;
        let members = ctx.database.list_team_members(&team.id).await?;
        assert_eq!(members.len(), 1);
        assert_eq!(
            (members)
                .first()
                .expect("fixture contains the requested index")
                .user_id,
            first.id
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn team_member_requests_coerce_custom_user_ids_and_keep_permission_and_tenant_guards()
    -> TestResult {
        let plugin = OrganizationPlugin::with_config(configuration());
        let ctx = context(&plugin).await?;
        let (owner, owner_session) = actor(&ctx, "coercion-owner").await;
        let organization = ctx
            .database
            .create_organization(better_auth_core::types::CreateOrganization::new(
                "Custom IDs",
                "native-coercion",
            ))
            .await?;
        ctx.database
            .create_member(CreateMember {
                organization_id: organization.id.clone(),
                user_id: owner.id.clone(),
                role: "owner".to_owned(),
            })
            .await?;
        let team = plugin
            .create_team(
                &ctx,
                CreateTeam {
                    organization_id: organization.id.clone(),
                    name: "Custom ID team".to_owned(),
                    updated_at: None,
                },
            )
            .await?;
        let other_org = ctx
            .database
            .create_organization(better_auth_core::types::CreateOrganization::new(
                "Other tenant",
                "native-coercion-other",
            ))
            .await?;
        let other_team = plugin
            .create_team(
                &ctx,
                CreateTeam {
                    organization_id: other_org.id,
                    name: "Other team".to_owned(),
                    updated_at: None,
                },
            )
            .await?;
        for (index, (input, expected_id)) in [
            (Some(json!(42)), "42"),
            (Some(json!(1.0)), "1"),
            (Some(json!(1e21)), "1e+21"),
            (Some(json!(9_007_199_254_740_993_u64)), "9007199254740992"),
            (Some(json!(true)), "true"),
            (Some(Value::Null), "null"),
            (
                Some(json!(["42", null, {"key":"value"}])),
                "42,,[object Object]",
            ),
            (Some(json!({"key":"value"})), "[object Object]"),
            (None, "undefined"),
        ]
        .into_iter()
        .enumerate()
        {
            let (target, target_session) = create_user_and_session(
                &ctx,
                CreateUser {
                    id: Some(expected_id.to_owned()),
                    email: Some(format!("coercion-{index}@example.com")),
                    ..Default::default()
                },
                Duration::hours(1),
            )
            .await;
            ctx.database
                .create_member(CreateMember {
                    organization_id: organization.id.clone(),
                    user_id: target.id.clone(),
                    role: "member".to_owned(),
                })
                .await?;
            let mut request = json!({"organizationId":organization.id,"teamId":team.id});
            if let Some(input) = input {
                drop(
                    request
                        .as_object_mut()
                        .expect("request is an object")
                        .insert("userId".to_owned(), input),
                );
            }
            let added = call(
                &plugin,
                &ctx,
                Some(&owner_session.token),
                HttpMethod::Post,
                "/organization/add-team-member",
                Some(request.clone()),
                &[],
            )
            .await?;
            assert_eq!(added.status, 200, "add-member must coerce {expected_id}");
            let added: TeamMember = body(&added)?;
            assert_eq!(added.user_id, expected_id);
            let persisted = ctx.database.list_team_members(&team.id).await?;
            assert_eq!(persisted.len(), 1);
            assert_eq!(
                (persisted)
                    .first()
                    .expect("fixture contains the requested index")
                    .id,
                added.id
            );
            assert_eq!(
                (persisted)
                    .first()
                    .expect("fixture contains the requested index")
                    .user_id,
                expected_id
            );
            if expected_id == "42" {
                assert_error(
                    &call(
                        &plugin,
                        &ctx,
                        Some(&target_session.token),
                        HttpMethod::Post,
                        "/organization/add-team-member",
                        Some(request.clone()),
                        &[],
                    )
                    .await?,
                    403,
                    "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER",
                )?;
                assert_error(
                    &call(
                        &plugin,
                        &ctx,
                        Some(&target_session.token),
                        HttpMethod::Post,
                        "/organization/remove-team-member",
                        Some(request.clone()),
                        &[],
                    )
                    .await?,
                    403,
                    "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER",
                )?;
                let mut wrong_tenant = request.clone();
                drop(
                    wrong_tenant
                        .as_object_mut()
                        .expect("request is an object")
                        .insert("teamId".to_owned(), json!(other_team.id)),
                );
                assert_error(
                    &call(
                        &plugin,
                        &ctx,
                        Some(&owner_session.token),
                        HttpMethod::Post,
                        "/organization/add-team-member",
                        Some(wrong_tenant),
                        &[],
                    )
                    .await?,
                    400,
                    "TEAM_NOT_FOUND",
                )?;
                assert_eq!(ctx.database.list_team_members(&team.id).await?.len(), 1);
                assert!(
                    ctx.database
                        .list_team_members(&other_team.id)
                        .await?
                        .is_empty()
                );
            }
            let removed = call(
                &plugin,
                &ctx,
                Some(&owner_session.token),
                HttpMethod::Post,
                "/organization/remove-team-member",
                Some(request),
                &[],
            )
            .await?;
            assert_eq!(removed.status, 200);
            assert!(ctx.database.list_team_members(&team.id).await?.is_empty());
        }
        Ok(())
    }

    fn configuration() -> OrganizationConfig {
        OrganizationConfig {
            teams: TeamsConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    async fn context(plugin: &OrganizationPlugin) -> AuthResult<AuthContext<BundledSchema>> {
        configured_context(plugin, create_test_config()).await
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn configured_context(
        plugin: &OrganizationPlugin,
        config: better_auth_core::AuthConfig,
    ) -> AuthResult<AuthContext<BundledSchema>> {
        configured_context_with_connection(plugin, config)
            .await
            .map(|(context, _)| context)
    }

    async fn configured_context_with_connection(
        plugin: &OrganizationPlugin,
        config: better_auth_core::AuthConfig,
    ) -> AuthResult<(
        AuthContext<BundledSchema>,
        better_auth_seaorm::DatabaseConnection,
    )> {
        let database = better_auth_seaorm::Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let config = std::sync::Arc::new(config);
        let store = std::sync::Arc::new(better_auth_seaorm::SeaOrmStore::<BundledSchema>::new(
            std::sync::Arc::clone(&config),
            database.clone(),
        ));
        let mut ctx = AuthContext::new(config, store);
        let mut init = AuthInitContext::new(
            std::sync::Arc::clone(&ctx.config),
            std::sync::Arc::clone(&ctx.database),
        );
        plugin.on_init(&mut init).await?;
        let parts = init.into_parts();
        ctx.metadata = parts.metadata;
        Ok((ctx, database))
    }

    pub(super) async fn actor(
        ctx: &AuthContext<BundledSchema>,
        name: &str,
    ) -> (UserView, SessionView) {
        create_user_and_session(
            ctx,
            CreateUser {
                email: Some(format!("{name}@example.com")),
                name: Some(name.to_owned()),
                email_verified: Some(true),
                ..Default::default()
            },
            Duration::hours(1),
        )
        .await
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) async fn call(
        plugin: &OrganizationPlugin,
        ctx: &AuthContext<BundledSchema>,
        token: Option<&str>,
        method: HttpMethod,
        path: &str,
        body: Option<Value>,
        query: &[(&str, &str)],
    ) -> AuthResult<AuthResponse> {
        let mut req = AuthRequest::new(method, path);
        if let Some(token) = token {
            let cookie =
                better_auth_core::utils::cookie_utils::create_session_cookie(token, &ctx.config)
                    .unwrap();
            let pair = cookie
                .split(';')
                .next()
                .ok_or_else(|| AuthError::internal("Session cookie missing pair"))?;
            drop(req.headers.insert("cookie".to_owned(), pair.to_owned()));
        }
        for (key, value) in query {
            drop(req.query.insert((*key).to_owned(), (*value).to_owned()));
        }
        if let Some(body) = body {
            req.body = Some(serde_json::to_vec(&body)?);
            drop(
                req.headers
                    .insert("content-type".to_owned(), "application/json".to_owned()),
            );
        }
        match plugin.on_request(&req, ctx).await {
            Ok(Some(response)) => Ok(response),
            Ok(None) => Err(AuthError::internal("Organization route was not handled")),
            Err(error) => Ok(error.to_auth_response()),
        }
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) fn body<T: DeserializeOwned>(
        response: &AuthResponse,
    ) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&response.body)
    }

    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) fn id(value: &Value) -> Result<&str, std::io::Error> {
        value
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| std::io::Error::other("Response is missing ID"))
    }

    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(super) fn assert_error(response: &AuthResponse, status: u16, code: &str) -> TestResult {
        assert_eq!(response.status, status);
        assert_eq!(
            body::<Value>(response)?.get("code").and_then(Value::as_str),
            Some(code)
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn team_routes_enforce_principal_membership_scope_and_persist_session_changes()
    -> TestResult {
        let plugin = OrganizationPlugin::with_config(configuration());
        let ctx = context(&plugin).await?;
        let (owner, owner_session) = actor(&ctx, "team-owner").await;
        let (member, member_session) = actor(&ctx, "team-member").await;
        let (stranger, stranger_session) = actor(&ctx, "team-stranger").await;
        let created = call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/create",
            Some(json!({"name":"Teams", "slug":"native-teams"})),
            &[],
        )
        .await?;
        assert_eq!(created.status, 200);
        let organization: Value = body(&created)?;
        let org_id = id(&organization)?;
        assert!(organization.get("teams").is_none());
        let defaults = ctx.database.list_teams(org_id).await?;
        let default_team = defaults
            .first()
            .ok_or_else(|| std::io::Error::other("Default team not created"))?;
        assert_eq!(defaults.len(), 1);
        assert_eq!(default_team.name, "Teams");
        assert!(default_team.updated_at.is_none());
        assert!(
            ctx.database
                .get_team_member(&default_team.id, &owner.id)
                .await?
                .is_some()
        );
        let persisted = ctx
            .database
            .get_session(&owner_session.token)
            .await?
            .ok_or_else(|| std::io::Error::other("Owner session missing"))?;
        assert_eq!(persisted.active_team_id(), Some(default_team.id.as_str()));
        drop(
            ctx.database
                .create_member(CreateMember::new(org_id, &member.id, "member"))
                .await?,
        );
        drop(
            ctx.database
                .update_session_active_organization(&member_session.token, Some(org_id))
                .await?,
        );

        assert_error(
            &call(
                &plugin,
                &ctx,
                None,
                HttpMethod::Post,
                "/organization/create-team",
                Some(json!({"name":"Unauthenticated", "organizationId":org_id})),
                &[],
            )
            .await?,
            401,
            "UNAUTHORIZED",
        )?;
        assert_error(
            &call(
                &plugin,
                &ctx,
                Some(&member_session.token),
                HttpMethod::Post,
                "/organization/create-team",
                Some(json!({"name":"Forbidden"})),
                &[],
            )
            .await?,
            403,
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
        )?;
        assert_error(
            &call(
                &plugin,
                &ctx,
                Some(&stranger_session.token),
                HttpMethod::Get,
                "/organization/list-teams",
                None,
                &[("organizationId", org_id)],
            )
            .await?,
            403,
            "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION",
        )?;

        let created_team = call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/create-team",
            Some(json!({"name":"Engineering"})),
            &[],
        )
        .await?;
        assert_eq!(created_team.status, 200);
        let team: Team = body(&created_team)?;
        assert_eq!(team.organization_id, org_id);
        assert_eq!(team.updated_at, Some(team.created_at));
        let updated = call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/update-team",
            Some(json!({"teamId":team.id,"data":{"name":"Platform"}})),
            &[],
        )
        .await?;
        assert_eq!(updated.status, 200);
        assert_eq!(body::<Team>(&updated)?.name, "Platform");
        assert_eq!(
            ctx.database
                .get_team(Some(org_id), &team.id)
                .await?
                .map(|row| row.name),
            Some("Platform".to_owned())
        );
        assert_error(
            &call(
                &plugin,
                &ctx,
                Some(&owner_session.token),
                HttpMethod::Post,
                "/organization/add-team-member",
                Some(json!({"teamId":team.id,"userId":stranger.id})),
                &[],
            )
            .await?,
            400,
            "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
        )?;
        let added = call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/add-team-member",
            Some(json!({"teamId":team.id,"userId":member.id})),
            &[],
        )
        .await?;
        assert_eq!(added.status, 200);
        let membership: TeamMember = body(&added)?;
        assert_eq!(membership.user_id, member.id);
        assert_eq!(membership.team_id, team.id);
        let active = call(
            &plugin,
            &ctx,
            Some(&member_session.token),
            HttpMethod::Post,
            "/organization/set-active-team",
            Some(json!({"teamId":team.id})),
            &[],
        )
        .await?;
        assert_eq!(active.status, 200);
        assert!(active.headers.get("set-cookie").is_some());
        let persisted_2 = ctx
            .database
            .get_session(&member_session.token)
            .await?
            .ok_or_else(|| std::io::Error::other("Member session missing"))?;
        assert_eq!(persisted_2.active_team_id(), Some(team.id.as_str()));
        assert_eq!(persisted_2.token(), member_session.token);
        let listed = call(
            &plugin,
            &ctx,
            Some(&member_session.token),
            HttpMethod::Get,
            "/organization/list-team-members",
            None,
            &[],
        )
        .await?;
        assert_eq!(listed.status, 200);
        let rows: Vec<TeamMember> = body(&listed)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows.first().map(|row| row.id.as_str()),
            Some(membership.id.as_str())
        );
        let own_teams = call(
            &plugin,
            &ctx,
            Some(&member_session.token),
            HttpMethod::Get,
            "/organization/list-user-teams",
            None,
            &[],
        )
        .await?;
        assert_eq!(body::<Vec<Team>>(&own_teams)?.len(), 1);
        let other_teams = call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Get,
            "/organization/list-user-teams",
            None,
            &[("userId", &member.id), ("organizationId", org_id)],
        )
        .await?;
        assert_eq!(
            body::<Vec<Team>>(&other_teams)?
                .first()
                .map(|row| row.id.as_str()),
            Some(team.id.as_str())
        );
        assert_error(
            &call(
                &plugin,
                &ctx,
                Some(&member_session.token),
                HttpMethod::Get,
                "/organization/list-user-teams",
                None,
                &[("userId", &owner.id), ("organizationId", org_id)],
            )
            .await?,
            403,
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
        )?;
        let clear = call(
            &plugin,
            &ctx,
            Some(&member_session.token),
            HttpMethod::Post,
            "/organization/set-active-team",
            Some(json!({"teamId":null})),
            &[],
        )
        .await?;
        assert_eq!(body::<Value>(&clear)?, Value::Null);
        assert!(
            ctx.database
                .get_session(&member_session.token)
                .await?
                .is_some_and(|row| row.active_team_id().is_none())
        );
        let removed = call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/remove-team-member",
            Some(json!({"teamId":team.id,"userId":member.id})),
            &[],
        )
        .await?;
        assert_eq!(removed.status, 200);
        assert!(
            ctx.database
                .get_team_member(&team.id, &member.id)
                .await?
                .is_none()
        );
        let deleted = call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/remove-team",
            Some(json!({"teamId":team.id})),
            &[],
        )
        .await?;
        assert_eq!(deleted.status, 200);
        assert!(
            ctx.database
                .get_team(Some(org_id), &team.id)
                .await?
                .is_none()
        );
        assert_error(
            &call(
                &plugin,
                &ctx,
                Some(&owner_session.token),
                HttpMethod::Post,
                "/organization/remove-team",
                Some(json!({"teamId":default_team.id})),
                &[],
            )
            .await?,
            403,
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM",
        )?;
        drop(
            call(
                &plugin,
                &ctx,
                Some(&owner_session.token),
                HttpMethod::Post,
                "/organization/set-active-team",
                Some(json!({"teamId":null})),
                &[],
            )
            .await?,
        );
        assert_error(
            &call(
                &plugin,
                &ctx,
                Some(&owner_session.token),
                HttpMethod::Post,
                "/organization/remove-team",
                Some(json!({"teamId":default_team.id})),
                &[],
            )
            .await?,
            400,
            "UNABLE_TO_REMOVE_LAST_TEAM",
        )?;
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn lifecycle_hooks_change_persisted_team_data_and_veto_membership_before_writing()
    -> TestResult {
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let plugin = OrganizationPlugin::with_config(OrganizationConfig {
            teams: TeamsConfig {
                enabled: true,
                hooks: Some(std::sync::Arc::new(LifecycleHooks {
                    events: std::sync::Arc::clone(&events),
                })),
                ..Default::default()
            },
            ..Default::default()
        });
        let ctx = context(&plugin).await?;
        let (owner, session) = actor(&ctx, "hook-owner").await;
        let (denied, _) = actor(&ctx, "hook-denied").await;
        let created = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/create",
            Some(json!({"name":"Callbacks","slug":"native-callbacks"})),
            &[],
        )
        .await?;
        let created: Value = body(&created)?;
        let org_id = id(&created)?;
        assert_eq!(
            ctx.database
                .list_teams(org_id)
                .await?
                .first()
                .map(|team| team.name.as_str()),
            Some("hook:Callbacks")
        );
        drop(
            ctx.database
                .create_member(CreateMember::new(org_id, &denied.id, "member"))
                .await?,
        );
        let created_2 = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/create-team",
            Some(json!({"name":"Custom"})),
            &[],
        )
        .await?;
        let team: Team = body(&created_2)?;
        assert_eq!(team.name, "hook:Custom");
        let updated = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/update-team",
            Some(json!({"teamId":team.id,"data":{"name":"Changed"}})),
            &[],
        )
        .await?;
        assert_eq!(body::<Team>(&updated)?.name, "updated:Changed");
        assert_eq!(
            ctx.database
                .get_team(Some(org_id), &team.id)
                .await?
                .map(|team| team.name),
            Some("updated:Changed".to_owned())
        );
        let refused = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/add-team-member",
            Some(json!({"teamId":team.id,"userId":denied.id})),
            &[],
        )
        .await?;
        assert_eq!(refused.status, 403);
        assert!(
            ctx.database
                .get_team_member(&team.id, &denied.id)
                .await?
                .is_none()
        );
        let admitted = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/add-team-member",
            Some(json!({"teamId":team.id,"userId":owner.id})),
            &[],
        )
        .await?;
        assert_eq!(admitted.status, 200);
        let removed = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/remove-team-member",
            Some(json!({"teamId":team.id,"userId":owner.id})),
            &[],
        )
        .await?;
        assert_eq!(removed.status, 200);
        let deleted = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/remove-team",
            Some(json!({"teamId":team.id})),
            &[],
        )
        .await?;
        assert_eq!(deleted.status, 200);
        assert!(ctx.database.get_team(None, &team.id).await?.is_none());
        assert_eq!(
            *events
                .lock()
                .map_err(|_error| std::io::Error::other("Hook event lock poisoned"))?,
            vec![
                "before-create",
                "after-create",
                "before-create",
                "after-create",
                "before-update",
                "after-update",
                "before-add",
                "before-add",
                "after-add",
                "before-remove",
                "after-remove",
                "before-delete",
                "after-delete"
            ]
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn default_team_factory_receives_request_and_its_persisted_team_becomes_active()
    -> TestResult {
        use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};

        let plugin = OrganizationPlugin::with_config(OrganizationConfig {
            teams: TeamsConfig {
                enabled: true,
                default_team_factory: Some(std::sync::Arc::new(CustomDefaultTeam)),
                ..Default::default()
            },
            ..Default::default()
        });
        let mut config = create_test_config();
        config.session.update_age = None;
        let (ctx, database) = configured_context_with_connection(&plugin, config).await?;
        let (owner, session) = actor(&ctx, "factory-owner").await;
        // Refresh-on-every-access must still refresh only once for one authenticated
        // request. A real database trigger records expiry writes, while the factory
        // receives the session already read by the handler.
        for statement in [
            "CREATE TABLE session_refresh_audit (refreshes INTEGER NOT NULL)",
            "INSERT INTO session_refresh_audit (refreshes) VALUES (0)",
            "CREATE TRIGGER record_session_refresh AFTER UPDATE OF expires_at ON sessions BEGIN UPDATE session_refresh_audit SET refreshes = refreshes + 1; END",
        ] {
            database
                .execute_raw(Statement::from_string(DbBackend::Sqlite, statement))
                .await?;
        }
        let response = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/create",
            Some(json!({"name":"FactoryOrg","slug":"native-factory"})),
            &[],
        )
        .await?;
        assert_eq!(response.status, 200);
        let refreshes: i64 = database
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT refreshes FROM session_refresh_audit",
            ))
            .await?
            .ok_or("Refresh audit row missing")?
            .try_get("", "refreshes")?;
        assert_eq!(refreshes, 1, "One request must refresh the session once");
        let organization: Value = body(&response)?;
        let teams = ctx.database.list_teams(id(&organization)?).await?;
        assert_eq!(teams.len(), 1);
        let team = teams
            .first()
            .ok_or_else(|| std::io::Error::other("Factory returned no team"))?;
        assert_eq!(team.name, "Factory:FactoryOrg");
        assert!(
            ctx.database
                .get_team_member(&team.id, &owner.id)
                .await?
                .is_some()
        );
        assert_eq!(
            ctx.database
                .get_session(&session.token)
                .await?
                .and_then(|session| session.active_team_id),
            Some(team.id.clone())
        );
        let kept = call(&plugin, &ctx, Some(&session.token), HttpMethod::Post, "/organization/create", Some(json!({"name":"KeptFactory","slug":"native-factory-kept","keepCurrentActiveOrganization":true})), &[]).await?;
        assert_eq!(kept.status, 200);
        let kept: Value = body(&kept)?;
        let refreshes_2: i64 = database
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT refreshes FROM session_refresh_audit",
            ))
            .await?
            .ok_or("Refresh audit row missing")?
            .try_get("", "refreshes")?;
        assert_eq!(
            refreshes_2, 2,
            "Two requests must refresh the session twice"
        );
        let kept_teams = ctx.database.list_teams(id(&kept)?).await?;
        assert_eq!(kept_teams.len(), 1);
        assert_eq!(
            (kept_teams)
                .first()
                .expect("fixture contains the requested index")
                .name,
            "Factory:KeptFactory"
        );
        assert!(
            ctx.database
                .get_team_member(
                    &(kept_teams)
                        .first()
                        .expect("fixture contains the requested index")
                        .id,
                    &owner.id
                )
                .await?
                .is_some()
        );
        let preserved = ctx
            .database
            .get_session(&session.token)
            .await?
            .ok_or("Session must remain active")?;
        assert_eq!(preserved.active_organization_id(), Some(id(&organization)?));
        assert_eq!(preserved.active_team_id(), Some(team.id.as_str()));

        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn configured_team_limits_apply_to_server_and_http_creation() -> TestResult {
        let plugin = OrganizationPlugin::with_config(OrganizationConfig {
            teams: TeamsConfig {
                enabled: true,
                create_default_team: false,
                maximum_teams: Some(1.0),
                maximum_members_per_team: Some(1.0),
                ..Default::default()
            },
            ..Default::default()
        });
        let mut config = create_test_config();
        config.advanced.database.default_find_many_limit = 1;
        let ctx = configured_context(&plugin, config).await?;
        let (owner, session) = actor(&ctx, "limited-owner").await;
        let (_, target_session) = actor(&ctx, "limited-target").await;
        let created = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/create",
            Some(json!({"name":"Limits","slug":"native-limits"})),
            &[],
        )
        .await?;
        let organization: Value = body(&created)?;
        let org_id = id(&organization)?;
        assert!(ctx.database.list_teams(org_id).await?.is_empty());
        let team = plugin
            .create_team(
                &ctx,
                CreateTeam {
                    name: "Server team".to_owned(),
                    organization_id: org_id.to_owned(),
                    updated_at: Some(chrono::Utc::now()),
                },
            )
            .await?;
        assert_error(
            &call(
                &plugin,
                &ctx,
                Some(&session.token),
                HttpMethod::Post,
                "/organization/create-team",
                Some(json!({"name":"Second"})),
                &[],
            )
            .await?,
            400,
            "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS",
        )?;
        drop(
            ctx.database
                .create_member(CreateMember::new(org_id, &target_session.user_id, "member"))
                .await?,
        );
        let added = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/add-team-member",
            Some(json!({"teamId":team.id,"userId":owner.id})),
            &[],
        )
        .await?;
        assert_eq!(added.status, 200);
        assert_error(
            &call(
                &plugin,
                &ctx,
                Some(&session.token),
                HttpMethod::Post,
                "/organization/add-team-member",
                Some(json!({"teamId":team.id,"userId":target_session.user_id})),
                &[],
            )
            .await?,
            403,
            "TEAM_MEMBER_LIMIT_REACHED",
        )?;
        assert!(plugin.remove_team(&ctx, org_id, &team.id).await.is_err());
        let allowed = OrganizationPlugin::with_config(OrganizationConfig {
            teams: TeamsConfig {
                enabled: true,
                allow_removing_all_teams: true,
                ..Default::default()
            },
            ..Default::default()
        });
        allowed.remove_team(&ctx, org_id, &team.id).await?;
        assert!(ctx.database.list_teams(org_id).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn custom_role_configuration_replaces_defaults_and_whole_permission_checks_do_not_union_roles()
    -> TestResult {
        let plugin = OrganizationPlugin::with_config(OrganizationConfig {
            roles: Some(HashMap::from([
                (
                    "delegate".to_owned(),
                    RolePermissions {
                        team: vec!["create".to_owned()],
                        ac: vec!["create".to_owned(), "read".to_owned()],
                        ..Default::default()
                    },
                ),
                (
                    "member-editor".to_owned(),
                    RolePermissions {
                        member: vec!["update".to_owned()],
                        ..Default::default()
                    },
                ),
            ])),
            ..configuration()
        });
        let ctx = context(&plugin).await?;
        let (_, session) = actor(&ctx, "custom-role-owner").await;
        let created = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/create",
            Some(json!({"name":"Custom roles","slug":"native-custom-roles"})),
            &[],
        )
        .await?;
        let created: Value = body(&created)?;
        let _org_id = id(&created)?;
        let member_id = created
            .get("members")
            .and_then(Value::as_array)
            .and_then(|rows| rows.first())
            .and_then(|member| member.get("id"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                std::io::Error::other("Created organization has no creator membership")
            })?;
        assert_error(
            &call(
                &plugin,
                &ctx,
                Some(&session.token),
                HttpMethod::Post,
                "/organization/create-team",
                Some(json!({"name":"Owner defaults must not leak"})),
                &[],
            )
            .await?,
            403,
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
        )?;
        // update-member-role deliberately permits the creator even when custom
        // definitions omit owner permissions; the upstream endpoint opts into it.
        let assigned = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/update-member-role",
            Some(json!({"memberId":member_id,"role":["owner","delegate","member-editor"]})),
            &[],
        )
        .await?;
        assert_eq!(assigned.status, 200);
        let allowed = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/create-team",
            Some(json!({"name":"Delegated"})),
            &[],
        )
        .await?;
        assert_eq!(allowed.status, 200);
        let together = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/has-permission",
            Some(json!({"permissions":{"team":["create"],"member":["update"]}})),
            &[],
        )
        .await?;
        assert_eq!(
            (*(body::<Value>(&together)?)
                .get("success")
                .unwrap_or(&Value::Null)),
            false
        );
        let empty = OrganizationPlugin::with_config(OrganizationConfig {
            roles: Some(HashMap::new()),
            ..configuration()
        });
        assert_error(
            &call(
                &empty,
                &ctx,
                Some(&session.token),
                HttpMethod::Post,
                "/organization/create-team",
                Some(json!({"name":"Explicitly no roles"})),
                &[],
            )
            .await?,
            403,
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
        )?;

        let founder = OrganizationPlugin::with_config(OrganizationConfig {
            creator_role: "founder".to_owned(),
            roles: Some(HashMap::from([
                (
                    "founder".to_owned(),
                    RolePermissions {
                        invitation: vec!["create".to_owned()],
                        ..Default::default()
                    },
                ),
                (
                    "inviter".to_owned(),
                    RolePermissions {
                        invitation: vec!["create".to_owned()],
                        ..Default::default()
                    },
                ),
            ])),
            ..configuration()
        });
        let founder_ctx = context(&founder).await?;
        let (_, founder_session) = actor(&founder_ctx, "configured-founder").await;
        let created_2 = call(
            &founder,
            &founder_ctx,
            Some(&founder_session.token),
            HttpMethod::Post,
            "/organization/create",
            Some(json!({"name":"Founder roles","slug":"native-founder-roles"})),
            &[],
        )
        .await?;
        let created_2_3: Value = body(&created_2)?;
        let founder_org = id(&created_2_3)?;
        // The pinned invitation route recognizes the three built-in role names
        // even when permissions and the creator role have been replaced.
        let invited = call(
            &founder,
            &founder_ctx,
            Some(&founder_session.token),
            HttpMethod::Post,
            "/organization/invite-member",
            Some(json!({"email":"builtin-owner@example.com","role":"owner"})),
            &[],
        )
        .await?;
        assert_eq!(invited.status, 200);
        let invitation: Value = body(&invited)?;
        let saved = founder_ctx
            .database
            .get_invitation_by_id(id(&invitation)?)
            .await?
            .ok_or_else(|| std::io::Error::other("Owner-role invitation was not persisted"))?;
        assert_eq!(saved.organization_id, founder_org);
        assert_eq!(saved.role.as_deref(), Some("owner"));
        assert_eq!(
            saved.status,
            better_auth_core::types::InvitationStatus::Pending
        );

        let (sender, inviter_session) = actor(&founder_ctx, "configured-inviter").await;
        drop(
            founder_ctx
                .database
                .create_member(CreateMember::new(founder_org, &sender.id, "inviter"))
                .await?,
        );
        assert_error(
        &call(
            &founder,
            &founder_ctx,
            Some(&inviter_session.token),
            HttpMethod::Post,
            "/organization/invite-member",
            Some(json!({"organizationId":founder_org,"email":"protected-founder@example.com","role":"founder"})),
            &[],
        )
        .await?,
        403,
        "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE",
    )?;
        assert!(
            founder_ctx
                .database
                .get_pending_invitation(founder_org, "protected-founder@example.com")
                .await?
                .is_none()
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn invitation_email_policy_guards_id_actions_and_preserves_rejection_state() -> TestResult
    {
        let plugin = OrganizationPlugin::with_config(OrganizationConfig {
            require_email_verification_on_invitation: Some(true),
            ..configuration()
        });
        let mut ctx = context(&plugin).await?;
        let (owner, owner_session) = actor(&ctx, "verified-inviter").await;
        let (recipient, recipient_session) = actor(&ctx, "unverified-recipient").await;
        drop(
            ctx.database
                .update_user(
                    &recipient.id,
                    better_auth_core::UpdateUser {
                        email_verified: Some(false),
                        ..Default::default()
                    },
                )
                .await?,
        );
        let created = call(
            &plugin,
            &ctx,
            Some(&owner_session.token),
            HttpMethod::Post,
            "/organization/create",
            Some(json!({"name":"Verified invitation","slug":"verified-invitation"})),
            &[],
        )
        .await?;
        let created: Value = body(&created)?;
        let organization_id = id(&created)?;
        let invitation = ctx
            .database
            .create_invitation(better_auth_core::CreateInvitation {
                email: recipient
                    .email
                    .clone()
                    .ok_or_else(|| std::io::Error::other("Recipient has no email"))?,
                role: "member".to_owned(),
                organization_id: organization_id.to_owned(),
                inviter_id: owner.id.clone(),
                expires_at: chrono::Utc::now() + Duration::hours(1),
                team_id: None,
            })
            .await?;
        let forbidden_get = call(
            &plugin,
            &ctx,
            Some(&recipient_session.token),
            HttpMethod::Get,
            "/organization/get-invitation",
            None,
            &[("id", &invitation.id)],
        )
        .await?;
        assert_error(
            &forbidden_get,
            403,
            "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION",
        )?;
        for path in [
            "/organization/accept-invitation",
            "/organization/reject-invitation",
        ] {
            assert_error(
                &call(
                    &plugin,
                    &ctx,
                    Some(&recipient_session.token),
                    HttpMethod::Post,
                    path,
                    Some(json!({"invitationId":invitation.id})),
                    &[],
                )
                .await?,
                403,
                "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION",
            )?;
        }
        let untouched = ctx
            .database
            .get_invitation_by_id(&invitation.id)
            .await?
            .ok_or_else(|| std::io::Error::other("Rejected invitation disappeared"))?;
        assert_eq!(
            untouched.status,
            better_auth_core::InvitationStatus::Pending
        );
        assert!(
            ctx.database
                .get_member(organization_id, &recipient.id)
                .await?
                .is_none()
        );
        assert!(
            ctx.database
                .list_user_teams(&recipient.id)
                .await?
                .is_empty()
        );

        // Opaque IDs use the default policy without requiring email verification.
        let automatic = OrganizationPlugin::with_config(configuration());
        assert_eq!(
            call(
                &automatic,
                &ctx,
                Some(&recipient_session.token),
                HttpMethod::Get,
                "/organization/get-invitation",
                None,
                &[("id", &invitation.id)]
            )
            .await?
            .status,
            200
        );
        let mut numeric_config = ctx.config.as_ref().clone();
        numeric_config.advanced.database.use_number_id = true;
        ctx.config = std::sync::Arc::new(numeric_config);
        assert_error(
            &call(
                &automatic,
                &ctx,
                Some(&recipient_session.token),
                HttpMethod::Get,
                "/organization/get-invitation",
                None,
                &[("id", &invitation.id)],
            )
            .await?,
            403,
            "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION",
        )?;
        let explicit_false = OrganizationPlugin::with_config(OrganizationConfig {
            require_email_verification_on_invitation: Some(false),
            ..configuration()
        });
        assert_eq!(
            call(
                &explicit_false,
                &ctx,
                Some(&recipient_session.token),
                HttpMethod::Get,
                "/organization/get-invitation",
                None,
                &[("id", &invitation.id)]
            )
            .await?
            .status,
            200
        );
        let rejected = call(
            &explicit_false,
            &ctx,
            Some(&recipient_session.token),
            HttpMethod::Post,
            "/organization/reject-invitation",
            Some(json!({"invitationId":invitation.id})),
            &[],
        )
        .await?;
        assert_eq!(rejected.status, 200);
        assert_eq!(
            ctx.database
                .get_invitation_by_id(&invitation.id)
                .await?
                .ok_or_else(|| std::io::Error::other("Processed invitation disappeared"))?
                .status,
            better_auth_core::InvitationStatus::Rejected
        );
        let processed = call(
            &explicit_false,
            &ctx,
            Some(&recipient_session.token),
            HttpMethod::Get,
            "/organization/get-invitation",
            None,
            &[("id", &invitation.id)],
        )
        .await?;
        assert_eq!(processed.status, 400);
        assert_eq!(
            body::<Value>(&processed)?,
            json!({"message":"Invitation not found!"})
        );

        let expired = ctx
            .database
            .create_invitation(better_auth_core::CreateInvitation {
                email: invitation.email.clone(),
                role: "member".to_owned(),
                organization_id: organization_id.to_owned(),
                inviter_id: owner.id.clone(),
                expires_at: chrono::Utc::now() - Duration::hours(1),
                team_id: None,
            })
            .await?;
        let expired_get = call(
            &plugin,
            &ctx,
            Some(&recipient_session.token),
            HttpMethod::Get,
            "/organization/get-invitation",
            None,
            &[("id", &expired.id)],
        )
        .await?;
        assert_eq!(expired_get.status, 400);
        assert_eq!(
            body::<Value>(&expired_get)?,
            json!({"message":"Invitation not found!"})
        );
        assert_error(
            &call(
                &plugin,
                &ctx,
                Some(&recipient_session.token),
                HttpMethod::Post,
                "/organization/accept-invitation",
                Some(json!({"invitationId":expired.id})),
                &[],
            )
            .await?,
            400,
            "INVITATION_NOT_FOUND",
        )?;
        drop(
            ctx.database
                .update_user(
                    &recipient.id,
                    better_auth_core::UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await?,
        );
        // Rejecting an expired, pending invitation remains supported upstream.
        assert_eq!(
            call(
                &plugin,
                &ctx,
                Some(&recipient_session.token),
                HttpMethod::Post,
                "/organization/reject-invitation",
                Some(json!({"invitationId":expired.id})),
                &[]
            )
            .await?
            .status,
            200
        );
        let pending = ctx
            .database
            .create_invitation(better_auth_core::CreateInvitation {
                email: invitation.email,
                role: "member".to_owned(),
                organization_id: organization_id.to_owned(),
                inviter_id: owner.id.clone(),
                expires_at: chrono::Utc::now() + Duration::hours(1),
                team_id: None,
            })
            .await?;
        let owner_member = ctx
            .database
            .get_member(organization_id, &owner.id)
            .await?
            .ok_or_else(|| std::io::Error::other("Creator membership missing"))?;
        ctx.database.delete_member(&owner_member.id).await?;
        assert_error(
            &call(
                &plugin,
                &ctx,
                Some(&recipient_session.token),
                HttpMethod::Get,
                "/organization/get-invitation",
                None,
                &[("id", &pending.id)],
            )
            .await?,
            400,
            "INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION",
        )?;
        Ok(())
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
#[cfg(test)]
mod dynamic_role_tests {
    use super::extension_tests::{actor, assert_error, body, call, configured_context, id};
    use super::*;
    use crate::plugins::test_helpers::create_test_config;
    use better_auth_core::types::{
        CreateMember, CreateOrganizationRole, OrganizationPermissions, OrganizationRoleSelector,
    };
    use better_auth_core::wire::SessionView;
    use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    use serde_json::{Value, json};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[derive(Debug, Default)]
    struct PausingRoleLimits {
        pause: std::sync::atomic::AtomicBool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait]
    impl OrganizationLimitResolver for PausingRoleLimits {
        async fn maximum_roles(&self, _organization_id: &str) -> AuthResult<Option<f64>> {
            if self.pause.swap(false, std::sync::atomic::Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
            }
            Ok(Some(100.0))
        }
    }

    #[derive(Debug)]
    struct RoleLimits(std::sync::Arc<std::sync::Mutex<HashMap<String, usize>>>);

    #[async_trait]
    impl OrganizationLimitResolver for RoleLimits {
        #[expect(
            clippy::cast_precision_loss,
            reason = "Migrate the existing integer application policy to a Source Number"
        )]
        async fn maximum_roles(&self, organization_id: &str) -> AuthResult<Option<f64>> {
            let policies = self.0.lock().map_err(|_error| {
                better_auth_core::AuthError::internal("Role policy unavailable")
            })?;
            Ok(Some(
                policies.get(organization_id).copied().unwrap_or(0) as f64
            ))
        }
    }

    fn configuration() -> OrganizationConfig {
        OrganizationConfig {
            teams: TeamsConfig {
                enabled: true,
                create_default_team: false,
                ..Default::default()
            },
            access_control: Some(default_organization_statements()),
            dynamic_access_control: DynamicAccessControlConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    async fn organization(
        plugin: &OrganizationPlugin,
        ctx: &AuthContext<BundledSchema>,
        session: &SessionView,
        slug: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let response = call(
            plugin,
            ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/create",
            Some(json!({"name":slug,"slug":slug})),
            &[],
        )
        .await?;
        assert_eq!(response.status, 200);
        Ok(id(&body::<Value>(&response)?)?.to_owned())
    }

    fn permission(resource: &str, action: &str) -> OrganizationPermissions {
        [(resource.to_owned(), vec![action.to_owned()])].into()
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn dynamic_role_mutations_scope_the_tenant_and_apply_name_selectors_to_all_legacy_rows()
    -> TestResult {
        let plugin = OrganizationPlugin::with_config(configuration());
        let ctx = configured_context(&plugin, create_test_config()).await?;
        let (_, owner) = actor(&ctx, "role-owner").await;
        let (_, foreign) = actor(&ctx, "role-foreign").await;
        let org = organization(&plugin, &ctx, &owner, "native-role-mutations").await?;
        let other = organization(&plugin, &ctx, &foreign, "native-role-foreign").await?;
        let mut rows = Vec::new();
        for organization_id in [&org, &org, &other] {
            rows.push(
                ctx.database
                    .create_organization_role(CreateOrganizationRole {
                        organization_id: organization_id.clone(),
                        role: "legacy-editor".to_owned(),
                        permission: permission("team", "create"),
                    })
                    .await?,
            );
        }
        let wrong_scope = call(
            &plugin,
            &ctx,
            Some(&foreign.token),
            HttpMethod::Get,
            "/organization/get-role",
            None,
            &[
                ("organizationId", &other),
                (
                    "roleId",
                    &(rows)
                        .first()
                        .expect("fixture contains the requested index")
                        .id,
                ),
            ],
        )
        .await?;
        assert_error(&wrong_scope, 400, "ROLE_NOT_FOUND")?;
        let unauthorized_update = call(&plugin, &ctx, Some(&foreign.token), HttpMethod::Post,
        "/organization/update-role", Some(json!({"organizationId":org,"roleId":(rows).first().expect("fixture contains the requested index").id,"data":{"permission":{"team":["delete"]}}})), &[]).await?;
        assert_error(
            &unauthorized_update,
            403,
            "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
        )?;
        assert_eq!(
            serde_json::from_str::<OrganizationPermissions>(
                ctx.database
                    .get_organization_role(
                        &org,
                        &OrganizationRoleSelector::Id(
                            (rows)
                                .first()
                                .expect("fixture contains the requested index")
                                .id
                                .clone()
                        )
                    )
                    .await?
                    .ok_or("Role missing")?
                    .permission
                    .as_str()
            )?,
            permission("team", "create")
        );

        let by_id = call(&plugin, &ctx, Some(&owner.token), HttpMethod::Post,
        "/organization/update-role", Some(json!({"organizationId":org,"roleId":(rows).first().expect("fixture contains the requested index").id,"data":{"permission":{"team":["update"]}}})), &[]).await?;
        assert_eq!(by_id.status, 200);
        assert_eq!(
            (*(*(body::<Value>(&by_id)?)
                .get("roleData")
                .unwrap_or(&Value::Null))
            .get("updatedAt")
            .unwrap_or(&Value::Null)),
            Value::Null
        );
        let first_snapshot = ctx
            .database
            .get_organization_role(
                &org,
                &OrganizationRoleSelector::Id(
                    (rows)
                        .first()
                        .expect("fixture contains the requested index")
                        .id
                        .clone(),
                ),
            )
            .await?
            .ok_or("Role missing")?;
        assert_eq!(
            serde_json::from_str::<OrganizationPermissions>(first_snapshot.permission.as_str())?,
            permission("team", "update")
        );
        assert!(first_snapshot.updated_at.is_some());
        assert_eq!(
            serde_json::from_str::<OrganizationPermissions>(
                ctx.database
                    .get_organization_role(
                        &org,
                        &OrganizationRoleSelector::Id(
                            (rows)
                                .get(1)
                                .expect("fixture contains the requested index")
                                .id
                                .clone()
                        )
                    )
                    .await?
                    .ok_or("Role missing")?
                    .permission
                    .as_str()
            )?,
            permission("team", "create")
        );

        let by_name = call(&plugin, &ctx, Some(&owner.token), HttpMethod::Post,
        "/organization/update-role", Some(json!({"organizationId":org,"roleName":"legacy-editor","data":{"permission":{"member":["update"]}}})), &[]).await?;
        assert_eq!(by_name.status, 200);
        assert_eq!(
            (*(*(body::<Value>(&by_name)?)
                .get("roleData")
                .unwrap_or(&Value::Null))
            .get("id")
            .unwrap_or(&Value::Null)),
            (rows)
                .first()
                .expect("fixture contains the requested index")
                .id
        );
        assert_eq!(
            (*(*(body::<Value>(&by_name)?)
                .get("roleData")
                .unwrap_or(&Value::Null))
            .get("updatedAt")
            .unwrap_or(&Value::Null)),
            (*(serde_json::to_value(first_snapshot)?)
                .get("updatedAt")
                .unwrap_or(&Value::Null))
        );
        let updated = ctx.database.list_organization_roles(&org).await?;
        assert_eq!(updated.len(), 2);
        for row in &updated {
            assert_eq!(
                serde_json::from_str::<OrganizationPermissions>(row.permission.as_str())?,
                permission("member", "update")
            );
        }
        assert!(
            (updated)
                .first()
                .expect("persisted rows contain the requested index")
                .updated_at
                .is_some()
        );
        assert_eq!(
            (updated)
                .first()
                .expect("persisted rows contain the requested index")
                .updated_at,
            (updated)
                .get(1)
                .expect("persisted rows contain the requested index")
                .updated_at
        );
        let unaffected = ctx
            .database
            .get_organization_role(
                &other,
                &OrganizationRoleSelector::Id(
                    (rows)
                        .get(2)
                        .expect("fixture contains the requested index")
                        .id
                        .clone(),
                ),
            )
            .await?
            .ok_or("Foreign role missing")?;
        assert_eq!(
            serde_json::from_str::<OrganizationPermissions>(unaffected.permission.as_str())?,
            permission("team", "create")
        );
        assert_eq!(unaffected.updated_at, None);

        let deleted = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/delete-role",
            Some(json!({"organizationId":org,"roleName":"legacy-editor"})),
            &[],
        )
        .await?;
        assert_eq!(deleted.status, 200);
        assert_eq!(body::<Value>(&deleted)?, json!({"success":true}));
        assert_eq!(ctx.database.count_organization_roles(&org).await?, 0);
        assert_eq!(ctx.database.count_organization_roles(&other).await?, 1);
        let replay = call(
        &plugin,
        &ctx,
        Some(&owner.token),
        HttpMethod::Post,
        "/organization/delete-role",
        Some(json!({"organizationId":org,"roleId":(rows).first().expect("fixture contains the requested index").id})),
        &[],
    )
    .await?;
        assert_error(&replay, 400, "ROLE_NOT_FOUND")?;

        let id_only = ctx
            .database
            .create_organization_role(CreateOrganizationRole {
                organization_id: org.clone(),
                role: "another-duplicate".to_owned(),
                permission: permission("team", "create"),
            })
            .await?;
        let retained = ctx
            .database
            .create_organization_role(CreateOrganizationRole {
                organization_id: org.clone(),
                role: "another-duplicate".to_owned(),
                permission: permission("team", "create"),
            })
            .await?;
        let deleted_2 = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/delete-role",
            Some(json!({"organizationId":org,"roleId":id_only.id})),
            &[],
        )
        .await?;
        assert_eq!(deleted_2.status, 200);
        assert_eq!(ctx.database.count_organization_roles(&org).await?, 1);
        assert!(
            ctx.database
                .get_organization_role(&org, &OrganizationRoleSelector::Id(retained.id))
                .await?
                .is_some()
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn dynamic_role_creation_preserves_the_membership_resource_and_name_check_order()
    -> TestResult {
        let plugin = OrganizationPlugin::with_config(configuration());
        let ctx = configured_context(&plugin, create_test_config()).await?;
        let (_, owner) = actor(&ctx, "name-owner").await;
        let (_, outsider) = actor(&ctx, "name-outsider").await;
        let (member, member_session) = actor(&ctx, "name-member").await;
        let org = organization(&plugin, &ctx, &owner, "native-role-name-priority").await?;
        ctx.database
            .create_member(CreateMember {
                organization_id: org.clone(),
                user_id: member.id,
                role: "member".to_owned(),
            })
            .await?;
        ctx.database
            .create_organization_role(CreateOrganizationRole {
                organization_id: org.clone(),
                role: "existing".to_owned(),
                permission: permission("team", "create"),
            })
            .await?;
        for (session, name, requested, status, code) in [
            (
                &outsider,
                "existing",
                json!({}),
                403,
                "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
            ),
            (
                &outsider,
                "OWNER",
                json!({}),
                400,
                "ROLE_NAME_IS_ALREADY_TAKEN",
            ),
            (
                &member_session,
                "existing",
                json!({}),
                403,
                "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
            ),
            (
                &owner,
                "existing",
                json!({"invented":["read"]}),
                400,
                "INVALID_RESOURCE",
            ),
            (
                &owner,
                "existing",
                json!({}),
                400,
                "ROLE_NAME_IS_ALREADY_TAKEN",
            ),
        ] {
            let denied = call(
                &plugin,
                &ctx,
                Some(&session.token),
                HttpMethod::Post,
                "/organization/create-role",
                Some(json!({"organizationId":org,"role":name,"permission":requested})),
                &[],
            )
            .await?;
            assert_error(&denied, status, code)?;
            assert_eq!(ctx.database.count_organization_roles(&org).await?, 1);
        }
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn assigned_role_checks_filter_the_tenant_before_the_configured_adapter_page()
    -> TestResult {
        let plugin = OrganizationPlugin::with_config(configuration());
        let mut config = create_test_config();
        config.advanced.database.default_find_many_limit = 1;
        let ctx = configured_context(&plugin, config).await?;
        let (_, owner) = actor(&ctx, "page-owner").await;
        let (assigned, assigned_session) = actor(&ctx, "page-assigned").await;
        let (prefix, _) = actor(&ctx, "page-prefix").await;
        let org = organization(&plugin, &ctx, &owner, "native-assigned-role-page").await?;
        let role = ctx
            .database
            .create_organization_role(CreateOrganizationRole {
                organization_id: org.clone(),
                role: "editor".to_owned(),
                permission: permission("team", "create"),
            })
            .await?;
        let member = ctx
            .database
            .create_member(CreateMember {
                organization_id: org.clone(),
                user_id: assigned.id.clone(),
                role: " member, editor ".to_owned(),
            })
            .await?;
        let denied = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/delete-role",
            Some(json!({"organizationId":org,"roleId":role.id})),
            &[],
        )
        .await?;
        assert_error(&denied, 400, "ROLE_IS_ASSIGNED_TO_MEMBERS")?;
        assert!(
            ctx.database
                .get_organization_role(&org, &OrganizationRoleSelector::Id(role.id.clone()))
                .await?
                .is_some()
        );

        ctx.database.delete_member(&member.id).await?;
        ctx.database
            .create_member(CreateMember {
                organization_id: org.clone(),
                user_id: prefix.id,
                role: "prefixeditor".to_owned(),
            })
            .await?;
        ctx.database
            .create_member(CreateMember {
                organization_id: org.clone(),
                user_id: assigned.id.clone(),
                role: "editor".to_owned(),
            })
            .await?;
        // The pinned adapter inspects the first matching page, including a prefix match
        // that is not an exact role. A later assignment does not block this deletion.
        let deleted = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/delete-role",
            Some(json!({"organizationId":org,"roleId":role.id})),
            &[],
        )
        .await?;
        assert_eq!(deleted.status, 200);
        assert_eq!(body::<Value>(&deleted)?, json!({"success":true}));
        assert!(
            ctx.database
                .get_organization_role(&org, &OrganizationRoleSelector::Id(role.id))
                .await?
                .is_none()
        );
        assert_eq!(
            ctx.database
                .get_member(&org, &assigned.id)
                .await?
                .ok_or("Assigned member missing")?
                .role,
            "editor"
        );
        let revoked = call(
            &plugin,
            &ctx,
            Some(&assigned_session.token),
            HttpMethod::Post,
            "/organization/create-team",
            Some(json!({"organizationId":org,"name":"Unavailable"})),
            &[],
        )
        .await?;
        assert_error(
            &revoked,
            403,
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
        )?;
        assert!(ctx.database.list_teams(&org).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn permission_requests_preserve_empty_legacy_xor_and_membership_wire_behavior()
    -> TestResult {
        let plugin = OrganizationPlugin::with_config(configuration());
        let ctx = configured_context(&plugin, create_test_config()).await?;
        let (_, owner) = actor(&ctx, "permission-owner").await;
        let (_, outsider) = actor(&ctx, "permission-outsider").await;
        let org = organization(&plugin, &ctx, &owner, "native-role-permission-shapes").await?;
        for (request, success) in [
            (json!({"permissions":{}}), false),
            (json!({"permissions":{"team":[]}}), false),
            (json!({"permissions":{"invented":[]}}), false),
            (json!({"permission":{"team":["create"]}}), false),
            (
                json!({"permissions":{"team":["create"]},"permission":null}),
                true,
            ),
            (
                json!({"permissions":null,"permission":{"team":["create"]}}),
                false,
            ),
            (
                json!({"organizationId":"","permissions":{"team":["create"]}}),
                true,
            ),
        ] {
            let response = call(
                &plugin,
                &ctx,
                Some(&owner.token),
                HttpMethod::Post,
                "/organization/has-permission",
                Some(request),
                &[],
            )
            .await?;
            assert_eq!(response.status, 200);
            assert_eq!(
                body::<Value>(&response)?,
                json!({"error":null,"success":success})
            );
        }
        let both = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/has-permission",
            Some(json!({"permissions":{"team":["create"]},"permission":{"team":["create"]}})),
            &[],
        )
        .await?;
        assert_error(&both, 400, "VALIDATION_ERROR")?;
        assert_eq!(
            (*(body::<Value>(&both)?)
                .get("message")
                .unwrap_or(&Value::Null)),
            "[body] Invalid input: more than one option matched"
        );
        let denied = call(
            &plugin,
            &ctx,
            Some(&outsider.token),
            HttpMethod::Post,
            "/organization/has-permission",
            Some(json!({"organizationId":org,"permissions":{"team":["create"]}})),
            &[],
        )
        .await?;
        assert_error(&denied, 401, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")?;
        let invalid_without_authentication = call(
            &plugin,
            &ctx,
            None,
            HttpMethod::Post,
            "/organization/create-role",
            Some(json!({"role":123,"permission":{}})),
            &[],
        )
        .await?;
        assert_error(&invalid_without_authentication, 400, "VALIDATION_ERROR")?;
        assert_eq!(
            (*(body::<Value>(&invalid_without_authentication)?)
                .get("message")
                .unwrap_or(&Value::Null)),
            "[body.role] Invalid input: expected string, received number"
        );
        assert_eq!(ctx.database.count_organization_roles(&org).await?, 0);
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn role_wire_validation_preserves_union_selection_and_rejects_null_updates_without_mutation()
    -> TestResult {
        let plugin = OrganizationPlugin::with_config(configuration());
        let ctx = configured_context(&plugin, create_test_config()).await?;
        let (_, owner) = actor(&ctx, "validation-owner").await;
        let org = organization(&plugin, &ctx, &owner, "native-role-validation").await?;
        let role = ctx
            .database
            .create_organization_role(CreateOrganizationRole {
                organization_id: org.clone(),
                role: "editor".to_owned(),
                permission: permission("team", "create"),
            })
            .await?;
        for (request, message) in [
            (
                json!({"roleName":"","data":{}}),
                "[body.roleName] Too small: expected string to have >=1 characters",
            ),
            (
                json!({"roleId":"","data":{}}),
                "[body.roleId] Too small: expected string to have >=1 characters",
            ),
            (
                json!({"roleName":"","roleId":"","data":{}}),
                "[body] Invalid input",
            ),
            (json!({"roleName":123,"data":{}}), "[body] Invalid input"),
            (
                json!({"roleId":role.id,"data":{"permission":null}}),
                "[body.data.permission] Invalid input: expected record, received null",
            ),
            (
                json!({"roleId":role.id,"data":{"roleName":null}}),
                "[body.data.roleName] Invalid input: expected string, received null",
            ),
            (
                json!({"organizationId":null,"roleId":role.id,"data":{}}),
                "[body.organizationId] Invalid input: expected string, received null",
            ),
        ] {
            let response = call(
                &plugin,
                &ctx,
                Some(&owner.token),
                HttpMethod::Post,
                "/organization/update-role",
                Some(request),
                &[],
            )
            .await?;
            assert_error(&response, 400, "VALIDATION_ERROR")?;
            assert_eq!(
                (*(body::<Value>(&response)?)
                    .get("message")
                    .unwrap_or(&Value::Null)),
                message
            );
            let persisted = ctx
                .database
                .get_organization_role(&org, &OrganizationRoleSelector::Id(role.id.clone()))
                .await?
                .ok_or("Role missing")?;
            assert_eq!(
                serde_json::from_str::<OrganizationPermissions>(persisted.permission.as_str())?,
                permission("team", "create")
            );
            assert_eq!(persisted.updated_at, None);
        }
        let selected = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/update-role",
            Some(
                json!({"roleName":null,"roleId":role.id,"data":{"permission":{"team":["update"]}}}),
            ),
            &[],
        )
        .await?;
        assert_eq!(selected.status, 200);
        assert_eq!(
            (*(*(body::<Value>(&selected)?)
                .get("roleData")
                .unwrap_or(&Value::Null))
            .get("id")
            .unwrap_or(&Value::Null)),
            role.id
        );
        assert_eq!(
            serde_json::from_str::<OrganizationPermissions>(
                ctx.database
                    .get_organization_role(&org, &OrganizationRoleSelector::Id(role.id.clone()))
                    .await?
                    .ok_or("Role missing")?
                    .permission
                    .as_str()
            )?,
            permission("team", "update")
        );
        Ok(())
    }

    fn delegated_configuration() -> OrganizationConfig {
        let mut config = configuration();
        drop(
            config
                .access_control
                .as_mut()
                .expect("Access control configured")
                .insert(
                    "apiKey".to_owned(),
                    vec![
                        "create".to_owned(),
                        "read".to_owned(),
                        "update".to_owned(),
                        "delete".to_owned(),
                    ],
                ),
        );
        config.roles = Some(
            [
                (
                    "owner".to_owned(),
                    RolePermissions {
                        organization: vec!["update".to_owned(), "delete".to_owned()],
                        member: vec![
                            "create".to_owned(),
                            "update".to_owned(),
                            "delete".to_owned(),
                        ],
                        invitation: vec!["create".to_owned(), "cancel".to_owned()],
                        team: vec![
                            "create".to_owned(),
                            "update".to_owned(),
                            "delete".to_owned(),
                        ],
                        ac: vec![
                            "create".to_owned(),
                            "read".to_owned(),
                            "update".to_owned(),
                            "delete".to_owned(),
                        ],
                        api_key: vec![
                            "create".to_owned(),
                            "read".to_owned(),
                            "update".to_owned(),
                            "delete".to_owned(),
                        ],
                        ..Default::default()
                    },
                ),
                (
                    "delegator".to_owned(),
                    RolePermissions {
                        team: vec!["create".to_owned()],
                        ac: vec!["create".to_owned(), "read".to_owned(), "update".to_owned()],
                        ..Default::default()
                    },
                ),
                (
                    "auditor".to_owned(),
                    RolePermissions {
                        member: vec!["update".to_owned()],
                        ..Default::default()
                    },
                ),
                ("member".to_owned(), RolePermissions::default()),
            ]
            .into(),
        );
        config
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn delegation_checks_each_grant_without_unioning_full_requests_and_revokes_api_key_authority()
    -> TestResult {
        let plugin = OrganizationPlugin::with_config(delegated_configuration());
        let ctx = configured_context(&plugin, create_test_config()).await?;
        let (_, owner) = actor(&ctx, "delegation-owner").await;
        let (delegate, delegate_session) = actor(&ctx, "delegation-member").await;
        let org = organization(&plugin, &ctx, &owner, "native-role-delegation").await?;
        let member = ctx
            .database
            .create_member(CreateMember {
                organization_id: org.clone(),
                user_id: delegate.id.clone(),
                role: "delegator,auditor".to_owned(),
            })
            .await?;
        let combined = call(
            &plugin,
            &ctx,
            Some(&delegate_session.token),
            HttpMethod::Post,
            "/organization/has-permission",
            Some(json!({"permissions":{"team":["create"],"member":["update"]}})),
            &[],
        )
        .await?;
        // A member may hold both grants, but one role must authorize the entire request.
        // The session still needs explicit organization selection for this direct actor.
        assert_error(&combined, 400, "NO_ACTIVE_ORGANIZATION")?;
        let combined_2 = call(
            &plugin,
            &ctx,
            Some(&delegate_session.token),
            HttpMethod::Post,
            "/organization/has-permission",
            Some(
                json!({"organizationId":org,"permissions":{"team":["create"],"member":["update"]}}),
            ),
            &[],
        )
        .await?;
        assert_eq!(
            body::<Value>(&combined_2)?,
            json!({"error":null,"success":false})
        );
        let denied = call(&plugin, &ctx, Some(&delegate_session.token), HttpMethod::Post,
        "/organization/create-role", Some(json!({"organizationId":org,"role":"escalated","permission":{"team":["delete","delete"],"apiKey":["create"]}})), &[]).await?;
        assert_error(&denied, 403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE")?;
        assert_eq!(
            (*(body::<Value>(&denied)?)
                .get("missingPermissions")
                .unwrap_or(&Value::Null)),
            json!(["team:delete", "team:delete", "apiKey:create"])
        );
        assert_eq!(ctx.database.count_organization_roles(&org).await?, 0);
        let allowed = call(&plugin, &ctx, Some(&delegate_session.token), HttpMethod::Post,
        "/organization/create-role", Some(json!({"organizationId":org,"role":"combined","permission":{"team":["create"],"member":["update"]}})), &[]).await?;
        assert_eq!(allowed.status, 200);
        assert_eq!(
            (*(body::<Value>(&allowed)?)
                .get("statements")
                .unwrap_or(&Value::Null)),
            json!({"team":["create"],"member":["update"]})
        );

        let key_role = call(&plugin, &ctx, Some(&owner.token), HttpMethod::Post,
        "/organization/create-role", Some(json!({"organizationId":org,"role":"key-editor","permission":{"apiKey":["create","read"]}})), &[]).await?;
        assert_eq!(key_role.status, 200);
        let role_id = (*(*(body::<Value>(&key_role)?)
            .get("roleData")
            .unwrap_or(&Value::Null))
        .get("id")
        .unwrap_or(&Value::Null))
        .as_str()
        .ok_or("Role ID missing")?
        .to_owned();
        drop(
            ctx.database
                .update_member_role(&member.id, "key-editor")
                .await?,
        );
        crate::plugins::helpers::require_org_api_key_permission(&ctx, &delegate.id, &org, "create")
            .await?;
        crate::plugins::helpers::require_org_api_key_permission(&ctx, &delegate.id, &org, "read")
            .await?;
        let error = crate::plugins::helpers::require_org_api_key_permission(
            &ctx,
            &delegate.id,
            &org,
            "delete",
        )
        .await
        .err()
        .ok_or("Unowned key permission granted")?;
        assert_error(
            &error.to_auth_response(),
            403,
            "INSUFFICIENT_API_KEY_PERMISSIONS",
        )?;
        let changed = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/update-role",
            Some(
                json!({"organizationId":org,"roleId":role_id,"data":{"permission":{"apiKey":[]}}}),
            ),
            &[],
        )
        .await?;
        assert_eq!(changed.status, 200);
        let error_2 = crate::plugins::helpers::require_org_api_key_permission(
            &ctx,
            &delegate.id,
            &org,
            "read",
        )
        .await
        .err()
        .ok_or("Revoked key permission granted")?;
        assert_error(
            &error_2.to_auth_response(),
            403,
            "INSUFFICIENT_API_KEY_PERMISSIONS",
        )?;
        drop(
            ctx.database
                .update_member_role(&member.id, " owner ")
                .await?,
        );
        let error_3 = crate::plugins::helpers::require_org_api_key_permission(
            &ctx,
            &delegate.id,
            &org,
            "read",
        )
        .await
        .err()
        .ok_or("Whitespace role bypassed creator check")?;
        assert_error(
            &error_3.to_auth_response(),
            403,
            "INSUFFICIENT_API_KEY_PERMISSIONS",
        )?;
        drop(ctx.database.update_member_role(&member.id, "owner").await?);
        crate::plugins::helpers::require_org_api_key_permission(&ctx, &delegate.id, &org, "delete")
            .await?;
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn callback_role_limits_are_scoped_and_count_rows_beyond_the_list_page() -> TestResult {
        let policies = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
        let mut config = configuration();
        config.dynamic_access_control.maximum_roles_per_organization = Some(99.0);
        config.dynamic_access_control.limit_resolver = Some(std::sync::Arc::new(RoleLimits(
            std::sync::Arc::clone(&policies),
        )));
        let plugin = OrganizationPlugin::with_config(config);
        let mut config_2 = create_test_config();
        config_2.advanced.database.default_find_many_limit = 1;
        let ctx = configured_context(&plugin, config_2).await?;
        let (_, owner) = actor(&ctx, "quota-owner").await;
        let first = organization(&plugin, &ctx, &owner, "native-role-quota-one").await?;
        let second = organization(&plugin, &ctx, &owner, "native-role-quota-two").await?;
        let _ignored_clone = policies
            .lock()
            .map_err(|_error| "Role policy unavailable")?
            .insert(first.clone(), 1);
        let _ignored_clone_2 = policies
            .lock()
            .map_err(|_error| "Role policy unavailable")?
            .insert(second.clone(), 2);
        for (org, names) in [(&first, vec!["one"]), (&second, vec!["one", "two"])] {
            for name in names {
                let created = call(
                    &plugin,
                    &ctx,
                    Some(&owner.token),
                    HttpMethod::Post,
                    "/organization/create-role",
                    Some(json!({"organizationId":org,"role":name,"permission":{}})),
                    &[],
                )
                .await?;
                assert_eq!(created.status, 200);
            }
            let listed = call(
                &plugin,
                &ctx,
                Some(&owner.token),
                HttpMethod::Get,
                "/organization/list-roles",
                None,
                &[("organizationId", org)],
            )
            .await?;
            assert_eq!(body::<Vec<Value>>(&listed)?.len(), 1);
            let rejected = call(
                &plugin,
                &ctx,
                Some(&owner.token),
                HttpMethod::Post,
                "/organization/create-role",
                Some(json!({"organizationId":org,"role":"overflow","permission":{}})),
                &[],
            )
            .await?;
            assert_error(&rejected, 400, "TOO_MANY_ROLES")?;
        }
        assert_eq!(ctx.database.count_organization_roles(&first).await?, 1);
        assert_eq!(ctx.database.count_organization_roles(&second).await?, 2);
        let deleted = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/delete-role",
            Some(json!({"organizationId":second,"roleName":"two"})),
            &[],
        )
        .await?;
        assert_eq!(deleted.status, 200);
        let created = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/create-role",
            Some(json!({"organizationId":second,"role":"replacement","permission":{}})),
            &[],
        )
        .await?;
        assert_eq!(created.status, 200);
        assert_eq!(ctx.database.count_organization_roles(&second).await?, 2);
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn overlapping_permission_reloads_change_pending_delegation_only_in_the_selected_organization()
    -> TestResult {
        for refreshed_organization in [None, Some(false), Some(true)] {
            let policy = std::sync::Arc::new(PausingRoleLimits::default());
            let mut config = configuration();
            config.dynamic_access_control.limit_resolver =
                Some(std::sync::Arc::<PausingRoleLimits>::clone(&policy));
            let plugin = OrganizationPlugin::with_config(config);
            let ctx = configured_context(&plugin, create_test_config()).await?;
            let (_, owner) = actor(&ctx, "cache-owner").await;
            let (delegate, delegated_session) = actor(&ctx, "cache-delegate").await;
            let org = organization(&plugin, &ctx, &owner, "native-pending-role-cache").await?;
            let other = organization(&plugin, &ctx, &owner, "native-unrelated-role-cache").await?;
            let manager = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/create-role",
            Some(json!({"organizationId":org,"role":"manager","permission":{"ac":["create"],"team":["create"]}})),
            &[],
        ).await?;
            assert_eq!(manager.status, 200);
            let manager_id = (*(*(body::<Value>(&manager)?)
                .get("roleData")
                .unwrap_or(&Value::Null))
            .get("id")
            .unwrap_or(&Value::Null))
            .as_str()
            .ok_or("Manager role id missing")?
            .to_owned();
            ctx.database
                .create_member(CreateMember {
                    organization_id: org.clone(),
                    user_id: delegate.id,
                    role: "manager".to_owned(),
                })
                .await?;
            policy
                .pause
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let pending = call(
                &plugin,
                &ctx,
                Some(&delegated_session.token),
                HttpMethod::Post,
                "/organization/create-role",
                Some(
                    json!({"organizationId":org,"role":"delegated","permission":{"team":["create"]}}),
                ),
                &[],
            );
            let revoke = async {
                policy.entered.notified().await;
                let changed = call(
                &plugin,
                &ctx,
                Some(&owner.token),
                HttpMethod::Post,
                "/organization/update-role",
                Some(json!({"organizationId":org,"roleId":manager_id,"data":{"permission":{"ac":["create"]}}})),
                &[],
            ).await?;
                assert_eq!(changed.status, 200);
                if let Some(same_organization) = refreshed_organization {
                    let refreshed = call(
                    &plugin,
                    &ctx,
                    Some(&owner.token),
                    HttpMethod::Post,
                    "/organization/has-permission",
                    Some(json!({"organizationId":if same_organization { &org } else { &other },"permissions":{"team":["create"]}})),
                    &[],
                ).await?;
                    assert_eq!(refreshed.status, 200);
                    assert_eq!(
                        (*(body::<Value>(&refreshed)?)
                            .get("success")
                            .unwrap_or(&Value::Null)),
                        true
                    );
                }
                policy.release.notify_one();
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let (pending, revoked) =
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    tokio::join!(pending, revoke)
                })
                .await?;
            revoked?;
            let pending = pending?;
            if refreshed_organization == Some(true) {
                assert_error(&pending, 403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE")?;
                assert_eq!(
                    (*(body::<Value>(&pending)?)
                        .get("missingPermissions")
                        .unwrap_or(&Value::Null)),
                    json!(["team:create"])
                );
            } else {
                assert_eq!(pending.status, 200);
            }
            let manager_2 = ctx
                .database
                .get_organization_role(&org, &OrganizationRoleSelector::Id(manager_id))
                .await?
                .ok_or("Updated manager role missing")?;
            assert_eq!(
                serde_json::from_str::<OrganizationPermissions>(manager_2.permission.as_str())?,
                permission("ac", "create")
            );
            let created = ctx
                .database
                .get_organization_role(
                    &org,
                    &OrganizationRoleSelector::Name("delegated".to_owned()),
                )
                .await?;
            if refreshed_organization == Some(true) {
                assert!(created.is_none());
                assert_eq!(ctx.database.count_organization_roles(&org).await?, 1);
            } else {
                assert_eq!(
                    serde_json::from_str::<OrganizationPermissions>(
                        created.ok_or("Delegated role missing")?.permission.as_str()
                    )?,
                    permission("team", "create")
                );
                assert_eq!(ctx.database.count_organization_roles(&org).await?, 2);
            }
            assert_eq!(ctx.database.count_organization_roles(&other).await?, 0);
        }
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn default_role_validation_collects_ordered_issues_before_authorization_and_persistence()
    -> TestResult {
        let plugin = OrganizationPlugin::with_config(configuration());
        let ctx = configured_context(&plugin, create_test_config()).await?;
        let (_, owner) = actor(&ctx, "default-validation-owner").await;
        let org = organization(&plugin, &ctx, &owner, "native-default-role-validation").await?;
        for (transfer_encoding, length, bytes, code, message) in [
            (
                Some("chunked"),
                None,
                None,
                "VALIDATION_ERROR",
                "[body] Invalid input: expected object, received null",
            ),
            (
                None,
                Some("0"),
                None,
                "VALIDATION_ERROR",
                "[body] Invalid input: expected object, received undefined",
            ),
            (
                None,
                None,
                None,
                "VALIDATION_ERROR",
                "[body] Invalid input: expected object, received undefined",
            ),
            (
                None,
                None,
                Some(Vec::new()),
                "BAD_REQUEST",
                "Invalid JSON in request body",
            ),
            (
                None,
                None,
                Some(b"{malformed".to_vec()),
                "BAD_REQUEST",
                "Invalid JSON in request body",
            ),
        ] {
            let mut request = AuthRequest::new(HttpMethod::Post, "/organization/create-role");
            drop(
                request
                    .headers
                    .insert("content-type".to_owned(), "application/json".to_owned()),
            );
            if let Some(value) = transfer_encoding {
                drop(
                    request
                        .headers
                        .insert("transfer-encoding".to_owned(), value.to_owned()),
                );
            }
            if let Some(value) = length {
                drop(
                    request
                        .headers
                        .insert("content-length".to_owned(), value.to_owned()),
                );
            }
            request.body = bytes;
            let response = plugin
                .on_request(&request, &ctx)
                .await?
                .ok_or("Role route missing")?;
            assert_error(&response, 400, code)?;
            assert_eq!(
                (*(body::<Value>(&response)?)
                    .get("message")
                    .unwrap_or(&Value::Null)),
                message
            );
            assert_eq!(ctx.database.count_organization_roles(&org).await?, 0);
        }
        for (path, input, expected) in [
            (
                "/organization/create-role",
                json!({"role":"extra","permission":{},"additionalFields":null}),
                "[body.additionalFields] Invalid input: expected object, received null",
            ),
            (
                "/organization/create-role",
                json!({"role":"extra","permission":{},"additionalFields":1}),
                "[body.additionalFields] Invalid input: expected object, received number",
            ),
            (
                "/organization/create-role",
                json!({"role":"extra","permission":{},"additionalFields":[]}),
                "[body.additionalFields] Invalid input: expected object, received array",
            ),
            (
                "/organization/create-role",
                json!({"organizationId":null,"role":1,"permission":null,"additionalFields":1}),
                "[body.organizationId] Invalid input: expected string, received null; [body.role] Invalid input: expected string, received number; [body.permission] Invalid input: expected record, received null; [body.additionalFields] Invalid input: expected object, received number",
            ),
            (
                "/organization/create-role",
                json!({"role":"extra","permission":{"team":[null,1],"member":1}}),
                "[body.permission.team.0] Invalid input: expected string, received null; [body.permission.team.1] Invalid input: expected string, received number; [body.permission.member] Invalid input: expected array, received number",
            ),
            (
                "/organization/create-role",
                json!({"role":"extra","permission":{"2":[null],"1":[false],"team":[1]}}),
                "[body.permission.1.0] Invalid input: expected string, received boolean; [body.permission.2.0] Invalid input: expected string, received null; [body.permission.team.0] Invalid input: expected string, received number",
            ),
            (
                "/organization/update-role",
                json!({"organizationId":1,"roleName":"","data":{"permission":null,"roleName":1}}),
                "[body.organizationId] Invalid input: expected string, received number; [body.data.permission] Invalid input: expected record, received null; [body.data.roleName] Invalid input: expected string, received number; [body.roleName] Too small: expected string to have >=1 characters",
            ),
            (
                "/organization/has-permission",
                json!({"organizationId":null,"permissions":null,"permission":null}),
                "[body.organizationId] Invalid input: expected string, received null; [body] Invalid input",
            ),
        ] {
            for token in [Some(owner.token.as_str()), None] {
                let response = call(
                    &plugin,
                    &ctx,
                    token,
                    HttpMethod::Post,
                    path,
                    Some(input.clone()),
                    &[],
                )
                .await?;
                assert_error(&response, 400, "VALIDATION_ERROR")?;
                assert_eq!(
                    (*(body::<Value>(&response)?)
                        .get("message")
                        .unwrap_or(&Value::Null)),
                    expected
                );
                assert_eq!(ctx.database.count_organization_roles(&org).await?, 0);
            }
        }
        let created = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/create-role",
            Some(json!({"role":"ΟΣ","permission":{},"additionalFields":{"ignored":"value"}})),
            &[],
        )
        .await?;
        assert_eq!(created.status, 200);
        let value = body::<Value>(&created)?;
        assert_eq!(
            (*(*(value).get("roleData").unwrap_or(&Value::Null))
                .get("role")
                .unwrap_or(&Value::Null)),
            "ος"
        );
        assert!(
            (*(value).get("roleData").unwrap_or(&Value::Null))
                .get("ignored")
                .is_none()
        );
        assert_eq!(
            (ctx.database.list_organization_roles(&org).await?)
                .first()
                .expect("fixture contains the requested index")
                .role,
            "ος"
        );
        let duplicate = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/create-role",
            Some(json!({"role":"ος","permission":{}})),
            &[],
        )
        .await?;
        assert_error(&duplicate, 400, "ROLE_NAME_IS_ALREADY_TAKEN")?;
        assert_eq!(ctx.database.count_organization_roles(&org).await?, 1);
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn expired_and_revoked_role_sessions_cannot_mutate_existing_permissions() -> TestResult {
        let plugin = OrganizationPlugin::with_config(configuration());
        let ctx = configured_context(&plugin, create_test_config()).await?;
        let (user, owner) = actor(&ctx, "session-role-owner").await;
        let org = organization(&plugin, &ctx, &owner, "native-role-session-guards").await?;
        let role = ctx
            .database
            .create_organization_role(CreateOrganizationRole {
                organization_id: org.clone(),
                role: "retained".to_owned(),
                permission: permission("team", "create"),
            })
            .await?;
        for expired in [true, false] {
            let session = ctx
                .session_manager()
                .create_session(&user, None, None)
                .await?;
            if expired {
                ctx.database
                    .update_session_expiry(
                        &session.token,
                        chrono::Utc::now() - chrono::Duration::seconds(1),
                    )
                    .await?;
            } else {
                ctx.database.delete_session(&session.token).await?;
            }
            let denied = call(&plugin, &ctx, Some(&session.token), HttpMethod::Post, "/organization/update-role",
            Some(json!({"organizationId":org,"roleId":role.id,"data":{"permission":{"team":["delete"]}}})), &[]).await?;
            assert_error(&denied, 401, "UNAUTHORIZED")?;
            let persisted = ctx
                .database
                .get_organization_role(&org, &OrganizationRoleSelector::Id(role.id.clone()))
                .await?
                .ok_or("Role missing")?;
            assert_eq!(
                serde_json::from_str::<OrganizationPermissions>(persisted.permission.as_str())?,
                permission("team", "create")
            );
            assert_eq!(persisted.updated_at, None);
            assert_eq!(ctx.database.count_organization_roles(&org).await?, 1);
        }
        let allowed = call(&plugin, &ctx, Some(&owner.token), HttpMethod::Post, "/organization/update-role",
        Some(json!({"organizationId":org,"roleId":role.id,"data":{"permission":{"team":["update"]}}})), &[]).await?;
        assert_eq!(allowed.status, 200);
        assert_eq!(
            serde_json::from_str::<OrganizationPermissions>(
                ctx.database
                    .get_organization_role(&org, &OrganizationRoleSelector::Id(role.id))
                    .await?
                    .ok_or("Role missing")?
                    .permission
                    .as_str()
            )?,
            permission("team", "update")
        );
        Ok(())
    }
}
// LCOV_EXCL_STOP
