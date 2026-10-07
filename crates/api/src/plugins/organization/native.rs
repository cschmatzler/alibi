//! Typed logical organization operations, independent of HTTP request construction.
use super::{OrganizationPlugin, handlers, types};
use crate::plugins::endpoint::{definition, error_response, validation};
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::entity::{AuthOrganization, AuthUser};
use alibi_core::session::SessionRequest;
use alibi_core::types::{Team, TeamMember};
use alibi_core::utils::json::JsValue;
use alibi_core::wire::InvitationView;
use alibi_core::{AuthContext, AuthError, AuthResponse, AuthResult, AuthSchema, HttpMethod};

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        definition(
            "listOrganizations",
            "listOrganizations",
            Some("/organization/list"),
            HttpMethod::Get,
        ),
        definition(
            "updateOrganization",
            "updateOrganization",
            Some("/organization/update"),
            HttpMethod::Post,
        ),
        definition(
            "getOrganization",
            "getOrganization",
            Some("/organization/get-organization"),
            HttpMethod::Get,
        ),
        definition(
            "getFullOrganization",
            "getFullOrganization",
            Some("/organization/get-full-organization"),
            HttpMethod::Get,
        ),
        definition(
            "checkOrganizationSlug",
            "checkOrganizationSlug",
            Some("/organization/check-slug"),
            HttpMethod::Post,
        ),
        definition(
            "setActiveOrganization",
            "setActiveOrganization",
            Some("/organization/set-active"),
            HttpMethod::Post,
        ),
        definition(
            "leaveOrganization",
            "leaveOrganization",
            Some("/organization/leave"),
            HttpMethod::Post,
        ),
        definition(
            "inviteMember",
            "inviteMember",
            Some("/organization/invite-member"),
            HttpMethod::Post,
        ),
        definition(
            "getInvitation",
            "getInvitation",
            Some("/organization/get-invitation"),
            HttpMethod::Get,
        ),
        definition(
            "listInvitations",
            "listInvitations",
            Some("/organization/list-invitations"),
            HttpMethod::Get,
        ),
        definition(
            "listUserInvitations",
            "listUserInvitations",
            Some("/organization/list-user-invitations"),
            HttpMethod::Get,
        ),
        definition(
            "acceptInvitation",
            "acceptInvitation",
            Some("/organization/accept-invitation"),
            HttpMethod::Post,
        ),
        definition(
            "rejectInvitation",
            "rejectInvitation",
            Some("/organization/reject-invitation"),
            HttpMethod::Post,
        ),
        definition(
            "cancelInvitation",
            "cancelInvitation",
            Some("/organization/cancel-invitation"),
            HttpMethod::Post,
        ),
        definition(
            "getActiveMember",
            "getActiveMember",
            Some("/organization/get-active-member"),
            HttpMethod::Get,
        ),
        definition(
            "getActiveMemberRole",
            "getActiveMemberRole",
            Some("/organization/get-active-member-role"),
            HttpMethod::Get,
        ),
        definition(
            "listMembers",
            "listMembers",
            Some("/organization/list-members"),
            HttpMethod::Get,
        ),
        definition(
            "updateMemberRole",
            "updateMemberRole",
            Some("/organization/update-member-role"),
            HttpMethod::Post,
        ),
        definition(
            "hasPermission",
            "hasPermission",
            Some("/organization/has-permission"),
            HttpMethod::Post,
        ),
        definition(
            "createTeam",
            "createTeam",
            Some("/organization/create-team"),
            HttpMethod::Post,
        ),
        definition(
            "updateTeam",
            "updateTeam",
            Some("/organization/update-team"),
            HttpMethod::Post,
        ),
        definition(
            "removeTeam",
            "removeTeam",
            Some("/organization/remove-team"),
            HttpMethod::Post,
        ),
        definition(
            "setActiveTeam",
            "setActiveTeam",
            Some("/organization/set-active-team"),
            HttpMethod::Post,
        ),
        definition(
            "addTeamMember",
            "addTeamMember",
            Some("/organization/add-team-member"),
            HttpMethod::Post,
        ),
        definition(
            "removeTeamMember",
            "removeTeamMember",
            Some("/organization/remove-team-member"),
            HttpMethod::Post,
        ),
        definition(
            "listTeams",
            "listTeams",
            Some("/organization/list-teams"),
            HttpMethod::Get,
        ),
        definition(
            "listUserTeams",
            "listUserTeams",
            Some("/organization/list-user-teams"),
            HttpMethod::Get,
        ),
        definition(
            "listTeamMembers",
            "listTeamMembers",
            Some("/organization/list-team-members"),
            HttpMethod::Get,
        ),
        definition(
            "createOrganizationRole",
            "createOrganizationRole",
            Some("/organization/create-role"),
            HttpMethod::Post,
        ),
        definition(
            "updateOrganizationRole",
            "updateOrganizationRole",
            Some("/organization/update-role"),
            HttpMethod::Post,
        ),
        definition(
            "deleteOrganizationRole",
            "deleteOrganizationRole",
            Some("/organization/delete-role"),
            HttpMethod::Post,
        ),
        definition(
            "getOrganizationRole",
            "getOrganizationRole",
            Some("/organization/get-role"),
            HttpMethod::Get,
        ),
        definition(
            "listOrganizationRoles",
            "listOrganizationRoles",
            Some("/organization/list-roles"),
            HttpMethod::Get,
        ),
    ]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    // Native calls validate logical values after before hooks, without media-type or URL decoding.
    match call.operation_id() {
        "updateOrganization" => {
            drop(handlers::org_input::update_value(call.body().cloned()).map_err(error_response)?);
        }
        "getOrganization" => {
            let _: types::GetOrganizationQuery = call
                .query_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "getFullOrganization" => {
            let _: types::GetFullOrganizationQuery = call
                .query_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "checkOrganizationSlug" => {
            let _: types::CheckSlugRequest = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "setActiveOrganization" => {
            drop(
                handlers::org_input::set_active_value(call.body().cloned())
                    .map_err(error_response)?,
            );
        }
        "leaveOrganization" => {
            let _: types::LeaveOrganizationRequest = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "inviteMember" => {
            drop(
                handlers::org_input::invitation_create_value(call.body().cloned())
                    .map_err(error_response)?,
            );
        }
        "getInvitation" => {
            let _: types::GetInvitationQuery = call
                .query_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "listInvitations" => {
            let _: types::ListInvitationsQuery = call
                .query_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "listUserInvitations" => {
            let _: types::ListUserInvitationsQuery = call
                .query_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "acceptInvitation" => {
            let _: types::AcceptInvitationRequest = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "rejectInvitation" => {
            let _: types::RejectInvitationRequest = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "cancelInvitation" => {
            let _: types::CancelInvitationRequest = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "getActiveMemberRole" => {
            let _: types::GetActiveMemberRoleQuery = call
                .query_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "listMembers" => {
            let _: types::ListMembersQuery = call
                .query_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "updateMemberRole" => {
            drop(
                handlers::org_input::member_role_update_value(call.body().cloned())
                    .map_err(error_response)?,
            );
        }
        "hasPermission" => {
            let _: types::HasPermissionRequest = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "createTeam" => {
            let _: types::CreateTeamRequest = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "updateTeam" => {
            let _: types::UpdateTeamRequest = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "removeTeam" => {
            let _: types::RemoveTeamRequest = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "setActiveTeam" => {
            let _: types::SetActiveTeamRequest = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "addTeamMember" => {
            let _: types::TeamMemberRequest = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "removeTeamMember" => {
            let _: types::TeamMemberRequest = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "listTeams" => {
            let _: types::TeamQuery = call
                .query_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "listUserTeams" => {
            let _: types::TeamQuery = call
                .query_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "listTeamMembers" => {
            let _: types::TeamQuery = call
                .query_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "createOrganizationRole" => {
            let _: types::CreateRoleRequest = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "updateOrganizationRole" => {
            let _: types::UpdateRoleRequest = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "deleteOrganizationRole" => {
            let _: types::RoleQuery = call
                .body_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "getOrganizationRole" => {
            let _: types::RoleQuery = call
                .query_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        "listOrganizationRoles" => {
            let _: types::RoleQuery = call
                .query_as()
                .map_err(|error| validation(error.to_string()))?;
        }
        _ => {}
    }
    Ok(EndpointInput {
        body: call.body().cloned(),
        query: call.query().cloned(),
    })
}

impl OrganizationPlugin {
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    #[must_use]
    pub fn list_organizations_endpoint() -> ServerEndpoint<Vec<types::OrganizationResponse>> {
        ServerEndpoint::new("organization", "listOrganizations")
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn update_endpoint(
        input: &types::UpdateOrganizationRequest,
    ) -> AuthResult<ServerEndpoint<Option<types::CreatedOrganizationResponse>>> {
        ServerEndpoint::new("organization", "updateOrganization").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn get_organization_endpoint(
        input: &types::GetOrganizationQuery,
    ) -> AuthResult<ServerEndpoint<Option<types::OrganizationResponse>>> {
        ServerEndpoint::new("organization", "getOrganization").with_query(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn get_full_organization_endpoint(
        input: &types::GetFullOrganizationQuery,
    ) -> AuthResult<
        ServerEndpoint<
            Option<types::FullOrganizationResponse<types::OrganizationResponse, InvitationView>>,
        >,
    > {
        ServerEndpoint::new("organization", "getFullOrganization").with_query(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn check_slug_endpoint(
        input: &types::CheckSlugRequest,
    ) -> AuthResult<ServerEndpoint<types::CheckSlugResponse>> {
        ServerEndpoint::new("organization", "checkOrganizationSlug").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn set_active_endpoint(
        input: &types::SetActiveOrganizationRequest,
    ) -> AuthResult<ServerEndpoint<Option<types::OrganizationResponse>>> {
        ServerEndpoint::new("organization", "setActiveOrganization").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn leave_endpoint(
        input: &types::LeaveOrganizationRequest,
    ) -> AuthResult<ServerEndpoint<types::SuccessResponse>> {
        ServerEndpoint::new("organization", "leaveOrganization").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn invite_member_endpoint(
        input: &types::InviteMemberRequest,
    ) -> AuthResult<ServerEndpoint<InvitationView>> {
        ServerEndpoint::new("organization", "inviteMember").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn get_invitation_endpoint(
        input: &types::GetInvitationQuery,
    ) -> AuthResult<ServerEndpoint<types::GetInvitationResponse<InvitationView>>> {
        ServerEndpoint::new("organization", "getInvitation").with_query(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn list_invitations_endpoint(
        input: &types::ListInvitationsQuery,
    ) -> AuthResult<ServerEndpoint<Vec<InvitationView>>> {
        ServerEndpoint::new("organization", "listInvitations").with_query(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn list_user_invitations_endpoint(
        input: &types::ListUserInvitationsQuery,
    ) -> AuthResult<ServerEndpoint<Vec<types::UserInvitationResponse<InvitationView>>>> {
        ServerEndpoint::new("organization", "listUserInvitations").with_query(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn accept_invitation_endpoint(
        input: &types::AcceptInvitationRequest,
    ) -> AuthResult<
        ServerEndpoint<types::AcceptInvitationResponse<InvitationView, types::BasicMemberResponse>>,
    > {
        ServerEndpoint::new("organization", "acceptInvitation").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn reject_invitation_endpoint(
        input: &types::RejectInvitationRequest,
    ) -> AuthResult<
        ServerEndpoint<
            types::AcceptInvitationResponse<InvitationView, Option<types::BasicMemberResponse>>,
        >,
    > {
        ServerEndpoint::new("organization", "rejectInvitation").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn cancel_invitation_endpoint(
        input: &types::CancelInvitationRequest,
    ) -> AuthResult<ServerEndpoint<InvitationView>> {
        ServerEndpoint::new("organization", "cancelInvitation").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    #[must_use]
    pub fn get_active_member_endpoint() -> ServerEndpoint<types::MemberResponse> {
        ServerEndpoint::new("organization", "getActiveMember")
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn get_active_member_role_endpoint(
        input: &types::GetActiveMemberRoleQuery,
    ) -> AuthResult<ServerEndpoint<types::GetActiveMemberRoleResponse>> {
        ServerEndpoint::new("organization", "getActiveMemberRole").with_query(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn list_members_endpoint(
        input: &types::ListMembersQuery,
    ) -> AuthResult<ServerEndpoint<types::ListMembersResponse>> {
        ServerEndpoint::new("organization", "listMembers").with_query(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn update_member_role_endpoint(
        input: &types::UpdateMemberRoleRequest,
    ) -> AuthResult<ServerEndpoint<types::BasicMemberResponse>> {
        ServerEndpoint::new("organization", "updateMemberRole").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn has_permission_endpoint(
        input: &types::HasPermissionRequest,
    ) -> AuthResult<ServerEndpoint<types::HasPermissionResponse>> {
        ServerEndpoint::new("organization", "hasPermission").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn create_team_endpoint(
        input: &types::CreateTeamRequest,
    ) -> AuthResult<ServerEndpoint<Team>> {
        ServerEndpoint::new("organization", "createTeam").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn update_team_endpoint(
        input: &types::UpdateTeamRequest,
    ) -> AuthResult<ServerEndpoint<Team>> {
        ServerEndpoint::new("organization", "updateTeam").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn remove_team_endpoint(
        input: &types::RemoveTeamRequest,
    ) -> AuthResult<ServerEndpoint<types::MessageResponse>> {
        ServerEndpoint::new("organization", "removeTeam").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn set_active_team_endpoint(
        input: &types::SetActiveTeamRequest,
    ) -> AuthResult<ServerEndpoint<Option<Team>>> {
        ServerEndpoint::new("organization", "setActiveTeam").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn add_team_member_endpoint(
        input: &types::TeamMemberRequest,
    ) -> AuthResult<ServerEndpoint<TeamMember>> {
        ServerEndpoint::new("organization", "addTeamMember").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn remove_team_member_endpoint(
        input: &types::TeamMemberRequest,
    ) -> AuthResult<ServerEndpoint<types::MessageResponse>> {
        ServerEndpoint::new("organization", "removeTeamMember").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn list_teams_endpoint(input: &types::TeamQuery) -> AuthResult<ServerEndpoint<Vec<Team>>> {
        ServerEndpoint::new("organization", "listTeams").with_query(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn list_user_teams_endpoint(
        input: &types::TeamQuery,
    ) -> AuthResult<ServerEndpoint<Vec<Team>>> {
        ServerEndpoint::new("organization", "listUserTeams").with_query(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn list_team_members_endpoint(
        input: &types::TeamQuery,
    ) -> AuthResult<ServerEndpoint<Vec<TeamMember>>> {
        ServerEndpoint::new("organization", "listTeamMembers").with_query(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn create_role_endpoint(
        input: &types::CreateRoleRequest,
    ) -> AuthResult<ServerEndpoint<types::CreateRoleResponse>> {
        ServerEndpoint::new("organization", "createOrganizationRole").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn update_role_endpoint(
        input: &types::UpdateRoleRequest,
    ) -> AuthResult<ServerEndpoint<types::UpdateRoleResponse>> {
        ServerEndpoint::new("organization", "updateOrganizationRole").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn delete_role_endpoint(
        input: &types::RoleQuery,
    ) -> AuthResult<ServerEndpoint<types::SuccessResponse>> {
        ServerEndpoint::new("organization", "deleteOrganizationRole").with_body(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn get_role_endpoint(
        input: &types::RoleQuery,
    ) -> AuthResult<ServerEndpoint<types::RoleResponse>> {
        ServerEndpoint::new("organization", "getOrganizationRole").with_query(input)
    }
    /// Construct a typed native call through installed dispatch hooks.
    /// # Errors
    /// Returns a serialization error for input that cannot be represented.
    pub fn list_roles_endpoint(
        input: &types::RoleQuery,
    ) -> AuthResult<ServerEndpoint<Vec<types::RoleResponse>>> {
        ServerEndpoint::new("organization", "listOrganizationRoles").with_query(input)
    }
}

fn response(output: AuthResponse) -> AuthResult<EndpointResponse> {
    let value = if output.body.is_empty() {
        JsValue::Null
    } else {
        alibi_core::utils::json::from_slice::<JsValue>(&output.body)?
    };
    let mut response = if output.status >= 400 {
        EndpointResponse::error(error_response(output.clone())).with_error_body(value)
    } else {
        EndpointResponse::value(value)
    };
    response.set_status(Some(output.status));
    response.merge_headers(output.headers);
    Ok(response)
}

fn query_pairs(call: &EndpointCall) -> AuthResult<std::collections::HashMap<String, String>> {
    call.query()
        .and_then(JsValue::as_object)
        .map(|fields| {
            fields
                .iter()
                .map(|(key, value)| {
                    value
                        .coerce_string()
                        .map(|value| (key.clone(), value))
                        .map_err(validation)
                })
                .collect()
        })
        .unwrap_or_else(|| Ok(Default::default()))
}

pub(super) async fn execute<S: AuthSchema>(
    plugin: &OrganizationPlugin,
    call: &EndpointCall,
    ctx: &AuthContext<S>,
) -> AuthResult<EndpointResponse> {
    let config = &plugin.config;
    if call.operation_id() == "listUserInvitations" {
        let query: types::ListUserInvitationsQuery = call.query_as()?;
        if let Some(email) = query.email.as_deref().filter(|email| !email.is_empty()) {
            if call.request().is_some() {
                return Err(AuthError::bad_request(
                    "User email cannot be passed for client side API calls.",
                ));
            }
            return EndpointResponse::json(
                &handlers::invitation::list_user_invitations_for_email_core(email, ctx).await?,
            );
        }
    }
    let (user, session) = ctx.require_cached_session(call).await.map_err(|error| {
        if matches!(
            error,
            AuthError::Unauthenticated | AuthError::SessionNotFound
        ) {
            handlers::extension_common::org_error(401, "UNAUTHORIZED")
        } else {
            error
        }
    })?;
    match call.operation_id() {
        "listOrganizations" => {
            EndpointResponse::json(&handlers::org::list_organizations_core(&user, ctx).await?)
        }
        "updateOrganization" => {
            let (body, metadata) =
                handlers::org_input::update_value(call.body().cloned()).map_err(error_response)?;
            EndpointResponse::json(
                &handlers::org::update_organization_core(
                    &body, metadata, &user, &session, config, ctx,
                )
                .await?,
            )
        }
        "getOrganization" => {
            let query: types::GetOrganizationQuery = call.query_as()?;
            let organization =
                if let Some(slug) = query.organization_slug.as_deref().filter(|s| !s.is_empty()) {
                    ctx.database.get_organization_by_slug(slug).await?
                } else if let Some(id) = query
                    .organization_id
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .or(session.active_organization_id.as_deref())
                {
                    ctx.database.get_organization_by_id(id).await?
                } else {
                    return EndpointResponse::json(&Option::<types::OrganizationResponse>::None);
                }
                .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
            if ctx
                .database
                .get_member(&organization.id(), &user.id())
                .await?
                .is_none()
            {
                drop(
                    ctx.database
                        .update_session_active_organization_record(&session.token, None)
                        .await?,
                );
                return Err(AuthError::forbidden(
                    "User is not a member of the organization",
                ));
            }
            EndpointResponse::json(&types::OrganizationResponse::from_stored_organization(
                &organization,
            )?)
        }
        "getFullOrganization" => EndpointResponse::json(
            &handlers::org::get_full_organization_core(
                &call.query_as()?,
                &user,
                &session,
                config,
                ctx,
            )
            .await
            .map_err(AuthError::from)?,
        ),
        "checkOrganizationSlug" => {
            EndpointResponse::json(&handlers::org::check_slug_core(&call.body_as()?, ctx).await?)
        }
        "setActiveOrganization" => {
            let body = handlers::org_input::set_active_value(call.body().cloned())
                .map_err(error_response)?;
            let organization =
                handlers::org::set_active_organization_core(&body, &user, &session, ctx).await?;
            if organization.is_some()
                || session
                    .active_organization_id
                    .as_deref()
                    .is_some_and(|id| !id.is_empty())
            {
                use alibi_core::utils::cookie_utils::{
                    create_session_cookie_with_max_age, create_session_like_cookie,
                    related_cookie_name, sign_cookie_value, verify_cookie_value,
                };
                let preference = related_cookie_name(&ctx.config, "dont_remember");
                let dont_remember = call.session_headers().get("cookie").is_some_and(|header| {
                    cookie::Cookie::split_parse(header)
                        .flatten()
                        .find(|cookie| cookie.name() == preference)
                        .and_then(|cookie| {
                            verify_cookie_value(cookie.value(), ctx.config.current_secret())
                        })
                        .is_some_and(|value| !value.is_empty())
                });
                call.queue_response_header(
                    "set-cookie",
                    create_session_cookie_with_max_age(
                        Some(&session.token),
                        (!dont_remember).then(|| ctx.config.session.expires_in.num_seconds()),
                        &ctx.config,
                    )?,
                );
                if dont_remember {
                    call.queue_response_header(
                        "set-cookie",
                        create_session_like_cookie(
                            &preference,
                            &sign_cookie_value("true", ctx.config.current_secret()),
                            None,
                            &ctx.config,
                        )?,
                    );
                }
            }
            EndpointResponse::json(&organization)
        }
        "leaveOrganization" => EndpointResponse::json(
            &handlers::org::leave_organization_core(&call.body_as()?, &user, &session, config, ctx)
                .await?,
        ),
        "inviteMember" => {
            let body = handlers::org_input::invitation_create_value(call.body().cloned())
                .map_err(error_response)?;
            EndpointResponse::json(
                &handlers::invitation::invite_member_core(&body, &user, &session, config, ctx)
                    .await?,
            )
        }
        "getInvitation" => EndpointResponse::json(
            &handlers::invitation::get_invitation_core(&call.query_as()?, &user, config, ctx)
                .await?,
        ),
        "listInvitations" => EndpointResponse::json(
            &handlers::invitation::list_invitations_core(&call.query_as()?, &user, &session, ctx)
                .await?,
        ),
        "listUserInvitations" => EndpointResponse::json(
            &handlers::invitation::list_user_invitations_core(&user, ctx).await?,
        ),
        "acceptInvitation" => {
            let transport = handlers::invitation_acceptance::AcceptanceTransport::native(call);
            let result = handlers::invitation_acceptance::accept(
                &call.body_as()?,
                &user,
                &session,
                config,
                ctx,
                &transport,
            )
            .await;
            if matches!(result, Err(AuthError::Internal(_) | AuthError::Database(_))) {
                transport.discard_cookies();
            }
            EndpointResponse::json(&result?)
        }
        "rejectInvitation" => EndpointResponse::json(
            &handlers::invitation::reject_invitation_core(&call.body_as()?, &user, config, ctx)
                .await?,
        ),
        "cancelInvitation" => EndpointResponse::json(
            &handlers::invitation::cancel_invitation_core(&call.body_as()?, &user, config, ctx)
                .await?,
        ),
        "getActiveMember" => EndpointResponse::json(
            &handlers::member::get_active_member_core(&user, &session, ctx).await?,
        ),
        "getActiveMemberRole" => EndpointResponse::json(
            &handlers::member::get_active_member_role_core(&call.query_as()?, &user, &session, ctx)
                .await?,
        ),
        "listMembers" => EndpointResponse::json(
            &handlers::member::list_members_core(&call.query_as()?, &user, &session, config, ctx)
                .await
                .map_err(AuthError::from)?,
        ),
        "updateMemberRole" => {
            let body = handlers::org_input::member_role_update_value(call.body().cloned())
                .map_err(error_response)?;
            response(
                handlers::member::update_member_role_response(&body, &user, &session, config, ctx)
                    .await?,
            )
        }
        "hasPermission" => EndpointResponse::json(
            &handlers::has_permission_core(&call.body_as()?, &user, &session, config, ctx).await?,
        ),
        "createTeam" | "updateTeam" | "removeTeam" | "setActiveTeam" | "addTeamMember"
        | "removeTeamMember" | "listTeams" | "listUserTeams" | "listTeamMembers" => {
            let path = match call.operation_id() {
                "createTeam" => "/organization/create-team",
                "updateTeam" => "/organization/update-team",
                "removeTeam" => "/organization/remove-team",
                "setActiveTeam" => "/organization/set-active-team",
                "addTeamMember" => "/organization/add-team-member",
                "removeTeamMember" => "/organization/remove-team-member",
                "listTeams" => "/organization/list-teams",
                "listUserTeams" => "/organization/list-user-teams",
                "listTeamMembers" => "/organization/list-team-members",
                _ => return Err(AuthError::not_found("Unknown operation")),
            };
            let method = call.default_method();
            let query = query_pairs(call)?;
            let body = call
                .body()
                .map(JsValue::to_json_value)
                .transpose()
                .map_err(|error| validation(error.to_string()))?;
            let result = handlers::team::team_core(
                method,
                path,
                body,
                &query,
                user,
                session,
                call.request(),
                false,
                ctx,
                config,
            )
            .await?;
            response(result.ok_or_else(|| AuthError::not_found("Unknown operation"))?)
        }
        "createOrganizationRole"
        | "updateOrganizationRole"
        | "deleteOrganizationRole"
        | "getOrganizationRole"
        | "listOrganizationRoles" => {
            let path = match call.operation_id() {
                "createOrganizationRole" => "/organization/create-role",
                "updateOrganizationRole" => "/organization/update-role",
                "deleteOrganizationRole" => "/organization/delete-role",
                "getOrganizationRole" => "/organization/get-role",
                "listOrganizationRoles" => "/organization/list-roles",
                _ => return Err(AuthError::not_found("Unknown operation")),
            };
            let method = call.default_method();
            let query = query_pairs(call)?;
            let body = call
                .body()
                .map(JsValue::to_json_value)
                .transpose()
                .map_err(|error| validation(error.to_string()))?
                .and_then(|value| value.as_object().cloned())
                .unwrap_or_default();
            let result =
                handlers::role::role_core(method, path, body, &query, call, ctx, config).await?;
            response(result.ok_or_else(|| AuthError::not_found("Unknown operation"))?)
        }
        _ => Err(AuthError::not_found("Unregistered organization operation")),
    }
}
