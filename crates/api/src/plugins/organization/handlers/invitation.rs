use better_auth_core::entity::{
    AuthInvitation, AuthMember, AuthOrganization, AuthSession, AuthUser,
};

use better_auth_core::error::{AuthError, AuthResult};

use better_auth_core::plugin::AuthContext;

use better_auth_core::types::{AuthRequest, AuthResponse, CreateInvitation, InvitationStatus};

use better_auth_core::wire::InvitationView;

use std::collections::HashMap;

use super::{require_session, resolve_organization_id};

use crate::plugins::organization::OrganizationConfig;

use crate::plugins::organization::types::{
    AcceptInvitationRequest, AcceptInvitationResponse, BasicMemberResponse,
    CancelInvitationRequest, GetInvitationQuery, GetInvitationResponse, InviteMemberRequest,
    ListInvitationsQuery, RejectInvitationRequest, UserInvitationResponse,
};

impl crate::plugins::organization::OrganizationPlugin {
    /// List pending invitations for an email through a trusted server-side call.
    ///
    /// This method accepts an application-authorized email without a session.
    /// The HTTP endpoint instead derives the email from a verified session and
    /// rejects client email selectors.
    ///
    /// # Errors
    ///
    /// Returns errors from input validation, permission checks, storage, or configured organization hooks.
    pub async fn list_user_invitations(
        &self,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
        email: &str,
    ) -> AuthResult<Vec<UserInvitationResponse<InvitationView>>> {
        list_user_invitations_for_email_core(email, ctx).await
    }
}

fn normalized_roles(input: &crate::plugins::organization::types::RoleInput) -> String {
    input.joined()
}

fn requested_roles(input: &crate::plugins::organization::types::RoleInput) -> Vec<&str> {
    input.roles()
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn require_verified_invitation_email<S: better_auth_core::AuthSchema>(
    user: &impl AuthUser,
    config: &OrganizationConfig,
    ctx: &AuthContext<S>,
    message: &'static str,
) -> AuthResult<()> {
    let required = config
        .require_email_verification_on_invitation
        .unwrap_or(ctx.config.advanced.database.use_number_id);
    if required && !user.email_verified() {
        return Err(AuthError::forbidden(message));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

#[expect(
    clippy::too_many_lines,
    reason = "Keep invitation authorization, quota checks, and delivery callbacks in their required order"
)]
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn invite_member_core(
    body: &InviteMemberRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<InvitationView> {
    let org_id =
        resolve_organization_id(body.organization_id.as_deref(), None, session, ctx).await?;

    let member = ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    if !super::extension_common::has_action(
        member.role(),
        "invitation",
        "create",
        config,
        ctx,
        &org_id,
    )
    .await?
    {
        return Err(AuthError::forbidden(
            "You don't have permission to invite members",
        ));
    }

    let roles = requested_roles(&body.role);
    if roles.is_empty() {
        return Err(AuthError::bad_request("Role is required"));
    }

    let mut valid_roles = vec!["owner".to_owned(), "admin".to_owned(), "member".to_owned()];
    valid_roles.extend(
        config
            .roles
            .iter()
            .flat_map(|roles_2| roles_2.keys().cloned()),
    );
    if config.dynamic_access_control.enabled {
        valid_roles.extend(
            ctx.database
                .list_organization_roles(&org_id)
                .await?
                .into_iter()
                .map(|role| role.role),
        );
    }

    let unknown_roles: Vec<_> = roles
        .iter()
        .copied()
        .filter(|role| !valid_roles.iter().any(|valid| valid == role))
        .collect();

    if !unknown_roles.is_empty() {
        // Upstream's invite path throws `new APIError` with the code inlined in
        // the message and no `code` field — unlike the member path, which sets
        // both. See organization/routes/crud-invites.ts.
        return Err(AuthError::bad_request(format!(
            "ROLE_NOT_FOUND: {}",
            unknown_roles.join(", ")
        )));
    }

    let member_is_creator = member
        .role()
        .split(',')
        .map(str::trim)
        .any(|role| role == config.effective_creator_role());
    let invites_creator_role = roles
        .iter()
        .any(|role| *role == config.effective_creator_role());

    if invites_creator_role && !member_is_creator {
        return Err(AuthError::forbidden(
            "You are not allowed to invite a user with this role",
        ));
    }

    if let Some(limit) = config.invitation_limit {
        let pending_count = usize::try_from(
            ctx.database
                .count_pending_organization_invitations(&org_id)
                .await?,
        )
        .map_err(|error| AuthError::Internal(error.to_string()))?;
        if pending_count >= limit {
            return Err(AuthError::Upstream {
                status: 403,
                code: "INVITATION_LIMIT_REACHED",
                message: "Invitation limit reached",
            });
        }
    }

    if let Some(existing_user) = ctx.database.get_user_by_email(&body.email).await?
        && ctx
            .database
            .get_member(&org_id, &existing_user.id())
            .await?
            .is_some()
    {
        return Err(AuthError::bad_request(
            "User is already a member of this organization",
        ));
    }

    if let Some(existing) = ctx
        .database
        .get_pending_invitation(&org_id, &body.email)
        .await?
    {
        return Ok(ctx.invitation_view(&existing));
    }

    let expires_at = chrono::Utc::now()
        + chrono::Duration::seconds(
            i64::try_from(config.invitation_expires_in)
                .map_err(|error| AuthError::Config(error.to_string()))?,
        );
    let requested_teams = if config.teams.enabled {
        body.team_id
            .as_ref()
            .map(|input| input.ids())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    for team_id in &requested_teams {
        if team_id.contains(',') {
            return Err(super::extension_common::org_error(400, "INVALID_TEAM_ID"));
        }
        let team = ctx
            .database
            .get_team(Some(&org_id), team_id)
            .await?
            .ok_or_else(|| super::extension_common::org_error(400, "TEAM_NOT_FOUND"))?;
        let limit_context = crate::plugins::organization::extensions::TeamLimitContext {
            organization_id: org_id.clone(),
            team_id: Some(team.id.clone()),
            session: Some(ctx.session_view(session)),
            user: Some(ctx.user_view(user)),
            request: None,
        };
        let maximum = match &config.teams.limit_resolver {
            Some(resolver) => resolver.maximum_team_members(&limit_context).await?,
            None => config.teams.maximum_members_per_team,
        };
        if let Some(limit) = maximum
            && ctx.database.list_team_members(team_id).await?.len() >= limit
        {
            return Err(super::extension_common::org_error(
                403,
                "TEAM_MEMBER_LIMIT_REACHED",
            ));
        }
    }

    let invitation_data = CreateInvitation {
        organization_id: org_id,
        email: body.email.to_lowercase(),
        role: normalized_roles(&body.role),
        team_id: if requested_teams.is_empty() {
            None
        } else {
            Some(requested_teams.join(","))
        },
        inviter_id: user.id().to_string(),
        expires_at,
    };

    let invitation = ctx.database.create_invitation(invitation_data).await?;
    Ok(ctx.invitation_view(&invitation))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn get_invitation_core(
    query: &GetInvitationQuery,
    user: &impl AuthUser,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<GetInvitationResponse<InvitationView>> {
    let invitation = ctx
        .database
        .get_invitation_by_id(&query.id)
        .await?
        .filter(|invitation| invitation.is_pending() && !invitation.is_expired())
        .ok_or_else(|| AuthError::bad_request("Invitation not found!"))?;
    if user
        .email()
        .is_none_or(|email| email.to_lowercase() != invitation.email().to_lowercase())
    {
        return Err(AuthError::forbidden(
            "You are not the recipient of the invitation",
        ));
    }
    require_verified_invitation_email(
        user,
        config,
        ctx,
        "Email verification required to view or list invitations for the session email",
    )?;

    let organization = ctx
        .database
        .get_organization_by_id(&invitation.organization_id())
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
    let inviter_member = ctx
        .database
        .get_member(&invitation.organization_id(), &invitation.inviter_id())
        .await?
        .ok_or_else(|| {
            AuthError::bad_request("Inviter is no longer a member of the organization")
        })?;
    let inviter = ctx
        .database
        .get_user_by_id(&inviter_member.user_id())
        .await?
        .ok_or_else(|| {
            AuthError::bad_request("Inviter is no longer a member of the organization")
        })?;

    Ok(GetInvitationResponse {
        invitation: ctx.invitation_view(&invitation),
        organization_name: organization.name().to_owned(),
        organization_slug: organization.slug().to_owned(),
        inviter_email: inviter.email().map(str::to_owned),
    })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn list_invitations_core(
    query: &ListInvitationsQuery,
    user: &impl AuthUser,
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<InvitationView>> {
    let org_id =
        resolve_organization_id(query.organization_id.as_deref(), None, session, ctx).await?;

    drop(
        ctx.database
            .get_member(&org_id, &user.id())
            .await?
            .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?,
    );

    let invitations = ctx.database.list_organization_invitations(&org_id).await?;
    Ok(invitations
        .iter()
        .map(|invitation| ctx.invitation_view(invitation))
        .collect())
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn list_user_invitations_core(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<UserInvitationResponse<InvitationView>>> {
    // Upstream refuses to list invitations for a session whose email is not
    // verified, so an unverified address cannot enumerate what it was invited to.
    if !user.email_verified() {
        return Err(AuthError::forbidden(
            "Email verification required to view or list invitations for the session email",
        ));
    }

    list_user_invitations_for_email_core(user.email().unwrap_or_default(), ctx).await
}

async fn list_user_invitations_for_email_core(
    email: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<UserInvitationResponse<InvitationView>>> {
    if email.is_empty() {
        return Err(AuthError::bad_request(
            "Missing session headers, or email query parameter.",
        ));
    }
    // The adapter's configured page limit applies before pending-state filtering.
    let invitations = ctx.database.list_user_invitations(email).await?;
    let pending = invitations
        .iter()
        .filter(|invitation| invitation.status() == &InvitationStatus::Pending)
        .collect::<Vec<_>>();
    let organization_ids = pending
        .iter()
        .map(|invitation| invitation.organization_id().into_owned())
        .collect::<Vec<_>>();
    let organizations_by_id = ctx
        .database
        .list_organizations_by_ids(&organization_ids)
        .await?
        .into_iter()
        .map(|organization| (organization.id.clone(), organization))
        .collect::<HashMap<_, _>>();
    Ok(pending
        .into_iter()
        .map(|invitation| UserInvitationResponse {
            invitation: ctx.invitation_view(invitation),
            organization_name: organizations_by_id
                .get(invitation.organization_id().as_ref())
                .map(|organization| organization.name().to_owned()),
        })
        .collect())
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn reject_invitation_core(
    body: &RejectInvitationRequest,
    user: &impl AuthUser,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AcceptInvitationResponse<InvitationView, Option<BasicMemberResponse>>> {
    let invitation = ctx
        .database
        .get_invitation_by_id(&body.invitation_id)
        .await?
        .filter(better_auth_core::Invitation::is_pending)
        .ok_or(AuthError::Upstream {
            status: 400,
            code: "INVITATION_NOT_FOUND",
            message: "Invitation not found!",
        })?;

    let user_email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User has no email"))?;

    if invitation.email().to_lowercase() != user_email.to_lowercase() {
        return Err(AuthError::forbidden(
            "You are not the recipient of the invitation",
        ));
    }
    require_verified_invitation_email(
        user,
        config,
        ctx,
        "Email verification required before accepting or rejecting invitation",
    )?;

    let updated_invitation = ctx
        .database
        .update_invitation_status(&invitation.id(), InvitationStatus::Rejected)
        .await?;

    Ok(AcceptInvitationResponse {
        invitation: ctx.invitation_view(&updated_invitation),
        member: None,
    })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn cancel_invitation_core(
    body: &CancelInvitationRequest,
    user: &impl AuthUser,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<InvitationView> {
    let invitation = ctx
        .database
        .get_invitation_by_id(&body.invitation_id)
        .await?
        .ok_or_else(|| AuthError::not_found("Invitation not found"))?;

    let member = ctx
        .database
        .get_member(invitation.organization_id().as_ref(), &user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("Not a member of this organization"))?;

    if !super::extension_common::has_action(
        member.role(),
        "invitation",
        "cancel",
        config,
        ctx,
        invitation.organization_id().as_ref(),
    )
    .await?
    {
        return Err(AuthError::forbidden(
            "You don't have permission to cancel invitations",
        ));
    }

    if !invitation.is_pending() {
        return Err(AuthError::bad_request("Invitation not found"));
    }

    let updated_invitation = ctx
        .database
        .update_invitation_status(&invitation.id(), InvitationStatus::Canceled)
        .await?;

    Ok(ctx.invitation_view(&updated_invitation))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_invite_member(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let body: InviteMemberRequest = match better_auth_core::validate_request_body(req) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let invitation = invite_member_core(&body, &user, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &invitation)?)
}

///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_get_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, _) = match require_session(req, ctx).await {
        Ok(session) => session,
        Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
            return Ok(AuthResponse::json(
                401,
                &serde_json::json!({ "message": "Not authenticated" }),
            )?);
        }
        Err(error) => return Err(error),
    };
    let query = parse_query::<GetInvitationQuery>(&req.query);
    let response = match get_invitation_core(&query, &user, config, ctx).await {
        // This endpoint uses a plain APIError upstream. Its not-found payload
        // deliberately lacks the code attached by accept/reject invitation.
        Err(AuthError::BadRequest(message)) if message == "Invitation not found!" => {
            return Ok(AuthResponse::json(
                400,
                &serde_json::json!({ "message": message }),
            )?);
        }
        result => result?,
    };
    Ok(AuthResponse::json(200, &response)?)
}

///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_list_invitations(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, session) = require_session(req, ctx).await?;
    let query = parse_query::<ListInvitationsQuery>(&req.query);
    let invitations = list_invitations_core(&query, &user, &session, ctx).await?;
    Ok(AuthResponse::json(200, &invitations)?)
}

///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_list_user_invitations(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    // An email selector is available only to trusted server-side callers.
    if req
        .query
        .get("email")
        .is_some_and(|email| !email.is_empty())
    {
        return Ok(AuthResponse::json(
            400,
            &serde_json::json!({
                "message": "User email cannot be passed for client side API calls."
            }),
        )?);
    }
    let (user, _session) = match require_session(req, ctx).await {
        Ok(session) => session,
        Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
            return Ok(AuthResponse::json(
                400,
                &serde_json::json!({
                    "message": "Missing session headers, or email query parameter."
                }),
            )?);
        }
        Err(error) => return Err(error),
    };
    let invitations = list_user_invitations_core(&user, ctx).await?;
    Ok(AuthResponse::json(200, &invitations)?)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub async fn handle_accept_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = super::extension_common::session(req, ctx).await?;
    let body: AcceptInvitationRequest = match better_auth_core::validate_request_body(req) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let transport = super::invitation_acceptance::AcceptanceTransport::new(req);
    let response =
        match super::invitation_acceptance::accept(&body, &user, &session, config, ctx, &transport)
            .await
        {
            Ok(response) => response,
            Err(AuthError::Internal(_) | AuthError::Database(_)) => {
                // The pinned HTTP boundary discards these uncaught-error cookies,
                // while explicit application API errors retain them.
                transport.discard_cookies();
                return Ok(AuthResponse::new(500));
            }
            Err(error) => return Err(error),
        };
    Ok(AuthResponse::json(200, &response)?)
}

///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_reject_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let body: RejectInvitationRequest = match better_auth_core::validate_request_body(req) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let response = reject_invitation_core(&body, &user, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_cancel_invitation(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, _session) = require_session(req, ctx).await?;
    let body: CancelInvitationRequest = match better_auth_core::validate_request_body(req) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let response = cancel_invitation_core(&body, &user, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

fn parse_query<T: Default + serde::de::DeserializeOwned>(query: &HashMap<String, String>) -> T {
    let json_value = serde_json::to_value(query)
        .unwrap_or(serde_json::Value::Object(serde_json::Map::default()));
    serde_json::from_value(json_value).unwrap_or_default()
}
