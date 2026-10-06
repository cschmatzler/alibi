use super::page::OrganizationPageError;
use super::require_session;
use crate::plugins::organization::OrganizationConfig;
use crate::plugins::organization::policy::{read_page_limit, truthy_number};
use crate::plugins::organization::types::{
    BasicMemberResponse, CheckSlugRequest, CheckSlugResponse, CreateOrganizationRequest,
    CreateOrganizationResponse, CreatedOrganizationResponse, DeleteOrganizationRequest,
    FullOrganizationResponse, GetFullOrganizationQuery, LeaveOrganizationRequest, MemberResponse,
    NullableStringField, OrganizationResponse, SetActiveOrganizationRequest,
    UpdateOrganizationRequest,
};
use better_auth_core::entity::{AuthMember, AuthOrganization, AuthSession, AuthUser};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::store::MemberPageQuery;
use better_auth_core::types::{
    AuthRequest, AuthResponse, CreateMember, CreateOrganization, UpdateOrganization,
};
use better_auth_core::wire::{InvitationView, SessionView};
use std::collections::HashMap;

fn has_role(member: &impl AuthMember, role: &str) -> bool {
    member
        .role()
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == role)
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

#[expect(
    clippy::too_many_lines,
    reason = "Keep organization quotas, creation callbacks, and initial membership in request order"
)]
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn create_organization_core(
    body: &CreateOrganizationRequest,
    user: &impl AuthUser,
    request: Option<&AuthRequest>,
    session: Option<&SessionView>,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<CreateOrganizationResponse<CreatedOrganizationResponse, BasicMemberResponse>> {
    let callback_user = ctx.user_view(user);
    let allowed = match &config.creation_policy {
        Some(policy) => policy.allow_creation(&callback_user).await?,
        None => None,
    }
    .unwrap_or(config.allow_user_to_create_organization);
    let system_action = request.is_none() && session.is_none();
    if !allowed && !system_action {
        return Err(super::extension_common::org_error(
            403,
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION",
        ));
    }

    // Upstream lists all memberships before evaluating either limit branch.
    let user_orgs = ctx.database.list_user_organizations(&user.id()).await?;
    let reached = match &config.creation_policy {
        Some(policy) => policy.limit_reached(&callback_user).await?,
        None => None,
    }
    .unwrap_or_else(|| {
        config.organization_limit.is_some_and(|limit| {
            #[expect(
                clippy::as_conversions,
                clippy::cast_precision_loss,
                reason = "JavaScript compares adapter array length as a Number"
            )]
            let count = user_orgs.len() as f64;
            count >= limit
        })
    });
    if reached {
        return Err(super::extension_common::org_error(
            403,
            "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS",
        ));
    }

    if ctx
        .database
        .get_organization_by_slug(&body.slug)
        .await?
        .is_some()
    {
        return Err(super::extension_common::org_error(
            400,
            "ORGANIZATION_ALREADY_EXISTS",
        ));
    }

    let mut org_data = CreateOrganization {
        additional_fields: config
            .organization_fields
            .parse_create(&body.additional_fields)
            .map_err(organization_field_error)?,
        id: None,
        name: body.name.clone(),
        slug: body.slug.clone(),
        logo: body.logo.clone(),
        metadata: body.metadata.clone(),
    };
    if let Some(hooks) = &config.creation_hooks {
        let context = super::super::hooks::organization::OrganizationDraftContext {
            organization: org_data.clone(),
            user: callback_user.clone(),
        };
        if let Some(patch) = hooks.before_create(&context).await? {
            patch.apply(&mut org_data);
        }
    }

    let organization = ctx.database.create_organization(org_data).await?;

    let mut member_data = CreateMember {
        organization_id: organization.id().to_string(),
        user_id: user.id().to_string(),
        role: config.effective_creator_role().to_owned(),
    };
    if let Some(hooks) = &config.creation_hooks {
        let context = super::super::hooks::organization::OrganizationMemberDraftContext {
            organization: organization.clone(),
            member: member_data.clone(),
            user: callback_user.clone(),
        };
        if let Some(patch) = hooks.before_add_member(&context).await? {
            patch.apply(&mut member_data);
        }
    }

    let member = ctx.database.create_member(member_data).await?;
    let created_context = super::super::hooks::organization::OrganizationCreatedContext {
        organization: organization.clone(),
        member: member.clone(),
        user: callback_user,
    };
    if let Some(hooks) = &config.creation_hooks {
        hooks.after_add_member(&created_context).await?;
    }
    let member_response = BasicMemberResponse::from_member(&member);
    let default_team_id = if config.teams.enabled && config.teams.create_default_team {
        let mut data = better_auth_core::types::CreateTeam {
            name: organization.name().to_owned(),
            organization_id: organization.id().into_owned(),
            updated_at: None,
        };
        let hooks = crate::plugins::organization::extensions::TeamHookContext {
            organization: organization.clone(),
            user: Some(ctx.user_view(user)),
        };
        if let Some(callback) = &config.teams.hooks {
            callback
                .before_create(&mut data, &hooks)
                .await
                .map_err(crate::plugins::organization::extensions::team_callback_error)?;
        }
        let custom = match &config.teams.default_team_factory {
            Some(factory) => {
                let factory_context =
                    crate::plugins::organization::extensions::DefaultTeamContext {
                        request: request.cloned(),
                        user: ctx.user_view(user),
                        session: session.cloned(),
                        config: std::sync::Arc::clone(&ctx.config),
                    };
                factory
                    .create(&organization, &factory_context, ctx.database.as_ref())
                    .await
                    .map_err(crate::plugins::organization::extensions::team_callback_error)?
            }
            None => None,
        };
        let team = match custom {
            Some(team) => team,
            None => ctx.database.create_team(data).await?,
        };
        drop(
            ctx.database
                .add_team_member(&team.id, user.id().as_ref(), None)
                .await?,
        );
        if let Some(callback) = &config.teams.hooks {
            callback
                .after_create(&team, &hooks)
                .await
                .map_err(crate::plugins::organization::extensions::team_callback_error)?;
        }
        Some(team.id)
    } else {
        None
    };

    if let Some(hooks) = &config.creation_hooks {
        hooks.after_create(&created_context).await?;
    }
    Ok(CreateOrganizationResponse {
        organization: CreatedOrganizationResponse::from_organization(&organization),
        members: vec![member_response],
        default_team_id,
    })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn update_organization_core(
    body: &UpdateOrganizationRequest,
    raw_metadata: Option<indexmap::IndexMap<String, better_auth_core::utils::json::JsValue>>,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Option<CreatedOrganizationResponse>> {
    let org_id = body
        .organization_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .or_else(|| session.active_organization_id().filter(|id| !id.is_empty()))
        .ok_or_else(|| super::extension_common::org_error(400, "ORGANIZATION_NOT_FOUND"))?
        .to_owned();

    let member = ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .ok_or_else(|| {
            super::extension_common::org_error(400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
        })?;

    if !super::extension_common::has_action(
        member.role(),
        "organization",
        "update",
        config,
        ctx,
        &org_id,
    )
    .await?
    {
        return Err(super::extension_common::org_error(
            403,
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION",
        ));
    }

    if let Some(ref new_slug) = body.data.slug
        && let Some(existing) = ctx.database.get_organization_by_slug(new_slug).await?
        && existing.id() != org_id
    {
        return Err(super::extension_common::org_error(
            400,
            "ORGANIZATION_SLUG_ALREADY_TAKEN",
        ));
    }

    let mut update_data = UpdateOrganization {
        additional_fields: config
            .organization_fields
            .parse_update(&body.data.additional_fields)
            .map_err(organization_field_error)?,
        name: body.data.name.clone(),
        slug: body.data.slug.clone(),
        logo: body.data.logo.clone(),
        metadata: body.data.metadata.clone(),
    };

    if let Some(hooks) = &config.update_hooks {
        let original = super::super::OrganizationUpdateContext {
            organization: super::super::OrganizationUpdateInput {
                name: update_data.name.clone(),
                slug: update_data.slug.clone(),
                logo: update_data.logo.clone(),
                metadata: raw_metadata,
            },
            user: ctx.user_view(user),
            member,
        };
        if let Some(patch) = hooks.before_update(&original).await? {
            patch.apply(&mut update_data)?;
        }
        let organization = ctx
            .database
            .update_organization_if_present(&org_id, update_data)
            .await?
            .as_ref()
            .map(CreatedOrganizationResponse::from_organization);
        hooks
            .after_update(&super::super::OrganizationUpdatedContext {
                organization: organization.clone(),
                user: original.user,
                member: original.member,
            })
            .await?;
        return Ok(organization);
    }
    let updated = ctx
        .database
        .patch_organization_if_present(&org_id, update_data)
        .await?;

    Ok(updated
        .as_ref()
        .map(CreatedOrganizationResponse::from_organization))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn delete_organization_core(
    body: &DeleteOrganizationRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    invocation: crate::plugins::organization::hooks::organization::DeleteInvocation<'_>,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Option<OrganizationResponse>> {
    if config.disable_organization_deletion {
        return Err(super::extension_common::org_error(
            404,
            "ORGANIZATION_DELETION_DISABLED",
        ));
    }

    if body.organization_id.is_empty() {
        return Err(super::extension_common::org_error(
            400,
            "ORGANIZATION_NOT_FOUND",
        ));
    }

    let member = ctx
        .database
        .get_member(&body.organization_id, &user.id())
        .await?
        .ok_or_else(|| {
            super::extension_common::org_error(400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
        })?;

    if !super::extension_common::has_action(
        member.role(),
        "organization",
        "delete",
        config,
        ctx,
        body.organization_id.as_str(),
    )
    .await?
    {
        return Err(super::extension_common::org_error(
            403,
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION",
        ));
    }

    if session.active_organization_id() == Some(body.organization_id.as_str()) {
        drop(
            ctx.database
                .update_session_active_organization_record(session.token(), None)
                .await?,
        );
    }
    let Some(organization) = ctx
        .database
        .get_organization_by_id(&body.organization_id)
        .await?
    else {
        return Ok(None);
    };

    let original = OrganizationResponse::from_stored_organization(&organization)?;
    let callback = crate::plugins::organization::OrganizationDeleteContext {
        organization: original.clone(),
        user: ctx.user_view(user),
        session: ctx.session_view(session),
        headers: invocation.headers.clone(),
        request: invocation.request.map(|request| {
            AuthRequest::from_parts(
                request.method.clone(),
                request.path.clone(),
                request.headers.clone(),
                request.body.clone(),
                request.query.clone(),
            )
        }),
    };
    if let Some(hooks) = &config.deletion_hooks {
        hooks.before_delete(&callback).await?;
    }
    ctx.database
        .delete_organization(&body.organization_id)
        .await?;
    if let Some(hooks) = &config.deletion_hooks {
        hooks.after_delete(&callback).await?;
    }
    Ok(Some(original))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn list_organizations_core(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<OrganizationResponse>> {
    let organizations = ctx.database.list_user_organizations(&user.id()).await?;
    let responses = organizations
        .iter()
        .map(OrganizationResponse::from_stored_organization)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(responses)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "Preserve JavaScript Number rounding at the compatibility boundary"
)]
pub(in crate::plugins) async fn get_full_organization_core(
    query: &GetFullOrganizationQuery,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<
    Option<FullOrganizationResponse<OrganizationResponse, InvitationView>>,
    OrganizationPageError,
> {
    let org_id = if let Some(slug) = query
        .organization_slug
        .as_deref()
        .filter(|slug| !slug.is_empty())
    {
        let organization = ctx
            .database
            .get_organization_by_slug(slug)
            .await?
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
        organization.id().to_string()
    } else if let Some(id) = query.organization_id.as_deref().filter(|id| !id.is_empty()) {
        id.to_owned()
    } else if let Some(active_org_id) = session.active_organization_id() {
        active_org_id.to_owned()
    } else {
        return Ok(None);
    };

    let organization = ctx
        .database
        .get_organization_by_id(&org_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;

    let members_limit = query
        .members_limit
        .filter(|limit| truthy_number(*limit))
        .unwrap_or(ctx.config.advanced.database.default_find_many_limit as f64);
    let member_params = MemberPageQuery {
        organization_id: org_id.clone(),
        limit: Some(members_limit),
        ..Default::default()
    };
    let (members_raw, _) = ctx
        .database
        .query_organization_members_page(&member_params)
        .await?;
    let user_ids = members_raw
        .iter()
        .map(|member| member.user_id.clone())
        .collect::<Vec<_>>();
    let users_by_id = ctx
        .database
        .list_users_by_ids_page(&user_ids, read_page_limit(config.membership_limit.as_ref()))
        .await?
        .into_iter()
        .map(|user_2| (user_2.id().to_string(), user_2))
        .collect::<HashMap<_, _>>();
    let mut members = Vec::with_capacity(members_raw.len());

    for member in &members_raw {
        let user_info = users_by_id
            .get(&member.user_id)
            .ok_or(OrganizationPageError::MissingUser)?;
        members.push(MemberResponse::from_member_and_user(member, user_info));
    }

    let invitations = ctx.database.list_organization_invitations(&org_id).await?;

    let response = FullOrganizationResponse {
        organization: OrganizationResponse::from_stored_organization(&organization)
            .map_err(AuthError::from)?,
        members,
        invitations: invitations
            .iter()
            .map(|invitation| ctx.invitation_view(invitation))
            .collect(),
        teams: if config.teams.enabled {
            Some(
                ctx.database
                    .list_teams(&org_id)
                    .await?
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            )
        } else {
            None
        },
    };
    if ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .is_none()
    {
        drop(
            ctx.database
                .update_session_active_organization_record(session.token(), None)
                .await?,
        );
        return Err(AuthError::forbidden("User is not a member of the organization").into());
    }

    Ok(Some(response))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn check_slug_core(
    body: &CheckSlugRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<CheckSlugResponse> {
    if ctx
        .database
        .get_organization_by_slug(&body.slug)
        .await?
        .is_some()
    {
        return Err(AuthError::bad_request("Organization slug already taken"));
    }

    Ok(CheckSlugResponse { status: true })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn set_active_organization_core(
    body: &SetActiveOrganizationRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Option<OrganizationResponse>> {
    if matches!(body.organization_id, NullableStringField::Null) {
        if session
            .active_organization_id()
            .as_ref()
            .is_none_or(|id| id.is_empty())
        {
            return Ok(None);
        }

        drop(
            ctx.database
                .update_session_active_organization_record(session.token(), None)
                .await?,
        );
        return Ok(None);
    }

    let explicit_id = match &body.organization_id {
        NullableStringField::Value(id) if !id.is_empty() => Some(id.as_str()),
        NullableStringField::Missing
        | NullableStringField::Null
        | NullableStringField::Value(_) => None,
    };
    let org_id = if let Some(id) = explicit_id {
        id.to_owned()
    } else if let Some(slug) = body
        .organization_slug
        .as_deref()
        .filter(|slug| !slug.is_empty())
    {
        let organization = ctx
            .database
            .get_organization_by_slug(slug)
            .await?
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
        organization.id().to_string()
    } else if let Some(active_org_id) = session.active_organization_id().filter(|id| !id.is_empty())
    {
        active_org_id.to_owned()
    } else {
        return Ok(None);
    };

    if ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .is_none()
    {
        drop(
            ctx.database
                .update_session_active_organization_record(session.token(), None)
                .await?,
        );
        return Err(super::extension_common::org_error(
            403,
            "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
        ));
    }

    let organization = ctx
        .database
        .get_organization_by_id(&org_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Organization not found"))?;

    drop(
        ctx.database
            .update_session_active_organization_record(
                session.token(),
                Some(organization.id().as_ref()),
            )
            .await?,
    );

    Ok(Some(OrganizationResponse::from_stored_organization(
        &organization,
    )?))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn leave_organization_core(
    body: &LeaveOrganizationRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<MemberResponse> {
    let member = ctx
        .database
        .get_member(&body.organization_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    if has_role(&member, config.effective_creator_role()) {
        let all_members = ctx
            .database
            .list_organization_members(&body.organization_id)
            .await?;
        let owner_count = all_members
            .iter()
            .filter(|candidate| has_role(*candidate, config.effective_creator_role()))
            .count();

        if owner_count <= 1 {
            return Err(AuthError::bad_request(
                "You cannot leave the organization as the only owner",
            ));
        }
    }

    let response = MemberResponse::from_member_and_user(&member, user);
    ctx.database.delete_member(&member.id()).await?;

    if session.active_organization_id() == Some(&body.organization_id) {
        drop(
            ctx.database
                .update_session_active_organization_record(session.token(), None)
                .await?,
        );
    }

    Ok(response)
}

// ---------------------------------------------------------------------------
// Old handlers (rewritten to call core)
// ---------------------------------------------------------------------------

/// Handle create organization request
///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_create_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let body = match super::org_input::create(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let (user, session) = match require_session(req, ctx).await {
        Ok(session) => session,
        Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
            return Ok(AuthResponse::new(401).with_header("content-type", "application/json"));
        }
        Err(error) => return Err(error),
    };
    let response =
        create_organization_core(&body, &user, Some(req), Some(&session), config, ctx).await?;
    if !body.keep_current_active_organization.unwrap_or(false) {
        drop(
            ctx.database
                .update_session_active_organization_record(
                    session.token(),
                    Some(response.organization.id.as_str()),
                )
                .await?,
        );
        if let Some(team_id) = &response.default_team_id {
            drop(
                ctx.database
                    .update_session_active_team_record(session.token(), Some(team_id))
                    .await?,
            );
        }
    }
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle update organization request
///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_update_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (body, raw_metadata) = match super::org_input::update(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let (user, session) = match require_session(req, ctx).await {
        Ok(session) => session,
        Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
            return Ok(AuthResponse::json(
                401,
                &serde_json::json!({"message":"User not found"}),
            )?);
        }
        Err(error) => return Err(error),
    };
    let updated =
        match update_organization_core(&body, raw_metadata, &user, &session, config, ctx).await {
            Ok(updated) => updated,
            Err(AuthError::Database(_)) if config.update_hooks.is_none() => {
                return Ok(AuthResponse::new(500));
            }
            Err(error) => return Err(error),
        };
    Ok(AuthResponse::json(200, &updated)?)
}

/// Handle delete organization request
///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_delete_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let body = match super::org_input::delete(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    if config.disable_organization_deletion {
        return Err(super::extension_common::org_error(
            404,
            "ORGANIZATION_DELETION_DISABLED",
        ));
    }
    let (user, session) = match require_session(req, ctx).await {
        Ok(session) => session,
        Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
            return Ok(AuthResponse::new(401).with_header("content-type", "application/json"));
        }
        Err(error) => return Err(error),
    };
    let Some(response) = delete_organization_core(
        &body,
        &user,
        &session,
        crate::plugins::organization::hooks::organization::DeleteInvocation {
            headers: &req.headers,
            request: Some(req),
        },
        config,
        ctx,
    )
    .await?
    else {
        return Ok(AuthResponse::new(400).with_header("content-type", "application/json"));
    };
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle list organizations request
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub async fn handle_list_organizations(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, _session) = super::extension_common::session(req, ctx).await?;
    let organizations = list_organizations_core(&user, ctx).await?;
    Ok(AuthResponse::json(200, &organizations)?)
}

/// Retrieve organization metadata without loading members, invitations or teams.
///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_get_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, session) = match require_session(req, ctx).await {
        Ok(session) => session,
        Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
            return Ok(AuthResponse::json(
                401,
                &better_auth_core::ErrorCodeMessageResponse {
                    code: Some("UNAUTHORIZED".into()),
                    message: "Unauthorized".into(),
                },
            )?);
        }
        Err(error) => return Err(error),
    };
    let slug = req
        .query
        .get("organizationSlug")
        .filter(|value| !value.is_empty());
    let id = req
        .query
        .get("organizationId")
        .filter(|value| !value.is_empty());
    let organization = if let Some(slug) = slug {
        ctx.database.get_organization_by_slug(slug).await?
    } else if let Some(id) = id
        .map(String::as_str)
        .or_else(|| session.active_organization_id())
    {
        ctx.database.get_organization_by_id(id).await?
    } else {
        return Ok(AuthResponse::json(
            200,
            &Option::<OrganizationResponse>::None,
        )?);
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
                .update_session_active_organization_record(session.token(), None)
                .await?,
        );
        return Err(AuthError::forbidden(
            "User is not a member of the organization",
        ));
    }
    // Metadata reads expose the stored JSON text; create/update responses parse it.
    let response = OrganizationResponse::from_stored_organization(&organization)?;
    Ok(AuthResponse::json(200, &response)?)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub async fn handle_get_full_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = super::extension_common::session(req, ctx).await?;
    let query = parse_query::<GetFullOrganizationQuery>(&req.query);
    let response = match get_full_organization_core(&query, &user, &session, config, ctx).await {
        Ok(response) => response,
        Err(error) => return error.response(),
    };
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle check slug request
///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_check_slug(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    drop(super::extension_common::session(req, ctx).await?);
    let body: CheckSlugRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let response = check_slug_core(&body, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle set active organization request
///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_set_active_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let body = match super::org_input::set_active(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let (user, session) = match require_session(req, ctx).await {
        Ok(session) => session,
        Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
            return Err(super::extension_common::org_error(401, "UNAUTHORIZED"));
        }
        Err(error) => return Err(error),
    };
    let organization = set_active_organization_core(&body, &user, &session, ctx).await?;
    let mut response = AuthResponse::json(200, &organization)?;
    // The source only writes a cookie after a selection/clear update. Its null
    // and omitted-selector early returns on an unselected session do not.
    if organization.is_some()
        || session
            .active_organization_id()
            .is_some_and(|id| !id.is_empty())
    {
        use better_auth_core::utils::cookie_utils::{
            create_session_cookie_with_max_age, create_session_like_cookie, related_cookie_name,
            sign_cookie_value, verify_cookie_value,
        };
        let preference = related_cookie_name(&ctx.config, "dont_remember");
        let dont_remember = req.header("cookie").is_some_and(|header| {
            cookie::Cookie::split_parse(header)
                .flatten()
                .find(|cookie| cookie.name() == preference)
                .and_then(|cookie| verify_cookie_value(cookie.value(), ctx.config.current_secret()))
                .is_some_and(|value| !value.is_empty())
        });
        response = response.with_appended_header(
            "Set-Cookie",
            create_session_cookie_with_max_age(
                Some(session.token()),
                if dont_remember {
                    None
                } else {
                    Some(ctx.config.session.expires_in.num_seconds())
                },
                &ctx.config,
            )?,
        );
        if dont_remember {
            response = response.with_appended_header(
                "Set-Cookie",
                create_session_like_cookie(
                    &preference,
                    &sign_cookie_value("true", ctx.config.current_secret()),
                    None,
                    &ctx.config,
                )?,
            );
        }
    }
    Ok(response)
}

/// Handle leave organization request
///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_leave_organization(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = super::extension_common::session(req, ctx).await?;
    let body: LeaveOrganizationRequest = match better_auth_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let response = leave_organization_core(&body, &user, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Helper function to parse query parameters into a struct
fn parse_query<T: Default + serde::de::DeserializeOwned>(query: &HashMap<String, String>) -> T {
    let json_value = serde_json::to_value(query)
        .unwrap_or(serde_json::Value::Object(serde_json::Map::default()));
    serde_json::from_value(json_value).unwrap_or_default()
}

fn organization_field_error(
    error: better_auth_core::field_policy::FieldInputError,
) -> better_auth_core::AuthError {
    match error {
        better_auth_core::field_policy::FieldInputError::Validation { code, message } => {
            better_auth_core::AuthError::Api {
                status: 400,
                code: Some(code.to_owned()),
                message,
            }
        }
        better_auth_core::field_policy::FieldInputError::Transform(error) => error,
    }
}

// LCOV_EXCL_START

#[cfg(test)]
mod tests {
    use super::{get_full_organization_core, handle_create_organization};
    use crate::plugins::organization::OrganizationConfig;
    use crate::plugins::organization::types::GetFullOrganizationQuery;
    use crate::plugins::organization::{DynamicAccessControlConfig, TeamsConfig};
    use crate::plugins::test_helpers::{
        create_auth_json_request_no_query, create_test_context, create_user,
        create_user_and_session,
    };
    use better_auth_core::types::{CreateOrganization, CreateUser, HttpMethod};
    use chrono::Duration;

    fn test_config() -> OrganizationConfig {
        OrganizationConfig {
            organization_fields: Default::default(),
            allow_user_to_create_organization: true,
            organization_limit: None,
            creation_policy: None,
            creation_hooks: None,
            update_hooks: None,
            member_role_hooks: None,
            member_removal_hooks: None,
            member_addition_hooks: None,
            invitation_acceptance_hooks: None,
            deletion_hooks: None,
            membership_limit: Some(crate::plugins::organization::MembershipLimit::Fixed(100.0)),
            creator_role: "owner".to_owned(),
            invitation_expires_in: Some(172_800.0),
            invitation_limit: Some(crate::plugins::organization::InvitationLimit::Fixed(100.0)),
            cancel_pending_invitations_on_reinvite: false,
            invitation_hooks: None,
            send_invitation_email: None,
            disable_organization_deletion: false,
            roles: None,
            require_email_verification_on_invitation: None,
            teams: TeamsConfig::default(),
            dynamic_access_control: DynamicAccessControlConfig::default(),
            access_control: None,
        }
    }

    fn test_user(email: &str, name: &str) -> CreateUser {
        CreateUser {
            email: Some(email.to_owned()),
            name: Some(name.to_owned()),
            ..CreateUser::default()
        }
    }

    #[tokio::test]
    async fn create_organization_keeps_current_active_organization_when_requested() {
        let ctx = create_test_context().await;
        let config = test_config();
        let (user, session) = create_user_and_session(
            &ctx,
            test_user("owner@example.com", "Owner"),
            Duration::hours(1),
        )
        .await;
        let existing = ctx
            .database
            .create_organization(CreateOrganization {
                additional_fields: Default::default(),
                id: None,
                name: "Existing".to_owned(),
                slug: "existing".to_owned(),
                logo: None,
                metadata: None,
            })
            .await
            .expect("organization should be created");
        ctx.database
            .update_session_active_organization(&session.token, Some(&existing.id))
            .await
            .expect("active organization should update");

        let request = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/organization/create",
            Some(&session.token),
            Some(serde_json::json!({
                "name": "Next",
                "slug": "next",
                "keepCurrentActiveOrganization": true
            })),
        );

        handle_create_organization(&request, &ctx, &config)
            .await
            .expect("request should succeed");

        let updated_session = ctx
            .database
            .get_session(&session.token)
            .await
            .expect("session lookup should succeed")
            .expect("session should exist");
        assert_eq!(updated_session.active_organization_id, Some(existing.id));
        assert_eq!(user.id, session.user_id);
    }

    #[tokio::test]
    async fn create_organization_updates_active_organization_by_default() {
        let ctx = create_test_context().await;
        let config = test_config();
        let (_, session) = create_user_and_session(
            &ctx,
            test_user("owner2@example.com", "Owner"),
            Duration::hours(1),
        )
        .await;

        let request = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/organization/create",
            Some(&session.token),
            Some(serde_json::json!({
                "name": "Created",
                "slug": "created"
            })),
        );

        let response = handle_create_organization(&request, &ctx, &config)
            .await
            .expect("request should succeed");
        let body: serde_json::Value =
            serde_json::from_slice(&response.body).expect("response should be JSON");
        let created_id = (*(body).get("id").unwrap_or(&serde_json::Value::Null))
            .as_str()
            .expect("response should contain organization id");

        let updated_session = ctx
            .database
            .get_session(&session.token)
            .await
            .expect("session lookup should succeed")
            .expect("session should exist");
        assert_eq!(
            updated_session.active_organization_id.as_deref(),
            Some(created_id)
        );
    }

    #[tokio::test]
    async fn get_full_organization_respects_members_limit() {
        let ctx = create_test_context().await;
        let config = test_config();
        let (user, session) = create_user_and_session(
            &ctx,
            test_user("owner3@example.com", "Owner"),
            Duration::hours(1),
        )
        .await;
        let organization = ctx
            .database
            .create_organization(CreateOrganization {
                additional_fields: Default::default(),
                id: None,
                name: "Team".to_owned(),
                slug: "team".to_owned(),
                logo: None,
                metadata: None,
            })
            .await
            .expect("organization should be created");
        ctx.database
            .create_member(better_auth_core::types::CreateMember {
                organization_id: organization.id.clone(),
                user_id: user.id.clone(),
                role: config.creator_role.clone(),
            })
            .await
            .expect("owner member should be created");

        let extra_user = create_user(&ctx, test_user("member@example.com", "Member")).await;
        ctx.database
            .create_member(better_auth_core::types::CreateMember {
                organization_id: organization.id.clone(),
                user_id: extra_user.id.clone(),
                role: "member".to_owned(),
            })
            .await
            .expect("extra member should be created");

        let response = get_full_organization_core(
            &GetFullOrganizationQuery {
                organization_id: Some(organization.id.clone()),
                organization_slug: None,
                members_limit: Some(1.0),
            },
            &user,
            &session,
            &config,
            &ctx,
        )
        .await
        .expect("request should succeed")
        .expect("organization should exist");

        assert_eq!(response.members.len(), 1);
    }
}
// LCOV_EXCL_STOP
