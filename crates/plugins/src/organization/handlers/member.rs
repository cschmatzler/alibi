use super::page::OrganizationPageError;
use super::{require_session, resolve_organization_id};
use crate::organization::OrganizationConfig;
use crate::organization::policy::{read_page_limit, truthy_number};
use crate::organization::types::{
    BasicMemberResponse, GetActiveMemberRoleQuery, GetActiveMemberRoleResponse, ListMembersQuery,
    ListMembersResponse, MemberResponse, OrganizationMemberRemovalSnapshot, RemoveMemberRequest,
    RemovedMemberResponse, UpdateMemberRoleRequest,
};
use alibi_core::entity::{AuthMember, AuthOrganization, AuthSession, AuthUser};
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::plugin::AuthContext;
use alibi_core::store::MemberPageQuery;
use alibi_core::types::{AuthRequest, AuthResponse};
use std::collections::HashMap;

fn has_role(member: &impl AuthMember, role: &str) -> bool {
    member
        .role()
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == role)
}

// Source update inputs and the removal requester-owner guard use JS trim.
// Other stored role checks and generic RoleInput normalization remain separate.
fn js_role_trim(role: &str) -> &str {
    role.trim_matches(|character| {
        matches!(character,
            '\u{0009}'..='\u{000D}' | '\u{0020}' | '\u{00A0}' | '\u{1680}' |
            '\u{2000}'..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' |
            '\u{205F}' | '\u{3000}' | '\u{FEFF}')
    })
}

fn normalized_update_roles(role: &super::super::types::RoleInput) -> Vec<&str> {
    let inputs = match role {
        super::super::types::RoleInput::One(role) => std::slice::from_ref(role),
        super::super::types::RoleInput::Many(roles) => roles.as_slice(),
    };
    inputs
        .iter()
        .flat_map(|role_2| role_2.split(','))
        .map(js_role_trim)
        .filter(|role_3| !role_3.is_empty())
        .collect()
}

pub(crate) async fn get_active_member_core(
    user: &impl AuthUser,
    session: &impl AuthSession,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<MemberResponse> {
    let org_id = session
        .active_organization_id()
        .ok_or_else(|| AuthError::bad_request("No active organization"))?;

    let member = ctx
        .database
        .get_member(org_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    Ok(MemberResponse::from_member_and_user(&member, user))
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "Preserve JavaScript Number rounding at the compatibility boundary"
)]
pub(crate) async fn list_members_core(
    query: &ListMembersQuery,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> Result<ListMembersResponse, OrganizationPageError> {
    let org_id = if let Some(slug) = query.organization_slug.as_deref() {
        let organization = ctx
            .database
            .get_organization_by_slug(slug)
            .await?
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
        organization.id().to_string()
    } else {
        resolve_organization_id(query.organization_id.as_deref(), None, session, ctx).await?
    };

    drop(
        ctx.database
            .get_member(&org_id, &user.id())
            .await?
            .ok_or_else(|| AuthError::forbidden("You are not a member of this organization"))?,
    );

    let member_params = MemberPageQuery {
        organization_id: org_id,
        limit: Some(
            query
                .limit
                .filter(|limit| truthy_number(*limit))
                .unwrap_or_else(|| read_page_limit(config.membership_limit.as_ref())),
        ),
        offset: Some(
            query
                .offset
                .filter(|offset| truthy_number(*offset))
                .unwrap_or(0.0),
        ),
        sort_by: query.sort_by.clone(),
        sort_direction: query.sort_direction.clone(),
        filter_field: query.filter_field.clone(),
        filter_value: query.filter_value.clone(),
        filter_operator: query.filter_operator.clone(),
    };
    let (members_raw, total) = ctx
        .database
        .query_organization_members_page(&member_params)
        .await?;
    let user_ids = members_raw
        .iter()
        .map(|member| member.user_id.clone())
        .collect::<Vec<_>>();
    let users_by_id = ctx
        .database
        .list_users_by_ids_page(&user_ids, members_raw.len() as f64)
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

    Ok(ListMembersResponse { members, total })
}

pub(crate) async fn get_active_member_role_core(
    query: &GetActiveMemberRoleQuery,
    user: &impl AuthUser,
    session: &impl AuthSession,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<GetActiveMemberRoleResponse> {
    let org_id = if let Some(slug) = query.organization_slug.as_deref() {
        let organization = ctx
            .database
            .get_organization_by_slug(slug)
            .await?
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
        organization.id().to_string()
    } else {
        resolve_organization_id(query.organization_id.as_deref(), None, session, ctx).await?
    };

    let requester_member = ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::forbidden("You are not a member of this organization"))?;

    if let Some(user_id) = query.user_id.as_deref() {
        let target_member = ctx
            .database
            .get_member(&org_id, user_id)
            .await?
            .ok_or_else(|| AuthError::forbidden("You are not a member of this organization"))?;
        return Ok(GetActiveMemberRoleResponse {
            role: target_member.role().to_owned(),
        });
    }

    Ok(GetActiveMemberRoleResponse {
        role: requester_member.role().to_owned(),
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep ownership checks and membership removal callbacks adjacent to their writes"
)]
pub(crate) async fn remove_member_core(
    body: &RemoveMemberRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<RemovedMemberResponse<OrganizationMemberRemovalSnapshot>> {
    let org_id = body
        .organization_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .or_else(|| session.active_organization_id())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| super::extension_common::org_error(400, "NO_ACTIVE_ORGANIZATION"))?;

    let requester_member = ctx
        .database
        .get_member(org_id, &user.id())
        .await?
        .ok_or_else(|| super::extension_common::org_error(400, "MEMBER_NOT_FOUND"))?;

    let by_email = body.member_id_or_email.contains('@');
    let target_member = if by_email {
        let target_user = ctx
            .database
            .get_user_by_email(&body.member_id_or_email)
            .await?
            .filter(|target| {
                target.email() == Some(body.member_id_or_email.to_lowercase().as_str())
            })
            .ok_or_else(|| super::extension_common::org_error(400, "MEMBER_NOT_FOUND"))?;
        ctx.database
            .get_member(org_id, &target_user.id())
            .await?
            .ok_or_else(|| super::extension_common::org_error(400, "MEMBER_NOT_FOUND"))?
    } else {
        ctx.database
            .get_member_by_id(&body.member_id_or_email)
            .await?
            .ok_or_else(|| super::extension_common::org_error(400, "MEMBER_NOT_FOUND"))?
    };

    let creator_role = config.effective_creator_role();
    if target_member
        .role()
        .split(',')
        .any(|role| role == creator_role)
    {
        if !requester_member
            .role()
            .split(',')
            .map(js_role_trim)
            .any(|role| role == creator_role)
        {
            return Err(super::extension_common::org_error(
                400,
                "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
            ));
        }
        let page = ctx
            .database
            .query_organization_members_page(&MemberPageQuery {
                organization_id: org_id.into(),
                limit: Some(read_page_limit(config.membership_limit.as_ref())),
                ..Default::default()
            })
            .await?
            .0;
        if page
            .iter()
            .filter(|candidate| candidate.role().split(',').any(|role| role == creator_role))
            .count()
            <= 1
        {
            return Err(super::extension_common::org_error(
                400,
                "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
            ));
        }
    }
    if !super::extension_common::has_action(
        requester_member.role(),
        "member",
        "delete",
        config,
        ctx,
        org_id,
    )
    .await?
    {
        return Err(super::extension_common::org_error(
            401,
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER",
        ));
    }
    if target_member.organization_id() != org_id {
        return Err(super::extension_common::org_error(400, "MEMBER_NOT_FOUND"));
    }
    let organization = ctx
        .database
        .get_organization_by_id(org_id)
        .await?
        .ok_or_else(|| super::extension_common::org_error(400, "ORGANIZATION_NOT_FOUND"))?;
    let target_user = ctx
        .database
        .get_user_by_id(&target_member.user_id())
        .await?
        .ok_or_else(|| AuthError::Api {
            status: 400,
            code: None,
            message: "User not found".into(),
        })?;
    let is_self_removal = target_member.user_id() == user.id();
    let response = RemovedMemberResponse {
        member: OrganizationMemberRemovalSnapshot {
            user: by_email.then(|| alibi_core::entity::MemberUserView::from_user(&target_user)),
            member: target_member.clone(),
        },
    };
    let original = if let Some(hooks) = &config.member_removal_hooks {
        let original = super::super::OrganizationMemberRemovalContext {
            member: response.member.clone(),
            user: ctx.user_view(&target_user),
            organization: super::super::types::OrganizationResponse::from_stored_organization(
                &organization,
            )?,
        };
        hooks.before_remove(&original).await?;
        Some(original)
    } else {
        None
    };

    ctx.database
        .delete_member_with_context(
            &target_member.id(),
            org_id,
            &target_member.user_id(),
            config.teams.enabled,
        )
        .await?;

    if is_self_removal && session.active_organization_id() == Some(org_id) {
        drop(
            ctx.database
                .update_session_active_organization_record(session.token(), None)
                .await?,
        );
    }

    if let (Some(hooks), Some(original)) = (&config.member_removal_hooks, original) {
        hooks.after_remove(&original).await?;
    }

    Ok(response)
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep role authorization and before/after callbacks adjacent to the membership write"
)]
pub(crate) async fn update_member_role_core(
    body: &UpdateMemberRoleRequest,
    organization_id: &str,
    user: &impl AuthUser,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<BasicMemberResponse> {
    let org_id = organization_id.to_owned();

    let requester_member = ctx
        .database
        .get_member(&org_id, &user.id())
        .await?
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    if !has_role(&requester_member, config.effective_creator_role())
        && !super::extension_common::has_action(
            requester_member.role(),
            "member",
            "update",
            config,
            ctx,
            &org_id,
        )
        .await?
    {
        return Err(AuthError::forbidden(
            "You are not allowed to update this member",
        ));
    }

    let target_member = ctx
        .database
        .get_member_by_id(&body.member_id)
        .await?
        .ok_or_else(|| AuthError::bad_request("Member not found"))?;

    if target_member.organization_id() != org_id {
        return Err(AuthError::forbidden(
            "You are not allowed to update this member",
        ));
    }

    let requester_is_owner = has_role(&requester_member, config.effective_creator_role());
    let target_is_owner = has_role(&target_member, config.effective_creator_role());
    let new_role = normalized_update_roles(&body.role).join(",");
    let new_role_contains_owner = new_role
        .split(',')
        .any(|role| role == config.effective_creator_role());

    if (new_role_contains_owner || target_is_owner) && !requester_is_owner {
        return Err(AuthError::forbidden(
            "You are not allowed to update this member",
        ));
    }

    if target_is_owner && requester_member.id() == target_member.id() && !new_role_contains_owner {
        let all_members = ctx.database.list_organization_members(&org_id).await?;
        let owner_count = all_members
            .iter()
            .filter(|candidate| has_role(*candidate, config.effective_creator_role()))
            .count();

        if owner_count <= 1 {
            return Err(AuthError::bad_request(
                "You cannot leave the organization without an owner",
            ));
        }
    }

    let mut valid_roles = std::collections::HashSet::from([
        "owner".to_owned(),
        "admin".to_owned(),
        "member".to_owned(),
    ]);
    valid_roles.extend(config.roles.iter().flat_map(|roles| roles.keys().cloned()));
    if config.dynamic_access_control.enabled {
        valid_roles.extend(
            ctx.database
                .list_organization_roles(&org_id)
                .await?
                .into_iter()
                .map(|role| role.role),
        );
    }
    let unknown = normalized_update_roles(&body.role)
        .into_iter()
        .filter(|role| !valid_roles.contains(*role))
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(AuthError::bad_request(format!(
            "ROLE_NOT_FOUND: {}",
            unknown.join(", ")
        )));
    }

    if let Some(hooks) = &config.member_role_hooks {
        let organization = ctx
            .database
            .get_organization_by_id(&org_id)
            .await?
            .ok_or_else(|| super::extension_common::org_error(400, "ORGANIZATION_NOT_FOUND"))?;
        let target_user = ctx
            .database
            .get_user_by_id(&target_member.user_id)
            .await?
            .ok_or_else(|| AuthError::Api {
                status: 400,
                code: None,
                message: "User not found".into(),
            })?;
        let original = super::super::OrganizationMemberRoleContext {
            new_role: new_role.clone(),
            user: ctx.user_view(&target_user),
            organization: super::super::types::OrganizationResponse::from_stored_organization(
                &organization,
            )?,
            member: target_member,
        };
        let role = hooks
            .before_update(&original)
            .await?
            .and_then(|patch| patch.role)
            .filter(|role| !role.is_empty())
            .unwrap_or(new_role);
        let updated = ctx
            .database
            .update_member_role_if_present(&body.member_id, &role)
            .await?
            .ok_or_else(|| super::extension_common::org_error(400, "MEMBER_NOT_FOUND"))?;
        hooks
            .after_update(&super::super::OrganizationMemberRoleUpdatedContext {
                previous_role: original.member.role,
                member: updated.clone(),
                user: original.user,
                organization: original.organization,
            })
            .await?;
        return Ok(BasicMemberResponse::from_member(&updated));
    }

    let updated = ctx
        .database
        .update_member_role(&body.member_id, &new_role)
        .await?;

    Ok(BasicMemberResponse::from_member(&updated))
}

/// Handle get active member request
///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_get_active_member(
    req: &AuthRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, session) = super::extension_common::session(req, ctx).await?;
    let response = get_active_member_core(&user, &session, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle list members request
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub async fn handle_list_members(
    req: &AuthRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let (user, session) = super::extension_common::session(req, ctx).await?;
    let query = parse_query::<ListMembersQuery>(&req.query);
    let response = match list_members_core(&query, &user, &session, config, ctx).await {
        Ok(response) => response,
        Err(error) => return error.response(),
    };
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle get active member role request
///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_get_active_member_role(
    req: &AuthRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let (user, session) = super::extension_common::session(req, ctx).await?;
    let query = parse_query::<GetActiveMemberRoleQuery>(&req.query);
    let response = get_active_member_role_core(&query, &user, &session, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle remove member request
///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_remove_member(
    req: &AuthRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let body = match super::org_input::member_remove(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let (user, session) = super::extension_common::session(req, ctx).await?;
    let response = match remove_member_core(&body, &user, &session, config, ctx).await {
        Ok(response) => response,
        // The pinned HTTP endpoint returns an empty 500 for uncaught adapter
        // failures. Keep explicit application errors and nested auth unchanged.
        Err(AuthError::Database(_)) => return Ok(AuthResponse::new(500)),
        Err(error) => return Err(error),
    };
    Ok(AuthResponse::json(200, &response)?)
}

/// Handle update member role request
///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_update_member_role(
    req: &AuthRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let body = match super::org_input::member_role_update(req) {
        Ok(body) => body,
        Err(response) => return Ok(response),
    };
    // Pinned nested session middleware maps failed session retrieval to
    // Unauthorized. Scope this mapping to authentication, not later callbacks.
    let (user, session) = match require_session(req, ctx).await {
        Ok(session) => session,
        Err(AuthError::Unauthenticated) => {
            return Err(super::extension_common::org_error(401, "UNAUTHORIZED"));
        }
        Err(error) => return Err(error),
    };
    update_member_role_response(&body, &user, &session, config, ctx).await
}

/// Validate an authenticated role update with HTTP semantics and apply it.
pub(crate) async fn update_member_role_response(
    body: &UpdateMemberRoleRequest,
    user: &impl AuthUser,
    session: &alibi_core::wire::SessionView,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let empty = || {
        let mut response = AuthResponse::new(400);
        drop(response.headers.insert("content-type", "application/json"));
        response
    };
    // An empty string is falsy before organization resolution; an empty array
    // or whitespace-only string reaches resolution before role normalization.
    if matches!(&body.role, super::super::types::RoleInput::One(role) if role.is_empty()) {
        return Ok(empty());
    }
    let organization_id = body
        .organization_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .or_else(|| session.active_organization_id())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| super::extension_common::org_error(400, "NO_ACTIVE_ORGANIZATION"))?;
    if normalized_update_roles(&body.role).is_empty() {
        return Ok(empty());
    }
    let response = match update_member_role_core(body, organization_id, user, config, ctx).await {
        Err(AuthError::BadRequest(message)) if message.starts_with("ROLE_NOT_FOUND: ") => {
            return Ok(AuthResponse::json(
                400,
                &serde_json::json!({"code":"ROLE_NOT_FOUND", "message": message}),
            )?);
        }
        result => result?,
    };
    Ok(AuthResponse::json(200, &response)?)
}

/// Helper function to parse query parameters into a struct
fn parse_query<T: Default + serde::de::DeserializeOwned>(query: &HashMap<String, String>) -> T {
    let json_value = serde_json::to_value(query)
        .unwrap_or(serde_json::Value::Object(serde_json::Map::default()));
    serde_json::from_value(json_value).unwrap_or_default()
}
