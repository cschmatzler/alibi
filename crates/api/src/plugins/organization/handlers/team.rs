use super::super::extensions::{TeamHookContext, TeamLimitContext};
use super::super::{OrganizationConfig, OrganizationPlugin};
use super::extension_common::{has_action, org_error, session};
use alibi_core::entity::AuthUser;
use alibi_core::types::{AddTeamMemberResult, CreateTeam, Team, UpdateTeam};
use alibi_core::wire::{SessionView, UserView};
use alibi_core::{AuthContext, AuthRequest, AuthResponse, AuthResult, AuthSchema, HttpMethod};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[serde_with::skip_serializing_none]
#[derive(Debug, Deserialize, Serialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateTeamRequest {
    pub name: String,
    pub organization_id: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Deserialize, Serialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct RemoveTeamRequest {
    pub team_id: String,
    pub organization_id: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Deserialize, Serialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTeamRequest {
    pub team_id: String,
    pub data: UpdateTeamData,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Deserialize, Serialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTeamData {
    #[validate(length(min = 1))]
    pub name: Option<String>,
    pub organization_id: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Deserialize, Serialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct TeamMemberRequest {
    pub team_id: String,
    #[serde(
        default = "super::super::types::undefined_string",
        deserialize_with = "super::super::types::deserialize_coercible_string"
    )]
    pub user_id: String,
    pub organization_id: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct SetActiveTeamRequest {
    #[serde(
        default,
        rename = "teamId",
        deserialize_with = "super::super::types::deserialize_nullable_string_field"
    )]
    #[serde(skip_serializing_if = "super::super::types::NullableStringField::is_missing")]
    pub team_id: super::super::types::NullableStringField,
}

impl OrganizationPlugin {
    /// Controlled server-side creation; the organization is explicit and no request principal is fabricated.
    ///
    /// # Errors
    ///
    /// Returns errors from input validation, permission checks, storage, or configured organization hooks.
    pub async fn create_team<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        data: CreateTeam,
    ) -> AuthResult<Team> {
        if !self.config.teams.enabled {
            return Err(alibi_core::AuthError::NotImplemented(
                "Teams are disabled".to_owned(),
            ));
        }
        create_team_core(data, None, None, ctx, &self.config).await
    }
    /// Create a team with the actual signed-cookie principal from supplied headers.
    /// This low-level server API enforces the same organization permissions as HTTP;
    /// builder-wide dispatch hooks and API-key session injection require normal dispatch.
    ///
    /// # Errors
    /// Returns an error if authentication, authorization, policy, hooks, or storage fail.
    pub async fn create_team_with_headers<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        headers: &std::collections::HashMap<String, String>,
        data: CreateTeam,
    ) -> AuthResult<Team> {
        if !self.config.teams.enabled {
            return Err(alibi_core::AuthError::NotImplemented(
                "Teams are disabled".to_owned(),
            ));
        }
        let mut resolution = AuthRequest::new(HttpMethod::Post, "/organization/create-team");
        resolution.headers = headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect();
        let (user, current) = session(&resolution, ctx).await?;
        let user = ctx.user_view(&user);
        create_team_core(data, Some((&user, &current)), None, ctx, &self.config).await
    }

    /// Remove a team with the actual signed-cookie principal from supplied headers.
    /// Current active-team and organization permission checks also apply to server calls.
    /// This low-level helper does not execute builder-wide dispatch hooks.
    ///
    /// # Errors
    /// Returns an error if authentication, authorization, hooks, or storage fail.
    pub async fn remove_team_with_headers<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        headers: &std::collections::HashMap<String, String>,
        organization_id: &str,
        team_id: &str,
    ) -> AuthResult<()> {
        if !self.config.teams.enabled {
            return Err(alibi_core::AuthError::NotImplemented(
                "Teams are disabled".to_owned(),
            ));
        }
        let mut resolution = AuthRequest::new(HttpMethod::Post, "/organization/remove-team");
        resolution.headers = headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect();
        let (user, current) = session(&resolution, ctx).await?;
        let user = ctx.user_view(&user);
        remove_team_core(
            organization_id,
            team_id,
            Some((&user, &current)),
            ctx,
            &self.config,
        )
        .await
    }

    ///
    /// # Errors
    ///
    /// Returns errors from input validation, permission checks, storage, or configured organization hooks.
    pub async fn remove_team<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        organization_id: &str,
        team_id: &str,
    ) -> AuthResult<()> {
        if !self.config.teams.enabled {
            return Err(alibi_core::AuthError::NotImplemented(
                "Teams are disabled".to_owned(),
            ));
        }
        remove_team_core(organization_id, team_id, None, ctx, &self.config).await
    }
}

fn org_id(explicit: Option<&str>, session: Option<&SessionView>) -> AuthResult<String> {
    explicit
        .filter(|id| !id.is_empty())
        .or_else(|| {
            let s = session?;
            s.active_organization_id.as_deref()
        })
        .map(str::to_owned)
        .ok_or_else(|| org_error(400, "NO_ACTIVE_ORGANIZATION"))
}

async fn hook_context<S: AuthSchema>(
    ctx: &AuthContext<S>,
    org_id: &str,
    user: Option<UserView>,
) -> AuthResult<TeamHookContext> {
    let organization = ctx
        .database
        .get_organization_by_id(org_id)
        .await?
        .ok_or_else(|| org_error(400, "ORGANIZATION_NOT_FOUND"))?;
    Ok(TeamHookContext { organization, user })
}

///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
#[expect(
    clippy::cast_precision_loss,
    reason = "Source compares stored counts as ECMAScript Numbers"
)]
pub async fn create_team_core<S: AuthSchema>(
    mut data: CreateTeam,
    actor: Option<(&UserView, &SessionView)>,
    request: Option<&AuthRequest>,
    ctx: &AuthContext<S>,
    config: &OrganizationConfig,
) -> AuthResult<Team> {
    if let Some((user, _)) = actor {
        let member = ctx
            .database
            .get_member(&data.organization_id, &user.id)
            .await?
            .ok_or_else(|| {
                org_error(
                    403,
                    "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION",
                )
            })?;
        if !has_action(
            &member.role,
            "team",
            "create",
            config,
            ctx,
            &data.organization_id,
        )
        .await?
        {
            return Err(org_error(
                403,
                "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
            ));
        }
    }
    let limit_ctx = TeamLimitContext {
        organization_id: data.organization_id.clone(),
        team_id: None,
        session: actor.map(|(_, session)| session.clone()),
        user: actor.map(|(user, _)| user.clone()),
        request: request.cloned(),
    };
    let existing_teams = ctx.database.list_teams(&data.organization_id).await?;
    let maximum = match &config.teams.limit_resolver {
        Some(resolver) => resolver.maximum_teams(&limit_ctx).await?,
        None => config.teams.maximum_teams,
    };
    if let Some(maximum) = maximum.filter(|limit| *limit != 0.0 && !limit.is_nan())
        && existing_teams.len() as f64 >= maximum
    {
        return Err(org_error(
            400,
            "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS",
        ));
    }
    let hooks = hook_context(
        ctx,
        &data.organization_id,
        actor.map(|(user, _)| user.clone()),
    )
    .await?;
    // The HTTP endpoint's timestamp is chosen after the awaited policy and
    // organization lookup, as Source constructs teamData at that point.
    // Trusted native calls retain any explicitly supplied timestamp.
    if request.is_some() {
        data.updated_at = Some(chrono::Utc::now());
    }
    if let Some(callback) = &config.teams.hooks {
        callback
            .before_create(&mut data, &hooks)
            .await
            .map_err(super::super::extensions::team_callback_error)?;
    }
    let team = ctx.database.create_team(data).await?;
    if let Some(callback) = &config.teams.hooks {
        callback
            .after_create(&team, &hooks)
            .await
            .map_err(super::super::extensions::team_callback_error)?;
    }
    Ok(team)
}

///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn remove_team_core<S: AuthSchema>(
    organization_id: &str,
    team_id: &str,
    actor: Option<(&UserView, &SessionView)>,
    ctx: &AuthContext<S>,
    config: &OrganizationConfig,
) -> AuthResult<()> {
    if let Some((user, session)) = actor {
        let member = ctx
            .database
            .get_member(organization_id, &user.id)
            .await?
            .ok_or_else(|| org_error(403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM"))?;
        if session.active_team_id.as_deref() == Some(team_id) {
            return Err(org_error(403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM"));
        }
        if !has_action(&member.role, "team", "delete", config, ctx, organization_id).await? {
            return Err(org_error(
                403,
                "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION",
            ));
        }
    }
    let team = ctx
        .database
        .get_team(Some(organization_id), team_id)
        .await?
        .ok_or_else(|| org_error(400, "TEAM_NOT_FOUND"))?;
    if !config.teams.allow_removing_all_teams
        && ctx.database.list_teams(organization_id).await?.len() <= 1
    {
        return Err(org_error(400, "UNABLE_TO_REMOVE_LAST_TEAM"));
    }
    let hooks = hook_context(ctx, organization_id, actor.map(|(user, _)| user.clone())).await?;
    if let Some(callback) = &config.teams.hooks {
        callback
            .before_delete(&team, &hooks)
            .await
            .map_err(super::super::extensions::team_callback_error)?;
    }
    let _ignored_delete_team = ctx.database.delete_team(organization_id, team_id).await?;
    if let Some(callback) = &config.teams.hooks {
        callback
            .after_delete(&team, &hooks)
            .await
            .map_err(super::super::extensions::team_callback_error)?;
    }
    Ok(())
}

///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_team_request<S: AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
    config: &OrganizationConfig,
) -> AuthResult<Option<AuthResponse>> {
    let is_known = matches!(
        (req.method(), req.path()),
        (
            HttpMethod::Post,
            "/organization/create-team"
                | "/organization/update-team"
                | "/organization/remove-team"
                | "/organization/set-active-team"
                | "/organization/add-team-member"
                | "/organization/remove-team-member"
        ) | (
            HttpMethod::Get,
            "/organization/list-teams"
                | "/organization/list-user-teams"
                | "/organization/list-team-members"
        )
    );
    if !config.teams.enabled || !is_known {
        return Ok(None);
    }
    let (user, current) = session(req, ctx).await?;
    team_core(
        req.method(),
        req.path(),
        None,
        &req.query,
        user,
        current,
        Some(req),
        true,
        ctx,
        config,
    )
    .await
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep team endpoint dispatch and each organization ownership check adjacent to its writes"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "Shared execution keeps logical input, original request metadata, authenticated authority, and installed configuration separate"
)]
pub(in crate::plugins::organization) async fn team_core<S: AuthSchema>(
    method: &HttpMethod,
    path: &str,
    input: Option<serde_json::Value>,
    query: &std::collections::HashMap<String, String>,
    user: alibi_core::AuthenticatedUser<S>,
    current: SessionView,
    request: Option<&AuthRequest>,
    http_input: bool,
    ctx: &AuthContext<S>,
    config: &OrganizationConfig,
) -> AuthResult<Option<AuthResponse>> {
    if !config.teams.enabled {
        return Err(org_error(404, "TEAMS_DISABLED"));
    }
    let user_view = ctx.user_view(&user);
    macro_rules! body {
        ($ty:ty) => {
            if let Some(request) = request.filter(|_| http_input) {
                match alibi_core::validate_request_body::<$ty>(request) {
                    Ok(body) => body,
                    Err(response) => return Ok(Some(response)),
                }
            } else {
                let body: $ty =
                    serde_json::from_value(input.clone().unwrap_or(serde_json::Value::Null))
                        .map_err(|error| crate::plugins::endpoint::validation(error.to_string()))?;
                body.validate()
                    .map_err(|error| crate::plugins::endpoint::validation(error.to_string()))?;
                body
            }
        };
    }
    let response = match (method, path) {
        (HttpMethod::Post, "/organization/create-team") => {
            let body = body!(CreateTeamRequest);
            let org = org_id(body.organization_id.as_deref(), Some(&current))?;
            let team = create_team_core(
                CreateTeam {
                    name: body.name,
                    organization_id: org,
                    updated_at: Some(chrono::Utc::now()),
                },
                Some((&user_view, &current)),
                request,
                ctx,
                config,
            )
            .await?;
            AuthResponse::json(200, &team)?
        }
        (HttpMethod::Post, "/organization/remove-team") => {
            let body = body!(RemoveTeamRequest);
            let org = org_id(body.organization_id.as_deref(), Some(&current))?;
            remove_team_core(
                &org,
                &body.team_id,
                Some((&user_view, &current)),
                ctx,
                config,
            )
            .await?;
            AuthResponse::json(
                200,
                &serde_json::json!({"message":"Team removed successfully."}),
            )?
        }
        (HttpMethod::Post, "/organization/update-team") => {
            let body = body!(UpdateTeamRequest);
            if body.data.name.as_deref() == Some("") {
                return Ok(Some(AuthResponse::json(
                    400,
                    &serde_json::json!({"code":"VALIDATION_ERROR","message":"[body.data.name] Too small: expected string to have >=1 characters"}),
                )?));
            }
            let org = org_id(body.data.organization_id.as_deref(), Some(&current))?;
            let member = ctx
                .database
                .get_member(&org, user.id().as_ref())
                .await?
                .ok_or_else(|| org_error(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM"))?;
            if !has_action(&member.role, "team", "update", config, ctx, &org).await? {
                return Err(org_error(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM"));
            }
            let team = ctx
                .database
                .get_team(Some(&org), &body.team_id)
                .await?
                .ok_or_else(|| org_error(400, "TEAM_NOT_FOUND"))?;
            let hooks = hook_context(ctx, &org, Some(user_view)).await?;
            let mut updates = UpdateTeam {
                name: body.data.name,
            };
            if let Some(callback) = &config.teams.hooks {
                callback
                    .before_update(&team, &mut updates, &hooks)
                    .await
                    .map_err(super::super::extensions::team_callback_error)?;
            }
            let team_2 = ctx
                .database
                .update_team(&org, &body.team_id, updates)
                .await?;
            if let Some(callback) = &config.teams.hooks {
                callback
                    .after_update(&team_2, &hooks)
                    .await
                    .map_err(super::super::extensions::team_callback_error)?;
            }
            AuthResponse::json(200, &team_2)?
        }
        (HttpMethod::Get, "/organization/list-teams") => {
            let org = org_id(
                query.get("organizationId").map(String::as_str),
                Some(&current),
            )?;
            if ctx
                .database
                .get_member(&org, user.id().as_ref())
                .await?
                .is_none()
            {
                return Err(org_error(
                    403,
                    "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION",
                ));
            }
            AuthResponse::json(200, &ctx.database.list_teams(&org).await?)?
        }
        (HttpMethod::Get, "/organization/list-user-teams") => {
            let target = query
                .get("userId")
                .filter(|id| !id.is_empty())
                .map_or(user_view.id.as_str(), String::as_str);
            let explicit = query
                .get("organizationId")
                .filter(|id| !id.is_empty())
                .map(String::as_str);
            let scope = if target == user_view.id {
                explicit.map(str::to_owned)
            } else {
                Some(org_id(explicit, Some(&current))?)
            };
            if let Some(org) = &scope {
                let requester = ctx
                    .database
                    .get_member(org, &user_view.id)
                    .await?
                    .ok_or_else(|| org_error(403, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION"))?;
                if target != user_view.id {
                    if !has_action(&requester.role, "member", "update", config, ctx, org).await? {
                        return Err(org_error(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER"));
                    }
                    if ctx.database.get_member(org, target).await?.is_none() {
                        return Err(org_error(400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"));
                    }
                }
            }
            let mut teams = Vec::new();
            for team in ctx.database.list_user_teams(target).await? {
                if scope
                    .as_deref()
                    .is_some_and(|org| team.organization_id != org)
                {
                    continue;
                }
                if ctx
                    .database
                    .get_member(&team.organization_id, target)
                    .await?
                    .is_some()
                {
                    teams.push(team);
                }
            }
            AuthResponse::json(200, &teams)?
        }
        (HttpMethod::Get, "/organization/list-team-members") => {
            let team_id = query
                .get("teamId")
                .filter(|id| !id.is_empty())
                .map(String::as_str)
                .or(current.active_team_id.as_deref())
                .ok_or_else(|| org_error(400, "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM"))?;
            let team = ctx
                .database
                .get_team(None, team_id)
                .await?
                .ok_or_else(|| org_error(400, "TEAM_NOT_FOUND"))?;
            if ctx
                .database
                .get_member(&team.organization_id, &user_view.id)
                .await?
                .is_none()
                || ctx
                    .database
                    .get_team_member(team_id, &user_view.id)
                    .await?
                    .is_none()
            {
                return Err(org_error(400, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM"));
            }
            AuthResponse::json(200, &ctx.database.list_team_members(team_id).await?)?
        }
        (HttpMethod::Post, "/organization/set-active-team") => {
            use super::super::types::NullableStringField;
            let body = body!(SetActiveTeamRequest);
            let team_id = match body.team_id {
                NullableStringField::Null => None,
                NullableStringField::Missing => current.active_team_id.clone(),
                NullableStringField::Value(value) => {
                    if value.is_empty() {
                        current.active_team_id.clone()
                    } else {
                        Some(value)
                    }
                }
            };
            if team_id.is_none() {
                let mut response = AuthResponse::json(200, &serde_json::Value::Null)?;
                if current.active_team_id.is_some() {
                    let updated = ctx
                        .database
                        .update_session_active_team_record(&current.token, None)
                        .await?;
                    response.headers.append(
                        "set-cookie",
                        alibi_core::utils::cookie_utils::create_session_cookie(
                            alibi_core::AuthSession::token(&updated),
                            &ctx.config,
                        )?,
                    );
                }
                response
            } else {
                let team_id = team_id
                    .as_deref()
                    .ok_or_else(|| org_error(400, "TEAM_NOT_FOUND"))?;
                let org = org_id(None, Some(&current))?;
                let team = ctx
                    .database
                    .get_team(Some(&org), team_id)
                    .await?
                    .ok_or_else(|| org_error(400, "TEAM_NOT_FOUND"))?;
                if ctx
                    .database
                    .get_team_member(team_id, &user_view.id)
                    .await?
                    .is_none()
                {
                    return Err(org_error(403, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM"));
                }
                let updated = ctx
                    .database
                    .update_session_active_team_record(&current.token, Some(team_id))
                    .await?;
                AuthResponse::json(200, &team)?.with_header(
                    "set-cookie",
                    alibi_core::utils::cookie_utils::create_session_cookie(
                        alibi_core::AuthSession::token(&updated),
                        &ctx.config,
                    )?,
                )
            }
        }
        (
            HttpMethod::Post,
            "/organization/add-team-member" | "/organization/remove-team-member",
        ) => {
            let body = body!(TeamMemberRequest);
            let org = org_id(body.organization_id.as_deref(), Some(&current))?;
            let requester = ctx
                .database
                .get_member(&org, &user_view.id)
                .await?
                .ok_or_else(|| org_error(400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"))?;
            let add = path.ends_with("/add-team-member");
            let action = if add { "update" } else { "delete" };
            if !has_action(&requester.role, "member", action, config, ctx, &org).await? {
                return Err(org_error(
                    403,
                    if add {
                        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER"
                    } else {
                        "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER"
                    },
                ));
            }
            if ctx
                .database
                .get_member(&org, &body.user_id)
                .await?
                .is_none()
            {
                return Err(org_error(400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"));
            }
            let team = ctx
                .database
                .get_team(Some(&org), &body.team_id)
                .await?
                .ok_or_else(|| org_error(400, "TEAM_NOT_FOUND"))?;
            let target = ctx
                .database
                .get_user_by_id(&body.user_id)
                .await?
                .ok_or_else(|| alibi_core::AuthError::bad_request("User not found"))?;
            let target = ctx.user_view(&target);
            let hooks = hook_context(ctx, &org, Some(user_view)).await?;
            if add {
                if let Some(callback) = &config.teams.hooks {
                    callback
                        .before_add_member(&team, &target, &hooks)
                        .await
                        .map_err(super::super::extensions::team_callback_error)?;
                }
                let limit_ctx = TeamLimitContext {
                    organization_id: org,
                    team_id: Some(team.id.clone()),
                    session: Some(current),
                    user: hooks.user.clone(),
                    request: None,
                };
                let maximum = match &config.teams.limit_resolver {
                    Some(resolver) => resolver.maximum_team_members(&limit_ctx).await?,
                    None => config.teams.maximum_members_per_team,
                };
                let member = match ctx
                    .database
                    .add_team_member(&team.id, &body.user_id, maximum)
                    .await?
                {
                    AddTeamMemberResult::Added(member) | AddTeamMemberResult::Existing(member) => {
                        member
                    }
                    AddTeamMemberResult::LimitReached => {
                        return Err(org_error(403, "TEAM_MEMBER_LIMIT_REACHED"));
                    }
                };
                if let Some(callback) = &config.teams.hooks {
                    callback
                        .after_add_member(&member, &team, &target, &hooks)
                        .await
                        .map_err(super::super::extensions::team_callback_error)?;
                }
                AuthResponse::json(200, &member)?
            } else {
                let member = ctx
                    .database
                    .get_team_member(&team.id, &body.user_id)
                    .await?
                    .ok_or_else(|| org_error(400, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM"))?;
                if let Some(callback) = &config.teams.hooks {
                    callback
                        .before_remove_member(&member, &team, &target, &hooks)
                        .await
                        .map_err(super::super::extensions::team_callback_error)?;
                }
                let _ignored_remove_team_member = ctx
                    .database
                    .remove_team_member(&team.id, &body.user_id)
                    .await?;
                if let Some(callback) = &config.teams.hooks {
                    callback
                        .after_remove_member(&member, &team, &target, &hooks)
                        .await
                        .map_err(super::super::extensions::team_callback_error)?;
                }
                AuthResponse::json(
                    200,
                    &serde_json::json!({"message":"Team member removed successfully."}),
                )?
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(response))
}
