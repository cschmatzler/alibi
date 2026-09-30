use super::super::extensions::{TeamHookContext, TeamLimitContext};
use super::super::{OrganizationConfig, OrganizationPlugin};
use super::extension_common::{has_action, org_error, session};
use better_auth_core::entity::AuthUser;
use better_auth_core::types::{AddTeamMemberResult, CreateTeam, Team, UpdateTeam};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthRequest, AuthResponse, AuthResult, AuthSchema, HttpMethod,
};
use serde::Deserialize;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateTeamRequest {
    pub name: String,
    pub organization_id: Option<String>,
}
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct RemoveTeamRequest {
    pub team_id: String,
    pub organization_id: Option<String>,
}
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct UpdateTeamRequest {
    team_id: String,
    data: UpdateTeamData,
}
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct UpdateTeamData {
    #[validate(length(min = 1))]
    name: Option<String>,
    organization_id: Option<String>,
}
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
struct TeamMemberRequest {
    team_id: String,
    #[serde(
        default = "super::super::types::undefined_string",
        deserialize_with = "super::super::types::deserialize_coercible_string"
    )]
    user_id: String,
    organization_id: Option<String>,
}
#[derive(Debug, Deserialize, Validate)]
struct SetActiveRequest {
    #[serde(
        default,
        rename = "teamId",
        deserialize_with = "super::super::types::deserialize_nullable_string_field"
    )]
    team_id: super::super::types::NullableStringField,
}

fn org_id(explicit: Option<&str>, session: Option<&SessionView>) -> AuthResult<String> {
    explicit
        .filter(|id| !id.is_empty())
        .or_else(|| session.and_then(|s| s.active_organization_id.as_deref()))
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
    let maximum = match &config.teams.limit_resolver {
        Some(resolver) => resolver.maximum_teams(&limit_ctx).await?,
        None => config.teams.maximum_teams,
    };
    if let Some(maximum) = maximum.filter(|limit| *limit != 0)
        && ctx.database.list_teams(&data.organization_id).await?.len() >= maximum
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
    if let Some(callback) = &config.teams.hooks {
        callback.before_create(&mut data, &hooks).await?;
    }
    let team = ctx.database.create_team(data).await?;
    if let Some(callback) = &config.teams.hooks {
        callback.after_create(&team, &hooks).await?;
    }
    Ok(team)
}

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
        callback.before_delete(&team, &hooks).await?;
    }
    let _ = ctx.database.delete_team(organization_id, team_id).await?;
    if let Some(callback) = &config.teams.hooks {
        callback.after_delete(&team, &hooks).await?;
    }
    Ok(())
}

impl OrganizationPlugin {
    /// Controlled server-side creation; the organization is explicit and no request principal is fabricated.
    pub async fn create_team<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        data: CreateTeam,
    ) -> AuthResult<Team> {
        if !self.config.teams.enabled {
            return Err(better_auth_core::AuthError::NotImplemented(
                "Teams are disabled".to_owned(),
            ));
        }
        create_team_core(data, None, None, ctx, &self.config).await
    }
    pub async fn remove_team<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        organization_id: &str,
        team_id: &str,
    ) -> AuthResult<()> {
        if !self.config.teams.enabled {
            return Err(better_auth_core::AuthError::NotImplemented(
                "Teams are disabled".to_owned(),
            ));
        }
        remove_team_core(organization_id, team_id, None, ctx, &self.config).await
    }
}

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
    let user_view = ctx.user_view(&user);
    macro_rules! body {
        ($ty:ty) => {
            match better_auth_core::validate_request_body::<$ty>(req) {
                Ok(body) => body,
                Err(response) => return Ok(Some(response)),
            }
        };
    }
    let response = match (req.method(), req.path()) {
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
                Some(req),
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
                callback.before_update(&team, &mut updates, &hooks).await?;
            }
            let team = ctx
                .database
                .update_team(&org, &body.team_id, updates)
                .await?;
            if let Some(callback) = &config.teams.hooks {
                callback.after_update(&team, &hooks).await?;
            }
            AuthResponse::json(200, &team)?
        }
        (HttpMethod::Get, "/organization/list-teams") => {
            let org = org_id(
                req.query.get("organizationId").map(String::as_str),
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
            let target = req
                .query
                .get("userId")
                .filter(|id| !id.is_empty())
                .map(String::as_str)
                .unwrap_or(user_view.id.as_str());
            let explicit = req
                .query
                .get("organizationId")
                .filter(|id| !id.is_empty())
                .map(String::as_str);
            let scope = if target != user_view.id {
                Some(org_id(explicit, Some(&current))?)
            } else {
                explicit.map(str::to_owned)
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
            let team_id = req
                .query
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
            let body = body!(SetActiveRequest);
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
                        .update_session_active_team(&current.token, None)
                        .await?;
                    response.headers.append(
                        "set-cookie",
                        better_auth_core::utils::cookie_utils::create_session_cookie(
                            better_auth_core::AuthSession::token(&updated),
                            &ctx.config,
                        ),
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
                    .update_session_active_team(&current.token, Some(team_id))
                    .await?;
                AuthResponse::json(200, &team)?.with_header(
                    "set-cookie",
                    better_auth_core::utils::cookie_utils::create_session_cookie(
                        better_auth_core::AuthSession::token(&updated),
                        &ctx.config,
                    ),
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
            let add = req.path().ends_with("/add-team-member");
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
                .ok_or_else(|| better_auth_core::AuthError::bad_request("User not found"))?;
            let target = ctx.user_view(&target);
            let hooks = hook_context(ctx, &org, Some(user_view)).await?;
            if add {
                if let Some(callback) = &config.teams.hooks {
                    callback.before_add_member(&team, &target, &hooks).await?;
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
                        .await?;
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
                        .await?;
                }
                let _ = ctx
                    .database
                    .remove_team_member(&team.id, &body.user_id)
                    .await?;
                if let Some(callback) = &config.teams.hooks {
                    callback
                        .after_remove_member(&member, &team, &target, &hooks)
                        .await?;
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
