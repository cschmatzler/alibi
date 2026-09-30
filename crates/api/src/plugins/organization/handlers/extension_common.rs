use super::super::OrganizationConfig;
use better_auth_core::types::OrganizationPermissions;
use better_auth_core::wire::SessionView;
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema};
use std::collections::HashMap;

pub fn org_error(status: u16, code: &'static str) -> AuthError {
    let message = match code {
        "UNAUTHORIZED" => "Unauthorized",
        "NO_ACTIVE_ORGANIZATION" => "No active organization",
        "ORGANIZATION_NOT_FOUND" => "Organization not found",
        "TEAM_NOT_FOUND" => "Team not found",
        "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION" => {
            "You are not allowed to invite users to this organization"
        }
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION" => {
            "You are not allowed to create teams in this organization"
        }
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION" => {
            "You are not allowed to delete teams in this organization"
        }
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM" => "You are not allowed to update this team",
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM" => "You are not allowed to delete this team",
        "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION" => {
            "You are not allowed to access this organization as an owner"
        }
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION" => "You are not a member of this organization",
        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION" => "User is not a member of the organization",
        "USER_IS_NOT_A_MEMBER_OF_THE_TEAM" => "User is not a member of the team",
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER" => "You are not allowed to update this member",
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER" => {
            "You are not allowed to create a new member"
        }
        "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER" => {
            "You are not allowed to remove a team member"
        }
        "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM" => "You do not have an active team",
        "TEAM_MEMBER_LIMIT_REACHED" => "Team member limit reached",
        "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS" => {
            "You have reached the maximum number of teams"
        }
        "UNABLE_TO_REMOVE_LAST_TEAM" => "Unable to remove last team",
        "INVALID_TEAM_ID" => "Team id contains a reserved character",
        _ => "Organization operation failed",
    };
    AuthError::Upstream {
        status,
        code,
        message,
    }
}

pub async fn session<S: AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<(S::User, SessionView)> {
    ctx.require_session(req).await.map_err(|error| match error {
        AuthError::Unauthenticated | AuthError::SessionNotFound => org_error(401, "UNAUTHORIZED"),
        error => error,
    })
}

pub fn organization_roles<S: AuthSchema>(
    config: &OrganizationConfig,
    ctx: &AuthContext<S>,
    org_id: &str,
) -> AuthResult<HashMap<String, OrganizationPermissions>> {
    let _ = (ctx, org_id);
    let defaults = super::super::extensions::default_organization_statements();
    let mut roles = if config.roles.is_none() {
        HashMap::from([
            ("owner".to_owned(), defaults.clone()),
            (
                "admin".to_owned(),
                defaults
                    .into_iter()
                    .map(|(key, actions)| {
                        if key == "organization" {
                            (key, vec!["update".to_owned()])
                        } else {
                            (key, actions)
                        }
                    })
                    .collect(),
            ),
            (
                "member".to_owned(),
                [("ac".to_owned(), vec!["read".to_owned()])].into(),
            ),
        ])
    } else {
        HashMap::new()
    };
    for (role, permission) in config.roles.iter().flatten() {
        let mut permissions = permission.additional.clone();
        for (resource, actions) in [
            ("organization", &permission.organization),
            ("member", &permission.member),
            ("invitation", &permission.invitation),
            ("apikey", &permission.api_key),
            ("team", &permission.team),
            ("ac", &permission.ac),
        ] {
            let _ = permissions.insert(resource.to_owned(), actions.clone());
        }
        let _ = roles.insert(role.clone(), permissions);
    }
    Ok(roles)
}

pub fn has_permissions<S: AuthSchema>(
    role: &str,
    required: &OrganizationPermissions,
    config: &OrganizationConfig,
    ctx: &AuthContext<S>,
    org_id: &str,
) -> AuthResult<bool> {
    let roles = organization_roles(config, ctx, org_id)?;
    Ok(role.split(',').any(|name| {
        roles.get(name).is_some_and(|permissions| {
            required.iter().all(|(resource, actions)| {
                actions.iter().all(|action| {
                    permissions
                        .get(resource)
                        .is_some_and(|granted| granted.contains(action))
                })
            })
        })
    }))
}

pub fn has_action<S: AuthSchema>(
    role: &str,
    resource: &str,
    action: &str,
    config: &OrganizationConfig,
    ctx: &AuthContext<S>,
    org_id: &str,
) -> AuthResult<bool> {
    has_permissions(
        role,
        &[(resource.to_owned(), vec![action.to_owned()])].into(),
        config,
        ctx,
        org_id,
    )
}
