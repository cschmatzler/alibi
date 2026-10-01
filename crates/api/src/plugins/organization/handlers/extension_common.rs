use super::super::OrganizationConfig;

use better_auth_core::types::OrganizationPermissions;

use better_auth_core::wire::SessionView;

use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema};

use std::collections::HashMap;

use std::sync::{Mutex, OnceLock};

type OrganizationRoles = HashMap<String, OrganizationPermissions>;

// The pinned runtime's cacheAllRoles map is shared by organization plugin
// instances. Fresh permission checks replace only the selected organization's
// snapshot; delegated role grants subsequently use that snapshot.
fn role_cache() -> &'static Mutex<HashMap<String, OrganizationRoles>> {
    static CACHE: OnceLock<Mutex<HashMap<String, OrganizationRoles>>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

#[must_use]
pub fn org_error(status: u16, code: &'static str) -> AuthError {
    let message = match code {
        "UNAUTHORIZED" => "Unauthorized",
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION" => {
            "You are not allowed to update this organization"
        }
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION" => {
            "You are not allowed to create a new organization"
        }
        "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS" => {
            "You have reached the maximum number of organizations"
        }
        "NO_ACTIVE_ORGANIZATION" => "No active organization",
        "ORGANIZATION_NOT_FOUND" => "Organization not found",
        "ORGANIZATION_ALREADY_EXISTS" => "Organization already exists",
        "ORGANIZATION_SLUG_ALREADY_TAKEN" => "Organization slug already taken",
        "ORGANIZATION_DELETION_DISABLED" => "Organization deletion is disabled",
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION" => {
            "You are not allowed to delete this organization"
        }
        "TEAM_NOT_FOUND" => "Team not found",
        "MEMBER_NOT_FOUND" => "Member not found",
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
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER" => "You are not allowed to delete this member",
        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER" => {
            "You cannot leave the organization as the only owner"
        }
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
        "MISSING_AC_INSTANCE" => {
            "Dynamic Access Control requires a pre-defined ac instance on the server auth plugin. Read server logs for more information"
        }
        "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE" => {
            "You must be in an organization to create a role"
        }
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE" => "You are not allowed to create a role",
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE" => "You are not allowed to update a role",
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE" => "You are not allowed to delete a role",
        "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE" => "You are not allowed to read a role",
        "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE" => "You are not allowed to list a role",
        "TOO_MANY_ROLES" => "This organization has too many roles",
        "INVALID_RESOURCE" => "The provided permission includes an invalid resource",
        "ROLE_NAME_IS_ALREADY_TAKEN" => "That role name is already taken",
        "CANNOT_DELETE_A_PRE_DEFINED_ROLE" => "Cannot delete a pre-defined role",
        "ROLE_IS_ASSIGNED_TO_MEMBERS" => {
            "Cannot delete a role that is assigned to members. Please reassign the members to a different role first"
        }
        "ROLE_NOT_FOUND" => "Role not found",
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
) -> AuthResult<(better_auth_core::AuthenticatedUser<S>, SessionView)> {
    ctx.require_cached_session(req)
        .await
        .map_err(|error| match error {
            AuthError::Unauthenticated | AuthError::SessionNotFound => {
                org_error(401, "UNAUTHORIZED")
            }
            error => error,
        })
}

fn configured_roles(config: &OrganizationConfig) -> OrganizationRoles {
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
            ("apiKey", &permission.api_key),
            ("team", &permission.team),
            ("ac", &permission.ac),
        ] {
            drop(permissions.insert(resource.to_owned(), actions.clone()));
        }
        drop(roles.insert(role.clone(), permissions));
    }
    roles
}

///
/// # Errors
///
/// Returns errors from organization-role storage or the shared role cache.
pub async fn organization_roles<S: AuthSchema>(
    config: &OrganizationConfig,
    ctx: &AuthContext<S>,
    org_id: &str,
) -> AuthResult<OrganizationRoles> {
    let mut roles = configured_roles(config);
    if config.dynamic_access_control.enabled && config.access_control.is_some() {
        for role in ctx.database.list_organization_roles(org_id).await? {
            let permissions = roles.entry(role.role).or_default();
            for (resource, actions) in role.permission {
                let merged = permissions.entry(resource).or_default();
                for action in actions {
                    if !merged.contains(&action) {
                        merged.push(action);
                    }
                }
            }
        }
    }
    drop(
        role_cache()
            .lock()
            .map_err(|_error| AuthError::internal("Organization role cache unavailable"))?
            .insert(org_id.to_owned(), roles.clone()),
    );
    Ok(roles)
}

pub(super) fn cached_has_permissions(
    role: &str,
    required: &OrganizationPermissions,
    config: &OrganizationConfig,
    org_id: &str,
) -> AuthResult<bool> {
    let mut cache = role_cache()
        .lock()
        .map_err(|_error| AuthError::internal("Organization role cache unavailable"))?;
    let roles = cache
        .entry(org_id.to_owned())
        .or_insert_with(|| configured_roles(config));
    let permitted = role_has_permissions(role, required, roles);
    drop(cache);
    Ok(permitted)
}

///
/// # Errors
///
/// Propagates errors from role loading and authorization callbacks.
pub async fn has_permissions<S: AuthSchema>(
    role: &str,
    required: &OrganizationPermissions,
    config: &OrganizationConfig,
    ctx: &AuthContext<S>,
    org_id: &str,
) -> AuthResult<bool> {
    let roles = organization_roles(config, ctx, org_id).await?;
    Ok(role_has_permissions(role, required, &roles))
}

#[must_use]
pub fn role_has_permissions<H: std::hash::BuildHasher>(
    role: &str,
    required: &OrganizationPermissions,
    roles: &HashMap<String, OrganizationPermissions, H>,
) -> bool {
    !required.is_empty()
        && role.split(',').any(|name| {
            roles.get(name).is_some_and(|permissions| {
                required.iter().all(|(resource, actions)| {
                    !actions.is_empty()
                        && actions.iter().all(|action| {
                            permissions
                                .get(resource)
                                .is_some_and(|granted| granted.contains(action))
                        })
                })
            })
        })
}

///
/// # Errors
///
/// Propagates errors from role loading and authorization callbacks.
pub async fn has_action<S: AuthSchema>(
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
    .await
}
