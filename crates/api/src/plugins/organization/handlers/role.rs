use super::super::OrganizationConfig;
use super::extension_common::{
    cached_has_permissions, org_error, organization_roles, role_has_permissions, session,
};
use super::validation;
use better_auth_core::entity::AuthUser;
use better_auth_core::types::{
    CreateOrganizationRole, OrganizationPermissions, OrganizationRole, OrganizationRoleSelector,
    StoredOrganizationPermissions, UpdateOrganizationRole,
};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, HttpMethod,
};
struct RoleUpdates {
    role_name: Option<String>,
    permission: Option<OrganizationPermissions>,
}

// Parsing belongs after the endpoint's authorization checks, not in adapters.
fn parsed_role(role: &OrganizationRole) -> AuthResult<serde_json::Value> {
    let permission: serde_json::Value = serde_json::from_str(role.permission.as_str())
        .map_err(|error| AuthError::CallbackFailure(Box::new(error.into())))?;
    let mut value = serde_json::to_value(role)?;
    value["permission"] = permission;
    Ok(value)
}

fn selector(
    name: Option<&str>,
    id: Option<&str>,
    query: bool,
) -> Result<OrganizationRoleSelector, validation::Issue> {
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        return Ok(OrganizationRoleSelector::Name(name.to_owned()));
    }
    if let Some(id) = id.filter(|id| !id.is_empty()) {
        return Ok(OrganizationRoleSelector::Id(id.to_owned()));
    }
    Err(validation::issue(match (query, name, id) {
        (true, Some(""), None) => {
            "[query.roleName] Too small: expected string to have >=1 characters"
        }
        (true, None, Some("")) => {
            "[query.roleId] Too small: expected string to have >=1 characters"
        }
        (false, Some(""), None) => {
            "[body.roleName] Too small: expected string to have >=1 characters"
        }
        (false, None, Some("")) => {
            "[body.roleId] Too small: expected string to have >=1 characters"
        }
        (true, _, _) => "[query] Invalid input",
        (false, _, _) => "[body] Invalid input",
    }))
}

fn check_predefined_name(name: &str, config: &OrganizationConfig) -> AuthResult<()> {
    if (config.roles.is_none() && ["owner", "admin", "member"].contains(&name))
        || config
            .roles
            .as_ref()
            .is_some_and(|configured_roles| configured_roles.contains_key(name))
    {
        return Err(org_error(400, "ROLE_NAME_IS_ALREADY_TAKEN"));
    }
    Ok(())
}

async fn check_name<S: AuthSchema>(
    name: &str,
    org_id: &str,
    config: &OrganizationConfig,
    ctx: &AuthContext<S>,
) -> AuthResult<()> {
    check_predefined_name(name, config)?;
    if ctx
        .database
        .get_organization_role(org_id, &OrganizationRoleSelector::Name(name.to_owned()))
        .await?
        .is_some()
    {
        return Err(org_error(400, "ROLE_NAME_IS_ALREADY_TAKEN"));
    }
    Ok(())
}

fn missing_permissions(
    role: &str,
    permissions: &OrganizationPermissions,
    config: &OrganizationConfig,
    organization_id: &str,
) -> AuthResult<Vec<String>> {
    let ac = config
        .access_control
        .as_ref()
        .ok_or_else(|| org_error(501, "MISSING_AC_INSTANCE"))?;
    if permissions.keys().any(|key| !ac.contains_key(key)) {
        return Err(org_error(400, "INVALID_RESOURCE"));
    }
    let mut missing = Vec::new();
    for (resource, actions) in permissions {
        for action in actions {
            if !cached_has_permissions(
                role,
                &[(resource.clone(), vec![action.clone()])].into(),
                config,
                organization_id,
            )? {
                missing.push(format!("{resource}:{action}"));
            }
        }
    }
    Ok(missing)
}

///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
#[expect(
    clippy::too_many_lines,
    reason = "Keep role endpoint dispatch and each permission check adjacent to its persistence operation"
)]
#[expect(
    clippy::cast_precision_loss,
    reason = "Source compares stored counts as ECMAScript Numbers"
)]
pub async fn handle_role_request<S: AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
    config: &OrganizationConfig,
) -> AuthResult<Option<AuthResponse>> {
    let known = matches!(
        (req.method(), req.path()),
        (
            HttpMethod::Post,
            "/organization/create-role" | "/organization/update-role" | "/organization/delete-role"
        ) | (
            HttpMethod::Get,
            "/organization/get-role" | "/organization/list-roles"
        )
    );
    if !config.dynamic_access_control.enabled || !known {
        return Ok(None);
    }
    let body = if *req.method() == HttpMethod::Post {
        match validation::body_object(req) {
            Ok(body) => body,
            Err(response) => return Ok(Some(response)),
        }
    } else {
        serde_json::Map::default()
    };
    let mut issues = validation::Issues::default();
    let (explicit, chosen, create, updates) = match (req.method(), req.path()) {
        (HttpMethod::Post, "/organization/create-role") => {
            let organization_id = issues
                .take(validation::optional_string(
                    &body,
                    "organizationId",
                    "body.organizationId",
                ))
                .flatten();
            let create = issues
                .take(validation::required_string(&body, "role", "body.role"))
                .zip(issues.take(validation::permissions(
                    body.get("permission"),
                    "body.permission",
                )));
            if let Some(additional) = body.get("additionalFields") {
                let _ignored_take = issues.take(validation::object(
                    Some(additional),
                    "body.additionalFields",
                ));
            }
            (organization_id, None, create, None)
        }
        (HttpMethod::Post, "/organization/update-role") => {
            let organization_id = issues
                .take(validation::optional_string(
                    &body,
                    "organizationId",
                    "body.organizationId",
                ))
                .flatten();
            let updates = issues
                .take(validation::object(body.get("data"), "body.data"))
                .map(|data| {
                    let permission = data.get("permission").and_then(|value| {
                        issues.take(validation::permissions(Some(value), "body.data.permission"))
                    });
                    let role_name = issues
                        .take(validation::optional_string(
                            data,
                            "roleName",
                            "body.data.roleName",
                        ))
                        .flatten();
                    RoleUpdates {
                        role_name,
                        permission,
                    }
                });
            let chosen = issues.take(selector(
                body.get("roleName").and_then(serde_json::Value::as_str),
                body.get("roleId").and_then(serde_json::Value::as_str),
                false,
            ));
            (organization_id, chosen, None, updates)
        }
        (HttpMethod::Post, "/organization/delete-role") => {
            let organization_id = issues
                .take(validation::optional_string(
                    &body,
                    "organizationId",
                    "body.organizationId",
                ))
                .flatten();
            let chosen = issues.take(selector(
                body.get("roleName").and_then(serde_json::Value::as_str),
                body.get("roleId").and_then(serde_json::Value::as_str),
                false,
            ));
            (organization_id, chosen, None, None)
        }
        (HttpMethod::Get, "/organization/get-role") => (
            req.query.get("organizationId").cloned(),
            issues.take(selector(
                req.query.get("roleName").map(String::as_str),
                req.query.get("roleId").map(String::as_str),
                true,
            )),
            None,
            None,
        ),
        _ => (req.query.get("organizationId").cloned(), None, None, None),
    };
    if let Some(response) = issues.response() {
        return Ok(Some(response));
    }
    let (user, current) = session(req, ctx).await?;
    let action = match req.path() {
        "/organization/create-role" => "create",
        "/organization/update-role" => "update",
        "/organization/delete-role" => "delete",
        _ => "read",
    };
    let error_code = match req.path() {
        "/organization/create-role" => "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
        "/organization/update-role" => "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE",
        "/organization/delete-role" => "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE",
        "/organization/list-roles" => "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE",
        _ => "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE",
    };
    if (action == "create" || action == "update") && config.access_control.is_none() {
        return Err(org_error(501, "MISSING_AC_INSTANCE"));
    }
    let org = explicit
        .or(current.active_organization_id)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            org_error(
                400,
                if action == "create" {
                    "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE"
                } else {
                    "NO_ACTIVE_ORGANIZATION"
                },
            )
        })?;
    if let Some((name, _)) = &create {
        check_predefined_name(&name.to_lowercase(), config)?;
    }
    let member = ctx
        .database
        .get_member(&org, user.id().as_ref())
        .await?
        .ok_or_else(|| org_error(403, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION"))?;
    let roles = organization_roles(config, ctx, &org).await?;
    if !role_has_permissions(
        &member.role,
        &[("ac".to_owned(), vec![action.to_owned()])].into(),
        &roles,
    ) {
        return Err(org_error(403, error_code));
    }
    let response = if let Some((name, permission)) = create {
        let maximum = match &config.dynamic_access_control.limit_resolver {
            Some(resolver) => resolver.maximum_roles(&org).await?,
            None => config.dynamic_access_control.maximum_roles_per_organization,
        }
        .unwrap_or(f64::INFINITY);
        if ctx.database.count_organization_roles(&org).await? as f64 >= maximum {
            return Err(org_error(400, "TOO_MANY_ROLES"));
        }
        let missing = missing_permissions(&member.role, &permission, config, &org)?;
        if !missing.is_empty() {
            return Ok(Some(AuthResponse::json(
                403,
                &serde_json::json!({"message":"You are not allowed to create a role","code":error_code,"missingPermissions":missing}),
            )?));
        }
        let name = name.to_lowercase();
        check_name(&name, &org, config, ctx).await?;
        let role = ctx
            .database
            .create_organization_role(CreateOrganizationRole {
                organization_id: org,
                role: name,
                permission: permission.clone(),
            })
            .await?;
        AuthResponse::json(
            200,
            &serde_json::json!({"success":true,"roleData":parsed_role(&role)?,"statements":permission}),
        )?
    } else if req.path() == "/organization/list-roles" {
        let roles = ctx.database.list_organization_roles(&org).await?;
        let parsed = roles
            .iter()
            .map(parsed_role)
            .collect::<AuthResult<Vec<_>>>()?;
        AuthResponse::json(200, &parsed)?
    } else {
        let chosen = chosen.ok_or_else(|| org_error(400, "ROLE_NOT_FOUND"))?;
        if action == "delete"
            && matches!(&chosen,OrganizationRoleSelector::Name(name) if (config.roles.is_none() && ["owner","admin","member"].contains(&name.as_str())) || config.roles.as_ref().is_some_and(|configured_roles| configured_roles.contains_key(name)))
        {
            return Err(org_error(400, "CANNOT_DELETE_A_PRE_DEFINED_ROLE"));
        }
        let mut role = ctx
            .database
            .get_organization_role(&org, &chosen)
            .await?
            .ok_or_else(|| org_error(400, "ROLE_NOT_FOUND"))?;
        // Source's update route skips parsing an empty stored string. Reads and
        // deletes still parse it and fail before returning or deleting the row.
        let mut role_data = if updates.is_some() && role.permission.as_str().is_empty() {
            let mut value = serde_json::to_value(&role)?;
            value["permission"] = serde_json::Value::Null;
            value
        } else {
            parsed_role(&role)?
        };
        if action == "delete" {
            if ctx
                .database
                .has_organization_role_members(&org, &role.role)
                .await?
            {
                return Err(org_error(400, "ROLE_IS_ASSIGNED_TO_MEMBERS"));
            }
            let _ignored_delete_organization_role =
                ctx.database.delete_organization_role(&org, &chosen).await?;
            AuthResponse::json(200, &serde_json::json!({"success":true}))?
        } else if let Some(updates) = updates {
            // Upstream returns `newPermission || oldPermission || null`.
            if matches!(&role_data["permission"], serde_json::Value::Bool(false))
                || role_data["permission"].as_f64() == Some(0.0)
                || role_data["permission"].as_str() == Some("")
            {
                role_data["permission"] = serde_json::Value::Null;
            }
            // Only requested fields belong in the batch update. Copying the
            // selected row's permissions would overwrite other legacy rows
            // with the same name and normalize their literal permission JSON.
            let mut update = UpdateOrganizationRole::default();
            if let Some(permission) = &updates.permission {
                let missing = missing_permissions(&member.role, permission, config, &org)?;
                if !missing.is_empty() {
                    return Ok(Some(AuthResponse::json(
                        403,
                        &serde_json::json!({"message":"You are not allowed to update a role","code":error_code,"missingPermissions":missing}),
                    )?));
                }
                role.permission = StoredOrganizationPermissions::from_record(permission)?;
                role_data["permission"] = serde_json::to_value(permission)?;
                update.permission = Some(permission.clone());
            }
            if let Some(name) = updates.role_name.filter(|name| !name.is_empty()) {
                let name = name.to_lowercase();
                check_name(&name, &org, config, ctx).await?;
                update.role = Some(name.clone());
                role_data["role"] = serde_json::Value::String(name.clone());
                role.role = name;
            }
            drop(
                ctx.database
                    .update_organization_role(&org, &chosen, update)
                    .await?,
            );
            // The upstream return value merges the pre-update row; the stored updatedAt still advances.
            AuthResponse::json(
                200,
                &serde_json::json!({"success":true,"roleData":role_data}),
            )?
        } else {
            AuthResponse::json(200, &role_data)?
        }
    };
    Ok(Some(response))
}
