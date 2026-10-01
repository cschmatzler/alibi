pub mod extension_common;

pub mod invitation;

pub mod member;

pub(in crate::plugins) mod member_addition;

pub mod org;

pub(in crate::plugins) mod org_input;

mod page;

pub mod role;

pub mod team;

mod validation;

pub(in crate::plugins) mod invitation_acceptance;

use super::OrganizationConfig;
use super::types::{HasPermissionRequest, HasPermissionResponse};
use better_auth_core::entity::{AuthMember, AuthSession, AuthUser};
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::plugin::AuthContext;
use better_auth_core::types::{AuthRequest, AuthResponse};
pub use invitation::*;
pub use member::*;
pub use org::*;

/// Helper function to require authenticated session
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn require_session<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> AuthResult<(S::User, better_auth_core::wire::SessionView)> {
    ctx.require_session(req).await
}

/// Helper function to get organization ID from request or session
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn resolve_organization_id(
    org_id: Option<&str>,
    org_slug: Option<&str>,
    session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<String> {
    if let Some(id) = org_id {
        return Ok(id.to_owned());
    }

    if let Some(slug) = org_slug {
        if let Some(org) = ctx.database.get_organization_by_slug(slug).await? {
            use better_auth_core::entity::AuthOrganization;
            return Ok(org.id().to_string());
        }
        return Err(AuthError::not_found("Organization not found"));
    }

    session
        .active_organization_id()
        .map(ToOwned::to_owned)
        .ok_or_else(|| AuthError::bad_request("No active organization"))
}

// ---------------------------------------------------------------------------
// Core function
// ---------------------------------------------------------------------------

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn has_permission_core(
    body: &HasPermissionRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<HasPermissionResponse> {
    let org_id = body
        .organization_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .or_else(|| session.active_organization_id())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| extension_common::org_error(400, "NO_ACTIVE_ORGANIZATION"))?;

    let member = ctx
        .database
        .get_member(org_id, &user.id())
        .await?
        .ok_or_else(|| {
            extension_common::org_error(401, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
        })?;

    let required = body
        .permissions
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let has_all_permissions =
        extension_common::has_permissions(member.role(), &required, config, ctx, org_id).await?;

    Ok(HasPermissionResponse {
        success: has_all_permissions,
        error: None,
    })
}

// ---------------------------------------------------------------------------
// Old handler (rewritten to call core)
// ---------------------------------------------------------------------------

/// Handle has-permission request
///
/// # Errors
///
/// Returns errors from input validation, permission checks, storage, or configured organization hooks.
pub async fn handle_has_permission(
    req: &AuthRequest,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    config: &OrganizationConfig,
) -> AuthResult<AuthResponse> {
    let input = match validation::body_object(req) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let mut issues = validation::Issues::default();
    let organization_id = issues
        .take(validation::optional_string(
            &input,
            "organizationId",
            "body.organizationId",
        ))
        .flatten();
    let canonical = validation::permissions(input.get("permissions"), "body.permissions").ok();
    let legacy = validation::permissions(input.get("permission"), "body.permission").ok();
    let permissions = match (canonical, legacy) {
        (Some(_), Some(_)) => {
            issues.push("[body] Invalid input: more than one option matched");
            indexmap::IndexMap::default()
        }
        (None, None) => {
            issues.push("[body] Invalid input");
            indexmap::IndexMap::default()
        }
        (Some(permissions), None) => permissions,
        // The pinned legacy branch validates successfully, but only the canonical
        // property is used by its handler. Retain the resulting false response.
        (None, Some(_)) => indexmap::IndexMap::default(),
    };
    if let Some(response) = issues.response() {
        return Ok(response);
    }
    let body = HasPermissionRequest {
        organization_id,
        permissions: permissions.into_iter().collect(),
    };
    let (user, session) = require_session(req, ctx).await?;
    let response = has_permission_core(&body, &user, &session, config, ctx).await?;
    Ok(AuthResponse::json(200, &response)?)
}
