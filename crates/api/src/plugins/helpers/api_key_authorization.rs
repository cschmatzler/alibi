use super::*;
/// Fetch an API key by ID and verify that it belongs to the given user.
///
/// Returns `AuthError::not_found` if the key does not exist or belongs to
/// another user.  This pattern was duplicated in `handle_get`, `handle_update`,
/// and `handle_delete`.
///
/// # Errors
///
/// Returns an error if the key is missing, belongs to another owner, or its lookup fails.
pub async fn get_owned_api_key(
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    config: &crate::plugins::api_key::ApiKeyConfig,
    key_id: &str,
    user_id: &str,
    action: &str,
) -> AuthResult<alibi_core::ApiKey> {
    use crate::plugins::api_key::{ApiKeyReferences, config_id_matches};

    let api_key = config
        .read_key(ctx, key_id, false)
        .await?
        .ok_or_else(|| AuthError::not_found("API Key not found"))?;

    // A key only exists as far as the configuration that addressed it.
    if !config_id_matches(&api_key.config_id, &config.config_id) {
        return Err(AuthError::not_found("API Key not found"));
    }

    match config.references {
        ApiKeyReferences::User => {
            if api_key.reference_id != user_id {
                return Err(AuthError::not_found("API Key not found"));
            }
        }
        ApiKeyReferences::Organization => {
            require_org_api_key_permission(ctx, user_id, &api_key.reference_id, action).await?;
        }
    }

    Ok(api_key)
}

/// Authorize a user against an organization-owned API key, mirroring
/// upstream's `checkOrgApiKeyPermission`.
///
/// # Errors
///
/// Returns an error if organization permissions cannot be loaded or do not authorize the operation.
pub async fn require_org_api_key_permission(
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    user_id: &str,
    organization_id: &str,
    action: &str,
) -> AuthResult<()> {
    use crate::plugins::api_key::{ApiKeyErrorCode, api_key_error};
    use crate::plugins::organization::{
        DynamicAccessControlConfig, METADATA_CREATOR_ROLE, METADATA_ENABLED, METADATA_ROLES,
        OrganizationConfig,
    };

    // Organization-owned keys are meaningless without the organization plugin,
    // which is what supplies the access control below.
    if !ctx
        .get_metadata(METADATA_ENABLED)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Err(api_key_error(ApiKeyErrorCode::OrganizationPluginRequired));
    }

    let Some(member) = ctx.database.get_member(organization_id, user_id).await? else {
        return Err(api_key_error(ApiKeyErrorCode::UserNotMemberOfOrganization));
    };

    // Upstream passes `allowCreatorAllPermissions`, so the creator role clears
    // every action without consulting the statements. Roles are composite
    // (comma-separated), so holding it alongside others still counts.
    let creator_role = ctx
        .get_metadata(METADATA_CREATOR_ROLE)
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "owner".to_owned());
    let config = OrganizationConfig {
        roles: ctx
            .get_metadata(METADATA_ROLES)
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .flatten(),
        access_control: ctx
            .get_metadata("organization.access_control")
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .flatten(),
        dynamic_access_control: DynamicAccessControlConfig {
            enabled: ctx
                .get_metadata("organization.dynamic_roles.enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            ..Default::default()
        },
        ..Default::default()
    };
    // Source resolves dynamic roles before the creator permission shortcut.
    // Invalid legacy rows must deny owners too, without exposing loader errors.
    if member.role.split(',').any(|role| role == creator_role) {
        return crate::plugins::organization::handlers::extension_common::organization_roles(
            &config,
            ctx,
            organization_id,
        )
        .await
        .map(|_| ())
        .map_err(|_error| api_key_error(ApiKeyErrorCode::InsufficientApiKeyPermissions));
    }

    // The pinned API-key plugin turns failed dynamic role resolution into a
    // denied permission rather than allowing or exposing its internal error.
    let allowed = crate::plugins::organization::handlers::extension_common::has_action(
        &member.role,
        "apiKey",
        action,
        &config,
        ctx,
        organization_id,
    )
    .await
    .unwrap_or(false);

    if allowed {
        Ok(())
    } else {
        Err(api_key_error(
            ApiKeyErrorCode::InsufficientApiKeyPermissions,
        ))
    }
}
