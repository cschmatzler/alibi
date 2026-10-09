//! Configuration-sensitive overlays on pinned plugin schema declarations.
use super::PluginOpenApiMetadata;
use alibi_core::{AuthInitContext, AuthSchema};
use serde_json::json;

pub(super) fn apply<S: AuthSchema>(
    plugin: &str,
    ctx: &AuthInitContext<S>,
    metadata: &mut PluginOpenApiMetadata,
) {
    if plugin == "email-password" && ctx.get_metadata("username.enabled") == Some(&json!(true)) {
        metadata
            .models
            .extend(super::source_models::models("username").unwrap_or_default());
    }
    if plugin == "organization" {
        let teams = ctx.get_metadata("organization.teams.enabled") == Some(&json!(true));
        let dynamic = ctx.get_metadata("organization.dynamic_roles.enabled") == Some(&json!(true));
        metadata.models.retain(|model| match model.name.as_str() {
            "Team" | "TeamMember" => teams,
            "OrganizationRole" => dynamic,
            _ => true,
        });
        if !teams {
            for model in &mut metadata.models {
                model.fields.retain(|field| {
                    !matches!(
                        (model.name.as_str(), field.name.as_str()),
                        ("Session", "activeTeamId") | ("Invitation", "teamId")
                    )
                });
            }
        }
    }
    if plugin == "last-login-method"
        && ctx.get_metadata("last-login-method.store-in-database") != Some(&json!(true))
    {
        metadata.models.clear();
    }
}
