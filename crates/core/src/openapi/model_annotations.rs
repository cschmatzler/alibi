//! Semantic model policies layered over the physical field registry.
use super::{OpenApiField, OpenApiModel, PluginOpenApiMetadata};
use crate::{AuthInitContext, AuthSchema};
use serde_json::{Value, json};
fn set(
    model: &mut OpenApiModel,
    name: &str,
    required: Option<bool>,
    input: Option<bool>,
    returned: Option<bool>,
    default: Option<Value>,
) {
    if let Some(field) = model.fields.iter_mut().find(|field| field.name == name) {
        if let Some(required) = required {
            field.required = required;
        }
        if let Some(input) = input {
            field.input = input;
        }
        if let Some(returned) = returned {
            field.returned = returned;
        }
        if let Some(default) = default
            && let Some(object) = field.schema.as_object_mut()
        {
            let _ = object.insert("default".into(), default);
        }
    }
}
fn reorder(model: &mut OpenApiModel, names: &[&str]) {
    model.fields.sort_by_key(|field| {
        names
            .iter()
            .position(|name| *name == field.name)
            .unwrap_or(names.len())
    });
}
pub(super) fn apply<S: AuthSchema>(
    plugin: &str,
    ctx: &AuthInitContext<S>,
    metadata: &mut PluginOpenApiMetadata,
) {
    if plugin == "email-password" && ctx.get_metadata("username.enabled") == Some(&json!(true)) {
        metadata
            .models
            .extend(super::annotations::plugin_metadata("username", &[]).models);
    }
    if plugin == "organization" {
        let teams = ctx.get_metadata("organization.teams.enabled") == Some(&json!(true));
        let dynamic = ctx.get_metadata("organization.dynamic_roles.enabled") == Some(&json!(true));
        if dynamic {
            metadata.models.extend(
                super::annotations::plugin_metadata("organization-dynamic-roles", &[]).models,
            );
        }
        if teams {
            metadata
                .models
                .extend(super::annotations::plugin_metadata("organization-teams", &[]).models);
        }
        for model in &mut metadata.models {
            match model.name.as_str() {
                "Organization" => {
                    model.fields.retain(|field| field.name != "updatedAt");
                    if let Some(field) = model
                        .fields
                        .iter_mut()
                        .find(|field| field.name == "metadata")
                    {
                        field.schema = json!({"type":"string"});
                        field.required = false;
                    }
                    reorder(model, &["name", "slug", "logo", "createdAt", "metadata"]);
                }
                "Member" => set(model, "role", None, None, None, Some(json!("member"))),
                "Invitation" => {
                    if !teams {
                        model.fields.retain(|field| field.name != "teamId");
                    }
                    set(model, "role", Some(false), None, None, None);
                    set(model, "status", None, None, None, Some(json!("pending")));
                    reorder(
                        model,
                        &[
                            "organizationId",
                            "email",
                            "role",
                            "teamId",
                            "status",
                            "expiresAt",
                            "createdAt",
                            "inviterId",
                        ],
                    );
                }
                "Team" => {
                    set(
                        model,
                        "memberCount",
                        None,
                        Some(false),
                        Some(false),
                        Some(json!(0)),
                    );
                    reorder(
                        model,
                        &[
                            "name",
                            "memberCount",
                            "organizationId",
                            "createdAt",
                            "updatedAt",
                        ],
                    );
                }
                "TeamMember" => {
                    set(model, "membershipKey", None, Some(false), Some(false), None);
                    set(model, "createdAt", Some(false), None, None, None);
                }
                _ => {}
            }
        }
    }
    for model in &mut metadata.models {
        if plugin == "admin" {
            model.fields.retain(|field| field.name != "metadata");
            for field in &mut model.fields {
                field.input = false;
            }
            set(model, "banned", None, None, None, Some(json!(false)));
        }
        if plugin == "two-factor" {
            set(
                model,
                "twoFactorEnabled",
                None,
                Some(false),
                None,
                Some(json!(false)),
            );
        }
        if plugin == "phone-number" {
            set(model, "phoneNumberVerified", None, Some(false), None, None);
        }
        if plugin == "anonymous" {
            set(
                model,
                "isAnonymous",
                None,
                Some(false),
                None,
                Some(json!(false)),
            );
        }
    }
    if plugin == "two-factor" {
        metadata.models.push(OpenApiModel::new(
            "TwoFactor",
            vec![
                OpenApiField::new("secret", json!({"type":"string"}), true).hidden(),
                OpenApiField::new("backupCodes", json!({"type":"string"}), true).hidden(),
                OpenApiField::new("userId", json!({"type":"string"}), true).hidden(),
                OpenApiField::new("verified", json!({"type":"boolean","default":true}), false)
                    .read_only(),
                OpenApiField::new(
                    "failedVerificationCount",
                    json!({"type":"number","default":0}),
                    false,
                )
                .read_only()
                .hidden(),
                OpenApiField::new(
                    "lockedUntil",
                    json!({"type":"string","format":"date-time"}),
                    false,
                )
                .read_only()
                .hidden(),
            ],
        ));
    }
}
