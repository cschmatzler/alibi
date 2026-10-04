//! Built-in wire annotations. Registration determines which annotations are collected.
use super::{OpenApiEndpoint, OpenApiField, OpenApiModel, PluginOpenApiMetadata};
use crate::AuthRoute;
use better_auth_schema_registry::{EntityRole, FieldDef, core_fields, plugin_schemas};
use serde_json::{Value, json};

pub(crate) fn is_core(plugin: &str) -> bool {
    matches!(
        plugin,
        "core"
            | "email-password"
            | "session-management"
            | "email-verification"
            | "password-management"
            | "user-management"
            | "account-management"
            | "oauth"
    )
}
fn wire_name(name: &str) -> String {
    let mut words = name.split('_');
    let mut output = words.next().unwrap_or_default().to_owned();
    for word in words {
        let mut letters = word.chars();
        if let Some(first) = letters.next() {
            output.extend(first.to_uppercase());
            output.extend(letters);
        }
    }
    output
}
fn field(field: &FieldDef, core: bool) -> Option<OpenApiField> {
    // `active` is an internal Rust revocation flag, not a public session field.
    if field.is_primary_key || (core && field.name == "active") {
        return None;
    }
    let ty = field.ty.trim_start_matches("Option<").trim_end_matches('>');
    let schema = match ty {
        "DateTimeUtc" => json!({"type":"string","format":"date-time"}),
        "bool" => json!({"type":"boolean"}),
        "i64" | "f64" => json!({"type":"number"}),
        "Json" => json!({"type":"json"}),
        _ => json!({"type":"string"}),
    };
    let mut field = OpenApiField::new(
        wire_name(field.name),
        schema,
        !field.ty.starts_with("Option<"),
    );
    if core && matches!(field.name.as_str(), "name" | "email") {
        field.required = true;
    }
    if core && field.name == "emailVerified" {
        field.input = false;
        if let Some(object) = field.schema.as_object_mut() {
            drop(object.insert("default".into(), json!(false)));
        }
    }
    Some(field)
}
/// Core wire projection guaranteed by the schema's mandatory entity accessors.
#[must_use]
pub fn core_models() -> Vec<OpenApiModel> {
    [
        ("User", EntityRole::User),
        ("Session", EntityRole::Session),
        ("Account", EntityRole::Account),
        ("Verification", EntityRole::Verification),
    ]
    .into_iter()
    .map(|(name, role)| {
        OpenApiModel::new(
            name,
            core_fields(role)
                .iter()
                .filter_map(|definition| field(definition, true))
                .collect(),
        )
    })
    .collect()
}
/// Default annotations for registered built-in routes and plugin model fields.
/// Custom plugins should override their metadata hook to describe additional constraints.
#[must_use]
pub fn plugin_metadata(plugin: &str, routes: &[AuthRoute]) -> PluginOpenApiMetadata {
    let mut metadata = PluginOpenApiMetadata::default();
    for route in routes {
        metadata.endpoints.push((
            route.method.clone(),
            route.path.clone(),
            super::source_endpoints::endpoint(
                if plugin == "email-password"
                    && matches!(
                        route.path.as_str(),
                        "/sign-in/username" | "/is-username-available"
                    )
                {
                    "username"
                } else {
                    plugin
                },
                &route.path,
            )
            .or_else(|| endpoint(&route.path))
            .unwrap_or_else(|| OpenApiEndpoint {
                operation_id: Some(route.operation_id.clone()),
                ..Default::default()
            }),
        ));
    }
    if let Some(models) = super::source_models::models(plugin) {
        metadata.models = models;
        return metadata;
    }
    if let Some(schema) = plugin_schemas().iter().find(|schema| schema.name == plugin) {
        for (name, definitions) in [
            ("User", schema.user_fields),
            ("Session", schema.session_fields),
        ] {
            let fields = definitions
                .iter()
                .filter_map(|definition| field(definition, false))
                .collect::<Vec<_>>();
            if !fields.is_empty() {
                metadata.models.push(OpenApiModel::new(name, fields));
            }
        }
        for entity in schema.extra_entities {
            let wire = if plugin == "jwt" {
                "jwks".into()
            } else {
                wire_name(entity.mod_name)
            };
            let mut chars = wire.chars();
            let name = chars
                .next()
                .map(|first| {
                    let mut name = first.to_uppercase().collect::<String>();
                    name.push_str(chars.as_str());
                    name
                })
                .unwrap_or_default();
            metadata.models.push(OpenApiModel::new(
                name,
                entity
                    .fields
                    .iter()
                    .filter_map(|definition| field(definition, false))
                    .collect(),
            ));
        }
    }
    metadata
}
#[must_use]
pub fn instance_plugin_metadata<S: crate::AuthSchema>(
    plugin: &str,
    routes: &[AuthRoute],
    ctx: &crate::AuthInitContext<S>,
) -> PluginOpenApiMetadata {
    let mut metadata = plugin_metadata(plugin, routes);
    super::model_annotations::apply(plugin, ctx, &mut metadata);
    metadata
}
#[must_use]
pub fn core_routes() -> Vec<AuthRoute> {
    vec![
        AuthRoute::get("/ok", "ok"),
        AuthRoute::get("/error", "error"),
        AuthRoute::post("/update-user", "update_user"),
    ]
}
fn response(description: &str, schema: &Value) -> Value {
    json!({"description":description,"content":{"application/json":{"schema":schema}}})
}
fn endpoint(path: &str) -> Option<OpenApiEndpoint> {
    if let Some(metadata) = super::sign_in_annotations::endpoint(path)
        .or_else(|| super::oauth_annotations::endpoint(path))
    {
        return Some(metadata);
    }
    if let Some(metadata) = super::user_annotations::endpoint(path) {
        return Some(metadata);
    }
    if let Some(metadata) = super::account_annotations::endpoint(path)
        .or_else(|| super::password_annotations::endpoint(path))
        .or_else(|| super::email_annotations::endpoint(path))
    {
        return Some(metadata);
    }
    if let Some(metadata) = super::session_annotations::endpoint(path) {
        return Some(metadata);
    }
    let mut metadata = OpenApiEndpoint::default();
    match path {
        "/callback/{provider}" | "/callback/:id" => {
            metadata.document_path = Some("/callback/:id".into());
            let mut properties = serde_json::Map::new();
            for name in [
                "code",
                "error",
                "device_id",
                "error_description",
                "state",
                "user",
                "iss",
            ] {
                drop(properties.insert(name.into(), json!({"type":"string"})));
            }
            metadata.request_body = Some(
                json!({"required":false,"content":{"application/json":{"schema":{"type":"object","properties":properties}}}}),
            );
        }
        "/ok" => {
            metadata.description = Some("Check if the API is working".into());
            drop(metadata.responses.insert("200".into(), response("API is working",&(json!({"type":"object","properties":{"ok":{"type":"boolean","description":"Indicates if the API is working"}},"required":["ok"]})))));
        }
        "/error" => {
            metadata.description = Some("Displays an error page".into());
            drop(metadata.responses.insert("200".into(),json!({"description":"Success","content":{"text/html":{"schema":{"type":"string","description":"The HTML content of the error page"}}}})));
        }
        "/get-session" => {
            metadata.operation_id = Some("getSession".into());
            metadata.description = Some("Get the current session".into());
            // The upstream query is an optional wrapper; getParameters only
            // reflects a direct object, so its generated parameter list is empty.
            drop(metadata.responses.insert("200".into(),response("Success",&(json!({"type":["object","null"],"properties":{"session":{"$ref":"#/components/schemas/Session"},"user":{"$ref":"#/components/schemas/User"}},"required":["session","user"]})))));
        }
        _ => return None,
    }
    Some(metadata)
}
