//! Built-in endpoint and model declarations owned by the feature crate.
mod account_annotations;
mod email_annotations;
mod model_annotations;
mod oauth_annotations;
mod password_annotations;
mod session_annotations;
mod sign_in_annotations;
mod user_annotations;
#[rustfmt::skip]
#[allow(warnings, clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction, reason = "Generated API declarations retain the upstream generator output")]
mod source_endpoints;
#[rustfmt::skip]
#[allow(warnings, clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction, reason = "Generated API declarations retain the upstream generator output")]
mod source_models;
use alibi_core::AuthRoute;
use alibi_core::{OpenApiEndpoint, OpenApiField, OpenApiModel, PluginOpenApiMetadata};
use alibi_schema_registry::{FieldDef, plugin_schemas};
use serde_json::{Value, json};

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
            _ = object.insert("default".into(), json!(false));
        }
    }
    Some(field)
}
/// Default annotations for registered built-in routes and plugin model fields.
/// Custom plugins should override their metadata hook to describe additional constraints.
#[must_use]
pub fn plugin_metadata(plugin: &str, routes: &[AuthRoute]) -> PluginOpenApiMetadata {
    let is_core = |owner: &str| {
        matches!(
            owner,
            "core"
                | "email-password"
                | "session-management"
                | "email-verification"
                | "password-management"
                | "user-management"
                | "account-management"
                | "oauth"
        )
    };
    let mut metadata = PluginOpenApiMetadata {
        core: is_core(plugin),
        ..Default::default()
    };
    for route in routes {
        let owner = if plugin == "email-password"
            && matches!(
                route.path.as_str(),
                "/sign-in/username" | "/is-username-available"
            ) {
            "username"
        } else {
            plugin
        };
        let mut annotation = source_endpoints::endpoint(owner, &route.path)
            .or_else(|| endpoint(&route.path))
            .unwrap_or_else(|| OpenApiEndpoint {
                operation_id: Some(route.operation_id.clone()),
                ..Default::default()
            });
        if owner != plugin {
            annotation.owner = Some(owner.into());
            annotation.core = Some(is_core(owner));
        }
        metadata
            .endpoints
            .push((route.method.clone(), route.path.clone(), annotation));
    }
    if let Some(models) = source_models::models(plugin) {
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
pub fn instance_plugin_metadata<S: alibi_core::AuthSchema>(
    plugin: &str,
    routes: &[AuthRoute],
    ctx: &alibi_core::AuthInitContext<S>,
) -> PluginOpenApiMetadata {
    let mut metadata = plugin_metadata(plugin, routes);
    model_annotations::apply(plugin, ctx, &mut metadata);
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
    if let Some(metadata) =
        sign_in_annotations::endpoint(path).or_else(|| oauth_annotations::endpoint(path))
    {
        return Some(metadata);
    }
    if let Some(metadata) = user_annotations::endpoint(path) {
        return Some(metadata);
    }
    if let Some(metadata) = account_annotations::endpoint(path)
        .or_else(|| password_annotations::endpoint(path))
        .or_else(|| email_annotations::endpoint(path))
    {
        return Some(metadata);
    }
    if let Some(metadata) = session_annotations::endpoint(path) {
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
                _ = properties.insert(name.into(), json!({"type":"string"}));
            }
            metadata.request_body = Some(
                json!({"required":false,"content":{"application/json":{"schema":{"type":"object","properties":properties}}}}),
            );
        }
        "/ok" => {
            metadata.description = Some("Check if the API is working".into());
            _ = metadata.responses.insert("200".into(), response("API is working",&(json!({"type":"object","properties":{"ok":{"type":"boolean","description":"Indicates if the API is working"}},"required":["ok"]}))));
        }
        "/error" => {
            metadata.description = Some("Displays an error page".into());
            _ = metadata.responses.insert("200".into(),json!({"description":"Success","content":{"text/html":{"schema":{"type":"string","description":"The HTML content of the error page"}}}}));
        }
        "/get-session" => {
            metadata.operation_id = Some("getSession".into());
            metadata.description = Some("Get the current session".into());
            // The upstream query is an optional wrapper; getParameters only
            // reflects a direct object, so its generated parameter list is empty.
            _ = metadata.responses.insert("200".into(),response("Success",&(json!({"type":["object","null"],"properties":{"session":{"$ref":"#/components/schemas/Session"},"user":{"$ref":"#/components/schemas/User"}},"required":["session","user"]}))));
        }
        _ => return None,
    }
    Some(metadata)
}
