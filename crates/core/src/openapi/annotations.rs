//! Generic route annotations and the mandatory entity wire projections.
use super::{OpenApiEndpoint, OpenApiField, OpenApiModel, PluginOpenApiMetadata};
use crate::AuthRoute;
use alibi_schema_registry::{EntityRole, FieldDef, core_fields};
use serde_json::json;

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
/// Generic annotations for routes; built-in plugins supply their own declarations.
#[must_use]
pub fn route_metadata(routes: &[AuthRoute]) -> PluginOpenApiMetadata {
    PluginOpenApiMetadata {
        endpoints: routes
            .iter()
            .map(|route| {
                (
                    route.method.clone(),
                    route.path.clone(),
                    OpenApiEndpoint {
                        operation_id: Some(route.operation_id.clone()),
                        ..Default::default()
                    },
                )
            })
            .collect(),
        ..Default::default()
    }
}
