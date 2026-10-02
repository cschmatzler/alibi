//! Additional and plugin user input fields on the two core writable-user routes.
use super::{OpenApiEndpoint, OpenApiField};
use indexmap::IndexMap;
use serde_json::{Map, Value, json};
fn property(field: &OpenApiField) -> Value {
    match field.schema.get("type").and_then(Value::as_str) {
        Some("json") => json!({}),
        Some("array") => {
            json!({"type":"array","items":field.schema.get("items").cloned().unwrap_or_else(||json!({}))})
        }
        _ => {
            let mut output = Map::new();
            for key in ["type", "enum", "format", "default"] {
                if let Some(value) = field.schema.get(key) {
                    drop(output.insert(key.into(), value.clone()));
                }
            }
            Value::Object(output)
        }
    }
}
pub(super) fn apply(
    path: &str,
    endpoint: &mut OpenApiEndpoint,
    fields: &IndexMap<String, OpenApiField>,
) {
    if !matches!(path, "/sign-up/email" | "/update-user") {
        return;
    }
    let writable = fields
        .values()
        .filter(|field| field.input)
        .collect::<Vec<_>>();
    if writable.is_empty() {
        return;
    }
    let body = endpoint.request_body.get_or_insert_with(
        || json!({"content":{"application/json":{"schema":{"type":"object","properties":{}}}}}),
    );
    let Some(schema) = body
        .pointer_mut("/content/application~1json/schema")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    let Some(properties) = schema
        .entry("properties")
        .or_insert_with(|| json!({}))
        .as_object_mut()
    else {
        return;
    };
    for field in &writable {
        let _ignored_or_insert_with = properties
            .entry(field.name.clone())
            .or_insert_with(|| property(field));
    }
    if path == "/sign-up/email" {
        let mut required = schema
            .get("required")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for field in writable {
            if field.required && !field.has_default && !required.contains(&json!(field.name)) {
                required.push(json!(field.name));
            }
        }
        if !required.is_empty() {
            drop(schema.insert("required".into(), json!(required)));
        }
    }
}
