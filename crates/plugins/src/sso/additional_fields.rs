//! Declared provider input and response policies shared by real SSO operations.
use super::{AuthResult, JsValue, Value};
use alibi_core::field_policy::{FieldInputError, SessionFields};

pub(super) fn validate_and_copy(
    fields: &SessionFields,
    original: Option<&JsValue>,
    output: &mut JsValue,
    create: bool,
) -> AuthResult<()> {
    let mut issues = Vec::new();
    for (name, field) in &fields.0 {
        if !field.input {
            continue;
        }
        let value = original.and_then(|input| input.get(name));
        if value.is_none() && (!create || !field.required) {
            continue;
        }
        if value.is_some_and(JsValue::is_null) && !field.required {
            continue;
        }
        let kind = field
            .schema
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("string");
        let valid = value.is_some_and(|value| match kind {
            "string" => value.is_string(),
            "boolean" => value.as_bool().is_some(),
            "number" | "integer" => value.as_f64().is_some_and(f64::is_finite),
            "json" => true,
            "string[]" | "number[]" | "array" => value.as_array().is_some(),
            "object" => value.as_object().is_some(),
            _ => false,
        });
        if !valid {
            let expected = match kind {
                "string[]" | "number[]" => "array",
                other => other,
            };
            issues.push(format!(
                "[body.{name}] Invalid input: expected {expected}, received {}",
                crate::authentication_helpers::json_type(value)
            ));
        } else if matches!(kind, "string[]" | "number[]") {
            for (index, item) in value
                .and_then(JsValue::as_array)
                .into_iter()
                .flatten()
                .enumerate()
            {
                let expected = if kind == "string[]" {
                    "string"
                } else {
                    "number"
                };
                if !(if expected == "string" {
                    item.is_string()
                } else {
                    item.as_f64().is_some_and(f64::is_finite)
                }) {
                    issues.push(format!(
                        "[body.{name}.{index}] Invalid input: expected {expected}, received {}",
                        crate::authentication_helpers::json_type(Some(item))
                    ));
                }
            }
        }
    }
    if !issues.is_empty() {
        return Err(crate::endpoint::validation(issues.join("; ")));
    }
    if let JsValue::Object(output) = output {
        for name in fields.0.keys() {
            if let Some(value) = original.and_then(|input| input.get(name)) {
                _ = output.insert(name.clone(), value.clone());
            }
        }
    }
    Ok(())
}

pub(super) struct ParsedFields {
    pub values: serde_json::Map<String, Value>,
    pub has_input_fields: bool,
}

pub(super) fn parse(
    fields: &SessionFields,
    input: &JsValue,
    create: bool,
) -> AuthResult<ParsedFields> {
    for (name, field) in &fields.0 {
        if !field.input && input.get(name).is_some() {
            return Err(super::api(400, &format!("{name} is not allowed to be set")));
        }
    }
    let input = input
        .as_object()
        .ok_or_else(|| crate::endpoint::validation("Invalid body"))?;
    let parsed = if create {
        fields.parse_create(input)
    } else {
        fields.parse_update(input)
    }
    .map_err(|error| match error {
        FieldInputError::Validation { code, message } => alibi_core::AuthError::Api {
            status: 400,
            code: Some(code.into()),
            message,
        },
        FieldInputError::Transform(error) => error,
    })?;
    let has_input_fields = parsed.has_input_fields();
    let values = parsed
        .iter()
        .map(|(name, value)| Ok((name.clone(), value.to_json_value()?)))
        .collect::<AuthResult<_>>()?;
    Ok(ParsedFields {
        values,
        has_input_fields,
    })
}

pub(super) fn filter(fields: &SessionFields, output: &mut Value) {
    if let Some(output) = output.as_object_mut() {
        for (name, field) in &fields.0 {
            if !field.returned {
                _ = output.remove(name);
            }
        }
    }
}
