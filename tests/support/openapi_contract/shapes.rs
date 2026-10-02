//! Field-naming checks for the public camelCase response contract.

use serde_json::Value;

// ---------------------------------------------------------------------------
// camelCase enforcement
// ---------------------------------------------------------------------------

/// Check that all field names in a JSON value use camelCase (no underscores).
pub fn check_camel_case_fields(value: &Value, path: &str) -> Vec<String> {
    let mut violations = Vec::new();
    check_camel_case_inner(value, path, &mut violations);
    violations
}

fn check_camel_case_inner(value: &Value, path: &str, violations: &mut Vec<String>) {
    if let Value::Object(map) = value {
        for (key, val) in map {
            let child_path = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };

            if key.contains('_') && !key.starts_with('_') {
                violations.push(format!("{child_path} (field: {key})"));
            }

            check_camel_case_inner(val, &child_path, violations);
        }
    } else if let Value::Array(arr) = value {
        for (i, item) in arr.iter().enumerate() {
            let child_path = format!("{path}[{i}]");
            check_camel_case_inner(item, &child_path, violations);
        }
    }
}
