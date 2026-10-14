//! Effective manual `IdP` SSO services for linked authentication authority.
use super::{Value, json};
const REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
pub(super) fn identity(config: &Value, binding: &str) -> Value {
    let mut services = serde_json::Map::<String, Value>::new();
    if let Some(entries) = config
        .get("idpMetadata")
        .and_then(|idp| idp.get("singleSignOnService"))
        .and_then(Value::as_array)
    {
        for entry in entries {
            let Some(binding) = entry.get("Binding").and_then(Value::as_str) else {
                continue;
            };
            let Some(location) = entry.get("Location") else {
                continue;
            };
            match services.get_mut(binding) {
                None => {
                    _ = services.insert(binding.into(), location.clone());
                }
                Some(Value::Array(values)) => values.push(location.clone()),
                Some(value) => *value = json!([value.clone(), location.clone()]),
            }
        }
    } else if let Some(location) = config.get("entryPoint") {
        _ = services.insert(REDIRECT.into(), location.clone());
    }
    services
        .get(binding)
        .cloned()
        .unwrap_or_else(|| Value::Object(services))
}
