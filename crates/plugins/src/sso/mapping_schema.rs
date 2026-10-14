//! Validate protocol-specific public identity mappings before provider writes.
use super::super::authentication_helpers::{JsonField, JsonFieldKind};
use super::{AuthError, AuthResult, JsValue};
pub(super) fn oidc(mapping: &JsValue) -> AuthResult<JsValue> {
    validate(mapping, false)
}
pub(super) fn saml(mapping: &JsValue) -> AuthResult<JsValue> {
    validate(mapping, true)
}
fn validate(mapping: &JsValue, saml: bool) -> AuthResult<JsValue> {
    let location = if saml {
        "body.samlConfig.mapping"
    } else {
        "body.oidcConfig.mapping"
    };
    let mut fields = vec![
        JsonField::string("email", true),
        JsonField::string("emailVerified", false),
        JsonField::string("name", true),
    ];
    if saml {
        fields.extend([
            JsonField::string("firstName", false),
            JsonField::string("lastName", false),
        ]);
    } else {
        fields.push(JsonField::string("image", false));
    }
    fields.push(JsonField {
        name: "extraFields",
        kind: JsonFieldKind::Record,
        required: false,
    });
    let parsed = super::super::endpoint::validate_fields(Some(mapping), location, &fields);
    let unknown = mapping.as_object().map_or_else(Vec::new, |object| {
        object
            .keys()
            .filter(|name| !fields.iter().any(|field| field.name == name.as_str()))
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_default()
    });
    if unknown.is_empty() {
        return parsed;
    }
    let suffix = if unknown.len() == 1 { "" } else { "s" };
    let issue = format!(
        "[{location}] Unrecognized key{suffix}: {}",
        unknown.join(", ")
    );
    let issue = match parsed {
        Err(AuthError::Api { message, .. }) => format!("{message}; {issue}"),
        Err(error) => return Err(error),
        Ok(_) => issue,
    };
    Err(super::super::endpoint::validation(issue))
}
