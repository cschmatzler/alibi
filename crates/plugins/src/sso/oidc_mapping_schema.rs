//! Validate the public OIDC identity mapping schema before provider writes.
use super::super::authentication_helpers::{JsonField, JsonFieldKind};
use super::{AuthError, AuthResult, JsValue};
pub(super) fn validate(mapping: &JsValue) -> AuthResult<JsValue> {
    let location = "body.oidcConfig.mapping";
    let fields = [
        JsonField::string("email", true),
        JsonField::string("emailVerified", false),
        JsonField::string("name", true),
        JsonField::string("image", false),
        JsonField {
            name: "extraFields",
            kind: JsonFieldKind::Record,
            required: false,
        },
    ];
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
