//! Admit scope arrays before registering or updating durable OIDC configuration.
use super::{AuthResult, JsValue};
use crate::authentication_helpers::json_type;

pub(super) fn validate(scopes: &JsValue) -> AuthResult<()> {
    let Some(values) = scopes.as_array() else {
        return Err(crate::endpoint::validation(format!(
            "[body.oidcConfig.scopes] Invalid input: expected array, received {}",
            json_type(Some(scopes))
        )));
    };
    let issues = values
        .iter()
        .enumerate()
        .filter(|(_, value)| !value.is_string())
        .map(|(index, value)| {
            format!(
                "[body.oidcConfig.scopes.{index}] Invalid input: expected string, received {}",
                json_type(Some(value))
            )
        })
        .collect::<Vec<_>>();
    if issues.is_empty() {
        Ok(())
    } else {
        Err(crate::endpoint::validation(issues.join("; ")))
    }
}
