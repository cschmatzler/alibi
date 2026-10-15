//! OIDC claims request structure and the provider's advertised claim boundary.
use super::OAuthProviderPlugin;
use alibi_core::utils::json::JsValue;
use serde_json::Value;

pub(super) struct ClaimsRequest {
    pub user_info: Vec<String>,
    pub acr_satisfied: bool,
}
pub(super) fn parse(value: &Value) -> Option<ClaimsRequest> {
    let parsed = match value {
        Value::String(text) => alibi_core::utils::json::parse_value(text).ok()?,
        value => JsValue::from(value.clone()),
    };
    let object = parsed.as_object()?;
    let mut user_info = Vec::new();
    if let Some(value) = object.get("userinfo") {
        let members = value.as_object()?;
        if members
            .values()
            .any(|member| !member.is_null() && !member.is_object())
        {
            return None;
        }
        user_info.extend(members.keys().cloned());
    }
    let mut acr_satisfied = true;
    if let Some(value) = object.get("id_token") {
        let members = value.as_object()?;
        if members
            .values()
            .any(|member| !member.is_null() && !member.is_object())
        {
            return None;
        }
        if let Some(acr) = members.get("acr").filter(|value| !value.is_null()) {
            let fields = acr.as_object()?;
            if fields
                .get("essential")
                .is_some_and(|value| !value.is_boolean())
                || fields.get("value").is_some_and(|value| !value.is_string())
                || fields.get("values").is_some_and(|value| {
                    value
                        .as_array()
                        .is_none_or(|values| values.iter().any(|value| !value.is_string()))
                })
            {
                return None;
            }
            if fields.get("essential").and_then(JsValue::as_bool) == Some(true) {
                acr_satisfied = fields
                    .get("value")
                    .is_none_or(|value| value.as_str() == Some("0"))
                    && fields.get("values").is_none_or(|value| {
                        value.as_array().is_some_and(|values| {
                            values.iter().any(|value| value.as_str() == Some("0"))
                        })
                    });
            }
        }
    }
    Some(ClaimsRequest {
        user_info,
        acr_satisfied,
    })
}
impl OAuthProviderPlugin {
    pub(super) fn supported_claims(&self) -> Vec<String> {
        if let Some(claims) = &self.config.advertised_claims {
            return claims.clone();
        }
        let mut claims = ["sub", "iss", "aud", "exp", "iat", "sid", "scope", "azp"]
            .map(str::to_owned)
            .to_vec();
        for (scope, names) in [
            (
                "profile",
                vec!["name", "picture", "given_name", "family_name"],
            ),
            ("email", vec!["email", "email_verified"]),
        ] {
            if self.config.scopes.iter().any(|value| value == scope) {
                claims.extend(names.into_iter().map(str::to_owned));
            }
        }
        claims
    }
}
