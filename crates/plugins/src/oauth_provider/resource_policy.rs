//! Live resource admission shared by browser grants and trusted/protocol minting.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::EndpointError;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthSchema};
use serde_json::{Value, json};

pub(super) struct ResourceAdmission {
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
}
pub(super) fn resource_list(value: Option<&Value>) -> Vec<String> {
    let values = match value {
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    let mut unique = Vec::new();
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}
pub(super) fn failure(code: &str, description: &str) -> EndpointError {
    EndpointError {
        error: AuthError::Api {
            status: 400,
            code: None,
            message: String::new(),
        },
        headers: None,
        body: Some(Box::new(JsValue::from(
            json!({"error":code,"error_description":description}),
        ))),
        body_absent: false,
    }
}
impl OAuthProviderPlugin {
    pub(super) async fn admit_resources<S: AuthSchema, T: AsRef<str>>(
        &self,
        ctx: &AuthContext<S>,
        client_id: &str,
        requested: &[T],
        resources: Option<&Value>,
    ) -> Result<ResourceAdmission, EndpointError> {
        let mut audiences = resource_list(resources);
        let mut scopes = requested
            .iter()
            .map(|scope| scope.as_ref().to_owned())
            .collect::<Vec<_>>();
        if audiences.is_empty() {
            return Ok(ResourceAdmission { scopes, audiences });
        }
        let userinfo = format!(
            "{}{}/oauth2/userinfo",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path
        );
        let mut rows = Vec::new();
        for resource in &audiences {
            if resource == &userinfo {
                continue;
            }
            let Some(row) = ctx.database.get_oauth_resource(resource).await? else {
                return Err(failure(
                    "invalid_target",
                    &format!("requested resource {resource} is not configured"),
                ));
            };
            if row.metadata.get("disabled") == Some(&Value::Bool(true)) {
                return Err(failure(
                    "invalid_target",
                    &format!("requested resource {resource} is disabled"),
                ));
            }
            rows.push(row);
        }
        if self.config.enforce_per_client_resources && !rows.is_empty() {
            let links = ctx.database.list_oauth_client_resources(client_id).await?;
            let missing = rows
                .iter()
                .filter(|row| !links.iter().any(|link| link.resource_id == row.identifier))
                .map(|row| row.identifier.as_str())
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                return Err(failure(
                    "invalid_target",
                    &format!(
                        "client {client_id} is not linked to resource(s) {}",
                        missing.join(", ")
                    ),
                ));
            }
        }
        for row in &rows {
            if let Some(allowed) = row.metadata.get("allowedScopes").and_then(Value::as_array) {
                scopes.retain(|scope| allowed.iter().any(|value| value.as_str() == Some(scope)));
                if scopes.is_empty() {
                    return Err(failure(
                        "invalid_scope",
                        &format!(
                            "none of the requested scopes are allowed for resource {}",
                            row.identifier
                        ),
                    ));
                }
            }
        }
        for (field, description) in [
            (
                "signingAlgorithm",
                "multi-resource request has conflicting signingAlgorithm pins; a single JWS signature cannot satisfy multiple algorithms",
            ),
            (
                "signingKeyId",
                "multi-resource request has conflicting signingKeyId pins; a single JWS signature cannot satisfy multiple key ids",
            ),
        ] {
            let pins = rows
                .iter()
                .filter_map(|row| row.metadata.get(field).and_then(Value::as_str))
                .filter(|value| !value.is_empty())
                .collect::<std::collections::HashSet<_>>();
            if pins.len() > 1 {
                return Err(failure("invalid_request", description));
            }
        }
        // The implicit UserInfo audience depends on the original request, not
        // the post-intersection scope set.
        if requested.iter().any(|scope| scope.as_ref() == "openid")
            && !audiences.contains(&userinfo)
        {
            audiences.push(userinfo);
        }
        Ok(ResourceAdmission { scopes, audiences })
    }
}
