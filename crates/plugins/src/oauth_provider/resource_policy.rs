//! Live resource admission shared by browser grants and trusted/protocol minting.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::EndpointError;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema};
use serde_json::{Value, json};

pub(super) struct ResourceAdmission {
    pub dpop_required: bool,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    pub access_ttl: Option<f64>,
    pub refresh_ttl: Option<f64>,
    pub claims: serde_json::Map<String, Value>,
    pub signing_algorithm: Option<crate::jwt::JwtAlgorithm>,
    pub signing_key_id: Option<String>,
}
impl ResourceAdmission {
    pub(super) fn access_expiration(
        &self,
        issued: i64,
        scope_expiration: &Value,
    ) -> AuthResult<Value> {
        let Some(ttl) = self.access_ttl else {
            return Ok(scope_expiration.clone());
        };
        let resource = super::issuance::expiration(issued, ttl)?
            .as_f64()
            .ok_or_else(|| AuthError::internal("Invalid resource expiration"))?;
        let scope = scope_expiration
            .as_f64()
            .ok_or_else(|| AuthError::internal("Invalid scope expiration"))?;
        super::issuance::number(resource.min(scope))
    }
    pub(super) fn refresh_expiration(&self, issued: i64, default: f64) -> AuthResult<Value> {
        super::issuance::expiration(
            issued,
            self.refresh_ttl.map_or(default, |ttl| ttl.min(default)),
        )
    }
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
            return Ok(ResourceAdmission {
                dpop_required: false,
                scopes,
                audiences,
                access_ttl: None,
                refresh_ttl: None,
                claims: serde_json::Map::new(),
                signing_algorithm: None,
                signing_key_id: None,
            });
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
        let mut access_ttl: Option<f64> = None;
        let mut refresh_ttl: Option<f64> = None;
        let mut claims = serde_json::Map::new();
        for row in &rows {
            if let Some(ttl) = row.metadata.get("accessTokenTtl").and_then(Value::as_f64) {
                access_ttl = Some(access_ttl.map_or(ttl, |current| current.min(ttl)));
            }
            if let Some(ttl) = row.metadata.get("refreshTokenTtl").and_then(Value::as_f64) {
                refresh_ttl = Some(refresh_ttl.map_or(ttl, |current| current.min(ttl)));
            }
            if let Some(fields) = row.metadata.get("customClaims").and_then(Value::as_object) {
                claims.extend(fields.clone());
            }
        }
        let signing_algorithm = rows
            .iter()
            .filter_map(|row| row.metadata.get("signingAlgorithm").and_then(Value::as_str))
            .find(|value| !value.is_empty())
            .map(str::parse)
            .transpose()?;
        let signing_key_id = rows
            .iter()
            .filter_map(|row| row.metadata.get("signingKeyId").and_then(Value::as_str))
            .find(|value| !value.is_empty())
            .map(str::to_owned);
        // The implicit UserInfo audience depends on the original request, not
        // the post-intersection scope set.
        if requested.iter().any(|scope| scope.as_ref() == "openid")
            && !audiences.contains(&userinfo)
        {
            audiences.push(userinfo);
        }
        Ok(ResourceAdmission {
            dpop_required: rows.iter().any(|row| {
                row.metadata.get("dpopBoundAccessTokensRequired") == Some(&Value::Bool(true))
            }),
            scopes,
            audiences,
            access_ttl,
            refresh_ttl,
            claims,
            signing_algorithm,
            signing_key_id,
        })
    }
}
