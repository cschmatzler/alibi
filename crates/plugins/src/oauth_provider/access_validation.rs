//! Trusted server access-token validation without protocol client authentication.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::EndpointError;
use alibi_core::store::OAuthTokenKind;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthSession};
use serde_json::{Value, json};

impl OAuthProviderPlugin {
    /// Validate access authority and return its RFC 7662 payload.
    /// Unknown tokens are errors; recognized but inactive authority returns `active: false`.
    pub async fn validate_access_token<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        token: &str,
        client_id: Option<&str>,
    ) -> Result<Value, EndpointError> {
        if !self.config.disable_jwt_plugin
            && let Some(jwt) = ctx.extensions.get::<crate::jwt::JwtPlugin>()
            && let Some(mut claims) = jwt.verify_signed_payload(token, None, ctx).await?
        {
            let now = serde_json::Number::from(chrono::Utc::now().timestamp())
                .as_f64()
                .ok_or_else(|| AuthError::internal("Invalid token validation time"))?;
            let issuer = issuer(ctx, self.config.disable_jwt_plugin);
            if claims.get("iss").and_then(Value::as_str) != Some(issuer.as_str()) {
                return Err(AuthError::internal("unexpected \"iss\" claim value").into());
            }
            for field in ["exp", "nbf", "iat"] {
                if claims.get(field).is_some_and(|value| !value.is_number()) {
                    return Ok(json!({"active":false}));
                }
            }
            if claims
                .get("nbf")
                .and_then(Value::as_f64)
                .is_some_and(|nbf| nbf > now)
            {
                return Err(AuthError::internal("unexpected \"nbf\" claim value").into());
            }
            if claims
                .get("exp")
                .and_then(Value::as_f64)
                .is_some_and(|exp| exp <= now)
            {
                return Ok(json!({"active":false}));
            }
            let Some(resources) = audience_values(claims.get("aud")) else {
                return Ok(json!({"active":false}));
            };
            if !audiences_allowed(ctx, &resources).await? {
                return Ok(json!({"active":false}));
            }
            let Some(issuing_id) = claims
                .get("azp")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
            else {
                return Ok(json!({"active":false}));
            };
            let Some(client) = self.get_client(ctx, &issuing_id).await? else {
                return Ok(json!({"active":false}));
            };
            if client.metadata.get("disabled") == Some(&Value::Bool(true))
                || !authorized(ctx, client_id, &issuing_id, &resources).await?
            {
                return Ok(json!({"active":false}));
            }
            if let Some(sid) = claims.get("sid").and_then(Value::as_str)
                && ctx
                    .database
                    .get_session_by_id(sid)
                    .await?
                    .is_none_or(|session| session.expires_at() < chrono::Utc::now())
            {
                return Ok(json!({"active":false}));
            }
            _ = claims.insert("client_id".into(), json!(issuing_id));
            _ = claims.insert("active".into(), json!(true));
            _ = claims.insert(
                "token_type".into(),
                json!(if claims
                    .get("cnf")
                    .and_then(|cnf| cnf.get("jkt"))
                    .and_then(Value::as_str)
                    .is_some_and(|jkt| !jkt.is_empty())
                {
                    "DPoP"
                } else {
                    "Bearer"
                }),
            );
            return Ok(Value::Object(claims));
        }
        if !self.config.disable_jwt_plugin && compact_jwt(token) {
            return Err(AuthError::internal("JWT verification failed").into());
        }
        let hash = self.hash_token(token, "access_token").await?;
        let Some(row) = ctx
            .database
            .get_oauth_token(OAuthTokenKind::Access, &hash)
            .await?
        else {
            return Err(invalid_access_token());
        };
        let Some(row) = super::userinfo::live_access_row(row, ctx, self).await? else {
            return Ok(json!({"active":false}));
        };
        let resources = row
            .metadata
            .get("resources")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !audiences_allowed(ctx, &resources).await?
            || !authorized(ctx, client_id, &row.client_id, &resources).await?
        {
            return Ok(json!({"active":false}));
        }
        let scopes = row
            .metadata
            .get("scopes")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            });
        let payload = json!({"active":true,"iss":issuer(ctx,self.config.disable_jwt_plugin),"client_id":row.client_id,"azp":row.client_id,"exp":row.expires_at.timestamp(),"iat":row.created_at.timestamp(),"token_type":"Bearer"});
        let mut payload = payload
            .as_object()
            .cloned()
            .ok_or_else(|| AuthError::internal("Invalid access-token payload"))?;
        if let Some(scope) = scopes {
            _ = payload.insert("scope".into(), json!(scope));
        }
        if let Some(user_id) = row.user_id.as_deref()
            && let Some(user) = ctx.database.get_user_by_id(user_id).await?
        {
            _ = payload.insert("sub".into(), json!(ctx.user_view(&user).id));
        }
        if let Some(sid) = row.session_id {
            _ = payload.insert("sid".into(), json!(sid));
        }
        if !resources.is_empty() {
            let mut audiences = resources;
            let userinfo = format!("{}/oauth2/userinfo", base_url(ctx));
            if scopes_contain(&row.metadata, "openid") && !audiences.contains(&userinfo) {
                audiences.push(userinfo);
            }
            _ = payload.insert(
                "aud".into(),
                match audiences.as_slice() {
                    [one] => json!(one),
                    _ => json!(audiences),
                },
            );
        }
        Ok(Value::Object(payload))
    }
    /// Require recognized and active authority, preserving the reference Bearer challenge.
    pub async fn require_active_access_token<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        token: &str,
        client_id: Option<&str>,
    ) -> Result<Value, EndpointError> {
        let payload = self.validate_access_token(ctx, token, client_id).await?;
        if payload.get("active") == Some(&Value::Bool(true)) {
            Ok(payload)
        } else {
            Err(invalid_access_token())
        }
    }
}
fn base_url<S: AuthSchema>(ctx: &AuthContext<S>) -> String {
    format!(
        "{}{}",
        ctx.config.base_url.trim_end_matches('/'),
        ctx.config.base_path
    )
}
fn issuer<S: AuthSchema>(ctx: &AuthContext<S>, disabled: bool) -> String {
    if !disabled
        && let Some(value) = ctx
            .extensions
            .get::<crate::jwt::JwtDiscoveryOptions>()
            .and_then(|jwt| jwt.issuer.clone())
    {
        return value;
    }
    base_url(ctx)
}
fn audience_values(value: Option<&Value>) -> Option<Vec<String>> {
    match value {
        None => Some(Vec::new()),
        Some(Value::String(value)) => Some(vec![value.clone()]),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| value.as_str().map(str::to_owned))
            .collect(),
        _ => None,
    }
}
async fn audiences_allowed<S: AuthSchema>(
    ctx: &AuthContext<S>,
    audiences: &[String],
) -> AuthResult<bool> {
    if audiences.len() > 64 {
        return Ok(false);
    }
    let userinfo = format!("{}/oauth2/userinfo", base_url(ctx));
    for audience in audiences {
        if audience != &userinfo && ctx.database.get_oauth_resource(audience).await?.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}
async fn authorized<S: AuthSchema>(
    ctx: &AuthContext<S>,
    caller: Option<&str>,
    issuer: &str,
    resources: &[String],
) -> AuthResult<bool> {
    if caller.is_none_or(|caller| caller.is_empty() || caller == issuer) {
        return Ok(true);
    }
    let links = ctx
        .database
        .list_oauth_client_resources(caller.unwrap_or_default())
        .await?;
    Ok(links
        .iter()
        .any(|link| resources.contains(&link.resource_id)))
}
fn scopes_contain(metadata: &Value, scope: &str) -> bool {
    metadata
        .get("scopes")
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|value| value == scope))
}
fn invalid_access_token() -> EndpointError {
    let mut headers = alibi_core::Headers::new();
    _ = headers.insert(
        "WWW-Authenticate",
        "Bearer error=\"invalid_token\", error_description=\"Invalid access token\"",
    );
    EndpointError {
        error: AuthError::Api {
            status: 401,
            code: None,
            message: String::new(),
        },
        headers: Some(headers),
        body: Some(Box::new(alibi_core::utils::json::JsValue::from(
            json!({"error":"invalid_token","error_description":"Invalid access token"}),
        ))),
        body_absent: false,
    }
}

fn compact_jwt(token: &str) -> bool {
    use base64::Engine as _;
    let parts = token.split('.').collect::<Vec<_>>();
    let [header, payload, signature] = parts.as_slice() else {
        return false;
    };
    let decode = |text: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    };
    decode(header).is_some_and(|value| value.get("alg").is_some_and(Value::is_string))
        && decode(payload).is_some_and(|value| value.is_object())
        && !signature.is_empty()
}
