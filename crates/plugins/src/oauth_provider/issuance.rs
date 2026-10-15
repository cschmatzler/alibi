//! Shared trusted minting primitive; grant admission belongs to the caller.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointCall, EndpointError};
use alibi_core::store::{CreateOAuthToken, OAuthClient, OAuthTokenKind};
use alibi_core::wire::UserView;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthUser};
use serde_json::{Value, json};

/// Inputs authorized by a trusted grant handler or companion endpoint.
/// Supplying these does not repeat client authentication or scope admission.
#[derive(Clone, Debug)]
pub struct OAuthTokenIssueParams {
    pub client: OAuthClient,
    pub scopes: Vec<String>,
    pub user: Option<UserView>,
    pub reference_id: Option<String>,
    pub session_id: Option<String>,
    pub nonce: Option<String>,
    pub auth_time: Option<chrono::DateTime<chrono::Utc>>,
    pub resources: Option<Vec<String>>,
    pub original_resources: Option<Vec<String>>,
    pub requested_user_info_claims: Option<Vec<String>>,
    pub access_token_claims: Option<Value>,
    pub id_token_claims: Option<Value>,
    pub token_response: Option<Value>,
    pub confirmation: Option<Value>,
    pub(crate) authorization_code_id: Option<String>,
}
impl OAuthTokenIssueParams {
    pub fn new(client: OAuthClient, scopes: Vec<String>) -> Self {
        Self {
            client,
            scopes,
            user: None,
            reference_id: None,
            session_id: None,
            nonce: None,
            auth_time: None,
            resources: None,
            original_resources: None,
            requested_user_info_claims: None,
            access_token_claims: None,
            id_token_claims: None,
            token_response: None,
            confirmation: None,
            authorization_code_id: None,
        }
    }
}
pub(super) fn random_token() -> String {
    rand::RngExt::sample_iter(rand::rng(), rand::distr::Alphanumeric)
        .map(char::from)
        .filter(char::is_ascii_alphabetic)
        .take(32)
        .collect()
}
/// Preserve JavaScript number serialization, including integral default values.
pub(super) fn number(value: f64) -> AuthResult<Value> {
    serde_json::from_str(&value.to_string()).map_err(AuthError::from)
}
pub(super) fn expiration(issued: i64, lifetime: f64) -> AuthResult<Value> {
    let issued = json!(issued)
        .as_f64()
        .ok_or_else(|| AuthError::internal("Invalid issuance time"))?;
    number(issued + lifetime)
}
pub(super) fn expiration_date(value: &Value) -> AuthResult<chrono::DateTime<chrono::Utc>> {
    let seconds = value
        .as_f64()
        .ok_or_else(|| AuthError::internal("Invalid token expiration"))?;
    let millis = (seconds * 1000.0)
        .trunc()
        .to_string()
        .parse::<i64>()
        .map_err(|_| AuthError::internal("Invalid token expiration"))?;
    chrono::DateTime::from_timestamp_millis(millis)
        .ok_or_else(|| AuthError::internal("Invalid token expiration"))
}
impl OAuthProviderPlugin {
    /// Mint authority for an already authorized caller. The grant is required,
    /// but need not be registered: admission is the trusted caller's responsibility.
    pub async fn issue_tokens<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        call: &EndpointCall,
        grant_type: Option<&str>,
        params: &OAuthTokenIssueParams,
    ) -> Result<Value, EndpointError> {
        if grant_type.is_none_or(str::is_empty) {
            return Err(EndpointError {
                error: AuthError::Api {
                    status: 500,
                    code: None,
                    message: String::new(),
                },
                headers: None,
                body: Some(Box::new(alibi_core::utils::json::JsValue::from(
                    json!({"error":"server_error","error_description":"issueTokens requires a grant type; pass it to getOAuthProviderApi(ctx, opts, grantType)."}),
                ))),
                body_absent: false,
            });
        }
        self.mint_tokens(ctx, call, params).await
    }
    pub(super) async fn mint_tokens<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        req: &impl alibi_core::session::SessionRequest,
        p: &OAuthTokenIssueParams,
    ) -> Result<Value, EndpointError> {
        let issued = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .ok_or_else(|| AuthError::internal("Invalid token issue time"))?;
        let lifetime = if p.user.is_some() {
            self.config.access_token_expires_in
        } else {
            self.config.m2m_access_token_expires_in
        };
        let expires_claim = expiration(issued.timestamp(), lifetime)?;
        let expires = expiration_date(&expires_claim)?;
        let user_id = p.user.as_ref().map(|user| user.id().as_ref().to_owned());
        let mut metadata = serde_json::Map::from_iter([
            ("scopes".into(), json!(p.scopes)),
            ("resources".into(), json!(p.resources)),
        ]);
        for (key, value) in [
            (
                "referenceId",
                p.reference_id.as_ref().map(|value| json!(value)),
            ),
            ("confirmation", p.confirmation.clone()),
            (
                "requestedUserInfoClaims",
                p.requested_user_info_claims
                    .as_ref()
                    .filter(|v| !v.is_empty())
                    .map(|v| json!(v)),
            ),
        ] {
            if let Some(value) = value {
                _ = metadata.insert(key.into(), value);
            }
        }
        let refresh = if p.user.is_some()
            && p.scopes.iter().any(|s| s == "offline_access")
            && super::authentication::client_allows_grant(&p.client, "refresh_token")
        {
            let token = random_token();
            let mut retained = metadata.clone();
            _ = retained.insert(
                "resources".into(),
                json!(p.original_resources.as_ref().or(p.resources.as_ref())),
            );
            _ = retained.insert("authTime".into(), json!(p.auth_time));
            let row = ctx
                .database
                .create_oauth_token(
                    OAuthTokenKind::Refresh,
                    CreateOAuthToken {
                        token: self.hash_token(&token, "refresh_token").await?,
                        client_id: p.client.client_id.clone(),
                        user_id: user_id.clone(),
                        session_id: p.session_id.clone(),
                        authorization_code_id: p.authorization_code_id.clone(),
                        metadata: Value::Object(retained),
                        created_at: issued,
                        expires_at: expiration_date(&expiration(
                            issued.timestamp(),
                            self.config.refresh_token_expires_in,
                        )?)?,
                    },
                )
                .await?;
            Some((row.id, token))
        } else {
            None
        };
        let access = if !self.config.disable_jwt_plugin
            && p.resources.as_ref().is_some_and(|r| !r.is_empty())
        {
            let base = format!(
                "{}{}",
                ctx.config.base_url.trim_end_matches('/'),
                ctx.config.base_path
            );
            let userinfo = format!("{base}/oauth2/userinfo");
            let mut audiences = p.resources.clone().unwrap_or_default();
            // Resource policy is resolved independently of client scope admission.
            for resource in &audiences {
                if resource != &userinfo
                    && ctx.database.get_oauth_resource(resource).await?.is_none()
                {
                    return Err(EndpointError {
                        error: AuthError::Api {
                            status: 400,
                            code: None,
                            message: String::new(),
                        },
                        headers: None,
                        body: Some(Box::new(alibi_core::utils::json::JsValue::from(
                            json!({"error":"invalid_target","error_description":format!("requested resource {resource} is not configured")}),
                        ))),
                        body_absent: false,
                    });
                }
            }
            if p.scopes.iter().any(|s| s == "openid") && !audiences.contains(&userinfo) {
                audiences.push(userinfo);
            }
            let mut unique = Vec::new();
            for resource in audiences {
                if !unique.contains(&resource) {
                    unique.push(resource);
                }
            }
            let audience = if unique.len() == 1 {
                json!(unique.first())
            } else {
                json!(unique)
            };
            let jwt = ctx
                .extensions
                .get::<crate::jwt::JwtPlugin>()
                .ok_or_else(|| AuthError::config("jwt_config"))?;
            let issuer = ctx
                .extensions
                .get::<crate::jwt::JwtDiscoveryOptions>()
                .and_then(|o| o.issuer.clone())
                .unwrap_or(base);
            let mut payload = p
                .access_token_claims
                .as_ref()
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            for key in [
                "sub",
                "aud",
                "client_id",
                "azp",
                "scope",
                "sid",
                "iss",
                "iat",
                "exp",
                "jti",
                "cnf",
                "auth_time",
                "acr",
                "amr",
            ] {
                _ = payload.remove(key);
            }
            for (key, value) in [
                (
                    "sub",
                    json!(user_id.as_deref().unwrap_or(&p.client.client_id)),
                ),
                ("aud", audience),
                ("client_id", json!(p.client.client_id)),
                ("azp", json!(p.client.client_id)),
                ("scope", json!(p.scopes.join(" "))),
                ("iss", json!(issuer)),
                ("iat", json!(issued.timestamp())),
                ("exp", expires_claim.clone()),
                ("jti", json!(random_token())),
            ] {
                _ = payload.insert(key.into(), value);
            }
            if let Some(sid) = &p.session_id {
                _ = payload.insert("sid".into(), json!(sid));
            }
            if let Some(cnf) = &p.confirmation {
                _ = payload.insert("cnf".into(), cnf.clone());
            }
            let options = crate::jwt::JwtSignOptions {
                header: Some(serde_json::Map::from_iter([(
                    "typ".into(),
                    json!("at+jwt"),
                )])),
                ..Default::default()
            };
            jwt.sign_jwt(payload, &options, req.physical_request(), ctx)
                .await?
        } else {
            let token = random_token();
            if let Some((id, _)) = &refresh {
                _ = metadata.insert("refreshId".into(), json!(id));
            }
            _ = ctx
                .database
                .create_oauth_token(
                    OAuthTokenKind::Access,
                    CreateOAuthToken {
                        token: self.hash_token(&token, "access_token").await?,
                        client_id: p.client.client_id.clone(),
                        user_id,
                        session_id: p.session_id.clone(),
                        authorization_code_id: p.authorization_code_id.clone(),
                        metadata: Value::Object(metadata),
                        created_at: issued,
                        expires_at: expires,
                    },
                )
                .await?;
            token
        };
        let mut response = p
            .token_response
            .as_ref()
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        for key in [
            "access_token",
            "expires_in",
            "expires_at",
            "token_type",
            "refresh_token",
            "scope",
            "id_token",
        ] {
            _ = response.remove(key);
        }
        for (key, value) in [
            ("access_token", json!(access)),
            ("expires_in", number(lifetime)?),
            ("expires_at", expires_claim),
            (
                "token_type",
                json!(
                    if p.confirmation.as_ref().and_then(|v| v.get("jkt")).is_some() {
                        "DPoP"
                    } else {
                        "Bearer"
                    }
                ),
            ),
            ("scope", json!(p.scopes.join(" "))),
        ] {
            _ = response.insert(key.into(), value);
        }
        if let Some((_, token)) = refresh {
            _ = response.insert("refresh_token".into(), json!(token));
        }
        if p.user.is_some() && p.scopes.iter().any(|s| s == "openid") {
            let proof = json!({"userId":p.user.as_ref().map(|u|u.id().as_ref().to_owned()),"sessionId":p.session_id,"authTime":p.auth_time.map(|t|t.timestamp_millis()),"query":{"nonce":p.nonce},"idTokenClaims":p.id_token_claims});
            match Box::pin(self.issue_id_token(&p.client, &proof, &access, req, ctx)).await? {
                Ok(Some(token)) => {
                    _ = response.insert("id_token".into(), json!(token));
                }
                Ok(None) => {}
                Err(response) => return Err(super::authentication::response_error(&response)?),
            }
        }
        Ok(Value::Object(response))
    }
}
