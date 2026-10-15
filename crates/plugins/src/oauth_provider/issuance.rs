//! Shared trusted minting primitive; grant admission belongs to the caller.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointCall, EndpointError};
use alibi_core::store::{CreateOAuthToken, OAuthClient, OAuthToken, OAuthTokenKind};
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
    /// Retained authority supplied by an already-authorized caller. Rotation
    /// atomically claims its ID; endpoint scope/client admission is not repeated.
    pub refresh_token: Option<OAuthToken>,
    pub requested_user_info_claims: Option<Vec<String>>,
    pub access_token_claims: Option<Value>,
    pub id_token_claims: Option<Value>,
    pub token_response: Option<Value>,
    pub confirmation: Option<Value>,
    /// Captured authorization data, including `query.dpop_jkt`.
    pub verification_value: Option<Value>,
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
            refresh_token: None,
            requested_user_info_claims: None,
            access_token_claims: None,
            id_token_claims: None,
            token_response: None,
            confirmation: None,
            verification_value: None,
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
pub(super) fn remaining(issued: i64, expires: &Value) -> AuthResult<Value> {
    let issued = json!(issued)
        .as_f64()
        .ok_or_else(|| AuthError::internal("Invalid issuance time"))?;
    let expires = expires
        .as_f64()
        .ok_or_else(|| AuthError::internal("Invalid token expiration"))?;
    number(expires - issued)
}
pub(super) struct AccessTokenIssuance<'a> {
    pub params: &'a OAuthTokenIssueParams,
    pub issued: chrono::DateTime<chrono::Utc>,
    pub expires: &'a Value,
    pub policy: &'a super::resource_policy::ResourceAdmission,
    pub refresh_id: Option<&'a str>,
}
fn token_metadata(p: &OAuthTokenIssueParams) -> serde_json::Map<String, Value> {
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
    metadata
}
impl OAuthProviderPlugin {
    pub(super) fn access_expiration<T: AsRef<str>>(
        &self,
        issued: i64,
        has_user: bool,
        scopes: &[T],
    ) -> AuthResult<Value> {
        let lifetime = if has_user {
            self.config.access_token_expires_in
        } else {
            self.config.m2m_access_token_expires_in
        };
        let mut result = expiration(issued, lifetime)?;
        for scope in scopes {
            let Some(configured) = self.config.scope_expirations.get(scope.as_ref()) else {
                continue;
            };
            // The reference tests the configured value's JS truthiness before
            // converting it: numeric zero/NaN are absent, a Date at epoch isn't.
            if matches!(configured,crate::jwt::JwtExpiration::Numeric(value) if *value==0.0 || value.is_nan())
            {
                continue;
            }
            let candidate = configured.timestamp(Some(&json!(issued)));
            let current = result
                .as_f64()
                .ok_or_else(|| AuthError::internal("Invalid scope expiration"))?;
            let proposed = candidate
                .as_f64()
                .ok_or_else(|| AuthError::internal("Invalid scope expiration"))?;
            if current >= proposed {
                result = candidate;
            }
        }
        Ok(result)
    }
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
    pub(super) async fn create_access_token<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        req: &impl alibi_core::session::SessionRequest,
        issuance: AccessTokenIssuance<'_>,
    ) -> Result<String, EndpointError> {
        let AccessTokenIssuance {
            params: p,
            issued,
            expires: expires_claim,
            policy,
            refresh_id,
        } = issuance;
        let audiences = &policy.audiences;
        let expires = expiration_date(expires_claim)?;
        let user_id = p.user.as_ref().map(|user| user.id().as_ref().to_owned());
        let mut metadata = token_metadata(p);
        let access = if !self.config.disable_jwt_plugin && !audiences.is_empty() {
            let base = format!(
                "{}{}",
                ctx.config.base_url.trim_end_matches('/'),
                ctx.config.base_path
            );
            let audience = if audiences.len() == 1 {
                json!(audiences.first())
            } else {
                json!(audiences)
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
            payload.extend(policy.claims.clone());
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
                signing_algorithm: policy.signing_algorithm,
                signing_key_id: policy.signing_key_id.clone(),
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
            if let Some(id) = refresh_id {
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
        Ok(access)
    }
    pub(super) async fn create_refresh_token<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        p: &OAuthTokenIssueParams,
        policy: &super::resource_policy::ResourceAdmission,
        issued: chrono::DateTime<chrono::Utc>,
        requested: bool,
    ) -> Result<Option<(String, String)>, EndpointError> {
        let Some(user) = p.user.as_ref() else {
            return Ok(None);
        };
        if !requested || !super::authentication::client_allows_grant(&p.client, "refresh_token") {
            return Ok(None);
        }
        let token = random_token();
        let protected = self.hash_token(&token, "refresh_token").await?;
        if let Some(original) = p.refresh_token.as_ref()
            && !ctx
                .database
                .claim_oauth_refresh_rotation_by_id(
                    &original.id,
                    issued,
                    super::refresh::replay_deadline(
                        issued,
                        self.config.refresh_token_reuse_interval,
                    )?,
                )
                .await?
        {
            return Err(super::resource_policy::failure(
                "invalid_grant",
                "invalid refresh token",
            ));
        }
        let mut metadata = token_metadata(p);
        let resources = p
            .refresh_token
            .as_ref()
            .and_then(|row| row.metadata.get("resources"))
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| json!(p.original_resources.as_ref().or(p.resources.as_ref())));
        _ = metadata.insert("resources".into(), resources);
        _ = metadata.insert("authTime".into(), json!(p.auth_time));
        let row = ctx
            .database
            .create_oauth_token(
                OAuthTokenKind::Refresh,
                CreateOAuthToken {
                    token: protected,
                    client_id: p.client.client_id.clone(),
                    user_id: Some(user.id().as_ref().to_owned()),
                    session_id: p.session_id.clone(),
                    authorization_code_id: p.authorization_code_id.clone(),
                    metadata: Value::Object(metadata),
                    created_at: issued,
                    expires_at: expiration_date(&policy.refresh_expiration(
                        issued.timestamp(),
                        self.config.refresh_token_expires_in,
                    )?)?,
                },
            )
            .await?;
        Ok(Some((row.id, token)))
    }
    pub(super) async fn mint_tokens<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        req: &impl alibi_core::session::SessionRequest,
        p: &OAuthTokenIssueParams,
    ) -> Result<Value, EndpointError> {
        let issued = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .ok_or_else(|| AuthError::internal("Invalid token issue time"))?;
        let expires_claim =
            self.access_expiration(issued.timestamp(), p.user.is_some(), &p.scopes)?;
        let resource_value = json!(p.resources);
        let admission = self
            .admit_resources(ctx, &p.client.client_id, &p.scopes, Some(&resource_value))
            .await?;
        let expires_claim = admission.access_expiration(issued.timestamp(), &expires_claim)?;
        let refresh_requested = p.scopes.iter().any(|scope| scope == "offline_access")
            || p.refresh_token
                .as_ref()
                .and_then(|row| row.metadata.get("scopes"))
                .and_then(Value::as_array)
                .is_some_and(|scopes| scopes.iter().any(|scope| scope == "offline_access"));
        let mut resolved = p.clone();
        resolved.scopes = admission.scopes.clone();
        resolved.confirmation = match p.confirmation.as_ref().filter(|value| !value.is_null()) {
            Some(confirmation) => Some(confirmation.clone()),
            None => self.resolve_dpop_binding(ctx, req, p, &admission).await?,
        };
        if resolved.requested_user_info_claims.is_none() {
            resolved.requested_user_info_claims = p
                .refresh_token
                .as_ref()
                .and_then(|row| row.metadata.get("requestedUserInfoClaims"))
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                });
        }
        let p = &resolved;
        let refresh = self
            .create_refresh_token(ctx, p, &admission, issued, refresh_requested)
            .await?;
        let rotated = refresh.is_some();
        let access = self
            .create_access_token(
                ctx,
                req,
                AccessTokenIssuance {
                    params: p,
                    issued,
                    expires: &expires_claim,
                    policy: &admission,
                    refresh_id: refresh.as_ref().map(|(id, _)| id.as_str()),
                },
            )
            .await?;
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
            ("expires_in", remaining(issued.timestamp(), &expires_claim)?),
            ("expires_at", expires_claim),
            (
                "token_type",
                json!(if p
                    .confirmation
                    .as_ref()
                    .and_then(crate::oauth2::get_confirmation_jkt)
                    .is_some()
                {
                    "DPoP"
                } else {
                    "Bearer"
                }),
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
        let response = Value::Object(response);
        if rotated && let Some(original) = p.refresh_token.as_ref() {
            let scopes = p.scopes.iter().map(String::as_str).collect::<Vec<_>>();
            let request = super::refresh::replay_request(
                &scopes,
                &json!({"resource":p.resources}),
                None,
                p.confirmation.as_ref(),
            );
            self.store_rotation_replay(ctx, original, request, &response)
                .await;
        }
        Ok(response)
    }
}
