//! OAuth authorization-code token exchange and single-use grant lifecycle.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint};
use alibi_core::session::SessionRequest;
use alibi_core::store::{CreateOAuthToken, OAuthTokenKind};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthResult, AuthSchema, AuthSession};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
impl OAuthProviderPlugin {
    /// Exchange an OAuth grant through the provider's public server operation.
    pub fn oauth2_token_endpoint(
        input: &impl serde::Serialize,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "oauth2Token").with_body(input)
    }
    pub(super) async fn token<S: AuthSchema>(
        &self,
        input: Option<&JsValue>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let body: Value = input
            .map(JsValue::to_json_value)
            .transpose()?
            .unwrap_or_else(|| json!({}));
        let text = |key: &str| body.get(key).and_then(Value::as_str).unwrap_or_default();
        let grant = text("grant_type").trim();
        if !self
            .config
            .grant_types
            .iter()
            .any(|supported| supported == grant)
        {
            return error(
                400,
                "unsupported_grant_type",
                &format!("unsupported grant_type {grant}"),
            );
        }
        // Each remaining grant receives its own issuance and lifecycle finding.
        if grant != "authorization_code" {
            return error(
                400,
                "invalid_request",
                if text("client_id").is_empty() {
                    "Missing required client_id"
                } else if grant == "refresh_token" {
                    "Missing a required refresh_token for refresh_token grant"
                } else {
                    "Missing required client credentials"
                },
            );
        }
        let credentials = super::credentials::extract(&body, req);
        let client_id = credentials.client_id.clone();
        let secret = &credentials.secret;
        if client_id.is_empty() {
            return error(400, "invalid_request", "client_id is required");
        }
        let code = text("code");
        if code.is_empty() {
            return error(400, "invalid_request", "code is required");
        }
        let verifier = text("code_verifier");
        if secret.is_empty() && verifier.is_empty() {
            return error(
                400,
                "invalid_request",
                "Either code_verifier or client_secret is required",
            );
        }
        let identifier = URL_SAFE_NO_PAD.encode(Sha256::digest(code));
        let Some(proof) = ctx.verifications().consume(&identifier).await? else {
            ctx.database
                .delete_oauth_tokens_for_code(&identifier)
                .await?;
            return error(400, "invalid_grant", "invalid code");
        };
        let Ok(value) = serde_json::from_str::<Value>(proof.value()?) else {
            return error(400, "invalid_grant", "malformed verification value");
        };
        if value.get("type").unwrap_or(&Value::Null) != "authorization_code"
            || !value.get("query").unwrap_or(&Value::Null).is_object()
        {
            return error(400, "invalid_grant", "malformed verification value");
        }
        let query = &value.get("query").unwrap_or(&Value::Null);
        if query.get("client_id").and_then(Value::as_str) != Some(client_id.as_str()) {
            return error(400, "invalid_grant", "invalid client_id");
        }
        let bound = query
            .get("redirect_uri")
            .unwrap_or(&Value::Null)
            .as_str()
            .unwrap_or_default();
        if !bound.is_empty() && text("redirect_uri").is_empty() {
            return error(400, "invalid_request", "redirect_uri is required");
        }
        if bound != text("redirect_uri") {
            return error(400, "invalid_grant", "redirect_uri mismatch");
        }
        let Some(scope) = query.get("scope").unwrap_or(&Value::Null).as_str() else {
            return error(500, "invalid_scope", "verification scope unset");
        };
        let client = match credentials.authenticate(ctx).await? {
            Ok(client) => client,
            Err(response) => {
                return Ok(response
                    .with_header("Cache-Control", "no-store")
                    .with_header("Pragma", "no-cache"));
            }
        };
        let registered = client
            .metadata
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            .unwrap_or("client_secret_basic");
        if client
            .metadata
            .get("grant_types")
            .unwrap_or(&Value::Null)
            .as_array()
            .is_some_and(|grants| !grants.iter().any(|g| g == grant))
        {
            return error(
                400,
                "unauthorized_client",
                "client is not authorized to use grant type authorization_code",
            );
        }
        let ceiling = client
            .metadata
            .get("scope")
            .unwrap_or(&Value::Null)
            .as_str()
            .unwrap_or_default()
            .split(' ')
            .collect::<Vec<_>>();
        let invalid = scope
            .split(' ')
            .filter(|s| !ceiling.contains(s))
            .collect::<Vec<_>>();
        if !invalid.is_empty() {
            return error(
                400,
                "invalid_scope",
                &format!("The following scopes are invalid: {}", invalid.join(", ")),
            );
        }
        let challenge = query
            .get("code_challenge")
            .unwrap_or(&Value::Null)
            .as_str()
            .unwrap_or_default();
        if registered == "none" && verifier.is_empty() {
            return error(400, "invalid_request", "PKCE is required for this client");
        }
        if !challenge.is_empty() && verifier.is_empty() {
            return error(
                401,
                "invalid_request",
                "code_verifier required because PKCE was used in authorization",
            );
        }
        if challenge.is_empty() && !verifier.is_empty() {
            return error(
                401,
                "invalid_request",
                "code_verifier provided but PKCE was not used in authorization",
            );
        }
        if !verifier.is_empty()
            && (query.get("code_challenge_method").unwrap_or(&Value::Null) != "S256"
                || URL_SAFE_NO_PAD.encode(Sha256::digest(verifier)) != challenge)
        {
            return error(401, "invalid_request", "code verification failed");
        }
        let user_id = value
            .get("userId")
            .unwrap_or(&Value::Null)
            .as_str()
            .unwrap_or_default();
        if ctx.database.get_user_by_id(user_id).await?.is_none() {
            return error(
                400,
                "invalid_user",
                "missing user, user may have been deleted",
            );
        }
        let session_id = value
            .get("sessionId")
            .unwrap_or(&Value::Null)
            .as_str()
            .unwrap_or_default();
        let session = ctx
            .database
            .get_user_sessions(user_id)
            .await?
            .into_iter()
            .find(|s| s.id().as_ref() == session_id);
        if session.is_none_or(|s| s.expires_at() < chrono::Utc::now()) {
            return error(400, "invalid_request", "session no longer exists");
        }
        let issued = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .ok_or_else(|| alibi_core::AuthError::internal("Invalid token issue time"))?;
        let expires = issued + chrono::Duration::seconds(3600);

        let random_token = || {
            rand::RngExt::sample_iter(rand::rng(), rand::distr::Alphanumeric)
                .map(char::from)
                .filter(char::is_ascii_alphabetic)
                .take(32)
                .collect::<String>()
        };
        let scopes = scope.split(' ').collect::<Vec<_>>();
        let refresh_allowed = client
            .metadata
            .get("grant_types")
            .and_then(Value::as_array)
            .is_none_or(|grants| grants.iter().any(|g| g == "refresh_token"));
        let resources = value
            .get("resource")
            .filter(|value| value.as_array().is_none_or(|values| !values.is_empty()))
            .cloned()
            .unwrap_or(Value::Null);
        let refresh = if refresh_allowed && scopes.contains(&"offline_access") {
            let token = random_token();
            let auth_time = value
                .get("authTime")
                .and_then(Value::as_i64)
                .and_then(chrono::DateTime::from_timestamp_millis);
            let row = ctx.database.create_oauth_token(OAuthTokenKind::Refresh,CreateOAuthToken {
                token:URL_SAFE_NO_PAD.encode(Sha256::digest(&token)),client_id:client_id.clone(),user_id:Some(user_id.into()),session_id:Some(session_id.into()),authorization_code_id:Some(identifier.clone()),
                metadata:json!({"scopes":scopes,"resources":resources,"authTime":auth_time}),created_at:issued,expires_at:issued+chrono::Duration::seconds(2_592_000)
            }).await?;
            Some((row.id, token))
        } else {
            None
        };
        let token = random_token();
        let mut metadata = json!({"scopes":scopes,"resources":resources});
        if let Some((id, _)) = &refresh {
            _ = metadata
                .as_object_mut()
                .ok_or_else(|| alibi_core::AuthError::internal("Invalid access-token metadata"))?
                .insert("refreshId".into(), json!(id));
        }
        _ = ctx
            .database
            .create_oauth_token(
                OAuthTokenKind::Access,
                CreateOAuthToken {
                    token: URL_SAFE_NO_PAD.encode(Sha256::digest(&token)),
                    client_id: client_id.clone(),
                    user_id: Some(user_id.into()),
                    session_id: Some(session_id.into()),
                    authorization_code_id: Some(identifier),
                    metadata,
                    created_at: issued,
                    expires_at: expires,
                },
            )
            .await?;
        let mut response = json!({"access_token":token,"expires_in":3600,"expires_at":expires.timestamp(),"token_type":"Bearer","scope":scope});
        if scopes.contains(&"openid") {
            match self
                .issue_id_token(&client, &value, &token, req, ctx)
                .await?
            {
                Ok(Some(token)) => {
                    _ = response
                        .as_object_mut()
                        .ok_or_else(|| alibi_core::AuthError::internal("Invalid token response"))?
                        .insert("id_token".into(), json!(token));
                }
                Ok(None) => {}
                Err(response) => {
                    return Ok(response
                        .with_header("Cache-Control", "no-store")
                        .with_header("Pragma", "no-cache"));
                }
            }
        }
        if let Some((_, token)) = refresh {
            _ = response
                .as_object_mut()
                .ok_or_else(|| alibi_core::AuthError::internal("Invalid token response"))?
                .insert("refresh_token".into(), json!(token));
        }
        Ok(EndpointResponse::json(&response)?
            .with_header("Cache-Control", "no-store")
            .with_header("Pragma", "no-cache"))
    }
}
fn error(status: u16, code: &str, description: &str) -> AuthResult<EndpointResponse> {
    super::clients::status_protocol_error(status, code, description).map(|r| {
        r.with_header("Cache-Control", "no-store")
            .with_header("Pragma", "no-cache")
    })
}
