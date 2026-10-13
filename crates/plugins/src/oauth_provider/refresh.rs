//! Refresh grants bind retained authority to its client and atomically rotate it.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::EndpointResponse;
use alibi_core::session::SessionRequest;
use alibi_core::store::{CreateOAuthToken, OAuthTokenKind};
use alibi_core::{AuthContext, AuthResult, AuthSchema};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
impl OAuthProviderPlugin {
    pub(super) async fn refresh_grant<S: AuthSchema>(
        &self,
        body: &Value,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let credentials = super::credentials::extract(body, req);
        if credentials.client_id.is_empty() {
            return error("invalid_request", "Missing required client_id");
        }
        let token = body
            .get("refresh_token")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if token.is_empty() {
            return error(
                "invalid_request",
                "Missing a required refresh_token for refresh_token grant",
            );
        }
        let protected = URL_SAFE_NO_PAD.encode(Sha256::digest(token));
        let Some(original) = ctx
            .database
            .get_oauth_token(OAuthTokenKind::Refresh, &protected)
            .await?
        else {
            return error("invalid_grant", "session not found");
        };
        if original.client_id != credentials.client_id || original.expires_at < chrono::Utc::now() {
            return error("invalid_grant", "invalid refresh token");
        }
        let original_scopes = original
            .metadata
            .get("scopes")
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        let scopes = body.get("scope").and_then(Value::as_str).map_or_else(
            || original_scopes.clone(),
            |value| value.split(' ').collect(),
        );
        for scope in &scopes {
            if !original_scopes.contains(scope) {
                return error("invalid_scope", &format!("unable to issue scope {scope}"));
            }
        }
        let client = match credentials.authenticate(ctx).await? {
            Ok(client) => client,
            Err(response) => return Ok(no_store(response)),
        };
        let ceiling = client
            .metadata
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .split(' ')
            .collect::<Vec<_>>();
        let invalid = scopes
            .iter()
            .filter(|scope| !ceiling.contains(scope))
            .copied()
            .collect::<Vec<_>>();
        if !invalid.is_empty() {
            return error(
                "invalid_scope",
                &format!("The following scopes are invalid: {}", invalid.join(", ")),
            );
        }
        if client
            .metadata
            .get("grant_types")
            .and_then(Value::as_array)
            .is_some_and(|grants| !grants.iter().any(|grant| grant == "refresh_token"))
        {
            return error(
                "unauthorized_client",
                "client is not authorized to use grant type refresh_token",
            );
        }
        if original
            .metadata
            .get("revoked")
            .is_some_and(|value| !value.is_null())
        {
            if let Some(user) = &original.user_id {
                ctx.database
                    .delete_oauth_refresh_family(&original.client_id, user)
                    .await?;
            }
            return error("invalid_grant", "invalid refresh token");
        }
        let Some(user_id) = original.user_id.as_deref() else {
            return error("invalid_request", "user not found");
        };
        if ctx.database.get_user_by_id(user_id).await?.is_none() {
            return error("invalid_request", "user not found");
        }
        let issued = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .ok_or_else(|| alibi_core::AuthError::internal("Invalid token issuance time"))?;
        let random = || {
            rand::RngExt::sample_iter(rand::rng(), rand::distr::Alphanumeric)
                .map(char::from)
                .filter(char::is_ascii_alphabetic)
                .take(32)
                .collect::<String>()
        };
        let rotate =
            original_scopes.contains(&"offline_access") || scopes.contains(&"offline_access");
        let next_refresh = if rotate {
            if !ctx
                .database
                .claim_oauth_refresh_rotation(&protected, issued)
                .await?
            {
                return error("invalid_grant", "invalid refresh token");
            }
            let token = random();
            let mut metadata = original.metadata.as_object().cloned().unwrap_or_default();
            for key in [
                "revoked",
                "rotatedAt",
                "rotationReplayResponse",
                "rotationReplayExpiresAt",
            ] {
                _ = metadata.remove(key);
            }
            _ = metadata.insert("scopes".into(), json!(scopes));
            let row = ctx
                .database
                .create_oauth_token(
                    OAuthTokenKind::Refresh,
                    CreateOAuthToken {
                        token: URL_SAFE_NO_PAD.encode(Sha256::digest(&token)),
                        client_id: original.client_id.clone(),
                        user_id: original.user_id.clone(),
                        session_id: original.session_id.clone(),
                        authorization_code_id: original.authorization_code_id.clone(),
                        metadata: Value::Object(metadata),
                        created_at: issued,
                        expires_at: issued + chrono::Duration::seconds(2_592_000),
                    },
                )
                .await?;
            Some((row.id, token))
        } else {
            None
        };
        let access = random();
        let mut metadata = json!({"scopes":scopes,"resources":original.metadata.get("resources")})
            .as_object()
            .cloned()
            .ok_or_else(|| alibi_core::AuthError::internal("Invalid access metadata"))?;
        if let Some((id, _)) = &next_refresh {
            _ = metadata.insert("refreshId".into(), json!(id));
        }
        for key in ["referenceId", "confirmation", "requestedUserInfoClaims"] {
            if let Some(value) = original.metadata.get(key) {
                _ = metadata.insert(key.into(), value.clone());
            }
        }
        let expires = issued + chrono::Duration::seconds(3600);
        _ = ctx
            .database
            .create_oauth_token(
                OAuthTokenKind::Access,
                CreateOAuthToken {
                    token: URL_SAFE_NO_PAD.encode(Sha256::digest(&access)),
                    client_id: original.client_id.clone(),
                    user_id: original.user_id.clone(),
                    session_id: original.session_id.clone(),
                    authorization_code_id: original.authorization_code_id.clone(),
                    metadata: Value::Object(metadata),
                    created_at: issued,
                    expires_at: expires,
                },
            )
            .await?;
        let mut response = serde_json::Map::from_iter([
            ("access_token".into(), json!(access)),
            ("expires_in".into(), json!(3600)),
            ("expires_at".into(), json!(expires.timestamp())),
            ("token_type".into(), json!("Bearer")),
            ("scope".into(), json!(scopes.join(" "))),
        ]);
        if let Some((_, token)) = next_refresh {
            _ = response.insert("refresh_token".into(), json!(token));
        }
        if scopes.contains(&"openid") {
            let auth_time = original
                .metadata
                .get("authTime")
                .and_then(Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.timestamp_millis());
            let proof = json!({"userId":user_id,"sessionId":original.session_id,"authTime":auth_time,"query":{}});
            match Box::pin(self.issue_id_token(&client, &proof, &access, req, ctx)).await? {
                Ok(Some(token)) => {
                    _ = response.insert("id_token".into(), json!(token));
                }
                Ok(None) => {}
                Err(response) => return Ok(no_store(response)),
            }
        }
        Ok(no_store(EndpointResponse::json(&response)?))
    }
}
fn no_store(response: EndpointResponse) -> EndpointResponse {
    response
        .with_header("cache-control", "no-store")
        .with_header("pragma", "no-cache")
}
fn error(code: &str, description: &str) -> AuthResult<EndpointResponse> {
    super::clients::status_protocol_error(400, code, description).map(no_store)
}
