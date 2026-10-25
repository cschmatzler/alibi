//! OAuth authorization-code token exchange and single-use grant lifecycle.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint};
use alibi_core::session::SessionRequest;
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
            .supported_grant_types()
            .iter()
            .any(|supported| supported == grant)
        {
            return error(
                400,
                "unsupported_grant_type",
                &format!("unsupported grant_type {grant}"),
            );
        }
        if grant == "refresh_token" {
            return Box::pin(self.refresh_grant(&body, req, ctx)).await;
        }
        if grant == "client_credentials" {
            return Box::pin(self.machine_grant(&body, req, ctx)).await;
        }
        if grant != "authorization_code" {
            if let Some(response) = self.extension_grant(grant, input, req, ctx).await? {
                return Ok(response);
            }
            return error(
                400,
                "unsupported_grant_type",
                &format!("unsupported grant_type {grant}"),
            );
        }
        let credentials = match super::credentials::extract(&body, req, ctx, self, "token").await? {
            Ok(credentials) => credentials,
            Err(response) => {
                return Ok(response
                    .with_header("Cache-Control", "no-store")
                    .with_header("Pragma", "no-cache"));
            }
        };
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
        if secret.is_empty() && verifier.is_empty() && !credentials.pre_verified {
            return error(
                400,
                "invalid_request",
                "Either code_verifier or client_secret is required",
            );
        }
        // RFC 6749 §5.2: an unknown or unauthenticated client is
        // `invalid_client`, so resolve it before the code lookup can report
        // `invalid_grant` and before a one-time code is consumed.
        let client = match Box::pin(credentials.authenticate(ctx, self)).await? {
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
        let identifier = self.hash_token(code, "authorization_code").await?;
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
        // Match authorization's policy using the consumed grant's scopes and
        // nonce, but only after binding and client authentication have passed.
        // Required clients reject an absent verifier before challenge matching.
        let has_oidc_nonce = scope.split(' ').any(|scope| scope == "openid")
            && query
                .get("nonce")
                .and_then(Value::as_str)
                .is_some_and(|nonce| !nonce.is_empty());
        let pkce_required = registered == "none"
            || client.metadata.get("require_pkce") != Some(&Value::Bool(false))
            || (scope.split(' ').any(|scope| scope == "offline_access") && !has_oidc_nonce);
        if pkce_required && verifier.is_empty() {
            return error(400, "invalid_request", "PKCE is required for this client");
        }
        if !challenge.is_empty() && verifier.is_empty() {
            return error(
                400,
                "invalid_request",
                "code_verifier required because PKCE was used in authorization",
            );
        }
        if challenge.is_empty() && !verifier.is_empty() {
            return error(
                400,
                "invalid_request",
                "code_verifier provided but PKCE was not used in authorization",
            );
        }
        if !verifier.is_empty()
            && (query.get("code_challenge_method").unwrap_or(&Value::Null) != "S256"
                || URL_SAFE_NO_PAD.encode(Sha256::digest(verifier)) != challenge)
        {
            return error(400, "invalid_grant", "code verification failed");
        }
        let user_id = value
            .get("userId")
            .unwrap_or(&Value::Null)
            .as_str()
            .unwrap_or_default();
        let Some(user) = ctx.database.get_user_by_id(user_id).await? else {
            return error(
                400,
                "invalid_user",
                "missing user, user may have been deleted",
            );
        };
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
        let mut params = super::OAuthTokenIssueParams::new(
            client,
            scope.split(' ').map(str::to_owned).collect(),
        );
        params.user = Some(ctx.trusted_user_view(&user));
        params.verification_value = Some(value.clone());
        params.reference_id = value
            .get("referenceId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let supported = self.supported_claims();
        params.requested_user_info_claims = Some(
            query
                .get("claims")
                .and_then(super::claims_request::parse)
                .map(|request| {
                    request
                        .user_info
                        .into_iter()
                        .filter(|name| supported.contains(name))
                        .collect()
                })
                .unwrap_or_default(),
        );

        params.session_id = Some(session_id.into());
        params.authorization_code_id = Some(identifier);
        params.auth_time = value
            .get("authTime")
            .and_then(Value::as_i64)
            .and_then(chrono::DateTime::from_timestamp_millis);
        params.nonce = query
            .get("nonce")
            .and_then(Value::as_str)
            .map(str::to_owned);
        params.resources = value
            .get("resource")
            .filter(|v| v.as_array().is_none_or(|a| !a.is_empty()))
            .and_then(|v| {
                v.as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .or_else(|| v.as_str().map(|v| vec![v.into()]))
            });
        let response = match self
            .mint_tokens(ctx, req, &params, "authorization_code")
            .await
        {
            Ok(value) => value,
            Err(error) => return super::issuance::error_response(error),
        };
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
