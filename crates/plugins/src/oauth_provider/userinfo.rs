//! Scoped user claims resolved from the real issued access-token authority.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint};
use alibi_core::session::SessionRequest;
use alibi_core::store::{OAuthToken, OAuthTokenKind};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthSession, HttpMethod};
use serde_json::{Value, json};
/// The shared access-token liveness gate used by public protocol consumers.
pub(super) async fn live_access<S: AuthSchema>(
    token: &str,
    ctx: &AuthContext<S>,
    provider: &OAuthProviderPlugin,
) -> AuthResult<Option<OAuthToken>> {
    let hash = provider.hash_token(token, "access_token").await?;
    let Some(row) = ctx
        .database
        .get_oauth_token(OAuthTokenKind::Access, &hash)
        .await?
    else {
        return Ok(None);
    };
    live_access_row(row, ctx, provider).await
}
pub(super) async fn live_access_row<S: AuthSchema>(
    row: OAuthToken,
    ctx: &AuthContext<S>,
    provider: &OAuthProviderPlugin,
) -> AuthResult<Option<OAuthToken>> {
    if row.expires_at < chrono::Utc::now()
        || row.metadata.get("revoked").is_some_and(|v| !v.is_null())
    {
        return Ok(None);
    }
    let Some(client) = provider.get_client(ctx, &row.client_id).await? else {
        return Ok(None);
    };
    if client.metadata.get("disabled") == Some(&Value::Bool(true)) {
        return Ok(None);
    }
    if let Some(session) = row.session_id.as_deref() {
        let sessions = if let Some(user) = row.user_id.as_deref() {
            ctx.database.get_user_sessions(user).await?
        } else {
            Vec::new()
        };
        if !sessions
            .iter()
            .any(|value| value.id().as_ref() == session && value.expires_at() >= chrono::Utc::now())
        {
            return Ok(None);
        }
    }
    Ok(Some(row))
}
impl OAuthProviderPlugin {
    /// Read the current user claims authorized by an OAuth access token.
    #[must_use]
    pub fn oauth2_user_info_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("oauth-provider", "oauth2UserInfo")
    }
    pub(super) async fn user_info<S: AuthSchema>(
        &self,
        input: Option<&JsValue>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let headers = req.session_headers();
        let header = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.as_str());
        let authorization = crate::oauth2::parse_access_token_authorization(header);
        let body_token = if req
            .physical_request()
            .is_some_and(|request| *request.method() == HttpMethod::Post)
        {
            input
                .and_then(|value| value.get("access_token"))
                .and_then(JsValue::as_str)
                .filter(|value| !value.is_empty())
        } else {
            None
        };
        if authorization.is_some() && body_token.is_some() {
            return error(
                400,
                "invalid_request",
                "Multiple access token transport methods are not allowed",
            );
        }
        let Some(authorization) = authorization.or_else(|| {
            body_token.map(|token| crate::oauth2::AccessTokenAuthorization {
                scheme: "Bearer".into(),
                token: token.into(),
            })
        }) else {
            return error(401, "invalid_request", "access token not found");
        };
        let payload = match self
            .require_active_access_token(ctx, &authorization.token, None)
            .await
        {
            Ok(payload) => payload,
            Err(error) => {
                let mut response = EndpointResponse::error(error.error);
                if let Some(body) = error.body {
                    response = response.with_error_body(*body);
                }
                if let Some(headers) = error.headers {
                    response.merge_headers(headers);
                }
                return Ok(no_store(response));
            }
        };
        if payload
            .get("cnf")
            .and_then(crate::oauth2::get_confirmation_jkt)
            .is_some()
            && req.physical_request().is_none()
        {
            return error(
                401,
                "invalid_token",
                "DPoP-bound access token requires an HTTP request context",
            );
        }
        let method = match req.physical_request().map(alibi_core::AuthRequest::method) {
            Some(HttpMethod::Post) => "POST",
            Some(HttpMethod::Put) => "PUT",
            Some(HttpMethod::Patch) => "PATCH",
            Some(HttpMethod::Delete) => "DELETE",
            Some(HttpMethod::Options) => "OPTIONS",
            Some(HttpMethod::Head) => "HEAD",
            Some(HttpMethod::Get) | None => "GET",
        };
        let url = super::dpop::endpoint_url(ctx, req, "/oauth2/userinfo");
        let replay = crate::oauth2::create_dpop_replay_store(ctx);
        let mut binding =
            crate::oauth2::EnforceDpopBindingParams::new(&payload, &authorization, method, &url);
        binding.proof_jwt = super::dpop::proof_header(req);
        binding.replay_store = Some(&replay);
        binding.proof_max_age_seconds = self.config.dpop_proof_max_age_seconds;
        binding.signing_algorithms = self.config.dpop_signing_algorithms.clone();
        if let Err(failure) = crate::oauth2::enforce_dpop_binding(&binding).await {
            if crate::oauth2::is_dpop_binding_error(&failure) {
                return error(
                    401,
                    failure.code.as_deref().unwrap_or_default(),
                    &failure.message,
                );
            }
            return Err(AuthError::internal(failure.message));
        }
        let scopes = payload
            .get("scope")
            .and_then(Value::as_str)
            .map(|scope| scope.split(' ').collect::<Vec<_>>())
            .unwrap_or_default();
        if !scopes.contains(&"openid") {
            return error(400, "invalid_scope", "Missing required scope");
        }
        let Some(id) = payload
            .get("sub")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return error(400, "invalid_request", "user not found");
        };
        let Some(user) = ctx.database.get_user_by_id(id).await? else {
            return error(400, "invalid_request", "user not found");
        };
        let user = ctx.user_view(&user);
        let mut claims = serde_json::Map::from_iter([("sub".into(), json!(user.id))]);
        if scopes.contains(&"profile") {
            if let Some(name) = user.name {
                _ = claims.insert("name".into(), json!(name));
                let parts = name
                    .split(' ')
                    .filter(|value| !value.is_empty())
                    .collect::<Vec<_>>();
                if let Some((family, given)) = parts.split_last()
                    && !given.is_empty()
                {
                    _ = claims.insert("given_name".into(), json!(given.join(" ")));
                    _ = claims.insert("family_name".into(), json!(family));
                }
            }
            if let Some(image) = user.image {
                _ = claims.insert("picture".into(), json!(image));
            }
        }
        if scopes.contains(&"email") {
            if let Some(email) = user.email {
                _ = claims.insert("email".into(), json!(email));
            }
            _ = claims.insert("email_verified".into(), json!(user.email_verified));
        }
        Ok(no_store(EndpointResponse::json(&claims)?))
    }
}
fn no_store(response: EndpointResponse) -> EndpointResponse {
    response
        .with_header("Cache-Control", "no-store")
        .with_header("Pragma", "no-cache")
}
fn error(status: u16, code: &str, description: &str) -> AuthResult<EndpointResponse> {
    super::clients::status_protocol_error(status, code, description).map(no_store)
}
