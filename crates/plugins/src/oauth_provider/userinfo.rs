//! Scoped user claims resolved from the real issued access-token authority.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint};
use alibi_core::session::SessionRequest;
use alibi_core::store::{OAuthClient, OAuthToken};
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthSession, HttpMethod};
use serde_json::{Value, json};
/// The shared access-token liveness gate used by public protocol consumers.
pub(super) async fn live_access_row<S: AuthSchema>(
    row: OAuthToken,
    ctx: &AuthContext<S>,
    provider: &OAuthProviderPlugin,
) -> AuthResult<Option<(OAuthToken, OAuthClient)>> {
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
        let sessions = if ctx.config.session.secondary_storage.is_some()
            && ctx.config.session.store_in_database
            && ctx.config.session.preserve_in_database
            && !ctx.config.session.stateless
        {
            // Preserved SQL rows, not browser-cache membership, decide bound
            // OAuth authority. A single-delete veto may already have evicted
            // the cache while leaving this durable session live.
            ctx.database
                .get_session_by_id(session)
                .await?
                .into_iter()
                .collect()
        } else if let Some(user) = row.user_id.as_deref() {
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
    Ok(Some((row, client)))
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
            // RFC 6750 §3.1: a request without credentials gets no error code.
            let algorithms = self.dpop_algorithms().join(" ");
            return error(401, "invalid_request", "access token not found").map(|response| {
                super::clients::with_challenge(
                    response,
                    &format!("Bearer, DPoP algs=\"{algorithms}\""),
                )
            });
        };
        let uses_dpop_scheme = authorization.scheme == "DPoP";
        let validation = match self
            .require_active_access_token_with_claims(
                ctx, &authorization.token, None, req.physical_request(),
            )
            .await
        {
            Ok(payload) => payload,
            Err(failure) if failure.error.status_code() == 401 => {
                let body = failure.body.as_deref();
                let field = |name: &str| {
                    body.and_then(|body| body.get(name))
                        .and_then(JsValue::as_str)
                        .map(str::to_owned)
                };
                let code = field("error").unwrap_or_else(|| "invalid_token".into());
                let description = field("error_description").unwrap_or_default();
                if uses_dpop_scheme {
                    return self.dpop_unauthorized(&code, &description);
                }
                let challenge = failure
                    .headers
                    .as_ref()
                    .and_then(|headers| headers.get("WWW-Authenticate"))
                    .map_or_else(
                        || "Bearer error=\"invalid_token\"".to_owned(),
                        |value| value.to_string(),
                    );
                return error(401, &code, &description)
                    .map(|response| super::clients::with_challenge(response, &challenge));
            }
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
        let payload = validation.payload;
        let requested = validation.requested_user_info_claims;
        if payload
            .get("cnf")
            .and_then(crate::oauth2::get_confirmation_jkt)
            .is_some()
            && req.physical_request().is_none()
        {
            return self.dpop_unauthorized(
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
            // Every binding failure means the token is DPoP-bound or the
            // request used the DPoP scheme, so it is challenged with DPoP.
            if crate::oauth2::is_dpop_binding_error(&failure) {
                return self.dpop_unauthorized(
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
        let user = ctx.user_view(&user)?;
        let client_id = payload
            .get("client_id")
            .or_else(|| payload.get("azp"))
            .and_then(Value::as_str);
        let client = if self
            .config
            .pairwise_secret
            .as_ref()
            .is_some_and(|secret| !secret.is_empty())
            || self
                .config
                .extensions
                .iter()
                .any(|extension| extension.claims.user_info.is_some())
        {
            if let Some(client_id) = client_id {
                self.get_client(ctx, client_id).await?
            } else {
                None
            }
        } else {
            None
        };
        let subject = client.as_ref().map_or_else(
            || Ok(user.id.clone()),
            |client| self.resolve_subject(&user.id, client),
        )?;
        let mut claims = serde_json::Map::from_iter([("sub".into(), json!(subject))]);
        let wanted = |name: &str, scope: &str| {
            scopes.contains(&scope) || requested.iter().any(|claim| claim == name)
        };
        if let Some(name) = user.name.as_deref() {
            if wanted("name", "profile") {
                _ = claims.insert("name".into(), json!(name));
            }
            if wanted("given_name", "profile") || wanted("family_name", "profile") {
                let parts = name
                    .split(' ')
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>();
                if let Some((family, given)) = parts.split_last()
                    && !given.is_empty()
                {
                    if wanted("given_name", "profile") {
                        _ = claims.insert("given_name".into(), json!(given.join(" ")));
                    }
                    if wanted("family_name", "profile") {
                        _ = claims.insert("family_name".into(), json!(family));
                    }
                }
            }
        }
        if wanted("picture", "profile")
            && let Some(image) = user.image.as_ref()
        {
            _ = claims.insert("picture".into(), json!(image));
        }
        if wanted("email", "email")
            && let Some(email) = user.email.as_ref()
        {
            _ = claims.insert("email".into(), json!(email));
        }
        if wanted("email_verified", "email") {
            _ = claims.insert("email_verified".into(), json!(user.email_verified));
        }
        let scopes = scopes.into_iter().map(str::to_owned).collect::<Vec<_>>();
        let input = super::OAuthUserInfoClaimsInput {
            context: super::extension_claims::callback_context(ctx, req),
            options: &self.config,
            user: &user,
            client: client.as_ref(),
            scopes: &scopes,
            payload: &payload,
            requested_claims: &requested,
        };
        let extensions = self.collect_user_info_claims(input.clone()).await?;
        super::extension_claims::merge_additive(&mut claims, extensions);
        if let Some(contributor) = &self.config.custom_user_info_claims {
            // Unlike extensions, the operator may replace ordinary claims,
            // including Object.prototype names. JS pickClaims assigns into {},
            // whose __proto__ setter does not create an own key for spreading.
            let operator = contributor.contribute(input).await?;
            claims.extend(operator.into_iter().filter(|(key, _)| key != "__proto__"));
        }
        // Subject presentation remains authoritative, including pairwise clients.
        _ = claims.insert("sub".into(), json!(subject));
        Ok(no_store(EndpointResponse::json(&claims)?))
    }
}
impl OAuthProviderPlugin {
    fn dpop_algorithms(&self) -> Vec<String> {
        self.config
            .dpop_signing_algorithms
            .clone()
            .unwrap_or_else(|| crate::oauth2::DPOP_SIGNING_ALGORITHMS.map(str::to_owned).into())
    }
    /// A 401 with an RFC 9449 §7.1 `DPoP` challenge listing the accepted algorithms.
    fn dpop_unauthorized(&self, code: &str, description: &str) -> AuthResult<EndpointResponse> {
        let challenge = dpop_challenge(code, description, &self.dpop_algorithms());
        error(401, code, description)
            .map(|response| super::clients::with_challenge(response, &challenge))
    }
}
/// Fit a runtime message into RFC 6750 §3's `error_description` character set:
/// `"` becomes `'`, other excluded characters become spaces, and an empty
/// result is omitted.
fn challenge_description(description: &str) -> Option<String> {
    let replaced = description
        .chars()
        .map(|c| match c {
            '"' => '\'',
            '\x20' | '\x21' | '\x23'..='\x5b' | '\x5d'..='\x7e' => c,
            _ => ' ',
        })
        .collect::<String>();
    let collapsed = replaced
        .split(' ')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!collapsed.is_empty()).then_some(collapsed)
}
fn quote_auth_param(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
/// An RFC 9449 §7.1 `WWW-Authenticate: DPoP` challenge value.
fn dpop_challenge(code: &str, description: &str, algorithms: &[String]) -> String {
    let mut params = vec![format!("DPoP error=\"{}\"", quote_auth_param(code))];
    if let Some(description) = challenge_description(description) {
        params.push(format!("error_description=\"{description}\""));
    }
    params.push(format!("algs=\"{}\"", quote_auth_param(&algorithms.join(" "))));
    params.join(", ")
}
fn no_store(response: EndpointResponse) -> EndpointResponse {
    response
        .with_header("Cache-Control", "no-store")
        .with_header("Pragma", "no-cache")
}
fn error(status: u16, code: &str, description: &str) -> AuthResult<EndpointResponse> {
    super::clients::status_protocol_error(status, code, description).map(no_store)
}
