//! Short-lived, single-use credentials that hand an existing session to a client.

mod endpoint;

use super::authentication_helpers::{JsonField, RequestBody, parse_body};
use super::helpers::{get_cookie, response_session};
use alibi_core::utils::cookie_utils::{
    create_session_cookie_with_max_age, create_session_like_cookie, related_cookie_name,
    sign_cookie_value, verify_cookie_value,
};
use alibi_core::wire::{SessionView, UserView};
use alibi_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, CreateVerification, HttpMethod,
};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
pub use endpoint::OneTimeTokenOutput;
use rand::seq::IndexedRandom as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// The authenticated account and session represented by a one-time token.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OneTimeTokenSession {
    pub session: SessionView,
    pub user: UserView,
}

enum TokenSessionAbsence {
    InvalidToken,
    SessionNotFound,
}

impl TokenSessionAbsence {
    const fn message(&self) -> &'static str {
        match self {
            Self::InvalidToken => "Invalid token",
            Self::SessionNotFound => "Session not found",
        }
    }
}

enum TokenSessionLookup<S: AuthSchema> {
    Found {
        user: S::User,
        session: alibi_core::AdapterRecord<S::Session>,
    },
    Missing(TokenSessionAbsence),
}

/// Application-owned token generation, including asynchronous generators.
///
/// Return [`AuthError::Api`] or [`AuthError::Upstream`] for an explicit public
/// veto. Other callback errors produce an empty HTTP 500 without exposing the cause.
#[async_trait]
pub trait GenerateOneTimeToken: Send + Sync {
    async fn generate(
        &self,
        session: &OneTimeTokenSession,
        request: Option<&AuthRequest>,
    ) -> AuthResult<String>;
}

/// Application-owned hashing applied consistently at issuance and consumption.
///
/// Errors follow the same public-veto/ordinary-failure contract as
/// [`GenerateOneTimeToken`], before any verification is created or consumed.
#[async_trait]
pub trait HashOneTimeToken: Send + Sync {
    async fn hash(&self, token: &str) -> AuthResult<String>;
}

#[derive(Clone, Default)]
pub enum OneTimeTokenStorage {
    #[default]
    Plain,
    Hashed,
    Custom(Arc<dyn HashOneTimeToken>),
}

impl std::fmt::Debug for OneTimeTokenStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => f.write_str("OneTimeTokenStorage::Plain"),
            Self::Hashed => f.write_str("OneTimeTokenStorage::Hashed"),
            Self::Custom(..) => f.write_str("OneTimeTokenStorage::Custom"),
        }
    }
}

#[derive(Clone)]
pub struct OneTimeTokenConfig {
    pub expires_in: Duration,
    pub storage: OneTimeTokenStorage,
    pub generator: Option<Arc<dyn GenerateOneTimeToken>>,
    pub disable_client_request: bool,
    pub disable_set_session_cookie: bool,
    pub set_ott_header_on_new_session: bool,
}

impl std::fmt::Debug for OneTimeTokenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneTimeTokenConfig").finish_non_exhaustive()
    }
}

impl Default for OneTimeTokenConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::minutes(3),
            storage: OneTimeTokenStorage::Plain,
            generator: None,
            disable_client_request: false,
            disable_set_session_cookie: false,
            set_ott_header_on_new_session: false,
        }
    }
}

#[derive(Clone, Default)]
pub struct OneTimeTokenPlugin {
    config: OneTimeTokenConfig,
}

impl std::fmt::Debug for OneTimeTokenPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneTimeTokenPlugin").finish_non_exhaustive()
    }
}

impl OneTimeTokenPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub const fn with_config(config: OneTimeTokenConfig) -> Self {
        Self { config }
    }

    /// Issue a token for a trusted, authenticated server-side session.
    ///
    /// The caller supplies the session it has already authenticated. The token
    /// preserves that session's identity and expiry; it does not create one.
    ///
    /// # Errors
    ///
    /// Returns an error if token generation, hashing, or persistence fails.
    pub async fn generate_for_session(
        &self,
        session: &OneTimeTokenSession,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<String> {
        let token = match &self.config.generator {
            Some(generator) => generator
                .generate(session, request)
                .await
                .map_err(crate::helpers::callback_failure)?,
            None => random_token(),
        };
        let stored = self.stored_token(&token).await?;
        _ = ctx
            .verifications()
            .create(CreateVerification {
                identifier: format!("one-time-token:{stored}"),
                value: session.session.token.clone(),
                expires_at: Utc::now() + self.config.expires_in,
            })
            .await?;
        Ok(token)
    }

    /// Consume a token and resolve its existing session for a server caller.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, expired, or invalid token/session, or if storage fails.
    pub async fn verify_token(
        &self,
        token: &str,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<OneTimeTokenSession> {
        let session = self.consume_session(token, ctx).await?;
        if session.session.expires_at < Utc::now() {
            return Err(AuthError::bad_request("Session expired"));
        }
        Ok(session)
    }

    async fn stored_token(&self, token: &str) -> AuthResult<String> {
        match &self.config.storage {
            OneTimeTokenStorage::Plain => Ok(token.to_owned()),
            OneTimeTokenStorage::Hashed => {
                Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())))
            }
            OneTimeTokenStorage::Custom(hasher) => hasher
                .hash(token)
                .await
                .map_err(crate::helpers::callback_failure),
        }
    }

    async fn consume_session(
        &self,
        token: &str,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<OneTimeTokenSession> {
        let (user, session) = match self.consume_stored_session(token, ctx).await? {
            TokenSessionLookup::Found { user, session } => (user, session),
            TokenSessionLookup::Missing(absence) => {
                return Err(AuthError::bad_request(absence.message()));
            }
        };
        Ok(OneTimeTokenSession {
            session: ctx.session_view(&session),
            user: ctx.user_view(&user),
        })
    }

    async fn consume_stored_session<S: AuthSchema>(
        &self,
        token: &str,
        ctx: &AuthContext<S>,
    ) -> AuthResult<TokenSessionLookup<S>> {
        let stored = self.stored_token(token).await?;
        let Some(verification) = ctx
            .verifications()
            .consume(&format!("one-time-token:{stored}"))
            .await?
        else {
            return Ok(TokenSessionLookup::Missing(
                TokenSessionAbsence::InvalidToken,
            ));
        };
        let Some(session) = ctx
            .database
            .get_session_record(verification.value()?)
            .await?
        else {
            return Ok(TokenSessionLookup::Missing(
                TokenSessionAbsence::SessionNotFound,
            ));
        };
        let Some(user) = ctx.session_user(&session).await? else {
            return Ok(TokenSessionLookup::Missing(
                TokenSessionAbsence::SessionNotFound,
            ));
        };
        Ok(TokenSessionLookup::Found { user, session })
    }

    async fn generate(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, session) =
            ctx.require_cached_session(req)
                .await
                .map_err(|error| match error {
                    AuthError::Unauthenticated => unauthorized(),
                    error @ (AuthError::Api { .. }
                    | AuthError::Upstream { .. }
                    | AuthError::BadRequest(_)
                    | AuthError::InvalidRequest(_)
                    | AuthError::Validation(_)
                    | AuthError::InvalidCredentials
                    | AuthError::AuthenticationFailed(_)
                    | AuthError::SessionNotFound
                    | AuthError::Forbidden(_)
                    | AuthError::UserCreationCancelled
                    | AuthError::SessionCreationCancelled
                    | AuthError::BannedUser(_)
                    | AuthError::Unauthorized
                    | AuthError::UserNotFound
                    | AuthError::NotFound(_)
                    | AuthError::Conflict(_)
                    | AuthError::MethodNotAllowed(_)
                    | AuthError::PayloadTooLarge(_)
                    | AuthError::UnprocessableEntity(_)
                    | AuthError::RateLimited { .. }
                    | AuthError::NotImplemented(_)
                    | AuthError::Config(_)
                    | AuthError::Database(_)
                    | AuthError::Serialization(_)
                    | AuthError::Plugin { .. }
                    | AuthError::CallbackFailure(_)
                    | AuthError::Internal(_)
                    | AuthError::Encryption(_)
                    | AuthError::PasswordHash(_)
                    | AuthError::Jwt(_)) => error,
                })?;
        if self.config.disable_client_request {
            return message_response(400, "Client requests are disabled");
        }
        let token = self
            .generate_for_session(
                &OneTimeTokenSession {
                    session: ctx.session_view(&session),
                    user: ctx.user_view(&user),
                },
                Some(req),
                ctx,
            )
            .await?;
        Ok(AuthResponse::json(200, &json!({ "token": token }))?)
    }

    async fn verify(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyRequest = match parse_body(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        let session = match self.consume_session(&body.token, ctx).await {
            Ok(session) => session,
            Err(AuthError::BadRequest(message)) => return message_response(400, &message),
            Err(error) => return Err(error),
        };
        if !self.config.disable_set_session_cookie {
            // Source republishes the existing adapter session's parsed views;
            // verification does not create a replacement session.
            alibi_core::session::cookie_cache::runtime::emit_issuance_snapshot(
                ctx,
                alibi_core::CacheVersionContext::created(
                    session.user.clone(),
                    session.session.clone(),
                    session.user.clone(),
                    session.session.clone(),
                ),
            )
            .await?;
        }
        let mut response = if session.session.expires_at < Utc::now() {
            message_response(400, "Session expired")?
        } else {
            AuthResponse::json(200, &session)?
        };
        // The reference sets the existing session cookie before checking its
        // expiry, including on the expired-session rejection response.
        if !self.config.disable_set_session_cookie {
            let dont_remember = get_cookie(req, &related_cookie_name(&ctx.config, "dont_remember"))
                .and_then(|value| verify_cookie_value(&value, ctx.config.current_secret()))
                .is_some_and(|value| !value.is_empty());
            response.headers.append(
                "set-cookie",
                create_session_cookie_with_max_age(
                    Some(&session.session.token),
                    (!dont_remember).then_some(ctx.config.session.expires_in.num_seconds()),
                    &ctx.config,
                )?,
            );
            if dont_remember {
                response.headers.append(
                    "set-cookie",
                    create_session_like_cookie(
                        &related_cookie_name(&ctx.config, "dont_remember"),
                        &sign_cookie_value("true", ctx.config.current_secret()),
                        None,
                        &ctx.config,
                    )?,
                );
            }
        }
        Ok(response)
    }
}

#[derive(Deserialize)]
struct VerifyRequest {
    token: String,
}

impl RequestBody for VerifyRequest {
    const FIELDS: &'static [JsonField] = &[JsonField::string("token", true)];
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for OneTimeTokenPlugin {
    fn static_openapi_metadata(&self) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::plugin_metadata(
            <Self as alibi_core::AuthPlugin<S>>::name(self),
            &<Self as alibi_core::AuthPlugin<S>>::routes(self),
        )
    }

    fn openapi_metadata(
        &self,
        ctx: &alibi_core::AuthInitContext<S>,
    ) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::instance_plugin_metadata(
            <Self as alibi_core::AuthPlugin<S>>::name(self),
            &<Self as alibi_core::AuthPlugin<S>>::routes(self),
            ctx,
        )
    }

    fn name(&self) -> &'static str {
        "one-time-token"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/one-time-token/generate", "generate_one_time_token"),
            AuthRoute::post("/one-time-token/verify", "verify_one_time_token"),
        ]
    }
    fn server_endpoints(&self) -> Vec<alibi_core::endpoint::EndpointDefinition> {
        endpoint::definitions()
    }

    fn validate_endpoint(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<alibi_core::endpoint::EndpointInput> {
        endpoint::validate(call)
    }

    async fn on_endpoint(
        &self,
        call: &alibi_core::endpoint::EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<alibi_core::endpoint::EndpointResponse> {
        self.call_endpoint(call, ctx).await
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, "/one-time-token/generate") => {
                Ok(Some(self.generate(req, ctx).await?))
            }
            (HttpMethod::Post, "/one-time-token/verify") => Ok(Some(self.verify(req, ctx).await?)),
            _ => Ok(None),
        }
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        if !self.config.set_ott_header_on_new_session {
            return Ok(response);
        }
        if let Some(session) = response_session(ctx, &response).await? {
            let token = self
                .generate_for_session(
                    &OneTimeTokenSession {
                        session: ctx.session_view(&session.session),
                        user: ctx.user_view(&session.user),
                    },
                    Some(req),
                    ctx,
                )
                .await?;
            let mut expose = response
                .headers
                .get("access-control-expose-headers")
                .into_iter()
                .flat_map(|value| value.split(','))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .fold(Vec::<String>::new(), |mut headers, value| {
                    if !headers.iter().any(|header| header == value) {
                        headers.push(value.to_owned());
                    }
                    headers
                });
            if !expose.iter().any(|header| header == "set-ott") {
                expose.push("set-ott".to_owned());
            }
            _ = response.headers.insert("set-ott", token);
            _ = response
                .headers
                .insert("access-control-expose-headers", expose.join(", "));
        }
        Ok(response)
    }
}

const fn unauthorized() -> AuthError {
    AuthError::Upstream {
        status: 401,
        code: "UNAUTHORIZED",
        message: "Unauthorized",
    }
}

fn message_response(status: u16, message: &str) -> AuthResult<AuthResponse> {
    Ok(AuthResponse::json(status, &json!({ "message": message }))?)
}

fn random_token() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    (0..32)
        .map(|_| char::from(ALPHABET.choose(&mut rand::rng()).copied().unwrap_or(b'a')))
        .collect()
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "asserted one-time-token contracts against real SQLite"
    )]

    use super::*;
    use crate::test_helpers;
    use alibi_core::CreateUser;

    type TestSchema = alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

    struct CustomHasher;

    #[async_trait]
    impl HashOneTimeToken for CustomHasher {
        async fn hash(&self, token: &str) -> AuthResult<String> {
            Ok(format!("custom:{token}"))
        }
    }

    struct CustomGenerator;

    #[async_trait]
    impl GenerateOneTimeToken for CustomGenerator {
        async fn generate(
            &self,
            session: &OneTimeTokenSession,
            request: Option<&AuthRequest>,
        ) -> AuthResult<String> {
            assert_eq!(request.map(AuthRequest::path), None);
            assert_ne!(session.user.id.len(), 0);
            Ok("custom-generated-token".to_owned())
        }
    }

    async fn setup() -> (AuthContext<TestSchema>, OneTimeTokenSession) {
        let ctx = test_helpers::create_test_context().await;
        let (user, session) = test_helpers::create_user_and_session(
            &ctx,
            CreateUser::new().with_email("one-time-token@fixture.test"),
            Duration::days(1),
        )
        .await;
        (ctx, OneTimeTokenSession { session, user })
    }

    fn signed_request(
        path: &str,
        session: &OneTimeTokenSession,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthRequest {
        let mut req = test_helpers::create_auth_request_no_query(HttpMethod::Get, path, None, None);
        req.headers.insert(
            "cookie".to_owned(),
            alibi_core::utils::cookie_utils::create_session_cookie(
                &session.session.token,
                &ctx.config,
            )
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned(),
        );
        req
    }

    #[tokio::test]
    async fn default_tokens_are_persisted_consumed_once_and_reuse_the_original_session() {
        let (ctx, session) = setup().await;
        let plugin = OneTimeTokenPlugin::new();
        let token = plugin
            .generate_for_session(&session, None, &ctx)
            .await
            .unwrap();
        assert_eq!(token.chars().count(), 32);
        let identifier = format!("one-time-token:{token}");
        let stored = ctx
            .database
            .get_latest_verification_by_identifier(&identifier)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.value, session.session.token);
        assert!((stored.expires_at - Utc::now()).num_seconds() >= 179);
        let verified = plugin.verify_token(&token, &ctx).await.unwrap();
        assert_eq!(verified.session.token, session.session.token);
        assert_eq!(verified.user.id, session.user.id);
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(&identifier)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            matches!(plugin.verify_token(&token, &ctx).await, Err(AuthError::BadRequest(message)) if message == "Invalid token")
        );
        assert_eq!(
            ctx.database
                .get_user_sessions(&session.user.id)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn expired_latest_generation_invalidates_older_live_token_and_revoked_session_consumes_the_token()
     {
        let (ctx, session) = setup().await;
        let plugin = OneTimeTokenPlugin::new();
        let identifier = "one-time-token:duplicate";
        ctx.database
            .create_verification(CreateVerification {
                identifier: identifier.to_owned(),
                value: session.session.token.clone(),
                expires_at: Utc::now() + Duration::minutes(3),
            })
            .await
            .unwrap();
        ctx.database
            .create_verification(CreateVerification {
                identifier: identifier.to_owned(),
                value: session.session.token.clone(),
                expires_at: Utc::now() - Duration::seconds(1),
            })
            .await
            .unwrap();
        assert!(
            matches!(plugin.verify_token("duplicate", &ctx).await, Err(AuthError::BadRequest(message)) if message == "Invalid token")
        );
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(identifier)
                .await
                .unwrap()
                .is_none()
        );
        let token = plugin
            .generate_for_session(&session, None, &ctx)
            .await
            .unwrap();
        ctx.database
            .delete_session(&session.session.token)
            .await
            .unwrap();
        assert!(
            matches!(plugin.verify_token(&token, &ctx).await, Err(AuthError::BadRequest(message)) if message == "Session not found")
        );
        assert!(
            matches!(plugin.verify_token(&token, &ctx).await, Err(AuthError::BadRequest(message)) if message == "Invalid token")
        );
    }

    #[tokio::test]
    async fn concurrent_token_redemption_has_exactly_one_winner() {
        let (ctx, session) = setup().await;
        let plugin = OneTimeTokenPlugin::new();
        let token = plugin
            .generate_for_session(&session, None, &ctx)
            .await
            .unwrap();
        let (first, second) = tokio::join!(
            plugin.verify_token(&token, &ctx),
            plugin.verify_token(&token, &ctx)
        );
        assert_ne!(first.is_ok(), second.is_ok());
        let verified = first.or(second).unwrap();
        assert_eq!(verified.session.token, session.session.token);
        assert_eq!(
            ctx.database
                .get_user_sessions(&session.user.id)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn hashed_and_custom_storage_share_consistent_issue_and_consume_paths() {
        let (ctx, session) = setup().await;
        for storage in [
            OneTimeTokenStorage::Hashed,
            OneTimeTokenStorage::Custom(Arc::new(CustomHasher)),
        ] {
            let plugin = OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
                storage,
                generator: Some(Arc::new(CustomGenerator)),
                ..Default::default()
            });
            let token = plugin
                .generate_for_session(&session, None, &ctx)
                .await
                .unwrap();
            let stored = plugin.stored_token(&token).await.unwrap();
            assert_ne!(token, stored);
            assert!(
                ctx.database
                    .get_latest_verification_by_identifier(&format!("one-time-token:{token}"))
                    .await
                    .unwrap()
                    .is_none()
            );
            let row = ctx
                .database
                .get_latest_verification_by_identifier(&format!("one-time-token:{stored}"))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.value, session.session.token);
            assert_eq!(
                plugin
                    .verify_token(&token, &ctx)
                    .await
                    .unwrap()
                    .session
                    .token,
                session.session.token
            );
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn http_transfer_cookie_headers_and_server_only_configuration_are_observable() {
        let (ctx, session) = setup().await;
        let plugin = OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
            disable_client_request: true,
            set_ott_header_on_new_session: true,
            ..Default::default()
        });
        let req = signed_request("/one-time-token/generate", &session, &ctx);
        assert_eq!(plugin.generate(&req, &ctx).await.unwrap().status, 400);
        let token = plugin
            .generate_for_session(&session, None, &ctx)
            .await
            .unwrap();
        let verify = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/one-time-token/verify",
            None,
            Some(json!({ "token": token })),
        );
        let response = plugin.verify(&verify, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        let cookie = response.headers.get("set-cookie").unwrap();
        let cookie = cookie::Cookie::parse(cookie.clone()).unwrap();
        assert_eq!(
            verify_cookie_value(cookie.value(), &ctx.config.secret).as_deref(),
            Some(session.session.token.as_str())
        );
        for (preference, persistent) in [
            (None, true),
            (Some(""), true),
            (Some("false"), false),
            (Some("true"), false),
        ] {
            let token_2 = plugin
                .generate_for_session(&session, None, &ctx)
                .await
                .unwrap();
            let mut verify_2 = test_helpers::create_auth_json_request_no_query(
                HttpMethod::Post,
                "/one-time-token/verify",
                None,
                Some(json!({ "token": token_2 })),
            );
            if let Some(value) = preference {
                verify_2.headers.insert(
                    "cookie".to_owned(),
                    format!(
                        "{}={}",
                        related_cookie_name(&ctx.config, "dont_remember"),
                        sign_cookie_value(value, &ctx.config.secret)
                    ),
                );
            }
            let verified = plugin.verify(&verify_2, &ctx).await.unwrap();
            assert_eq!(verified.status, 200);
            let cookies = verified
                .headers
                .get_all("set-cookie")
                .map(|header| cookie::Cookie::parse(header.clone()).unwrap())
                .collect::<Vec<_>>();
            let session_cookie = cookies
                .iter()
                .find(|cookie_2| cookie_2.name() == ctx.config.session.cookie_name)
                .unwrap();
            assert_eq!(
                cookies.iter().any(|candidate| candidate.name()
                    == related_cookie_name(&ctx.config, "dont_remember")),
                !persistent
            );
            assert_eq!(
                session_cookie
                    .max_age()
                    .map(cookie::time::Duration::whole_seconds),
                persistent.then_some(ctx.config.session.expires_in.num_seconds()),
                "receiving preference {preference:?}"
            );
            assert_eq!(
                verify_cookie_value(session_cookie.value(), &ctx.config.secret).as_deref(),
                Some(session.session.token.as_str())
            );
        }
        let mut response = response;
        response.headers.insert(
            "access-control-expose-headers",
            " existing, ,existing, set-ott, set-ott, Existing ",
        );
        let hooked = plugin.after_request(&verify, &ctx, response).await.unwrap();
        assert_eq!(
            hooked.headers.get("access-control-expose-headers").unwrap(),
            "existing, set-ott, Existing"
        );
        let delivered = plugin
            .verify_token(hooked.headers.get("set-ott").unwrap(), &ctx)
            .await
            .unwrap();
        assert_eq!(delivered.session.token, session.session.token);
        assert_eq!(delivered.user.id, session.user.id);
        let no_cookie = OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
            disable_set_session_cookie: true,
            ..Default::default()
        });
        let token_3 = no_cookie
            .generate_for_session(&session, None, &ctx)
            .await
            .unwrap();
        let verify_3 = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/one-time-token/verify",
            None,
            Some(json!({ "token": token_3 })),
        );
        assert!(
            no_cookie
                .verify(&verify_3, &ctx)
                .await
                .unwrap()
                .headers
                .get("set-cookie")
                .is_none()
        );
    }
}
// LCOV_EXCL_STOP
