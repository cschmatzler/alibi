//! Short-lived, single-use credentials that hand an existing session to a client.

use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use better_auth_core::utils::cookie_utils::{
    create_session_cookie_with_max_age, create_session_like_cookie, related_cookie_name,
    sign_cookie_value, verify_cookie_value,
};
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, AuthSession, AuthVerification, CreateVerification, HttpMethod,
};
use chrono::{Duration, Utc};
use rand::{rngs::OsRng, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::authentication_helpers::{JsonField, RequestBody, parse_body};
use super::helpers::{get_cookie, response_session};

/// The authenticated account and session represented by a one-time token.
#[derive(Clone, Debug, Serialize)]
pub struct OneTimeTokenSession {
    pub session: SessionView,
    pub user: UserView,
}

/// Application-owned token generation, including asynchronous generators.
#[async_trait]
pub trait GenerateOneTimeToken: Send + Sync {
    async fn generate(
        &self,
        session: &OneTimeTokenSession,
        request: Option<&AuthRequest>,
    ) -> AuthResult<String>;
}

/// Application-owned hashing applied consistently at issuance and consumption.
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

#[derive(Clone)]
pub struct OneTimeTokenConfig {
    pub expires_in: Duration,
    pub storage: OneTimeTokenStorage,
    pub generator: Option<Arc<dyn GenerateOneTimeToken>>,
    pub disable_client_request: bool,
    pub disable_set_session_cookie: bool,
    pub set_ott_header_on_new_session: bool,
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

impl OneTimeTokenPlugin {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_config(config: OneTimeTokenConfig) -> Self {
        Self { config }
    }

    /// Issue a token for a trusted, authenticated server-side session.
    ///
    /// The caller supplies the session it has already authenticated. The token
    /// preserves that session's identity and expiry; it does not create one.
    pub async fn generate_for_session(
        &self,
        session: &OneTimeTokenSession,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<String> {
        let token = match &self.config.generator {
            Some(generator) => generator.generate(session, request).await?,
            None => random_token(),
        };
        let stored = self.stored_token(&token).await?;
        let _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: format!("one-time-token:{stored}"),
                value: session.session.token.clone(),
                expires_at: Utc::now() + self.config.expires_in,
            })
            .await?;
        Ok(token)
    }

    /// Consume a token and resolve its existing session for a server caller.
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
            OneTimeTokenStorage::Custom(hasher) => hasher.hash(token).await,
        }
    }

    async fn consume_session(
        &self,
        token: &str,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<OneTimeTokenSession> {
        let stored = self.stored_token(token).await?;
        let verification = ctx
            .database
            .consume_verification_by_identifier(&format!("one-time-token:{stored}"))
            .await?
            .ok_or_else(|| AuthError::bad_request("Invalid token"))?;
        let session = ctx
            .database
            .get_session(verification.value())
            .await?
            .ok_or_else(|| AuthError::bad_request("Session not found"))?;
        let user = ctx
            .database
            .get_user_by_id(session.user_id().as_ref())
            .await?
            .ok_or_else(|| AuthError::bad_request("Session not found"))?;
        Ok(OneTimeTokenSession {
            session: ctx.session_view(&session),
            user: ctx.user_view(&user),
        })
    }

    async fn generate(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, session) = ctx
            .require_session(req)
            .await
            .map_err(|error| match error {
                AuthError::Unauthenticated => unauthorized(),
                error => error,
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
        let mut response = if session.session.expires_at < Utc::now() {
            message_response(400, "Session expired")?
        } else {
            AuthResponse::json(200, &session)?
        };
        // The reference sets the existing session cookie before checking its
        // expiry, including on the expired-session rejection response.
        if !self.config.disable_set_session_cookie {
            let dont_remember = get_cookie(req, &related_cookie_name(&ctx.config, "dont_remember"))
                .and_then(|value| verify_cookie_value(&value, &ctx.config.secret))
                .is_some_and(|value| !value.is_empty());
            response.headers.append(
                "set-cookie",
                create_session_cookie_with_max_age(
                    Some(&session.session.token),
                    (!dont_remember).then_some(ctx.config.session.expires_in.num_seconds()),
                    &ctx.config,
                ),
            );
            if dont_remember {
                response.headers.append(
                    "set-cookie",
                    create_session_like_cookie(
                        &related_cookie_name(&ctx.config, "dont_remember"),
                        &sign_cookie_value("true", &ctx.config.secret),
                        None,
                        &ctx.config,
                    ),
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

fn unauthorized() -> AuthError {
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
        .map(|_| char::from(ALPHABET.choose(&mut OsRng).copied().unwrap_or(b'a')))
        .collect()
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for OneTimeTokenPlugin {
    fn name(&self) -> &'static str {
        "one-time-token"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/one-time-token/generate", "generate_one_time_token"),
            AuthRoute::post("/one-time-token/verify", "verify_one_time_token"),
        ]
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
            let _ = response.headers.insert("set-ott", token);
            let _ = response
                .headers
                .insert("access-control-expose-headers", expose.join(", "));
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests;
