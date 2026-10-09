//! Single-use mailbox authentication links, with native delivery callbacks.

use super::authentication_helpers::{
    JsonField, JsonFieldKind, RequestBody, parse_body, redirect, revoke_unproven_access,
    session_response,
};
use super::token_crypto::hash_token;
use alibi_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, AuthUser,
    CreateUser, CreateVerification,
};
use async_trait::async_trait;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use url::Url;

/// Delivery data. Debug omits the token, URL and arbitrary delivery metadata.
#[derive(Clone, Serialize)]
pub struct MagicLinkDelivery {
    pub email: String,
    pub url: String,
    pub token: String,
    #[serde(serialize_with = "alibi_core::utils::json::serialize")]
    pub metadata: Option<alibi_core::utils::json::JsValue>,
}

impl std::fmt::Debug for MagicLinkDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MagicLinkDelivery").finish_non_exhaustive()
    }
}

#[async_trait]
pub trait SendMagicLink: Send + Sync {
    async fn send(
        &self,
        delivery: &MagicLinkDelivery,
        context: &alibi_core::CallbackContext,
    ) -> AuthResult<()>;
}

#[async_trait]
pub trait MagicLinkTokenGenerator: Send + Sync {
    async fn generate(&self, email: &str) -> AuthResult<String>;
}

#[async_trait]
pub trait MagicLinkTokenHasher: Send + Sync {
    async fn hash(&self, token: &str) -> AuthResult<String>;
}

#[derive(Clone)]
pub enum MagicLinkTokenStorage {
    Plain,
    Hashed,
    Custom(Arc<dyn MagicLinkTokenHasher>),
}

impl std::fmt::Debug for MagicLinkTokenStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => f.write_str("MagicLinkTokenStorage::Plain"),
            Self::Hashed => f.write_str("MagicLinkTokenStorage::Hashed"),
            Self::Custom(..) => f.write_str("MagicLinkTokenStorage::Custom"),
        }
    }
}

#[derive(Clone)]
pub struct MagicLinkConfig {
    pub send_magic_link: Option<Arc<dyn SendMagicLink>>,
    pub generate_token: Option<Arc<dyn MagicLinkTokenGenerator>>,
    pub storage: MagicLinkTokenStorage,
    /// Lifetime in seconds. Zero and NaN use 300 seconds. Fractions retain
    /// JavaScript millisecond rounding; invalid dates fail before persistence.
    pub expires_in: f64,
    pub rate_limit: alibi_core::EndpointRateLimit,
    pub disable_sign_up: bool,
}

impl std::fmt::Debug for MagicLinkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MagicLinkConfig").finish_non_exhaustive()
    }
}

impl Default for MagicLinkConfig {
    fn default() -> Self {
        Self {
            send_magic_link: None,
            generate_token: None,
            storage: MagicLinkTokenStorage::Plain,
            expires_in: 300.0,
            rate_limit: alibi_core::EndpointRateLimit {
                window_seconds: 60.0,
                max_requests: 5.0,
            },
            disable_sign_up: false,
        }
    }
}

#[derive(Clone)]
pub struct MagicLinkPlugin {
    config: MagicLinkConfig,
}

impl std::fmt::Debug for MagicLinkPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MagicLinkPlugin").finish_non_exhaustive()
    }
}

impl MagicLinkPlugin {
    #[must_use]
    pub const fn new(config: MagicLinkConfig) -> Self {
        Self { config }
    }

    async fn store_token(&self, token: &str) -> AuthResult<String> {
        match &self.config.storage {
            MagicLinkTokenStorage::Plain => Ok(token.to_owned()),
            MagicLinkTokenStorage::Hashed => Ok(hash_token(token)),
            MagicLinkTokenStorage::Custom(hasher) => {
                hasher.hash(token).await.map_err(|error| match error {
                    AuthError::Api { .. }
                    | AuthError::Upstream { .. }
                    | AuthError::CallbackFailure(_) => error,
                    error => AuthError::CallbackFailure(Box::new(error)),
                })
            }
        }
    }

    async fn sign_in(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: SignInRequest = match parse_body(req) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let token = if let Some(generator) = &self.config.generate_token {
            generator.generate(&body.email).await?
        } else {
            let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let mut rng = rand::rng();
            (0..32)
                .filter_map(|_| alphabet.get(rng.random_range(0..alphabet.len())).copied())
                .map(char::from)
                .collect()
        };
        let stored = self.store_token(&token).await?;
        let data = LinkData {
            record_type: "magic-link".into(),
            email: body.email.clone(),
            name: body.name,
        };
        let Some(expires_at) =
            super::passwordless_numeric::expires_at(self.config.expires_in, true)
        else {
            return Ok(AuthResponse::new(500));
        };
        _ = ctx
            .verifications()
            .create(CreateVerification {
                identifier: format!("magic-link:{stored}"),
                value: serde_json::to_string(&data)?,
                expires_at,
            })
            .await?;
        let mut url = Url::parse(&ctx.config.base_url)
            .map_err(|_error| AuthError::config("Invalid base URL"))?;
        let path = url.path().trim_end_matches('/');
        let base_path = if path.is_empty() {
            ctx.config.base_path.as_str()
        } else {
            path
        };
        let verify_path = format!("{}/magic-link/verify", base_path.trim_end_matches('/'));
        url.set_path(&verify_path);
        url.set_query(None);
        url.set_fragment(None);
        _ = url
            .query_pairs_mut()
            .append_pair("token", &token)
            .append_pair(
                "callbackURL",
                body.callback_url
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .unwrap_or("/"),
            );
        if let Some(callback) = body.new_user_callback_url.filter(|value| !value.is_empty()) {
            _ = url
                .query_pairs_mut()
                .append_pair("newUserCallbackURL", &callback);
        }
        if let Some(callback) = body.error_callback_url.filter(|value| !value.is_empty()) {
            _ = url
                .query_pairs_mut()
                .append_pair("errorCallbackURL", &callback);
        }
        self.config
            .send_magic_link
            .as_ref()
            .ok_or_else(|| AuthError::config("Magic link sender is not configured"))?
            .send(
                &MagicLinkDelivery {
                    email: body.email,
                    url: url.to_string(),
                    token,
                    metadata: body.metadata,
                },
                &alibi_core::CallbackContext::new(ctx, Some(req)),
            )
            .await
            .map_err(|error| match error {
                AuthError::Api { .. }
                | AuthError::Upstream { .. }
                | AuthError::CallbackFailure(_) => error,
                error => AuthError::CallbackFailure(Box::new(error)),
            })?;
        AuthResponse::json(200, &json!({"status":true})).map_err(AuthError::from)
    }

    async fn verify(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let token = req.query.get("token").ok_or(AuthError::Upstream {
            status: 400,
            code: "VALIDATION_ERROR",
            message: "[query.token] Invalid input: expected string, received undefined",
        })?;
        let callback = decode_callback(req, "callbackURL")?;
        let error_callback = decode_callback(req, "errorCallbackURL")?;
        let new_user_callback = decode_callback(req, "newUserCallbackURL")?;
        // Each pinned originCheck closure labels its input callbackURL,
        // including the new-user and error callbacks.
        for value in [&callback, &new_user_callback, &error_callback] {
            if !ctx.config.current_origin_check_disabled()
                && value
                    .as_deref()
                    .is_some_and(|value| !ctx.config.is_redirect_target_trusted(value))
            {
                return Err(AuthError::Upstream {
                    status: 403,
                    code: "INVALID_CALLBACK_URL",
                    message: "Invalid callbackURL",
                });
            }
        }
        let base = Url::parse(&ctx.config.base_url)
            .map_err(|_error| AuthError::config("Invalid base URL"))?;
        let callback_url = base
            .join(callback.as_deref().unwrap_or("/"))
            .map_err(|_error| AuthError::bad_request("Invalid callbackURL"))?;
        let error_url = base
            .join(error_callback.as_deref().unwrap_or(callback_url.as_str()))
            .map_err(|_error| AuthError::bad_request("Invalid errorCallbackURL"))?;
        let new_user_url = base
            .join(
                new_user_callback
                    .as_deref()
                    .unwrap_or(callback_url.as_str()),
            )
            .map_err(|_error| AuthError::bad_request("Invalid newUserCallbackURL"))?;
        let stored = self.store_token(token).await?;
        let identifier = format!("magic-link:{stored}");
        let pending = ctx.verifications().find(&identifier).await?;
        if pending
            .as_ref()
            .and_then(|row| parse_link_data(row.value().ok()?))
            .is_none()
        {
            return Ok(error_redirect(error_url, "INVALID_TOKEN", None));
        }
        let Some(verification) = ctx.verifications().consume(&identifier).await? else {
            return Ok(error_redirect(error_url, "INVALID_TOKEN", None));
        };

        let Some(data) = parse_link_data(verification.value()?) else {
            return Ok(error_redirect(error_url, "INVALID_TOKEN", None));
        };
        let mut is_new_user = false;
        let user = match ctx.database.get_user_by_email_record(&data.email).await? {
            Some(user) if !user.email_verified() => {
                match revoke_unproven_access(ctx, &user.id()).await? {
                    Some(user) => user,
                    None => return Ok(error_redirect(error_url, "user_not_found", None)),
                }
            }
            Some(user) => user,
            None if self.config.disable_sign_up => {
                return Ok(error_redirect(error_url, "new_user_signup_disabled", None));
            }
            None => {
                let mut user = CreateUser::new()
                    .with_email(data.email)
                    .with_name(data.name.unwrap_or_default())
                    .with_email_verified(true);
                super::helpers::apply_default_role(ctx, &mut user);
                is_new_user = true;
                match ctx
                    .database
                    .create_user_with_source_record(
                        user,
                        alibi_core::user_validation::UserValidationSource::creation("magic-link"),
                    )
                    .await
                {
                    Ok(user) => user,
                    Err(error) => {
                        let (_, code, message) = error.error_payload();
                        if let Some(code) = code {
                            return Ok(error_redirect(error_url, &code, Some(&message)));
                        }
                        return Err(error);
                    }
                }
            }
        };
        let (payload, mut response) = session_response(ctx, req, user).await?;
        if callback.is_none() {
            response.body = serde_json::to_vec(&payload)?;
            return Ok(response);
        }
        let mut redirect_response = redirect(if is_new_user {
            new_user_url.as_str()
        } else {
            callback_url.as_str()
        });
        for cookie in response.headers.get_all("set-cookie") {
            redirect_response.headers.append("Set-Cookie", cookie);
        }
        Ok(redirect_response)
    }
}

alibi_core::impl_auth_plugin! {
    MagicLinkPlugin, "magic-link";
    routes {
        post "/sign-in/magic-link" => sign_in, "signInWithMagicLink";
        get "/magic-link/verify" => verify, "verifyMagicLink";
    }
    extra {
    fn static_openapi_metadata(&self) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::plugin_metadata(<Self as alibi_core::AuthPlugin<S>>::name(self), &<Self as alibi_core::AuthPlugin<S>>::routes(self))
    }

    fn openapi_metadata(&self, ctx: &alibi_core::AuthInitContext<S>) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::instance_plugin_metadata(<Self as alibi_core::AuthPlugin<S>>::name(self), &<Self as alibi_core::AuthPlugin<S>>::routes(self), ctx)
    }

        fn rate_limits(&self) -> Vec<alibi_core::PluginRateLimit> {
            vec![alibi_core::PluginRateLimit { matches: |path| path.starts_with("/sign-in/magic-link") || path.starts_with("/magic-link/verify"), limit: alibi_core::EndpointRateLimit {
                window_seconds: if self.config.rate_limit.window_seconds == 0.0 || self.config.rate_limit.window_seconds.is_nan() { 60.0 } else { self.config.rate_limit.window_seconds },
                max_requests: if self.config.rate_limit.max_requests == 0.0 || self.config.rate_limit.max_requests.is_nan() { 5.0 } else { self.config.rate_limit.max_requests },
            } }]
        }
        async fn on_init(&self, ctx: &mut alibi_core::AuthInitContext<S>) -> AuthResult<()> {
            ctx.set_metadata("magic-link.enabled", json!(true));
            Ok(())
        }
    }
}

#[derive(Deserialize)]
struct SignInRequest {
    email: String,
    name: Option<String>,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL")]
    new_user_callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL")]
    error_callback_url: Option<String>,
    metadata: Option<alibi_core::utils::json::JsValue>,
}

#[derive(Deserialize, Serialize)]
struct LinkData {
    #[serde(rename = "type")]
    record_type: String,
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

fn parse_link_data(value: &str) -> Option<LinkData> {
    let value: serde_json::Value = serde_json::from_str(value).ok()?;
    let object = value.as_object()?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "type" | "email" | "name"))
        || object.get("type")?.as_str()? != "magic-link"
        || !super::authentication_helpers::is_valid_email(object.get("email")?.as_str()?)
        || object.get("name").is_some_and(|name| !name.is_string())
    {
        return None;
    }
    serde_json::from_value(value).ok()
}

impl RequestBody for SignInRequest {
    const FIELDS: &'static [JsonField] = &[
        JsonField {
            name: "email",
            kind: JsonFieldKind::Email,
            required: true,
        },
        JsonField::string("name", false),
        JsonField::string("callbackURL", false),
        JsonField::string("newUserCallbackURL", false),
        JsonField::string("errorCallbackURL", false),
        JsonField {
            name: "metadata",
            kind: JsonFieldKind::Record,
            required: false,
        },
    ];
}

fn decode_callback(req: &AuthRequest, name: &str) -> AuthResult<Option<String>> {
    req.query
        .get(name)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let bytes = value.as_bytes();
            for (index, byte) in bytes.iter().enumerate() {
                if *byte == b'%'
                    && (bytes
                        .get(index + 1)
                        .is_none_or(|byte| !byte.is_ascii_hexdigit())
                        || bytes
                            .get(index + 2)
                            .is_none_or(|byte| !byte.is_ascii_hexdigit()))
                {
                    return Err(AuthError::CallbackFailure(Box::new(AuthError::internal(
                        "Malformed callback encoding",
                    ))));
                }
            }
            urlencoding::decode(value)
                .map(std::borrow::Cow::into_owned)
                .map_err(|error| {
                    AuthError::CallbackFailure(Box::new(AuthError::internal(error.to_string())))
                })
        })
        .transpose()
}

fn error_redirect(mut url: Url, error: &str, description: Option<&str>) -> AuthResponse {
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != "error" && (description.is_none() || key != "error_description"))
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.set_query(None);
    for (key, value) in pairs {
        _ = url.query_pairs_mut().append_pair(&key, &value);
    }
    _ = url.query_pairs_mut().append_pair("error", error);
    if let Some(description) = description {
        _ = url
            .query_pairs_mut()
            .append_pair("error_description", description);
    }
    redirect(url.as_str())
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers;
    use alibi_core::{AuthPlugin, AuthSession, AuthUser, AuthVerification, CreateUser, HttpMethod};
    use chrono::{Duration, Utc};
    use serde_json::Value;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Outbox(Mutex<Vec<MagicLinkDelivery>>);

    #[async_trait]
    impl SendMagicLink for Outbox {
        async fn send(
            &self,
            delivery: &MagicLinkDelivery,
            _context: &alibi_core::CallbackContext,
        ) -> AuthResult<()> {
            self.0.lock().unwrap().push(delivery.clone());
            Ok(())
        }
    }

    struct FixedToken;

    #[async_trait]
    impl MagicLinkTokenGenerator for FixedToken {
        async fn generate(&self, _: &str) -> AuthResult<String> {
            Ok("application-issued-link-token".into())
        }
    }

    struct PrefixHasher;

    #[async_trait]
    impl MagicLinkTokenHasher for PrefixHasher {
        async fn hash(&self, token: &str) -> AuthResult<String> {
            Ok(format!("application-hash:{}", hash_token(token)))
        }
    }

    struct FailedDelivery;

    #[async_trait]
    impl SendMagicLink for FailedDelivery {
        async fn send(
            &self,
            _: &MagicLinkDelivery,
            _context: &alibi_core::CallbackContext,
        ) -> AuthResult<()> {
            Err(AuthError::internal("deterministic sender outage"))
        }
    }

    fn configured() -> (MagicLinkPlugin, Arc<Outbox>) {
        let outbox = Arc::new(Outbox::default());
        (
            MagicLinkPlugin::new(MagicLinkConfig {
                send_magic_link: Some(Arc::<Outbox>::clone(&outbox)),
                ..Default::default()
            }),
            outbox,
        )
    }

    fn verify_request(token: &str) -> AuthRequest {
        let mut req = AuthRequest::new(HttpMethod::Get, "/magic-link/verify");
        _ = req.query.insert("token".into(), token.into());
        req
    }

    // Upstream: magicLink signInMagicLink persists before delivery, then consumes
    // once; no callback gives the complete real user/session response.
    #[tokio::test]
    async fn delivered_link_authenticates_its_mailbox_once_and_persists_session() {
        let ctx = test_helpers::create_test_context().await;
        let (plugin, outbox) = configured();
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/sign-in/magic-link",
            None,
            Some(
                json!({"email":"owner@example.com","name":"Owner","metadata":{"campaign":"welcome"}}),
            ),
        );
        assert_eq!(
            plugin.on_request(&req, &ctx).await.unwrap().unwrap().status,
            200
        );
        let delivery = outbox.0.lock().unwrap().last().unwrap().clone();
        let url = Url::parse(&delivery.url).unwrap();
        assert_eq!(url.path(), "/api/auth/magic-link/verify");
        assert_eq!(
            url.query_pairs()
                .find(|(key, _)| key == "callbackURL")
                .map(|(_, value)| value.into_owned()),
            Some("/".into())
        );
        assert_eq!(
            delivery.metadata,
            Some(json!({"campaign":"welcome"}).into())
        );
        let stored = ctx
            .database
            .get_latest_verification_by_identifier(&format!("magic-link:{}", delivery.token))
            .await
            .unwrap()
            .unwrap();
        assert!(
            (stored.expires_at() - Utc::now() - Duration::seconds(300))
                .num_seconds()
                .abs()
                <= 1
        );
        let req_2 = verify_request(&delivery.token);
        let response = plugin.on_request(&req_2, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 200);
        let payload: Value = serde_json::from_slice(&response.body).unwrap();
        let token = payload.get("token").and_then(Value::as_str).unwrap();
        let user = ctx
            .database
            .get_user_by_email("owner@example.com")
            .await
            .unwrap()
            .unwrap();
        assert!(user.email_verified());
        assert_eq!(
            ctx.database
                .get_session(token)
                .await
                .unwrap()
                .unwrap()
                .user_id(),
            user.id()
        );
        assert!(payload.get("session").is_some());
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(&format!("magic-link:{}", delivery.token))
                .await
                .unwrap()
                .is_none()
        );
        let replay = plugin.on_request(&req_2, &ctx).await.unwrap().unwrap();
        assert_eq!(replay.status, 302);
        assert!(
            replay
                .headers
                .get("location")
                .unwrap()
                .contains("error=INVALID_TOKEN")
        );
    }

    // Upstream: callbackURL/newUserCallbackURL choose different destinations;
    // untrusted redirects are rejected before single-use consumption.
    #[tokio::test]
    async fn callback_authorization_does_not_burn_token_and_new_user_redirects() {
        let ctx = test_helpers::create_test_context().await;
        let (plugin, outbox) = configured();
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/sign-in/magic-link",
            None,
            Some(json!({"email":"new@example.com"})),
        );
        _ = plugin.on_request(&req, &ctx).await.unwrap();
        let delivery = outbox.0.lock().unwrap().last().unwrap().clone();
        let mut req_2 = verify_request(&delivery.token);
        _ = req_2
            .query
            .insert("callbackURL".into(), "https://evil.example/steal".into());
        assert_eq!(
            plugin
                .on_request(&req_2, &ctx)
                .await
                .unwrap_err()
                .status_code(),
            403
        );
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(&format!("magic-link:{}", delivery.token))
                .await
                .unwrap()
                .is_some()
        );
        _ = req_2.query.insert("callbackURL".into(), "/existing".into());
        _ = req_2
            .query
            .insert("newUserCallbackURL".into(), "/welcome?source=magic".into());
        let response = plugin.on_request(&req_2, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers.get("location"),
            Some(&"http://localhost:3000/welcome?source=magic".into())
        );
        assert!(response.headers.contains_key("set-cookie"));
    }

    // Upstream: disabled signup still issues/delivers, but consumes and redirects
    // with new_user_signup_disabled when the token identifies a new user.
    #[tokio::test]
    async fn disabled_signup_consumes_token_without_creating_user() {
        let ctx = test_helpers::create_test_context().await;
        let (mut plugin, outbox) = configured();
        plugin.config.disable_sign_up = true;
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/sign-in/magic-link",
            None,
            Some(json!({"email":"disabled@example.com"})),
        );
        _ = plugin.on_request(&req, &ctx).await.unwrap();
        let delivery = outbox.0.lock().unwrap().last().unwrap().clone();
        let response = plugin
            .on_request(&verify_request(&delivery.token), &ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 302);
        assert!(
            response
                .headers
                .get("location")
                .unwrap()
                .contains("new_user_signup_disabled")
        );
        assert!(
            ctx.database
                .get_user_by_email("disabled@example.com")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(&format!("magic-link:{}", delivery.token))
                .await
                .unwrap()
                .is_none()
        );
    }

    // Upstream: hashed storage derives the lookup key, and verification after
    // expiry invalidates the record without minting a user/session.
    #[tokio::test]
    async fn hashed_expired_token_is_removed_and_cannot_create_session() {
        let ctx = test_helpers::create_test_context().await;
        let (mut plugin, outbox) = configured();
        plugin.config.storage = MagicLinkTokenStorage::Hashed;
        plugin.config.expires_in = -1.0;
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/sign-in/magic-link",
            None,
            Some(json!({"email":"expired@example.com"})),
        );
        _ = plugin.on_request(&req, &ctx).await.unwrap();
        let delivery = outbox.0.lock().unwrap().last().unwrap().clone();
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(&format!("magic-link:{}", delivery.token))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(&format!(
                    "magic-link:{}",
                    hash_token(&delivery.token)
                ))
                .await
                .unwrap()
                .is_some()
        );
        let response = plugin
            .on_request(&verify_request(&delivery.token), &ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 302);
        assert!(
            response
                .headers
                .get("location")
                .unwrap()
                .contains("INVALID_TOKEN")
        );
        assert!(
            ctx.database
                .get_user_by_email("expired@example.com")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(&format!(
                    "magic-link:{}",
                    hash_token(&delivery.token)
                ))
                .await
                .unwrap()
                .is_none()
        );
    }

    // Upstream: a magic-link proof removes unproven standing sessions before login.
    #[tokio::test]
    async fn existing_unverified_user_keeps_identity_but_loses_previous_session() {
        let ctx = test_helpers::create_test_context().await;
        let user = ctx
            .database
            .create_user(CreateUser::new().with_email("promote@example.com"))
            .await
            .unwrap();
        let previous = ctx
            .session_manager()
            .create_session(&user, None, None)
            .await
            .unwrap();
        let (plugin, outbox) = configured();
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/sign-in/magic-link",
            None,
            Some(json!({"email":"promote@example.com"})),
        );
        _ = plugin.on_request(&req, &ctx).await.unwrap();
        let delivery = outbox.0.lock().unwrap().last().unwrap().clone();
        assert_eq!(
            plugin
                .on_request(&verify_request(&delivery.token), &ctx)
                .await
                .unwrap()
                .unwrap()
                .status,
            200
        );
        let promoted = ctx
            .database
            .get_user_by_email("promote@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(promoted.id(), user.id());
        assert!(promoted.email_verified());
        assert!(
            ctx.database
                .get_session(previous.token())
                .await
                .unwrap()
                .is_none()
        );
    }

    // Upstream: custom token generation and storage compose, and concurrent calls
    // consume a shared token once even when both callers know the actual secret.
    #[tokio::test]
    async fn custom_generation_hashing_and_concurrent_consumption_preserve_owned_session() {
        let ctx = test_helpers::create_test_context().await;
        let (mut plugin, outbox) = configured();
        plugin.config.generate_token = Some(Arc::new(FixedToken));
        plugin.config.storage = MagicLinkTokenStorage::Custom(Arc::new(PrefixHasher));
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/sign-in/magic-link",
            None,
            Some(json!({"email":"custom@example.com"})),
        );
        _ = plugin.on_request(&req, &ctx).await.unwrap();
        let token = outbox.0.lock().unwrap().last().unwrap().token.clone();
        assert_eq!(token, "application-issued-link-token");
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(&format!("magic-link:{token}"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(&format!(
                    "magic-link:application-hash:{}",
                    hash_token(&token)
                ))
                .await
                .unwrap()
                .is_some()
        );
        let req_2 = verify_request(&token);
        let (first, second) = tokio::join!(
            plugin.on_request(&req_2, &ctx),
            plugin.on_request(&req_2, &ctx)
        );
        let mut statuses = [
            first.unwrap().unwrap().status,
            second.unwrap().unwrap().status,
        ];
        statuses.sort_unstable();
        assert_eq!(statuses, [200, 302]);
        let user = ctx
            .database
            .get_user_by_email("custom@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            ctx.database
                .get_user_sessions(&user.id())
                .await
                .unwrap()
                .len(),
            1
        );
    }

    // Golden Zod vectors and all originCheck closures are evaluated before the
    // challenge is touched, including error/new-user callbacks.
    #[tokio::test]
    async fn validation_and_every_callback_guard_leave_the_challenge_untouched() {
        let ctx = test_helpers::create_test_context().await;
        let (plugin, outbox) = configured();
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/sign-in/magic-link",
            None,
            Some(json!({"email":"ok@example.com","name":null,"metadata":[]})),
        );
        let response = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 400);
        let payload: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            payload,
            json!({"code":"VALIDATION_ERROR","message":"[body.name] Invalid input: expected string, received null; [body.metadata] Invalid input: expected record, received array"})
        );
        assert!(outbox.0.lock().unwrap().is_empty());
        let req_2 = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/sign-in/magic-link",
            None,
            Some(json!({"email":"ok@example.com"})),
        );
        _ = plugin.on_request(&req_2, &ctx).await.unwrap();
        let token = outbox.0.lock().unwrap().last().unwrap().token.clone();
        for field in ["callbackURL", "newUserCallbackURL", "errorCallbackURL"] {
            let mut req_3 = verify_request(&token);
            _ = req_3
                .query
                .insert(field.into(), "https://foreign.example/steal".into());
            let error = plugin.on_request(&req_3, &ctx).await.unwrap_err();
            let (_, code, message) = error.error_payload();
            assert_eq!(code.as_deref(), Some("INVALID_CALLBACK_URL"));
            assert_eq!(message, "Invalid callbackURL");
            assert!(
                ctx.database
                    .get_latest_verification_by_identifier(&format!("magic-link:{token}"))
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        let missing = AuthRequest::new(HttpMethod::Get, "/magic-link/verify");
        assert_eq!(
            plugin
                .on_request(&missing, &ctx)
                .await
                .unwrap_err()
                .error_payload()
                .1
                .as_deref(),
            Some("VALIDATION_ERROR")
        );
    }

    // Upstream: delivery fails after persistence; an already issued token retains
    // its deadline and is usable after the application restores the sender.
    #[tokio::test]
    async fn sender_failure_keeps_token_and_error_redirect_preserves_query_state() {
        let ctx = test_helpers::create_test_context().await;
        let (mut plugin, _) = configured();
        plugin.config.generate_token = Some(Arc::new(FixedToken));
        plugin.config.send_magic_link = Some(Arc::new(FailedDelivery));
        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/sign-in/magic-link",
            None,
            Some(json!({"email":"outage@example.com"})),
        );
        assert_eq!(
            plugin
                .on_request(&req, &ctx)
                .await
                .unwrap_err()
                .status_code(),
            500
        );
        assert!(
            ctx.database
                .get_latest_verification_by_identifier("magic-link:application-issued-link-token")
                .await
                .unwrap()
                .is_some()
        );
        let req_2 = verify_request("application-issued-link-token");
        assert_eq!(
            plugin
                .on_request(&req_2, &ctx)
                .await
                .unwrap()
                .unwrap()
                .status,
            200
        );
        let mut replay = req_2;
        _ = replay.query.insert(
            "errorCallbackURL".into(),
            "/error?source=magic&error=old&error_description=preserved".into(),
        );
        let response = plugin.on_request(&replay, &ctx).await.unwrap().unwrap();
        let url = Url::parse(response.headers.get("location").unwrap()).unwrap();
        assert_eq!(
            url.query_pairs()
                .find(|(key, _)| key == "error_description")
                .map(|(_, value)| value.into_owned()),
            Some("preserved".into())
        );
        assert_eq!(
            url.query_pairs()
                .find(|(key, _)| key == "error")
                .map(|(_, value)| value.into_owned()),
            Some("INVALID_TOKEN".into())
        );
    }
}
// LCOV_EXCL_STOP
