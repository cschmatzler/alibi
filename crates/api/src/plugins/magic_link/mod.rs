//! Single-use mailbox authentication links, with native delivery callbacks.

#[cfg(test)]
mod tests;

use super::authentication_helpers::{
    JsonField, JsonFieldKind, RequestBody, parse_body, redirect, revoke_unproven_access,
    session_response,
};
use super::token_crypto::hash_token;
use async_trait::async_trait;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, AuthUser,
    CreateUser, CreateVerification,
};
use chrono::{Duration, Utc};
use rand::{Rng, rngs::OsRng};
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
    #[serde(serialize_with = "better_auth_core::utils::json::serialize")]
    pub metadata: Option<better_auth_core::utils::json::JsValue>,
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
        context: &better_auth_core::CallbackContext,
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
    pub expires_in: Duration,
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
            expires_in: Duration::seconds(300),
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
            MagicLinkTokenStorage::Custom(hasher) => hasher.hash(token).await,
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
            let mut rng = OsRng;
            (0..32)
                .filter_map(|_| alphabet.get(rng.gen_range(0..alphabet.len())).copied())
                .map(char::from)
                .collect()
        };
        let stored = self.store_token(&token).await?;
        let data = LinkData {
            email: body.email.clone(),
            name: body.name,
        };
        let expires_in = if self.config.expires_in.is_zero() {
            Duration::seconds(300)
        } else {
            self.config.expires_in
        };
        drop(
            ctx.verifications()
                .create(CreateVerification {
                    identifier: stored,
                    value: serde_json::to_string(&data)?,
                    expires_at: Utc::now() + expires_in,
                })
                .await?,
        );
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
                &better_auth_core::CallbackContext::new(ctx, Some(req)),
            )
            .await?;
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
        let Some(verification) = ctx.verifications().consume(&stored).await? else {
            return Ok(error_redirect(error_url, "INVALID_TOKEN", None));
        };

        let data: LinkData = serde_json::from_str(verification.value()?)?;
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
                        better_auth_core::user_validation::UserValidationSource::creation(
                            "magic-link",
                        ),
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

better_auth_core::impl_auth_plugin! {
    MagicLinkPlugin, "magic-link";
    routes {
        post "/sign-in/magic-link" => sign_in, "signInWithMagicLink";
        get "/magic-link/verify" => verify, "verifyMagicLink";
    }
    extra {
        async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
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
    metadata: Option<better_auth_core::utils::json::JsValue>,
}

#[derive(Deserialize, Serialize)]
struct LinkData {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
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
            urlencoding::decode(value)
                .map(std::borrow::Cow::into_owned)
                .map_err(|_error| AuthError::bad_request("Invalid callbackURL"))
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
