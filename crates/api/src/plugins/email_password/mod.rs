mod signup;
use super::{email_verification::EmailVerificationPlugin, two_factor};
use crate::plugins::authentication_helpers::{
    JsonField, JsonFieldKind, RequestBody, is_valid_email, parse_body,
};
use crate::plugins::helpers::{SessionIssueError, apply_default_role};
use async_trait::async_trait;
use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::field_policy::FieldValues;
use better_auth_core::utils::cookie_utils::{
    create_session_cookie, create_session_cookie_with_max_age, create_session_like_cookie,
    related_cookie_name, sign_cookie_value,
};
use better_auth_core::utils::password::{self as password_utils, PasswordHasher};
pub use better_auth_core::utils::username::{
    UsernameConfig, UsernameNormalization, UsernameNormalizer, UsernameValidationOrder,
    UsernameValidator,
};
use better_auth_core::wire::UserView;
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{
    AuthRequest, AuthResponse, CreateAccount, CreateSession, CreateUser, ErrorCodeMessageResponse,
    HttpMethod, RequestMeta,
};
use serde::{Deserialize, Serialize};
pub use signup::{CustomSyntheticUserCallback, ExistingUserSignupCallback, SyntheticUserContext};
use std::io::Write;
use std::sync::Arc;
use validator::Validate;

const MESSAGE_INVALID_USERNAME_OR_PASSWORD: &str = "Invalid username or password";

const MESSAGE_EMAIL_NOT_VERIFIED: &str = "Email not verified";

const MESSAGE_USERNAME_IS_ALREADY_TAKEN: &str = "Username is already taken. Please try another.";

/// Email and password authentication plugin
pub struct EmailPasswordPlugin {
    config: EmailPasswordConfig,
    /// Optional reference to the email-verification plugin so that
    /// `send_on_sign_in` can be triggered during the sign-in flow.
    email_verification: Option<Arc<EmailVerificationPlugin>>,
}

#[derive(Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Independent configuration switches model distinct upstream behavior, rather than mutually exclusive states"
)]
pub struct EmailPasswordConfig {
    /// Whether email/password authentication is enabled. Routes remain registered.
    pub enabled: bool,
    pub enable_signup: bool,
    /// Whether to enable the username schema, signup hooks, and endpoints.
    pub enable_username: bool,
    pub username: UsernameConfig,
    pub require_email_verification: bool,
    /// Minimum UTF-16 password length. Zero uses the default of 8.
    pub password_min_length: usize,
    /// Maximum UTF-16 password length. Zero uses the default of 128.
    pub password_max_length: usize,
    /// Whether to automatically sign in the user after sign-up (default: true).
    /// When false, sign-up returns the user but doesn't create a session.
    pub auto_sign_in: bool,
    /// Custom password hasher. When `None`, the default scrypt hasher is used.
    pub password_hasher: Option<Arc<dyn PasswordHasher>>,
    pub on_existing_user_signup: Option<Arc<ExistingUserSignupCallback>>,
    pub custom_synthetic_user: Option<Arc<CustomSyntheticUserCallback>>,
}

impl EmailPasswordConfig {
    const fn effective_min_length(&self) -> usize {
        if self.password_min_length == 0 {
            8
        } else {
            self.password_min_length
        }
    }

    const fn effective_max_length(&self) -> usize {
        if self.password_max_length == 0 {
            128
        } else {
            self.password_max_length
        }
    }
}

impl std::fmt::Debug for EmailPasswordConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailPasswordConfig")
            .field("enabled", &self.enabled)
            .field("enable_signup", &self.enable_signup)
            .field("enable_username", &self.enable_username)
            .field("username", &self.username)
            .field(
                "require_email_verification",
                &self.require_email_verification,
            )
            .field("password_min_length", &self.password_min_length)
            .field("password_max_length", &self.password_max_length)
            .field("auto_sign_in", &self.auto_sign_in)
            .field(
                "password_hasher",
                &self.password_hasher.as_ref().map(|_| "custom"),
            )
            .field(
                "on_existing_user_signup",
                &self.on_existing_user_signup.as_ref().map(|_| "custom"),
            )
            .field(
                "custom_synthetic_user",
                &self.custom_synthetic_user.as_ref().map(|_| "custom"),
            )
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Validate)]
pub(in crate::plugins) struct SignUpRequest {
    #[serde(flatten, default)]
    additional_fields: indexmap::IndexMap<String, better_auth_core::utils::json::JsValue>,
    #[serde(rename = "lastLoginMethod")]
    last_login_method: Option<better_auth_core::utils::json::JsValue>,
    #[validate(length(min = 1, message = "Name is required"))]
    name: String,
    #[validate(email(message = "Invalid email address"))]
    email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    password: String,
    username: Option<String>,
    #[serde(rename = "displayUsername")]
    display_username: Option<String>,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    image: Option<String>,
    #[serde(rename = "rememberMe")]
    remember_me: Option<bool>,
    #[serde(rename = "phoneNumber")]
    phone_number: Option<better_auth_core::utils::json::JsValue>,
    #[serde(rename = "phoneNumberVerified")]
    phone_number_verified: Option<better_auth_core::utils::json::JsValue>,
}

impl RequestBody for SignUpRequest {
    const FIELDS: &'static [JsonField] = &[
        JsonField::string("name", true),
        JsonField {
            name: "email",
            kind: JsonFieldKind::Email,
            required: true,
        },
        JsonField {
            name: "password",
            kind: JsonFieldKind::NonEmptyString,
            required: true,
        },
        JsonField::string("image", false),
        JsonField::string("callbackURL", false),
        JsonField {
            name: "rememberMe",
            kind: JsonFieldKind::Boolean,
            required: false,
        },
    ];
}

#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct SignInRequest {
    #[validate(email(message = "Invalid email address"))]
    email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    password: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    #[serde(rename = "rememberMe")]
    remember_me: Option<bool>,
}

impl RequestBody for SignInRequest {
    const FIELDS: &'static [JsonField] = &[
        JsonField::string("email", true),
        JsonField::string("password", true),
        JsonField::string("callbackURL", false),
        JsonField {
            name: "rememberMe",
            kind: JsonFieldKind::Boolean,
            required: false,
        },
    ];
}

#[derive(Debug, Deserialize, Validate)]
pub(in crate::plugins) struct SignInUsernameRequest {
    username: String,
    password: String,
    #[serde(rename = "rememberMe")]
    remember_me: Option<bool>,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
struct IsUsernameAvailableRequest {
    username: String,
}

#[derive(Debug, Serialize)]
struct IsUsernameAvailableResponse {
    available: bool,
}

#[derive(Debug, Serialize)]
pub(in crate::plugins) struct SignUpResponse<U> {
    token: Option<String>,
    user: U,
}

#[derive(Debug, Serialize)]
pub(in crate::plugins) struct SignInResponse<U> {
    redirect: bool,
    token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    user: U,
}

#[derive(Debug, Serialize)]
pub(in crate::plugins) struct SignInUsernameResponse<U> {
    /// Upstream returns the same redirect envelope as `/sign-in/email`.
    redirect: bool,
    token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    user: U,
}

/// Result of sign-in: either a successful session or a 2FA redirect.
pub(in crate::plugins) enum SignInCoreResult<U: Serialize> {
    Success {
        response: SignInResponse<U>,
        token: String,
        set_cookie_headers: Vec<String>,
    },
    TwoFactorRedirect {
        response: two_factor::TwoFactorRedirectResponse,
        set_cookie_headers: Vec<String>,
    },
}

impl EmailPasswordPlugin {
    #[expect(
        clippy::new_without_default,
        reason = "plugin construction is intentionally explicit"
    )]
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: EmailPasswordConfig::default(),
            email_verification: None,
        }
    }

    #[must_use]
    pub const fn with_config(config: EmailPasswordConfig) -> Self {
        Self {
            config,
            email_verification: None,
        }
    }

    /// Attach an [`EmailVerificationPlugin`] so that `send_on_sign_in` is
    /// automatically called when a user signs in with an unverified email.
    #[must_use]
    pub fn with_email_verification(mut self, plugin: Arc<EmailVerificationPlugin>) -> Self {
        self.email_verification = Some(plugin);
        self
    }

    #[must_use]
    pub const fn enable_signup(mut self, enable: bool) -> Self {
        self.config.enable_signup = enable;
        self
    }

    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    #[must_use]
    pub fn on_existing_user_signup(mut self, callback: Arc<ExistingUserSignupCallback>) -> Self {
        self.config.on_existing_user_signup = Some(callback);
        self
    }

    #[must_use]
    pub fn custom_synthetic_user(mut self, callback: Arc<CustomSyntheticUserCallback>) -> Self {
        self.config.custom_synthetic_user = Some(callback);
        self
    }

    #[must_use]
    pub const fn enable_username(mut self, enable: bool) -> Self {
        self.config.enable_username = enable;
        self
    }

    /// Configure the installed username plugin's validation and normalization.
    #[must_use]
    pub fn username_config(mut self, policy: UsernameConfig) -> Self {
        self.config.username = policy;
        self
    }

    #[must_use]
    pub const fn require_email_verification(mut self, require: bool) -> Self {
        self.config.require_email_verification = require;
        self
    }

    #[must_use]
    pub const fn password_min_length(mut self, length: usize) -> Self {
        self.config.password_min_length = length;
        self
    }

    #[must_use]
    pub const fn password_max_length(mut self, length: usize) -> Self {
        self.config.password_max_length = length;
        self
    }

    #[must_use]
    pub const fn auto_sign_in(mut self, auto: bool) -> Self {
        self.config.auto_sign_in = auto;
        self
    }

    #[must_use]
    pub fn password_hasher(mut self, hasher: Arc<dyn PasswordHasher>) -> Self {
        self.config.password_hasher = Some(hasher);
        self
    }

    async fn handle_sign_up(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let ignored = if self.config.enable_username {
            &[][..]
        } else {
            &["username", "displayUsername"][..]
        };
        let mut signup_req: SignUpRequest =
            match super::authentication_helpers::parse_body_with_ignored_fields(req, ignored) {
                Ok(value) => value,
                Err(response) => return Ok(response),
            };

        better_auth_core::middleware::CsrfMiddleware::new(
            better_auth_core::middleware::CsrfConfig::new(),
            Arc::clone(&ctx.config),
        )
        .check_form_origin(req)?;
        signup_req.email = signup_req.email.to_lowercase();
        if self.config.enable_username {
            let policy = &self.config.username;
            if signup_req.username.is_none()
                && let Some(display) = &signup_req.display_username
                && policy.value_error(display).await?.is_none()
            {
                signup_req.username = Some(display.clone());
            }
            if let Some(username) = &signup_req.username {
                policy.validate_hook_value(username).await?;
                if ctx
                    .database
                    .get_user_by_username(&policy.normalize(username)?)
                    .await?
                    .is_some()
                {
                    return username_error_response(
                        400,
                        "USERNAME_IS_ALREADY_TAKEN",
                        MESSAGE_USERNAME_IS_ALREADY_TAKEN,
                    );
                }
            }
            if let Some(display) = &signup_req.display_username {
                policy.validate_display(display).await?;
            }
            if policy.include_display_username
                && signup_req
                    .display_username
                    .as_ref()
                    .is_none_or(String::is_empty)
            {
                signup_req.display_username.clone_from(&signup_req.username);
            }
            if !policy.include_display_username {
                signup_req.display_username = None;
            }
            let mut callback_body = req.body_as_json::<better_auth_core::utils::json::JsValue>()?;
            if let better_auth_core::utils::json::JsValue::Object(body) = &mut callback_body {
                if let Some(value) = &signup_req.username {
                    drop(body.insert(
                        "username".into(),
                        better_auth_core::utils::json::JsValue::String(value.clone()),
                    ));
                }
                if let Some(value) = &signup_req.display_username {
                    drop(body.insert(
                        "displayUsername".into(),
                        better_auth_core::utils::json::JsValue::String(value.clone()),
                    ));
                }
            }
            req.extensions()
                .insert(better_auth_core::hooks::TransformedRequestBody(
                    callback_body,
                ));
        }

        better_auth_core::cache::runtime::set_issuance_preference(
            req,
            signup_req.remember_me == Some(false),
        );
        let meta = RequestMeta::from_request(req);
        let (response, session_token) =
            sign_up_core(req, &signup_req, &self.config, &meta, ctx).await?;

        if let Some(token) = session_token {
            let cookie_header =
                create_session_cookie_for_remember_me(&token, signup_req.remember_me, &ctx.config);
            Ok(append_dont_remember_cookie(
                AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header),
                signup_req.remember_me,
                &ctx.config,
            ))
        } else {
            Ok(AuthResponse::json(200, &response)?)
        }
    }

    async fn handle_sign_in(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let signin_req: SignInRequest = match parse_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let mut callback_body: better_auth_core::utils::json::JsValue = req.body_as_json()?;
        if let better_auth_core::utils::json::JsValue::Object(body) = &mut callback_body {
            let _remember = body
                .entry("rememberMe".into())
                .or_insert(better_auth_core::utils::json::JsValue::Bool(true));
        }
        req.extensions()
            .insert(better_auth_core::hooks::ValidatedRequestBody(callback_body));
        better_auth_core::middleware::CsrfMiddleware::new(
            better_auth_core::middleware::CsrfConfig::new(),
            Arc::clone(&ctx.config),
        )
        .check_form_origin(req)?;

        better_auth_core::cache::runtime::set_issuance_preference(
            req,
            signin_req.remember_me == Some(false),
        );
        let meta = RequestMeta::from_request(req);
        match sign_in_core(
            req,
            &signin_req,
            &self.config,
            self.email_verification.as_deref(),
            &meta,
            ctx,
        )
        .await?
        {
            SignInCoreResult::Success {
                response,
                token,
                set_cookie_headers,
            } => {
                let mut auth_response = AuthResponse::json(200, &response)?.with_appended_header(
                    "Set-Cookie",
                    create_session_cookie_for_remember_me(
                        &token,
                        signin_req.remember_me,
                        &ctx.config,
                    ),
                );
                if let Some(url) = signin_req
                    .callback_url
                    .as_deref()
                    .filter(|url| !url.is_empty())
                {
                    auth_response = auth_response.with_header("Location", url);
                }
                for cookie in set_cookie_headers {
                    auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
                }
                Ok(append_dont_remember_cookie(
                    auth_response,
                    signin_req.remember_me,
                    &ctx.config,
                ))
            }
            SignInCoreResult::TwoFactorRedirect {
                response,
                set_cookie_headers,
            } => {
                let mut auth_response = AuthResponse::json(200, &response)?;
                for cookie in set_cookie_headers {
                    auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
                }
                Ok(auth_response)
            }
        }
    }

    async fn handle_sign_in_username(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let signin_req: SignInUsernameRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        if signin_req.username.is_empty() || signin_req.password.is_empty() {
            return username_error_response(
                401,
                "INVALID_USERNAME_OR_PASSWORD",
                MESSAGE_INVALID_USERNAME_OR_PASSWORD,
            );
        }

        let policy = &self.config.username;
        let validation_input =
            if policy.validation_order == Some(UsernameValidationOrder::PreNormalization) {
                policy.normalize(&signin_req.username)?
            } else {
                signin_req.username.clone()
            };
        if let Err(error) = policy.validate_value(&validation_input, 422).await {
            return Ok(error.to_auth_response());
        }
        let username = policy.normalize(&validation_input)?;

        let meta = RequestMeta::from_request(req);
        match sign_in_username_core(
            req,
            &signin_req,
            &username,
            &self.config,
            self.email_verification.as_deref(),
            &meta,
            ctx,
        )
        .await
        {
            Ok(SignInCoreResult::Success {
                response,
                token,
                set_cookie_headers,
            }) => {
                let username_response = SignInUsernameResponse {
                    redirect: response.redirect,
                    token: response.token,
                    url: response.url,
                    user: response.user,
                };
                let mut auth_response = AuthResponse::json(200, &username_response)?
                    .with_appended_header(
                        "Set-Cookie",
                        create_session_cookie_for_remember_me(
                            &token,
                            signin_req.remember_me,
                            &ctx.config,
                        ),
                    );
                if let Some(url) = signin_req
                    .callback_url
                    .as_deref()
                    .filter(|url| !url.is_empty())
                {
                    auth_response = auth_response.with_header("Location", url);
                }
                for cookie in set_cookie_headers {
                    auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
                }
                Ok(append_dont_remember_cookie(
                    auth_response,
                    signin_req.remember_me,
                    &ctx.config,
                ))
            }
            Ok(SignInCoreResult::TwoFactorRedirect {
                response,
                set_cookie_headers,
            }) => {
                let mut auth_response = AuthResponse::json(200, &response)?;
                for cookie in set_cookie_headers {
                    auth_response = auth_response.with_appended_header("Set-Cookie", cookie);
                }
                Ok(auth_response)
            }
            Err(SignInUsernameFailure::InvalidUsernameOrPassword) => username_error_response(
                401,
                "INVALID_USERNAME_OR_PASSWORD",
                MESSAGE_INVALID_USERNAME_OR_PASSWORD,
            ),
            Err(SignInUsernameFailure::EmailNotVerified) => {
                username_error_response(403, "EMAIL_NOT_VERIFIED", MESSAGE_EMAIL_NOT_VERIFIED)
            }
            Err(SignInUsernameFailure::Auth(error)) => Err(error),
        }
    }

    async fn handle_is_username_available(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: IsUsernameAvailableRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        if body.username.is_empty() {
            return username_error_response(422, "INVALID_USERNAME", "Username is invalid");
        }

        if let Err(error) = self
            .config
            .username
            .validate_value(&body.username, 422)
            .await
        {
            return Ok(error.to_auth_response());
        }
        let normalized = self.config.username.normalize(&body.username)?;
        let user = ctx.database.get_user_by_username(&normalized).await?;
        let available = user.is_none();

        Ok(AuthResponse::json(
            200,
            &IsUsernameAvailableResponse { available },
        )?)
    }
}

pub(in crate::plugins) enum SignInUsernameFailure {
    InvalidUsernameOrPassword,
    EmailNotVerified,
    Auth(AuthError),
}

impl Default for EmailPasswordConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enable_signup: true,
            enable_username: true,
            username: UsernameConfig::default(),
            require_email_verification: false,
            password_min_length: 8,
            password_max_length: 128,
            auto_sign_in: true,
            password_hasher: None,
            on_existing_user_signup: None,
            custom_synthetic_user: None,
        }
    }
}

#[async_trait]
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for EmailPasswordPlugin {
    fn name(&self) -> &'static str {
        "email-password"
    }

    async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
        let mut config = self.config.clone();
        config.password_min_length = config.effective_min_length();
        config.password_max_length = config.effective_max_length();
        ctx.extensions.insert(config);
        if self.config.enable_username {
            ctx.extensions.insert(self.config.username.clone());
            let policy = self.config.username.clone();
            ctx.register_user_create_transform(move |mut data| {
                policy.normalize_fields(
                    &mut data.username,
                    &mut data.display_username,
                    &mut data.additional_fields,
                    true,
                )?;
                Ok(data)
            });
            let policy = self.config.username.clone();
            ctx.register_user_update_transform(move |_, mut data| {
                policy.normalize_fields(
                    &mut data.username,
                    &mut data.display_username,
                    &mut data.additional_fields,
                    false,
                )?;
                Ok(data)
            });
        }
        if self.config.enable_username {
            drop(
                ctx.metadata
                    .insert("username.enabled".into(), serde_json::Value::Bool(true)),
            );
        }
        Ok(())
    }

    fn user_fields(&self) -> better_auth_core::field_policy::FieldConfigs {
        if self.config.enable_username {
            self.config.username.fields()
        } else {
            Default::default()
        }
    }

    fn routes(&self) -> Vec<AuthRoute> {
        let mut routes = vec![AuthRoute::post("/sign-in/email", "sign_in_email")];
        if self.config.enable_username {
            routes.extend([
                AuthRoute::post("/sign-in/username", "sign_in_username"),
                AuthRoute::post("/is-username-available", "is_username_available"),
            ]);
        }

        routes.push(AuthRoute::post("/sign-up/email", "sign_up_email"));

        routes
    }

    fn allowed_media_types(&self, route: &AuthRoute) -> Vec<&'static str> {
        if matches!(route.path.as_str(), "/sign-up/email" | "/sign-in/email") {
            vec!["application/x-www-form-urlencoded", "application/json"]
        } else {
            vec!["application/json"]
        }
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/sign-up/email") => Ok(Some(self.handle_sign_up(req, ctx).await?)),
            (HttpMethod::Post, "/sign-in/email") => Ok(Some(self.handle_sign_in(req, ctx).await?)),
            (HttpMethod::Post, "/sign-in/username") if self.config.enable_username => {
                Ok(Some(self.handle_sign_in_username(req, ctx).await?))
            }
            (HttpMethod::Post, "/is-username-available") if self.config.enable_username => {
                Ok(Some(self.handle_is_username_available(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }

    async fn on_user_created(&self, user: &S::User, _ctx: &AuthContext<S>) -> AuthResult<()> {
        if self.config.require_email_verification
            && !user.email_verified()
            && let Some(email) = user.email()
        {
            drop(writeln!(
                std::io::stdout().lock(),
                "Email verification required for user: {email}"
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for EmailPasswordPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailPasswordPlugin")
            .finish_non_exhaustive()
    }
}

fn username_error_response(status: u16, code: &str, message: &str) -> AuthResult<AuthResponse> {
    AuthResponse::json(
        status,
        &ErrorCodeMessageResponse {
            code: Some(code.to_owned()),
            message: message.to_owned(),
        },
    )
    .map_err(AuthError::from)
}

fn create_session_cookie_for_remember_me(
    token: &str,
    remember_me: Option<bool>,
    config: &better_auth_core::AuthConfig,
) -> String {
    if remember_me == Some(false) {
        create_session_cookie_with_max_age(Some(token), None, config)
    } else {
        create_session_cookie(token, config)
    }
}

fn append_dont_remember_cookie(
    response: AuthResponse,
    remember_me: Option<bool>,
    config: &better_auth_core::AuthConfig,
) -> AuthResponse {
    if remember_me == Some(false) {
        response.with_appended_header(
            "Set-Cookie",
            create_session_like_cookie(
                &related_cookie_name(config, "dont_remember"),
                &sign_cookie_value("true", config.current_secret()),
                None,
                config,
            ),
        )
    } else {
        response
    }
}

// ---------------------------------------------------------------------------
// Core functions — framework-agnostic business logic
// ---------------------------------------------------------------------------

/// Core sign-up logic.
///
/// Returns `(response, Option<session_token>)`. The session token is present
/// only when `auto_sign_in` is true.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
#[expect(
    clippy::too_many_lines,
    reason = "Keep signup validation, persistence, and provider callbacks in compatibility order"
)]
pub(in crate::plugins) async fn sign_up_core<S: better_auth_core::AuthSchema>(
    request: &AuthRequest,
    body: &SignUpRequest,
    config: &EmailPasswordConfig,
    meta: &RequestMeta,
    ctx: &AuthContext<S>,
) -> AuthResult<(SignUpResponse<serde_json::Value>, Option<String>)> {
    if !config.enabled || !config.enable_signup {
        return Err(AuthError::Upstream {
            status: 400,
            code: "EMAIL_PASSWORD_SIGN_UP_DISABLED",
            message: "Email and password sign up is not enabled",
        });
    }

    password_utils::validate_password(
        &body.password,
        config.effective_min_length(),
        config.effective_max_length(),
        ctx,
    )?;

    let mut input_fields = body.additional_fields.clone();
    if config.enable_username {
        if let Some(value) = &body.username {
            drop(input_fields.insert(
                "username".into(),
                better_auth_core::utils::json::JsValue::String(value.clone()),
            ));
        }
        if config.username.include_display_username
            && let Some(value) = &body.display_username
        {
            drop(input_fields.insert(
                "displayUsername".into(),
                better_auth_core::utils::json::JsValue::String(value.clone()),
            ));
        }
    }
    let additional_fields =
        ctx.parse_user_fields(&input_fields, true)
            .map_err(|error| match error {
                better_auth_core::field_policy::FieldInputError::Validation { code, message } => {
                    AuthError::Api {
                        status: 400,
                        code: Some(code.into()),
                        message,
                    }
                }
                better_auth_core::field_policy::FieldInputError::Transform(error) => error,
            })?;

    super::last_login_method::reject_last_login_method_input(ctx, body.last_login_method.as_ref())?;

    let phone_enabled = ctx
        .get_metadata("phone-number.enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if phone_enabled {
        super::phone_number::reject_verified_input(body.phone_number_verified.as_ref())?;
    }

    // Check if user already exists
    if let Some(user) = ctx.database.get_user_by_email(&body.email).await? {
        if config.require_email_verification || !config.auto_sign_in {
            drop(
                ctx.hash_password(config.password_hasher.as_ref(), &body.password)
                    .await?,
            );
            signup::notify_existing(ctx.user_view(&user), request, config, ctx).await?;
            return signup::synthetic_response(body, config, ctx);
        }
        // TS returns 422 UNPROCESSABLE_ENTITY for duplicate email
        return Err(AuthError::UnprocessableEntity(
            "User already exists. Use another email.".to_owned(),
        ));
    }

    // Hash password
    let password_hash = ctx
        .hash_password(config.password_hasher.as_ref(), &body.password)
        .await?;

    let mut create_user = CreateUser::new()
        .with_email(&body.email)
        .with_name(&body.name);
    create_user.image = body.image.clone();
    create_user.additional_fields = additional_fields;
    create_user.email_verified = Some(false);
    super::authentication_helpers::apply_creation_input_defaults(ctx, &mut create_user);
    if phone_enabled {
        create_user.phone_number =
            super::phone_number::parse_signup_phone(ctx, body.phone_number.as_ref()).await?;
    }
    apply_default_role(ctx, &mut create_user);
    if config.enable_username {
        create_user.username = create_user
            .additional_fields
            .get("username")
            .and_then(better_auth_core::utils::json::JsValue::as_str)
            .map(str::to_owned);
        if create_user.username.is_none()
            && let Some(value) = &body.username
        {
            create_user.username = Some(config.username.normalize(value)?);
        }
        if config.username.include_display_username {
            create_user.display_username = create_user
                .additional_fields
                .get("displayUsername")
                .and_then(better_auth_core::utils::json::JsValue::as_str)
                .map(str::to_owned)
                .or_else(|| body.display_username.clone());
        }
    }
    let auto_sign_in = config.auto_sign_in && !config.require_email_verification;
    let expires_in = if body.remember_me == Some(false) {
        chrono::Duration::days(1)
    } else {
        ctx.config.session.expires_in
    };
    let ip_address = meta.ip_address.clone();
    let user_agent = meta.user_agent.clone();
    let database = Arc::clone(&ctx.database);
    let transaction_database = Arc::clone(&database);
    let require_email_verification = config.require_email_verification;
    let callback_url = body.callback_url.clone();
    let duplicate_body = body.clone();
    let duplicate_config = config.clone();
    let signup_context = AuthContext {
        config: Arc::clone(&ctx.config),
        database: Arc::clone(&ctx.database),
        email_provider: ctx.email_provider.clone(),
        metadata: ctx.metadata.clone(),
        extensions: ctx.extensions.clone(),
    };

    better_auth_core::store::transaction(database.as_ref(), move |tx| {
        let _database = Arc::clone(&transaction_database);
        Box::pin(async move {
            let user = match tx
                .create_user_with_source_record(
                    create_user,
                    better_auth_core::user_validation::UserValidationSource::creation(
                        "email-password",
                    ),
                )
                .await
            {
                Ok(user) => user,
                Err(AuthError::UserCreationCancelled) => {
                    return Err(AuthError::bad_request("Failed to create user"));
                }
                Err(error) if error.status_code() == 403 && !auto_sign_in => {
                    return signup::synthetic_response(
                        &duplicate_body,
                        &duplicate_config,
                        &signup_context,
                    );
                }
                Err(AuthError::Database(_) | AuthError::CallbackFailure(_)) => {
                    return Err(AuthError::UnprocessableEntity(
                        "Failed to create user".to_owned(),
                    ));
                }
                Err(error) => return Err(error),
            };

            drop(
                tx.create_account_record(CreateAccount {
                    additional_fields: Default::default(),
                    user_id: user.id().to_string(),
                    account_id: user.id().to_string(),
                    provider_id: "credential".to_owned(),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                    password: Some(password_hash.clone()),
                })
                .await?,
            );

            super::email_verification::send_signup_verification(
                &user,
                callback_url.as_deref(),
                require_email_verification,
                &signup_context,
                tx,
            )
            .await?;

            if auto_sign_in {
                let session = tx
                    .create_session_record(CreateSession {
                        additional_fields: FieldValues::default(),
                        token: None,
                        active_team_id: None,
                        user_id: user.id().to_string(),
                        expires_at: chrono::Utc::now() + expires_in,
                        ip_address,
                        user_agent,
                        impersonated_by: None,
                        active_organization_id: None,
                    })
                    .await?;
                let token = session.token().to_owned();
                better_auth_core::cache::runtime::emit_issuance(&signup_context, &user, &session)
                    .await?;
                super::helpers::record_completed_session_record::<S>(&user, &session);

                Ok((
                    SignUpResponse {
                        token: Some(token.clone()),
                        user: password_utils::serialize_to_value(&signup_context.user_view(&user))?,
                    },
                    Some(token),
                ))
            } else {
                Ok((
                    SignUpResponse {
                        token: None,
                        user: password_utils::serialize_to_value(&signup_context.user_view(&user))?,
                    },
                    None,
                ))
            }
        })
    })
    .await
}

async fn load_credential_password_hash(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<String> {
    super::helpers::get_credential_account(ctx, user.id())
        .await?
        .and_then(|account| account.password().map(str::to_owned))
        .ok_or(AuthError::InvalidCredentials)
}

async fn verify_user_password(
    user: &impl AuthUser,
    password: &str,
    config: &EmailPasswordConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    let stored_hash = load_credential_password_hash(user, ctx).await?;
    password_utils::verify_password(config.password_hasher.as_ref(), password, &stored_hash).await
}

/// Shared sign-in finalization logic after user lookup and credential verification.
async fn finalize_sign_in_with_user_core<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    user: better_auth_core::AdapterRecord<S::User>,
    remember_me: Option<bool>,
    _email_verification: Option<&EmailVerificationPlugin>,
    callback_url: Option<&str>,
    meta: &RequestMeta,
    ctx: &AuthContext<S>,
) -> AuthResult<SignInCoreResult<UserView>> {
    let mut set_cookie_headers = Vec::new();

    let mut issuing_config = (*ctx.config).clone();
    if remember_me == Some(false) {
        issuing_config.session.expires_in = chrono::Duration::days(1);
    }
    let issuing_context = AuthContext {
        config: Arc::new(issuing_config),
        database: Arc::clone(&ctx.database),
        email_provider: ctx.email_provider.clone(),
        metadata: ctx.metadata.clone(),
        extensions: ctx.extensions.clone(),
    };
    let issued = super::helpers::issue_selected_user_session_record(
        &issuing_context,
        user.clone(),
        meta.ip_address.clone(),
        meta.user_agent.clone(),
    )
    .await
    .map_err(SessionIssueError::into_auth_error)?;
    if two_factor::is_enabled(ctx) && user.two_factor_enabled() {
        let trusted_device = two_factor::inspect_trusted_device(req, &user, ctx).await?;
        if trusted_device.trusted {
            set_cookie_headers.extend(trusted_device.set_cookie_headers);
        } else {
            ctx.database.delete_session(issued.session.token()).await?;
            better_auth_core::cache::runtime::discard_issuance(req);
            let redirect = two_factor::begin_sign_in_challenge(&user, remember_me, ctx).await?;
            let mut redirect_headers = trusted_device.set_cookie_headers;
            redirect_headers.extend(redirect.set_cookie_headers);
            return Ok(SignInCoreResult::TwoFactorRedirect {
                response: redirect.response,
                set_cookie_headers: redirect_headers,
            });
        }
    }

    let session = issued.session;
    let token = session.token().to_owned();

    let response = SignInResponse {
        redirect: callback_url.is_some_and(|url| !url.is_empty()),
        token: token.clone(),
        url: callback_url.map(str::to_owned),
        user: ctx.user_view(&issued.user),
    };
    Ok(SignInCoreResult::Success {
        response,
        token,
        set_cookie_headers,
    })
}

/// Core sign-in by email.
async fn send_required_sign_in_verification(
    user: &impl AuthUser,
    callback_url: Option<&str>,
    email_verification: Option<&EmailVerificationPlugin>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<()> {
    if let Some(plugin) = email_verification {
        plugin
            .send_verification_on_sign_in(user, callback_url, ctx)
            .await?;
    } else if let Some(config) = ctx
        .extensions
        .get::<super::email_verification::EmailVerificationConfig>()
        && config.send_on_sign_in
    {
        EmailVerificationPlugin::with_config((*config).clone())
            .send_verification_on_sign_in(user, callback_url, ctx)
            .await?;
    }
    Ok(())
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn sign_in_core(
    req: &AuthRequest,
    body: &SignInRequest,
    config: &EmailPasswordConfig,
    email_verification: Option<&EmailVerificationPlugin>,
    meta: &RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SignInCoreResult<UserView>> {
    if !config.enabled {
        return Err(AuthError::Upstream {
            status: 400,
            code: "EMAIL_PASSWORD_DISABLED",
            message: "Email and password is not enabled",
        });
    }
    if !is_valid_email(&body.email) {
        return Err(AuthError::Upstream {
            status: 400,
            code: "INVALID_EMAIL",
            message: "Invalid email",
        });
    }
    if body.password.encode_utf16().count() > config.effective_max_length() {
        return Err(AuthError::bad_request("Password too long"));
    }
    let user = ctx
        .database
        .get_user_by_email_record(&body.email.to_lowercase())
        .await?;
    let Some(user) = user else {
        drop(
            ctx.hash_password(config.password_hasher.as_ref(), &body.password)
                .await?,
        );
        return Err(AuthError::InvalidCredentials);
    };
    let credential = ctx
        .database
        .get_user_accounts_record(&user.id())
        .await?
        .into_iter()
        .find(|account| {
            account.provider_id() == "credential" && account.account_id() == user.id().as_ref()
        });
    let Some(current_password) = credential
        .as_ref()
        .and_then(AuthAccount::password)
        .filter(|password| !password.is_empty())
    else {
        drop(
            ctx.hash_password(config.password_hasher.as_ref(), &body.password)
                .await?,
        );
        return Err(AuthError::InvalidCredentials);
    };
    password_utils::verify_password(
        config.password_hasher.as_ref(),
        &body.password,
        current_password,
    )
    .await?;

    if config.require_email_verification && !user.email_verified() {
        send_required_sign_in_verification(
            &user,
            body.callback_url.as_deref(),
            email_verification,
            ctx,
        )
        .await?;
        return Err(AuthError::Upstream {
            status: 403,
            code: "EMAIL_NOT_VERIFIED",
            message: "Email not verified",
        });
    }

    finalize_sign_in_with_user_core(
        req,
        user,
        body.remember_me,
        email_verification,
        body.callback_url.as_deref(),
        meta,
        ctx,
    )
    .await
}

/// Core sign-in by username.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn sign_in_username_core(
    req: &AuthRequest,
    body: &SignInUsernameRequest,
    normalized_username: &str,
    config: &EmailPasswordConfig,
    email_verification: Option<&EmailVerificationPlugin>,
    meta: &RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> Result<SignInCoreResult<UserView>, SignInUsernameFailure> {
    let Some(user) = ctx
        .database
        .get_user_by_username_record(normalized_username)
        .await
        .map_err(SignInUsernameFailure::Auth)?
    else {
        drop(
            ctx.hash_password(config.password_hasher.as_ref(), &body.password)
                .await
                .map_err(SignInUsernameFailure::Auth)?,
        );
        return Err(SignInUsernameFailure::InvalidUsernameOrPassword);
    };

    verify_user_password(&user, &body.password, config, ctx)
        .await
        .map_err(|error| match error {
            AuthError::InvalidCredentials => SignInUsernameFailure::InvalidUsernameOrPassword,
            other @ (AuthError::Api { .. }
            | AuthError::Upstream { .. }
            | AuthError::BadRequest(_)
            | AuthError::InvalidRequest(_)
            | AuthError::Validation(_)
            | AuthError::Unauthenticated
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
            | AuthError::RateLimited
            | AuthError::NotImplemented(_)
            | AuthError::Config(_)
            | AuthError::Database(_)
            | AuthError::Serialization(_)
            | AuthError::Plugin { .. }
            | AuthError::CallbackFailure(_)
            | AuthError::Internal(_)
            | AuthError::PasswordHash(_)
            | AuthError::Jwt(_)) => SignInUsernameFailure::Auth(other),
        })?;

    if !user.email_verified()
        && (config.require_email_verification
            || email_verification.is_some_and(EmailVerificationPlugin::is_verification_required))
    {
        send_required_sign_in_verification(
            &user,
            body.callback_url.as_deref(),
            email_verification,
            ctx,
        )
        .await
        .map_err(SignInUsernameFailure::Auth)?;
        return Err(SignInUsernameFailure::EmailNotVerified);
    }

    finalize_sign_in_with_user_core(
        req,
        user,
        body.remember_me,
        email_verification,
        body.callback_url.as_deref(),
        meta,
        ctx,
    )
    .await
    .map_err(SignInUsernameFailure::Auth)
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::AuthContext;
    use better_auth_core::config::AuthConfig;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type TestSchema =
        better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

    async fn create_test_context() -> AuthContext<TestSchema> {
        let config = AuthConfig::new("test-secret-key-at-least-32-chars-long");
        let config = Arc::new(config);
        let database = crate::plugins::test_helpers::create_test_database().await;
        AuthContext::new(config, database)
    }

    fn create_signup_request(email: &str, password: &str) -> AuthRequest {
        let body = serde_json::json!({
            "name": "Test User",
            "email": email,
            "password": password,
        });
        AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-up/email".to_owned(),
            HashMap::new(),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        )
    }

    // Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
    #[tokio::test]
    async fn test_auto_sign_in_false_returns_no_session() {
        let plugin = EmailPasswordPlugin::new().auto_sign_in(false);
        let ctx = create_test_context().await;

        let req = create_signup_request("auto@example.com", "Password123!");
        let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Response should NOT have a Set-Cookie header
        let has_cookie = response
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"));
        assert!(!has_cookie, "auto_sign_in=false should not set a cookie");

        // Response body token should be null
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            (*(body).get("token").unwrap_or(&serde_json::Value::Null)).is_null(),
            "auto_sign_in=false should return null token"
        );
        // But the user should still be created
        assert!(
            (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
                .get("id")
                .unwrap_or(&serde_json::Value::Null))
            .is_string()
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
    #[tokio::test]
    async fn test_auto_sign_in_true_returns_session() {
        let plugin = EmailPasswordPlugin::new(); // default auto_sign_in=true
        let ctx = create_test_context().await;

        let req = create_signup_request("autotrue@example.com", "Password123!");
        let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Response SHOULD have a Set-Cookie header
        let has_cookie = response
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"));
        assert!(has_cookie, "auto_sign_in=true should set a cookie");

        // Response body token should be a string
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            (*(body).get("token").unwrap_or(&serde_json::Value::Null)).is_string(),
            "auto_sign_in=true should return a session token"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
    #[tokio::test]
    async fn test_password_max_length_rejection() {
        let plugin = EmailPasswordPlugin::new().password_max_length(128);
        let ctx = create_test_context().await;

        // Password of exactly 129 chars should be rejected
        let long_password = format!("A1!{}", "a".repeat(126)); // 129 chars total
        let req = create_signup_request("long@example.com", &long_password);
        let err = plugin.handle_sign_up(&req, &ctx).await.unwrap_err();
        assert_eq!(err.status_code(), 400);

        // Password of exactly 128 chars should be accepted
        let ok_password = format!("A1!{}", "a".repeat(125)); // 128 chars total
        let req_2 = create_signup_request("ok@example.com", &ok_password);
        let response = plugin.handle_sign_up(&req_2, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
    }

    // Upstream reference: packages/better-auth/src/api/routes/sign-up.test.ts :: describe("sign-up with custom fields") and packages/better-auth/src/api/routes/sign-in.test.ts :: describe("sign-in"); adapted to the Rust email-password plugin behavior.
    #[tokio::test]
    async fn test_custom_password_hasher() {
        /// A simple test hasher that prefixes the password with "hashed:"
        struct TestHasher;

        #[async_trait]
        impl PasswordHasher for TestHasher {
            async fn hash(&self, password: &str) -> AuthResult<String> {
                Ok(format!("hashed:{password}"))
            }
            async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
                Ok(hash == format!("hashed:{password}"))
            }
        }

        let hasher: Arc<dyn PasswordHasher> = Arc::new(TestHasher);
        let plugin = EmailPasswordPlugin::new().password_hasher(hasher);
        let ctx = create_test_context().await;

        // Sign up with custom hasher
        let req = create_signup_request("hasher@example.com", "Password123!");
        let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Verify the stored hash uses our custom hasher
        let user = ctx
            .database
            .get_user_by_email("hasher@example.com")
            .await
            .unwrap()
            .unwrap();
        let stored_hash = ctx
            .database
            .get_user_accounts(&user.id())
            .await
            .unwrap()
            .into_iter()
            .find(|account| account.provider_id() == "credential")
            .and_then(|account| account.password().map(str::to_owned))
            .expect("credential account should store hashed password");
        assert_eq!(stored_hash, "hashed:Password123!");

        // Sign in should work with the custom hasher
        let signin_body = serde_json::json!({
            "email": "hasher@example.com",
            "password": "Password123!",
        });
        let signin_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-in/email".to_owned(),
            HashMap::new(),
            Some(signin_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response_2 = plugin.handle_sign_in(&signin_req, &ctx).await.unwrap();
        assert_eq!(response_2.status, 200);

        // Sign in with wrong password should fail
        let bad_body = serde_json::json!({
            "email": "hasher@example.com",
            "password": "WrongPassword!",
        });
        let bad_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-in/email".to_owned(),
            HashMap::new(),
            Some(bad_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let err = plugin.handle_sign_in(&bad_req, &ctx).await.unwrap_err();
        assert_eq!(err.to_string(), AuthError::InvalidCredentials.to_string());
    }

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts :: sign-in path verifies the password once before creating a session; adapted to ensure the Rust username path does not duplicate expensive password verification.
    #[tokio::test]
    async fn test_sign_in_username_verifies_password_once() {
        struct CountingHasher {
            verify_calls: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl PasswordHasher for CountingHasher {
            async fn hash(&self, password: &str) -> AuthResult<String> {
                Ok(format!("hashed:{password}"))
            }

            async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
                self.verify_calls.fetch_add(1, Ordering::SeqCst);
                Ok(hash == format!("hashed:{password}"))
            }
        }

        let verify_calls = Arc::new(AtomicUsize::new(0));
        let hasher: Arc<dyn PasswordHasher> = Arc::new(CountingHasher {
            verify_calls: std::sync::Arc::clone(&verify_calls),
        });
        let plugin = EmailPasswordPlugin::new().password_hasher(hasher);
        let ctx = create_test_context().await;

        let signup_body = serde_json::json!({
            "email": "username-counter@example.com",
            "password": "Password123!",
            "name": "Counter User",
            "username": "Counter_User",
        });
        let signup_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-up/email".to_owned(),
            HashMap::new(),
            Some(signup_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let signup_response = plugin.handle_sign_up(&signup_req, &ctx).await.unwrap();
        assert_eq!(signup_response.status, 200);

        verify_calls.store(0, Ordering::SeqCst);

        let signin_body = serde_json::json!({
            "username": "COUNTER_USER",
            "password": "Password123!",
        });
        let signin_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-in/username".to_owned(),
            HashMap::new(),
            Some(signin_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let signin_response = plugin
            .handle_sign_in_username(&signin_req, &ctx)
            .await
            .unwrap();
        assert_eq!(signin_response.status, 200);
        assert_eq!(verify_calls.load(Ordering::SeqCst), 1);
    }

    // Rust-specific surface: route-table registration for the endpoint declared in
    // packages/better-auth/src/plugins/username/index.ts :: isUsernameAvailable.
    #[tokio::test]
    async fn test_is_username_available_route_registered() {
        let plugin = EmailPasswordPlugin::new();
        let routes = <EmailPasswordPlugin as AuthPlugin<TestSchema>>::routes(&plugin);
        assert!(
            routes.iter().any(|r| r.path == "/is-username-available"),
            "route /is-username-available should be registered"
        );
    }

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
    // isUsernameAvailable returns `{ available: true }` when no user holds the
    // normalized username; adapted to the Rust email-password plugin.
    #[tokio::test]
    async fn test_is_username_available_fresh() {
        let plugin = EmailPasswordPlugin::new();
        let ctx = create_test_context().await;

        let body = serde_json::json!({ "username": "fresh_user" });
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/is-username-available".to_owned(),
            HashMap::new(),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin
            .handle_is_username_available(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(json).get("available").unwrap_or(&serde_json::Value::Null)),
            true
        );
    }

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
    // isUsernameAvailable returns `{ available: false }` when the adapter finds a
    // user on the normalized username; adapted to the Rust email-password plugin.
    #[tokio::test]
    async fn test_is_username_available_taken() {
        let plugin = EmailPasswordPlugin::new();
        let ctx = create_test_context().await;

        // Sign up a user with a username
        let signup_body = serde_json::json!({
            "name": "Taken User",
            "email": "taken@example.com",
            "password": "Password123!",
            "username": "taken_user",
        });
        let signup_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-up/email".to_owned(),
            HashMap::new(),
            Some(signup_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let resp = plugin.handle_sign_up(&signup_req, &ctx).await.unwrap();
        assert_eq!(resp.status, 200);

        let body = serde_json::json!({ "username": "taken_user" });
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/is-username-available".to_owned(),
            HashMap::new(),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin
            .handle_is_username_available(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(json).get("available").unwrap_or(&serde_json::Value::Null)),
            false
        );
    }

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
    // isUsernameAvailable throws UNPROCESSABLE_ENTITY with code USERNAME_TOO_SHORT
    // below `minUsernameLength` (default 3); adapted to the Rust email-password plugin.
    #[tokio::test]
    async fn test_is_username_available_too_short() {
        let plugin = EmailPasswordPlugin::new();
        let ctx = create_test_context().await;

        let body = serde_json::json!({ "username": "ab" });
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/is-username-available".to_owned(),
            HashMap::new(),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin
            .handle_is_username_available(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 422);
        let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(json).get("code").unwrap_or(&serde_json::Value::Null)),
            "USERNAME_TOO_SHORT"
        );
    }

    // Upstream reference: packages/better-auth/src/plugins/username/index.ts ::
    // isUsernameAvailable rejects usernames that fail `defaultUsernameValidator`
    // with UNPROCESSABLE_ENTITY; adapted to the Rust email-password plugin.
    #[tokio::test]
    async fn test_is_username_available_invalid_chars() {
        let plugin = EmailPasswordPlugin::new();
        let ctx = create_test_context().await;

        let body = serde_json::json!({ "username": "bad user!" });
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/is-username-available".to_owned(),
            HashMap::new(),
            Some(body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin
            .handle_is_username_available(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 422);
        let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(json).get("code").unwrap_or(&serde_json::Value::Null)),
            "INVALID_USERNAME"
        );
    }
}
// LCOV_EXCL_STOP
