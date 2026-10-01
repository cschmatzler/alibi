use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use validator::Validate;

use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{
    AuthRequest, AuthResponse, CreateAccount, CreateSession, CreateUser, ErrorCodeMessageResponse,
    HttpMethod, RequestMeta,
};

use super::{email_verification::EmailVerificationPlugin, two_factor};
use better_auth_core::utils::cookie_utils::{
    create_session_cookie, create_session_cookie_with_max_age, create_session_like_cookie,
    related_cookie_name, sign_cookie_value,
};
use better_auth_core::utils::password::{self as password_utils, PasswordHasher};
use better_auth_core::utils::username::{
    UsernameValidationError, normalize_username, normalize_username_fields, validate_username,
};
use better_auth_core::wire::UserView;

use crate::plugins::authentication_helpers::{
    JsonField, JsonFieldKind, RequestBody, is_valid_email, parse_body,
};
use crate::plugins::helpers::{SessionIssueError, apply_default_role, issue_user_session};

const MESSAGE_INVALID_USERNAME_OR_PASSWORD: &str = "Invalid username or password";
const MESSAGE_EMAIL_NOT_VERIFIED: &str = "Email not verified";
const MESSAGE_USERNAME_TOO_SHORT: &str = "Username is too short";
const MESSAGE_USERNAME_TOO_LONG: &str = "Username is too long";
const MESSAGE_INVALID_USERNAME: &str = "Username is invalid";
const MESSAGE_USERNAME_IS_ALREADY_TAKEN: &str = "Username is already taken. Please try another.";

fn username_error_response(status: u16, code: &str, message: &str) -> AuthResult<AuthResponse> {
    AuthResponse::json(
        status,
        &ErrorCodeMessageResponse {
            code: Some(code.to_string()),
            message: message.to_string(),
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
                &sign_cookie_value("true", &config.secret),
                None,
                config,
            ),
        )
    } else {
        response
    }
}
/// Email and password authentication plugin
pub struct EmailPasswordPlugin {
    config: EmailPasswordConfig,
    /// Optional reference to the email-verification plugin so that
    /// `send_on_sign_in` can be triggered during the sign-in flow.
    email_verification: Option<Arc<EmailVerificationPlugin>>,
}

#[derive(Clone)]
pub struct EmailPasswordConfig {
    pub enable_signup: bool,
    /// Whether to enable the username schema, signup hooks, and endpoints.
    pub enable_username: bool,
    pub require_email_verification: bool,
    pub password_min_length: usize,
    /// Maximum password length (default: 128).
    pub password_max_length: usize,
    /// Whether to automatically sign in the user after sign-up (default: true).
    /// When false, sign-up returns the user but doesn't create a session.
    pub auto_sign_in: bool,
    /// Custom password hasher. When `None`, the default scrypt hasher is used.
    pub password_hasher: Option<Arc<dyn PasswordHasher>>,
}

impl std::fmt::Debug for EmailPasswordConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailPasswordConfig")
            .field("enable_signup", &self.enable_signup)
            .field("enable_username", &self.enable_username)
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
            .finish()
    }
}

#[derive(Debug, Deserialize, Validate)]
pub(crate) struct SignUpRequest {
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
pub(crate) struct SignInRequest {
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
pub(crate) struct SignInUsernameRequest {
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
pub(crate) struct SignUpResponse<U: Serialize> {
    token: Option<String>,
    user: U,
}

#[derive(Debug, Serialize)]
pub(crate) struct SignInResponse<U: Serialize> {
    redirect: bool,
    token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    user: U,
}

#[derive(Debug, Serialize)]
pub(crate) struct SignInUsernameResponse<U: Serialize> {
    /// Upstream returns the same redirect envelope as `/sign-in/email`.
    redirect: bool,
    token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    user: U,
}

/// Result of sign-in: either a successful session or a 2FA redirect.
pub(crate) enum SignInCoreResult<U: Serialize> {
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
    pub fn new() -> Self {
        Self {
            config: EmailPasswordConfig::default(),
            email_verification: None,
        }
    }

    pub fn with_config(config: EmailPasswordConfig) -> Self {
        Self {
            config,
            email_verification: None,
        }
    }

    /// Attach an [`EmailVerificationPlugin`] so that `send_on_sign_in` is
    /// automatically called when a user signs in with an unverified email.
    pub fn with_email_verification(mut self, plugin: Arc<EmailVerificationPlugin>) -> Self {
        self.email_verification = Some(plugin);
        self
    }

    pub fn enable_signup(mut self, enable: bool) -> Self {
        self.config.enable_signup = enable;
        self
    }

    pub fn enable_username(mut self, enable: bool) -> Self {
        self.config.enable_username = enable;
        self
    }

    pub fn require_email_verification(mut self, require: bool) -> Self {
        self.config.require_email_verification = require;
        self
    }

    pub fn password_min_length(mut self, length: usize) -> Self {
        self.config.password_min_length = length;
        self
    }

    pub fn password_max_length(mut self, length: usize) -> Self {
        self.config.password_max_length = length;
        self
    }

    pub fn auto_sign_in(mut self, auto: bool) -> Self {
        self.config.auto_sign_in = auto;
        self
    }

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

        signup_req.email = signup_req.email.to_lowercase();

        let (username, display_username) = normalize_username_fields(
            signup_req.username.take(),
            signup_req.display_username.take(),
        );
        signup_req.username = username;
        signup_req.display_username = display_username;

        if let Some(username) = signup_req.username.as_deref() {
            match validate_username(username) {
                Ok(()) => {}
                Err(UsernameValidationError::TooShort) => {
                    return username_error_response(
                        400,
                        "USERNAME_TOO_SHORT",
                        MESSAGE_USERNAME_TOO_SHORT,
                    );
                }
                Err(UsernameValidationError::TooLong) => {
                    return username_error_response(
                        400,
                        "USERNAME_TOO_LONG",
                        MESSAGE_USERNAME_TOO_LONG,
                    );
                }
                Err(UsernameValidationError::Invalid) => {
                    return username_error_response(
                        400,
                        "INVALID_USERNAME",
                        MESSAGE_INVALID_USERNAME,
                    );
                }
            }

            // Upstream's username hook rejects a taken username before the user
            // is created, so the client sees USERNAME_IS_ALREADY_TAKEN rather
            // than a failed insert.
            if ctx.database.get_user_by_username(username).await?.is_some() {
                return username_error_response(
                    400,
                    "USERNAME_IS_ALREADY_TAKEN",
                    MESSAGE_USERNAME_IS_ALREADY_TAKEN,
                );
            }
        }

        let meta = RequestMeta::from_request(req);
        let (response, session_token) = sign_up_core(&signup_req, &self.config, &meta, ctx).await?;

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

        if !is_valid_email(&signin_req.email) {
            return Err(AuthError::Upstream {
                status: 400,
                code: "INVALID_EMAIL",
                message: "Invalid email",
            });
        }
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

        let username = normalize_username(&signin_req.username);

        match validate_username(&username) {
            Ok(()) => {}
            Err(UsernameValidationError::TooShort) => {
                return username_error_response(
                    422,
                    "USERNAME_TOO_SHORT",
                    MESSAGE_USERNAME_TOO_SHORT,
                );
            }
            Err(UsernameValidationError::TooLong) => {
                return username_error_response(
                    422,
                    "USERNAME_TOO_LONG",
                    MESSAGE_USERNAME_TOO_LONG,
                );
            }
            Err(UsernameValidationError::Invalid) => {
                return username_error_response(422, "INVALID_USERNAME", MESSAGE_INVALID_USERNAME);
            }
        }

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
            return username_error_response(422, "INVALID_USERNAME", MESSAGE_INVALID_USERNAME);
        }

        match validate_username(&body.username) {
            Ok(()) => {}
            Err(UsernameValidationError::TooShort) => {
                return username_error_response(
                    422,
                    "USERNAME_TOO_SHORT",
                    MESSAGE_USERNAME_TOO_SHORT,
                );
            }
            Err(UsernameValidationError::TooLong) => {
                return username_error_response(
                    422,
                    "USERNAME_TOO_LONG",
                    MESSAGE_USERNAME_TOO_LONG,
                );
            }
            Err(UsernameValidationError::Invalid) => {
                return username_error_response(422, "INVALID_USERNAME", MESSAGE_INVALID_USERNAME);
            }
        }

        let normalized = normalize_username(&body.username);
        let user = ctx.database.get_user_by_username(&normalized).await?;
        let available = user.is_none();

        Ok(AuthResponse::json(
            200,
            &IsUsernameAvailableResponse { available },
        )?)
    }
}

// ---------------------------------------------------------------------------
// Core functions — framework-agnostic business logic
// ---------------------------------------------------------------------------

/// Core sign-up logic.
///
/// Returns `(response, Option<session_token>)`. The session token is present
/// only when `auto_sign_in` is true.
pub(crate) async fn sign_up_core<S: better_auth_core::AuthSchema>(
    body: &SignUpRequest,
    config: &EmailPasswordConfig,
    meta: &RequestMeta,
    ctx: &AuthContext<S>,
) -> AuthResult<(SignUpResponse<UserView>, Option<String>)> {
    if !config.enable_signup {
        return Err(AuthError::forbidden("User registration is not enabled"));
    }

    password_utils::validate_password(
        &body.password,
        config.password_min_length,
        config.password_max_length,
        ctx,
    )?;

    let phone_enabled = ctx
        .get_metadata("phone-number.enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if phone_enabled {
        super::phone_number::reject_verified_input(body.phone_number_verified.as_ref())?;
    }

    // Check if user already exists
    if ctx.database.get_user_by_email(&body.email).await?.is_some() {
        // TS returns 422 UNPROCESSABLE_ENTITY for duplicate email
        return Err(AuthError::UnprocessableEntity(
            "User already exists. Use another email.".to_string(),
        ));
    }

    // Hash password
    let password_hash =
        password_utils::hash_password(config.password_hasher.as_ref(), &body.password).await?;

    let mut create_user = CreateUser::new()
        .with_email(&body.email)
        .with_name(&body.name);
    create_user.image = body.image.clone();
    if phone_enabled {
        create_user.phone_number =
            super::phone_number::parse_signup_phone(ctx, body.phone_number.as_ref()).await?;
    }
    apply_default_role(ctx, &mut create_user);
    if config.enable_username {
        if let Some(ref username) = body.username {
            create_user = create_user.with_username(normalize_username(username));
        }
        if let Some(ref display_username) = body.display_username {
            create_user.display_username = Some(display_username.clone());
        } else if let Some(ref username) = body.username {
            create_user.display_username = Some(username.clone());
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
    let database = ctx.database.clone();
    let transaction_database = database.clone();
    let require_email_verification = config.require_email_verification;
    let callback_url = body.callback_url.clone();
    let signup_context = AuthContext {
        config: ctx.config.clone(),
        database: ctx.database.clone(),
        email_provider: ctx.email_provider.clone(),
        metadata: ctx.metadata.clone(),
        extensions: ctx.extensions.clone(),
    };

    better_auth_core::store::transaction(database.as_ref(), move |tx| {
        let _database = transaction_database.clone();
        Box::pin(async move {
            let user = match tx.create_user(create_user).await {
                Ok(user) => user,
                Err(AuthError::Database(_)) => {
                    return Err(AuthError::UnprocessableEntity(
                        "Failed to create user".to_string(),
                    ));
                }
                Err(error) => return Err(error),
            };

            let _ = tx
                .create_account(CreateAccount {
                    user_id: user.id().to_string(),
                    account_id: user.id().to_string(),
                    provider_id: "credential".to_string(),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                    password: Some(password_hash.clone()),
                })
                .await?;

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
                    .create_session(CreateSession {
                        additional_fields: Default::default(),
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
                let token = session.token().to_string();
                super::helpers::record_completed_session::<S>(&user, &session);

                Ok((
                    SignUpResponse {
                        token: Some(token.clone()),
                        user: signup_context.user_view(&user),
                    },
                    Some(token),
                ))
            } else {
                Ok((
                    SignUpResponse {
                        token: None,
                        user: signup_context.user_view(&user),
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
    ctx.database
        .get_user_accounts(&user.id())
        .await?
        .into_iter()
        .find(|account| account.provider_id() == "credential" && account.password().is_some())
        .and_then(|account| account.password().map(str::to_string))
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
async fn finalize_sign_in_with_user_core(
    req: &AuthRequest,
    user: impl AuthUser,
    remember_me: Option<bool>,
    email_verification: Option<&EmailVerificationPlugin>,
    callback_url: Option<&str>,
    meta: &RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SignInCoreResult<UserView>> {
    let mut set_cookie_headers = Vec::new();
    if two_factor::is_enabled(ctx) && user.two_factor_enabled() {
        let trusted_device = two_factor::inspect_trusted_device(req, &user, ctx).await?;
        if trusted_device.trusted {
            set_cookie_headers.extend(trusted_device.set_cookie_headers);
        } else {
            let redirect = two_factor::begin_sign_in_challenge(&user, remember_me, ctx).await?;
            let mut redirect_headers = trusted_device.set_cookie_headers;
            redirect_headers.extend(redirect.set_cookie_headers);
            return Ok(SignInCoreResult::TwoFactorRedirect {
                response: redirect.response,
                set_cookie_headers: redirect_headers,
            });
        }
    }

    let _ = email_verification;

    let mut issuing_config = (*ctx.config).clone();
    if remember_me == Some(false) {
        issuing_config.session.expires_in = chrono::Duration::days(1);
    }
    let issuing_context = AuthContext {
        config: Arc::new(issuing_config),
        database: ctx.database.clone(),
        email_provider: ctx.email_provider.clone(),
        metadata: ctx.metadata.clone(),
        extensions: ctx.extensions.clone(),
    };
    let issued = issue_user_session(
        &issuing_context,
        &user.id(),
        meta.ip_address.clone(),
        meta.user_agent.clone(),
    )
    .await
    .map_err(SessionIssueError::into_auth_error)?;
    let session = issued.session;
    let token = session.token().to_string();

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

pub(crate) async fn sign_in_core(
    req: &AuthRequest,
    body: &SignInRequest,
    config: &EmailPasswordConfig,
    email_verification: Option<&EmailVerificationPlugin>,
    meta: &RequestMeta,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SignInCoreResult<UserView>> {
    let user = ctx
        .database
        .get_user_by_email(&body.email.to_lowercase())
        .await?
        .ok_or(AuthError::InvalidCredentials)?;

    verify_user_password(&user, &body.password, config, ctx).await?;

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
pub(crate) async fn sign_in_username_core(
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
        .get_user_by_username(normalized_username)
        .await
        .map_err(SignInUsernameFailure::Auth)?
    else {
        let _ = password_utils::hash_password(config.password_hasher.as_ref(), &body.password)
            .await
            .map_err(SignInUsernameFailure::Auth)?;
        return Err(SignInUsernameFailure::InvalidUsernameOrPassword);
    };

    verify_user_password(&user, &body.password, config, ctx)
        .await
        .map_err(|error| match error {
            AuthError::InvalidCredentials => SignInUsernameFailure::InvalidUsernameOrPassword,
            other => SignInUsernameFailure::Auth(other),
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

pub(crate) enum SignInUsernameFailure {
    InvalidUsernameOrPassword,
    EmailNotVerified,
    Auth(AuthError),
}

impl Default for EmailPasswordConfig {
    fn default() -> Self {
        Self {
            enable_signup: true,
            enable_username: true,
            require_email_verification: false,
            password_min_length: 8,
            password_max_length: 128,
            auto_sign_in: true,
            password_hasher: None,
        }
    }
}

#[async_trait]
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for EmailPasswordPlugin {
    fn name(&self) -> &'static str {
        "email-password"
    }

    async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
        ctx.extensions.insert(self.config.clone());
        if self.config.enable_username {
            _ = ctx
                .metadata
                .insert("username.enabled".into(), serde_json::Value::Bool(true));
        }
        Ok(())
    }

    fn routes(&self) -> Vec<AuthRoute> {
        let mut routes = vec![AuthRoute::post("/sign-in/email", "sign_in_email")];
        if self.config.enable_username {
            routes.extend([
                AuthRoute::post("/sign-in/username", "sign_in_username"),
                AuthRoute::post("/is-username-available", "is_username_available"),
            ]);
        }

        if self.config.enable_signup {
            routes.push(AuthRoute::post("/sign-up/email", "sign_up_email"));
        }

        routes
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/sign-up/email") if self.config.enable_signup => {
                Ok(Some(self.handle_sign_up(req, ctx).await?))
            }
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
            println!("Email verification required for user: {}", email);
        }
        Ok(())
    }
}

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
            "/sign-up/email".to_string(),
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
            body["token"].is_null(),
            "auto_sign_in=false should return null token"
        );
        // But the user should still be created
        assert!(body["user"]["id"].is_string());
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
            body["token"].is_string(),
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
        let req = create_signup_request("ok@example.com", &ok_password);
        let response = plugin.handle_sign_up(&req, &ctx).await.unwrap();
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
                Ok(format!("hashed:{}", password))
            }
            async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
                Ok(hash == format!("hashed:{}", password))
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
            .and_then(|account| account.password().map(str::to_string))
            .expect("credential account should store hashed password");
        assert_eq!(stored_hash, "hashed:Password123!");

        // Sign in should work with the custom hasher
        let signin_body = serde_json::json!({
            "email": "hasher@example.com",
            "password": "Password123!",
        });
        let signin_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-in/email".to_string(),
            HashMap::new(),
            Some(signin_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let response = plugin.handle_sign_in(&signin_req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        // Sign in with wrong password should fail
        let bad_body = serde_json::json!({
            "email": "hasher@example.com",
            "password": "WrongPassword!",
        });
        let bad_req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-in/email".to_string(),
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
            verify_calls: verify_calls.clone(),
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
            "/sign-up/email".to_string(),
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
            "/sign-in/username".to_string(),
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
        let routes =
            <EmailPasswordPlugin as better_auth_core::AuthPlugin<TestSchema>>::routes(&plugin);
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
            "/is-username-available".to_string(),
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
        assert_eq!(json["available"], true);
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
            "/sign-up/email".to_string(),
            HashMap::new(),
            Some(signup_body.to_string().into_bytes()),
            HashMap::new(),
        );
        let resp = plugin.handle_sign_up(&signup_req, &ctx).await.unwrap();
        assert_eq!(resp.status, 200);

        let body = serde_json::json!({ "username": "taken_user" });
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/is-username-available".to_string(),
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
        assert_eq!(json["available"], false);
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
            "/is-username-available".to_string(),
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
        assert_eq!(json["code"], "USERNAME_TOO_SHORT");
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
            "/is-username-available".to_string(),
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
        assert_eq!(json["code"], "INVALID_USERNAME");
    }
}
