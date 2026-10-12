use super::two_factor;
use crate::authentication_helpers::{JsonField, JsonFieldKind, RequestBody};
use alibi_core::AuthError;
use serde::{Deserialize, Serialize};
use validator::Validate;
/// Input for the public `signUpEmail` server operation.
#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
pub struct SignUpRequest {
    #[serde(flatten, default)]
    pub additional_fields: indexmap::IndexMap<String, alibi_core::utils::json::JsValue>,
    #[serde(rename = "lastLoginMethod", skip_serializing_if = "Option::is_none")]
    pub last_login_method: Option<alibi_core::utils::json::JsValue>,
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "displayUsername", skip_serializing_if = "Option::is_none")]
    pub display_username: Option<String>,
    #[serde(rename = "callbackURL", skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(rename = "rememberMe", skip_serializing_if = "Option::is_none")]
    pub remember_me: Option<bool>,
    #[serde(rename = "phoneNumber", skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<alibi_core::utils::json::JsValue>,
    #[serde(
        rename = "phoneNumberVerified",
        skip_serializing_if = "Option::is_none"
    )]
    pub phone_number_verified: Option<alibi_core::utils::json::JsValue>,
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

/// Input for the public `signInEmail` server operation.
#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
pub struct SignInRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
    #[serde(rename = "callbackURL", skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    #[serde(rename = "rememberMe", skip_serializing_if = "Option::is_none")]
    pub remember_me: Option<bool>,
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
    pub(in crate::email_password) username: String,
    pub(in crate::email_password) password: String,
    #[serde(rename = "rememberMe")]
    pub(in crate::email_password) remember_me: Option<bool>,
    #[serde(rename = "callbackURL")]
    pub(in crate::email_password) callback_url: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub(in crate::email_password) struct IsUsernameAvailableRequest {
    pub(in crate::email_password) username: String,
}

/// Guest-readable username availability without issuing authentication authority.
#[derive(Debug, Serialize, Deserialize)]
pub struct IsUsernameAvailableResponse {
    pub available: bool,
}

/// Created or synthetic public user returned by `signUpEmail`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignUpResponse<U> {
    pub token: Option<String>,
    pub user: U,
}

/// A completed credential session returned by `signInEmail`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignInResponse<U> {
    pub redirect: bool,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub user: U,
}

#[derive(Debug, Serialize)]
pub(crate) struct SignInUsernameResponse<U> {
    /// Upstream returns the same redirect envelope as `/sign-in/email`.
    pub(in crate::email_password) redirect: bool,
    pub(in crate::email_password) token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::email_password) url: Option<String>,
    pub(in crate::email_password) user: U,
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

pub(crate) enum SignInUsernameFailure {
    InvalidUsernameOrPassword,
    EmailNotVerified,
    Auth(AuthError),
}

/// Credential sign-in may complete or require a second factor.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum SignInEmailResponse {
    Session(Box<SignInResponse<alibi_core::UserView>>),
    TwoFactor {
        #[serde(rename = "twoFactorRedirect")]
        two_factor_redirect: bool,
        #[serde(rename = "twoFactorMethods")]
        two_factor_methods: Vec<String>,
    },
}

impl SignUpRequest {
    /// Construct core sign-up input; application/plugin fields remain available.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        email: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            email: email.into(),
            password: password.into(),
            additional_fields: indexmap::IndexMap::default(),
            last_login_method: None,
            username: None,
            display_username: None,
            callback_url: None,
            image: None,
            remember_me: None,
            phone_number: None,
            phone_number_verified: None,
        }
    }
}
