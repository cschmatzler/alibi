use alibi_core::wire::UserView;
use serde::{Deserialize, Serialize};
use validator::Validate;

/// Public input to the `signInSocial` server operation.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SocialSignInRequest {
    #[validate(length(min = 1, message = "Provider is required"))]
    pub provider: String,
    #[serde(rename = "callbackURL", skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL", skip_serializing_if = "Option::is_none")]
    pub new_user_callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL", skip_serializing_if = "Option::is_none")]
    pub error_callback_url: Option<String>,
    #[serde(rename = "disableRedirect", skip_serializing_if = "Option::is_none")]
    pub disable_redirect: Option<bool>,
    #[serde(rename = "idToken", skip_serializing_if = "Option::is_none")]
    pub id_token: Option<OAuthIdTokenRequest>,
    #[serde(rename = "requestSignUp", skip_serializing_if = "Option::is_none")]
    pub request_sign_up: Option<bool>,
    #[serde(rename = "loginHint", skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
    #[serde(
        rename = "authorizationParams",
        skip_serializing_if = "Option::is_none"
    )]
    pub authorization_params: Option<std::collections::BTreeMap<String, String>>,
    #[serde(rename = "additionalParams", skip_serializing_if = "Option::is_none")]
    pub additional_params: Option<std::collections::BTreeMap<String, String>>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "alibi_core::utils::json::deserialize_optional_map"
    )]
    pub additional_data: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

/// Public input to the `linkSocialAccount` server operation.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct LinkSocialRequest {
    #[validate(length(min = 1, message = "Provider is required"))]
    pub provider: String,
    #[serde(rename = "callbackURL", skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL", skip_serializing_if = "Option::is_none")]
    pub error_callback_url: Option<String>,
    #[serde(rename = "disableRedirect", skip_serializing_if = "Option::is_none")]
    pub disable_redirect: Option<bool>,
    #[serde(rename = "idToken", skip_serializing_if = "Option::is_none")]
    pub id_token: Option<OAuthIdTokenRequest>,
    #[serde(rename = "requestSignUp", skip_serializing_if = "Option::is_none")]
    pub request_sign_up: Option<bool>,
    #[serde(
        rename = "authorizationParams",
        skip_serializing_if = "Option::is_none"
    )]
    pub authorization_params: Option<std::collections::BTreeMap<String, String>>,
    #[serde(rename = "additionalParams", skip_serializing_if = "Option::is_none")]
    pub additional_params: Option<std::collections::BTreeMap<String, String>>,
    #[serde(rename = "additionalData", skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "alibi_core::utils::json::deserialize_optional_map"
    )]
    pub additional_data: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(rename = "loginHint", skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
}

/// ID-token credentials accepted by logical social sign-in.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct OAuthIdTokenRequest {
    #[validate(length(min = 1, message = "Token is required"))]
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<super::providers::OAuthCallbackUserPayload>,
    #[serde(rename = "accessToken", skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken", skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

/// Provider authorization URL or authenticated user returned by social sign-in.
#[derive(Debug, Serialize, Deserialize)]
pub struct SocialSignInResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub redirect: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserView>,
}

/// Public result of the `getAccessToken` server operation.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenResponse {
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(
        rename = "accessTokenExpiresAt",
        skip_serializing_if = "Option::is_none"
    )]
    pub access_token_expires_at: Option<String>,
    pub scopes: Vec<String>,
    #[serde(rename = "idToken", skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct RefreshTokenResponse {
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "accessTokenExpiresAt")]
    pub access_token_expires_at: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "refreshTokenExpiresAt")]
    pub refresh_token_expires_at: Option<String>,
    pub scope: Option<String>,
    #[serde(rename = "idToken")]
    pub id_token: Option<String>,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "accountId", skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
}

/// Owned account identity returned by the `accountInfo` server operation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfoAccount {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub provider_id: String,
    pub account_id: String,
}

/// Provider profile and owned account returned by the `accountInfo` server operation.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccountInfoResponse {
    pub user: alibi_core::field_policy::FieldOutput,
    pub data: serde_json::Value,
    pub account: AccountInfoAccount,
}

impl SocialSignInRequest {
    /// Construct provider selection; optional OAuth inputs remain configurable.
    #[must_use]
    pub fn new(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            callback_url: None,
            new_user_callback_url: None,
            error_callback_url: None,
            disable_redirect: None,
            id_token: None,
            request_sign_up: None,
            login_hint: None,
            authorization_params: None,
            additional_params: None,
            additional_data: None,
            scopes: None,
        }
    }
}

impl LinkSocialRequest {
    /// Construct provider selection; the caller supplies verified session headers at dispatch.
    #[must_use]
    pub fn new(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            callback_url: None,
            error_callback_url: None,
            disable_redirect: None,
            id_token: None,
            request_sign_up: None,
            authorization_params: None,
            additional_params: None,
            additional_data: None,
            scopes: None,
            login_hint: None,
        }
    }
}

/// Validated input shared by the OAuth callback's logical query and POST body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OAuthCallbackInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
}
