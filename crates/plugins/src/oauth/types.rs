use alibi_core::wire::UserView;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub(super) struct SocialSignInRequest {
    #[validate(length(min = 1, message = "Provider is required"))]
    pub provider: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL")]
    pub new_user_callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    #[serde(rename = "disableRedirect")]
    pub disable_redirect: Option<bool>,
    #[serde(rename = "idToken")]
    pub id_token: Option<OAuthIdTokenRequest>,
    #[serde(rename = "requestSignUp")]
    pub request_sign_up: Option<bool>,
    #[serde(rename = "loginHint")]
    pub login_hint: Option<String>,
    #[serde(rename = "additionalParams")]
    pub additional_params: Option<std::collections::BTreeMap<String, String>>,
    #[serde(rename = "additionalData")]
    #[serde(
        default,
        deserialize_with = "alibi_core::utils::json::deserialize_optional_map"
    )]
    pub additional_data: Option<serde_json::Map<String, serde_json::Value>>,
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Validate)]
pub(super) struct LinkSocialRequest {
    #[validate(length(min = 1, message = "Provider is required"))]
    pub provider: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    #[serde(rename = "disableRedirect")]
    pub disable_redirect: Option<bool>,
    #[serde(rename = "idToken")]
    pub id_token: Option<OAuthIdTokenRequest>,
    #[serde(rename = "requestSignUp")]
    pub request_sign_up: Option<bool>,
    #[serde(rename = "additionalParams")]
    pub additional_params: Option<std::collections::BTreeMap<String, String>>,
    #[serde(rename = "additionalData")]
    #[serde(
        default,
        deserialize_with = "alibi_core::utils::json::deserialize_optional_map"
    )]
    pub additional_data: Option<serde_json::Map<String, serde_json::Value>>,
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Validate)]
pub(super) struct OAuthIdTokenRequest {
    #[validate(length(min = 1, message = "Token is required"))]
    pub token: String,
    pub nonce: Option<String>,
    pub user: Option<super::providers::OAuthCallbackUserPayload>,
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<i64>,
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub(super) struct SocialSignInResponse {
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

#[derive(Debug, Serialize)]
pub(super) struct AccessTokenResponse {
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AccountInfoAccount {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub provider_id: String,
    pub account_id: String,
}

#[derive(Debug, Serialize)]
pub(super) struct AccountInfoResponse {
    pub user: alibi_core::field_policy::FieldOutput,
    pub data: serde_json::Value,
    pub account: AccountInfoAccount,
}
