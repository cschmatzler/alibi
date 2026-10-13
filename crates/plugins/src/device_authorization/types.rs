use serde::{Deserialize, Serialize};
use validator::Validate;

/// Request a device proof for an application and optional owner/scope.
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct DeviceCodeRequest {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub(super) struct DeviceTokenRequest {
    pub device_code: String,
    pub client_id: String,
}

#[derive(Debug, Deserialize, Validate)]
pub(super) struct DeviceActionRequest {
    #[serde(rename = "userCode")]
    pub user_code: String,
}

/// Issued device and user codes, verification URIs, expiry and polling interval.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i64,
    pub interval: i64,
}

/// A bearer token issued after consuming an approved device proof.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
}

#[derive(Debug, Serialize)]
#[expect(
    clippy::option_option,
    reason = "The wire contract distinguishes an omitted field, explicit null, and a supplied value"
)]
pub(super) struct DeviceVerifyResponse {
    pub user_code: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Option<String>>,
}

/// A device authorization decision was persisted for its claiming owner.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceActionResponse {
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct DeviceErrorResponse {
    pub error: String,
    pub error_description: String,
}
