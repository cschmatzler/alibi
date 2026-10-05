use super::*;
/// Generic `{ ok: bool }` response used by `/ok` and `/error` endpoints.
#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

/// Generic `{ status: bool }` response.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: bool,
}

/// `{ status: bool, message: String }` response (e.g. change-email).
#[derive(Debug, Serialize)]
pub struct StatusMessageResponse {
    pub status: bool,
    pub message: String,
}

/// Generic `{ success: bool }` response (e.g. sign-out).
///
/// Use for endpoints where the upstream spec defines `success` rather than `status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SuccessResponse {
    pub success: bool,
}

/// `{ success: bool, message: String }` response (e.g. delete-user).
///
/// Use for endpoints where the upstream spec defines `success` rather than `status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SuccessMessageResponse {
    pub success: bool,
    pub message: String,
}

/// Health-check response for `/health`.
#[derive(Debug, Serialize)]
pub struct HealthCheckResponse {
    pub status: &'static str,
    pub service: &'static str,
}

/// Error body `{ message: String }`.
#[derive(Debug, Serialize)]
pub struct ErrorMessageResponse {
    pub message: String,
}

/// Error body `{ code: String, message: String }` matching the TS better-auth
/// error response shape.
#[derive(Debug, Serialize)]
pub struct ErrorCodeMessageResponse {
    /// Omitted when upstream has no explicit code for this error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
}

/// Middleware error response `{ code: String, message: String }`.
#[derive(Debug, Serialize)]
pub struct CodeMessageResponse {
    pub code: &'static str,
    pub message: String,
}

/// Rate-limit error response with `retryAfter` field.
#[derive(Debug, Serialize)]
pub struct RateLimitErrorResponse {
    pub code: &'static str,
    pub message: &'static str,
    #[serde(rename = "retryAfter")]
    pub retry_after: u64,
}

/// Validation error response `{ code, message, errors }`.
#[derive(Debug, Serialize)]
pub struct ValidationErrorResponse<'a> {
    pub code: &'static str,
    pub message: &'static str,
    pub errors: HashMap<std::borrow::Cow<'a, str>, Vec<String>>,
}
