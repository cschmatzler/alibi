use super::ApiKeyPermissions;

use better_auth_core::utils::json::JsValue;

pub(in crate::plugins) use better_auth_core::wire::ApiKeyView;

use better_auth_core::{AuthRequest, AuthResponse};

use serde::{Deserialize, Deserializer, Serialize};

use validator::Validate;

/// API key creation parameters for HTTP and trusted server callers.
#[serde_with::skip_serializing_none]
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateKeyRequest {
    /// Configuration to use, or the default configuration when absent.
    #[serde(default, deserialize_with = "present")]
    pub config_id: Option<String>,
    /// User authorizing a server-side creation; HTTP clients must omit this field.
    #[serde(default, deserialize_with = "coerced_string")]
    pub user_id: Option<String>,
    /// Organization owning the key when the configuration references organizations.
    #[serde(default, deserialize_with = "coerced_string")]
    pub organization_id: Option<String>,
    /// Display name for the key.
    #[serde(default, deserialize_with = "present")]
    pub name: Option<String>,
    /// Prefix prepended to the generated key.
    #[serde(default, deserialize_with = "present")]
    pub prefix: Option<String>,
    /// Lifetime in seconds; null or absence uses the configured default.
    pub expires_in: Option<f64>,
    /// Remaining uses, available only to trusted server callers.
    pub remaining: Option<f64>,
    /// Enable rate limiting for this key, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub rate_limit_enabled: Option<bool>,
    /// Rate limit window in milliseconds, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub rate_limit_time_window: Option<f64>,
    /// Requests per window, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub rate_limit_max: Option<f64>,
    /// Refill interval in milliseconds, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub refill_interval: Option<f64>,
    /// Uses restored per refill, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub refill_amount: Option<f64>,
    /// Resource permissions, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub permissions: Option<ApiKeyPermissions>,
    /// Optional metadata; preservation of null matches the upstream wire contract.
    #[serde(default, deserialize_with = "present")]
    pub metadata: Option<JsValue>,
}

/// API key updates for HTTP and trusted server callers.
#[serde_with::skip_serializing_none]
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateKeyRequest {
    /// Configuration used to locate the key.
    #[serde(default, deserialize_with = "present")]
    pub config_id: Option<String>,
    /// Identifier of the key to update.
    pub key_id: String,
    /// User authorizing a server-side update, or the current session user over HTTP.
    #[serde(default, deserialize_with = "coerced_string")]
    pub user_id: Option<String>,
    /// Replacement display name.
    #[serde(default, deserialize_with = "present")]
    pub name: Option<String>,
    /// Whether the key can authenticate requests.
    #[serde(default, deserialize_with = "present")]
    pub enabled: Option<bool>,
    /// Replacement remaining uses, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub remaining: Option<f64>,
    /// Enable rate limiting, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub rate_limit_enabled: Option<bool>,
    /// Replacement rate limit window in milliseconds, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub rate_limit_time_window: Option<f64>,
    /// Replacement requests per window, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub rate_limit_max: Option<f64>,
    /// Replacement refill interval in milliseconds, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub refill_interval: Option<f64>,
    /// Replacement uses per refill, available only to server callers.
    #[serde(default, deserialize_with = "present")]
    pub refill_amount: Option<f64>,
    /// Replacement resource permissions; null clears permissions. Server callers only.
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub permissions: Option<Option<ApiKeyPermissions>>,
    /// Replacement metadata; null clears metadata when metadata is enabled.
    #[serde(default, deserialize_with = "present")]
    pub metadata: Option<JsValue>,
    /// Absent leaves expiration unchanged, null clears expiration, and a value sets seconds from now.
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub expires_in: Option<Option<f64>>,
}

impl Validate for CreateKeyRequest {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let mut errors = numeric_errors(&[
            ("expiresIn", self.expires_in, Some(1.0)),
            ("remaining", self.remaining, Some(0.0)),
            ("refillAmount", self.refill_amount, Some(1.0)),
            ("refillInterval", self.refill_interval, None),
            ("rateLimitTimeWindow", self.rate_limit_time_window, None),
            ("rateLimitMax", self.rate_limit_max, None),
        ]);
        if let Some(prefix) = self.prefix.as_deref()
            && let Err(error) = validate_prefix(prefix)
        {
            errors.add("prefix", error);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Validate for UpdateKeyRequest {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let errors = numeric_errors(&[
            ("expiresIn", self.expires_in.flatten(), Some(1.0)),
            ("remaining", self.remaining, Some(1.0)),
            ("refillAmount", self.refill_amount, None),
            ("refillInterval", self.refill_interval, None),
            ("rateLimitTimeWindow", self.rate_limit_time_window, None),
            ("rateLimitMax", self.rate_limit_max, None),
        ]);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(in crate::plugins) struct DeleteKeyRequest {
    #[serde(default, deserialize_with = "present")]
    pub config_id: Option<String>,
    pub key_id: String,
}

/// Query parameters accepted by `GET /api-key/list`.
#[derive(Debug, Default)]
pub(in crate::plugins) struct ListKeysQuery {
    pub config_id: Option<String>,
    pub organization_id: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
}

impl ListKeysQuery {
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    ///
    /// # Errors
    /// Returns an error when validation, storage, or an application callback fails.
    pub(in crate::plugins) fn from_request(req: &AuthRequest) -> Result<Self, AuthResponse> {
        let number = |key: &str| -> Result<Option<usize>, AuthResponse> {
            let Some(value) = req.query.get(key) else {
                return Ok(None);
            };
            let parsed = if value.trim().is_empty() {
                0.0
            } else {
                value.trim().parse::<f64>().map_err(|_error| {
                    query_error(key, "Invalid input: expected number, received NaN")
                })?
            };
            if !parsed.is_finite() {
                return Err(query_error(
                    key,
                    if parsed.is_nan() {
                        "Invalid input: expected number, received NaN"
                    } else {
                        "Invalid input: expected number, received number"
                    },
                ));
            }
            if parsed.fract() != 0.0 {
                return Err(query_error(
                    key,
                    "Invalid input: expected int, received number",
                ));
            }
            if parsed < 0.0 {
                return Err(query_error(key, "Too small: expected number to be >=0"));
            }
            Ok(Some(parsed as usize))
        };
        if let Some(direction) = req.query.get("sortDirection")
            && !matches!(direction.as_str(), "asc" | "desc")
        {
            return Err(query_error(
                "sortDirection",
                "Invalid option: expected one of \"asc\"|\"desc\"",
            ));
        }
        Ok(Self {
            config_id: req.query.get("configId").cloned(),
            organization_id: req.query.get("organizationId").cloned(),
            limit: number("limit")?,
            offset: number("offset")?,
            sort_by: req.query.get("sortBy").cloned(),
            sort_direction: req.query.get("sortDirection").cloned(),
        })
    }
}

/// Paginated API key response; absent pagination parameters are omitted.
#[derive(Debug, Serialize)]
pub(in crate::plugins) struct ListKeysResponse {
    #[serde(rename = "apiKeys")]
    pub api_keys: Vec<ApiKeyView>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
}

/// Newly issued API key. The plaintext key is only returned during creation.
#[derive(Debug, Serialize)]
pub struct CreateKeyResponse {
    /// Plaintext secret to deliver to the key holder.
    pub key: String,
    /// Stored public key attributes, without the secret hash.
    #[serde(flatten)]
    pub api_key: ApiKeyView,
}

/// Result of trusted forced expiration cleanup. Store failures are logged.
#[derive(Debug, Serialize)]
pub struct DeleteExpiredApiKeysResponse {
    pub success: bool,
    pub error: Option<String>,
}

/// Parse with the DTO schema and retain the field path in upstream validation errors.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) fn parse_api_key_body<T>(request: &AuthRequest) -> Result<T, AuthResponse>
where
    T: serde::de::DeserializeOwned + Validate,
{
    let input: JsValue = request
        .body_as_json()
        .map_err(|_error| validation_response("body", "Invalid JSON"))?;
    let body: T = serde_path_to_error::deserialize(input.clone()).map_err(|error| {
        let mut path = error.path().to_string().replace('[', ".").replace(']', "");
        if path == "." {
            path.clear();
        }
        let detail = error.inner().to_string();
        let input_number = {
            let mut value = Some(&input);
            for segment in error.path() {
                value = value.and_then(|current| match segment {
                    serde_path_to_error::Segment::Seq { index } => current.as_array()?.get(*index),
                    serde_path_to_error::Segment::Map { key } => current.get(key),
                    serde_path_to_error::Segment::Enum { variant } => current.get(variant),
                    serde_path_to_error::Segment::Unknown => None,
                });
            }
            value.and_then(JsValue::as_f64)
        };
        let nonfinite_input = input_number.filter(|number| !number.is_finite());
        let message = detail
            .strip_prefix("missing field `")
            .and_then(|rest| rest.split('`').next())
            .map_or_else(
                || {
                    if let Some((received, expected)) = detail
                        .strip_prefix("invalid type: ")
                        .and_then(|detail| detail.split_once(", expected "))
                    {
                        let expected = expected.split(" at line ").next().unwrap_or(expected);
                        let expected = match expected {
                            "a string" => "string",
                            "a boolean" => "boolean",
                            "f64" => "number",
                            "a sequence" => "array",
                            "a map" => "record",
                            _ => "object",
                        };
                        let received = nonfinite_input.map_or_else(
                            || {
                                if received.starts_with("string") {
                                    "string"
                                } else if received.starts_with("integer")
                                    || received.starts_with("floating point")
                                {
                                    "number"
                                } else if received.starts_with("boolean") {
                                    "boolean"
                                } else {
                                    match received {
                                        "sequence" => "array",
                                        "map" => "object",
                                        value => value,
                                    }
                                }
                            },
                            |number| {
                                if number.is_sign_negative() {
                                    "-Infinity"
                                } else {
                                    "Infinity"
                                }
                            },
                        );
                        format!("Invalid input: expected {expected}, received {received}")
                    } else if detail.starts_with("number out of range") && nonfinite_input.is_some()
                    {
                        format!(
                            "Invalid input: expected number, received {}",
                            if nonfinite_input.is_some_and(f64::is_sign_negative) {
                                "-Infinity"
                            } else {
                                "Infinity"
                            }
                        )
                    } else {
                        detail.clone()
                    }
                },
                |field| {
                    field.clone_into(&mut path);
                    "Invalid input: expected string, received undefined".to_owned()
                },
            );
        let location = if path.is_empty() {
            "body".to_owned()
        } else {
            format!("body.{path}")
        };
        validation_response(&location, &message)
    })?;
    body.validate()
        .map_err(|error| better_auth_core::validation_error_response(&error))?;
    Ok(body)
}

fn numeric_errors(
    fields: &[(&'static str, Option<f64>, Option<f64>)],
) -> validator::ValidationErrors {
    let mut errors = validator::ValidationErrors::new();
    for &(field, value, minimum) in fields {
        let Some(value) = value else {
            continue;
        };
        let message = if value.is_finite() {
            minimum
                .filter(|minimum| value < *minimum)
                .map(|minimum| format!("Too small: expected number to be >={minimum}"))
        } else {
            Some(format!(
                "Invalid input: expected number, received {}",
                if value.is_nan() {
                    "NaN"
                } else if value.is_sign_negative() {
                    "-Infinity"
                } else {
                    "Infinity"
                }
            ))
        };
        if let Some(message) = message {
            let mut error = validator::ValidationError::new("range");
            error.message = Some(message.into());
            errors.add(field, error);
        }
    }
    errors
}

/// Deserialize an explicitly supplied value without treating null as an absent field.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn coerced_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    fn js_string(value: &JsValue) -> String {
        match value {
            JsValue::String(value) => value.clone(),
            JsValue::Array(values) => values
                .iter()
                .map(|value_2| {
                    if value_2.is_null() {
                        String::new()
                    } else {
                        js_string(value_2)
                    }
                })
                .collect::<Vec<_>>()
                .join(","),
            JsValue::Object(_) => "[object Object]".into(),
            JsValue::Number(number) => ryu_js::Buffer::new().format(*number).to_owned(),
            JsValue::Null => "null".into(),
            JsValue::Bool(value) => value.to_string(),
        }
    }
    JsValue::deserialize(deserializer).map(|value| Some(js_string(&value)))
}

fn validate_prefix(prefix: &str) -> Result<(), validator::ValidationError> {
    if !prefix.is_empty()
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Ok(())
    } else {
        let mut error = validator::ValidationError::new("regex");
        error.message = Some(
            "Invalid prefix format, must be alphanumeric and contain only underscores and hyphens."
                .into(),
        );
        Err(error)
    }
}

fn query_error(field: &str, message: &str) -> AuthResponse {
    validation_response(&format!("query.{field}"), message)
}

fn validation_response(location: &str, message: &str) -> AuthResponse {
    let body = serde_json::json!({
        "code": "VALIDATION_ERROR", "message": format!("[{location}] {message}")
    });
    AuthResponse::text(400, body.to_string()).with_header("content-type", "application/json")
}
