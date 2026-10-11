//! Configured username validation and normalization stages.

use super::UsernameValidationError;
use crate::{AuthError, AuthResult, utils::json::JsValue};
use async_trait::async_trait;
use std::{fmt, future::Future, sync::Arc};

/// Awaited application validation of a username or display username.
#[async_trait]
pub trait UsernameValidator: Send + Sync {
    async fn validate(&self, value: &str) -> AuthResult<bool>;
}
#[async_trait]
impl<F, Fut> UsernameValidator for F
where
    F: Fn(String) -> Fut + Send + Sync,
    Fut: Future<Output = AuthResult<bool>> + Send,
{
    async fn validate(&self, value: &str) -> AuthResult<bool> {
        self(value.to_owned()).await
    }
}

/// A synchronous normalization callback; errors propagate to its caller.
pub trait UsernameNormalizer: Send + Sync {
    fn normalize(&self, value: &str) -> AuthResult<String>;
}
impl<F> UsernameNormalizer for F
where
    F: Fn(&str) -> AuthResult<String> + Send + Sync,
{
    fn normalize(&self, value: &str) -> AuthResult<String> {
        self(value)
    }
}

#[derive(Clone, Default)]
pub enum UsernameNormalization {
    #[default]
    Lowercase,
    Preserve,
    Custom(Arc<dyn UsernameNormalizer>),
}
impl fmt::Debug for UsernameNormalization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Lowercase => "Lowercase",
            Self::Preserve => "Preserve",
            Self::Custom(_) => "Custom",
        })
    }
}

/// The explicit upstream validation-order setting. An absent setting is
/// distinct: sign-in validates raw input, while lookup always normalizes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsernameValidationOrder {
    PreNormalization,
    PostNormalization,
}

#[derive(Clone)]
pub struct UsernameConfig {
    /// UTF-16 lengths; zero uses the upstream defaults of 3 and 30.
    pub min_length: usize,
    pub max_length: usize,
    pub normalization: UsernameNormalization,
    pub validator: Option<Arc<dyn UsernameValidator>>,
    pub include_display_username: bool,
    pub display_normalizer: Option<Arc<dyn UsernameNormalizer>>,
    pub display_validator: Option<Arc<dyn UsernameValidator>>,
    pub validation_order: Option<UsernameValidationOrder>,
    pub display_validation_order: Option<UsernameValidationOrder>,
    pub immutable_username: bool,
    /// Admit usernames supplied by endpoint callers.
    pub input: bool,
}
impl Default for UsernameConfig {
    fn default() -> Self {
        Self {
            min_length: 3,
            max_length: 30,
            normalization: UsernameNormalization::Lowercase,
            validator: None,
            include_display_username: true,
            display_normalizer: None,
            display_validator: None,
            validation_order: None,
            display_validation_order: None,
            immutable_username: false,
            input: true,
        }
    }
}
impl fmt::Debug for UsernameConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsernameConfig")
            .field("min_length", &self.min_length)
            .field("max_length", &self.max_length)
            .field("normalization", &self.normalization)
            .field("validator", &self.validator.as_ref().map(|_| "callback"))
            .field("include_display_username", &self.include_display_username)
            .field(
                "display_normalizer",
                &self.display_normalizer.as_ref().map(|_| "callback"),
            )
            .field(
                "display_validator",
                &self.display_validator.as_ref().map(|_| "callback"),
            )
            .field("validation_order", &self.validation_order)
            .field("display_validation_order", &self.display_validation_order)
            .field("immutable_username", &self.immutable_username)
            .field("input", &self.input)
            .finish()
    }
}
impl UsernameConfig {
    pub fn normalize(&self, value: &str) -> AuthResult<String> {
        match &self.normalization {
            UsernameNormalization::Lowercase => Ok(value.to_lowercase()),
            UsernameNormalization::Preserve => Ok(value.to_owned()),
            UsernameNormalization::Custom(normalizer) => normalizer
                .normalize(value)
                .map_err(AuthError::into_callback_failure),
        }
    }
    pub fn normalize_display(&self, value: &str) -> AuthResult<String> {
        self.display_normalizer.as_ref().map_or_else(
            || Ok(value.to_owned()),
            |normalizer| {
                normalizer
                    .normalize(value)
                    .map_err(AuthError::into_callback_failure)
            },
        )
    }
    pub async fn value_error(&self, value: &str) -> AuthResult<Option<UsernameValidationError>> {
        let length = value.encode_utf16().count();
        let minimum = if self.min_length == 0 {
            3
        } else {
            self.min_length
        };
        let maximum = if self.max_length == 0 {
            30
        } else {
            self.max_length
        };
        if length < minimum {
            return Ok(Some(UsernameValidationError::TooShort));
        }
        if length > maximum {
            return Ok(Some(UsernameValidationError::TooLong));
        }
        let valid = if let Some(validator) = &self.validator {
            validator
                .validate(value)
                .await
                .map_err(AuthError::into_callback_failure)?
        } else {
            super::valid_default_characters(value)
        };
        Ok((!valid).then_some(UsernameValidationError::Invalid))
    }
    pub async fn validate_value(&self, value: &str, status: u16) -> AuthResult<()> {
        if let Some(error) = self.value_error(value).await? {
            return Err(error.auth_error(status));
        }
        Ok(())
    }
    pub async fn validate_hook_value(&self, value: &str) -> AuthResult<()> {
        if self.validation_order == Some(UsernameValidationOrder::PostNormalization) {
            self.validate_value(&self.normalize(value)?, 400).await
        } else {
            self.validate_value(value, 400).await
        }
    }
    /// Normalize an untyped passwordless create-hook value without changing
    /// the string-only contract of configured native callbacks.
    pub fn normalize_raw_hook_value(&self, value: &JsValue) -> AuthResult<JsValue> {
        if let JsValue::String(value) = value {
            return self.normalize(value).map(JsValue::String);
        }
        if matches!(self.normalization, UsernameNormalization::Preserve) {
            return Ok(value.clone());
        }
        Err(AuthError::CallbackFailure(Box::new(AuthError::internal(
            "Username normalization requires a string",
        ))))
    }
    /// The dependency reads raw .length before its default regular expression.
    /// Numeric and boolean candidates have no length; its regular expression
    /// applies String coercion independently from later normalization.
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "Raw JavaScript length comparisons use IEEE754 numbers"
    )]
    pub async fn validate_raw_hook_value(&self, value: &JsValue) -> AuthResult<()> {
        if let JsValue::String(value) = value {
            return self.validate_hook_value(value).await;
        }
        let normalized;
        let value = if self.validation_order == Some(UsernameValidationOrder::PostNormalization) {
            normalized = self.normalize_raw_hook_value(value)?;
            &normalized
        } else {
            value
        };
        let raw_length = match value {
            JsValue::String(value) => Some(value.encode_utf16().count() as f64),
            JsValue::Array(value) => Some(value.len() as f64),
            JsValue::Object(value) => value
                .get("length")
                .map(|length| -> AuthResult<f64> {
                    Ok(match length {
                        JsValue::Null => 0.0,
                        JsValue::Bool(value) => {
                            if *value {
                                1.0
                            } else {
                                0.0
                            }
                        }
                        JsValue::Number(value) => *value,
                        value => {
                            let text = value.coerce_string().map_err(|message| {
                                AuthError::CallbackFailure(Box::new(AuthError::internal(message)))
                            })?;
                            crate::utils::javascript::string_to_number(&text).unwrap_or(f64::NAN)
                        }
                    })
                })
                .transpose()?,
            _ => None,
        };
        let minimum = if self.min_length == 0 {
            3
        } else {
            self.min_length
        };
        let maximum = if self.max_length == 0 {
            30
        } else {
            self.max_length
        };
        if raw_length.is_some_and(|length| length < minimum as f64) {
            return Err(UsernameValidationError::TooShort.auth_error(400));
        }
        if raw_length.is_some_and(|length| length > maximum as f64) {
            return Err(UsernameValidationError::TooLong.auth_error(400));
        }
        if self.validator.is_some() {
            return Err(AuthError::CallbackFailure(Box::new(AuthError::internal(
                "Configured username validation requires a string",
            ))));
        }
        let text = value.coerce_string().map_err(|message| {
            AuthError::CallbackFailure(Box::new(AuthError::internal(message)))
        })?;
        if text.is_empty() || !super::valid_default_characters(&text) {
            return Err(UsernameValidationError::Invalid.auth_error(400));
        }
        Ok(())
    }
    pub async fn validate_display(&self, value: &str) -> AuthResult<()> {
        if !self.include_display_username {
            return Ok(());
        }
        if let Some(validator) = &self.display_validator {
            let normalized;
            let input = if self.display_validation_order
                == Some(UsernameValidationOrder::PostNormalization)
            {
                normalized = self.normalize_display(value)?;
                &normalized
            } else {
                value
            };
            if !validator
                .validate(input)
                .await
                .map_err(AuthError::into_callback_failure)?
            {
                return Err(AuthError::Upstream {
                    status: 400,
                    code: "INVALID_DISPLAY_USERNAME",
                    message: "Display username is invalid",
                });
            }
        }
        Ok(())
    }
    /// Schema input transforms run both during endpoint parsing and storage.
    pub fn fields(&self) -> crate::field_policy::FieldConfigs {
        use crate::field_policy::FieldConfig;
        let mut fields = crate::field_policy::FieldConfigs::new();
        let policy = self.clone();
        _ = fields.insert(
            "username".into(),
            FieldConfig::new(serde_json::json!({"type":"string"})).transform(move |value| {
                match value {
                    Some(JsValue::String(value)) => {
                        Ok(Some(JsValue::String(policy.normalize(value)?)))
                    }
                    value => Ok(value.cloned()),
                }
            }),
        );
        if let Some(field) = fields.get_mut("username") {
            field.input = self.input;
        }
        if self.include_display_username {
            let policy = self.clone();
            _ = fields.insert(
                "displayUsername".into(),
                FieldConfig::new(serde_json::json!({"type":"string"})).transform(move |value| {
                    match value {
                        Some(JsValue::String(value)) => {
                            Ok(Some(JsValue::String(policy.normalize_display(value)?)))
                        }
                        value => Ok(value.cloned()),
                    }
                }),
            );
        } else {
            let mut hidden = FieldConfig::new(serde_json::json!({"type":"string"}));
            hidden.input = false;
            hidden.returned = false;
            _ = fields.insert("displayUsername".into(), hidden);
        }
        fields
    }
    /// Normalize the actual database-hook candidate before adapter transforms.
    pub fn normalize_fields(
        &self,
        username: &mut Option<String>,
        display: &mut Option<String>,
        values: &mut crate::field_policy::FieldValues,
        creation: bool,
    ) -> AuthResult<()> {
        if username.is_none()
            && let Some(raw) = values.get("username").cloned()
            && raw.is_truthy()
        {
            let normalized = self.normalize_raw_hook_value(&raw)?;
            _ = values.insert("username".into(), normalized);
            if creation
                && self.include_display_username
                && values
                    .get("displayUsername")
                    .is_none_or(|value| !value.is_truthy())
            {
                _ = values.insert("displayUsername".into(), raw);
            }
        }
        if display.is_none()
            && self.include_display_username
            && let Some(raw) = values
                .get("displayUsername")
                .filter(|raw| raw.is_truthy())
                .cloned()
            && self.display_normalizer.is_some()
        {
            let raw = raw.as_str().ok_or_else(|| {
                AuthError::CallbackFailure(Box::new(AuthError::internal(
                    "Configured display normalization requires a string",
                )))
            })?;
            _ = values.insert(
                "displayUsername".into(),
                JsValue::String(self.normalize_display(raw)?),
            );
        }
        let original_username = username.clone();
        if let Some(value) = username.as_mut() {
            if !value.is_empty() {
                *value = self.normalize(value)?;
            }
            _ = values.insert("username".into(), JsValue::String(value.clone()));
        }
        if self.include_display_username {
            if creation
                && username.as_ref().is_some_and(|value| !value.is_empty())
                && display.as_ref().is_none_or(String::is_empty)
            {
                display.clone_from(&original_username);
                if let Some(value) = &display {
                    _ = values.insert("displayUsername".into(), JsValue::String(value.clone()));
                }
            } else if let Some(value) = display.as_mut().filter(|value| !value.is_empty()) {
                *value = self.normalize_display(value)?;
                _ = values.insert("displayUsername".into(), JsValue::String(value.clone()));
            }
        } else {
            *display = None;
        }
        Ok(())
    }
}
