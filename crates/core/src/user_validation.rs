//! Application identity policy at the endpoint's actual admission boundary.
use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult};
use crate::hooks::{RequestHookContext, current_request_hook_context};
use crate::types::CreateUser;
use async_trait::async_trait;
use chrono::Utc;

/// The identity operation being admitted. Non-provider returning sign-ins do
/// not invoke this policy because they do not introduce new identity data.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UserValidationAction {
    #[default]
    CreateUser,
    LinkAccount,
    SignIn,
}

/// Provider identity before application profile mapping.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserValidationProvider {
    pub provider_id: String,
    /// Only a provider's actual object response is supplied. Arrays and scalar
    /// responses have no profile record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<serde_json::Value>,
}

/// Identity provenance supplied by the endpoint, never by its request body.
/// The string method permits application-defined identity extensions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserValidationSource {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub action: UserValidationAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth: Option<UserValidationProvider>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sso: Option<UserValidationProvider>,
}

impl UserValidationSource {
    #[must_use]
    pub fn creation(method: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            action: UserValidationAction::CreateUser,
            oauth: None,
            sso: None,
        }
    }

    #[must_use]
    pub fn oauth(
        provider_id: impl Into<String>,
        profile: &serde_json::Value,
        action: UserValidationAction,
    ) -> Self {
        Self {
            method: "oauth".into(),
            action,
            oauth: Some(UserValidationProvider {
                provider_id: provider_id.into(),
                profile: profile.is_object().then(|| profile.clone()),
            }),
            sso: None,
        }
    }
}

/// Mutable trusted candidate. Creation mutations are persisted; provider
/// sign-in/link mutations affect only this validation copy.
#[derive(Debug, Clone)]
pub struct UserValidationData {
    pub user: CreateUser,
    pub source: UserValidationSource,
}

/// A policy denial. An empty error is an admission, and an empty description
/// falls back to the error code, matching the callback's public contract.
#[derive(Debug, Clone)]
pub struct UserValidationRejection {
    pub error: String,
    pub error_description: Option<String>,
}

#[async_trait]
pub trait UserInfoValidator: Send + Sync {
    /// Observe the actual endpoint request (including original body bytes and
    /// its typed parsed body extensions), before database creation hooks or
    /// provider account/session writes. Exceptions are a generic 403 denial.
    async fn validate(
        &self,
        data: &mut UserValidationData,
        request: &RequestHookContext,
    ) -> AuthResult<Option<UserValidationRejection>>;
}

fn denial(code: &str, message: &str) -> AuthError {
    AuthError::Api {
        status: 403,
        code: Some(code.into()),
        message: message.into(),
    }
}

fn assert_source(source: Option<&UserValidationSource>) -> AuthResult<()> {
    let Some(source) = source.filter(|source| !source.method.is_empty()) else {
        return Err(denial(
            "validation_source_missing",
            "User validation source is required",
        ));
    };
    if source.method == "oauth"
        && source
            .oauth
            .as_ref()
            .is_none_or(|provider| provider.provider_id.is_empty())
    {
        return Err(denial(
            "validation_source_missing",
            "OAuth user validation source requires oauth.providerId",
        ));
    }
    if matches!(source.method.as_str(), "sso-oidc" | "sso-saml")
        && source
            .sso
            .as_ref()
            .is_none_or(|provider| provider.provider_id.is_empty())
    {
        return Err(denial(
            "validation_source_missing",
            "SSO user validation source requires sso.providerId",
        ));
    }
    Ok(())
}

/// Apply configured validation against fresh provider identity at a returning
/// sign-in or account-link boundary. Creation is owned by the store wrapper.
pub async fn validate_user_info(
    config: &AuthConfig,
    data: &mut UserValidationData,
) -> AuthResult<()> {
    let Some(validator) = &config.user_validation else {
        return Ok(());
    };
    assert_source(Some(&data.source))?;
    let request = current_request_hook_context().ok_or_else(|| {
        denial(
            "validation_context_missing",
            "User validation requires an endpoint context",
        )
    })?;
    match validator.validate(data, &request).await {
        Ok(Some(rejection)) if !rejection.error.is_empty() => {
            let message = rejection
                .error_description
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or(&rejection.error);
            Err(denial(&rejection.error, message))
        }
        Ok(_) => Ok(()),
        Err(_) => Err(denial("validation_failed", "User validation failed")),
    }
}

/// A creation candidate already normalized and admitted by the configured
/// identity policy. Adapters persist its trusted mutations without normalizing
/// it again, and retain their ordinary database hooks.
pub struct PreparedUserCreation {
    data: CreateUser,
    defaults: crate::store::UserCreationDefaults,
}

impl PreparedUserCreation {
    #[must_use]
    pub fn into_data(self) -> CreateUser {
        self.data
    }

    /// Adapters run their before hooks on the candidate, then apply these model
    /// defaults immediately before insertion.
    #[must_use]
    pub fn into_parts(self) -> (CreateUser, crate::store::UserCreationDefaults) {
        (self.data, self.defaults)
    }

    pub(crate) fn from_data(data: CreateUser) -> Self {
        Self {
            data,
            defaults: crate::store::UserCreationDefaults::default(),
        }
    }

    pub(crate) fn with_defaults(mut self, defaults: crate::store::UserCreationDefaults) -> Self {
        self.defaults = defaults;
        self
    }
}

pub(crate) async fn prepare_creation(
    config: &AuthConfig,
    mut user: CreateUser,
    source: Option<UserValidationSource>,
) -> AuthResult<PreparedUserCreation> {
    assert_source(source.as_ref())?;
    let mut source = source.ok_or_else(|| {
        denial(
            "validation_source_missing",
            "User validation source is required",
        )
    })?;
    source.action = UserValidationAction::CreateUser;
    let now = Utc::now();
    _ = user.created_at.get_or_insert(now);
    _ = user.updated_at.get_or_insert(now);
    user.email = user
        .email
        .map(|email| crate::utils::normalize_user_email(&email));
    let mut data = UserValidationData { user, source };
    validate_user_info(config, &mut data).await?;
    if data.user.created_at.is_none() || data.user.updated_at.is_none() {
        return Err(AuthError::NotImplemented(
            "Identity policy removal of creation timestamps is not supported".into(),
        ));
    }
    Ok(PreparedUserCreation::from_data(data.user))
}
