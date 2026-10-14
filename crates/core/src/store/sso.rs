//! Durable enterprise identity-provider configuration.
use crate::{AuthError, AuthResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SsoProvider {
    pub id: String,
    pub issuer: String,
    pub domain: String,
    pub provider_id: String,
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub oidc_config: Option<String>,
    pub saml_config: Option<String>,
    pub domain_verified: Option<bool>,
    #[serde(flatten, default)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}
/// A provider update prepared from the actual row locked by its adapter.
pub struct SsoProviderUpdate {
    pub provider: SsoProvider,
    pub identity_changed: bool,
}
pub type SsoProviderUpdateWork =
    dyn Fn(&SsoProvider) -> AuthResult<SsoProviderUpdate> + Send + Sync;
#[async_trait]
pub trait SsoProviderStore: Send + Sync {
    async fn mark_sso_domain_verified(&self, _id: &str, _domain: &str) -> AuthResult<bool> {
        Err(AuthError::config(
            "SSO persistence is not supported by this store",
        ))
    }
    async fn update_sso_provider(
        &self,
        _id: &str,
        _provider_id: &str,
        _prepare: &SsoProviderUpdateWork,
    ) -> AuthResult<Option<SsoProvider>> {
        Err(AuthError::config(
            "SSO persistence is not supported by this store",
        ))
    }
    /// Atomically retire a provider and every account linked to its identity namespace.
    async fn delete_sso_provider_and_accounts(
        &self,
        _id: &str,
        _provider_id: &str,
    ) -> AuthResult<bool> {
        Err(AuthError::config(
            "SSO persistence is not supported by this store",
        ))
    }
    async fn list_sso_providers(&self) -> AuthResult<Vec<SsoProvider>> {
        Err(AuthError::config(
            "SSO persistence is not supported by this store",
        ))
    }
    async fn create_sso_provider(&self, _provider: SsoProvider) -> AuthResult<SsoProvider> {
        Err(AuthError::config(
            "SSO persistence is not supported by this store",
        ))
    }
    async fn get_sso_provider(&self, _provider_id: &str) -> AuthResult<Option<SsoProvider>> {
        Err(AuthError::config(
            "SSO persistence is not supported by this store",
        ))
    }
    async fn list_sso_providers_by_user(&self, _user_id: &str) -> AuthResult<Vec<SsoProvider>> {
        Err(AuthError::config(
            "SSO persistence is not supported by this store",
        ))
    }
}

/// Physical storage category of a declared provider field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsoFieldType {
    String,
    Boolean,
    Number,
    Json,
    Date,
}
impl SsoFieldType {
    #[must_use]
    pub fn from_config(field: &crate::field_policy::FieldConfig) -> Self {
        match field.schema.get("type").and_then(serde_json::Value::as_str) {
            Some("boolean") => Self::Boolean,
            Some("number" | "integer") => Self::Number,
            Some("object" | "array" | "json" | "string[]" | "number[]") => Self::Json,
            Some("date") => Self::Date,
            _ => Self::String,
        }
    }
    #[must_use]
    pub const fn sql_type(self, postgres: bool) -> &'static str {
        match self {
            Self::String => "TEXT",
            Self::Boolean => {
                if postgres {
                    "BOOLEAN"
                } else {
                    "INTEGER"
                }
            }
            Self::Number => "INTEGER",
            Self::Json => {
                if postgres {
                    "JSONB"
                } else {
                    "TEXT"
                }
            }
            Self::Date => {
                if postgres {
                    "TIMESTAMPTZ"
                } else {
                    "DATE"
                }
            }
        }
    }
}
/// Resolve physical additional-column names without changing logical API names.
#[must_use]
pub fn sso_field_column<'a>(name: &'a str, field: &'a crate::field_policy::FieldConfig) -> &'a str {
    field.field_name.as_deref().unwrap_or(name)
}

/// Validate additional-field names against provider columns and returned fields.
pub fn validate_sso_fields(config: &crate::config::AdvancedDatabaseConfig) -> AuthResult<()> {
    const BUILT_IN: &[&str] = &[
        "id",
        "issuer",
        "domain",
        "providerId",
        "userId",
        "organizationId",
        "oidcConfig",
        "samlConfig",
        "domainVerified",
    ];
    const RESPONSE: &[&str] = &[
        "type",
        "redirectURI",
        "domainVerificationToken",
        "spMetadataUrl",
    ];
    let mapped = config.sso_provider.as_ref();
    for (name, field) in &config.sso_provider_fields.0 {
        if BUILT_IN.contains(&name.as_str()) || RESPONSE.contains(&name.as_str()) {
            return Err(AuthError::config(format!(
                "ssoProvider additional field \"{name}\" conflicts with a built-in or returned provider field"
            )));
        }
        let physical = sso_field_column(name, field);
        if physical.is_empty()
            || BUILT_IN.iter().any(|canonical| {
                let configured = mapped
                    .and_then(|mapping| {
                        mapping
                            .columns
                            .iter()
                            .find(|(key, _)| crate::config::sso_provider_column(key) == *canonical)
                            .map(|(_, value)| value.as_str())
                    })
                    .unwrap_or(canonical);
                configured == physical
            })
        {
            return Err(AuthError::config(format!(
                "ssoProvider additional field \"{name}\" maps to a built-in field"
            )));
        }
    }
    Ok(())
}
/// DDL for one declared column. Application callback defaults are evaluated at creation.
pub fn sso_field_definition(
    name: &str,
    field: &crate::field_policy::FieldConfig,
    postgres: bool,
) -> AuthResult<String> {
    use crate::field_policy::FieldDefault;
    let quote = |value: &str| format!("\"{}\"", value.replace('"', "\"\""));
    let mut definition = format!(
        "{} {}",
        quote(sso_field_column(name, field)),
        SsoFieldType::from_config(field).sql_type(postgres)
    );
    if let Some(FieldDefault::Value(value)) = &field.default {
        let default = match value {
            crate::utils::json::JsValue::Null => "NULL".to_owned(),
            crate::utils::json::JsValue::Bool(value) => {
                if postgres {
                    value.to_string()
                } else {
                    if *value { "1" } else { "0" }.to_owned()
                }
            }
            crate::utils::json::JsValue::Number(value) if value.is_finite() => value.to_string(),
            crate::utils::json::JsValue::String(value) => {
                format!("'{}'", value.replace('\'', "''"))
            }
            value => format!("'{}'", serde_json::to_string(value)?.replace('\'', "''")),
        };
        definition.push_str(" DEFAULT ");
        definition.push_str(&default);
    }
    if field.required {
        definition.push_str(" NOT NULL");
    }
    Ok(definition)
}
