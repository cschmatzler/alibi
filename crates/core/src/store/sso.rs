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
    /// Fields that decide which IdP identities linked accounts belong to changed.
    pub identity_changed: bool,
    /// Identity or signing trust changed; reported to the provider mutation guard.
    pub authentication_boundary_changed: bool,
    /// Only submitted fields are bound again during partial updates.
    pub additional_field_changes: serde_json::Map<String, serde_json::Value>,
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
        if BUILT_IN.contains(&name.as_str()) {
            return Err(AuthError::config(format!(
                "ssoProvider additional field \"{name}\" conflicts with a built-in field"
            )));
        }
        if RESPONSE.contains(&name.as_str()) {
            return Err(AuthError::config(format!(
                "ssoProvider additional field \"{name}\" conflicts with a returned provider field"
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
                "ssoProvider additional field \"{name}\" maps to built-in field \"{physical}\""
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

/// Apply application adapter input callbacks and defaults immediately before binding.
pub async fn prepare_sso_fields(
    fields: &crate::field_policy::SessionFields,
    input: &serde_json::Map<String, serde_json::Value>,
    create: bool,
) -> AuthResult<serde_json::Map<String, serde_json::Value>> {
    let policy = crate::field_policy::SessionAdapterFields(std::sync::Arc::new(fields.0.clone()));
    let mut values: crate::field_policy::FieldValues = input
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                crate::utils::json::JsValue::from(value.clone()),
            )
        })
        .collect();
    policy.attach(&mut values, create);
    values.apply_adapter_transforms_async().await?;
    values
        .into_iter()
        .map(|(key, value)| Ok((key, value.to_json_value()?)))
        .collect()
}
/// Resolve application output callbacks on the actual stored provider projection.
pub async fn project_sso_provider(
    fields: &crate::field_policy::SessionFields,
    mut provider: SsoProvider,
) -> AuthResult<SsoProvider> {
    let policy = crate::field_policy::SessionAdapterFields(std::sync::Arc::new(fields.0.clone()));
    let output = policy
        .output(std::mem::take(&mut provider.additional_fields))
        .await?;
    provider.additional_fields.clone_from(output.values());
    // The reference normalizes database date strings after output transforms.
    for (name, field) in &fields.0 {
        if SsoFieldType::from_config(field) == SsoFieldType::Date
            && let Some(value) = provider.additional_fields.get_mut(name)
            && let Some(text) = value.as_str()
        {
            *value = chrono::DateTime::parse_from_rfc3339(text).map_or(
                serde_json::Value::Null,
                |date| {
                    serde_json::Value::String(
                        date.with_timezone(&chrono::Utc)
                            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    )
                },
            );
        }
    }
    Ok(provider)
}
