use crate::AuthAccount;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
/// Public account response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountView {
    pub id: String,
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    #[serde(rename = "idToken")]
    pub id_token: Option<String>,
    #[serde(rename = "accessTokenExpiresAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize_optional")]
    pub access_token_expires_at: Option<DateTime<Utc>>,
    #[serde(rename = "refreshTokenExpiresAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize_optional")]
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    #[serde(skip_serializing)]
    pub password: Option<String>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub updated_at: DateTime<Utc>,
}

impl<T: AuthAccount> From<&T> for AccountView {
    fn from(account: &T) -> Self {
        Self {
            id: account.id().into_owned(),
            account_id: account.account_id().to_owned(),
            provider_id: account.provider_id().to_owned(),
            user_id: account.user_id().into_owned(),
            access_token: account.access_token().map(str::to_owned),
            refresh_token: account.refresh_token().map(str::to_owned),
            id_token: account.id_token().map(str::to_owned),
            access_token_expires_at: account.access_token_expires_at(),
            refresh_token_expires_at: account.refresh_token_expires_at(),
            scope: account.scope().map(str::to_owned),
            password: account.password().map(str::to_owned),
            created_at: account.created_at(),
            updated_at: account.updated_at(),
        }
    }
}

impl AuthAccount for AccountView {
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
    }
    fn account_id(&self) -> &str {
        &self.account_id
    }
    fn provider_id(&self) -> &str {
        &self.provider_id
    }
    fn user_id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.user_id)
    }
    fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }
    fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }
    fn id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }
    fn access_token_expires_at(&self) -> Option<DateTime<Utc>> {
        self.access_token_expires_at
    }
    fn refresh_token_expires_at(&self) -> Option<DateTime<Utc>> {
        self.refresh_token_expires_at
    }
    fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }
    fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}
