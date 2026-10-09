mod authorization;
mod cookies;
mod http;
mod identity;
mod linking;
mod redirects;
mod token_exchange;

use super::encryption::{encrypt_provider_token_set, encrypt_token_set, provider_token_nulls};
use super::providers::{
    OAuthCallbackUserName, OAuthCallbackUserPayload, OAuthClientAssertionContext, OAuthConfig,
    OAuthProvider, OAuthScopeOrder, OAuthTokenEndpointAuth, OAuthTokenGrant, OAuthTokenSet,
    OAuthUserInfo, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use super::state::{
    AccountCookiePayload, OAuthStateLink, OAuthStatePayload, RecoveredOAuthServerContext,
    account_cookie_name, capture_server_context, create_account_cookie_value,
    create_cookie_state_value, create_database_state_cookie_value, decode_account_cookie_value,
    decode_cookie_state_value, decode_database_state_cookie_value, filter_additional_state_data,
    get_cookie, state_cookie_name, state_verification_identifier, verified_server_context,
};
use super::types::{
    LinkSocialRequest, OAuthIdTokenRequest, SocialSignInRequest, SocialSignInResponse,
};
use crate::helpers::{SessionIssueError, apply_default_role, issue_selected_user_session_record};
use alibi_core::entity::{AuthSession, AuthUser};
use alibi_core::user_validation::{
    UserValidationAction, UserValidationData, UserValidationSource, validate_user_info,
};
use alibi_core::wire::{SessionView, UserView};
use alibi_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateAccount, CreateUser,
    CreateVerification, UpdateAccount, UpdateUser,
};
use authorization::link_social_core;
use authorization::social_sign_in_core;
use authorization::validate_authorization_params;
use chrono::{Duration, Utc};
use cookies::account_cookie_max_age;
use cookies::attach_cookie_state_payload;
use cookies::attach_state_cookie;
pub(crate) use cookies::create_account_cookie_headers;
pub(super) use cookies::decode_account_cookie;
pub(super) use http::handle_callback;
pub(super) use http::handle_link_social;
pub(crate) use http::handle_social_sign_in;
pub(crate) use identity::process_oauth_sign_in;
pub(crate) use identity::process_oauth_sign_in_with_output;
use identity::provider_candidate;
pub(crate) use linking::complete_link_social;
use linking::complete_link_social_with_raw_email;
use linking::link_with_id_token_core;
use linking::sign_in_with_id_token_core;
pub(crate) use redirects::ambiguous_account_sign_in_response;
use redirects::auth_base_url;
use redirects::build_default_error_url;
use redirects::build_redirect_url;
use redirects::callback_failure_location;
use redirects::callback_failure_redirect;
use redirects::redirect_response;
use redirects::validate_redirect_target;
use sha2::Sha256;
use std::collections::HashMap;
pub(crate) use token_exchange::fetch_user_info_from_provider;
pub(super) use token_exchange::refresh_tokens_via_provider;
pub(crate) use token_exchange::validate_authorization_code_via_provider;

pub(crate) struct ProcessOAuthUserResult {
    pub(crate) session: SessionView,
    pub(crate) user: UserView,
    pub(crate) is_register: bool,
    pub(crate) account_cookie: Option<AccountCookiePayload>,
}

pub(crate) enum OAuthSignInError {
    Generic(String),
    AccountLookup(AuthError),
    SessionAuth(AuthError),
    IdentityDenied { code: String, message: String },
    Banned(String),
    EmailNotVerified,
}

impl OAuthSignInError {
    fn from_identity_denial(error: AuthError) -> Self {
        let (_, code, message) = error.error_payload();
        Self::IdentityDenied {
            code: code.unwrap_or_else(|| "validation_failed".into()),
            message,
        }
    }
    fn from_account_lookup(error: AuthError) -> Self {
        if matches!(
            error,
            AuthError::Database(alibi_core::DatabaseError::AmbiguousAccount { .. })
        ) {
            Self::AccountLookup(error)
        } else {
            Self::Generic(error.to_string())
        }
    }

    pub(crate) fn is_ambiguous_account(&self) -> bool {
        matches!(
            self,
            Self::AccountLookup(AuthError::Database(
                alibi_core::DatabaseError::AmbiguousAccount { .. }
            ))
        )
    }

    pub(crate) fn redirect_parts(&self) -> (String, Option<&str>) {
        match self {
            // Upstream turns a plain internal error string into the `error`
            // param verbatim, with no description.
            Self::Generic(message) => (message.replace(' ', "_"), None),
            Self::AccountLookup(error) | Self::SessionAuth(error) => {
                (error.to_string().replace(' ', "_"), None)
            }
            // An APIError instead redirects with its `code` and message, so the
            // param is the constant, not a lowercased word.
            Self::Banned(message) => ("BANNED_USER".to_owned(), Some(message.as_str())),
            Self::IdentityDenied { code, message } => (code.clone(), Some(message.as_str())),
            Self::EmailNotVerified => ("email_not_verified".to_owned(), None),
        }
    }
}

impl From<String> for OAuthSignInError {
    fn from(value: String) -> Self {
        Self::Generic(value)
    }
}

impl From<SessionIssueError> for OAuthSignInError {
    fn from(value: SessionIssueError) -> Self {
        match value {
            SessionIssueError::Auth(error) => Self::SessionAuth(error),
            SessionIssueError::Banned { message } => Self::Banned(message),
        }
    }
}

struct InitiatedOAuthFlow {
    response: SocialSignInResponse,
    state: String,
    payload: OAuthStatePayload,
}

struct FlowStartRequest<'a> {
    provider_name: &'a str,
    provider: &'a OAuthProvider,
    callback_url: &'a str,
    new_user_callback_url: Option<String>,
    error_callback_url: Option<String>,
    scopes: Option<&'a [String]>,
    login_hint: Option<&'a str>,
    additional_params: Option<&'a std::collections::BTreeMap<String, String>>,
    request_sign_up: Option<bool>,
    additional_data: serde_json::Map<String, serde_json::Value>,
    link: Option<OAuthStateLink>,
    disable_redirect: bool,
}

/// Normalized policy shared by social callbacks and One Tap.
#[derive(Clone, Default)]
pub(crate) struct OAuthProcessPolicy {
    pub(crate) override_user_info: bool,
    pub(crate) require_email_verification: bool,
    pub(crate) callback_url: Option<String>,
    pub(crate) use_updated_user: bool,
}

impl OAuthProcessPolicy {
    const fn for_provider(provider: &OAuthProvider, callback_url: Option<String>) -> Self {
        Self {
            override_user_info: provider.override_user_info_on_sign_in
                && match &provider.authorization {
                    Some(policy) => policy.honor_factory_options,
                    None => true,
                },
            require_email_verification: provider.require_email_verification
                && match &provider.authorization {
                    Some(policy) => policy.honor_factory_options,
                    None => true,
                },
            callback_url,
            use_updated_user: true,
        }
    }
}

/// Authenticate the current request and return the validated session.
async fn require_session<S: alibi_core::AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> Result<alibi_core::SessionView, AuthError> {
    ctx.require_cached_session(req)
        .await
        .map(|(_, session)| session)
}

pub async fn resolve_oauth_account_key(
    provider: &OAuthProvider,
    tokens: &OAuthTokenSet,
    response: &mut OAuthUserInfoResponse,
) -> AuthResult<()> {
    if let Some(resolver) = provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.account_key.as_ref())
    {
        let subject = resolver
            .0
            .resolve(super::providers::OAuthAccountKeyContext {
                tokens: tokens.clone(),
                profile: response.data.clone(),
            })
            .await
            .map_err(AuthError::internal)?;
        response.user.id = super::providers::remaining_profile::raw_subject(Some(&subject))
            .map_err(AuthError::internal)?;
    } else if let Some(subject) = provider.account_subject {
        response.user.id = subject(&response.data).map_err(AuthError::internal)?;
    }
    if response
        .user
        .id
        .trim_matches(super::providers::remaining_profile::js_whitespace)
        .is_empty()
        || matches!(response.user.id.as_str(), "null" | "undefined")
    {
        return Err(AuthError::internal("Invalid provider subject"));
    }
    Ok(())
}

pub fn oauth_callback_path(provider_id: &str, provider: &OAuthProvider) -> String {
    match provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.callback_path.as_deref())
        .filter(|path| !path.is_empty())
    {
        Some(path) if path.starts_with('/') => path.to_owned(),
        Some(path) => format!("/{path}"),
        None => format!("/callback/{provider_id}"),
    }
}
pub fn oauth_disable_sign_up_option(provider: &OAuthProvider) -> Option<bool> {
    provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.disable_sign_up_option)
        .or(provider.disable_sign_up.then_some(true))
}

pub(crate) fn parse_callback_user_payload(
    user_data: Option<&str>,
) -> Option<OAuthCallbackUserPayload> {
    let value: serde_json::Value = serde_json::from_str(user_data?).ok()?;
    Some(OAuthCallbackUserPayload {
        name: value
            .get("name")
            .and_then(|value| value.as_object())
            .map(|name| OAuthCallbackUserName {
                first_name: name
                    .get("firstName")
                    .and_then(|value_2| value_2.as_str())
                    .map(String::from),
                last_name: name
                    .get("lastName")
                    .and_then(|value_3| value_3.as_str())
                    .map(String::from),
            }),
        email: value
            .get("email")
            .and_then(|value| value.as_str())
            .map(String::from),
    })
}

fn raw_truthy(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(false) => false,
        serde_json::Value::Number(number) => number.as_f64() != Some(0.0),
        serde_json::Value::String(value) => !value.is_empty(),
        serde_json::Value::Bool(true)
        | serde_json::Value::Array(_)
        | serde_json::Value::Object(_) => true,
    }
}

/// Mapped provider identity together with its original provenance.
pub(crate) struct OAuthIdentity<'a> {
    pub provider_name: &'a str,
    pub user: &'a OAuthUserInfo,
    pub profile: &'a serde_json::Value,
}

enum LinkSocialOutcome {
    Linked,
    InvalidRawEmail,
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers;

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck respects ctx.context.skipOriginCheck.
    #[tokio::test]
    async fn validate_redirect_target_respects_disable_origin_check() {
        let config = test_helpers::create_test_config().disable_origin_check(true);
        let ctx = test_helpers::create_test_context_with_config(config).await;

        assert!(
            validate_redirect_target("https://evil.com/phish", &ctx, "Invalid callbackURL").is_ok()
        );
    }

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck rejects untrusted origins by default.
    #[tokio::test]
    async fn validate_redirect_target_rejects_untrusted_by_default() {
        let ctx = test_helpers::create_test_context().await;

        assert!(
            validate_redirect_target("https://evil.com/phish", &ctx, "Invalid callbackURL")
                .is_err()
        );
    }

    // Upstream reference: packages/better-auth/src/api/middlewares/origin-check.ts :: originCheck allows relative paths.
    #[tokio::test]
    async fn validate_redirect_target_allows_relative() {
        let ctx = test_helpers::create_test_context().await;

        assert!(validate_redirect_target("/dashboard", &ctx, "Invalid callbackURL").is_ok());
    }

    #[test]
    fn build_redirect_url_preserves_plus_in_path_and_encodes_spaces_in_query() {
        let url = build_redirect_url(
            "http://localhost:3000/api/auth",
            Some("/dashboard+beta"),
            &[("error_description", "space value")],
        )
        .expect("redirect URL should build");

        assert_eq!(
            url,
            "http://localhost:3000/dashboard+beta?error_description=space%20value"
        );
    }
}
// LCOV_EXCL_STOP
