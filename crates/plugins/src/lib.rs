//! Built-in authentication plugins for Alibi.

#![cfg_attr(
    test,
    allow(
        unused_results,
        unreachable_pub,
        reason = "test code intentionally discards setup return values and exposes helpers broadly"
    )
)]

#[cfg(all(feature = "native-tls", feature = "rustls"))]
compile_error!(
    "features `native-tls` and `rustls` are mutually exclusive. \
     Enable exactly one of them: \
     for `native-tls` (default), remove the `rustls` feature; \
     for `rustls`, set `default-features = false, features = [\"rustls\"]`."
);

#[cfg(not(any(feature = "native-tls", feature = "rustls")))]
compile_error!(
    "one of the TLS backends must be enabled: \
     enable either the `native-tls` (default) or `rustls` feature."
);

/// Expand to the `OpenAPI` metadata methods of a plugin whose documentation
/// comes entirely from its registered routes.
macro_rules! route_openapi_metadata {
    ($schema:ident) => {
        fn static_openapi_metadata(&self) -> alibi_core::PluginOpenApiMetadata {
            crate::metadata::plugin_metadata(
                <Self as alibi_core::AuthPlugin<$schema>>::name(self),
                &<Self as alibi_core::AuthPlugin<$schema>>::routes(self),
            )
        }

        fn openapi_metadata(
            &self,
            ctx: &alibi_core::AuthInitContext<$schema>,
        ) -> alibi_core::PluginOpenApiMetadata {
            crate::metadata::instance_plugin_metadata(
                <Self as alibi_core::AuthPlugin<$schema>>::name(self),
                &<Self as alibi_core::AuthPlugin<$schema>>::routes(self),
                ctx,
            )
        }
    };
}

pub mod access;
pub mod account_management;
pub mod admin;
pub mod anonymous;
pub mod api_key;
pub(crate) mod authentication_helpers;
pub mod bearer;
pub mod captcha;
pub mod custom_session;
pub mod device_authorization;
pub mod email_otp;
pub mod email_password;
pub mod email_verification;
mod endpoint;
pub mod haveibeenpwned;
pub mod helpers;
pub mod jwt;
pub mod last_login_method;
pub mod magic_link;
pub mod metadata;
pub mod multi_session;
pub mod oauth;
pub mod oauth_popup;
pub mod oauth_proxy;
pub mod oauth_token_conversion;
pub mod one_tap;
pub mod one_time_token;
pub mod open_api;
pub mod organization;
pub mod passkey;
pub mod password_management;
mod passwordless_numeric;
pub mod phone_number;
pub mod session_management;
pub mod siwe;
pub(crate) mod token_crypto;
pub mod two_factor;
pub mod user_management;

// LCOV_EXCL_START
#[cfg(test)]
pub(crate) mod test_helpers {
    use alibi_core::config::AuthConfig;
    use alibi_core::wire::{SessionView, UserView};
    use alibi_core::{AuthContext, AuthRequest, CreateSession, CreateUser, HttpMethod};
    use alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    use alibi_seaorm::{Database, SeaOrmStore};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    pub type TestDatabase = dyn alibi_core::store::AuthStore<BundledSchema>;

    pub fn create_test_config() -> AuthConfig {
        AuthConfig::new("test-secret-key-at-least-32-chars-long")
    }

    pub async fn create_test_database() -> Arc<TestDatabase> {
        let database = Database::connect("sqlite::memory:")
            .await
            .expect("sqlite test database should connect");
        alibi_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .expect("sqlite test migrations should run");
        Arc::new(SeaOrmStore::<BundledSchema>::new(
            Arc::new(create_test_config()),
            database,
        ))
    }

    pub async fn create_test_context() -> AuthContext<BundledSchema> {
        create_test_context_with_config(create_test_config()).await
    }

    pub fn create_test_context_blocking() -> AuthContext<BundledSchema> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime should build")
            .block_on(create_test_context())
    }

    pub async fn create_test_context_with_config(config: AuthConfig) -> AuthContext<BundledSchema> {
        let config = Arc::new(config);
        let database = create_test_database().await;
        AuthContext::new(config, database)
    }

    pub async fn create_user(
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
        create_user: CreateUser,
    ) -> UserView {
        let user = ctx.database.create_user(create_user).await.unwrap();
        UserView::from(&user)
    }

    pub async fn create_session(
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
        user_id: String,
        expires_in: Duration,
    ) -> SessionView {
        let create_session = CreateSession {
            additional_fields: alibi_core::field_policy::FieldValues::default(),
            token: None,
            active_team_id: None,
            user_id,
            expires_at: Utc::now() + expires_in,
            ip_address: Some("127.0.0.1".to_owned()),
            user_agent: Some("test-agent".to_owned()),
            impersonated_by: None,
            active_organization_id: None,
        };
        let session = ctx.database.create_session(create_session).await.unwrap();
        SessionView::from(&session)
    }

    pub async fn create_user_and_session(
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
        user_data: CreateUser,
        session_expires_in: Duration,
    ) -> (UserView, SessionView) {
        let user = create_user(ctx, user_data).await;
        let session = create_session(ctx, user.id.clone(), session_expires_in).await;
        (user, session)
    }

    pub async fn create_test_context_with_user(
        create_user: CreateUser,
        session_expires_in: Duration,
    ) -> (AuthContext<BundledSchema>, UserView, SessionView) {
        let ctx = create_test_context().await;
        let (user, session) = create_user_and_session(&ctx, create_user, session_expires_in).await;
        (ctx, user, session)
    }

    pub fn create_auth_request(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<Vec<u8>>,
        query: HashMap<String, String>,
    ) -> AuthRequest {
        let mut headers = HashMap::new();
        if let Some(token) = token {
            let config = create_test_config();
            headers.insert(
                "cookie".to_owned(),
                format!(
                    "{}={}",
                    config.session.cookie_name,
                    alibi_core::utils::cookie_utils::sign_cookie_value(
                        token,
                        config.current_secret()
                    )
                ),
            );
        }

        AuthRequest::from_parts(method, path.to_owned(), headers, body, query)
    }

    pub fn create_auth_request_no_query(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> AuthRequest {
        create_auth_request(method, path, token, body, HashMap::new())
    }

    pub fn create_auth_json_request_no_query(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> AuthRequest {
        create_auth_json_request(method, path, token, body, HashMap::new())
    }

    pub fn create_auth_json_request(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
        query: HashMap<String, String>,
    ) -> AuthRequest {
        let mut req = create_auth_request(
            method,
            path,
            token,
            body.map(|b| serde_json::to_vec(&b).unwrap()),
            query,
        );
        req.headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        req
    }
}
// LCOV_EXCL_STOP

pub use account_management::AccountManagementPlugin;
pub use admin::{
    AdminBannedUserMessage, AdminBannedUserMessageHandler, AdminConfig, AdminPlugin,
    RolePermissions,
};
pub use alibi_core::PasswordHasher;
pub use anonymous::{
    AnonymousConfig, AnonymousIdentity, AnonymousLink, AnonymousPlugin, LinkAnonymousAccount,
};
pub use api_key::{
    ApiKeyCallbackContext, ApiKeyConfig, ApiKeyDefaultPermissions, ApiKeyErrorMessage,
    ApiKeyGenerationOptions, ApiKeyGenerator, ApiKeyGetter, ApiKeyPermissions, ApiKeyPlugin,
    ApiKeyValidator, DeleteExpiredApiKeysResponse,
};
pub use bearer::{BearerConfig, BearerPlugin};
pub use captcha::{CaptchaConfig, CaptchaPlugin, CaptchaProvider};
pub use custom_session::{CustomSessionPlugin, SessionTransform};
pub use device_authorization::DeviceAuthorizationPlugin;
pub use email_otp::{EmailOtpConfig, EmailOtpPlugin, SendEmailOtp};
pub use email_password::{EmailPasswordConfig, EmailPasswordPlugin};
pub use email_verification::{
    EmailVerificationConfig, EmailVerificationHook, EmailVerificationPlugin, SendVerificationEmail,
};
pub use haveibeenpwned::{HaveIBeenPwnedConfig, HaveIBeenPwnedPlugin, PwnedPasswordClient};
pub use last_login_method::{
    BeforeStoreLastLoginMethodCookie, LastLoginMethodConfig, LastLoginMethodContext,
    LastLoginMethodPlugin, ResolveLastLoginMethod,
};
pub use magic_link::{MagicLinkConfig, MagicLinkPlugin, SendMagicLink};
pub use multi_session::{MultiSessionConfig, MultiSessionPlugin};
pub use oauth::OAuthPlugin;
pub use oauth_popup::OAuthPopupPlugin;
pub use oauth_proxy::{OAuthProxyConfig, OAuthProxyPlugin};
pub use one_tap::{OAuthJwksSource, OneTapClientId, OneTapConfig, OneTapPlugin};
pub use open_api::{OpenApiConfig, OpenApiPlugin};
pub use organization::{
    OrganizationConfig, OrganizationCreatePatch, OrganizationCreatedContext,
    OrganizationCreationHooks, OrganizationDraftContext, OrganizationMemberCreatePatch,
    OrganizationMemberDraftContext, OrganizationPlugin,
};
pub use passkey::{
    AuthenticationResult, PasskeyAuthenticationAfterVerification, PasskeyAuthenticationConfig,
    PasskeyAuthenticationContext, PasskeyAuthenticatorSelection, PasskeyConfig, PasskeyExtensions,
    PasskeyExtensionsResolver, PasskeyOptionsContext, PasskeyPlugin,
    PasskeyRegistrationAfterVerification, PasskeyRegistrationConfig, PasskeyRegistrationContext,
    PasskeyRegistrationOverride, PasskeyRegistrationUser, PasskeyUserResolver,
    VerifiedPasskeyAuthentication, VerifiedPasskeyRegistration,
};
pub use password_management::{
    PasswordManagementConfig, PasswordManagementPlugin, SendResetPassword,
};
pub use phone_number::{PhoneNumberConfig, PhoneNumberPlugin, SendPhoneOtp};
pub use session_management::SessionManagementPlugin;
pub use siwe::{SiweConfig, SiwePlugin};
pub use two_factor::{
    SendTwoFactorOtp, TwoFactorBackupCipher, TwoFactorBackupStorage, TwoFactorConfig,
    TwoFactorOtpCipher, TwoFactorOtpHasher, TwoFactorOtpStorage, TwoFactorPlugin,
};
pub use user_management::{
    ChangeEmailConfig, DeleteUserConfig, SendChangeEmailConfirmation, UserManagementConfig,
    UserManagementPlugin,
};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct StatusResponse {
    status: bool,
}
