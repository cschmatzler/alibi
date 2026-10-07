//! Built-in plugins and plugin-specific configuration modules.

pub use alibi_api::OAuthPlugin;
pub use alibi_api::plugins::access;
pub use alibi_api::plugins::anonymous::{
    self, AnonymousConfig, AnonymousIdentity, AnonymousLink, AnonymousPlugin, LinkAnonymousAccount,
};
pub use alibi_api::plugins::api_key::{
    ApiKeyCallbackContext, ApiKeyDefaultPermissions, ApiKeyErrorMessage, ApiKeyGenerationOptions,
    ApiKeyGenerator, ApiKeyGetter, ApiKeyPermissions, ApiKeyValidator,
    DeleteExpiredApiKeysResponse,
};
pub use alibi_api::plugins::bearer::{self, BearerConfig, BearerPlugin};
pub use alibi_api::plugins::captcha::{self, CaptchaConfig, CaptchaPlugin, CaptchaProvider};
pub use alibi_api::plugins::custom_session::{self, CustomSessionPlugin, SessionTransform};
pub use alibi_api::plugins::email_otp::{EmailOtpConfig, EmailOtpPlugin, SendEmailOtp};
pub use alibi_api::plugins::email_verification::SendVerificationEmail;
pub use alibi_api::plugins::haveibeenpwned::{
    self, HaveIBeenPwnedConfig, HaveIBeenPwnedPlugin, PwnedPasswordClient,
};
pub use alibi_api::plugins::last_login_method::{
    self, BeforeStoreLastLoginMethodCookie, LastLoginMethodConfig, LastLoginMethodContext,
    LastLoginMethodPlugin, ResolveLastLoginMethod,
};
pub use alibi_api::plugins::magic_link::{MagicLinkConfig, MagicLinkPlugin, SendMagicLink};
pub use alibi_api::plugins::multi_session::{self, MultiSessionConfig, MultiSessionPlugin};
pub use alibi_api::plugins::oauth_popup::{self, OAuthPopupPlugin};
pub use alibi_api::plugins::oauth_token_conversion;
pub use alibi_api::plugins::one_tap::{
    self, OAuthJwksSource, OneTapClientId, OneTapConfig, OneTapPlugin,
};
pub use alibi_api::plugins::open_api::{self, OpenApiConfig, OpenApiPlugin};
pub use alibi_api::plugins::passkey::{
    AuthenticationResult, PasskeyAuthenticationAfterVerification, PasskeyAuthenticationConfig,
    PasskeyAuthenticationContext, PasskeyRegistrationAfterVerification, PasskeyRegistrationConfig,
    PasskeyRegistrationContext, PasskeyRegistrationOverride, PasskeyRegistrationUser,
    PasskeyUserResolver, VerifiedPasskeyAuthentication, VerifiedPasskeyRegistration,
};
pub use alibi_api::plugins::password_management::SendResetPassword;
pub use alibi_api::plugins::phone_number::{PhoneNumberConfig, PhoneNumberPlugin, SendPhoneOtp};
pub use alibi_api::plugins::two_factor::{
    SendTwoFactorOtp, TwoFactorBackupCipher, TwoFactorBackupStorage, TwoFactorOtpCipher,
    TwoFactorOtpHasher, TwoFactorOtpStorage,
};
pub use alibi_api::plugins::user_management::SendChangeEmailConfirmation;
pub use alibi_api::plugins::{
    AccountManagementPlugin, AdminBannedUserMessage, AdminBannedUserMessageHandler, AdminConfig,
    AdminPlugin, ApiKeyConfig, ApiKeyPlugin, ChangeEmailConfig, DeleteUserConfig,
    DeviceAuthorizationPlugin, EmailPasswordConfig, EmailPasswordPlugin, EmailVerificationConfig,
    EmailVerificationHook, EmailVerificationPlugin, OrganizationConfig, OrganizationPlugin,
    PasskeyConfig, PasskeyPlugin, PasswordManagementConfig, PasswordManagementPlugin,
    RolePermissions, SessionManagementPlugin, TwoFactorConfig, TwoFactorPlugin,
    UserManagementConfig, UserManagementPlugin, account_management, admin, api_key,
    device_authorization, email_otp, email_password, email_verification, jwt, magic_link, oauth,
    oauth_proxy, one_time_token, organization, passkey, password_management, phone_number,
    session_management, two_factor, user_management,
};
pub use alibi_api::plugins::{SiweConfig, SiwePlugin, siwe};
pub use alibi_api::{OAuthProxyConfig, OAuthProxyPlugin};
