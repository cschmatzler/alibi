//! # Better Auth Core
//!
//! Core abstractions for the Better Auth authentication framework.
//! Contains traits, types, configuration, and error handling.

#![cfg_attr(
    test,
    allow(
        unused_results,
        unreachable_pub,
        reason = "test code intentionally discards setup return values and exposes helpers broadly"
    )
)]

extern crate self as better_auth;

pub mod authenticated_user;
pub mod background_tasks;
pub mod cache;
pub mod config;
pub mod email;
pub mod entity;
pub mod error;
mod error_codes;
pub mod field_policy;
pub mod hooks;
pub mod middleware;
pub mod openapi;
pub mod plugin;
pub mod schema;
pub mod session;
pub mod store;
#[cfg(test)]
pub(crate) mod test_store;
pub mod types;
mod types_org;
mod types_plugin;
#[doc(hidden)]
pub mod user_query;
pub mod utils;
pub mod wire;

// Re-export commonly used items
pub use authenticated_user::AuthenticatedUser;
pub use background_tasks::{BackgroundTaskCompletion, BackgroundTaskHandler};
pub use better_auth_macros::{AuthSchema, PluginConfig};
pub use cache::{
    CacheVersionContext, CacheVersionSource, CookieCacheVersion, CookieCacheVersionResolver,
};
pub use config::{
    AccountConfig, AccountLinkingConfig, AdvancedConfig, AdvancedDatabaseConfig, AuthConfig,
    CookieAttributes, CookieCacheConfig, CookieCacheStrategy, CookieOverride, CrossSubDomainConfig,
    IpAddressConfig, JwtConfig, OAuthStateStrategy, PasswordConfig, SameSite, SessionConfig,
    core_paths, extract_origin,
};
pub use email::{ConsoleEmailProvider, EmailProvider};
pub use entity::{
    AuthAccount, AuthApiKey, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey,
    AuthSession, AuthTwoFactor, AuthUser, AuthVerification, MemberUserView,
};
pub use error::{
    AuthError, AuthResult, DatabaseError, validate_request_body, validation_error_response,
};
pub use hooks::{RequestHookContext, with_request_hook_context, with_request_hook_context_value};
pub use middleware::{
    BodyLimitConfig, BodyLimitMiddleware, CorsConfig, CorsMiddleware, CsrfConfig, CsrfMiddleware,
    EndpointRateLimit, Middleware, RateLimitConfig, RateLimitMiddleware,
};
pub use openapi::{
    OpenApiBuilder, OpenApiEndpoint, OpenApiField, OpenApiInfo, OpenApiModel, OpenApiOperation,
    OpenApiRegistry, OpenApiResponse, OpenApiSpec, PluginOpenApiMetadata,
};
pub use plugin::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRoute, BeforeRequestAction, ContextExtensions,
    VerificationEmailOverride, VerificationEmailOverrideHandle,
};
pub use schema::AuthSchema;
pub use session::SessionManager;
pub use store::{
    AuthStore, AuthTransaction, CacheAdapter, ConsumeApiKeyResult, MemoryCacheAdapter,
    WalletAddressStore, transaction,
};
pub use types::{
    ApiKey, AuthRequest, AuthResponse, CodeMessageResponse, CreateAccount, CreateApiKey,
    CreateDeviceCode, CreateInvitation, CreateMember, CreateOrganization, CreatePasskey,
    CreateSession, CreateTeam, CreateTwoFactor, CreateUser, CreateVerification,
    CreateWalletAddress, DeviceCode, ErrorCodeMessageResponse, ErrorMessageResponse, Headers,
    HealthCheckResponse, HttpMethod, Invitation, InvitationStatus, ListUsersParams, Member,
    OkResponse, Organization, OrganizationPermissions, Passkey, RateLimitErrorResponse,
    RequestMeta, StatusMessageResponse, StatusResponse, SuccessMessageResponse, SuccessResponse,
    Team, TeamMember, TwoFactor, UpdateAccount, UpdateApiKey, UpdateDeviceCode, UpdateOrganization,
    UpdatePasskey, UpdateTeam, UpdateTwoFactor, UpdateUser, UpdateUserRequest, UpdateUserResponse,
    UpdateVerification, UserFilterValue, ValidationErrorResponse, WalletAddress,
};
pub use utils::password::{PasswordHasher, ScryptHasher, hash_password, verify_password};
#[doc(hidden)]
pub use uuid;
pub use wire::{
    AccountView, ApiKeyView, InvitationView, OrganizationView, PasskeyView, SessionView, UserView,
    VerificationView,
};

#[doc(hidden)]
pub use crate as __private_core;

pub use types::{CreateJwk, Jwk};
