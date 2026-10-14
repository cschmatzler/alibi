pub mod adapter;
mod contracts;
mod database_hooks;
mod decorated;
mod jwks;
mod migrations;
pub mod oauth_clients;
mod org_extensions;
mod secondary_sessions;
pub mod secondary_storage;
mod session_deletion;
mod sso;
pub mod stateless;
mod wallets;
use crate::schema::AuthSchema;
pub(crate) use contracts::UserCreateTransform;
use contracts::create_data;
pub use contracts::{
    AccountStore, AdapterAfterHook, AdapterEvent, AfterCommitErrorPolicy, ApiKeyStore,
    AuthTransaction, BoxedTransactionValue, ConsumeApiKeyResult, DeviceCodeStore,
    InvitationCreateOptions, InvitationStore, ListOrganizationMembersParams, MemberPageQuery,
    MemberStore, NumericTextInput, OrganizationStore, PasskeyStore, SessionCreatedHook,
    SessionStore, TransactionFuture, TransactionStore, TransactionWork, TwoFactorStore,
    TypedTransactionFuture, UserCreationDefaults, UserStore, VerificationStore, transaction,
    transaction_with_policy, verification_reservation_key,
};
pub use database_hooks::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
pub(crate) use decorated::{
    AdapterCallbacks, PluginStore, SessionCreatedCallbacks, UserTransforms,
};
pub use jwks::JwkStore;
pub use migrations::SchemaMigrator;
pub use oauth_clients::{
    CreateOAuthClient, CreateOAuthClientResource, CreateOAuthConsent, CreateOAuthResource,
    CreateOAuthToken, OAuthClient, OAuthClientResource, OAuthClientStore, OAuthConsent,
    OAuthResource, OAuthToken, OAuthTokenKind,
};
pub use org_extensions::{OrganizationRoleStore, TeamStore, team_membership_key};
#[cfg(feature = "redis-cache")]
pub use secondary_storage::RedisAdapter;
pub use secondary_storage::{CacheAdapter, MemoryCacheAdapter};
pub(crate) use session_deletion::SessionDeletionHooks;
pub use session_deletion::{SessionDeletionHook, SessionDeletionWork};
pub use sso::{SsoProvider, SsoProviderStore, SsoProviderUpdate, SsoProviderUpdateWork};
pub use wallets::WalletAddressStore;

pub trait AuthStore<S: AuthSchema>:
    UserStore<S>
    + SessionStore<S>
    + AccountStore<S>
    + VerificationStore<S>
    + OrganizationStore
    + MemberStore
    + InvitationStore
    + OAuthClientStore
    + SsoProviderStore
    + TeamStore
    + OrganizationRoleStore
    + WalletAddressStore
    + TwoFactorStore
    + ApiKeyStore
    + PasskeyStore
    + DeviceCodeStore
    + JwkStore
    + TransactionStore<S>
    + Send
    + Sync
{
}

impl<S, T> AuthStore<S> for T
where
    S: AuthSchema,
    T: UserStore<S>
        + SessionStore<S>
        + AccountStore<S>
        + VerificationStore<S>
        + OrganizationStore
        + MemberStore
        + InvitationStore
        + OAuthClientStore
        + SsoProviderStore
        + TeamStore
        + OrganizationRoleStore
        + WalletAddressStore
        + TwoFactorStore
        + ApiKeyStore
        + PasskeyStore
        + DeviceCodeStore
        + JwkStore
        + TransactionStore<S>
        + Send
        + Sync,
{
}
