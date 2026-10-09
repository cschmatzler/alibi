pub mod adapter;
mod contracts;
mod database_hooks;
mod decorated;
mod jwks;
mod migrations;
mod org_extensions;
mod secondary_sessions;
pub mod secondary_storage;
pub mod stateless;
mod wallets;

use crate::schema::AuthSchema;
pub(crate) use contracts::UserCreateTransform;
use contracts::create_data;
pub use contracts::{
    AccountStore, AdapterAfterHook, AdapterEvent, ApiKeyStore, AuthTransaction,
    BoxedTransactionValue, ConsumeApiKeyResult, DeviceCodeStore, InvitationCreateOptions,
    InvitationStore, ListOrganizationMembersParams, MemberPageQuery, MemberStore, NumericTextInput,
    OrganizationStore, PasskeyStore, SessionCreatedHook, SessionStore, TransactionFuture,
    TransactionStore, TransactionWork, TwoFactorStore, TypedTransactionFuture,
    UserCreationDefaults, UserStore, VerificationStore, transaction, verification_reservation_key,
};
pub use database_hooks::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
pub(crate) use decorated::{
    AdapterCallbacks, PluginStore, SessionCreatedCallbacks, UserTransforms,
};
pub use jwks::JwkStore;
pub use migrations::SchemaMigrator;
pub use org_extensions::{OrganizationRoleStore, TeamStore, team_membership_key};
#[cfg(feature = "redis-cache")]
pub use secondary_storage::RedisAdapter;
pub use secondary_storage::{CacheAdapter, MemoryCacheAdapter};
pub use wallets::WalletAddressStore;

pub trait AuthStore<S: AuthSchema>:
    UserStore<S>
    + SessionStore<S>
    + AccountStore<S>
    + VerificationStore<S>
    + OrganizationStore
    + MemberStore
    + InvitationStore
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
