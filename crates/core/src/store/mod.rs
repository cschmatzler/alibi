pub use contracts::AdapterAfterHook;
pub use contracts::AdapterEvent;
pub use contracts::SessionCreatedHook;
pub(crate) use contracts::UserCreateTransform;
pub use contracts::UserCreationDefaults;
use contracts::create_data;
pub(crate) use decorated::AdapterCallbacks;
pub(crate) use decorated::PluginStore;
pub(crate) use decorated::SessionCreatedCallbacks;
pub(crate) use decorated::UserTransforms;
mod contracts;
mod decorated;

pub use contracts::AccountStore;
pub use contracts::ApiKeyStore;
pub use contracts::AuthTransaction;
pub use contracts::BoxedTransactionValue;
pub use contracts::ConsumeApiKeyResult;
pub use contracts::DeviceCodeStore;
pub use contracts::InvitationCreateOptions;
pub use contracts::InvitationStore;
pub use contracts::ListOrganizationMembersParams;
pub use contracts::MemberPageQuery;
pub use contracts::MemberStore;
pub use contracts::NumericTextInput;
pub use contracts::OrganizationStore;
pub use contracts::PasskeyStore;
pub use contracts::SessionStore;
pub use contracts::TransactionFuture;
pub use contracts::TransactionStore;
pub use contracts::TransactionWork;
pub use contracts::TwoFactorStore;
pub use contracts::TypedTransactionFuture;
pub use contracts::UserStore;
pub use contracts::VerificationStore;
pub use contracts::transaction;
pub use contracts::verification_reservation_key;
pub mod adapter;
pub mod secondary_storage;
pub mod stateless;

mod database_hooks;
mod migrations;
mod org_extensions;
mod secondary_sessions;

mod jwks;

mod wallets;

use crate::schema::AuthSchema;
pub use database_hooks::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
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
