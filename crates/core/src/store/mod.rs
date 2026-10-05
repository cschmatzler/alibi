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

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{
    AddTeamMemberResult, CreateJwk, CreateOrganizationRole, CreateTeam, CreateWalletAddress, Jwk,
    OrganizationRole, OrganizationRoleSelector, Team, TeamMember, UpdateOrganizationRole,
    UpdateTeam, WalletAddress,
};
use crate::types::{
    ApiKey, CreateAccount, CreateApiKey, CreateDeviceCode, CreateInvitation, CreateMember,
    CreateOrganization, CreatePasskey, CreateSession, CreateTwoFactor, CreateUser,
    CreateVerification, DeviceCode, Invitation, InvitationStatus, ListUsersParams, Member,
    Organization, Passkey, TwoFactor, UpdateAccount, UpdateApiKey, UpdateDeviceCode,
    UpdateOrganization, UpdatePasskeyAuthentication, UpdateTwoFactor, UpdateUser,
};
use crate::user_validation::{PreparedUserCreation, UserValidationSource, prepare_creation};
use crate::verification::{VerificationCreation, VerificationPublication, VerificationSnapshot};
use async_trait::async_trait;
pub use database_hooks::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
pub use jwks::JwkStore;
pub use migrations::SchemaMigrator;
pub use org_extensions::{OrganizationRoleStore, TeamStore, team_membership_key};
#[cfg(feature = "redis-cache")]
pub use secondary_storage::RedisAdapter;
pub use secondary_storage::{CacheAdapter, MemoryCacheAdapter};
use std::sync::Arc;
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
