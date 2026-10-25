pub mod adapter;
mod contracts;
mod database_hooks;
mod decorated;
mod jwks;
mod migrations;
pub mod oauth_clients;
mod org_extensions;
pub mod scim;
mod scim_group_patch;
pub use scim_group_patch::{
    ScimGroupPatch, ScimGroupPatchKind, ScimGroupPatchOperation, apply_scim_group_patch,
    check_scim_group_cardinality, prepare_scim_group_patch,
};
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
    transaction_with_policy, verification_reservation_id, verification_reservation_key,
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
pub use scim::{
    CreateScimGroup, CreateScimManagedConnection, CreateScimProjectionGrant, CreateScimUser,
    DecommissionScimManagedConnection, ReplaceScimGroup, ReplaceScimUser,
    RevokeScimManagedCredential, RotateScimManagedCredential, ScimAuthorizationSource,
    ScimConnectionBinding, ScimGroupMemberRecord, ScimGroupMemberships, ScimGroupPage,
    ScimGroupRecord, ScimIdentitySource, ScimIdentityState, ScimIdentityTombstone,
    ScimManagedConnection, ScimManagedConnectionEvent, ScimManagedConnectionState,
    ScimManagedCreation, ScimManagedCredential, ScimManagedStore, ScimProjectedUserState,
    ScimProjectionCandidate, ScimProjectionPreparedUser, ScimRoleExistenceInput,
    ScimRoleMappingInput, ScimUserAttributes, ScimUserMutationContext, ScimUserPage,
    ScimUserRecord, scim_group_membership_key,
};
#[cfg(feature = "redis-cache")]
pub use secondary_storage::RedisAdapter;
pub use secondary_storage::{CacheAdapter, MemoryCacheAdapter};
pub(crate) use session_deletion::SessionDeletionHooks;
pub use session_deletion::{SessionDeletionHook, SessionDeletionWork};
pub use sso::{
    SsoFieldType, SsoProvider, SsoProviderStore, SsoProviderUpdate, SsoProviderUpdateWork,
    prepare_sso_fields, project_sso_provider, sso_field_column, sso_field_definition,
    validate_sso_fields,
};
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
    + ScimManagedStore
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
        + ScimManagedStore
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
