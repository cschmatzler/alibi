//! Storage traits and cache adapters used by Alibi.

#[cfg(feature = "redis-cache")]
pub use better_auth_core::store::RedisAdapter;
pub use better_auth_core::store::WalletAddressStore;
pub use better_auth_core::store::stateless::{StatelessSchema, StatelessStore};
pub use better_auth_core::store::{
    AuthStore, AuthTransaction, CacheAdapter, MemoryCacheAdapter, transaction,
};
pub use better_auth_core::store::{
    DatabaseHookContext, DatabaseHooks, HookBackend, HookControl, SchemaMigrator,
};
// Direct adapter operations use the same contracts as the plugin runtime.
pub use better_auth_core::store::{InvitationStore, MemberStore, OrganizationStore, SessionStore};
