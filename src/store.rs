//! Storage traits and cache adapters used by Alibi.

#[cfg(feature = "redis-cache")]
pub use alibi_core::store::RedisAdapter;
pub use alibi_core::store::WalletAddressStore;
pub use alibi_core::store::stateless::{StatelessSchema, StatelessStore};
pub use alibi_core::store::*;
pub use alibi_core::store::{
    AuthStore, AuthTransaction, CacheAdapter, MemoryCacheAdapter, transaction,
};
pub use alibi_core::store::{
    DatabaseHookContext, DatabaseHooks, HookBackend, HookControl, SchemaMigrator,
};
// Direct adapter operations use the same contracts as the plugin runtime.
pub use alibi_core::store::{InvitationStore, MemberStore, OrganizationStore, SessionStore};
