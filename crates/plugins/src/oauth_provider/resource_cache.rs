//! The pinned provider shares opt-in resource policy by identifier across all contexts.
use alibi_core::store::OAuthResource;
use alibi_core::{AuthContext, AuthResult, AuthSchema};
use std::collections::HashMap;
use std::sync::LazyLock;
use tokio::sync::Mutex;

// Deliberately not scoped to a plugin, store, or initialized application. There
// is no TTL, size bound, or init/seed eviction in the reference implementation.
static RESOURCES: LazyLock<Mutex<HashMap<String, OAuthResource>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) async fn get<S: AuthSchema>(
    ctx: &AuthContext<S>,
    identifier: &str,
    cached: bool,
) -> AuthResult<Option<OAuthResource>> {
    if cached && let Some(row) = RESOURCES.lock().await.get(identifier).cloned() {
        return Ok(Some(row));
    }
    let row = ctx.database.get_oauth_resource(identifier).await?;
    if cached && let Some(row) = &row {
        _ = RESOURCES
            .lock()
            .await
            .insert(identifier.into(), row.clone());
    }
    // Misses are not retained. Rust callers own their values; unlike JS's
    // shallow Object.assign copies, no nested mutable references escape here.
    Ok(row)
}

pub(super) async fn invalidate(identifier: &str) {
    _ = RESOURCES.lock().await.remove(identifier);
}
