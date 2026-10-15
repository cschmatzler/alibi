//! Application-owned client identity resolution for external registries.
use alibi_core::store::OAuthClient;
use alibi_core::{AuthContext, AuthResult, AuthSchema, CallbackContext};
use async_trait::async_trait;
use std::sync::Arc;
/// A stable external source of OAuth clients, matching a contributed TS `ClientDiscovery`.
#[async_trait]
pub trait OAuthClientDiscovery: Send + Sync + std::fmt::Debug {
    /// Stable provenance identifier. Changing this requires migrating owned client rows.
    fn id(&self) -> &str;
    fn matches(&self, client_id: &str) -> bool;
    /// Additive authorization-server and `OpenID` discovery fields.
    /// Later discoveries override earlier fields; provider-owned fields take precedence.
    fn discovery_metadata(&self) -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }
    /// Runtime-owned fetch boundary for remote resources referenced by this registry.
    fn metadata_resource_fetch(&self) -> Option<Arc<dyn super::OAuthClientMetadataResourceFetch>> {
        None
    }

    /// Resolve or refresh a matching identity using the actual initialized callback context.
    /// Returning None for an owned row fails closed rather than treating it as managed.
    async fn resolve(
        &self,
        context: &CallbackContext,
        client_id: &str,
        existing: Option<OAuthClient>,
    ) -> AuthResult<Option<OAuthClient>>;
}
#[derive(Clone)]
pub(super) struct ClientDiscoveries(pub(super) Vec<Arc<dyn OAuthClientDiscovery>>);

pub(super) async fn resolve<S: AuthSchema>(
    ctx: &AuthContext<S>,
    client_id: &str,
) -> AuthResult<Option<OAuthClient>> {
    let discoveries = ctx.extensions.get::<ClientDiscoveries>();
    let configured = discoveries
        .as_ref()
        .map_or(&[][..], |sources| sources.0.as_slice());
    resolve_configured(ctx, client_id, configured).await
}

impl super::OAuthProviderPlugin {
    /// Resolve the raw client for a trusted server caller, including stored credentials.
    /// Equivalent to `getOAuthProviderApi(...).getClient`; callers authorize access.
    pub async fn get_client<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        client_id: &str,
    ) -> AuthResult<Option<OAuthClient>> {
        resolve_configured(ctx, client_id, &self.config.client_discoveries).await
    }
}

async fn resolve_configured<S: AuthSchema>(
    ctx: &AuthContext<S>,
    client_id: &str,
    configured: &[Arc<dyn OAuthClientDiscovery>],
) -> AuthResult<Option<OAuthClient>> {
    let existing = ctx.database.get_oauth_client(client_id).await?;
    if let Some(owner) = existing
        .as_ref()
        .and_then(|client| client.metadata.get("client_discovery_id"))
        .and_then(serde_json::Value::as_str)
        .filter(|owner| !owner.is_empty())
    {
        let Some(discovery) = configured.iter().find(|discovery| discovery.id() == owner) else {
            return Ok(None);
        };
        if !discovery.matches(client_id) {
            return Ok(None);
        }
        return discovery
            .resolve(&CallbackContext::new(ctx, None), client_id, existing)
            .await;
    }
    if existing.is_some() {
        return Ok(existing);
    }
    for discovery in configured {
        if discovery.matches(client_id) {
            let resolved = discovery
                .resolve(&CallbackContext::new(ctx, None), client_id, None)
                .await?;
            if resolved.is_some() {
                return Ok(resolved);
            }
        }
    }
    Ok(None)
}
