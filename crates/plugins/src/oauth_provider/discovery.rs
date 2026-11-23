//! Application-owned client identity resolution for external registries.
use alibi_core::store::OAuthClient;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, CallbackContext};
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

    /// Maximum age in seconds for using cached keys during a transient refresh failure.
    fn jwks_stale_if_error(&self) -> Option<f64> {
        None
    }

    /// Allow a public HTTPS key URL outside the client's origin and trusted origins.
    async fn is_cross_origin_jwks_uri_allowed(
        &self,
        _context: &CallbackContext,
        _client_id: &str,
        _jwks_uri: &str,
    ) -> AuthResult<bool> {
        Ok(false)
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

#[derive(Debug, Default)]
pub(super) struct TrustedCache {
    clients: std::sync::Mutex<std::collections::HashMap<String, OAuthClient>>,
}
impl TrustedCache {
    fn get(&self, id: &str) -> AuthResult<Option<OAuthClient>> {
        Ok(self
            .clients
            .lock()
            .map_err(|_| AuthError::internal("Trusted client cache unavailable"))?
            .get(id)
            .cloned())
    }
    fn set(&self, id: &str, client: OAuthClient) -> AuthResult<()> {
        _ = self
            .clients
            .lock()
            .map_err(|_| AuthError::internal("Trusted client cache unavailable"))?
            .insert(id.into(), client);
        Ok(())
    }
}
#[derive(Clone)]
pub(super) struct TrustedClients {
    pub(super) ids: std::collections::HashSet<String>,
    pub(super) cache: Arc<TrustedCache>,
}
type TrustedView<'a> = (&'a std::collections::HashSet<String>, &'a TrustedCache);

pub(super) async fn resolve<S: AuthSchema>(
    ctx: &AuthContext<S>,
    client_id: &str,
) -> AuthResult<Option<OAuthClient>> {
    let discoveries = ctx.extensions.get::<ClientDiscoveries>();
    let configured = discoveries
        .as_ref()
        .map_or(&[][..], |sources| sources.0.as_slice());
    let trusted = ctx.extensions.get::<TrustedClients>();
    resolve_configured(
        ctx,
        client_id,
        configured,
        trusted
            .as_ref()
            .map(|state| (&state.ids, state.cache.as_ref())),
    )
    .await
}

impl super::OAuthProviderPlugin {
    /// Resolve the raw client for a trusted server caller, including stored credentials.
    /// Equivalent to `getOAuthProviderApi(...).getClient`; callers authorize access.
    pub async fn get_client<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        client_id: &str,
    ) -> AuthResult<Option<OAuthClient>> {
        resolve_configured(
            ctx,
            client_id,
            &self.config.client_discoveries,
            Some((
                &self.config.cached_trusted_clients,
                self.trusted_clients.as_ref(),
            )),
        )
        .await
    }
}

async fn resolve_configured<S: AuthSchema>(
    ctx: &AuthContext<S>,
    client_id: &str,
    configured: &[Arc<dyn OAuthClientDiscovery>],
    trusted: Option<TrustedView<'_>>,
) -> AuthResult<Option<OAuthClient>> {
    if let Some((_, cache)) = trusted
        && let Some(client) = cache.get(client_id)?
        && client
            .metadata
            .get("client_discovery_id")
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Ok(Some(client));
    }
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
    if let Some(client) = existing {
        if let Some((ids, cache)) = trusted
            && ids.contains(client_id)
        {
            cache.set(client_id, client.clone())?;
        }
        return Ok(Some(client));
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

impl super::OAuthProviderPlugin {
    pub(super) fn client_discovery(&self, id: &str) -> Option<&dyn OAuthClientDiscovery> {
        self.config.client_discoveries.iter()
            .find(|source| source.id() == id)
            .map(Arc::as_ref)
    }

    pub(super) async fn allows_discovered_jwks_origin<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        request: Option<&alibi_core::AuthRequest>,
        owner: &str,
        client_id: &str,
        uri: &str,
    ) -> bool {
        if url::Url::parse(client_id).ok().zip(url::Url::parse(uri).ok())
            .is_some_and(|(id, key)| matches!(id.scheme(), "https" | "http") && id.origin() == key.origin())
        {
            return true;
        }
        let Some(discovery) = self.client_discovery(owner) else {
            return false;
        };
        discovery
            .is_cross_origin_jwks_uri_allowed(&CallbackContext::new(ctx, request), client_id, uri)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(%error, owner, "client discovery denied the JWKS origin");
                false
            })
    }
}
