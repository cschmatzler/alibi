//! Bounded remote client metadata transport and provider-scoped public-key caching.
use alibi_core::store::OAuthClient;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, Headers};
use async_trait::async_trait;
use indexmap::IndexMap;
use serde_json::Value;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::watch;

/// Cancellation exposed to an application-owned client metadata transport.
#[derive(Clone, Debug)]
pub struct OAuthClientMetadataAbortSignal {
    receiver: watch::Receiver<bool>,
    _keepalive: watch::Sender<bool>,
}
impl OAuthClientMetadataAbortSignal {
    #[must_use]
    pub fn aborted(&self) -> bool {
        *self.receiver.borrow()
    }
    /// Wait until the resource request's abort signal fires.
    pub async fn cancelled(&self) {
        let mut receiver = self.receiver.clone();
        loop {
            let aborted = *receiver.borrow_and_update();
            if aborted || receiver.changed().await.is_err() {
                return;
            }
        }
    }
}
/// Actual options supplied to a configured metadata resource fetch callback.
#[derive(Clone, Debug)]
pub struct OAuthClientMetadataFetchOptions {
    pub headers: Headers,
    pub redirect: &'static str,
    pub signal: OAuthClientMetadataAbortSignal,
}
/// A streaming HTTP response and its redirect history, matching a fetch Response.
#[derive(Debug)]
pub struct OAuthClientMetadataFetchResponse {
    pub response: reqwest::Response,
    pub redirected: bool,
}
/// Application-owned network boundary for a discovered client's referenced resources.
#[async_trait]
pub trait OAuthClientMetadataResourceFetch: Send + Sync + std::fmt::Debug {
    async fn fetch(
        &self,
        url: &str,
        options: OAuthClientMetadataFetchOptions,
    ) -> AuthResult<OAuthClientMetadataFetchResponse>;
}

const FETCH_ERROR: &str = "failed to fetch client JWKS";
const MAX_BYTES: usize = 64 * 1024;
#[derive(Clone, Debug)]
struct Entry {
    jwks: Value,
    fetched_at: i64,
}
#[derive(Debug, Default)]
pub(super) struct Cache {
    entries: Mutex<IndexMap<String, Entry>>,
}
impl Cache {
    fn get(&self, key: &str) -> AuthResult<Option<Entry>> {
        Ok(self
            .entries
            .lock()
            .map_err(|_| AuthError::internal("JWKS cache unavailable"))?
            .get(key)
            .cloned())
    }
    fn set(&self, key: String, jwks: Value, fetched_at: i64) -> AuthResult<()> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| AuthError::internal("JWKS cache unavailable"))?;
        _ = entries.insert(key, Entry { jwks, fetched_at });
        if entries.len() > 500 {
            _ = entries.shift_remove_index(0);
        }
        Ok(())
    }
}
fn owner(client: &OAuthClient) -> Option<&str> {
    client
        .metadata
        .get("client_discovery_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
}
fn uri(client: &OAuthClient) -> Option<&str> {
    client
        .metadata
        .get("jwks_uri")
        .and_then(Value::as_str)
        .filter(|uri| !uri.is_empty())
}
fn cache_key(client: &OAuthClient, uri: &str) -> String {
    format!(
        "{}:{uri}",
        client
            .metadata
            .get("client_discovery_id")
            .and_then(Value::as_str)
            .unwrap_or("managed")
    )
}
fn transport(
    provider: &super::OAuthProviderPlugin,
    client: &OAuthClient,
) -> Option<Arc<dyn OAuthClientMetadataResourceFetch>> {
    let id = owner(client)?;
    provider
        .config
        .client_discoveries
        .iter()
        .find(|source| source.id() == id)?
        .metadata_resource_fetch()
}
fn validate_uri<S: AuthSchema>(
    ctx: &AuthContext<S>,
    client: &OAuthClient,
    uri: &str,
) -> AuthResult<Result<(), &'static str>> {
    let parsed =
        url::Url::parse(uri).map_err(|_| AuthError::internal("Invalid client JWKS URL"))?;
    if parsed.scheme() != "https" {
        return Ok(Err("jwks_uri must use HTTPS"));
    }
    if !parsed.username().is_empty()
        || parsed
            .password()
            .is_some_and(|password| !password.is_empty())
    {
        return Ok(Err("jwks_uri must not contain credentials"));
    }
    if parsed.fragment().is_some() {
        return Ok(Err("jwks_uri must not include a fragment component"));
    }
    if !crate::sso::endpoint_host::public(parsed.host_str().unwrap_or_default()) {
        return Ok(Err(
            "jwks_uri must not point to a private or reserved address",
        ));
    }
    if owner(client).is_some()
        && url::Url::parse(&client.client_id).is_ok_and(|id| {
            matches!(id.scheme(), "https" | "http") && id.origin() == parsed.origin()
        })
    {
        return Ok(Ok(()));
    }
    if !ctx.config.is_redirect_target_trusted(uri) {
        return Ok(Err("client jwks_uri is not trusted"));
    }
    Ok(Ok(()))
}
pub(super) async fn get<S: AuthSchema>(
    ctx: &AuthContext<S>,
    provider: &super::OAuthProviderPlugin,
    client: &OAuthClient,
) -> AuthResult<Result<Value, &'static str>> {
    if let Some(inline) = client
        .metadata
        .get("jwks")
        .filter(|value| !value.is_null() && *value != "")
    {
        return Ok(Ok(if let Some(raw) = inline.as_str() {
            alibi_core::utils::json::parse_value(raw)
                .map_err(|_| AuthError::internal("Invalid stored client JWKS"))?
                .to_json_value()?
        } else {
            inline.clone()
        }));
    }
    let Some(uri) = uri(client) else {
        return Ok(Err("client has no JWKS configured"));
    };
    let fetcher = transport(provider, client);
    if owner(client).is_some() && fetcher.is_none() {
        return Ok(Err(
            "client discovery does not provide a metadata resource transport",
        ));
    }
    if let Err(description) = validate_uri(ctx, client, uri)? {
        return Ok(Err(description));
    }
    let now = chrono::Utc::now().timestamp_millis();
    let key = cache_key(client, uri);
    let cache = provider.client_jwks.clone();
    let cached = cache.get(&key)?;
    if let Some(entry) = &cached
        && now.saturating_sub(entry.fetched_at) < 300_000
    {
        return Ok(Ok(entry.jwks.clone()));
    }
    match fetch(uri, fetcher).await {
        Ok(Some(jwks)) => {
            cache.set(key, jwks.clone(), now)?;
            Ok(Ok(jwks))
        }
        Ok(None) => Ok(Err(FETCH_ERROR)),
        Err(()) => Ok(
            if let Some(entry) =
                cached.filter(|entry| now.saturating_sub(entry.fetched_at) < 600_000)
            {
                Ok(entry.jwks)
            } else {
                Err(FETCH_ERROR)
            },
        ),
    }
}
pub(super) async fn refetch(
    provider: &super::OAuthProviderPlugin,
    client: &OAuthClient,
) -> AuthResult<Option<Value>> {
    let Some(uri) = uri(client) else {
        return Ok(None);
    };
    let fetcher = transport(provider, client);
    if owner(client).is_some() && fetcher.is_none() {
        return Ok(None);
    }
    let Ok(Some(jwks)) = fetch(uri, fetcher).await else {
        return Ok(None);
    };
    provider.client_jwks.set(
        cache_key(client, uri),
        jwks.clone(),
        chrono::Utc::now().timestamp_millis(),
    )?;
    Ok(Some(jwks))
}
struct AbortTimer(tokio::task::JoinHandle<()>);
impl Drop for AbortTimer {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn fetch(
    uri: &str,
    transport: Option<Arc<dyn OAuthClientMetadataResourceFetch>>,
) -> Result<Option<Value>, ()> {
    let (sender, receiver) = watch::channel(false);
    let signal = OAuthClientMetadataAbortSignal {
        receiver,
        _keepalive: sender.clone(),
    };
    let _timer = AbortTimer(tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        _ = sender.send(true);
    }));
    let mut response = if let Some(transport) = transport {
        let mut headers = Headers::new();
        _ = headers.insert("accept", "application/json");
        transport
            .fetch(
                uri,
                OAuthClientMetadataFetchOptions {
                    headers,
                    redirect: "error",
                    signal,
                },
            )
            .await
            .map_err(|_| ())?
    } else {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ())?;
        OAuthClientMetadataFetchResponse {
            response: client
                .get(uri)
                .header("accept", "application/json")
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
                .map_err(|_| ())?,
            redirected: false,
        }
    };
    if response.redirected || response.response.status() != reqwest::StatusCode::OK {
        return Err(());
    }
    let Some(content_type) = header(&response.response, "content-type") else {
        return Err(());
    };
    if !json_content_type(&content_type) {
        return Err(());
    }
    if header(&response.response, "content-length")
        .as_deref()
        .and_then(alibi_core::utils::javascript::string_to_number)
        .is_some_and(|length| length.is_finite() && length > 65_536.0)
    {
        return Err(());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.response.chunk().await.map_err(|_| ())? {
        if bytes.len().saturating_add(chunk.len()) > MAX_BYTES {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let Ok(parsed) =
        alibi_core::utils::json::parse_value(text).and_then(|value| value.to_json_value())
    else {
        return Ok(None);
    };
    let valid = parsed
        .get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| !keys.is_empty() && keys.iter().all(Value::is_object))
        && super::clients::public_jwks_error(&parsed).is_none();
    Ok(valid.then_some(parsed))
}
fn header(response: &reqwest::Response, name: &str) -> Option<String> {
    let values = response
        .headers()
        .get_all(name)
        .iter()
        .map(|value| {
            value.to_str().map_or_else(
                |_| {
                    value
                        .as_bytes()
                        .iter()
                        .map(|byte| char::from(*byte))
                        .collect()
                },
                str::to_owned,
            )
        })
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| {
        values
            .join(", ")
            .trim_matches([' ', '\t', '\r', '\n'])
            .to_owned()
    })
}
fn json_content_type(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    let Some(subtype) = value.strip_prefix("application/") else {
        return false;
    };
    let subtype = subtype
        .split(';')
        .next()
        .unwrap_or_default()
        .trim_end_matches(alibi_core::utils::javascript::is_whitespace);
    subtype == "json"
        || subtype.strip_suffix("+json").is_some_and(|prefix| {
            !prefix.is_empty()
                && prefix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}
