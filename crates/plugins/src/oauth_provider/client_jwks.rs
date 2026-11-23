//! Bounded remote client metadata transport and provider-scoped public-key caching.
use alibi_core::store::OAuthClient;
use alibi_core::{AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, Headers};
use async_trait::async_trait;
use futures_util::future::{BoxFuture, FutureExt, Shared};
use indexmap::IndexMap;
use serde_json::Value;
use std::collections::HashMap;
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
const FRESH_MS: i64 = 300_000;
const DEFAULT_STALE_MS: i64 = 600_000;

#[derive(Clone, Debug)]
struct Entry {
    jwks: Value,
    fetched_at: i64,
    sequence: u64,
    failure: Option<(i64, FetchFailure)>,
}
#[derive(Clone, Copy, Debug)]
enum FetchFailure {
    Invalid,
    Rejected,
    Transient,
    Transport,
    Capacity,
}
type FetchResult = Result<Value, FetchFailure>;
type PendingFetch = Shared<BoxFuture<'static, FetchResult>>;

#[derive(Debug, Default)]
struct CacheState {
    entries: IndexMap<String, Entry>,
    pending: HashMap<String, (u64, i64, PendingFetch)>,
    sequence: u64,
}
#[derive(Debug, Default)]
pub(super) struct Cache(Mutex<CacheState>);
impl Cache {
    fn state(&self) -> AuthResult<std::sync::MutexGuard<'_, CacheState>> {
        self.0.lock().map_err(|_| AuthError::internal("JWKS cache unavailable"))
    }

    pub(super) fn sequence(&self) -> AuthResult<u64> {
        Ok(self.state()?.sequence)
    }

    fn get(&self, key: &str) -> AuthResult<Option<Entry>> {
        let mut state = self.state()?;
        let Some((key, entry)) = state.entries.shift_remove_entry(key) else {
            return Ok(None);
        };
        _ = state.entries.insert(key, entry.clone());
        Ok(Some(entry))
    }

    async fn load(
        &self,
        key: &str,
        uri: &str,
        fetcher: Option<Arc<dyn OAuthClientMetadataResourceFetch>>,
        min_sequence: u64,
    ) -> AuthResult<FetchResult> {
        let mut retry = false;
        loop {
            let (sequence, started, pending, joined) = {
                let mut state = self.state()?;
                if let Some((sequence, started, fetch)) = state.pending.get(key)
                    && *sequence >= min_sequence
                {
                    (*sequence, *started, fetch.clone(), true)
                } else {
                    let sequence = state.sequence;
                    state.sequence += 1;
                    let uri = uri.to_owned();
                    let fetcher = fetcher.clone();
                    let pending = async move {
                        tokio::time::timeout(
                            std::time::Duration::from_secs(6),
                            fetch(&uri, fetcher),
                        ).await.unwrap_or(Err(FetchFailure::Transport))
                    }.boxed().shared();
                    let started = chrono::Utc::now().timestamp_millis();
                    state.pending.retain(|_, (_, started_at, _)| started.saturating_sub(*started_at) < 6_000);
                    _ = state.pending.insert(key.to_owned(), (sequence, started, pending.clone()));
                    (sequence, started, pending, false)
                }
            };
            let result = pending.await;
            let mut state = self.state()?;
            if state.pending.get(key).is_some_and(|(current, _, _)| *current == sequence) {
                _ = state.pending.remove(key);
                match &result {
                    Ok(jwks) => {
                        _ = state.entries.shift_remove(key);
                        _ = state.entries.insert(key.to_owned(), Entry {
                            jwks: jwks.clone(), fetched_at: started, sequence, failure: None,
                        });
                        if state.entries.len() > 500 {
                            _ = state.entries.shift_remove_index(0);
                        }
                    }
                    Err(FetchFailure::Capacity) => {}
                    Err(failure) => {
                        if let Some(entry) = state.entries.get_mut(key)
                            && entry.sequence <= sequence
                            && (!matches!(entry.failure, Some((_, FetchFailure::Invalid | FetchFailure::Rejected)))
                                || matches!(failure, FetchFailure::Invalid | FetchFailure::Rejected))
                        {
                            entry.failure = Some((chrono::Utc::now().timestamp_millis(), *failure));
                        }
                    }
                }
            }
            if !joined || result.is_ok() || retry {
                return Ok(result);
            }
            retry = true;
        }
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
pub(super) async fn get<S: AuthSchema>(
    ctx: &AuthContext<S>,
    provider: &super::OAuthProviderPlugin,
    client: &OAuthClient,
    request: Option<&AuthRequest>,
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
    let discovery = owner(client).and_then(|id| provider.client_discovery(id));
    let fetcher = discovery.and_then(super::OAuthClientDiscovery::metadata_resource_fetch);
    if owner(client).is_some() && fetcher.is_none() {
        return Ok(Err("client discovery does not provide a metadata resource transport"));
    }
    if let Some(error) = super::clients::remote_key_uri_error(uri) {
        return Ok(Err(error));
    }
    if !ctx.config.is_redirect_target_trusted(uri) {
        let trusted = match owner(client) {
            Some(id) => provider.allows_discovered_jwks_origin(
                ctx, request, id, &client.client_id, uri,
            ).await,
            None => false,
        };
        if !trusted {
            return Ok(Err("client jwks_uri is not trusted"));
        }
    }

    let now = chrono::Utc::now().timestamp_millis();
    let key = cache_key(client, uri);
    let cache = &provider.client_jwks;
    let cached = cache.get(&key)?;
    let stale_ms = discovery
        .and_then(super::OAuthClientDiscovery::jwks_stale_if_error)
        .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
        .map_or(0.0, |seconds| seconds.min(86_400.0) * 1000.0);
    if let Some(entry) = &cached {
        let age = now.saturating_sub(entry.fetched_at);
        if age < FRESH_MS || (age >= DEFAULT_STALE_MS && age as f64 <= stale_ms
            && matches!(entry.failure, Some((failed_at, FetchFailure::Transient))
                if now.saturating_sub(failed_at) < 60_000))
        {
            return Ok(Ok(entry.jwks.clone()));
        }
    }
    match cache.load(&key, uri, fetcher, 0).await? {
        Ok(jwks) => Ok(Ok(jwks)),
        Err(failure) => Ok(cached.filter(|entry| {
            if matches!(failure, FetchFailure::Invalid) {
                return false;
            }
            let age = now.saturating_sub(entry.fetched_at);
            let failed_at = chrono::Utc::now().timestamp_millis();
            let transient = match failure {
                FetchFailure::Transient => !matches!(
                    entry.failure, Some((_, FetchFailure::Invalid | FetchFailure::Rejected))
                ),
                FetchFailure::Capacity => matches!(
                    entry.failure,
                    Some((previous, FetchFailure::Transient)) if failed_at.saturating_sub(previous) <= FRESH_MS
                ),
                _ => false,
            };
            age < DEFAULT_STALE_MS
                || (transient && failed_at.saturating_sub(entry.fetched_at) as f64 <= stale_ms)
        }).map(|entry| entry.jwks).ok_or(FETCH_ERROR)),
    }
}
pub(super) async fn refetch(
    provider: &super::OAuthProviderPlugin,
    client: &OAuthClient,
    min_sequence: u64,
) -> AuthResult<Option<Value>> {
    let Some(uri) = uri(client) else {
        return Ok(None);
    };
    let fetcher = owner(client).and_then(|id| provider.client_discovery(id))
        .and_then(super::OAuthClientDiscovery::metadata_resource_fetch);
    if owner(client).is_some() && fetcher.is_none() {
        return Ok(None);
    }
    Ok(provider.client_jwks.load(&cache_key(client, uri), uri, fetcher, min_sequence)
        .await?.ok())
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
) -> FetchResult {
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
                    redirect: "manual",
                    signal: signal.clone(),
                },
            )
            .await
            .map_err(|error| transport_failure(&error, signal.aborted()))?
    } else {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| transport_failure(&error, signal.aborted()))?;
        OAuthClientMetadataFetchResponse {
            response: client
                .get(uri)
                .header("accept", "application/json")
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
                .map_err(|error| transport_failure(&error, signal.aborted()))?,
            redirected: false,
        }
    };
    let status = response.response.status().as_u16();
    if response.redirected {
        return Err(FetchFailure::Rejected);
    }
    if matches!(status, 500 | 502 | 503 | 504) {
        return Err(FetchFailure::Transient);
    }
    if status != 200 {
        return Err(FetchFailure::Rejected);
    }
    let Some(content_type) = header(&response.response, "content-type") else {
        return Err(FetchFailure::Rejected);
    };
    if !json_content_type(&content_type) {
        return Err(FetchFailure::Rejected);
    }
    if header(&response.response, "content-length")
        .as_deref()
        .and_then(alibi_core::utils::javascript::string_to_number)
        .is_some_and(|length| length.is_finite() && length > 65_536.0)
    {
        return Err(FetchFailure::Rejected);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.response.chunk().await.map_err(|error| transport_failure(&error, signal.aborted()))? {
        if bytes.len().saturating_add(chunk.len()) > MAX_BYTES {
            return Err(FetchFailure::Rejected);
        }
        bytes.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let Ok(parsed) =
        alibi_core::utils::json::parse_value(text).and_then(|value| value.to_json_value())
    else {
        return Err(FetchFailure::Invalid);
    };
    let valid = parsed
        .get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| !keys.is_empty() && keys.iter().all(Value::is_object))
        && super::clients::public_jwks_error(&parsed).is_none();
    valid.then_some(parsed).ok_or(FetchFailure::Invalid)
}
fn transport_failure(
    error: &(dyn std::error::Error + 'static),
    aborted: bool,
) -> FetchFailure {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.downcast_ref::<reqwest::Error>().is_some_and(reqwest::Error::is_timeout)
            || error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                use std::io::ErrorKind;
                matches!(error.kind(), ErrorKind::ConnectionReset | ErrorKind::ConnectionRefused
                    | ErrorKind::TimedOut | ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable
                    | ErrorKind::BrokenPipe)
            })
        {
            return FetchFailure::Transient;
        }
        if let Some(AuthError::Api { code: Some(code), .. }) = error.downcast_ref::<AuthError>()
            && (matches!(code.as_str(), "EAI_AGAIN" | "ECONNRESET" | "ECONNREFUSED"
                | "ETIMEDOUT" | "EHOSTUNREACH" | "ENETUNREACH" | "EPIPE"
                | "UND_ERR_CONNECT_TIMEOUT" | "UND_ERR_HEADERS_TIMEOUT"
                | "UND_ERR_BODY_TIMEOUT" | "UND_ERR_SOCKET")
                || (aborted && code == "ERR_CIMD_REQUEST_ABORTED"))
        {
            return FetchFailure::Transient;
        }
        if matches!(error.downcast_ref::<AuthError>(),
            Some(AuthError::Api { code: Some(code), .. }) if code == "ERR_CIMD_DNS_LOOKUP_LIMIT")
        {
            return FetchFailure::Capacity;
        }
        current = error.source();
    }
    FetchFailure::Transport
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
