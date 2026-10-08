use super::*;
/// HTTP method enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Options,
    Head,
}

/// Authentication request wrapper
#[derive(Debug, Clone)]
#[expect(
    clippy::partial_pub_fields,
    reason = "Public request fields preserve the API while parsed query values are maintained through request helpers"
)]
pub struct AuthRequest {
    pub method: HttpMethod,
    pub path: String,
    pub(in crate::types) request_url: Option<url::Url>,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub query: HashMap<String, String>,
    pub(in crate::types) query_values: HashMap<String, Vec<String>>,
    /// Session authenticated by a trusted plugin hook for the current request.
    pub(crate) virtual_session: Option<crate::wire::SessionView>,
    /// Headers emitted by trusted nested handlers during this dispatch.
    pub(in crate::types) response_headers: Arc<Mutex<Headers>>,
    /// The original store snapshot retained for completed-handler hooks.
    pub(in crate::types) session_hook_snapshot:
        Arc<Mutex<Option<(crate::wire::UserView, crate::wire::SessionView)>>>,
    pub(in crate::types) extensions: RequestExtensions,
}

/// Typed state shared only by trusted handlers in one request dispatch.
///
/// Request clones share these values. Public dispatch starts with a fresh
/// instance, so fields supplied by an embedding caller never become authority.
#[derive(Clone, Default)]
pub struct RequestExtensions(Arc<Mutex<crate::plugin::ContextExtensions>>);

/// Body decoded by trusted dispatch after its media policy has been checked.
/// Original request bytes and headers remain available to application hooks.
#[derive(Clone, Debug)]
pub enum ParsedRequestBody {
    Value(crate::utils::json::JsValue),
    /// A transport body that has no JSON value; original bytes remain in body.
    Opaque(&'static str),
}

/// Multipart file contents retained for application handlers alongside decoded fields.
#[derive(Clone, Debug, Default)]
pub struct MultipartFiles(pub std::collections::HashMap<String, MultipartFile>);

#[derive(Clone, Debug)]
pub struct MultipartFile {
    pub filename: String,
    pub content_type: Option<String>,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for RequestExtensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestExtensions").finish_non_exhaustive()
    }
}

impl RequestExtensions {
    pub fn insert<T: std::any::Any + Send + Sync>(&self, value: T) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(value);
    }

    pub fn get<T: std::any::Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get()
    }
}

/// Metadata extracted from an incoming request for session creation.
///
/// Centralizes extraction of IP address and user-agent so that core
/// functions do not need the full [`AuthRequest`].
#[derive(Debug, Clone, Default)]
pub struct RequestMeta {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl RequestMeta {
    /// Extract metadata from an [`AuthRequest`]'s headers.
    ///
    /// Dispatch uses its initialized IP policy. Standalone requests use the
    /// default policy. An actual HTTP dispatch retains empty IP/user-agent
    /// strings when those headers provide no value, as session metadata.
    #[must_use]
    pub fn from_request(req: &AuthRequest) -> Self {
        let configured = req.extensions().get::<crate::config::IpAddressConfig>();
        let ip = configured.as_ref().map_or_else(
            || crate::config::IpAddressConfig::default().resolve_ip(&req.headers),
            |policy| policy.resolve_ip(&req.headers),
        );
        let user_agent = req
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
            .map(|(_, value)| value.clone());
        Self {
            ip_address: if configured.is_some() {
                Some(ip.unwrap_or_default())
            } else {
                ip
            },
            user_agent: if configured.is_some() {
                Some(user_agent.unwrap_or_default())
            } else {
                user_agent
            },
        }
    }
}

/// Authentication response wrapper
#[derive(Debug, Clone)]
pub struct AuthResponse {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
}

/// Response headers preserving repeated header names such as `Set-Cookie`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    /// Create an empty header collection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a header, replacing any existing values for the same name.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) -> Option<String> {
        let name = name.into();
        let value = value.into();
        let mut previous = None;

        self.0.retain(|(existing_name, existing_value)| {
            if existing_name.eq_ignore_ascii_case(&name) {
                previous = Some(existing_value.clone());
                false
            } else {
                true
            }
        });

        self.0.push((name, value));
        previous
    }

    /// Append a header without removing existing values of the same name.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.0.push((name.into(), value.into()));
    }

    /// Get the last value stored for a header name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&String> {
        self.0.iter().rev().find_map(|(existing_name, value)| {
            existing_name.eq_ignore_ascii_case(name).then_some(value)
        })
    }

    /// Iterate over all values stored for a header name.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a String> + 'a {
        self.0.iter().filter_map(move |(existing_name, value)| {
            existing_name.eq_ignore_ascii_case(name).then_some(value)
        })
    }

    /// Check whether a header name exists.
    #[must_use]
    pub fn contains_key(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Return whether the collection is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over stored header pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter().map(|(name, value)| (name, value))
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = (&'a String, &'a String);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, (String, String)>,
        fn(&(String, String)) -> (&String, &String),
    >;

    fn into_iter(self) -> Self::IntoIter {
        const fn map_pair((name, value): &(String, String)) -> (&String, &String) {
            (name, value)
        }

        self.0.iter().map(map_pair)
    }
}

impl IntoIterator for Headers {
    type Item = (String, String);
    type IntoIter = std::vec::IntoIter<(String, String)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Index<&str> for Headers {
    type Output = String;

    #[expect(
        clippy::expect_used,
        reason = "Index must panic on missing headers to satisfy the trait contract"
    )]
    fn index(&self, index: &str) -> &Self::Output {
        self.get(index).expect("header not found")
    }
}

impl AuthRequest {
    #[must_use]
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            request_url: None,
            headers: HashMap::new(),
            body: None,
            query: HashMap::new(),
            query_values: HashMap::new(),
            virtual_session: None,
            response_headers: Arc::new(Mutex::new(Headers::new())),
            session_hook_snapshot: Arc::new(Mutex::new(None)),
            extensions: RequestExtensions::default(),
        }
    }

    /// Construct a request from all public parts.
    ///
    /// Prefer [`AuthRequest::new`] when you only need method + path.
    #[must_use]
    pub fn from_parts(
        method: HttpMethod,
        path: String,
        headers: HashMap<String, String>,
        body: Option<Vec<u8>>,
        query: HashMap<String, String>,
    ) -> Self {
        Self {
            method,
            path,
            request_url: None,
            headers,
            body,
            query,
            query_values: HashMap::new(),
            virtual_session: None,
            response_headers: Arc::new(Mutex::new(Headers::new())),
            session_hook_snapshot: Arc::new(Mutex::new(None)),
            extensions: RequestExtensions::default(),
        }
    }

    /// Retain the absolute URL received by the HTTP transport.
    /// Origin inference uses this URL, independently of routing and forwarded headers.
    #[must_use]
    pub fn with_url(mut self, url: url::Url) -> Self {
        self.request_url = Some(url);
        self
    }

    /// The absolute transport URL, when supplied by the embedding integration.
    #[must_use]
    pub const fn url(&self) -> Option<&url::Url> {
        self.request_url.as_ref()
    }

    /// Replace query parameters with decoded pairs, preserving repeated values.
    /// The public `query` map retains the last value for existing integrations.
    pub fn set_query_pairs<I, K, V>(&mut self, pairs: I)
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.query.clear();
        self.query_values.clear();
        for (key, value) in pairs {
            let key = key.into();
            let value = value.into();
            drop(self.query.insert(key.clone(), value.clone()));
            self.query_values.entry(key).or_default().push(value);
        }
    }

    /// Values for a decoded query name, in their original per-name order.
    /// A direct update of the legacy map replaces the captured values when its
    /// last value changes; removing a name removes it from this view as well.
    #[must_use]
    pub fn query_values(&self, name: &str) -> Option<&[String]> {
        let current = self.query.get(name)?;
        match self.query_values.get(name) {
            Some(values) if values.last() == Some(current) => Some(values),
            _ => Some(std::slice::from_ref(current)),
        }
    }

    #[must_use]
    pub const fn method(&self) -> &HttpMethod {
        &self.method
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn header(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }

    /// Typed values established by trusted hooks and handlers in this dispatch.
    /// Caller-supplied values are discarded at every public dispatch boundary.
    #[must_use]
    pub const fn extensions(&self) -> &RequestExtensions {
        &self.extensions
    }

    /// Forward a header emitted by a nested server handler to the final response.
    ///
    /// Internal request clones share this accumulator, including clones used to
    /// normalize a route. Dispatch starts with a fresh accumulator, so values
    /// supplied by an external caller cannot become response headers.
    pub fn queue_response_header(&self, name: impl Into<String>, value: impl Into<String>) {
        self.response_headers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .append(name, value);
    }

    /// Drain headers accumulated by trusted handlers for this request.
    pub fn take_response_headers(&self) -> Headers {
        std::mem::take(
            &mut *self
                .response_headers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Record the original store snapshot observed by a trusted session handler.
    ///
    /// Completed-response hooks can observe this snapshot after refresh or
    /// expiry cleanup. It may contain an expired or deleted session and must
    /// never authorize work; use `AuthContext::require_session` for that.
    /// Dispatch resets caller-supplied snapshots before running trusted handlers.
    pub fn set_session_hook_snapshot(
        &self,
        user: crate::wire::UserView,
        session: crate::wire::SessionView,
    ) {
        *self
            .session_hook_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((user, session));
    }

    /// Return the handler's original session context for completed-response hooks.
    /// This is an observation of a read, not an authorization result.
    pub fn session_hook_snapshot(
        &self,
    ) -> Option<(crate::wire::UserView, crate::wire::SessionView)> {
        self.session_hook_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Return the user ID authenticated by a trusted plugin hook.
    #[must_use]
    pub fn virtual_user_id(&self) -> Option<&str> {
        self.virtual_session
            .as_ref()
            .map(|session| session.user_id.as_str())
    }

    /// Return the session authenticated by a trusted plugin hook.
    #[must_use]
    pub const fn virtual_session(&self) -> Option<&crate::wire::SessionView> {
        self.virtual_session.as_ref()
    }

    /// Attach a session authenticated by a trusted plugin hook.
    ///
    /// Call this method only from the request pipeline after a plugin returns
    /// `BeforeRequestAction::InjectSession`. Never populate the session from client input.
    pub fn set_virtual_session(&mut self, session: crate::wire::SessionView) {
        self.virtual_session = Some(session);
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the request body is missing or cannot be deserialized.
    pub fn body_as_json<T: for<'de> Deserialize<'de> + 'static>(
        &self,
    ) -> Result<T, serde_json::Error> {
        if let Some(body) = self.extensions.get::<ParsedRequestBody>() {
            return match &*body {
                ParsedRequestBody::Value(value) => crate::utils::json::from_value(value.clone()),
                ParsedRequestBody::Opaque(kind) => Err(serde::de::Error::custom(format!(
                    "Expected JSON body, received {kind}"
                ))),
            };
        }
        self.body.as_ref().map_or_else(
            || crate::utils::json::from_slice(b"{}"),
            |body| crate::utils::json::from_slice(body),
        )
    }
}

impl AuthResponse {
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body: Vec::new(),
        }
    }

    fn with_content(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: Headers(vec![("content-type".to_owned(), content_type.to_owned())]),
            body,
        }
    }

    /// # Errors
    /// Returns an error if the response body cannot be serialized.
    pub fn json<T: Serialize>(status: u16, data: &T) -> Result<Self, serde_json::Error> {
        Ok(Self::with_content(
            status,
            "application/json",
            crate::utils::json::to_vec(data)?,
        ))
    }

    #[must_use]
    pub fn text(status: u16, text: impl Into<String>) -> Self {
        Self::with_content(status, "text/plain", text.into().into_bytes())
    }

    #[must_use]
    pub fn html(status: u16, html: impl Into<String>) -> Self {
        Self::with_content(status, "text/html; charset=utf-8", html.into().into_bytes())
    }

    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        drop(self.headers.insert(name.into(), value.into()));
        self
    }

    #[must_use]
    pub fn with_appended_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.headers.append(name.into(), value.into());
        self
    }
}

impl From<AuthResponse> for ::http::Response<Vec<u8>> {
    /// Headers that are not valid HTTP names or values are dropped.
    fn from(response: AuthResponse) -> Self {
        let mut converted = Self::new(response.body);
        *converted.status_mut() = ::http::StatusCode::from_u16(response.status)
            .unwrap_or(::http::StatusCode::INTERNAL_SERVER_ERROR);
        let headers = converted.headers_mut();
        for (name, value) in response.headers {
            if let (Ok(name), Ok(value)) = (
                ::http::HeaderName::try_from(name),
                ::http::HeaderValue::try_from(value),
            ) {
                _ = headers.append(name, value);
            }
        }
        converted
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for AuthResponse {
    fn into_response(self) -> axum::response::Response {
        ::http::Response::from(self).map(axum::body::Body::from)
    }
}
