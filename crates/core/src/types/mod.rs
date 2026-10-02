// Re-export organization types
pub use super::types_org::{
    AddTeamMemberResult, CreateInvitation, CreateMember, CreateOrganization,
    CreateOrganizationRole, CreateTeam, Invitation, InvitationStatus, Member, Organization,
    OrganizationPermissions, OrganizationRole, OrganizationRoleSelector, Team, TeamMember,
    UpdateOrganization, UpdateOrganizationRole, UpdateTeam,
};
pub use super::types_plugin::{
    ApiKey, ApiKeyStartingCharacters, CreateApiKey, CreateDeviceCode, CreateJwk, CreatePasskey,
    CreateTwoFactor, CreateWalletAddress, DeviceCode, Jwk, Passkey, TwoFactor, UpdateApiKey,
    UpdateDeviceCode, UpdatePasskey, UpdatePasskeyAuthentication, UpdateTwoFactor, WalletAddress,
};
use crate::utils::normalize_user_email;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Index;
use std::sync::{Arc, Mutex};
use validator::Validate;

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
    request_url: Option<url::Url>,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub query: HashMap<String, String>,
    query_values: HashMap<String, Vec<String>>,
    /// Session authenticated by a trusted plugin hook for the current request.
    pub(crate) virtual_session: Option<crate::wire::SessionView>,
    /// Headers emitted by trusted nested handlers during this dispatch.
    response_headers: Arc<Mutex<Headers>>,
    /// The original store snapshot retained for completed-handler hooks.
    session_hook_snapshot: Arc<Mutex<Option<(crate::wire::UserView, crate::wire::SessionView)>>>,
    extensions: RequestExtensions,
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

/// User creation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUser {
    #[serde(flatten, default)]
    pub additional_fields: crate::field_policy::FieldValues,
    pub id: Option<String>,
    /// Trusted creation timestamps; omitted values use the adapter's clock.
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: Option<bool>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    /// `None` leaves the two-factor plugin field unset.
    pub two_factor_enabled: Option<bool>,
    pub role: Option<String>,
    /// `None` leaves the admin plugin field unset.
    pub banned: Option<bool>,
    #[serde(
        default,
        deserialize_with = "crate::utils::json::deserialize_optional_value"
    )]
    pub metadata: Option<serde_json::Value>,
    pub is_anonymous: Option<bool>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub last_login_method: Option<String>,
}

/// User update data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateUser {
    #[serde(flatten, default)]
    pub additional_fields: crate::field_policy::FieldValues,
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: Option<bool>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub role: Option<String>,
    pub banned: Option<bool>,
    pub ban_reason: Option<String>,
    /// `None` leaves the expiry unchanged; `Some(None)` clears it without unbanning.
    #[serde(
        default,
        deserialize_with = "deserialize_ban_expiry_patch",
        skip_serializing_if = "Option::is_none"
    )]
    pub ban_expires: Option<Option<DateTime<Utc>>>,
    pub two_factor_enabled: Option<bool>,
    #[serde(
        default,
        deserialize_with = "crate::utils::json::deserialize_optional_value"
    )]
    pub metadata: Option<serde_json::Value>,
    pub is_anonymous: Option<bool>,
    /// `None` leaves the field unchanged; `Some(None)` clears it.
    pub phone_number: Option<Option<String>>,
    pub phone_number_verified: Option<bool>,
    /// `None` leaves the field unchanged; `Some(None)` clears it.
    pub last_login_method: Option<Option<String>>,
}

/// Session creation data
#[derive(Debug, Clone)]
pub struct CreateSession {
    pub additional_fields: crate::field_policy::FieldValues,
    /// Optional token override for trusted database hooks and server-side creation.
    /// Stores generate a secure 32-character alphanumeric token when omitted.
    pub token: Option<String>,
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub impersonated_by: Option<String>,
    pub active_organization_id: Option<String>,
    pub active_team_id: Option<String>,
}

/// Account creation data
#[derive(Debug, Clone)]
pub struct CreateAccount {
    pub additional_fields: crate::field_policy::FieldValues,
    pub user_id: String,
    pub account_id: String,
    pub provider_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub password: Option<String>,
}

/// Account update data (for refreshing OAuth tokens)
#[derive(Debug, Clone, Default)]
pub struct UpdateAccount {
    pub additional_fields: crate::field_policy::FieldValues,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
    pub password: Option<String>,
}

/// Verification token creation data
#[derive(Debug, Clone)]
pub struct CreateVerification {
    pub identifier: String,
    pub value: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateVerification {
    pub value: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl CreateUser {
    #[must_use]
    pub fn new() -> Self {
        Self {
            additional_fields: crate::field_policy::FieldValues::new(),
            id: None,
            created_at: None,
            updated_at: None,
            email: None,
            name: None,
            image: None,
            email_verified: None,
            username: None,
            display_username: None,
            two_factor_enabled: None,
            role: None,
            banned: None,
            metadata: None,
            is_anonymous: None,
            phone_number: None,
            phone_number_verified: None,
            last_login_method: None,
        }
    }

    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(normalize_user_email(&email.into()));
        self
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn with_email_verified(mut self, verified: bool) -> Self {
        self.email_verified = Some(verified);
        self
    }

    #[must_use]
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    #[must_use]
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    #[must_use]
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

impl Default for CreateUser {
    fn default() -> Self {
        Self::new()
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

    ///
    /// # Errors
    ///
    /// Returns an error if the response body cannot be serialized.
    pub fn json<T: Serialize>(status: u16, data: &T) -> Result<Self, serde_json::Error> {
        let body = crate::utils::json::to_vec(data)?;
        let mut headers = Headers::new();
        drop(headers.insert("content-type".to_owned(), "application/json".to_owned()));

        Ok(Self {
            status,
            headers,
            body,
        })
    }

    #[must_use]
    pub fn text(status: u16, text: impl Into<String>) -> Self {
        let body = text.into().into_bytes();
        let mut headers = Headers::new();
        drop(headers.insert("content-type".to_owned(), "text/plain".to_owned()));

        Self {
            status,
            headers,
            body,
        }
    }

    #[must_use]
    pub fn html(status: u16, html: impl Into<String>) -> Self {
        let body = html.into().into_bytes();
        let mut headers = Headers::new();
        drop(headers.insert(
            "content-type".to_owned(),
            "text/html; charset=utf-8".to_owned(),
        ));

        Self {
            status,
            headers,
            body,
        }
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

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    #[validate(email(message = "Invalid email address"))]
    pub email: Option<String>,
    pub image: Option<String>,
    pub username: Option<String>,
    #[serde(rename = "displayUsername")]
    pub display_username: Option<String>,
    pub role: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::utils::json::deserialize_optional_value"
    )]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct UpdateUserResponse<U> {
    pub user: U,
}

/// Generic `{ ok: bool }` response used by `/ok` and `/error` endpoints.
#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

/// Generic `{ status: bool }` response.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: bool,
}

/// `{ status: bool, message: String }` response (e.g. change-email).
#[derive(Debug, Serialize)]
pub struct StatusMessageResponse {
    pub status: bool,
    pub message: String,
}

/// Generic `{ success: bool }` response (e.g. sign-out).
///
/// Use for endpoints where the upstream spec defines `success` rather than `status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SuccessResponse {
    pub success: bool,
}

/// `{ success: bool, message: String }` response (e.g. delete-user).
///
/// Use for endpoints where the upstream spec defines `success` rather than `status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SuccessMessageResponse {
    pub success: bool,
    pub message: String,
}

/// Health-check response for `/health`.
#[derive(Debug, Serialize)]
pub struct HealthCheckResponse {
    pub status: &'static str,
    pub service: &'static str,
}

/// Error body `{ message: String }`.
#[derive(Debug, Serialize)]
pub struct ErrorMessageResponse {
    pub message: String,
}

/// Error body `{ code: String, message: String }` matching the TS better-auth
/// error response shape.
#[derive(Debug, Serialize)]
pub struct ErrorCodeMessageResponse {
    /// Omitted when upstream has no explicit code for this error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
}

/// Middleware error response `{ code: String, message: String }`.
#[derive(Debug, Serialize)]
pub struct CodeMessageResponse {
    pub code: &'static str,
    pub message: String,
}

/// Rate-limit error response with `retryAfter` field.
#[derive(Debug, Serialize)]
pub struct RateLimitErrorResponse {
    pub code: &'static str,
    pub message: &'static str,
    #[serde(rename = "retryAfter")]
    pub retry_after: u64,
}

/// Validation error response `{ code, message, errors }`.
#[derive(Debug, Serialize)]
pub struct ValidationErrorResponse<'a> {
    pub code: &'static str,
    pub message: &'static str,
    pub errors: HashMap<std::borrow::Cow<'a, str>, Vec<String>>,
}

/// String operands for admin user-list filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UserFilterValue {
    /// One complete scalar string operand.
    Scalar(String),
    /// Ordered operands, including duplicates, for membership or adapter queries.
    Multiple(Vec<String>),
}

impl From<String> for UserFilterValue {
    fn from(value: String) -> Self {
        Self::Scalar(value)
    }
}

impl From<&str> for UserFilterValue {
    fn from(value: &str) -> Self {
        Self::Scalar(value.to_owned())
    }
}

impl From<Vec<String>> for UserFilterValue {
    fn from(value: Vec<String>) -> Self {
        Self::Multiple(value)
    }
}

/// Parameters for listing users through the configured adapter.
#[derive(Debug, Clone, Default)]
pub struct ListUsersParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub search_field: Option<String>,
    pub search_value: Option<String>,
    pub search_operator: Option<String>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
    pub filter_field: Option<String>,
    pub filter_value: Option<UserFilterValue>,
    pub filter_operator: Option<String>,
}

#[expect(
    clippy::option_option,
    reason = "The wire contract distinguishes an omitted field, explicit null, and a supplied value"
)]
fn deserialize_ban_expiry_patch<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<DateTime<Utc>>>, D::Error> {
    Option::<DateTime<Utc>>::deserialize(deserializer).map(Some)
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;

    // ── AuthRequest ─────────────────────────────────────────────────────

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_request_new_defaults() {
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        assert_eq!(req.method(), &HttpMethod::Get);
        assert_eq!(req.path(), "/test");
        assert!(req.headers.is_empty());
        assert!(req.body.is_none());
        assert!(req.virtual_user_id().is_none());
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_request_from_parts() {
        let mut headers = HashMap::new();
        drop(headers.insert("host".to_owned(), "localhost".to_owned()));
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/login".into(),
            headers,
            Some(b"{}".to_vec()),
            HashMap::new(),
        );
        assert_eq!(req.method(), &HttpMethod::Post);
        assert_eq!(req.header("host"), Some(&"localhost".to_owned()));
        assert!(req.body.is_some());
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_request_body_as_json_with_body() {
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/test".into(),
            HashMap::new(),
            Some(br#"{"name":"test","nested":{"$serde_json::private::RawValue":"hello"},"numbers":{"$serde_json::private::Number":"1e400"},"rounded":9007199254740993,"overflow":1e400}"#.to_vec()),
            HashMap::new(),
        );
        let val: serde_json::Value = req.body_as_json().expect("parse");
        assert_eq!(
            (*(val).get("name").unwrap_or(&serde_json::Value::Null)),
            "test"
        );
        assert_eq!(
            (*(*(val).get("nested").unwrap_or(&serde_json::Value::Null))
                .get("$serde_json::private::RawValue")
                .unwrap_or(&serde_json::Value::Null)),
            "hello"
        );
        assert_eq!(
            (*(*(val).get("numbers").unwrap_or(&serde_json::Value::Null))
                .get("$serde_json::private::Number")
                .unwrap_or(&serde_json::Value::Null)),
            "1e400"
        );
        assert_eq!(
            (*(val).get("rounded").unwrap_or(&serde_json::Value::Null)),
            9_007_199_254_740_992_u64
        );
        assert!((*(val).get("overflow").unwrap_or(&serde_json::Value::Null)).is_null());
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_request_body_as_json_without_body() {
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        let val: serde_json::Value = req.body_as_json().expect("parse empty");
        assert!(val.is_object());
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_request_virtual_user_id() {
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        assert!(req.virtual_user_id().is_none());
        let now = Utc::now();
        req.set_virtual_session(crate::wire::SessionView {
            omitted_fields: std::collections::BTreeSet::default(),
            id: "key-123".into(),
            token: "key-token".into(),
            user_id: "user-123".into(),
            created_at: now,
            updated_at: now,
            expires_at: now,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            active: true,
            extension_fields: std::collections::BTreeMap::default(),
        });
        assert_eq!(req.virtual_user_id(), Some("user-123"));
    }

    // ── AuthResponse ────────────────────────────────────────────────────

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_response_new() {
        let resp = AuthResponse::new(200);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, Vec::<u8>::new());
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_response_json() {
        let resp = AuthResponse::json(200, &OkResponse { ok: true }).expect("json");
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json"
        );
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(
            (*(body).get("ok").unwrap_or(&serde_json::Value::Null)),
            true
        );
    }

    // Pinned Better Call JSON response boundary: JavaScript numbers are rounded
    // before emission, including typed integers and arbitrary nested metadata.
    #[test]
    fn auth_response_json_emits_javascript_numbers_without_mutating_input() {
        #[derive(Serialize)]
        struct ResponseData {
            integer: u64,
            metadata: crate::utils::json::JsValue,
            nonfinite: f64,
        }
        let metadata = crate::utils::json::parse_value(
            r#"{"2":1e400,"1":-0.0,"rounded":9007199254740993,"small":1e-7,"large":1e21,"tie":229069639655724.625,"nested":[-1e400,5e-324],"01":true,"4294967295":false,"id":"9007199254740993","configId":"1e400","providerId":"-0.0"}"#,
        )
        .expect("valid JSON number lexemes");
        let data = ResponseData {
            integer: u64::MAX,
            metadata,
            nonfinite: f64::NAN,
        };
        let response = AuthResponse::json(200, &data).expect("emit response");
        assert_eq!(
            std::str::from_utf8(&response.body).expect("JSON UTF-8"),
            r#"{"integer":18446744073709552000,"metadata":{"1":0,"2":null,"rounded":9007199254740992,"small":1e-7,"large":1e+21,"tie":229069639655724.62,"nested":[null,5e-324],"01":true,"4294967295":false,"id":"9007199254740993","configId":"1e400","providerId":"-0.0"},"nonfinite":null}"#
        );
        assert_eq!(
            data.metadata
                .get("2")
                .and_then(crate::utils::json::JsValue::as_f64),
            Some(f64::INFINITY)
        );
        assert!(
            data.metadata
                .get("1")
                .and_then(crate::utils::json::JsValue::as_f64)
                .expect("number")
                .is_sign_negative()
        );
        assert_eq!(
            data.metadata
                .get("rounded")
                .and_then(crate::utils::json::JsValue::as_f64),
            Some(9_007_199_254_740_992.0)
        );
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_response_text() {
        let resp = AuthResponse::text(404, "Not found");
        assert_eq!(resp.status, 404);
        assert_eq!(resp.headers.get("content-type").unwrap(), "text/plain");
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "Not found");
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_response_html() {
        let resp = AuthResponse::html(200, "<h1>Hi</h1>");
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn auth_response_with_header() {
        let resp = AuthResponse::new(200).with_header("x-custom", "val");
        assert_eq!(resp.headers.get("x-custom").unwrap(), "val");
    }

    // ── RequestMeta ─────────────────────────────────────────────────────

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn request_meta_extracts_from_headers() {
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        drop(
            req.headers
                .insert("x-forwarded-for".into(), "1.2.3.4".into()),
        );
        drop(req.headers.insert("user-agent".into(), "TestAgent".into()));
        let meta = RequestMeta::from_request(&req);
        assert_eq!(meta.ip_address.as_deref(), Some("1.2.3.4"));
        assert_eq!(meta.user_agent.as_deref(), Some("TestAgent"));
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn request_meta_ignores_unconfigured_real_ip() {
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        drop(req.headers.insert("x-real-ip".into(), "5.6.7.8".into()));
        let meta = RequestMeta::from_request(&req);
        assert!(meta.ip_address.is_none());
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn request_meta_none_when_no_headers() {
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        let meta = RequestMeta::from_request(&req);
        assert!(meta.ip_address.is_none());
        assert!(meta.user_agent.is_none());
    }

    // ── CreateUser builder ──────────────────────────────────────────────

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn create_user_builder() {
        let cu = CreateUser::new()
            .with_email("Test@Example.COM")
            .with_name("Test")
            .with_email_verified(true)
            .with_username("testuser")
            .with_role("admin")
            .with_metadata(serde_json::json!({"key": "val"}));

        assert!(cu.id.is_none()); // ID generation is delegated to the model/store path
        assert_eq!(cu.email.as_deref(), Some("test@example.com"));
        assert_eq!(cu.name.as_deref(), Some("Test"));
        assert_eq!(cu.email_verified, Some(true));
        assert_eq!(cu.username.as_deref(), Some("testuser"));
        assert_eq!(cu.role.as_deref(), Some("admin"));
        assert!(cu.metadata.is_some());
    }

    // Rust-specific surface: Rust request/response/type helpers are public library behavior with no direct TS analogue.
    #[test]
    fn create_user_default() {
        let cu = CreateUser::default();
        assert!(cu.id.is_none());
        assert!(cu.email.is_none());
    }
}
// LCOV_EXCL_STOP
