//! Trusted endpoint calls keep logical input separate from an optional HTTP request.

use crate::types::RequestExtensions;
use crate::utils::json::JsValue;
use crate::wire::{SessionView, UserView};
use crate::{AuthError, AuthRequest, AuthResult, AuthSchema, Headers, HttpMethod};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

/// An operation registered by an installed plugin, independently of its HTTP routes.
#[derive(Clone, Debug)]
pub struct EndpointDefinition {
    pub name: &'static str,
    pub operation_id: &'static str,
    pub path: Option<String>,
    pub method: HttpMethod,
}

/// Typed operation input. Dispatch decodes the final input after before-hook patches.
#[derive(Clone, Debug)]
pub struct ServerEndpoint<T> {
    plugin: &'static str,
    name: &'static str,
    body: Option<JsValue>,
    query: Option<JsValue>,
    output: PhantomData<fn() -> T>,
}

impl<T> ServerEndpoint<T> {
    #[must_use]
    pub const fn new(plugin: &'static str, name: &'static str) -> Self {
        Self {
            plugin,
            name,
            body: None,
            query: None,
            output: PhantomData,
        }
    }

    /// # Errors
    /// Returns an error if application input cannot be serialized.
    pub fn with_body(mut self, body: &impl Serialize) -> AuthResult<Self> {
        self.body = Some(crate::utils::json::parse_value(
            &crate::utils::json::to_string(body)?,
        )?);
        Ok(self)
    }

    /// # Errors
    /// Returns an error if application input cannot be serialized.
    pub fn with_query(mut self, query: &impl Serialize) -> AuthResult<Self> {
        self.query = Some(crate::utils::json::parse_value(
            &crate::utils::json::to_string(query)?,
        )?);
        Ok(self)
    }

    #[must_use]
    pub fn with_body_value(mut self, body: JsValue) -> Self {
        self.body = Some(body);
        self
    }

    #[must_use]
    pub fn with_query_value(mut self, query: JsValue) -> Self {
        self.query = Some(query);
        self
    }

    #[must_use]
    pub const fn plugin(&self) -> &'static str {
        self.plugin
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    #[must_use]
    pub fn input(self) -> (Option<JsValue>, Option<JsValue>) {
        (self.body, self.query)
    }
}

/// Per-call options. Absent headers remain distinct from an explicitly empty collection.
#[derive(Clone, Debug, Default)]
pub struct EndpointOptions {
    pub headers: Option<HashMap<String, String>>,
    pub request: Option<AuthRequest>,
    pub method: Option<HttpMethod>,
}

#[derive(Clone, Debug, Default)]
struct EndpointState {
    session: Option<SessionView>,
    principal: Option<(UserView, SessionView)>,
    response_headers: Headers,
    session_observation: Option<(UserView, SessionView)>,
}

struct VerifiedEndpointUser<S: AuthSchema>(S::User);

/// Runtime normalization phase, retaining absence in original logical inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointPhase {
    Raw,
    Middleware,
    Handler,
}

/// Genuine logical endpoint data available to hooks and application callbacks.
///
/// Clones share trusted session state, observed snapshots and queued headers.
/// Every public dispatch constructs fresh state; supplied HTTP metadata cannot
/// carry a caller-populated virtual principal into this context.
#[derive(Clone, Debug)]
pub struct EndpointCall {
    operation_id: &'static str,
    path: Option<String>,
    method: Option<HttpMethod>,
    body: Option<JsValue>,
    query: Option<JsValue>,
    headers: Option<HashMap<String, String>>,
    request: Option<AuthRequest>,
    default_method: HttpMethod,
    phase: EndpointPhase,
    extensions: RequestExtensions,
    state: Arc<Mutex<EndpointState>>,
}

impl EndpointCall {
    #[must_use]
    pub fn new(
        definition: &EndpointDefinition,
        body: Option<JsValue>,
        query: Option<JsValue>,
        options: EndpointOptions,
    ) -> Self {
        Self {
            operation_id: definition.operation_id,
            path: definition.path.clone(),
            method: options.method,
            body,
            query,
            headers: options.headers.map(|headers| {
                headers
                    .into_iter()
                    .map(|(name, value)| (name.to_ascii_lowercase(), value))
                    .collect()
            }),
            request: options.request.map(fresh_request),
            default_method: definition.method.clone(),
            phase: EndpointPhase::Raw,
            extensions: RequestExtensions::default(),
            state: Arc::new(Mutex::new(EndpointState::default())),
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> &'static str {
        self.operation_id
    }

    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    #[must_use]
    pub const fn method(&self) -> Option<&HttpMethod> {
        self.method.as_ref()
    }

    #[must_use]
    pub const fn body(&self) -> Option<&JsValue> {
        self.body.as_ref()
    }

    #[must_use]
    pub const fn query(&self) -> Option<&JsValue> {
        self.query.as_ref()
    }

    #[must_use]
    pub const fn headers(&self) -> Option<&HashMap<String, String>> {
        self.headers.as_ref()
    }

    #[must_use]
    pub const fn request(&self) -> Option<&AuthRequest> {
        self.request.as_ref()
    }

    #[must_use]
    pub const fn phase(&self) -> EndpointPhase {
        self.phase
    }

    #[must_use]
    pub fn has_body(&self) -> bool {
        self.phase != EndpointPhase::Raw || self.body.is_some()
    }

    #[must_use]
    pub fn has_query(&self) -> bool {
        self.phase != EndpointPhase::Raw || self.query.is_some()
    }

    #[must_use]
    pub fn has_method(&self) -> bool {
        self.phase != EndpointPhase::Raw || self.method.is_some()
    }

    /// Middleware callbacks have their own path/query defaults; matchers retain raw input.
    #[must_use]
    pub fn middleware_context(&self) -> Self {
        let mut context = self.clone();
        context.phase = EndpointPhase::Middleware;
        if context.path.as_ref().is_none_or(String::is_empty) {
            context.path = Some("/".into());
        }
        context
    }

    /// A handler receives validated data and its registered method/path defaults.
    #[must_use]
    pub fn handler_context(&self, body: Option<JsValue>, query: Option<JsValue>) -> Self {
        let mut context = self.clone();
        context.phase = EndpointPhase::Handler;
        if context.path.as_ref().is_none_or(String::is_empty) {
            context.path = Some("virtual:".into());
        }
        if context.method.is_none() {
            context.method = Some(context.default_method.clone());
        }
        context.body = body;
        context.query = query;
        context
    }

    #[must_use]
    pub const fn extensions(&self) -> &RequestExtensions {
        &self.extensions
    }

    #[must_use]
    pub const fn default_method(&self) -> &HttpMethod {
        &self.default_method
    }

    #[must_use]
    pub fn virtual_session(&self) -> Option<SessionView> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .session
            .clone()
    }

    /// Retain the actual model and snapshot after a trusted hook has authenticated them.
    /// This is an application/plugin authority boundary, never client input.
    pub fn establish_session<S: AuthSchema>(
        &self,
        user: S::User,
        user_view: UserView,
        session: SessionView,
    ) {
        self.extensions.insert(VerifiedEndpointUser::<S>(user));
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.principal = Some((user_view, session.clone()));
        state.session = Some(session);
    }

    /// Callback-visible authenticated data. This observation does not confer authority.
    #[must_use]
    pub fn session(&self) -> Option<(UserView, SessionView)> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .principal
            .clone()
    }

    pub fn record_authenticated_session(&self, user: UserView, session: SessionView) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .principal = Some((user, session));
    }

    #[must_use]
    pub fn authenticated_user<S: AuthSchema>(&self) -> Option<S::User> {
        self.extensions
            .get::<VerifiedEndpointUser<S>>()
            .map(|user| user.0.clone())
    }

    pub fn set_response_header(&self, name: impl Into<String>, value: impl Into<String>) {
        drop(
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .response_headers
                .insert(name, value),
        );
    }

    pub fn queue_response_header(&self, name: impl Into<String>, value: impl Into<String>) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .response_headers
            .append(name, value);
    }

    pub fn take_response_headers(&self) -> Headers {
        std::mem::take(
            &mut self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .response_headers,
        )
    }

    pub fn set_session_hook_snapshot(&self, user: UserView, session: SessionView) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .session_observation = Some((user, session));
    }

    #[must_use]
    pub fn session_hook_snapshot(&self) -> Option<(UserView, SessionView)> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .session_observation
            .clone()
    }

    /// # Errors
    /// Returns a typed decoding error for the current, post-hook body.
    pub fn body_as<T: DeserializeOwned + 'static>(&self) -> AuthResult<T> {
        Ok(crate::utils::json::from_value(
            self.body.clone().unwrap_or(JsValue::Null),
        )?)
    }

    /// # Errors
    /// Returns a typed decoding error for the current, post-hook query.
    pub fn query_as<T: DeserializeOwned + 'static>(&self) -> AuthResult<T> {
        Ok(crate::utils::json::from_value(
            self.query.clone().unwrap_or(JsValue::Null),
        )?)
    }
}

/// Context patches accumulate without replacing the original input seen by later before hooks.
#[derive(Clone, Debug, Default)]
pub struct EndpointContextPatch {
    pub method: Option<HttpMethod>,
    pub request: Option<AuthRequest>,
    pub path: Option<String>,
    pub body: Option<JsValue>,
    pub query: Option<JsValue>,
    pub headers: Option<HashMap<String, String>>,
}

impl EndpointContextPatch {
    pub fn merge(&mut self, patch: Self) {
        if let Some(method) = patch.method {
            self.method = Some(method);
        }
        if let Some(request) = patch.request {
            self.request = Some(request);
        }
        if let Some(path) = patch.path {
            self.path = Some(path);
        }
        merge_optional(&mut self.body, patch.body);
        merge_optional(&mut self.query, patch.query);
        if let Some(headers) = patch.headers {
            self.headers.get_or_insert_with(HashMap::new).extend(
                headers
                    .into_iter()
                    .map(|(name, value)| (name.to_ascii_lowercase(), value)),
            );
        }
    }

    pub fn apply(self, call: &mut EndpointCall) {
        if let Some(method) = self.method {
            call.method = Some(method);
        }
        if let Some(request) = self.request {
            call.request = Some(fresh_request(request));
        }
        if let Some(path) = self.path {
            call.path = Some(path);
        }
        merge_optional(&mut call.body, self.body);
        merge_optional(&mut call.query, self.query);
        if let Some(headers) = self.headers {
            call.headers
                .get_or_insert_with(HashMap::new)
                .extend(headers);
        }
    }
}

fn merge_optional(target: &mut Option<JsValue>, patch: Option<JsValue>) {
    if let Some(patch) = patch.filter(|value| !value.is_null()) {
        if let Some(target) = target {
            merge_value(target, patch);
        } else {
            *target = Some(patch);
        }
    }
}

fn merge_value(target: &mut JsValue, patch: JsValue) {
    if let (JsValue::Object(target), JsValue::Object(patch)) = (&mut *target, &patch) {
        for (name, value) in patch {
            if value.is_null() || matches!(name.as_str(), "__proto__" | "constructor") {
                continue;
            }
            if let Some(target) = target.get_mut(name) {
                merge_value(target, value.clone());
            } else {
                drop(target.insert(name.clone(), value.clone()));
            }
        }
    } else {
        *target = patch;
    }
}

/// A before hook can accumulate input changes or finish without reaching the handler/after hooks.
#[derive(Debug)]
pub enum BeforeEndpointAction {
    Patch(Box<EndpointContextPatch>),
    Respond(EndpointResponse),
    /// Reject with an intentional API error and its complete public body.
    Reject(EndpointResponse),
}

/// Validated handler input. The dispatcher retains raw patched data for after hooks.
#[derive(Clone, Debug, Default)]
pub struct EndpointInput {
    pub body: Option<JsValue>,
    pub query: Option<JsValue>,
}

/// A returned value or intentional API error, available to completed endpoint hooks.
#[derive(Debug)]
pub struct EndpointResponse {
    result: Result<JsValue, AuthError>,
    error_body: Option<JsValue>,
    headers: Headers,
    status: Option<u16>,
}

impl EndpointResponse {
    #[must_use]
    pub fn value(value: JsValue) -> Self {
        Self {
            result: Ok(value),
            error_body: None,
            headers: Headers::new(),
            status: None,
        }
    }

    /// # Errors
    /// Returns an error if the endpoint value cannot be serialized.
    pub fn json(value: &impl Serialize) -> AuthResult<Self> {
        Ok(Self::value(crate::utils::json::parse_value(
            &crate::utils::json::to_string(value)?,
        )?))
    }

    #[must_use]
    pub fn error(error: AuthError) -> Self {
        let status = Some(error.status_code());
        Self {
            result: Err(error),
            error_body: None,
            headers: Headers::new(),
            status,
        }
    }

    #[must_use]
    pub fn with_error_body(mut self, body: JsValue) -> Self {
        self.error_body = Some(body);
        self
    }

    #[must_use]
    pub const fn error_body(&self) -> Option<&JsValue> {
        self.error_body.as_ref()
    }

    #[must_use]
    pub const fn result(&self) -> &Result<JsValue, AuthError> {
        &self.result
    }

    #[must_use]
    pub const fn headers(&self) -> &Headers {
        &self.headers
    }

    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        self.status
    }

    pub fn set_status(&mut self, status: Option<u16>) {
        self.status = status;
    }

    #[must_use]
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        merge_header(&mut self.headers, name.into(), value.into());
        self
    }

    pub fn merge_headers(&mut self, headers: Headers) {
        for (name, value) in headers {
            merge_header(&mut self.headers, name, value);
        }
    }

    /// Replace a returned value while retaining the actual handler status and headers.
    pub fn replace(&mut self, value: JsValue) {
        self.result = Ok(value);
        self.error_body = None;
    }

    pub fn replace_error(&mut self, error: AuthError) {
        self.result = Err(error);
        self.error_body = None;
    }

    pub fn into_output<T>(self) -> Result<EndpointOutput<T>, EndpointError> {
        match self.result {
            Ok(value) => Ok(EndpointOutput {
                value,
                headers: self.headers,
                status: self.status,
                output: PhantomData,
            }),
            Err(error) => Err(EndpointError {
                error,
                headers: Some(self.headers),
                body: self.error_body.map(Box::new),
            }),
        }
    }
}

fn merge_header(headers: &mut Headers, name: String, value: String) {
    if name.eq_ignore_ascii_case("set-cookie") {
        headers.append(name, value);
    } else {
        drop(headers.insert(name, value));
    }
}

/// Installed application middleware for logical endpoint calls.
#[async_trait::async_trait]
pub trait EndpointHook<S: AuthSchema>: Send + Sync {
    /// Matchers observe raw logical context, before middleware normalization.
    /// # Errors
    /// Returns an application matcher error, which dispatch logs and masks.
    fn matches_before(
        &self,
        _call: &EndpointCall,
        _ctx: &crate::AuthContext<S>,
    ) -> AuthResult<bool> {
        Ok(true)
    }

    /// # Errors
    /// Propagates actual callback failures without reaching later hooks or the handler.
    async fn before(
        &self,
        _call: &EndpointCall,
        _ctx: &crate::AuthContext<S>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        Ok(None)
    }

    /// # Errors
    /// Propagates actual after-matcher failures.
    fn matches_after(
        &self,
        _call: &EndpointCall,
        _ctx: &crate::AuthContext<S>,
        _response: &EndpointResponse,
    ) -> AuthResult<bool> {
        Ok(true)
    }

    /// # Errors
    /// API errors replace the result and continue; ordinary failures abort remaining hooks.
    async fn after(
        &self,
        _call: &EndpointCall,
        _ctx: &crate::AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        Ok(response)
    }
}

/// A successful call retains the actual value, since after hooks can replace its shape.
#[derive(Debug)]
pub struct EndpointOutput<T> {
    value: JsValue,
    headers: Headers,
    status: Option<u16>,
    output: PhantomData<fn() -> T>,
}

impl<T> EndpointOutput<T> {
    #[must_use]
    pub const fn value(&self) -> &JsValue {
        &self.value
    }

    #[must_use]
    pub const fn headers(&self) -> &Headers {
        &self.headers
    }

    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        self.status
    }
}

impl<T: DeserializeOwned + 'static> EndpointOutput<T> {
    /// # Errors
    /// Returns an error if an application hook replaced the expected output type.
    pub fn decode(&self) -> AuthResult<T> {
        Ok(crate::utils::json::from_value(self.value.clone())?)
    }
}

/// Actual application/API failure, with headers accumulated before an API error.
#[derive(Debug)]
pub struct EndpointError {
    pub error: AuthError,
    pub headers: Option<Headers>,
    pub body: Option<Box<JsValue>>,
}

impl From<AuthError> for EndpointError {
    fn from(error: AuthError) -> Self {
        Self {
            error,
            headers: None,
            body: None,
        }
    }
}

impl std::fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for EndpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Intentional endpoint/API errors continue through after hooks; ordinary failures propagate.
#[must_use]
pub fn is_endpoint_api_error(error: &AuthError) -> bool {
    matches!(error, AuthError::Api { .. } | AuthError::Upstream { .. }) || error.status_code() < 500
}

fn fresh_request(request: AuthRequest) -> AuthRequest {
    let pairs = request
        .query
        .keys()
        .flat_map(|name| {
            request
                .query_values(name)
                .into_iter()
                .flatten()
                .map(|value| (name.clone(), value.clone()))
        })
        .collect::<Vec<_>>();
    let url = request.url().cloned();
    let mut fresh = AuthRequest::from_parts(
        request.method,
        request.path,
        request.headers,
        request.body,
        request.query,
    );
    if let Some(url) = url {
        fresh = fresh.with_url(url);
    }
    fresh.set_query_pairs(pairs);
    fresh
}

tokio::task_local! { static ENDPOINT_CALL_CONTEXT: Option<EndpointCall>; }

#[must_use]
pub fn current_endpoint_call_context() -> Option<EndpointCall> {
    ENDPOINT_CALL_CONTEXT.try_with(Clone::clone).ok().flatten()
}

pub async fn with_endpoint_call_context<T>(
    call: EndpointCall,
    future: impl Future<Output = T>,
) -> T {
    let request = call
        .request()
        .map(crate::hooks::RequestHookContext::from_request);
    crate::hooks::with_optional_request_hook_context(
        request,
        ENDPOINT_CALL_CONTEXT.scope(Some(call), future),
    )
    .await
}

/// Isolate an independent HTTP dispatch from an enclosing logical endpoint call.
pub async fn without_endpoint_call_context<T>(future: impl Future<Output = T>) -> T {
    ENDPOINT_CALL_CONTEXT.scope(None, future).await
}
