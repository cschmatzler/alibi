//! Session authentication consumes logical credential input, not an invented HTTP request.

use crate::types::RequestExtensions;
use crate::{AuthRequest, AuthSchema, HttpMethod, SessionView, UserView};
use std::collections::HashMap;

/// Input and trusted state used by the shared physical/cache session readers.
/// Implementations must never populate authenticated state from client data.
pub trait SessionRequest: Send + Sync {
    fn session_headers(&self) -> &HashMap<String, String>;
    fn session_method(&self) -> &HttpMethod;
    fn session_query_truthy(&self, name: &str) -> bool;
    fn extensions(&self) -> &RequestExtensions;
    fn virtual_session(&self) -> Option<SessionView>;
    fn authenticated_user<S: AuthSchema>(&self) -> Option<S::User> {
        None
    }
    fn take_response_headers(&self) -> crate::Headers;
    fn queue_response_header(&self, name: impl Into<String>, value: impl Into<String>);
    fn set_session_hook_snapshot(&self, user: UserView, session: SessionView);
}

impl SessionRequest for AuthRequest {
    fn session_headers(&self) -> &HashMap<String, String> {
        &self.headers
    }
    fn session_method(&self) -> &HttpMethod {
        self.method()
    }
    fn session_query_truthy(&self, name: &str) -> bool {
        self.query.get(name).is_some_and(|value| !value.is_empty())
    }
    fn extensions(&self) -> &RequestExtensions {
        self.extensions()
    }
    fn virtual_session(&self) -> Option<SessionView> {
        self.virtual_session().cloned()
    }
    fn take_response_headers(&self) -> crate::Headers { self.take_response_headers() }
    fn queue_response_header(&self, name: impl Into<String>, value: impl Into<String>) {
        self.queue_response_header(name, value);
    }
    fn set_session_hook_snapshot(&self, user: UserView, session: SessionView) {
        self.set_session_hook_snapshot(user, session);
    }
}

impl SessionRequest for crate::endpoint::EndpointCall {
    fn session_headers(&self) -> &HashMap<String, String> {
        static EMPTY: std::sync::LazyLock<HashMap<String, String>> =
            std::sync::LazyLock::new(HashMap::new);
        self.headers().unwrap_or(&EMPTY)
    }
    fn session_method(&self) -> &HttpMethod {
        self.method().unwrap_or(self.default_method())
    }
    fn session_query_truthy(&self, name: &str) -> bool {
        self.query()
            .and_then(|query| query.get(name))
            .is_some_and(|value| match value {
                crate::utils::json::JsValue::Null => false,
                crate::utils::json::JsValue::Bool(value) => *value,
                crate::utils::json::JsValue::Number(value) => *value != 0.0 && !value.is_nan(),
                crate::utils::json::JsValue::String(value) => !value.is_empty(),
                crate::utils::json::JsValue::Array(_) | crate::utils::json::JsValue::Object(_) => {
                    true
                }
            })
    }
    fn extensions(&self) -> &RequestExtensions {
        self.extensions()
    }
    fn virtual_session(&self) -> Option<SessionView> {
        self.virtual_session()
    }
    fn authenticated_user<S: AuthSchema>(&self) -> Option<S::User> {
        self.authenticated_user::<S>()
    }
    fn take_response_headers(&self) -> crate::Headers { self.take_response_headers() }
    fn queue_response_header(&self, name: impl Into<String>, value: impl Into<String>) {
        self.queue_response_header(name, value);
    }
    fn set_session_hook_snapshot(&self, user: UserView, session: SessionView) {
        self.set_session_hook_snapshot(user, session);
    }
}
