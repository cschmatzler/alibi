use super::Middleware;
use crate::config::{AuthConfig, extract_origin};
use crate::error::{AuthError, AuthResult};
use crate::types::{AuthRequest, AuthResponse, HttpMethod};
use async_trait::async_trait;
#[cfg(test)]
use std::collections::HashMap;
use std::sync::Arc;

const CROSS_SITE_NAVIGATION_LOGIN_BLOCKED: &str =
    "Cross-site navigation login blocked. This request appears to be a CSRF attack.";

const INVALID_CALLBACK_URL: &str = "Invalid callbackURL";

const INVALID_ERROR_CALLBACK_URL: &str = "Invalid errorCallbackURL";

const INVALID_NEW_USER_CALLBACK_URL: &str = "Invalid newUserCallbackURL";

const INVALID_REDIRECT_URL: &str = "Invalid redirectURL";

const INVALID_ORIGIN: &str = "Invalid origin";

const MISSING_OR_NULL_ORIGIN: &str = "Missing or null Origin";

/// Configuration for Better Auth request-origin and CSRF protection.
#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// Whether the request protection middleware is enabled. Defaults to `true`.
    pub enabled: bool,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl CsrfConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// Better Auth request protection middleware.
///
/// This mirrors the upstream TypeScript behavior:
/// - mutating requests with cookies require a trusted `Origin` / `Referer`
/// - first-login `POST /sign-up/email` and `POST /sign-in/email` also use
///   Fetch Metadata headers to block cross-site navigation attacks
/// - callback / redirect targets are validated against trusted origins unless
///   `advanced.disable_origin_check` is set
#[derive(Debug)]
pub struct CsrfMiddleware {
    config: CsrfConfig,
    auth_config: Arc<AuthConfig>,
}

impl CsrfMiddleware {
    #[must_use]
    pub const fn new(config: CsrfConfig, auth_config: Arc<AuthConfig>) -> Self {
        Self {
            config,
            auth_config,
        }
    }

    const fn is_state_changing(method: &HttpMethod) -> bool {
        matches!(
            method,
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Delete | HttpMethod::Patch
        )
    }

    fn normalized_path<'a>(&self, path: &'a str) -> &'a str {
        let base_path = self.auth_config.base_path.as_str();
        if !base_path.is_empty() && base_path != "/" {
            path.strip_prefix(base_path).unwrap_or(path)
        } else {
            path
        }
    }

    fn is_form_csrf_path(path: &str) -> bool {
        matches!(path, "/sign-in/email" | "/sign-up/email")
    }

    fn header<'a>(req: &'a AuthRequest, name: &str) -> Option<&'a str> {
        req.headers
            .iter()
            .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
    }

    fn has_cookies(req: &AuthRequest) -> bool {
        Self::header(req, "cookie").is_some()
    }

    fn has_fetch_metadata(req: &AuthRequest) -> bool {
        ["sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"]
            .into_iter()
            .any(|name| Self::header(req, name).is_some_and(|value| !value.trim().is_empty()))
    }

    fn validate_origin(&self, req: &AuthRequest, force_validate: bool) -> Result<(), AuthError> {
        if self.auth_config.advanced.disable_csrf_check == Some(true)
            || self.auth_config.origin_check_disabled_for(req.path())
        {
            return Ok(());
        }

        if !force_validate && !Self::has_cookies(req) {
            return Ok(());
        }

        let inferred = (Self::header(req, "origin") == Some("null")
            && Self::header(req, "sec-fetch-site") == Some("same-origin"))
        .then(|| req.url().and_then(|url| extract_origin(url.as_str())))
        .flatten();
        let origin = inferred
            .or_else(|| {
                Self::header(req, "origin")
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .or_else(|| Self::header(req, "referer").and_then(extract_origin))
            })
            .filter(|value| value != "null")
            .ok_or_else(|| AuthError::forbidden(MISSING_OR_NULL_ORIGIN))?;

        if self.auth_config.is_origin_trusted(&origin) {
            Ok(())
        } else {
            Err(AuthError::forbidden(INVALID_ORIGIN))
        }
    }

    fn validate_form_csrf(&self, req: &AuthRequest) -> Result<(), AuthError> {
        if self.auth_config.advanced.disable_csrf_check == Some(true)
            || self.auth_config.advanced.disable_origin_check
                && self.auth_config.advanced.disable_csrf_check.is_none()
        {
            return Ok(());
        }

        if Self::has_cookies(req) {
            return self.validate_origin(req, false);
        }

        if Self::has_fetch_metadata(req) {
            let is_cross_site_navigation = matches!(
                (
                    Self::header(req, "sec-fetch-site"),
                    Self::header(req, "sec-fetch-mode"),
                ),
                (Some("cross-site"), Some("navigate"))
            );

            if is_cross_site_navigation {
                return Err(AuthError::forbidden(CROSS_SITE_NAVIGATION_LOGIN_BLOCKED));
            }

            return self.validate_origin(req, true);
        }

        if Self::header(req, "origin").is_some_and(|value| !value.is_empty())
            || Self::header(req, "referer").is_some_and(|value| !value.is_empty())
        {
            return self.validate_origin(req, true);
        }
        Ok(())
    }

    fn validate_redirect_targets(&self, req: &AuthRequest) -> Result<(), AuthError> {
        if self.auth_config.origin_check_disabled_for(req.path()) {
            return Ok(());
        }

        for (name, value) in Self::request_target_values(req)? {
            if !self.auth_config.is_redirect_target_trusted(&value) {
                return Err(AuthError::forbidden(Self::target_error_message(name)));
            }
        }

        Ok(())
    }

    fn request_target_values(req: &AuthRequest) -> Result<Vec<(&'static str, String)>, AuthError> {
        let body = Self::request_body_map(req).unwrap_or_default();
        let mut targets = Vec::new();
        for (key, label) in [
            ("callbackURL", "callbackURL"),
            ("redirectTo", "redirectURL"),
            ("errorCallbackURL", "errorCallbackURL"),
            ("newUserCallbackURL", "newUserCallbackURL"),
        ] {
            let value = body
                .get(key)
                .filter(|value| Self::is_truthy(value))
                .cloned()
                .or_else(|| {
                    (key == "callbackURL")
                        .then(|| req.query.get(key))
                        .flatten()
                        .filter(|value| !value.is_empty())
                        .cloned()
                        .map(serde_json::Value::String)
                });
            let Some(value) = value else {
                continue;
            };
            let Some(value) = value.as_str() else {
                return Err(AuthError::bad_request(format!(
                    "Invalid {label}: expected a string"
                )));
            };
            targets.push((key, value.to_owned()));
        }
        Ok(targets)
    }

    fn is_truthy(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Null => false,
            serde_json::Value::Bool(value) => *value,
            serde_json::Value::Number(value) => value.as_f64() != Some(0.0),
            serde_json::Value::String(value) => !value.is_empty(),
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => true,
        }
    }

    fn request_body_map(req: &AuthRequest) -> Option<serde_json::Map<String, serde_json::Value>> {
        let content_type = Self::header(req, "content-type").unwrap_or_default();
        if content_type.contains("application/x-www-form-urlencoded") {
            let body = req.body.as_ref()?;
            return Some(
                url::form_urlencoded::parse(body)
                    .map(|(key, value)| {
                        (
                            key.into_owned(),
                            serde_json::Value::String(value.into_owned()),
                        )
                    })
                    .collect(),
            );
        }
        req.body_as_json::<serde_json::Value>()
            .ok()?
            .as_object()
            .cloned()
    }

    fn target_error_message(name: &str) -> &'static str {
        match name {
            "callbackURL" => INVALID_CALLBACK_URL,
            "redirectTo" => INVALID_REDIRECT_URL,
            "errorCallbackURL" => INVALID_ERROR_CALLBACK_URL,
            "newUserCallbackURL" => INVALID_NEW_USER_CALLBACK_URL,
            _ => INVALID_ORIGIN,
        }
    }

    fn reject(error: AuthError) -> AuthResponse {
        error.to_auth_response()
    }

    /// Router protection after route/body resolution and before application hooks.
    ///
    /// # Errors
    /// Rejects untrusted request origins and redirect targets.
    pub fn check_request_origin(&self, req: &AuthRequest) -> AuthResult<()> {
        if !self.config.enabled || !Self::is_state_changing(req.method()) {
            return Ok(());
        }
        self.validate_origin(req, false)?;
        self.validate_redirect_targets(req)
    }

    /// Endpoint-local first-login protection, after application before hooks.
    ///
    /// # Errors
    /// Rejects cross-site navigation or untrusted first-login origins.
    pub fn check_form_origin(&self, req: &AuthRequest) -> AuthResult<()> {
        if self.config.enabled
            && Self::is_state_changing(req.method())
            && Self::is_form_csrf_path(self.normalized_path(req.path()))
        {
            self.validate_form_csrf(req)?;
        }
        Ok(())
    }
}

#[async_trait]
impl Middleware for CsrfMiddleware {
    fn name(&self) -> &'static str {
        "csrf"
    }

    async fn before_request(&self, req: &AuthRequest) -> AuthResult<Option<AuthResponse>> {
        if !self.config.enabled || !Self::is_state_changing(req.method()) {
            return Ok(None);
        }

        let path = self.normalized_path(req.path());
        let csrf_result = if Self::is_form_csrf_path(path) {
            self.validate_form_csrf(req)
        } else {
            self.validate_origin(req, false)
        };

        if let Err(error) = csrf_result {
            return Ok(Some(Self::reject(error)));
        }

        if let Err(error) = self.validate_redirect_targets(req) {
            return Ok(Some(Self::reject(error)));
        }

        Ok(None)
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(
        path: &str,
        origin: Option<&str>,
        cookie: bool,
        extra_headers: &[(&str, &str)],
    ) -> AuthRequest {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        if let Some(origin) = origin {
            headers.insert("origin".to_owned(), origin.to_owned());
        }
        if cookie {
            headers.insert(
                "cookie".to_owned(),
                "better-auth.session_token=test-token".to_owned(),
            );
        }
        for (name, value) in extra_headers {
            headers.insert((*name).to_owned(), (*value).to_owned());
        }
        AuthRequest::from_parts(
            HttpMethod::Post,
            path.to_owned(),
            headers,
            None,
            HashMap::new(),
        )
    }

    fn test_auth_config(trusted_origins: Vec<String>) -> Arc<AuthConfig> {
        Arc::new(
            AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
                .base_url("http://localhost:3000")
                .trusted_origins(trusted_origins),
        )
    }

    fn forbidden_message(response: Option<AuthResponse>) -> String {
        let response = response.expect("expected rejection response");
        assert_eq!(response.status, 403);
        let body = serde_json::from_slice::<serde_json::Value>(&response.body).unwrap();
        (*(body).get("message").unwrap_or(&serde_json::Value::Null))
            .as_str()
            .unwrap()
            .to_owned()
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn cookie_backed_requests_require_a_trusted_origin() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        let req = make_request("/sign-out", Some("http://evil.com"), true, &[]);
        let message = forbidden_message(mw.before_request(&req).await.unwrap());
        assert_eq!(message, INVALID_ORIGIN);
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn cookie_backed_requests_require_origin_or_referer() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        let req = make_request("/sign-out", None, true, &[]);
        let message = forbidden_message(mw.before_request(&req).await.unwrap());
        assert_eq!(message, MISSING_OR_NULL_ORIGIN);
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn sign_in_allows_same_origin_fetch_metadata_requests() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        let req = make_request(
            "/sign-in/email",
            Some("http://localhost:3000"),
            false,
            &[
                ("sec-fetch-site", "same-origin"),
                ("sec-fetch-mode", "cors"),
            ],
        );
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn sign_in_blocks_cross_site_navigation_login_attempts() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        let req = make_request(
            "/sign-in/email",
            Some("http://evil.com"),
            false,
            &[
                ("sec-fetch-site", "cross-site"),
                ("sec-fetch-mode", "navigate"),
            ],
        );
        let message = forbidden_message(mw.before_request(&req).await.unwrap());
        assert_eq!(message, CROSS_SITE_NAVIGATION_LOGIN_BLOCKED);
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn sign_up_rejects_untrusted_origin_without_metadata() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        let req = make_request("/sign-up/email", Some("http://evil.com"), false, &[]);
        assert_eq!(
            forbidden_message(mw.before_request(&req).await.unwrap()),
            "Invalid origin"
        );
    }

    // Pinned origin-check middleware applies JavaScript truthiness, then checks
    // each redirect field's type before route schema parsing.
    #[tokio::test]
    async fn redirect_targets_enforce_types_origins_and_callback_precedence() {
        let mw = CsrfMiddleware::new(CsrfConfig::new(), test_auth_config(vec![]));
        for (field, label) in [
            ("callbackURL", "callbackURL"),
            ("redirectTo", "redirectURL"),
            ("errorCallbackURL", "errorCallbackURL"),
            ("newUserCallbackURL", "newUserCallbackURL"),
        ] {
            for value in [
                serde_json::json!(5),
                serde_json::json!(true),
                serde_json::json!([]),
                serde_json::json!({}),
            ] {
                let mut req = make_request("/send-verification-email", None, false, &[]);
                req.body = Some(serde_json::json!({field:value}).to_string().into_bytes());
                let response = mw
                    .before_request(&req)
                    .await
                    .unwrap()
                    .expect("truthy non-string redirect must be rejected before the route");
                assert_eq!(response.status, 400);
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&response.body).unwrap(),
                    serde_json::json!({"message":format!("Invalid {label}: expected a string")})
                );
            }
            for value in [
                serde_json::Value::Null,
                serde_json::json!(false),
                serde_json::json!(0),
                serde_json::json!(""),
            ] {
                let mut req = make_request("/send-verification-email", None, false, &[]);
                req.body = Some(serde_json::json!({field:value}).to_string().into_bytes());
                assert!(mw.before_request(&req).await.unwrap().is_none());
            }
        }
        let mut request = make_request("/send-verification-email", None, false, &[]);
        request.query.insert(
            "callbackURL".to_owned(),
            "http://evil.com/dashboard".to_owned(),
        );
        request.body = Some(
            serde_json::json!({"callbackURL":"/safe"})
                .to_string()
                .into_bytes(),
        );
        assert!(
            mw.before_request(&request).await.unwrap().is_none(),
            "the body callback overrides the query callback"
        );
        request.body = Some(
            serde_json::json!({"callbackURL":null})
                .to_string()
                .into_bytes(),
        );
        let message = forbidden_message(mw.before_request(&request).await.unwrap());
        assert_eq!(
            message, INVALID_CALLBACK_URL,
            "a falsy body callback falls back to the query"
        );
        request.query.clear();
        request.query.insert(
            "redirectTo".to_owned(),
            "http://evil.com/ignored".to_owned(),
        );
        assert!(
            mw.before_request(&request).await.unwrap().is_none(),
            "upstream reads other redirects from the body only"
        );
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn csrf_can_be_disabled_explicitly() {
        let mw = CsrfMiddleware::new(CsrfConfig::new().enabled(false), test_auth_config(vec![]));
        let req = make_request("/sign-out", Some("http://evil.com"), true, &[]);
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[tokio::test]
    async fn advanced_disable_origin_check_skips_callback_url_validation() {
        let mut config = AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
            .base_url("http://localhost:3000")
            .disable_origin_check(true);
        config.trusted_origins = vec![];
        let mw = CsrfMiddleware::new(CsrfConfig::new(), Arc::new(config));
        let mut req = make_request("/sign-in/social", None, false, &[]);
        req.body = Some(
            serde_json::json!({
                "provider": "google",
                "callbackURL": "http://evil.com/dashboard"
            })
            .to_string()
            .into_bytes(),
        );

        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    // Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
    #[test]
    fn extract_origin_still_handles_paths() {
        assert_eq!(
            extract_origin("https://example.com/path"),
            Some("https://example.com".to_owned())
        );
        assert_eq!(
            extract_origin("http://localhost:3000"),
            Some("http://localhost:3000".to_owned())
        );
        assert_eq!(extract_origin("not-a-url"), None);
    }
}
// LCOV_EXCL_STOP
