#[cfg(test)]
mod tests;

use super::Middleware;

use crate::error::AuthResult;

use crate::types::{AuthRequest, AuthResponse, HttpMethod};

use async_trait::async_trait;

/// Configuration for CORS middleware.
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins. An empty list means no CORS headers are added.
    /// Use `["*"]` to allow all origins (not recommended for production).
    pub allowed_origins: Vec<String>,

    /// Allowed HTTP methods. Defaults to common auth methods.
    pub allowed_methods: Vec<String>,

    /// Allowed request headers.
    pub allowed_headers: Vec<String>,

    /// Headers exposed to the browser.
    pub exposed_headers: Vec<String>,

    /// Whether credentials (cookies, authorization) are allowed.
    pub allow_credentials: bool,

    /// Max age for preflight cache (seconds).
    pub max_age: u64,

    /// Whether CORS handling is enabled.
    pub enabled: bool,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            allowed_methods: vec![
                "GET".into(),
                "POST".into(),
                "PUT".into(),
                "DELETE".into(),
                "PATCH".into(),
                "OPTIONS".into(),
            ],
            allowed_headers: vec![
                "Content-Type".into(),
                "Authorization".into(),
                "X-Requested-With".into(),
            ],
            exposed_headers: Vec::new(),
            allow_credentials: true,
            max_age: 86400,
            enabled: true,
        }
    }
}

impl CorsConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn allowed_origin(mut self, origin: impl Into<String>) -> Self {
        self.allowed_origins.push(origin.into());
        self
    }

    #[must_use]
    pub const fn allow_credentials(mut self, allow: bool) -> Self {
        self.allow_credentials = allow;
        self
    }

    #[must_use]
    pub const fn max_age(mut self, seconds: u64) -> Self {
        self.max_age = seconds;
        self
    }

    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// CORS middleware.
///
/// Handles preflight OPTIONS requests and adds CORS response headers.
#[derive(Debug)]
pub struct CorsMiddleware {
    config: CorsConfig,
}

impl CorsMiddleware {
    #[must_use]
    pub const fn new(config: CorsConfig) -> Self {
        Self { config }
    }

    fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.config.allowed_origins.is_empty() {
            return false;
        }
        self.config
            .allowed_origins
            .iter()
            .any(|o| o == "*" || o == origin)
    }

    fn cors_headers(&self, origin: &str) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        // Use the request origin if allowed (not wildcard when credentials are on)
        let allow_origin = if self.config.allow_credentials {
            origin.to_owned()
        } else if self.config.allowed_origins.contains(&"*".to_owned()) {
            "*".to_owned()
        } else {
            origin.to_owned()
        };

        headers.push(("Access-Control-Allow-Origin".into(), allow_origin));

        if self.config.allow_credentials {
            headers.push(("Access-Control-Allow-Credentials".into(), "true".into()));
        }

        if !self.config.allowed_methods.is_empty() {
            headers.push((
                "Access-Control-Allow-Methods".into(),
                self.config.allowed_methods.join(", "),
            ));
        }

        if !self.config.allowed_headers.is_empty() {
            headers.push((
                "Access-Control-Allow-Headers".into(),
                self.config.allowed_headers.join(", "),
            ));
        }

        if !self.config.exposed_headers.is_empty() {
            headers.push((
                "Access-Control-Expose-Headers".into(),
                self.config.exposed_headers.join(", "),
            ));
        }

        headers.push((
            "Access-Control-Max-Age".into(),
            self.config.max_age.to_string(),
        ));

        headers
    }
}

#[async_trait]
impl Middleware for CorsMiddleware {
    fn name(&self) -> &'static str {
        "cors"
    }

    async fn before_request(&self, req: &AuthRequest) -> AuthResult<Option<AuthResponse>> {
        if !self.config.enabled {
            return Ok(None);
        }

        let origin = match req.headers.get("origin") {
            Some(o) => o.clone(),
            None => return Ok(None), // No Origin header → not a CORS request
        };

        if !self.is_origin_allowed(&origin) {
            return Ok(None); // Origin not allowed → skip CORS headers
        }

        // Handle preflight
        if req.method == HttpMethod::Options {
            let mut response = AuthResponse::new(204);
            for (key, value) in self.cors_headers(&origin) {
                response = response.with_header(key, value);
            }
            return Ok(Some(response));
        }

        Ok(None)
    }

    async fn after_request(
        &self,
        req: &AuthRequest,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        if !self.config.enabled {
            return Ok(response);
        }

        let origin = match req.headers.get("origin") {
            Some(o) => o.clone(),
            None => return Ok(response),
        };

        if !self.is_origin_allowed(&origin) {
            return Ok(response);
        }

        for (key, value) in self.cors_headers(&origin) {
            drop(response.headers.insert(key, value));
        }

        Ok(response)
    }
}
