//! `OpenAPI` schema generation and Scalar reference page.
use async_trait::async_trait;
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, HttpMethod, OpenApiBuilder, OpenApiRegistry, PluginOpenApiMetadata,
};

#[derive(Debug, Clone, Default)]
pub struct OpenApiConfig {
    pub path: Option<String>,
    pub theme: Option<String>,
    pub nonce: Option<String>,
    pub disable_default_reference: bool,
    /// Include native Rust extensions; defaults to pinned-equivalent documentation.
    pub include_native_extensions: bool,
}
impl OpenApiConfig {
    #[must_use]
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }
    #[must_use]
    pub fn theme(mut self, theme: impl Into<String>) -> Self {
        self.theme = Some(theme.into());
        self
    }
    #[must_use]
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
    #[must_use]
    pub const fn include_native_extensions(mut self, included: bool) -> Self {
        self.include_native_extensions = included;
        self
    }
    #[must_use]
    pub const fn disable_default_reference(mut self, disabled: bool) -> Self {
        self.disable_default_reference = disabled;
        self
    }
}
#[derive(Debug, Clone, Default)]
pub struct OpenApiPlugin {
    config: OpenApiConfig,
}
impl OpenApiPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub const fn with_config(config: OpenApiConfig) -> Self {
        Self { config }
    }
    fn path(&self) -> &str {
        self.config.path.as_deref().unwrap_or("/reference")
    }
}
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for OpenApiPlugin {
    fn name(&self) -> &'static str {
        "open-api"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/open-api/generate-schema", "generate_open_api_schema"),
            AuthRoute::get(self.path(), "open_api_reference"),
        ]
    }
    fn openapi_metadata(&self, _ctx: &AuthInitContext<S>) -> PluginOpenApiMetadata {
        PluginOpenApiMetadata::default()
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.method() != &HttpMethod::Get
            || (req.path() != "/open-api/generate-schema" && req.path() != self.path())
        {
            return Ok(None);
        }
        if req.path() != "/open-api/generate-schema" && self.config.disable_default_reference {
            return Ok(Some(
                AuthResponse::new(404).with_header("content-type", "application/json"),
            ));
        }
        let registry = ctx
            .extensions
            .get::<OpenApiRegistry>()
            .ok_or_else(|| AuthError::internal("OpenAPI registry is not initialized"))?;
        let spec = OpenApiBuilder::registered_with_native_extensions(
            &ctx.config,
            &registry,
            self.config.include_native_extensions,
        )
        .build();
        if req.path() == "/open-api/generate-schema" {
            return Ok(Some(AuthResponse::json(200, &spec)?));
        }
        let schema = serde_json::to_string(&spec)?;
        Ok(Some(
            AuthResponse::html(200, reference_html(&schema, &self.config))
                .with_header("content-type", "text/html"),
        ))
    }
}
fn reference_html(schema: &str, config: &OpenApiConfig) -> String {
    let nonce = config
        .nonce
        .as_deref()
        .filter(|nonce| !nonce.is_empty())
        .map(|nonce| format!("nonce=\"{nonce}\""))
        .unwrap_or_default();
    let theme = config
        .theme
        .as_deref()
        .filter(|theme| !theme.is_empty())
        .unwrap_or("default");
    // The bundled upstream brand asset is MIT-licensed Better Auth artwork.
    let favicon = encode_uri_component(include_str!("logo.svg"));
    format!(
        r#"<!doctype html>
<html>
  <head>
    <title>Scalar API Reference</title>
    <meta charset="utf-8" />
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script
      id="api-reference"
      type="application/json">
    {schema}
    </script>
	 <script {nonce}>
      var configuration = {{
	  	favicon: "data:image/svg+xml;utf8,{favicon}",
	   	theme: "{theme}",
        metaData: {{
			title: "Better Auth API",
			description: "API Reference for your Better Auth Instance",
		}}
      }}

      document.getElementById('api-reference').dataset.configuration =
        JSON.stringify(configuration)
    </script>
	  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference" {nonce}></script>
  </body>
</html>"#
    )
}
fn encode_uri_component(input: &str) -> String {
    let mut output = String::new();

    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(hex_digit(byte >> 4));
            output.push(hex_digit(byte & 15));
        }
    }
    output
}

fn hex_digit(digit: u8) -> char {
    char::from(if digit < 10 {
        b'0' + digit
    } else {
        b'A' + digit - 10
    })
}
