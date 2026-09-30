//! OpenAPI 3.1.1 documents built from each auth instance's registered metadata.
pub mod annotations;
mod metadata;
mod model_annotations;
mod session_annotations;
pub use metadata::{
    OpenApiEndpoint, OpenApiField, OpenApiModel, OpenApiRegistry, PluginOpenApiMetadata,
};

use crate::{AuthConfig, AuthPlugin, AuthSchema, HttpMethod};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Serialize)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub info: OpenApiInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub security: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Value>,
    pub paths: BTreeMap<String, BTreeMap<String, OpenApiOperation>>,
}
#[derive(Debug, Serialize)]
pub struct OpenApiInfo {
    pub title: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct OpenApiOperation {
    #[serde(rename = "operationId", skip_serializing_if = "String::is_empty")]
    pub operation_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub summary: String,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub security: Vec<Value>,
    pub parameters: Vec<Value>,
    #[serde(rename = "requestBody", skip_serializing_if = "Option::is_none")]
    pub request_body: Option<Value>,
    pub responses: BTreeMap<String, OpenApiResponse>,
}
#[derive(Debug, Clone, Serialize)]
pub struct OpenApiResponse {
    pub description: String,
    #[serde(flatten)]
    pub metadata: serde_json::Map<String, Value>,
}

/// Embedded builder, also used by the HTTP OpenAPI plugin.
pub struct OpenApiBuilder {
    spec: OpenApiSpec,
    used_ids: HashSet<String>,
}
impl OpenApiBuilder {
    pub fn new(title: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            spec: OpenApiSpec {
                openapi: "3.1.1".into(),
                info: OpenApiInfo {
                    title: title.into(),
                    version: version.into(),
                    description: None,
                },
                components: None,
                security: vec![],
                servers: vec![],
                tags: vec![],
                paths: BTreeMap::new(),
            },
            used_ids: HashSet::new(),
        }
    }
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.spec.info.description = Some(description.into());
        self
    }
    /// Construct the upstream document defaults from an immutable instance snapshot.
    pub fn registered(config: &AuthConfig, registry: &OpenApiRegistry) -> Self {
        let mut builder = Self::new("Better Auth", "1.1.0")
            .description("API Reference for your Better Auth Instance");
        let mut schemas = serde_json::Map::new();
        for model in registry.models.values() {
            let _ = schemas.insert(model.name.clone(), model.to_schema());
        }
        builder.spec.components = Some(json!({"schemas":schemas,"securitySchemes":{
            "apiKeyCookie":{"type":"apiKey","in":"cookie","name":"apiKeyCookie","description":"API Key authentication via cookie"},
            "bearerAuth":{"type":"http","scheme":"bearer","description":"Bearer token authentication"}
        }}));
        builder.spec.security = vec![json!({"apiKeyCookie":[],"bearerAuth":[]})];
        builder.spec.servers = vec![
            json!({"url":format!("{}{}",config.base_url.trim_end_matches('/'),config.base_path)}),
        ];
        builder.spec.tags = vec![
            json!({"name":"Default","description":"Default endpoints that are included with Better Auth by default. These endpoints are not part of any plugin."}),
        ];
        // Core endpoints precede plugin endpoints, regardless of the Rust plugin layout.
        for core in [true, false] {
            for endpoint in registry
                .endpoints
                .iter()
                .filter(|endpoint| endpoint.core == core)
            {
                if endpoint.plugin == "open-api"
                    || endpoint.metadata.server_only
                    || config.is_path_disabled(&endpoint.route.path)
                {
                    continue;
                }
                builder = builder.annotated(
                    &endpoint.route.method,
                    &endpoint.route.path,
                    &endpoint.plugin,
                    endpoint.core,
                    &endpoint.metadata,
                );
            }
        }
        builder
    }
    pub fn annotated(
        mut self,
        method: &HttpMethod,
        path: &str,
        plugin: &str,
        core: bool,
        metadata: &OpenApiEndpoint,
    ) -> Self {
        let method_name = match method {
            HttpMethod::Get => "get",
            HttpMethod::Post => "post",
            HttpMethod::Put => "put",
            HttpMethod::Delete => "delete",
            HttpMethod::Patch => "patch",
            HttpMethod::Options | HttpMethod::Head => return self,
        };
        if metadata.server_only {
            return self;
        }
        let mut parameters = metadata.parameters.clone();
        let path=path.split('/').map(|segment| {
            if let Some(name)=segment.strip_prefix(':') {
                if !parameters.iter().any(|parameter|parameter["in"]=="path" && parameter["name"]==name) { parameters.push(json!({"name":name,"in":"path","required":true,"schema":{"type":"string"}})); }
                format!("{{{name}}}")
            } else { segment.to_string() }
        }).collect::<Vec<_>>().join("/");
        let operation_id = metadata
            .operation_id
            .as_ref()
            .map(|id| {
                let mut candidate = id.clone();
                if self.used_ids.contains(&candidate) {
                    let mut chars = method_name.chars();
                    let suffix = chars
                        .next()
                        .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                        .unwrap_or_default();
                    candidate = format!("{id}{suffix}");
                    let mut index = 2;
                    while self.used_ids.contains(&candidate) {
                        candidate = format!("{id}{suffix}{index}");
                        index += 1;
                    }
                }
                let _ = self.used_ids.insert(candidate.clone());
                candidate
            })
            .unwrap_or_default();
        let mut responses = default_responses();
        for (status, response) in &metadata.responses {
            let mut fields = response.as_object().cloned().unwrap_or_default();
            let description = fields
                .remove("description")
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_default();
            let _ = responses.insert(
                status.clone(),
                OpenApiResponse {
                    description,
                    metadata: fields,
                },
            );
        }
        let tags = if core {
            let mut tags = vec!["Default".into()];
            tags.extend(metadata.tags.clone().unwrap_or_default());
            tags
        } else {
            metadata.tags.clone().unwrap_or_else(|| {
                let mut chars = plugin.chars();
                vec![
                    chars
                        .next()
                        .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                        .unwrap_or_default(),
                ]
            })
        };
        let mut request_body = metadata.request_body.clone();
        if core
            && request_body.is_none()
            && matches!(
                method,
                HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch
            )
        {
            request_body = Some(
                json!({"content":{"application/json":{"schema":{"type":"object","properties":{}}}}}),
            );
        }
        let _ = self.spec.paths.entry(path).or_default().insert(
            method_name.into(),
            OpenApiOperation {
                operation_id,
                summary: String::new(),
                description: metadata.description.clone(),
                tags,
                security: vec![json!({"bearerAuth":[]})],
                parameters,
                request_body,
                responses,
            },
        );
        self
    }
    pub fn route(self, method: &HttpMethod, path: &str, operation_id: &str, tag: &str) -> Self {
        let metadata = OpenApiEndpoint {
            operation_id: Some(operation_id.into()),
            tags: Some(vec![tag.into()]),
            ..Default::default()
        };
        self.annotated(method, path, tag, false, &metadata)
    }
    pub fn plugin<S: AuthSchema>(mut self, plugin: &dyn AuthPlugin<S>) -> Self {
        let routes = plugin.routes();
        let metadata = annotations::plugin_metadata(plugin.name(), &routes);
        for route in routes {
            let annotation = metadata
                .endpoints
                .iter()
                .find(|(method, path, _)| *method == route.method && *path == route.path)
                .map(|(_, _, metadata)| metadata.clone())
                .unwrap_or_default();
            self = self.annotated(
                &route.method,
                &route.path,
                plugin.name(),
                annotations::is_core(plugin.name()),
                &annotation,
            );
        }
        self
    }
    pub fn core_routes(self) -> Self {
        self.route(&HttpMethod::Get, "/ok", "ok", "core")
            .route(&HttpMethod::Get, "/error", "error", "core")
            .route(&HttpMethod::Post, "/update-user", "update_user", "core")
    }
    pub fn build(self) -> OpenApiSpec {
        self.spec
    }
}
fn default_responses() -> BTreeMap<String, OpenApiResponse> {
    [
        ("400","Bad Request. Usually due to missing parameters, or invalid parameters."),
        ("401","Unauthorized. Due to missing or invalid authentication."),
        ("403","Forbidden. You do not have permission to access this resource or to perform this action."),
        ("404","Not Found. The requested resource was not found."),
        ("429","Too Many Requests. You have exceeded the rate limit. Try again later."),
        ("500","Internal Server Error. This is a problem with the server that you cannot fix."),
    ].into_iter().map(|(status,description)| {
        let mut schema=json!({"type":"object","properties":{"message":{"type":"string"}}});
        if (status=="400" || status=="401") && let Some(object)=schema.as_object_mut() {let _=object.insert("required".into(),json!(["message"]));}
        let mut metadata=serde_json::Map::new();let _ = metadata.insert("content".into(),json!({"application/json":{"schema":schema}}));
        (status.into(),OpenApiResponse {description:description.into(),metadata})
    }).collect()
}
impl OpenApiSpec {
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
    pub fn to_value(&self) -> serde_json::Result<Value> {
        serde_json::to_value(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Rust-specific surface: `OpenApiBuilder` and `OpenApiSpec` are Rust-specific public APIs for embedded schema generation.
    #[test]
    fn test_builder_core_routes() {
        let spec = OpenApiBuilder::new("Better Auth", "0.1.0")
            .description("Authentication API")
            .core_routes()
            .build();

        assert_eq!(spec.openapi, "3.1.1");
        assert_eq!(spec.info.title, "Better Auth");
        assert!(spec.paths.contains_key("/ok"));
        assert!(spec.paths.contains_key("/error"));
        assert!(spec.paths.contains_key("/update-user"));

        // /ok should have a GET operation
        let ok_path = &spec.paths["/ok"];
        assert!(ok_path.contains_key("get"));
        assert_eq!(ok_path["get"].operation_id, "ok");
    }

    // Rust-specific surface: `OpenApiBuilder` and `OpenApiSpec` are Rust-specific public APIs for embedded schema generation.
    #[test]
    fn test_builder_custom_route() {
        let spec = OpenApiBuilder::new("Test", "1.0.0")
            .route(
                &HttpMethod::Post,
                "/sign-in/email",
                "sign_in_email",
                "email-password",
            )
            .build();

        let path = &spec.paths["/sign-in/email"];
        assert!(path.contains_key("post"));
        assert_eq!(path["post"].tags, vec!["email-password"]);
    }

    // Rust-specific surface: `OpenApiBuilder` and `OpenApiSpec` are Rust-specific public APIs for embedded schema generation.
    #[test]
    fn test_spec_to_json() {
        let spec = OpenApiBuilder::new("Test", "1.0.0").core_routes().build();

        let json = spec.to_json().unwrap();
        assert!(json.contains("\"openapi\": \"3.1.1\""));
        assert!(json.contains("\"/ok\""));
    }

    // Rust-specific surface: `OpenApiBuilder` and `OpenApiSpec` are Rust-specific public APIs for embedded schema generation.
    #[test]
    fn test_spec_to_value() {
        let spec = OpenApiBuilder::new("Test", "1.0.0").core_routes().build();

        let value = spec.to_value().unwrap();
        assert_eq!(value["openapi"], "3.1.1");
        assert!(value["paths"]["/ok"]["get"]["operationId"].is_string());
    }
}
