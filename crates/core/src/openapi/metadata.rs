//! Runtime documentation metadata, independent of route dispatch and database column names.
use crate::{AuthRoute, HttpMethod};
use indexmap::IndexMap;
use serde_json::{Value, json};

/// A model field's wire schema and input/output policy.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenApiField {
    pub name: String,
    pub schema: Value,
    pub required: bool,
    pub input: bool,
    pub returned: bool,
}
impl OpenApiField {
    pub fn new(name: impl Into<String>, schema: Value, required: bool) -> Self {
        Self {
            name: name.into(),
            schema,
            required,
            input: true,
            returned: true,
        }
    }
    pub fn read_only(mut self) -> Self {
        self.input = false;
        self
    }
    pub fn hidden(mut self) -> Self {
        self.returned = false;
        self
    }
}

/// An ordered model definition. Repeated registrations merge fields by wire name.
#[derive(Debug, Clone)]
pub struct OpenApiModel {
    pub name: String,
    pub fields: Vec<OpenApiField>,
}
impl OpenApiModel {
    pub fn new(name: impl Into<String>, fields: Vec<OpenApiField>) -> Self {
        Self {
            name: name.into(),
            fields,
        }
    }
    pub(crate) fn to_schema(&self) -> Value {
        let mut properties = serde_json::Map::new();
        let _ = properties.insert("id".into(), json!({"type":"string","readOnly":true}));
        let mut required = vec!["id".to_string()];
        for field in &self.fields {
            let mut schema = field.schema.clone();
            if !field.input
                && let Some(object) = schema.as_object_mut()
            {
                let _ = object.insert("readOnly".into(), json!(true));
            }
            let _ = properties.insert(field.name.clone(), schema);
            if field.required && field.returned && !required.contains(&field.name) {
                required.push(field.name.clone());
            }
        }
        json!({"type":"object","properties":properties,"required":required})
    }
}

/// Rich metadata for one route; dispatch still comes exclusively from `AuthRoute`.
#[derive(Debug, Clone, Default)]
pub struct OpenApiEndpoint {
    /// Canonical document template when dispatch uses equivalent parameter names.
    pub document_path: Option<String>,
    pub operation_id: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub parameters: Vec<Value>,
    pub request_body: Option<Value>,
    pub responses: IndexMap<String, Value>,
    pub server_only: bool,
    /// Rust extension omitted by the pinned-equivalent document policy.
    pub native_extension: bool,
}

/// A plugin's endpoint annotations and schema additions.
#[derive(Debug, Clone, Default)]
pub struct PluginOpenApiMetadata {
    pub endpoints: Vec<(HttpMethod, String, OpenApiEndpoint)>,
    pub models: Vec<OpenApiModel>,
}
impl PluginOpenApiMetadata {
    pub fn endpoint(
        mut self,
        method: HttpMethod,
        path: impl Into<String>,
        metadata: OpenApiEndpoint,
    ) -> Self {
        self.endpoints.push((method, path.into(), metadata));
        self
    }
    pub fn model(mut self, model: OpenApiModel) -> Self {
        self.models.push(model);
        self
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RegisteredEndpoint {
    pub route: AuthRoute,
    pub plugin: String,
    pub core: bool,
    pub metadata: OpenApiEndpoint,
}

/// Immutable snapshot of the routes and model projections registered on one auth instance.
#[derive(Debug, Clone, Default)]
pub struct OpenApiRegistry {
    pub(crate) endpoints: Vec<RegisteredEndpoint>,
    pub(crate) models: IndexMap<String, OpenApiModel>,
    pub(crate) user_input_fields: IndexMap<String, OpenApiField>,
    pub(crate) core_overrides: Vec<OpenApiModel>,
}
impl OpenApiRegistry {
    /// Actual dispatch routes, including routes omitted from generated documentation.
    pub fn registered_routes(&self) -> Vec<AuthRoute> {
        self.endpoints
            .iter()
            .map(|endpoint| endpoint.route.clone())
            .collect()
    }

    pub fn new(models: Vec<OpenApiModel>) -> Self {
        let mut registry = Self::default();
        let defaults = super::annotations::core_models();
        for model in models {
            if let Some(default) = defaults.iter().find(|default| default.name == model.name) {
                let overrides = model
                    .fields
                    .iter()
                    .filter(|field| !default.fields.contains(field))
                    .cloned()
                    .collect::<Vec<_>>();
                if model.name == "User" {
                    for field in &overrides {
                        let _ = registry
                            .user_input_fields
                            .insert(field.name.clone(), field.clone());
                    }
                }
                if !overrides.is_empty() {
                    registry
                        .core_overrides
                        .push(OpenApiModel::new(model.name.clone(), overrides));
                }
            }
            registry.merge_model(model);
        }
        registry
    }
    pub fn register(
        &mut self,
        plugin: &str,
        routes: Vec<AuthRoute>,
        metadata: PluginOpenApiMetadata,
    ) {
        for route in routes {
            let annotation = metadata
                .endpoints
                .iter()
                .find(|(method, path, _)| *method == route.method && *path == route.path)
                .map(|(_, _, value)| value.clone())
                .unwrap_or_default();
            let owner = if plugin == "email-password"
                && matches!(
                    route.path.as_str(),
                    "/sign-in/username" | "/is-username-available"
                ) {
                "username"
            } else {
                plugin
            };
            self.endpoints.push(RegisteredEndpoint {
                core: super::annotations::is_core(owner),
                plugin: owner.into(),
                route,
                metadata: annotation,
            });
        }
        for model in metadata.models {
            if model.name == "User" {
                for field in &model.fields {
                    let _ = self
                        .user_input_fields
                        .insert(field.name.clone(), field.clone());
                }
            }
            self.merge_model(model);
        }
    }
    fn merge_model(&mut self, model: OpenApiModel) {
        if let Some(existing) = self.models.get_mut(&model.name) {
            for field in model.fields {
                if let Some(current) = existing
                    .fields
                    .iter_mut()
                    .find(|current| current.name == field.name)
                {
                    *current = field;
                } else {
                    existing.fields.push(field);
                }
            }
        } else {
            let _ = self.models.insert(model.name.clone(), model);
        }
    }
}
