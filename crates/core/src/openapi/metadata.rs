//! Runtime documentation metadata, independent of route dispatch and database column names.
use crate::{AuthRoute, HttpMethod};
use indexmap::IndexMap;
use serde_json::{Value, json};

/// A model field's wire schema and input/output policy.
#[derive(Debug, Clone)]
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
    pub operation_id: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub parameters: Vec<Value>,
    pub request_body: Option<Value>,
    pub responses: IndexMap<String, Value>,
    pub server_only: bool,
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
}
impl OpenApiRegistry {
    pub fn new(models: Vec<OpenApiModel>) -> Self {
        let mut registry = Self::default();
        for model in models {
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
            self.endpoints.push(RegisteredEndpoint {
                core: super::annotations::is_core(plugin),
                plugin: plugin.into(),
                route,
                metadata: annotation,
            });
        }
        for model in metadata.models {
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
