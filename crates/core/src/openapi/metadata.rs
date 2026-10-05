//! Runtime documentation metadata, independent of route dispatch and database column names.
use crate::{AuthRoute, HttpMethod};
use indexmap::IndexMap;
use serde_json::{Value, json};

/// A model field's wire schema and input/output policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiField {
    pub name: String,
    pub schema: Value,
    pub required: bool,
    pub input: bool,
    pub returned: bool,
    /// Includes callable defaults without evaluating them for documentation.
    pub has_default: bool,
}
impl OpenApiField {
    #[must_use]
    pub fn new(name: impl Into<String>, schema: Value, required: bool) -> Self {
        Self {
            name: name.into(),
            has_default: schema.get("default").is_some(),
            schema,
            required,
            input: true,
            returned: true,
        }
    }
    fn from_policy(name: &str, policy: &crate::field_policy::FieldConfig) -> Self {
        let mut schema = policy.schema.clone();
        if let Some(object) = schema.as_object_mut() {
            drop(object.remove("default"));
            if let Some(crate::field_policy::FieldDefault::Value(value)) = &policy.default {
                drop(object.insert(
                    "default".into(),
                    value.to_json_value().unwrap_or(Value::Null),
                ));
            }
        }
        Self {
            name: name.into(),
            schema,
            required: policy.required,
            input: policy.input,
            returned: policy.returned,
            has_default: policy.default.is_some(),
        }
    }

    #[must_use]
    pub const fn read_only(mut self) -> Self {
        self.input = false;
        self
    }
    #[must_use]
    pub const fn hidden(mut self) -> Self {
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
    #[must_use]
    pub fn new(name: impl Into<String>, fields: Vec<OpenApiField>) -> Self {
        Self {
            name: name.into(),
            fields,
        }
    }
    pub(crate) fn to_schema(&self) -> Value {
        let mut properties = serde_json::Map::new();
        drop(properties.insert("id".into(), json!({"type":"string","readOnly":true})));
        let mut required = vec!["id".to_owned()];
        for field in &self.fields {
            let mut schema = field.schema.clone();
            if !field.input
                && let Some(object) = schema.as_object_mut()
            {
                drop(object.insert("readOnly".into(), json!(true)));
            }
            drop(properties.insert(field.name.clone(), schema));
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
    /// Optional documentation owner for a route contributed by another plugin.
    pub owner: Option<String>,
    /// Override the plugin-level core documentation classification.
    pub core: Option<bool>,
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
    /// Use the core API documentation policy for this plugin.
    pub core: bool,
    pub endpoints: Vec<(HttpMethod, String, OpenApiEndpoint)>,
    pub models: Vec<OpenApiModel>,
}
impl PluginOpenApiMetadata {
    #[must_use]
    pub fn endpoint(
        mut self,
        method: HttpMethod,
        path: impl Into<String>,
        metadata: OpenApiEndpoint,
    ) -> Self {
        self.endpoints.push((method, path.into(), metadata));
        self
    }
    #[must_use]
    pub fn model(mut self, model: OpenApiModel) -> Self {
        self.models.push(model);
        self
    }
}

#[derive(Debug, Clone)]
pub(super) struct RegisteredEndpoint {
    pub route: AuthRoute,
    pub plugin: String,
    pub core: bool,
    pub metadata: OpenApiEndpoint,
}

/// Immutable snapshot of the routes and model projections registered on one auth instance.
#[derive(Debug, Clone, Default)]
pub struct OpenApiRegistry {
    pub(super) endpoints: Vec<RegisteredEndpoint>,
    pub(crate) models: IndexMap<String, OpenApiModel>,
    pub(crate) user_input_fields: IndexMap<String, OpenApiField>,
    pub(crate) core_overrides: Vec<OpenApiModel>,
}
impl OpenApiRegistry {
    /// Whether an installed endpoint is available only through server calls.
    /// This is independent of document hiding and disabled-path configuration.
    #[must_use]
    pub fn is_server_only(&self, plugin: &str, route: &AuthRoute) -> bool {
        self.endpoints.iter().any(|endpoint| {
            endpoint.plugin == plugin
                && endpoint.route.method == route.method
                && endpoint.route.path == route.path
                && endpoint.metadata.server_only
        })
    }

    /// Actual registered routes, including endpoints unavailable over HTTP or omitted from documentation.
    #[must_use]
    pub fn registered_routes(&self) -> Vec<AuthRoute> {
        self.endpoints
            .iter()
            .map(|endpoint| endpoint.route.clone())
            .collect()
    }

    /// Apply application table policies before plugin collection. Documentation and
    /// adapter tables use config-over-plugin precedence; input/output parsing has
    /// its own source-distinct immutable field registry.
    #[must_use]
    pub fn configured(mut models: Vec<OpenApiModel>, config: &crate::AuthConfig) -> Self {
        for (model_name, fields) in [
            ("User", &config.user.additional_fields),
            ("Session", &config.session.additional_fields),
            ("Account", &config.account.additional_fields),
        ] {
            if let Some(model) = models.iter_mut().find(|model| model.name == model_name) {
                for (name, policy) in fields {
                    let field = OpenApiField::from_policy(name, policy);
                    if let Some(current) = model.fields.iter_mut().find(|field| field.name == *name)
                    {
                        *current = field;
                    } else {
                        model.fields.push(field);
                    }
                }
            }
        }
        Self::new(models)
    }

    #[must_use]
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
                        drop(
                            registry
                                .user_input_fields
                                .insert(field.name.clone(), field.clone()),
                        );
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
            self.endpoints.push(RegisteredEndpoint {
                core: annotation.core.unwrap_or(metadata.core),
                plugin: annotation.owner.as_deref().unwrap_or(plugin).into(),
                route,
                metadata: annotation,
            });
        }
        for model in metadata.models {
            if model.name == "User" {
                for field in &model.fields {
                    drop(
                        self.user_input_fields
                            .insert(field.name.clone(), field.clone()),
                    );
                }
            }
            self.merge_model(model);
        }
    }
    /// Register the actual plugin field policies alongside its route annotations.
    /// Configured model overlays remain distinct from plugin-wins user input.
    pub fn register_fields(
        &mut self,
        model_name: &str,
        fields: &crate::field_policy::FieldConfigs,
    ) {
        let fields = fields
            .iter()
            .map(|(name, policy)| OpenApiField::from_policy(name, policy))
            .collect::<Vec<_>>();
        if model_name == "User" {
            for field in &fields {
                drop(
                    self.user_input_fields
                        .insert(field.name.clone(), field.clone()),
                );
            }
        }
        self.merge_model(OpenApiModel::new(model_name, fields));
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
            drop(self.models.insert(model.name.clone(), model));
        }
    }
}
