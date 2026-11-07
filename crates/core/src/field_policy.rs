//! Application and plugin field policies at the session input boundary.
#[cfg(test)]
mod undefined_tests {
    use super::{FieldConfig, FieldValues, SessionAdapterFields};
    use crate::utils::json::JsValue;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, serde::Deserialize)]
    struct Observed {
        undefined: bool,
        value: JsValue,
    }

    #[derive(Debug, serde::Deserialize)]
    struct Case {
        creation: bool,
        required: bool,
        has_default: bool,
        on_update: bool,
        transform: bool,
        kind: String,
        input: JsValue,
        present: bool,
        expected: JsValue,
        events: Vec<String>,
        observed: Vec<Observed>,
    }

    #[derive(serde::Deserialize)]
    struct Fixture {
        better_auth: String,
        cases: Vec<Case>,
    }

    async fn assert_factory_cases(asynchronous: bool) {
        let fixture: Fixture =
            serde_json::from_str(include_str!("field_policy_undefined_cases.json")).unwrap();
        assert_eq!(fixture.better_auth, "1.7.18");
        assert_eq!(fixture.cases.len(), 256);
        for case in fixture.cases {
            let events = Arc::new(Mutex::new(Vec::new()));
            let observed = Arc::new(Mutex::new(Vec::new()));
            let mut field = FieldConfig::new(serde_json::json!({"type":"string"}));
            field.required = case.required;
            if case.has_default {
                let events = events.clone();
                field = field.default_callback(move || {
                    events.lock().unwrap().push("default".to_owned());
                    JsValue::String("default".into())
                });
            }
            if case.on_update {
                let events = events.clone();
                field = field.on_update(move || {
                    events.lock().unwrap().push("update".to_owned());
                    JsValue::String("updated".into())
                });
            }
            if case.transform {
                let events = events.clone();
                let observed = observed.clone();
                if asynchronous {
                    field = field.transform_adapter_input(move |value| {
                        events.lock().unwrap().push("input".to_owned());
                        observed.lock().unwrap().push(value.clone());
                        async move { Ok(value) }
                    });
                } else {
                    field = field.transform(move |value| {
                        events.lock().unwrap().push("input".to_owned());
                        observed.lock().unwrap().push(value.cloned());
                        Ok(value.cloned())
                    });
                }
            }
            let policy = SessionAdapterFields(Arc::new(
                [("marker".to_owned(), field)].into_iter().collect(),
            ));
            let mut fields = FieldValues::new();
            if case.kind != "absent" {
                _ = fields.insert(
                    "marker".into(),
                    if case.kind == "undefined" {
                        JsValue::Undefined
                    } else {
                        case.input.clone()
                    },
                );
            }
            policy.attach(&mut fields, case.creation);
            if asynchronous {
                fields.apply_adapter_transforms_async().await.unwrap();
            } else {
                fields.apply_adapter_transforms().unwrap();
            }
            assert_eq!(*events.lock().unwrap(), case.events, "{case:?}");
            let expected_inputs: Vec<_> = case
                .observed
                .iter()
                .map(|input| (!input.undefined).then_some(input.value.clone()))
                .collect();
            assert_eq!(*observed.lock().unwrap(), expected_inputs, "{case:?}");
            let stored = fields
                .get("marker")
                .cloned()
                .or_else(|| (!case.creation).then(|| JsValue::String("stored".into())));
            assert_eq!(stored.is_some(), case.present, "{case:?}");
            if case.present {
                assert_eq!(stored.as_ref(), Some(&case.expected), "{case:?}");
            }
            assert!(!fields.values().any(JsValue::is_undefined), "{case:?}");
            let snapshot = fields.clone();
            if asynchronous {
                fields.apply_adapter_transforms_async().await.unwrap();
            } else {
                fields.apply_adapter_transforms().unwrap();
            }
            assert_eq!(*fields, *snapshot, "{case:?}");
            assert_eq!(*events.lock().unwrap(), case.events, "{case:?}");
        }
    }

    async fn assert_memory_writes<S: crate::AuthSchema<User = crate::UserView>>(
        create_store: impl Fn(Arc<crate::AuthConfig>) -> Arc<dyn crate::AuthStore<S>>,
    ) {
        for on_update in [false, true] {
            let inputs = Arc::new(Mutex::new(Vec::new()));
            let observed = inputs.clone();
            let mut field = FieldConfig::new(serde_json::json!({"type":"string"}))
                .default_value(JsValue::String("default".into()));
            if on_update {
                field = field.on_update(|| JsValue::String("updated".into()));
            }
            field = field.transform_adapter_input(move |value| {
                observed.lock().unwrap().push(value.clone());
                async move { Ok(value) }
            });
            let mut config = crate::AuthConfig::default();
            _ = config.user.additional_fields.insert("marker".into(), field);
            let config = Arc::new(config);
            let physical = create_store(config.clone());
            let store = crate::AuthInitContext::new(config, physical.clone())
                .database_with_registered_transforms();
            let mut input = crate::CreateUser::new().with_email("undefined@fixture.test");
            _ = input
                .additional_fields
                .insert("marker".into(), JsValue::Undefined);
            let user = store.create_user(input).await.unwrap();
            assert_eq!(
                user.extension_fields["marker"],
                JsValue::String("default".into())
            );
            assert_eq!(
                *inputs.lock().unwrap(),
                [Some(JsValue::String("default".into()))]
            );
            for (value, expected) in [
                (
                    None,
                    JsValue::String(if on_update { "updated" } else { "default" }.into()),
                ),
                (
                    Some(JsValue::Undefined),
                    JsValue::String(if on_update { "updated" } else { "default" }.into()),
                ),
                (Some(JsValue::Null), JsValue::Null),
                (Some(JsValue::Bool(false)), JsValue::Bool(false)),
                (Some(JsValue::Number(0.0)), JsValue::Number(0.0)),
                (Some(JsValue::String("".into())), JsValue::String("".into())),
            ] {
                inputs.lock().unwrap().clear();
                let mut update = crate::UpdateUser::default();
                if let Some(value) = value.clone() {
                    _ = update.additional_fields.insert("marker".into(), value);
                }
                let user = store.update_user(&user.id, update).await.unwrap();
                assert_eq!(user.extension_fields["marker"], expected);
                assert_eq!(
                    physical
                        .get_user_by_id(&user.id)
                        .await
                        .unwrap()
                        .unwrap()
                        .extension_fields["marker"],
                    expected,
                );
                let missing = value.as_ref().is_none_or(JsValue::is_undefined);
                let expected_inputs: Vec<_> = if missing {
                    if on_update {
                        vec![Some(JsValue::String("updated".into()))]
                    } else {
                        vec![]
                    }
                } else {
                    vec![value]
                };
                assert_eq!(*inputs.lock().unwrap(), expected_inputs);
            }
        }
    }

    #[tokio::test]
    async fn adapter_input_undefined_preserves_memory_values_and_on_update() {
        assert_memory_writes::<crate::test_store::BundledSchema>(|config| {
            Arc::new(crate::test_store::MemoryStore::new(config))
        })
        .await;
    }

    #[tokio::test]
    async fn adapter_input_undefined_preserves_stateless_values_and_on_update() {
        assert_memory_writes::<crate::store::stateless::StatelessSchema>(|_| {
            Arc::new(crate::store::stateless::StatelessStore::default())
        })
        .await;
    }

    #[tokio::test]
    async fn adapter_input_undefined_matches_synchronous_factory_cases() {
        assert_factory_cases(false).await;
    }

    #[tokio::test]
    async fn adapter_input_undefined_matches_asynchronous_factory_cases() {
        assert_factory_cases(true).await;
    }
}

use crate::AdapterOutput;
use crate::utils::json::JsValue;
use crate::{AuthError, AuthResult};
use indexmap::{IndexMap, IndexSet};
use serde_json::Value;
use std::{fmt, future::Future, pin::Pin, sync::Arc};

/// Values retain JavaScript numbers until the actual database binding.
#[derive(Clone, Default)]
pub struct FieldValues {
    values: IndexMap<String, JsValue>,
    adapter_fields: Option<Arc<FieldConfigs>>,
    undefined_input_keys: IndexSet<String>,
    transform_omitted: bool,
    binding_names: IndexMap<String, String>,
}

impl FieldValues {
    pub(crate) fn update_own_properties(&self) -> crate::utils::json::JsObject {
        let mut data: crate::utils::json::JsObject = self
            .values
            .iter()
            .map(|(key, value)| (key.clone().into(), value.clone()))
            .collect();
        for key in &self.undefined_input_keys {
            _ = data.entry(key.clone().into()).or_insert(JsValue::Undefined);
        }
        data
    }

    pub(crate) fn update_metadata(&self) -> crate::store::UserUpdateFieldMetadata {
        crate::store::UserUpdateFieldMetadata {
            adapter_fields: self.adapter_fields.clone(),
            binding_names: self.binding_names.clone(),
            ..Default::default()
        }
    }

    pub(crate) fn from_user_update(
        data: crate::utils::json::JsObject,
        metadata: crate::store::UserUpdateFieldMetadata,
    ) -> AuthResult<Self> {
        let mut pending = metadata
            .adapter_fields
            .as_deref()
            .cloned()
            .unwrap_or_default();
        let mut fields = FieldConfigs::new();
        for core in alibi_schema_registry::core_fields(alibi_schema_registry::EntityRole::User) {
            let name = core.column_name.unwrap_or(core.name);
            if let Some(field) = pending.shift_remove(name) {
                _ = fields.insert(name.to_owned(), field);
            } else if name == "updatedAt" {
                _ = fields.insert(
                    name.to_owned(),
                    FieldConfig::new(serde_json::json!({"type":"date"}))
                        .on_update(|| JsValue::Date(chrono::Utc::now())),
                );
            }
        }
        fields.extend(pending);
        let values = data
            .into_iter()
            .map(|(key, value)| {
                key.to_utf8()
                    .map(|key| (key, value))
                    .map_err(|error| AuthError::config(error.to_string()))
            })
            .collect::<AuthResult<IndexMap<_, _>>>()?;
        Ok(Self {
            values,
            adapter_fields: Some(Arc::new(fields)),
            binding_names: metadata.binding_names,
            ..Self::default()
        })
    }

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Whether parsing supplied any keys, including a transform returning undefined.
    /// Unlike `is_empty`, this reflects JavaScript Object.keys before adapter omission.
    #[must_use]
    pub fn has_input_fields(&self) -> bool {
        !self.values.is_empty() || !self.undefined_input_keys.is_empty()
    }
    /// Resolve an immutable configured physical column at the binding boundary.
    #[must_use]
    pub fn binding_name<'a>(&'a self, name: &'a str) -> &'a str {
        self.binding_names.get(name).map_or(name, String::as_str)
    }
    /// Consume pending adapter callbacks once using current values after database hooks.
    /// Custom stores must call this immediately before binding configured session fields.
    ///
    /// # Errors
    ///
    /// Propagates errors from configured adapter field transforms.
    pub fn apply_adapter_transforms(&mut self) -> AuthResult<()> {
        if self.adapter_fields.as_ref().is_some_and(|fields| {
            fields
                .values()
                .any(|field| field.adapter_input_transform.is_some())
        }) {
            return Err(AuthError::config(
                "Asynchronous adapter transforms require apply_adapter_transforms_async",
            ));
        }
        if let Some(fields) = self.adapter_fields.take() {
            for (name, field) in &*fields {
                if self.prepare_adapter_value(name, field)
                    && let Some(transform) = &field.transform
                {
                    let value =
                        transform(self.values.get(name).filter(|value| !value.is_undefined()))?;
                    self.set_adapter_value(name, value);
                }
            }
        }
        self.finish_adapter_transforms();
        Ok(())
    }

    /// Await genuine storage-stage callbacks after database before hooks.
    /// Synchronous endpoint parsing is a separate phase.
    ///
    /// # Errors
    /// Propagates configured callback errors.
    pub async fn apply_adapter_transforms_async(&mut self) -> AuthResult<()> {
        if let Some(fields) = self.adapter_fields.take() {
            for (name, field) in &*fields {
                if !self.prepare_adapter_value(name, field) {
                    continue;
                }
                let value = if let Some(transform) = &field.adapter_input_transform {
                    transform(
                        self.values
                            .get(name)
                            .filter(|value| !value.is_undefined())
                            .cloned(),
                    )
                    .await
                    .map_err(crate::store::adapter::callback_error)?
                } else if let Some(transform) = &field.transform {
                    transform(self.values.get(name).filter(|value| !value.is_undefined()))?
                } else {
                    continue;
                };
                self.set_adapter_value(name, value);
            }
        }
        self.finish_adapter_transforms();
        Ok(())
    }

    fn prepare_adapter_value(&mut self, name: &str, field: &FieldConfig) -> bool {
        let undefined = self.values.get(name).is_none_or(JsValue::is_undefined);
        if undefined
            && if self.transform_omitted {
                field.default.is_none()
                    && field.transform.is_none()
                    && field.adapter_input_transform.is_none()
            } else {
                field.on_update.is_none()
            }
        {
            return false;
        }
        if self.transform_omitted
            && (undefined
                || (field.required && self.values.get(name).is_some_and(JsValue::is_null)))
            && let Some(default) = &field.default
        {
            _ = self.values.insert(name.to_owned(), default.value());
        }
        if !self.transform_omitted
            && undefined
            && let Some(update) = &field.on_update
        {
            _ = self.values.insert(name.to_owned(), update());
        }
        true
    }
    fn set_adapter_value(&mut self, name: &str, value: Option<JsValue>) {
        match value {
            Some(value) => {
                _ = self.values.insert(name.to_owned(), value);
            }
            None => {
                _ = self.values.shift_remove(name);
            }
        }
    }
    fn finish_adapter_transforms(&mut self) {
        self.values.retain(|_, value| !value.is_undefined());
        self.undefined_input_keys.clear();
        self.transform_omitted = false;
    }
    /// Preserve an existing trusted creation value before adapter defaults are applied.
    /// Database hooks may already have supplied a mapped replacement, which wins.
    pub fn preserve_creation_value(&mut self, name: &str, value: JsValue) {
        if self
            .adapter_fields
            .as_ref()
            .is_some_and(|fields| fields.contains_key(name))
        {
            _ = self.values.entry(name.to_owned()).or_insert(value);
        }
    }
}

impl fmt::Debug for FieldValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.values.fmt(f)
    }
}

impl std::ops::Deref for FieldValues {
    type Target = IndexMap<String, JsValue>;
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl std::ops::DerefMut for FieldValues {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}

impl From<IndexMap<String, JsValue>> for FieldValues {
    fn from(values: IndexMap<String, JsValue>) -> Self {
        Self {
            values,
            ..Self::default()
        }
    }
}

impl FromIterator<(String, JsValue)> for FieldValues {
    fn from_iter<T: IntoIterator<Item = (String, JsValue)>>(iter: T) -> Self {
        IndexMap::from_iter(iter).into()
    }
}

impl IntoIterator for FieldValues {
    type Item = (String, JsValue);
    type IntoIter = indexmap::map::IntoIter<String, JsValue>;
    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

impl<'a> IntoIterator for &'a FieldValues {
    type Item = (&'a String, &'a JsValue);
    type IntoIter = indexmap::map::Iter<'a, String, JsValue>;
    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

impl<'a> IntoIterator for &'a mut FieldValues {
    type Item = (&'a String, &'a mut JsValue);
    type IntoIter = indexmap::map::IterMut<'a, String, JsValue>;
    fn into_iter(self) -> Self::IntoIter {
        self.values.iter_mut()
    }
}

impl serde::Serialize for FieldValues {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.values.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for FieldValues {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        IndexMap::deserialize(deserializer).map(Self::from)
    }
}

pub type FieldOutput = serde_json::Map<String, Value>;

pub type FieldConfigs = IndexMap<String, FieldConfig>;

pub type FieldValidator = Arc<dyn Fn(&JsValue) -> Result<JsValue, String> + Send + Sync>;
pub type AsyncFieldValidator = Arc<
    dyn Fn(JsValue) -> Pin<Box<dyn Future<Output = Result<JsValue, String>> + Send>> + Send + Sync,
>;

/// `None` is JavaScript undefined: absent input or omitted adapter output.
pub type FieldTransform =
    Arc<dyn Fn(Option<&JsValue>) -> AuthResult<Option<JsValue>> + Send + Sync>;

/// Adapter output callbacks receive an owned actual storage value and are awaited.
pub type FieldOutputTransform = Arc<
    dyn Fn(Option<JsValue>) -> Pin<Box<dyn Future<Output = AuthResult<Option<JsValue>>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub enum FieldDefault {
    Value(JsValue),
    Callback(Arc<dyn Fn() -> JsValue + Send + Sync>),
}

impl fmt::Debug for FieldDefault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(value) => f.debug_tuple("Value").field(value).finish(),
            Self::Callback(_) => f.write_str("Callback(..)"),
        }
    }
}

impl FieldDefault {
    #[must_use]
    pub fn value(&self) -> JsValue {
        match self {
            Self::Value(value) => value.clone(),
            Self::Callback(callback) => callback(),
        }
    }
}

/// Type/schema metadata does not implicitly validate input values.
#[derive(Clone)]
pub struct FieldConfig {
    pub schema: Value,
    pub required: bool,
    pub input: bool,
    pub returned: bool,
    pub default: Option<FieldDefault>,
    pub validator: Option<FieldValidator>,
    pub async_validator: Option<AsyncFieldValidator>,
    /// Source declares output validators but does not invoke them at this stage.
    pub output_validator: Option<FieldValidator>,
    pub adapter_input_transform: Option<FieldOutputTransform>,
    pub transform: Option<FieldTransform>,
    pub output_transform: Option<FieldOutputTransform>,
    pub on_update: Option<Arc<dyn Fn() -> JsValue + Send + Sync>>,
    /// Physical column binding. Logical input/output names remain registry keys.
    pub field_name: Option<String>,
}

impl fmt::Debug for FieldConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldConfig")
            .field("schema", &self.schema)
            .field("required", &self.required)
            .field("input", &self.input)
            .field("returned", &self.returned)
            .field("default", &self.default)
            .field("validator", &self.validator.as_ref().map(|_| "callback"))
            .field(
                "async_validator",
                &self.async_validator.as_ref().map(|_| "callback"),
            )
            .field(
                "output_validator",
                &self.output_validator.as_ref().map(|_| "callback"),
            )
            .field(
                "adapter_input_transform",
                &self.adapter_input_transform.as_ref().map(|_| "callback"),
            )
            .field("transform", &self.transform.as_ref().map(|_| "callback"))
            .field(
                "output_transform",
                &self.output_transform.as_ref().map(|_| "callback"),
            )
            .field("on_update", &self.on_update.as_ref().map(|_| "callback"))
            .field("field_name", &self.field_name)
            .finish()
    }
}

impl FieldConfig {
    #[must_use]
    pub fn new(schema: Value) -> Self {
        Self {
            schema,
            required: false,
            input: true,
            returned: true,
            default: None,
            validator: None,
            async_validator: None,
            output_validator: None,
            adapter_input_transform: None,
            transform: None,
            output_transform: None,
            on_update: None,
            field_name: None,
        }
    }
    #[must_use]
    pub fn default_value(mut self, value: impl Into<JsValue>) -> Self {
        self.default = Some(FieldDefault::Value(value.into()));
        self
    }
    #[must_use]
    pub fn default_callback(
        mut self,
        callback: impl Fn() -> JsValue + Send + Sync + 'static,
    ) -> Self {
        self.default = Some(FieldDefault::Callback(Arc::new(callback)));
        self
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
    #[must_use]
    pub fn validate(
        mut self,
        validator: impl Fn(&JsValue) -> Result<JsValue, String> + Send + Sync + 'static,
    ) -> Self {
        self.validator = Some(Arc::new(validator));
        self.async_validator = None;
        self
    }
    #[must_use]
    pub fn transform(
        mut self,
        transform: impl Fn(Option<&JsValue>) -> AuthResult<Option<JsValue>> + Send + Sync + 'static,
    ) -> Self {
        self.transform = Some(Arc::new(transform));
        self
    }

    /// A Promise-style validator is invoked but rejected by endpoint parsing,
    /// matching the published `ASYNC_VALIDATION_NOT_SUPPORTED` contract.
    #[must_use]
    pub fn validate_async<F, Fut>(mut self, validate: F) -> Self
    where
        F: Fn(JsValue) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<JsValue, String>> + Send + 'static,
    {
        self.async_validator = Some(Arc::new(move |value| Box::pin(validate(value))));
        self.validator = None;
        self
    }

    #[must_use]
    pub fn validate_output(
        mut self,
        validate: impl Fn(&JsValue) -> Result<JsValue, String> + Send + Sync + 'static,
    ) -> Self {
        self.output_validator = Some(Arc::new(validate));
        self
    }

    /// Await this callback only at the actual adapter binding boundary. For a
    /// Source input transform shared with endpoint parsing, use a synchronous
    /// validator to select its parsed value before the awaited storage phase.
    #[must_use]
    pub fn transform_adapter_input<F, Fut>(mut self, transform: F) -> Self
    where
        F: Fn(Option<JsValue>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<Option<JsValue>>> + Send + 'static,
    {
        self.adapter_input_transform = Some(Arc::new(move |value| Box::pin(transform(value))));
        self
    }

    #[must_use]
    pub fn transform_output<F, Fut>(mut self, transform: F) -> Self
    where
        F: Fn(Option<JsValue>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<Option<JsValue>>> + Send + 'static,
    {
        self.output_transform = Some(Arc::new(move |value| Box::pin(transform(value))));
        self
    }

    #[must_use]
    pub fn on_update(mut self, callback: impl Fn() -> JsValue + Send + Sync + 'static) -> Self {
        self.on_update = Some(Arc::new(callback));
        self
    }

    #[must_use]
    pub fn field_name(mut self, name: impl Into<String>) -> Self {
        self.field_name = Some(name.into());
        self
    }
}

#[derive(Debug)]
pub enum FieldInputError {
    Validation { code: &'static str, message: String },
    Transform(crate::AuthError),
}

/// Immutable instance policies: configuration first, registered plugins last.
#[derive(Debug, Clone, Default)]
pub struct SessionFields(pub IndexMap<String, FieldConfig>);

impl SessionFields {
    pub fn defaults(&self, values: &mut FieldValues) {
        for (name, field) in &self.0 {
            if let Some(default) = &field.default {
                _ = values
                    .entry(name.clone())
                    .or_insert_with(|| default.value());
            }
        }
    }
    /// # Errors
    ///
    /// Returns a validation error for disallowed fields or rejected field validators.
    pub fn parse_update<K: std::hash::Hash + Eq>(
        &self,
        input: &IndexMap<K, JsValue>,
    ) -> Result<FieldValues, FieldInputError>
    where
        String: indexmap::Equivalent<K>,
    {
        self.parse(input, false)
    }

    /// Parse application input before database hooks. Creation defaults and
    /// required fields apply here; adapter binding remains a separate phase.
    pub fn parse_create<K: std::hash::Hash + Eq>(
        &self,
        input: &IndexMap<K, JsValue>,
    ) -> Result<FieldValues, FieldInputError>
    where
        String: indexmap::Equivalent<K>,
    {
        self.parse(input, true)
    }

    fn parse<K: std::hash::Hash + Eq>(
        &self,
        input: &IndexMap<K, JsValue>,
        creation: bool,
    ) -> Result<FieldValues, FieldInputError>
    where
        String: indexmap::Equivalent<K>,
    {
        let mut parsed = FieldValues::new();
        for (name, field) in &self.0 {
            let Some(value) = input.get(name) else {
                if creation {
                    if let Some(default) = &field.default {
                        _ = parsed.insert(name.clone(), default.value());
                    } else if field.required {
                        return Err(FieldInputError::Validation {
                            code: "MISSING_FIELD",
                            message: format!("{name} is required"),
                        });
                    }
                }
                continue;
            };
            if !field.input {
                if creation && let Some(default) = &field.default {
                    _ = parsed.insert(name.clone(), default.value());
                    continue;
                }
                if value.is_truthy() {
                    return Err(FieldInputError::Validation {
                        code: "FIELD_NOT_ALLOWED",
                        message: format!("{name} is not allowed to be set"),
                    });
                }
                continue;
            }
            if let Some(validator) = &field.async_validator {
                _ = validator(value.clone());
                return Err(FieldInputError::Transform(AuthError::Upstream {
                    status: 500,
                    code: "ASYNC_VALIDATION_NOT_SUPPORTED",
                    message: "Async validation is not supported",
                }));
            }
            let value = if let Some(validator) = &field.validator {
                Some(
                    validator(value).map_err(|message| FieldInputError::Validation {
                        code: "VALIDATION_ERROR",
                        message: if message.is_empty() {
                            "Validation Error".into()
                        } else {
                            message
                        },
                    })?,
                )
            } else if let Some(transform) = &field.transform {
                transform(Some(value)).map_err(FieldInputError::Transform)?
            } else {
                Some(value.clone())
            };
            match value {
                Some(value) => {
                    _ = parsed.insert(name.clone(), value);
                }
                None => {
                    _ = parsed.undefined_input_keys.insert(name.clone());
                }
            }
        }
        Ok(parsed)
    }
}

/// Immutable policies for application/plugin user fields.
#[derive(Debug, Clone, Default)]
pub struct UserFields(pub SessionFields);

/// Immutable policies for application/plugin account fields.
#[derive(Debug, Clone, Default)]
pub struct AccountFields(pub SessionFields);

/// Adapter precedence remains distinct from endpoint/public projection policies.
#[derive(Debug, Clone, Default)]
pub struct AdapterFieldPolicies {
    pub user: SessionAdapterFields,
    pub account: SessionAdapterFields,
}

/// Immutable adapter schema policies: plugins first, application configuration last.
/// This differs from input/output `SessionFields`, matching getAuthTables precedence.
#[derive(Debug, Clone, Default)]
pub struct SessionAdapterFields(pub Arc<FieldConfigs>);

impl SessionAdapterFields {
    pub(crate) fn attach_user_update(&self, update: &mut crate::store::PreparedUserUpdate) {
        if update.metadata.adapter_fields.is_none() {
            let mut fields = FieldValues::new();
            self.attach(&mut fields, false);
            update.metadata = fields.update_metadata();
        }
    }

    pub(crate) fn attach(&self, values: &mut FieldValues, creation: bool) {
        values.transform_omitted = creation;
        values.adapter_fields = Some(Arc::clone(&self.0));
        values.binding_names = self
            .0
            .iter()
            .filter_map(|(name, field)| {
                field
                    .field_name
                    .as_ref()
                    .map(|physical| (name.clone(), physical.clone()))
            })
            .collect();
    }

    /// Resolve declared fields from physical canonical getters and custom columns
    /// before applying their output policies. The base projection alone controls
    /// undeclared fields, so unrelated physical columns never become observable.
    pub(crate) async fn record_output(
        &self,
        canonical: JsValue,
        mut additional: crate::utils::json::JsObject,
        base: JsValue,
        supports_json: bool,
    ) -> AuthResult<AdapterOutput> {
        let (JsValue::Object(mut canonical), JsValue::Object(mut base)) = (canonical, base) else {
            return Err(AuthError::internal("Adapter output must be an object"));
        };
        if !supports_json {
            for (name, field) in &*self.0 {
                if field.schema.get("type").and_then(Value::as_str) == Some("json") {
                    // A retained logical model snapshot is not a physical SQLite cell.
                    // Leave the exact cell in place until after transform.output.
                    if additional.contains_key(name)
                        || field
                            .field_name
                            .as_ref()
                            .is_some_and(|column| additional.contains_key(column))
                    {
                        _ = canonical.shift_remove(name);
                        if let Some(column) = &field.field_name {
                            _ = canonical.shift_remove(column);
                        }
                    }
                }
            }
        }
        additional.extend(canonical);
        for name in self.0.keys() {
            // Typed DTOs omit optional core fields during serialization. The
            // actual initialized projection still distinguishes a stored null
            // from an absent property; retain it before applying output policy.
            if !additional.contains_key(name)
                && let Some(value) = base.get(name)
            {
                _ = additional.insert(name.clone().into(), value.clone());
            }
            _ = base.shift_remove(name);
        }
        let mut output = AdapterOutput::from_js_values(base);
        output.extend(
            self.output_with_json_support(additional, supports_json)
                .await?,
        );
        Ok(output)
    }

    /// Transform only declared additional fields, retaining their omission.
    pub(crate) async fn output(
        &self,
        values: crate::utils::json::JsObject,
    ) -> AuthResult<AdapterOutput> {
        self.output_with_json_support(values, true).await
    }

    pub(crate) fn exact_json_fields(&self) -> std::collections::BTreeSet<String> {
        self.0
            .iter()
            .filter(|(_, field)| field.output_transform.is_some())
            .flat_map(|(name, field)| std::iter::once(name.clone()).chain(field.field_name.clone()))
            .collect()
    }

    async fn output_with_json_support(
        &self,
        values: crate::utils::json::JsObject,
        supports_json: bool,
    ) -> AuthResult<AdapterOutput> {
        let mut output = AdapterOutput::default();
        for (name, field) in &*self.0 {
            let value = values
                .get(name)
                .or_else(|| {
                    field
                        .field_name
                        .as_ref()
                        .and_then(|physical| values.get(physical))
                })
                .cloned()
                .filter(|value| !value.is_undefined());
            let value = if let Some(transform) = &field.output_transform {
                transform(value).await.map_err(|error| match error {
                    AuthError::Api { .. } | AuthError::Upstream { .. } => error,
                    error => AuthError::CallbackFailure(Box::new(error)),
                })?
            } else {
                value
            };
            let value = if !supports_json
                && field.schema.get("type").and_then(Value::as_str) == Some("json")
            {
                value.map(|value| match value {
                    JsValue::String(text) => crate::utils::json::parse_adapter_string(&text),
                    value => value,
                })
            } else {
                value
            };
            output.insert(name.clone(), value);
        }
        Ok(output)
    }
}
