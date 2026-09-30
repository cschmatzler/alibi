//! Application and plugin field policies at the session input boundary.
use crate::utils::json::JsValue;
use indexmap::{IndexMap, IndexSet};
use serde_json::Value;
use std::{fmt, sync::Arc};

/// Values retain JavaScript numbers until the actual database binding.
#[derive(Clone, Default)]
pub struct FieldValues {
    values: IndexMap<String, JsValue>,
    adapter_transforms: IndexMap<String, FieldTransform>,
    undefined_input_keys: IndexSet<String>,
    transform_omitted: bool,
}
impl FieldValues {
    pub fn new() -> Self {
        Self::default()
    }
    /// Whether parsing supplied any keys, including a transform returning undefined.
    /// Unlike `is_empty`, this reflects JavaScript Object.keys before adapter omission.
    pub fn has_input_fields(&self) -> bool {
        !self.values.is_empty() || !self.undefined_input_keys.is_empty()
    }
    /// Consume pending adapter callbacks once using current values after database hooks.
    /// Custom stores must call this immediately before binding configured session fields.
    pub fn apply_adapter_transforms(&mut self) -> crate::AuthResult<()> {
        for (name, transform) in std::mem::take(&mut self.adapter_transforms) {
            if !self.transform_omitted && !self.values.contains_key(&name) {
                continue;
            }
            match transform(self.values.get(&name))? {
                Some(value) => {
                    let _ = self.values.insert(name, value);
                }
                None => {
                    let _ = self.values.shift_remove(&name);
                }
            }
        }
        self.undefined_input_keys.clear();
        self.transform_omitted = false;
        Ok(())
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
    fn from_iter<T: IntoIterator<Item = (String, JsValue)>>(values: T) -> Self {
        IndexMap::from_iter(values).into()
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
/// `None` is JavaScript undefined: absent input or omitted adapter output.
pub type FieldTransform =
    Arc<dyn Fn(Option<&JsValue>) -> crate::AuthResult<Option<JsValue>> + Send + Sync>;

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
    pub transform: Option<FieldTransform>,
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
            .field("transform", &self.transform.as_ref().map(|_| "callback"))
            .finish()
    }
}
impl FieldConfig {
    pub fn new(schema: Value) -> Self {
        Self {
            schema,
            required: false,
            input: true,
            returned: true,
            default: None,
            validator: None,
            transform: None,
        }
    }
    pub fn default_value(mut self, value: impl Into<JsValue>) -> Self {
        self.default = Some(FieldDefault::Value(value.into()));
        self
    }
    pub fn default_callback(
        mut self,
        callback: impl Fn() -> JsValue + Send + Sync + 'static,
    ) -> Self {
        self.default = Some(FieldDefault::Callback(Arc::new(callback)));
        self
    }
    pub fn read_only(mut self) -> Self {
        self.input = false;
        self
    }
    pub fn hidden(mut self) -> Self {
        self.returned = false;
        self
    }
    pub fn validate(
        mut self,
        validator: impl Fn(&JsValue) -> Result<JsValue, String> + Send + Sync + 'static,
    ) -> Self {
        self.validator = Some(Arc::new(validator));
        self
    }
    pub fn transform(
        mut self,
        transform: impl Fn(Option<&JsValue>) -> crate::AuthResult<Option<JsValue>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.transform = Some(Arc::new(transform));
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
    pub(crate) fn attach_adapter_transforms(&self, values: &mut FieldValues, creation: bool) {
        values.transform_omitted = creation;
        values.adapter_transforms = self
            .0
            .iter()
            .filter_map(|(name, field)| {
                field
                    .transform
                    .as_ref()
                    .map(|transform| (name.clone(), transform.clone()))
            })
            .collect();
    }
    pub fn defaults(&self, values: &mut FieldValues) {
        for (name, field) in &self.0 {
            if let Some(default) = &field.default {
                let _ = values
                    .entry(name.clone())
                    .or_insert_with(|| default.value());
            }
        }
    }
    pub fn parse_update(
        &self,
        input: &IndexMap<String, JsValue>,
    ) -> Result<FieldValues, FieldInputError> {
        let mut parsed = FieldValues::new();
        for (name, field) in &self.0 {
            let Some(value) = input.get(name) else {
                continue;
            };
            if !field.input {
                if truthy(value) {
                    return Err(FieldInputError::Validation {
                        code: "FIELD_NOT_ALLOWED",
                        message: format!("{name} is not allowed to be set"),
                    });
                }
                continue;
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
                    let _ = parsed.insert(name.clone(), value);
                }
                None => {
                    let _ = parsed.undefined_input_keys.insert(name.clone());
                }
            }
        }
        Ok(parsed)
    }
}
fn truthy(value: &JsValue) -> bool {
    match value {
        JsValue::Null => false,
        JsValue::Bool(value) => *value,
        JsValue::Number(value) => *value != 0.0 && !value.is_nan(),
        JsValue::String(value) => !value.is_empty(),
        JsValue::Array(_) | JsValue::Object(_) => true,
    }
}
