//! Logical JSON metadata and its database representation.

use crate::utils::json::{self, JsValue};

#[derive(Clone, Debug)]
pub struct MetadataCell(JsValue, Storage);

#[derive(Clone, Debug)]
enum Storage {
    EncodedText(String),
    StoredText,
    Scalar,
    Native,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataFormat {
    Sqlite,
    NativeJson,
}

pub enum MetadataParameter {
    Text(String),
    Scalar(JsValue),
    Json(Option<Box<serde_json::Value>>),
}

impl MetadataCell {
    pub fn for_format(value: JsValue, format: MetadataFormat) -> Result<Self, serde_json::Error> {
        match format {
            MetadataFormat::Sqlite => Self::try_from(value),
            MetadataFormat::NativeJson => {
                let _ = value.to_json_value()?;
                Ok(Self(value, Storage::Native))
            }
        }
    }

    #[must_use]
    pub fn stored_text(value: String) -> Self {
        Self(JsValue::String(value.into()), Storage::StoredText)
    }

    #[must_use]
    pub fn stored_json(value: serde_json::Value) -> Self {
        Self(value.into(), Storage::Native)
    }

    #[must_use]
    pub fn logical_value(&self) -> JsValue {
        match (&self.0, &self.1) {
            (JsValue::String(value), Storage::StoredText) => json::parse_adapter_string(value),
            _ => self.0.clone(),
        }
    }

    pub fn plain_value(&self) -> Result<JsValue, serde_json::Error> {
        match (&self.0, &self.1) {
            (JsValue::String(value), Storage::StoredText) => json::parse_js_value(value),
            _ => Ok(self.0.clone()),
        }
    }

    pub fn raw_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        self.0.to_json_value()
    }

    pub fn prepare(self, format: MetadataFormat) -> Result<Self, serde_json::Error> {
        if format == MetadataFormat::Sqlite && !matches!(self.1, Storage::Native) {
            return Ok(self);
        }
        let value = match self.1 {
            Storage::EncodedText(text) => json::parse_value(&text)?,
            Storage::StoredText => self.logical_value(),
            _ => self.0,
        };
        Self::for_format(value, format)
    }

    #[must_use]
    pub fn into_parameter(self) -> MetadataParameter {
        match self.1 {
            Storage::EncodedText(text) => MetadataParameter::Text(text),
            Storage::Scalar | Storage::StoredText => MetadataParameter::Scalar(self.0),
            Storage::Native if self.0.is_null() => MetadataParameter::Json(None),
            Storage::Native => MetadataParameter::Json(Some(Box::new(
                self.0
                    .to_json_value()
                    .expect("native JSON binding was validated"),
            ))),
        }
    }
}

impl PartialEq for MetadataCell {
    fn eq(&self, other: &Self) -> bool {
        self.logical_value() == other.logical_value()
    }
}

impl serde::Serialize for MetadataCell {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.logical_value().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for MetadataCell {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(JsValue::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<JsValue> for MetadataCell {
    type Error = serde_json::Error;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        let storage = match &value {
            JsValue::Undefined => {
                return Err(serde::ser::Error::custom(
                    "cannot bind undefined JSON metadata",
                ));
            }
            JsValue::Null | JsValue::Array(_) | JsValue::Object(_) | JsValue::Date(_) => {
                Storage::EncodedText(json::to_string(&value)?)
            }
            _ => Storage::Scalar,
        };
        Ok(Self(value, storage))
    }
}

impl From<serde_json::Value> for MetadataCell {
    fn from(value: serde_json::Value) -> Self {
        Self::try_from(JsValue::from(value)).expect("ordinary JSON contains no undefined root")
    }
}
