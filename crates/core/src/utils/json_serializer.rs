//! Trusted Serde-to-JavaScript conversion. DTO serializers stay human-readable.
//! Only closed native-value payload captures report non-human-readable. Their
//! payload representation is private and is not a stable binary encoding.
//! Struct/map field names never select a native protocol.

use super::{JsObject, JsString, JsValue};
use serde::Serialize;
use serde::ser::{self, Error as _};
use serde_json::Error;

pub(super) const UTF16_PROTOCOL: &str = "alibi::JsString/utf16-v1";
pub(super) const VALUE_PROTOCOL: &str = "alibi::JsValue/v1";
pub(super) const VALUE_ENUM: &str = "alibi::NativeValue";

/// Capture trusted native values without projecting through ordinary UTF-8 JSON.
pub fn to_js_value<T: Serialize + ?Sized>(value: &T) -> Result<JsValue, Error> {
    value.serialize(NativeSerializer::normal())
}

#[derive(Clone, Copy)]
enum Capture {
    String,
    Value,
}

#[derive(Clone, Copy)]
struct NativeSerializer {
    capture: Option<Capture>,
}
impl NativeSerializer {
    const fn normal() -> Self {
        Self { capture: None }
    }
    fn require_normal(self) -> Result<(), Error> {
        if self.capture.is_some() {
            Err(Error::custom("Invalid native value payload"))
        } else {
            Ok(())
        }
    }
}
macro_rules! number {
    ($($method:ident($type:ty)),* $(,)?) => {$(
        fn $method(self, value: $type) -> Result<JsValue, Error> {
            self.require_normal()?;
            Ok(JsValue::Number(value as f64))
        }
    )*};
}
impl ser::Serializer for NativeSerializer {
    type Ok = JsValue;
    type Error = Error;
    type SerializeSeq = Sequence;
    type SerializeTuple = Sequence;
    type SerializeTupleStruct = Sequence;
    type SerializeTupleVariant = Sequence;
    type SerializeMap = Object;
    type SerializeStruct = Object;
    type SerializeStructVariant = Object;

    number!(
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_i128(i128),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_u128(u128),
        serialize_f32(f32),
        serialize_f64(f64)
    );
    fn serialize_bool(self, value: bool) -> Result<JsValue, Error> {
        self.require_normal()?;
        Ok(JsValue::Bool(value))
    }
    fn serialize_char(self, value: char) -> Result<JsValue, Error> {
        self.serialize_str(&value.to_string())
    }
    fn serialize_str(self, value: &str) -> Result<JsValue, Error> {
        self.require_normal()?;
        Ok(JsValue::String(value.into()))
    }
    fn serialize_bytes(self, value: &[u8]) -> Result<JsValue, Error> {
        self.require_normal()?;
        Ok(JsValue::Array(
            value
                .iter()
                .map(|byte| JsValue::Number(f64::from(*byte)))
                .collect(),
        ))
    }
    fn serialize_none(self) -> Result<JsValue, Error> {
        self.serialize_unit()
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<JsValue, Error> {
        self.require_normal()?;
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<JsValue, Error> {
        self.require_normal()?;
        Ok(JsValue::Null)
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<JsValue, Error> {
        self.serialize_unit()
    }
    fn serialize_unit_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
    ) -> Result<JsValue, Error> {
        match self.capture {
            Some(Capture::Value) if name == VALUE_ENUM => match (index, variant) {
                (0, "Undefined") => Ok(JsValue::Undefined),
                (1, "Null") => Ok(JsValue::Null),
                _ => Err(Error::custom("Invalid native unit variant")),
            },
            Some(_) => Err(Error::custom("Invalid native value payload")),
            None => Ok(JsValue::String(variant.into())),
        }
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<JsValue, Error> {
        self.require_normal()?;
        match name {
            UTF16_PROTOCOL => {
                let JsValue::Array(units) = value.serialize(Self {
                    capture: Some(Capture::String),
                })?
                else {
                    return Err(Error::custom("Invalid UTF-16 payload"));
                };
                let units = units
                    .into_iter()
                    .map(|unit| {
                        unit.as_u64()
                            .and_then(|unit| u16::try_from(unit).ok())
                            .ok_or_else(|| Error::custom("Invalid UTF-16 code unit"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(JsValue::String(JsString::from_code_units(units)))
            }
            VALUE_PROTOCOL => value.serialize(Self {
                capture: Some(Capture::Value),
            }),
            _ => value.serialize(self),
        }
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<JsValue, Error> {
        let captured = value.serialize(Self::normal())?;
        match self.capture {
            Some(Capture::Value) if name == VALUE_ENUM => match (index, variant, captured) {
                (2, "Bool", value @ JsValue::Bool(_))
                | (3, "Number", value @ JsValue::Number(_))
                | (4, "String", value @ JsValue::String(_))
                | (6, "Array", value @ JsValue::Array(_))
                | (7, "Object", value @ JsValue::Object(_)) => Ok(value),
                (5, "Date", JsValue::Array(parts)) if parts.len() == 2 => {
                    let seconds = parts[0]
                        .as_i64()
                        .ok_or_else(|| Error::custom("Invalid native Date seconds"))?;
                    let nanos = parts[1]
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok())
                        .ok_or_else(|| Error::custom("Invalid native Date nanoseconds"))?;
                    chrono::DateTime::from_timestamp(seconds, nanos)
                        .map(JsValue::Date)
                        .ok_or_else(|| Error::custom("Invalid native Date"))
                }
                _ => Err(Error::custom("Invalid native value variant")),
            },
            Some(_) => Err(Error::custom("Invalid native value payload")),
            None => Ok(tagged(Some(variant), captured)),
        }
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Sequence, Error> {
        if matches!(self.capture, Some(Capture::Value)) {
            return Err(Error::custom("Invalid native value payload"));
        }
        Ok(Sequence {
            values: Vec::new(),
            variant: None,
            units: self.capture.is_some(),
        })
    }
    fn serialize_tuple(self, length: usize) -> Result<Sequence, Error> {
        self.serialize_seq(Some(length))
    }
    fn serialize_tuple_struct(self, _: &'static str, length: usize) -> Result<Sequence, Error> {
        self.serialize_seq(Some(length))
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        _: usize,
    ) -> Result<Sequence, Error> {
        self.require_normal()?;
        Ok(Sequence {
            values: Vec::new(),
            variant: Some(variant),
            units: false,
        })
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Object, Error> {
        self.require_normal()?;
        Ok(Object {
            fields: JsObject::new(),
            key: None,
            variant: None,
        })
    }
    fn serialize_struct(self, _: &'static str, length: usize) -> Result<Object, Error> {
        self.serialize_map(Some(length))
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        _: usize,
    ) -> Result<Object, Error> {
        self.require_normal()?;
        Ok(Object {
            fields: JsObject::new(),
            key: None,
            variant: Some(variant),
        })
    }
    fn is_human_readable(&self) -> bool {
        self.capture.is_none()
    }
}
fn tagged(variant: Option<&str>, value: JsValue) -> JsValue {
    match variant {
        None => value,
        Some(variant) => JsValue::Object([(variant.into(), value)].into_iter().collect()),
    }
}
struct Sequence {
    values: Vec<JsValue>,
    variant: Option<&'static str>,
    units: bool,
}
impl Sequence {
    fn push<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        let value = to_js_value(value)?;
        if self.units
            && value
                .as_u64()
                .is_none_or(|unit| u16::try_from(unit).is_err())
        {
            return Err(Error::custom("Invalid UTF-16 code unit"));
        }
        self.values.push(value);
        Ok(())
    }
    fn finish(self) -> JsValue {
        tagged(self.variant, JsValue::Array(self.values))
    }
}
impl ser::SerializeSeq for Sequence {
    type Ok = JsValue;
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }
    fn end(self) -> Result<JsValue, Error> {
        Ok(self.finish())
    }
}
impl ser::SerializeTuple for Sequence {
    type Ok = JsValue;
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }
    fn end(self) -> Result<JsValue, Error> {
        Ok(self.finish())
    }
}
impl ser::SerializeTupleStruct for Sequence {
    type Ok = JsValue;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }
    fn end(self) -> Result<JsValue, Error> {
        Ok(self.finish())
    }
}
impl ser::SerializeTupleVariant for Sequence {
    type Ok = JsValue;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }
    fn end(self) -> Result<JsValue, Error> {
        Ok(self.finish())
    }
}
struct Object {
    fields: JsObject,
    key: Option<JsString>,
    variant: Option<&'static str>,
}
impl Object {
    fn insert<T: Serialize + ?Sized>(&mut self, key: JsString, value: &T) -> Result<(), Error> {
        _ = self.fields.insert(key, to_js_value(value)?);
        Ok(())
    }
    fn finish(self) -> Result<JsValue, Error> {
        if self.key.is_some() {
            return Err(Error::custom("Missing map value"));
        }
        Ok(tagged(self.variant, JsValue::Object(self.fields)))
    }
}
impl ser::SerializeMap for Object {
    type Ok = JsValue;
    type Error = Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Error> {
        if self.key.is_some() {
            return Err(Error::custom("Missing map value"));
        }
        let key = to_js_value(key)?;
        self.key = Some(match key {
            JsValue::String(key) => key,
            JsValue::Bool(_) | JsValue::Number(_) => {
                key.coerce_js_string().map_err(Error::custom)?
            }
            _ => return Err(Error::custom("JSON object key must be a scalar string")),
        });
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        let key = self
            .key
            .take()
            .ok_or_else(|| Error::custom("Missing map key"))?;
        self.insert(key, value)
    }
    fn end(self) -> Result<JsValue, Error> {
        self.finish()
    }
}
impl ser::SerializeStruct for Object {
    type Ok = JsValue;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.insert(key.into(), value)
    }
    fn end(self) -> Result<JsValue, Error> {
        self.finish()
    }
}
impl ser::SerializeStructVariant for Object {
    type Ok = JsValue;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.insert(key.into(), value)
    }
    fn end(self) -> Result<JsValue, Error> {
        self.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serializer;

    #[derive(Serialize)]
    struct Envelope<T> {
        value: T,
    }
    #[derive(Serialize)]
    struct Profile {
        name: JsString,
        fields: JsObject,
        absent: JsValue,
        null: JsValue,
        date: JsValue,
    }

    #[test]
    fn native_serde_retains_nested_dto_keys_values_undefined_null_and_date() {
        let high = JsString::from_code_units(vec![0xd800]);
        let low = JsString::from_code_units(vec![0xdc00]);
        let date = chrono::DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap();
        let fields: JsObject = [
            (low.clone(), JsValue::String(high.clone())),
            ("absent".into(), JsValue::Undefined),
            ("null".into(), JsValue::Null),
        ]
        .into_iter()
        .collect();
        let dto = Envelope {
            value: Envelope {
                value: Profile {
                    name: high.clone(),
                    fields,
                    absent: JsValue::Undefined,
                    null: JsValue::Null,
                    date: JsValue::Date(date),
                },
            },
        };
        assert!(serde_json::to_value(&dto).is_err());
        assert!(serde_json::to_string(&dto).is_err());
        let native = to_js_value(&dto).unwrap();
        let profile = &native["value"]["value"];
        assert_eq!(profile["name"], JsValue::String(high.clone()));
        assert_eq!(
            profile["fields"].as_object().unwrap().get(&low),
            Some(&JsValue::String(high))
        );
        assert_eq!(
            profile.as_object().unwrap().get("absent"),
            Some(&JsValue::Undefined)
        );
        assert_eq!(
            profile.as_object().unwrap().get("null"),
            Some(&JsValue::Null)
        );
        assert_eq!(profile["date"], JsValue::Date(date));
        let bytes = super::super::stringify(&native).unwrap().unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        assert!(wire.contains(r#""name":"\ud800""#), "{wire}");
        assert!(wire.contains(r#""\udc00":"\ud800""#), "{wire}");
        assert!(!wire.contains("absent"));
        assert!(wire.contains(r#""null":null"#));
        assert!(wire.contains("2023-11-14T22:13:20.123Z"));
    }

    #[test]
    fn native_serde_root_undefined_and_ordinary_projection_remain_distinct() {
        assert_eq!(
            to_js_value(&JsValue::Undefined).unwrap(),
            JsValue::Undefined
        );
        assert_eq!(
            super::super::stringify(&to_js_value(&JsValue::Undefined).unwrap()).unwrap(),
            None
        );
        assert!(serde_json::to_value(JsValue::Undefined).is_err());
        assert!(serde_json::to_string(&JsValue::Undefined).is_err());
        let lone = JsString::from_code_units(vec![0xdfff]);
        assert_eq!(to_js_value(&lone).unwrap(), JsValue::String(lone.clone()));
        assert!(serde_json::to_value(&lone).is_err());
        assert!(serde_json::to_string(&lone).is_err());
        assert_eq!(
            serde_json::to_value(JsString::from("é😀")).unwrap(),
            serde_json::json!("é😀")
        );
        assert_eq!(
            serde_json::to_value(JsValue::String("é😀".into())).unwrap(),
            serde_json::json!("é😀")
        );
        let ordinary = JsValue::Object(
            [
                ("absent".into(), JsValue::Undefined),
                ("null".into(), JsValue::Null),
            ]
            .into_iter()
            .collect(),
        );
        assert_eq!(
            serde_json::to_value(ordinary).unwrap(),
            serde_json::json!({"null":null})
        );
    }

    struct HumanReadableDto(JsValue);
    impl Serialize for HumanReadableDto {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            assert!(serializer.is_human_readable());
            serializer.serialize_newtype_struct("application-wrapper", &self.0)
        }
    }

    #[test]
    fn native_serde_does_not_interpret_user_fields_or_change_dto_human_readability() {
        let literal = serde_json::json!({
            (UTF16_PROTOCOL): [0xd800],
            (VALUE_PROTOCOL): {"Undefined": null},
            (VALUE_ENUM): {"Date": [0,0]},
            "$serde_json::private::RawValue": "literal",
            "$serde_json::private::Number": "literal",
        });
        assert!(literal.get(UTF16_PROTOCOL).is_some());
        assert!(literal.get(VALUE_PROTOCOL).is_some());
        let parsed = super::super::parse_value(&literal.to_string()).unwrap();
        let wrapped = HumanReadableDto(parsed.clone());
        assert_eq!(to_js_value(&wrapped).unwrap(), parsed);
        assert_eq!(serde_json::to_value(&wrapped).unwrap(), literal);

        let user: crate::UserView = serde_json::from_value(serde_json::json!({
            "id":"user", "name":"Ordinary", "email":"user@fixture.test",
            "emailVerified":true, "createdAt":"2020-01-01T00:00:00.000Z",
            "updatedAt":"2020-01-01T00:00:00.000Z"
        }))
        .unwrap();
        #[derive(Serialize)]
        struct UserResponse {
            user: crate::UserView,
            profile: JsValue,
        }
        let response = Envelope {
            value: UserResponse {
                user,
                profile: JsValue::String(JsString::from_code_units(vec![0xd800])),
            },
        };
        let captured = to_js_value(&response).unwrap();
        assert_eq!(captured["value"]["user"]["name"], "Ordinary");
        assert_eq!(
            captured["value"]["profile"]
                .as_js_string()
                .unwrap()
                .code_units(),
            &[0xd800]
        );
        assert!(serde_json::to_value(&response).is_err());
    }
}
