use super::{JsObject, JsString, JsValue, native_serializer};
use serde::de::{DeserializeSeed, EnumAccess, IntoDeserializer, VariantAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Error;

#[derive(Deserialize)]
#[serde(rename = "alibi::NativeValue")]
enum NativeValue {
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    String(JsString),
    Date((i64, u32)),
    Array(Vec<JsValue>),
    Object(JsObject),
}

pub(super) fn decode<'de, D: Deserializer<'de>>(deserializer: D) -> Result<JsValue, D::Error> {
    Ok(match NativeValue::deserialize(deserializer)? {
        NativeValue::Undefined => JsValue::Undefined,
        NativeValue::Null => JsValue::Null,
        NativeValue::Bool(value) => JsValue::Bool(value),
        NativeValue::Number(value) => JsValue::Number(value),
        NativeValue::String(value) => JsValue::String(value),
        NativeValue::Date((seconds, nanos)) => JsValue::Date(
            chrono::DateTime::from_timestamp(seconds, nanos)
                .ok_or_else(|| serde::de::Error::custom("invalid native date"))?,
        ),
        NativeValue::Array(value) => JsValue::Array(value),
        NativeValue::Object(value) => JsValue::Object(value),
    })
}

pub(super) struct Capture(pub(super) JsValue);
impl<'de> Deserializer<'de> for Capture {
    type Error = Error;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Error> {
        Err(serde::de::Error::custom("expected a closed native payload"))
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        let JsValue::String(value) = self.0 else {
            return Err(serde::de::Error::custom("expected UTF-16 string payload"));
        };
        visitor.visit_seq(serde::de::value::SeqDeserializer::new(
            value.code_units().to_vec().into_iter(),
        ))
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        if name != native_serializer::VALUE_ENUM {
            return Err(serde::de::Error::custom("invalid native enum payload"));
        }
        visitor.visit_enum(NativeEnum(self.0))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        option unit unit_struct newtype_struct tuple tuple_struct map struct identifier ignored_any
    }
}

struct NativeEnum(JsValue);
impl<'de> EnumAccess<'de> for NativeEnum {
    type Error = Error;
    type Variant = Self;
    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self), Error> {
        let name = match &self.0 {
            JsValue::Undefined => "Undefined",
            JsValue::Null => "Null",
            JsValue::Bool(_) => "Bool",
            JsValue::Number(_) => "Number",
            JsValue::String(_) => "String",
            JsValue::Date(_) => "Date",
            JsValue::Array(_) => "Array",
            JsValue::Object(_) => "Object",
        };
        Ok((seed.deserialize(name.into_deserializer())?, self))
    }
}
impl<'de> VariantAccess<'de> for NativeEnum {
    type Error = Error;
    fn unit_variant(self) -> Result<(), Error> {
        match self.0 {
            JsValue::Undefined | JsValue::Null => Ok(()),
            _ => Err(serde::de::Error::custom("expected a native unit variant")),
        }
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        match self.0 {
            JsValue::Date(value) => {
                seed.deserialize(serde::de::value::SeqDeserializer::<_, Error>::new(
                    [value.timestamp(), i64::from(value.timestamp_subsec_nanos())].into_iter(),
                ))
            }
            value => seed.deserialize(value),
        }
    }
    fn tuple_variant<V: Visitor<'de>>(self, _: usize, _: V) -> Result<V::Value, Error> {
        Err(serde::de::Error::custom("invalid native tuple variant"))
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        _: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Error> {
        Err(serde::de::Error::custom("invalid native struct variant"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, Deserialize, serde::Serialize, PartialEq)]
    struct Envelope<T> {
        value: T,
    }
    #[derive(Debug, Deserialize, serde::Serialize, PartialEq)]
    struct Profile {
        name: JsString,
        fields: JsObject,
    }

    #[test]
    fn native_deserialization_preserves_nested_utf16_undefined_dates_and_literal_protocol_names() {
        let date = chrono::DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap();
        let high = JsString::from_code_units(vec![0xd800]);
        let low = JsString::from_code_units(vec![0xdc00]);
        let literal = super::super::parse_value(r#"{"alibi::JsValue/v1":{"Undefined":null},"alibi::JsString/utf16-v1":[55296],"alibi::NativeValue":"Date"}"#).unwrap();
        let dto = Envelope {
            value: Envelope {
                value: Profile {
                    name: high.clone(),
                    fields: [
                        (low.clone(), JsValue::String(high.clone())),
                        ("undefined".into(), JsValue::Undefined),
                        ("null".into(), JsValue::Null),
                        ("date".into(), JsValue::Date(date)),
                        (
                            "array".into(),
                            JsValue::Array(vec![
                                JsValue::Undefined,
                                JsValue::Date(date),
                                JsValue::String(low),
                            ]),
                        ),
                        ("literal".into(), literal),
                    ]
                    .into_iter()
                    .collect(),
                },
            },
        };
        let native = super::super::to_js_value(&dto).unwrap();
        let restored: Envelope<Envelope<Profile>> = super::super::from_value(native).unwrap();
        assert_eq!(restored, dto);
        let name: Envelope<JsString> = super::super::from_value(JsValue::Object(
            [("value".into(), JsValue::String(high.clone()))]
                .into_iter()
                .collect(),
        ))
        .unwrap();
        assert_eq!(name.value, high);
        let strict: Result<Envelope<String>, _> = super::super::from_value(JsValue::Object(
            [("value".into(), JsValue::String(high))]
                .into_iter()
                .collect(),
        ));
        assert!(strict.is_err());
        let root: Envelope<JsValue> = super::super::from_value(JsValue::Object(
            [("value".into(), JsValue::Undefined)].into_iter().collect(),
        ))
        .unwrap();
        assert_eq!(root.value, JsValue::Undefined);
    }

    #[test]
    fn ordinary_deserialization_is_transparent_and_dtos_remain_human_readable() {
        #[derive(Debug)]
        struct Readable(bool);
        impl<'de> Deserialize<'de> for Readable {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let human = deserializer.is_human_readable();
                let _ = bool::deserialize(deserializer)?;
                Ok(Self(human))
            }
        }
        let ordinary = r#"{"value":{"alibi::JsValue/v1":{"Undefined":null},"alibi::JsString/utf16-v1":[55296]}}"#;
        let from_json: Envelope<JsValue> = serde_json::from_str(ordinary).unwrap();
        let native: Envelope<JsValue> =
            super::super::from_value(super::super::parse_value(ordinary).unwrap()).unwrap();
        assert_eq!(from_json, native);
        assert!(native.value.is_object());
        assert_eq!(serde_json::from_str::<JsString>(r#""ok""#).unwrap(), "ok");
        assert!(serde_json::from_str::<JsString>("[55296]").is_err());
        assert!(serde_json::from_str::<JsString>(r#""\ud800""#).is_err());
        let readable: Envelope<Readable> =
            super::super::from_value(super::super::parse_value(r#"{"value":false}"#).unwrap())
                .unwrap();
        assert!(readable.value.0);
    }
}
