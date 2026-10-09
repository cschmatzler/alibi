//! JavaScript JSON numbers at request, response, callback and storage boundaries.
//!
//! `JsValue` carries IEEE754 numbers, including Infinity and signed zero, without
//! enabling `serde_json` features that reserve otherwise valid application keys.

use indexmap::IndexMap;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{DeserializeOwned, IntoDeserializer, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Number, Value};
use std::{
    any::{Any, TypeId},
    fmt,
};

#[derive(Clone, Debug, PartialEq)]
pub enum JsValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Self>),
    Object(IndexMap<String, Self>),
}

impl JsValue {
    /// JavaScript String coercion used by trusted endpoint ID schemas.
    /// # Errors
    /// Returns an error when an own toString value prevents object coercion.
    pub fn coerce_string(&self) -> Result<String, &'static str> {
        match self {
            Self::Null => Ok("null".to_owned()),
            Self::Bool(value) => Ok(value.to_string()),
            Self::String(value) => Ok(value.clone()),
            Self::Number(value) => Ok(ryu_js::Buffer::new().format(*value).to_owned()),
            Self::Array(values) => values
                .iter()
                .map(|value| match value {
                    Self::Null => Ok(String::new()),
                    value => value.coerce_string(),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(|values| values.join(",")),
            Self::Object(value) if value.contains_key("toString") => {
                Err("Cannot convert object to primitive value")
            }
            Self::Object(_) => Ok("[object Object]".to_owned()),
        }
    }

    #[must_use]
    pub const fn as_f64(&self) -> Option<f64> {
        if let Self::Number(n) = self {
            Some(*n)
        } else {
            None
        }
    }
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s)
        } else {
            None
        }
    }
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }
    #[must_use]
    pub const fn as_object(&self) -> Option<&IndexMap<String, Self>> {
        if let Self::Object(m) = self {
            Some(m)
        } else {
            None
        }
    }
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        if let Self::Array(a) = self {
            Some(a)
        } else {
            None
        }
    }
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        self.as_object()?.get(key)
    }
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
    #[must_use]
    pub const fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }
    #[must_use]
    pub const fn is_boolean(&self) -> bool {
        matches!(self, Self::Bool(_))
    }
    #[must_use]
    pub const fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }
    #[must_use]
    pub const fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }
    /// Apply JSON.stringify before converting to `serde_json`'s finite representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the JavaScript value cannot be represented as JSON.
    pub fn to_json_value(&self) -> Result<Value, serde_json::Error> {
        finite_value(self)
    }
}

impl From<Value> for JsValue {
    fn from(value: Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(b) => Self::Bool(b),
            Value::Number(n) => Self::Number(n.as_f64().unwrap_or_default()),
            Value::String(s) => Self::String(s),
            Value::Array(a) => Self::Array(a.into_iter().map(Self::from).collect()),
            Value::Object(m) => {
                Self::Object(m.into_iter().map(|(k, v)| (k, Self::from(v))).collect())
            }
        }
    }
}

impl Serialize for JsValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(b) => serializer.serialize_bool(*b),
            Self::Number(n) => serializer.serialize_f64(*n),
            Self::String(s) => serializer.serialize_str(s),
            Self::Array(a) => a.serialize(serializer),
            Self::Object(m) => m.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for JsValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsVisitor;
        impl<'de> Visitor<'de> for JsVisitor {
            type Value = JsValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value")
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(JsValue::Null)
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(JsValue::Null)
            }
            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
                Ok(JsValue::Bool(v))
            }
            #[expect(
                clippy::as_conversions,
                clippy::cast_precision_loss,
                reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
            )]
            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
                Ok(JsValue::Number(v as f64))
            }
            #[expect(
                clippy::as_conversions,
                clippy::cast_precision_loss,
                reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
            )]
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
                Ok(JsValue::Number(v as f64))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E> {
                Ok(JsValue::Number(v))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(JsValue::String(v.into()))
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(JsValue::String(v))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element()? {
                    values.push(value);
                }
                Ok(JsValue::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = IndexMap::new();
                while let Some((key, value)) = map.next_entry()? {
                    _ = values.insert(key, value);
                }
                Ok(JsValue::Object(values))
            }
        }
        deserializer.deserialize_any(JsVisitor)
    }
}

impl IntoDeserializer<'_, serde_json::Error> for JsValue {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}

macro_rules! signed_number {
    ($($method:ident),*) => {$(
#[expect(clippy::as_conversions, clippy::cast_possible_truncation, reason = "Finite integral values are checked against the target integer bounds before conversion")]
        fn $method<V: Visitor<'de>>(self,visitor:V)->Result<V::Value,Self::Error> {
            match self {
                Self::Number(n) if n.is_finite() && n.fract()==0.0 && (-9_223_372_036_854_776_000.0..9_223_372_036_854_776_000.0).contains(&n) => visitor.visit_i64(n as i64),
                value => value.deserialize_any(visitor),
            }
        }
    )*};
}

macro_rules! unsigned_number {
    ($($method:ident),*) => {$(
#[expect(clippy::as_conversions, clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "Finite integral values are checked against the target integer bounds before conversion")]
        fn $method<V: Visitor<'de>>(self,visitor:V)->Result<V::Value,Self::Error> {
            match self {
                Self::Number(n) if n.is_finite() && n.fract()==0.0 && (0.0..18_446_744_073_709_552_000.0).contains(&n) => visitor.visit_u64(n as u64),
                value => value.deserialize_any(visitor),
            }
        }
    )*};
}

impl<'de> Deserializer<'de> for JsValue {
    type Error = serde_json::Error;
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self {
            Self::Null => visitor.visit_unit(),
            Self::Bool(b) => visitor.visit_bool(b),
            Self::Number(n) => visitor.visit_f64(n),
            Self::String(s) => visitor.visit_string(s),
            Self::Array(a) => {
                visitor.visit_seq(serde::de::value::SeqDeserializer::new(a.into_iter()))
            }
            Self::Object(m) => {
                visitor.visit_map(serde::de::value::MapDeserializer::new(m.into_iter()))
            }
        }
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        if self.is_null() {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        match self {
            Self::String(s) => visitor.visit_enum(s.into_deserializer()),
            Self::Object(map) => visitor.visit_enum(serde::de::value::MapAccessDeserializer::new(
                serde::de::value::MapDeserializer::new(map.into_iter()),
            )),
            value @ (Self::Null | Self::Bool(_) | Self::Number(_) | Self::Array(_)) => {
                value.deserialize_any(visitor)
            }
        }
    }
    signed_number!(
        deserialize_i8,
        deserialize_i16,
        deserialize_i32,
        deserialize_i64,
        deserialize_i128
    );
    unsigned_number!(
        deserialize_u8,
        deserialize_u16,
        deserialize_u32,
        deserialize_u64,
        deserialize_u128
    );
    serde::forward_to_deserialize_any! {
        bool f32 f64 char str string bytes
        byte_buf unit unit_struct seq tuple tuple_struct map struct identifier ignored_any
    }
}

struct Parser<'a> {
    input: &'a str,
    position: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.position).copied()
    }
    fn whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.position += 1;
        }
    }
    fn take(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }
    fn string(&mut self) -> Result<String, serde_json::Error> {
        let start = self.position;
        if !self.take(b'"') {
            return Err(invalid("expected JSON string"));
        }
        loop {
            match self.peek() {
                Some(b'"') => {
                    self.position += 1;
                    return serde_json::from_str(
                        self.input
                            .get(start..self.position)
                            .ok_or_else(|| invalid("invalid JSON string bounds"))?,
                    );
                }
                Some(b'\\') => {
                    self.position += 1;
                    if self.peek().is_none() {
                        return Err(invalid("unterminated JSON escape"));
                    }
                    self.position += 1;
                }
                Some(_) => self.position += 1,
                None => return Err(invalid("unterminated JSON string")),
            }
        }
    }
    fn value(&mut self, depth: usize) -> Result<JsValue, serde_json::Error> {
        self.whitespace();
        match self.peek() {
            Some(b'"') => self.string().map(JsValue::String),
            Some(b'{') => {
                if depth >= 127 {
                    return Err(invalid("recursion limit exceeded"));
                }
                self.position += 1;
                self.whitespace();
                let mut values = IndexMap::new();
                if self.take(b'}') {
                    return Ok(JsValue::Object(values));
                }
                loop {
                    self.whitespace();
                    let key = self.string()?;
                    self.whitespace();
                    if !self.take(b':') {
                        return Err(invalid("expected JSON colon"));
                    }
                    let value = self.value(depth + 1)?;
                    _ = values.insert(key, value);
                    self.whitespace();
                    if self.take(b'}') {
                        break;
                    }
                    if !self.take(b',') {
                        return Err(invalid("expected JSON object delimiter"));
                    }
                }
                Ok(JsValue::Object(values))
            }
            Some(b'[') => {
                if depth >= 127 {
                    return Err(invalid("recursion limit exceeded"));
                }
                self.position += 1;
                self.whitespace();
                let mut values = Vec::new();
                if self.take(b']') {
                    return Ok(JsValue::Array(values));
                }
                loop {
                    values.push(self.value(depth + 1)?);
                    self.whitespace();
                    if self.take(b']') {
                        break;
                    }
                    if !self.take(b',') {
                        return Err(invalid("expected JSON array delimiter"));
                    }
                }
                Ok(JsValue::Array(values))
            }
            Some(b't') => self.literal("true", JsValue::Bool(true)),
            Some(b'f') => self.literal("false", JsValue::Bool(false)),
            Some(b'n') => self.literal("null", JsValue::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(invalid("expected JSON value")),
        }
    }
    fn literal(&mut self, text: &str, value: JsValue) -> Result<JsValue, serde_json::Error> {
        if self
            .input
            .get(self.position..)
            .is_some_and(|rest| rest.starts_with(text))
        {
            self.position += text.len();
            Ok(value)
        } else {
            Err(invalid("invalid JSON literal"))
        }
    }
    fn digits(&mut self) -> bool {
        let start = self.position;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.position += 1;
        }
        self.position > start
    }
    fn number(&mut self) -> Result<JsValue, serde_json::Error> {
        let start = self.position;
        _ = self.take(b'-');
        if !self.take(b'0') && !self.digits() {
            return Err(invalid("invalid JSON number"));
        }
        if self.take(b'.') && !self.digits() {
            return Err(invalid("invalid JSON fraction"));
        }
        if self.take(b'e') || self.take(b'E') {
            _ = self.take(b'+') || self.take(b'-');
            if !self.digits() {
                return Err(invalid("invalid JSON exponent"));
            }
        }
        self.input
            .get(start..self.position)
            .ok_or_else(|| invalid("invalid JSON number bounds"))?
            .parse::<f64>()
            .map(JsValue::Number)
            .map_err(|_error| invalid("invalid JSON number"))
    }
}

/// Parse RFC8259 structure with JavaScript f64 conversion. Strings use `serde_json`'s
/// escape/UTF8 validation; structural recursion is bounded to its default depth.
///
/// # Errors
///
/// Returns an error if the input is not valid JSON.
pub fn parse_value(input: &str) -> Result<JsValue, serde_json::Error> {
    let mut parser = Parser { input, position: 0 };
    let value = parser.value(0)?;
    parser.whitespace();
    if parser.position != input.len() {
        return Err(invalid("trailing JSON input"));
    }
    Ok(value)
}

/// # Errors
///
/// Returns an error if the input is not valid JSON or cannot be deserialized into the requested type.
pub fn from_slice<T: DeserializeOwned + 'static>(input: &[u8]) -> Result<T, serde_json::Error> {
    let text = std::str::from_utf8(input).map_err(|_error| invalid("invalid JSON UTF8"))?;
    from_value(parse_value(text)?)
}

/// Decode an owned DTO.
///
/// Root `Value` is constructed without `serde_json`'s private map markers. Arbitrary nested
/// `Value` fields must use `deserialize_value` or `deserialize_optional_value`; `JsValue` fields
/// require no adapter.
///
/// # Errors
///
/// Returns an error if the value cannot be deserialized into the requested type.
pub fn from_value<T: DeserializeOwned + 'static>(input: JsValue) -> Result<T, serde_json::Error> {
    if TypeId::of::<T>() == TypeId::of::<Value>() {
        let value: Box<dyn Any> = Box::new(input.to_json_value()?);
        return value
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_error| invalid("invalid JSON value type"));
    }
    T::deserialize(input)
}

/// Preserve arbitrary JSON object keys in a typed `serde_json::Value` field.
///
/// # Errors
///
/// Propagates errors from deserializing the JavaScript-compatible JSON representation.
pub fn deserialize_value<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
    JsValue::deserialize(deserializer)?
        .to_json_value()
        .map_err(serde::de::Error::custom)
}

/// Optional arbitrary JSON field adapter; null retains normal Option semantics.
///
/// # Errors
///
/// Propagates errors from deserializing the optional JSON representation.
pub fn deserialize_optional_value<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    Option::<JsValue>::deserialize(deserializer)?
        .map(|value| value.to_json_value().map_err(serde::de::Error::custom))
        .transpose()
}

/// Typed object adapter for arbitrary values inside a string-keyed map.
///
/// # Errors
///
/// Returns an error if the deserializer does not supply a valid JSON object.
pub fn deserialize_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<serde_json::Map<String, Value>, D::Error> {
    match deserialize_value(deserializer)? {
        Value::Object(map) => Ok(map),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_) => {
            Err(serde::de::Error::custom("expected JSON object"))
        }
    }
}

/// Deserialize arbitrary values in an optional object field.
///
/// # Errors
///
/// Returns an error if the supplied non-null value is not a valid JSON object.
pub fn deserialize_optional_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<serde_json::Map<String, Value>>, D::Error> {
    deserialize_optional_value(deserializer)?
        .map(|value| match value {
            Value::Object(map) => Ok(map),
            Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_)
            | Value::Array(_) => Err(serde::de::Error::custom("expected JSON object")),
        })
        .transpose()
}

/// Preserve arbitrary values in flattened public view extension fields.
///
/// # Errors
///
/// Returns an error if the deserializer does not supply a valid JSON object.
pub fn deserialize_btree_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<std::collections::BTreeMap<String, Value>, D::Error> {
    deserialize_map(deserializer).map(|map| map.into_iter().collect())
}

fn invalid(message: &str) -> serde_json::Error {
    <serde_json::Error as serde::de::Error>::custom(message)
}

#[must_use]
pub fn number_as_f64(number: &Number) -> Option<f64> {
    number.as_f64()
}

/// # Errors
///
/// Returns an error if the number cannot be serialized in JavaScript-compatible notation.
pub fn number_to_string(number: &Number) -> Result<String, serde_json::Error> {
    Ok(ryu_js::Buffer::new()
        .format(number_as_f64(number).ok_or_else(|| invalid("invalid JSON number"))?)
        .to_owned())
}

/// Encode Serialize data exactly as JSON.stringify would encode its numbers.
///
/// # Errors
///
/// Returns an error if the input cannot be serialized as JavaScript-compatible JSON.
pub fn to_vec<T: Serialize + ?Sized>(data: &T) -> Result<Vec<u8>, serde_json::Error> {
    let value = JsValue::from(serde_json::to_value(data)?);
    let mut bytes = Vec::new();
    write_value(&value, &mut bytes)?;
    Ok(bytes)
}

/// # Errors
///
/// Returns an error if the input cannot be serialized as JavaScript-compatible JSON.
pub fn to_string<T: Serialize + ?Sized>(data: &T) -> Result<String, serde_json::Error> {
    String::from_utf8(to_vec(data)?).map_err(|_error| invalid("invalid JSON output UTF8"))
}

/// # Errors
///
/// Returns an error if the `OpenAPI` document cannot be serialized.
pub fn to_value<T: Serialize + ?Sized>(data: &T) -> Result<Value, serde_json::Error> {
    finite_value(&JsValue::from(serde_json::to_value(data)?))
}

/// # Errors
///
/// Propagates errors from the serializer.
pub fn serialize<T: Serialize + ?Sized, S: Serializer>(
    data: &T,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    to_value(data)
        .map_err(serde::ser::Error::custom)?
        .serialize(serializer)
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
fn finite_value(value: &JsValue) -> Result<Value, serde_json::Error> {
    match value {
        JsValue::Null => Ok(Value::Null),
        JsValue::Bool(b) => Ok(Value::Bool(*b)),
        JsValue::Number(n) if !n.is_finite() => Ok(Value::Null),
        JsValue::Number(n)
            if n.fract() == 0.0
                && (-9_223_372_036_854_776_000.0..9_223_372_036_854_776_000.0).contains(n) =>
        {
            Ok(Value::Number(Number::from(*n as i64)))
        }
        JsValue::Number(n)
            if n.fract() == 0.0 && (0.0..18_446_744_073_709_552_000.0).contains(n) =>
        {
            Ok(Value::Number(Number::from(*n as u64)))
        }
        JsValue::Number(n) => Number::from_f64(*n)
            .map(Value::Number)
            .ok_or_else(|| invalid("invalid finite JSON number")),
        JsValue::String(s) => Ok(Value::String(s.clone())),
        JsValue::Array(a) => a
            .iter()
            .map(finite_value)
            .collect::<Result<_, _>>()
            .map(Value::Array),
        JsValue::Object(m) => {
            let mut entries: Vec<_> = m.iter().collect();
            entries.sort_by_key(|(name, _)| array_index(name).unwrap_or(u32::MAX));
            let mut values = serde_json::Map::new();
            for (key, value_2) in entries {
                _ = values.insert(key.clone(), finite_value(value_2)?);
            }
            Ok(Value::Object(values))
        }
    }
}

fn write_value(value: &JsValue, bytes: &mut Vec<u8>) -> Result<(), serde_json::Error> {
    match value {
        JsValue::Null => bytes.extend_from_slice(b"null"),
        JsValue::Bool(true) => bytes.extend_from_slice(b"true"),
        JsValue::Bool(false) => bytes.extend_from_slice(b"false"),
        JsValue::Number(n) => {
            if n.is_finite() {
                bytes.extend_from_slice(ryu_js::Buffer::new().format_finite(*n).as_bytes());
            } else {
                bytes.extend_from_slice(b"null");
            }
        }
        JsValue::String(s) => serde_json::to_writer(bytes, s)?,
        JsValue::Array(a) => {
            bytes.push(b'[');
            for (index, value_2) in a.iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                write_value(value_2, bytes)?;
            }
            bytes.push(b']');
        }
        JsValue::Object(m) => {
            let mut entries: Vec<_> = m.iter().collect();
            entries.sort_by_key(|(name, _)| array_index(name).unwrap_or(u32::MAX));
            bytes.push(b'{');
            for (index, (key, value_3)) in entries.into_iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                serde_json::to_writer(&mut *bytes, key)?;
                bytes.push(b':');
                write_value(value_3, bytes)?;
            }
            bytes.push(b'}');
        }
    }
    Ok(())
}

fn array_index(name: &str) -> Option<u32> {
    let index = name.parse::<u32>().ok()?;
    (index != u32::MAX && index.to_string() == name).then_some(index)
}
