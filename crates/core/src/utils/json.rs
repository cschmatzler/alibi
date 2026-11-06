//! JavaScript JSON numbers at request, response, callback and storage boundaries.
//!
//! `JsValue` carries IEEE754 numbers, including Infinity and signed zero, without
//! enabling `serde_json` features that reserve otherwise valid application keys.

#[path = "js_string.rs"]
mod js_string;
pub use js_string::JsString;
pub type JsObject = IndexMap<JsString, JsValue>;

use chrono::Datelike;
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
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    String(JsString),
    /// A trusted SDK Date value; JSON transport still produces a string.
    Date(chrono::DateTime<chrono::Utc>),
    Array(Vec<Self>),
    Object(JsObject),
}

/// Explicit typed decoding for values outside ordinary UTF-8 JSON.
pub trait FromJsValue: Sized {
    type Error: fmt::Display;
    fn from_js_value(value: JsValue) -> Result<Self, Self::Error>;
}
impl FromJsValue for JsValue {
    type Error = std::convert::Infallible;
    fn from_js_value(value: JsValue) -> Result<Self, Self::Error> {
        Ok(value)
    }
}

impl JsValue {
    /// JavaScript String coercion used by trusted endpoint ID schemas.
    /// # Errors
    /// Returns an error when an own toString value prevents object coercion.
    pub fn coerce_string(&self) -> Result<String, &'static str> {
        self.coerce_js_string()?
            .to_utf8()
            .map_err(|_| "isolated UTF-16 surrogate")
    }

    /// JavaScript String coercion, without projecting code units to UTF-8.
    pub fn coerce_js_string(&self) -> Result<JsString, &'static str> {
        Ok(match self {
            Self::Undefined => "undefined".into(),
            Self::Null => "null".into(),
            Self::Bool(value) => value.to_string().into(),
            Self::String(value) => value.clone(),
            Self::Date(value) => format!(
                "{}{}{:04}{}",
                value.format("%a %b %d "),
                if value.year() < 0 { "-" } else { "" },
                value.year().unsigned_abs(),
                value.format(" %H:%M:%S GMT%z (Coordinated Universal Time)")
            )
            .into(),
            Self::Number(value) => ryu_js::Buffer::new().format(*value).to_owned().into(),
            Self::Array(values) => {
                let mut units = Vec::new();
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        units.push(44);
                    }
                    if !matches!(value, Self::Undefined | Self::Null) {
                        units.extend_from_slice(value.coerce_js_string()?.code_units());
                    }
                }
                JsString::from_code_units(units)
            }
            Self::Object(value) if value.contains_key("toString") => {
                return Err("Cannot convert object to primitive value");
            }
            Self::Object(_) => "[object Object]".into(),
        })
    }

    /// Own enumerable properties used by object spread.
    #[must_use]
    pub fn spread(&self) -> JsObject {
        match self {
            Self::Object(values) => values.clone(),
            Self::Array(values) => values
                .iter()
                .enumerate()
                .map(|(index, value)| (index.to_string().into(), value.clone()))
                .collect(),
            Self::String(value) => value
                .code_units()
                .iter()
                .copied()
                .enumerate()
                .map(|(index, unit)| {
                    (
                        index.to_string().into(),
                        Self::String(JsString::from_code_units(vec![unit])),
                    )
                })
                .collect(),
            _ => JsObject::new(),
        }
    }

    /// Property access boxes primitives, but throws for nullish receivers.
    pub fn property(&self, key: &str) -> Result<Self, &'static str> {
        if matches!(self, Self::Undefined | Self::Null) {
            return Err("Cannot read properties of null or undefined");
        }
        if let Self::String(value) = self {
            if key == "length" {
                return Ok(Self::Number(value.len() as f64));
            }
            if let Some(index) = array_index(key).and_then(|index| usize::try_from(index).ok()) {
                return Ok(value.code_unit_at(index).map_or(Self::Undefined, |unit| {
                    Self::String(JsString::from_code_units(vec![unit]))
                }));
            }
        }
        if let Self::Array(values) = self {
            if key == "length" {
                return Ok(Self::Number(values.len() as f64));
            }
            if let Some(index) = array_index(key).and_then(|index| usize::try_from(index).ok()) {
                return Ok(values.get(index).cloned().unwrap_or(Self::Undefined));
            }
        }
        Ok(self.get(key).cloned().unwrap_or(Self::Undefined))
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
            s.as_str()
        } else {
            None
        }
    }
    #[must_use]
    pub const fn as_js_string(&self) -> Option<&JsString> {
        if let Self::String(s) = self {
            Some(s)
        } else {
            None
        }
    }
    #[must_use]
    pub const fn as_date(&self) -> Option<&chrono::DateTime<chrono::Utc>> {
        if let Self::Date(value) = self {
            Some(value)
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
    pub const fn as_object(&self) -> Option<&JsObject> {
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
    pub fn get<I: JsIndex>(&self, key: I) -> Option<&Self> {
        key.lookup(self)
    }
    #[must_use]
    pub fn as_object_mut(&mut self) -> Option<&mut JsObject> {
        if let Self::Object(value) = self {
            Some(value)
        } else {
            None
        }
    }
    #[must_use]
    pub fn is_undefined(&self) -> bool {
        matches!(self, Self::Undefined)
    }
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        self.as_f64()
            .filter(|n| {
                n.is_finite() && n.fract() == 0.0 && *n >= 0.0 && *n < 18_446_744_073_709_551_616.0
            })
            .map(|n| n as u64)
    }
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        self.as_f64()
            .filter(|n| {
                n.is_finite()
                    && n.fract() == 0.0
                    && *n >= -9_223_372_036_854_775_808.0
                    && *n < 9_223_372_036_854_775_808.0
            })
            .map(|n| n as i64)
    }
    /// JavaScript truthiness.
    #[must_use]
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Undefined | Self::Null => false,
            Self::Bool(value) => *value,
            Self::Number(value) => *value != 0.0 && !value.is_nan(),
            Self::String(value) => !value.is_empty(),
            Self::Date(_) | Self::Array(_) | Self::Object(_) => true,
        }
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

pub trait JsIndex {
    fn lookup<'a>(self, value: &'a JsValue) -> Option<&'a JsValue>;
}
impl JsIndex for &str {
    fn lookup<'a>(self, value: &'a JsValue) -> Option<&'a JsValue> {
        value.as_object()?.get(self)
    }
}
impl<T: AsRef<str> + ?Sized> JsIndex for &&T {
    fn lookup<'a>(self, value: &'a JsValue) -> Option<&'a JsValue> {
        value.as_object()?.get((*self).as_ref())
    }
}
impl JsIndex for &String {
    fn lookup<'a>(self, value: &'a JsValue) -> Option<&'a JsValue> {
        value.as_object()?.get(self)
    }
}
impl JsIndex for usize {
    fn lookup<'a>(self, value: &'a JsValue) -> Option<&'a JsValue> {
        value.as_array()?.get(self)
    }
}
impl std::ops::Index<&str> for JsValue {
    type Output = Self;
    fn index(&self, key: &str) -> &Self {
        self.get(key).unwrap_or(&Self::Undefined)
    }
}
impl std::ops::Index<usize> for JsValue {
    type Output = Self;
    fn index(&self, key: usize) -> &Self {
        self.get(key).unwrap_or(&Self::Undefined)
    }
}
impl Default for JsValue {
    fn default() -> Self {
        Self::Null
    }
}
/// Project object keys to an ordinary UTF-8 keyed input contract without changing values.
pub fn utf8_keys(value: &JsObject) -> Result<IndexMap<String, JsValue>, serde_json::Error> {
    value
        .iter()
        .map(|(key, value)| {
            Ok((
                key.to_utf8()
                    .map_err(|_| invalid("isolated UTF-16 surrogate in key"))?,
                value.clone(),
            ))
        })
        .collect()
}

impl From<Value> for JsValue {
    fn from(value: Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(b) => Self::Bool(b),
            Value::Number(n) => Self::Number(n.as_f64().unwrap_or_default()),
            Value::String(s) => Self::String(s.into()),
            Value::Array(a) => Self::Array(a.into_iter().map(Self::from).collect()),
            Value::Object(m) => Self::Object(
                m.into_iter()
                    .map(|(k, v)| (k.into(), Self::from(v)))
                    .collect(),
            ),
        }
    }
}

impl Serialize for JsValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        finite_value(self)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
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
                Ok(JsValue::String(v.into()))
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

/// Integral numbers within the target's range deserialize as integers; everything
/// else defers to `deserialize_any`.
macro_rules! integer_number {
    ($visit:ident, $cast:ty, $range:expr, $expect:meta, $($method:ident),*) => {$(
        #[$expect]
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            match self {
                Self::Number(n) if n.is_finite() && n.fract() == 0.0 && $range.contains(&n) => {
                    visitor.$visit(n as $cast)
                }
                value => value.deserialize_any(visitor),
            }
        }
    )*};
}

impl<'de> Deserializer<'de> for JsValue {
    type Error = serde_json::Error;
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self {
            Self::Undefined => Err(invalid("cannot deserialize undefined")),
            Self::Null => visitor.visit_unit(),
            Self::Bool(b) => visitor.visit_bool(b),
            Self::Number(n) => visitor.visit_f64(n),
            Self::String(s) => visitor.visit_string(
                s.to_utf8()
                    .map_err(|_| invalid("isolated UTF-16 surrogate"))?,
            ),
            Self::Date(value) => visitor.visit_string(crate::utils::datetime::json_date_millis(
                value.timestamp_millis(),
            )),
            Self::Array(a) => {
                visitor.visit_seq(serde::de::value::SeqDeserializer::new(a.into_iter()))
            }
            Self::Object(m) => visitor.visit_map(serde::de::value::MapDeserializer::new(
                ordinary_entries(m)?.into_iter(),
            )),
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
            Self::String(s) => visitor.visit_enum(
                s.to_utf8()
                    .map_err(|_| invalid("isolated UTF-16 surrogate"))?
                    .into_deserializer(),
            ),
            Self::Object(map) => visitor.visit_enum(serde::de::value::MapAccessDeserializer::new(
                serde::de::value::MapDeserializer::new(ordinary_entries(map)?.into_iter()),
            )),
            value @ (Self::Undefined
            | Self::Null
            | Self::Bool(_)
            | Self::Number(_)
            | Self::Date(_)
            | Self::Array(_)) => value.deserialize_any(visitor),
        }
    }
    integer_number!(
        visit_i64,
        i64,
        (-9_223_372_036_854_776_000.0..9_223_372_036_854_776_000.0),
        expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "Finite integral values are checked against the target integer bounds before conversion"
        ),
        deserialize_i8,
        deserialize_i16,
        deserialize_i32,
        deserialize_i64,
        deserialize_i128
    );
    integer_number!(
        visit_u64,
        u64,
        (0.0..18_446_744_073_709_552_000.0),
        expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "Finite integral values are checked against the target integer bounds before conversion"
        ),
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
    fn string(&mut self) -> Result<JsString, serde_json::Error> {
        if !self.take(b'"') {
            return Err(invalid("expected JSON string"));
        }
        let mut units = Vec::new();
        loop {
            match self.peek() {
                Some(b'"') => {
                    self.position += 1;
                    return Ok(JsString::from_code_units(units));
                }
                Some(b'\\') => {
                    self.position += 1;
                    let escaped = self
                        .peek()
                        .ok_or_else(|| invalid("unterminated JSON escape"))?;
                    self.position += 1;
                    let unit = match escaped {
                        b'"' => 34,
                        b'\\' => 92,
                        b'/' => 47,
                        b'b' => 8,
                        b'f' => 12,
                        b'n' => 10,
                        b'r' => 13,
                        b't' => 9,
                        b'u' => {
                            let mut unit = 0_u16;
                            for _ in 0..4 {
                                let digit = self
                                    .peek()
                                    .and_then(|b| char::from(b).to_digit(16))
                                    .ok_or_else(|| invalid("invalid JSON unicode escape"))?;
                                unit = unit * 16
                                    + u16::try_from(digit)
                                        .map_err(|_| invalid("invalid JSON unicode escape"))?;
                                self.position += 1;
                            }
                            unit
                        }
                        _ => return Err(invalid("invalid JSON escape")),
                    };
                    units.push(unit);
                }
                Some(0..=31) => return Err(invalid("control character in JSON string")),
                Some(_) => {
                    let ch = self
                        .input
                        .get(self.position..)
                        .and_then(|rest| rest.chars().next())
                        .ok_or_else(|| invalid("invalid JSON string"))?;
                    units.extend_from_slice(ch.encode_utf16(&mut [0; 2]));
                    self.position += ch.len_utf8();
                }
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
            .map_err(|_| invalid("invalid JSON number"))
    }
}

/// Parse JSON structure with JavaScript f64 conversion and UTF-16 escape decoding; structural recursion is bounded to its default depth.
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
    let text = std::str::from_utf8(input).map_err(|_| invalid("invalid JSON UTF8"))?;
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
    if TypeId::of::<T>() == TypeId::of::<JsValue>() {
        return (Box::new(input) as Box<dyn Any>)
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| invalid("invalid JavaScript value type"));
    }
    if TypeId::of::<T>() == TypeId::of::<Value>() {
        let value: Box<dyn Any> = Box::new(input.to_json_value()?);
        return value
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| invalid("invalid JSON value type"));
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
    String::from_utf8(to_vec(data)?).map_err(|_| invalid("invalid JSON output UTF8"))
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
        JsValue::Undefined => Err(invalid("undefined has no root JSON value")),
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
        JsValue::String(s) => s
            .to_utf8()
            .map(Value::String)
            .map_err(|_| invalid("isolated UTF-16 surrogate")),
        JsValue::Date(value) => Ok(Value::String(crate::utils::datetime::json_date_millis(
            value.timestamp_millis(),
        ))),
        JsValue::Array(a) => a
            .iter()
            .map(|value| {
                if matches!(value, JsValue::Undefined) {
                    Ok(Value::Null)
                } else {
                    finite_value(value)
                }
            })
            .collect::<Result<_, _>>()
            .map(Value::Array),
        JsValue::Object(m) => {
            let mut entries: Vec<_> = m
                .iter()
                .filter(|(_, value)| !matches!(value, JsValue::Undefined))
                .collect();
            entries
                .sort_by_key(|(name, _)| name.as_str().and_then(array_index).unwrap_or(u32::MAX));
            let mut values = serde_json::Map::new();
            for (key, value) in entries {
                if matches!(value, JsValue::Undefined) {
                    continue;
                }
                let key = key
                    .to_utf8()
                    .map_err(|_| invalid("isolated UTF-16 surrogate in key"))?;
                _ = values.insert(key, finite_value(value)?);
            }
            Ok(Value::Object(values))
        }
    }
}

fn write_value(value: &JsValue, bytes: &mut Vec<u8>) -> Result<(), serde_json::Error> {
    match value {
        JsValue::Undefined => return Err(invalid("undefined has no root JSON value")),
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
        JsValue::String(s) => write_string(s, bytes)?,
        JsValue::Date(value) => serde_json::to_writer(
            bytes,
            &crate::utils::datetime::json_date_millis(value.timestamp_millis()),
        )?,
        JsValue::Array(a) => {
            bytes.push(b'[');
            for (index, item) in a.iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                if matches!(item, JsValue::Undefined) {
                    bytes.extend_from_slice(b"null");
                } else {
                    write_value(item, bytes)?;
                }
            }
            bytes.push(b']');
        }
        JsValue::Object(m) => {
            let mut entries: Vec<_> = m
                .iter()
                .filter(|(_, value)| !matches!(value, JsValue::Undefined))
                .collect();
            entries
                .sort_by_key(|(name, _)| name.as_str().and_then(array_index).unwrap_or(u32::MAX));
            bytes.push(b'{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                write_string(key, bytes)?;
                bytes.push(b':');
                write_value(value, bytes)?;
            }
            bytes.push(b'}');
        }
    }
    Ok(())
}

/// Direct JSON.stringify projection without an intermediate UTF-8 value tree.
/// Root undefined has no JSON text.
pub fn stringify(value: &JsValue) -> Result<Option<Vec<u8>>, serde_json::Error> {
    if matches!(value, JsValue::Undefined) {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    write_value(value, &mut bytes)?;
    Ok(Some(bytes))
}

fn write_string(value: &JsString, bytes: &mut Vec<u8>) -> Result<(), serde_json::Error> {
    bytes.push(b'"');
    for scalar in char::decode_utf16(value.code_units().iter().copied()) {
        match scalar {
            Ok('"') => bytes.extend_from_slice(b"\\\""),
            Ok('\\') => bytes.extend_from_slice(b"\\\\"),
            Ok('\u{8}') => bytes.extend_from_slice(b"\\b"),
            Ok('\u{c}') => bytes.extend_from_slice(b"\\f"),
            Ok('\n') => bytes.extend_from_slice(b"\\n"),
            Ok('\r') => bytes.extend_from_slice(b"\\r"),
            Ok('\t') => bytes.extend_from_slice(b"\\t"),
            Ok(ch) if ch <= '\u{1f}' => {
                bytes.extend_from_slice(format!("\\u{:04x}", u32::from(ch)).as_bytes())
            }
            Ok(ch) => bytes.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes()),
            Err(err) => {
                bytes.extend_from_slice(format!("\\u{:04x}", err.unpaired_surrogate()).as_bytes())
            }
        }
    }
    bytes.push(b'"');
    Ok(())
}

fn ordinary_entries(map: JsObject) -> Result<Vec<(String, JsValue)>, serde_json::Error> {
    map.into_iter()
        .map(|(key, value)| {
            Ok((
                key.to_utf8()
                    .map_err(|_| invalid("isolated UTF-16 surrogate in key"))?,
                value,
            ))
        })
        .collect()
}

fn array_index(name: &str) -> Option<u32> {
    let index = name.parse::<u32>().ok()?;
    (index != u32::MAX && index.to_string() == name).then_some(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn lossless_utf16_parser_writer_and_projection() {
        for text in [
            r#""\ud83d""#,
            r#""\ude00""#,
            r#""\ude00\ud83d""#,
            r#""\ud83d\ud83d""#,
            r#"{"\ud800":"\udfff"}"#,
            r#""\\ud83d""#,
            r#""�""#,
        ] {
            let value = parse_value(text).unwrap();
            assert_eq!(
                String::from_utf8(stringify(&value).unwrap().unwrap()).unwrap(),
                text
            );
            assert_eq!(parse_value(text).unwrap(), value);
        }
        let pair = parse_value(r#""\ud83d\ude00""#).unwrap();
        assert_eq!(pair.as_js_string().unwrap().code_units(), &[0xd83d, 0xde00]);
        assert_eq!(stringify(&pair).unwrap().unwrap(), "\"😀\"".as_bytes());
        assert_eq!(pair.as_str(), Some("😀"));
        let high = parse_value(r#""\ud83d""#).unwrap();
        assert!(high.is_string());
        assert!(high.as_str().is_none());
        assert!(high.to_json_value().is_err());
        assert!(serde_json::to_value(&high).is_err());
        assert!(from_value::<String>(high.clone()).is_err());
        assert_eq!(from_value::<JsValue>(high.clone()).unwrap(), high);
        let key = parse_value(r#"{"\ud800":1}"#).unwrap();
        assert!(key.to_json_value().is_err());
        assert_eq!(
            key.as_object()
                .unwrap()
                .get(&JsString::from_code_units(vec![0xd800])),
            Some(&JsValue::Number(1.0))
        );
        let escaped = parse_value(r#""\\ud83d""#).unwrap();
        assert_eq!(escaped.as_js_string().unwrap().len(), 6);
        assert_ne!(escaped, high);
        assert_ne!(parse_value(r#""�""#).unwrap(), high);
    }

    #[test]
    fn lossless_spread_undefined_and_own_key_order() {
        let spread = JsValue::String("é😀".into()).spread();
        assert_eq!(spread["1"].as_js_string().unwrap().code_units(), &[0xd83d]);
        assert_eq!(spread["2"].as_js_string().unwrap().code_units(), &[0xde00]);
        let mut object = spread;
        object.insert("email".into(), JsValue::Undefined);
        object.insert("nested".into(), JsValue::Array(vec![JsValue::Undefined]));
        assert!(object.contains_key("email"));
        assert!(!object.contains_key("missing"));
        assert_eq!(
            stringify(&JsValue::Object(object)).unwrap().unwrap(),
            r#"{"0":"é","1":"\ud83d","2":"\ude00","nested":[null]}"#.as_bytes()
        );
        assert_eq!(stringify(&JsValue::Undefined).unwrap(), None);
        assert!(JsValue::Undefined.to_json_value().is_err());
        assert!(!JsValue::Undefined.is_truthy());
        assert_ne!(JsValue::Undefined, JsValue::Null);
        let value = parse_value(r#"{"4294967295":0,"2":2,"é":3,"0":0,"2":4,"01":1}"#).unwrap();
        assert_eq!(
            stringify(&value).unwrap().unwrap(),
            r#"{"0":0,"2":4,"4294967295":0,"é":3,"01":1}"#.as_bytes()
        );
        assert_eq!(
            JsValue::String("😀".into())
                .property("0")
                .unwrap()
                .as_js_string()
                .unwrap()
                .code_units(),
            &[0xd83d]
        );
        assert_eq!(
            JsValue::Array(vec![]).property("0").unwrap(),
            JsValue::Undefined
        );
        assert!(JsValue::Undefined.property("name").is_err());
    }

    #[test]
    fn lossless_private_marker_keys_remain_application_objects() {
        let text = r#"{"$serde_json::private::Number":"1e999","nested":{"$serde_json::private::RawValue":"\\ud83d"}}"#;
        let value = parse_value(text).unwrap();
        assert_eq!(stringify(&value).unwrap().unwrap(), text.as_bytes());
        assert!(value.is_object());
        assert!(value["nested"].is_object());
        for text in [r#""\u123""#, r#""\x20""#, "\"\n\"", r#"["\ud800",]"#] {
            assert!(parse_value(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn date_string_coercion_does_not_sign_positive_expanded_years() {
        for (year, prefix) in [
            (10000, "Sat Jan 01 10000"),
            (-1, "Fri Jan 01 -0001"),
            (0, "Sat Jan 01 0000"),
        ] {
            let date = JsValue::Date(Utc.with_ymd_and_hms(year, 1, 1, 0, 0, 0).unwrap());
            let expected = format!("{prefix} 00:00:00 GMT+0000 (Coordinated Universal Time)");
            assert_eq!(date.coerce_string().unwrap(), expected);
            assert_eq!(
                JsValue::Array(vec![date]).coerce_string().unwrap(),
                expected
            );
        }
    }
}
