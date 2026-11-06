//! JavaScript strings retain UTF-16 code units, including isolated surrogates.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt,
    hash::{Hash, Hasher},
};

#[derive(Clone, Default, Eq)]
pub struct JsString {
    units: Vec<u16>,
    utf8: Option<String>,
}

impl JsString {
    #[must_use]
    pub fn from_code_units(units: impl Into<Vec<u16>>) -> Self {
        let units = units.into();
        let utf8 = String::from_utf16(&units).ok();
        Self { units, utf8 }
    }

    #[must_use]
    pub fn code_units(&self) -> &[u16] {
        &self.units
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        self.utf8.as_deref()
    }

    pub fn to_utf8(&self) -> Result<String, std::string::FromUtf16Error> {
        String::from_utf16(&self.units)
    }

    /// JavaScript runtime UTF-8 binding conversion (USVString). Only adapters
    /// may use this at an actual database/protocol binding, after observers.
    #[must_use]
    pub fn to_utf8_binding(&self) -> String {
        String::from_utf16_lossy(&self.units)
    }

    /// Explicit projection for a pre-existing ordinary UTF-8 string contract.
    pub fn require_str(&self) -> crate::AuthResult<&str> {
        self.as_str().ok_or_else(|| {
            crate::AuthError::bad_request("String contains an isolated UTF-16 surrogate")
        })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.units.len()
    }

    #[must_use]
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.units
            .iter()
            .copied()
            .take(prefix.encode_utf16().count())
            .eq(prefix.encode_utf16())
    }

    #[must_use]
    pub fn trim_matches(&self, predicate: impl Fn(char) -> bool) -> Self {
        let mut units = self.units.as_slice();
        while units
            .first()
            .is_some_and(|unit| char::from_u32(u32::from(*unit)).is_some_and(&predicate))
        {
            units = &units[1..];
        }
        while units
            .last()
            .is_some_and(|unit| char::from_u32(u32::from(*unit)).is_some_and(&predicate))
        {
            units = &units[..units.len() - 1];
        }
        Self::from_code_units(units.to_vec())
    }

    #[must_use]
    pub fn to_lowercase(&self) -> Self {
        let mut units = Vec::new();
        let mut run = String::new();
        for value in char::decode_utf16(self.units.iter().copied()) {
            match value {
                Ok(value) => run.push(value),
                Err(value) => {
                    units.extend(run.to_lowercase().encode_utf16());
                    run.clear();
                    units.push(value.unpaired_surrogate());
                }
            }
        }
        units.extend(run.to_lowercase().encode_utf16());
        Self::from_code_units(units)
    }

    #[must_use]
    pub fn eq_ignore_str(&self, other: &str) -> bool {
        self.to_lowercase()
            .units
            .iter()
            .copied()
            .eq(other.to_lowercase().encode_utf16())
    }
    #[must_use]
    pub fn eq_ignore_ascii_case(&self, other: &Self) -> bool {
        self.units
            .iter()
            .map(|unit| {
                if (65..=90).contains(unit) {
                    unit + 32
                } else {
                    *unit
                }
            })
            .eq(other.units.iter().map(|unit| {
                if (65..=90).contains(unit) {
                    unit + 32
                } else {
                    *unit
                }
            }))
    }

    #[must_use]
    pub fn concat(&self, other: &Self) -> Self {
        let mut units = self.units.clone();
        units.extend_from_slice(&other.units);
        Self::from_code_units(units)
    }

    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        other.is_empty()
            || self
                .units
                .windows(other.len())
                .any(|window| window == other.code_units())
    }
    pub fn before(&self, delimiter: u16) -> Self {
        Self::from_code_units(
            self.units
                .iter()
                .copied()
                .take_while(|unit| *unit != delimiter)
                .collect::<Vec<_>>(),
        )
    }
    pub fn code_unit_at(&self, index: usize) -> Option<u16> {
        self.units.get(index).copied()
    }
}

impl From<String> for JsString {
    fn from(value: String) -> Self {
        Self {
            units: value.encode_utf16().collect(),
            utf8: Some(value),
        }
    }
}
impl From<&str> for JsString {
    fn from(value: &str) -> Self {
        value.to_owned().into()
    }
}
impl From<&JsString> for JsString {
    fn from(value: &JsString) -> Self {
        value.clone()
    }
}
impl From<std::borrow::Cow<'_, str>> for JsString {
    fn from(value: std::borrow::Cow<'_, str>) -> Self {
        value.into_owned().into()
    }
}
impl From<&String> for JsString {
    fn from(value: &String) -> Self {
        value.as_str().into()
    }
}
impl PartialEq for JsString {
    fn eq(&self, other: &Self) -> bool {
        self.units == other.units
    }
}
impl PartialEq<str> for JsString {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == Some(other)
    }
}
impl PartialEq<&str> for JsString {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}
impl Hash for JsString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if let Some(value) = self.as_str() {
            value.hash(state);
        } else {
            self.units.hash(state);
        }
    }
}
// Unlike Borrow<str>, this does not assert that every key has a UTF-8 view.
// Hashes of well-formed keys match str; ill-formed keys can only match JsString.
impl indexmap::Equivalent<JsString> for str {
    fn equivalent(&self, key: &JsString) -> bool {
        key == self
    }
}
impl indexmap::Equivalent<JsString> for String {
    fn equivalent(&self, key: &JsString) -> bool {
        key == self.as_str()
    }
}
impl fmt::Debug for JsString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(value) => value.fmt(f),
            None => f.debug_tuple("JsString").field(&self.units).finish(),
        }
    }
}
impl Serialize for JsString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_newtype_struct(
            super::native_serializer::UTF16_PROTOCOL,
            &Utf16Payload(self),
        )
    }
}
struct Utf16Payload<'a>(&'a JsString);
impl Serialize for Utf16Payload<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(
                self.0
                    .as_str()
                    .ok_or_else(|| serde::ser::Error::custom("isolated UTF-16 surrogate"))?,
            )
        } else {
            self.0.code_units().serialize(serializer)
        }
    }
}
impl<'de> Deserialize<'de> for JsString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}
