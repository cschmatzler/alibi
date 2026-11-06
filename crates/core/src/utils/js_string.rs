//! JavaScript strings retain UTF-16 code units, including isolated surrogates.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt,
    hash::{Hash, Hasher},
};

#[derive(Clone, Eq)]
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
    pub fn concat(&self, other: &Self) -> Self {
        let mut units = self.units.clone();
        units.extend_from_slice(&other.units);
        Self::from_code_units(units)
    }

    #[must_use]
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
        serializer.serialize_str(
            self.as_str()
                .ok_or_else(|| serde::ser::Error::custom("isolated UTF-16 surrogate"))?,
        )
    }
}
impl<'de> Deserialize<'de> for JsString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}
