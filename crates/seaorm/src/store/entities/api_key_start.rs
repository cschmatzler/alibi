use better_auth_core::{ApiKeyStartingCharacters, AuthError, AuthResult};
use sea_orm::sea_query::{ArrayType, Nullable, ValueType, ValueTypeErr};
use sea_orm::{ColIdx, ColumnType, DbBackend, QueryResult, TryGetError, TryGetable, Value};

/// SQLite preserves Bun's WTF-8 TEXT binding; only this public substring is
/// decoded lossily. Other columns continue to require valid UTF-8.
#[derive(Clone, Debug, PartialEq)]
pub struct ApiKeyStart {
    text: String,
    sqlite_bytes: Option<Vec<u8>>,
}

impl ApiKeyStart {
    pub(crate) fn prepare(value: ApiKeyStartingCharacters, backend: DbBackend) -> AuthResult<Self> {
        if let Ok(text) = String::from_utf16(value.as_utf16()) {
            return Ok(Self {
                text,
                sqlite_bytes: None,
            });
        }
        if backend != DbBackend::Sqlite {
            return Err(AuthError::internal(
                "UTF-16 API-key starting characters require SQLite storage",
            ));
        }
        let mut bytes = Vec::new();
        for scalar in char::decode_utf16(value.as_utf16().iter().copied()) {
            match scalar {
                Ok(scalar) => {
                    bytes.extend_from_slice(scalar.encode_utf8(&mut [0_u8; 4]).as_bytes())
                }
                Err(error) => {
                    let [high, low] = error.unpaired_surrogate().to_be_bytes();
                    bytes.extend_from_slice(&[
                        0xe0 | (high >> 4),
                        0x80 | ((high & 0x0f) << 2) | (low >> 6),
                        0x80 | (low & 0x3f),
                    ]);
                }
            }
        }
        Ok(Self::sqlite(bytes))
    }

    fn sqlite(bytes: Vec<u8>) -> Self {
        Self {
            text: String::from_utf8_lossy(&bytes).into_owned(),
            sqlite_bytes: Some(bytes),
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.text
    }

    pub(crate) const fn requires_sqlite_cast(&self) -> bool {
        self.sqlite_bytes.is_some()
    }
}

impl From<ApiKeyStart> for Value {
    fn from(value: ApiKeyStart) -> Self {
        value.sqlite_bytes.map_or_else(
            || Self::String(Some(value.text)),
            |bytes| Self::Bytes(Some(bytes)),
        )
    }
}

impl Nullable for ApiKeyStart {
    fn null() -> Value {
        Value::String(None)
    }
}

impl ValueType for ApiKeyStart {
    fn try_from(value: Value) -> Result<Self, ValueTypeErr> {
        if let Value::Bytes(Some(bytes)) = value {
            return Ok(Self::sqlite(bytes));
        }
        <String as ValueType>::try_from(value).map(|text| Self {
            text,
            sqlite_bytes: None,
        })
    }
    fn type_name() -> String {
        "ApiKeyStart".into()
    }
    fn array_type() -> ArrayType {
        ArrayType::String
    }
    fn column_type() -> ColumnType {
        ColumnType::Text
    }
}

impl TryGetable for ApiKeyStart {
    fn try_get_by<I: ColIdx>(result: &QueryResult, index: I) -> Result<Self, TryGetError> {
        if result.try_as_sqlite_row().is_some() {
            Vec::<u8>::try_get_by(result, index).map(Self::sqlite)
        } else {
            String::try_get_by(result, index).map(|text| Self {
                text,
                sqlite_bytes: None,
            })
        }
    }
}
