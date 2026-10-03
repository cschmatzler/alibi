use crate::pool::SqlxBackend;
use crate::value::{ColumnKind, SqlValue, SqlxValue, ValueTypeError};
use better_auth_core::{ApiKeyStartingCharacters, AuthError, AuthResult};
use sqlx::error::BoxDynError;
use sqlx::postgres::{PgTypeInfo, PgValueRef, Postgres};
use sqlx::sqlite::{Sqlite, SqliteTypeInfo, SqliteValueRef};
use sqlx::{Decode, Type};

/// SQLite preserves Bun's WTF-8 TEXT binding; only this public substring is
/// decoded lossily. Other columns continue to require valid UTF-8.
#[derive(Clone, Debug, PartialEq)]
pub struct ApiKeyStart {
    text: String,
    sqlite_bytes: Option<Vec<u8>>,
}

impl ApiKeyStart {
    pub(crate) fn prepare(
        value: ApiKeyStartingCharacters,
        backend: SqlxBackend,
    ) -> AuthResult<Self> {
        if let Ok(text) = String::from_utf16(value.as_utf16()) {
            return Ok(Self {
                text,
                sqlite_bytes: None,
            });
        }
        if backend != SqlxBackend::Sqlite {
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

impl SqlxValue for ApiKeyStart {
    const KIND: ColumnKind = ColumnKind::Text;
    fn null() -> SqlValue {
        SqlValue::Text(None)
    }
    fn into_sql_value(self) -> SqlValue {
        self.sqlite_bytes.map_or_else(
            || SqlValue::Text(Some(self.text)),
            |bytes| SqlValue::Bytes(Some(bytes)),
        )
    }
    fn from_sql_value(value: SqlValue) -> Result<Self, ValueTypeError> {
        match value {
            SqlValue::Bytes(Some(bytes)) => Ok(Self::sqlite(bytes)),
            SqlValue::Text(Some(text)) => Ok(Self {
                text,
                sqlite_bytes: None,
            }),
            _ => Err(ValueTypeError),
        }
    }
}

impl Type<Sqlite> for ApiKeyStart {
    fn type_info() -> SqliteTypeInfo {
        <Vec<u8> as Type<Sqlite>>::type_info()
    }
    fn compatible(ty: &SqliteTypeInfo) -> bool {
        <Vec<u8> as Type<Sqlite>>::compatible(ty)
    }
}

impl<'r> Decode<'r, Sqlite> for ApiKeyStart {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, BoxDynError> {
        <Vec<u8> as Decode<'r, Sqlite>>::decode(value).map(Self::sqlite)
    }
}

impl Type<Postgres> for ApiKeyStart {
    fn type_info() -> PgTypeInfo {
        <String as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <String as Type<Postgres>>::compatible(ty)
    }
}

impl<'r> Decode<'r, Postgres> for ApiKeyStart {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        <String as Decode<'r, Postgres>>::decode(value).map(|text| Self {
            text,
            sqlite_bytes: None,
        })
    }
}
