use crate::pool::Engine;
use crate::value::{ColumnKind, SqlValue, SqlxValue, ValueTypeError};
use better_auth_core::{ApiKeyStartText, ApiKeyStartingCharacters, AuthError, AuthResult};
use sqlx::error::BoxDynError;
#[cfg(feature = "postgres")]
use sqlx::postgres::{PgTypeInfo, PgValueRef, Postgres};
#[cfg(feature = "sqlite")]
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
    pub(crate) fn prepare(value: ApiKeyStartingCharacters, backend: Engine) -> AuthResult<Self> {
        match value.storage_text() {
            ApiKeyStartText::Utf8(text) => Ok(Self {
                text,
                sqlite_bytes: None,
            }),
            ApiKeyStartText::Wtf8(bytes) if backend == Engine::Sqlite => Ok(Self::sqlite(bytes)),
            ApiKeyStartText::Wtf8(_) => Err(AuthError::internal(
                "UTF-16 API-key starting characters require SQLite storage",
            )),
        }
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

#[cfg(feature = "sqlite")]
impl Type<Sqlite> for ApiKeyStart {
    fn type_info() -> SqliteTypeInfo {
        <Vec<u8> as Type<Sqlite>>::type_info()
    }
    fn compatible(ty: &SqliteTypeInfo) -> bool {
        <Vec<u8> as Type<Sqlite>>::compatible(ty)
    }
}

#[cfg(feature = "sqlite")]
impl<'r> Decode<'r, Sqlite> for ApiKeyStart {
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, BoxDynError> {
        <Vec<u8> as Decode<'r, Sqlite>>::decode(value).map(Self::sqlite)
    }
}

#[cfg(feature = "postgres")]
impl Type<Postgres> for ApiKeyStart {
    fn type_info() -> PgTypeInfo {
        <String as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <String as Type<Postgres>>::compatible(ty)
    }
}

#[cfg(feature = "postgres")]
impl<'r> Decode<'r, Postgres> for ApiKeyStart {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        <String as Decode<'r, Postgres>>::decode(value).map(|text| Self {
            text,
            sqlite_bytes: None,
        })
    }
}
