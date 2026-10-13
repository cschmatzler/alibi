//! INTEGER decoding across PostgreSQL int4 and SQLite 64-bit storage.
use crate::value::ValueTypeError;
use crate::{ColumnKind, SqlValue, SqlxValue};
use sqlx::error::BoxDynError;
use sqlx::{Decode, Type, ValueRef};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct Integer(pub i64);

impl From<i64> for Integer {
    fn from(value: i64) -> Self {
        Self(value)
    }
}
impl SqlxValue for Integer {
    const KIND: ColumnKind = ColumnKind::BigInt;
    fn null() -> SqlValue {
        SqlValue::BigInt(None)
    }
    fn into_sql_value(self) -> SqlValue {
        SqlValue::BigInt(Some(self.0))
    }
    fn from_sql_value(value: SqlValue) -> Result<Self, ValueTypeError> {
        match value {
            SqlValue::BigInt(Some(value)) => Ok(Self(value)),
            SqlValue::Int(Some(value)) => Ok(Self(i64::from(value))),
            _ => Err(ValueTypeError),
        }
    }
}
#[cfg(feature = "sqlite")]
impl Type<sqlx::Sqlite> for Integer {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <i64 as Type<sqlx::Sqlite>>::type_info()
    }
    fn compatible(ty: &sqlx::sqlite::SqliteTypeInfo) -> bool {
        <i64 as Type<sqlx::Sqlite>>::compatible(ty)
    }
}
#[cfg(feature = "sqlite")]
impl<'r> Decode<'r, sqlx::Sqlite> for Integer {
    fn decode(value: sqlx::sqlite::SqliteValueRef<'r>) -> Result<Self, BoxDynError> {
        <i64 as Decode<'r, sqlx::Sqlite>>::decode(value).map(Self)
    }
}
#[cfg(feature = "postgres")]
impl Type<sqlx::Postgres> for Integer {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <i32 as Type<sqlx::Postgres>>::type_info()
    }
    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <i64 as Type<sqlx::Postgres>>::compatible(ty)
            || <i32 as Type<sqlx::Postgres>>::compatible(ty)
    }
}
#[cfg(feature = "postgres")]
impl<'r> Decode<'r, sqlx::Postgres> for Integer {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        if <i64 as Type<sqlx::Postgres>>::compatible(&value.type_info()) {
            <i64 as Decode<'r, sqlx::Postgres>>::decode(value).map(Self)
        } else {
            <i32 as Decode<'r, sqlx::Postgres>>::decode(value).map(|value| Self(i64::from(value)))
        }
    }
}
#[cfg(feature = "sqlite")]
impl sqlx::Encode<'_, sqlx::Sqlite> for Integer {
    fn encode_by_ref(
        &self,
        buffer: &mut sqlx::sqlite::SqliteArgumentsBuffer,
    ) -> Result<sqlx::encode::IsNull, BoxDynError> {
        <i64 as sqlx::Encode<'_, sqlx::Sqlite>>::encode_by_ref(&self.0, buffer)
    }
}
#[cfg(feature = "postgres")]
impl sqlx::Encode<'_, sqlx::Postgres> for Integer {
    fn encode_by_ref(
        &self,
        buffer: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, BoxDynError> {
        <i32 as sqlx::Encode<'_, sqlx::Postgres>>::encode(i32::try_from(self.0)?, buffer)
    }
}
