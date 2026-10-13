use crate::value::{ColumnKind, SqlValue, SqlxValue, ValueTypeError};
use sqlx::error::BoxDynError;
#[cfg(feature = "postgres")]
use sqlx::postgres::{PgTypeInfo, PgValueRef, Postgres};
#[cfg(feature = "sqlite")]
use sqlx::sqlite::{Sqlite, SqliteTypeInfo, SqliteValueRef};
use sqlx::{Decode, Type, ValueRef};

/// Better Auth's number columns use SQLite INTEGER affinity.
///
/// SQLite may return either an integer or a real for the same column, including large JS chain
/// IDs. PostgreSQL returns its INTEGER as i32. Retain the value as a JS Number without requiring a
/// different persisted column type.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize)]
#[serde(transparent)]
pub struct Number(pub f64);

impl From<f64> for Number {
    fn from(value: f64) -> Self {
        Self(value)
    }
}

impl SqlxValue for Number {
    const KIND: ColumnKind = ColumnKind::Number;
    fn null() -> SqlValue {
        SqlValue::Double(None)
    }
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    fn into_sql_value(self) -> SqlValue {
        if self.0.fract() == 0.0 && self.0 >= i64::MIN as f64 && self.0 < i64::MAX as f64 {
            SqlValue::BigInt(Some(self.0 as i64))
        } else {
            SqlValue::Double(Some(self.0))
        }
    }
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    fn from_sql_value(value: SqlValue) -> Result<Self, ValueTypeError> {
        match value {
            SqlValue::Double(Some(value)) => Ok(Self(value)),
            SqlValue::BigInt(Some(value)) => Ok(Self(value as f64)),
            SqlValue::Int(Some(value)) => Ok(Self(f64::from(value))),
            _ => Err(ValueTypeError),
        }
    }
}

#[cfg(feature = "sqlite")]
impl Type<Sqlite> for Number {
    fn type_info() -> SqliteTypeInfo {
        <f64 as Type<Sqlite>>::type_info()
    }
    fn compatible(ty: &SqliteTypeInfo) -> bool {
        <f64 as Type<Sqlite>>::compatible(ty)
            || <i64 as Type<Sqlite>>::compatible(ty)
            || <i32 as Type<Sqlite>>::compatible(ty)
    }
}

#[cfg(feature = "sqlite")]
impl<'r> Decode<'r, Sqlite> for Number {
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    fn decode(value: SqliteValueRef<'r>) -> Result<Self, BoxDynError> {
        // Try f64, then i64, then i32, as the typed column decoders would.
        let ty = value.type_info().into_owned();
        if <f64 as Type<Sqlite>>::compatible(&ty) {
            <f64 as Decode<'r, Sqlite>>::decode(value).map(Self)
        } else if <i64 as Type<Sqlite>>::compatible(&ty) {
            <i64 as Decode<'r, Sqlite>>::decode(value).map(|value| Self(value as f64))
        } else {
            <i32 as Decode<'r, Sqlite>>::decode(value).map(|value| Self(f64::from(value)))
        }
    }
}

#[cfg(feature = "postgres")]
impl Type<Postgres> for Number {
    fn type_info() -> PgTypeInfo {
        <i32 as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <f64 as Type<Postgres>>::compatible(ty)
            || <i64 as Type<Postgres>>::compatible(ty)
            || <i32 as Type<Postgres>>::compatible(ty)
    }
}

#[cfg(feature = "postgres")]
impl<'r> Decode<'r, Postgres> for Number {
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let ty = value.type_info().into_owned();
        if <f64 as Type<Postgres>>::compatible(&ty) {
            <f64 as Decode<'r, Postgres>>::decode(value).map(Self)
        } else if <i64 as Type<Postgres>>::compatible(&ty) {
            <i64 as Decode<'r, Postgres>>::decode(value).map(|value| Self(value as f64))
        } else {
            <i32 as Decode<'r, Postgres>>::decode(value).map(|value| Self(f64::from(value)))
        }
    }
}

#[cfg(feature = "sqlite")]
impl sqlx::Encode<'_, Sqlite> for Number {
    fn encode_by_ref(
        &self,
        buffer: &mut sqlx::sqlite::SqliteArgumentsBuffer,
    ) -> Result<sqlx::encode::IsNull, BoxDynError> {
        <f64 as sqlx::Encode<'_, Sqlite>>::encode_by_ref(&self.0, buffer)
    }
}

#[cfg(feature = "postgres")]
impl sqlx::Encode<'_, Postgres> for Number {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::as_conversions,
        reason = "the finite, integral value is range-checked before encoding PostgreSQL int4"
    )]
    fn encode_by_ref(
        &self,
        buffer: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, BoxDynError> {
        if !self.0.is_finite()
            || self.0.fract() != 0.0
            || self.0 < f64::from(i32::MIN)
            || self.0 > f64::from(i32::MAX)
        {
            return Err("Better Auth PostgreSQL numbers must fit INTEGER".into());
        }
        <i32 as sqlx::Encode<'_, Postgres>>::encode(self.0 as i32, buffer)
    }
}
