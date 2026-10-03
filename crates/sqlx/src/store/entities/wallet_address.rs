use crate::value::{ColumnKind, SqlValue, SqlxValue, ValueTypeError};
use chrono::{DateTime, Utc};
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
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WalletChainId(pub f64);

impl From<f64> for WalletChainId {
    fn from(value: f64) -> Self {
        Self(value)
    }
}

impl SqlxValue for WalletChainId {
    const KIND: ColumnKind = ColumnKind::Other;
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
impl Type<Sqlite> for WalletChainId {
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
impl<'r> Decode<'r, Sqlite> for WalletChainId {
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
impl Type<Postgres> for WalletChainId {
    fn type_info() -> PgTypeInfo {
        <f64 as Type<Postgres>>::type_info()
    }
    fn compatible(ty: &PgTypeInfo) -> bool {
        <f64 as Type<Postgres>>::compatible(ty)
            || <i64 as Type<Postgres>>::compatible(ty)
            || <i32 as Type<Postgres>>::compatible(ty)
    }
}

#[cfg(feature = "postgres")]
impl<'r> Decode<'r, Postgres> for WalletChainId {
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

#[derive(Clone, Debug, PartialEq, sqlx::FromRow, crate::SqlxModel)]
#[auth(table = "wallet_address")]
pub struct Model {
    pub id: String,
    pub user_id: String,
    pub address: String,
    pub chain_id: WalletChainId,
    pub is_primary: bool,
    pub created_at: DateTime<Utc>,
}

impl From<Model> for better_auth_core::WalletAddress {
    fn from(row: Model) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            address: row.address,
            chain_id: row.chain_id.0,
            is_primary: row.is_primary,
            created_at: row.created_at,
        }
    }
}
