use alibi_core::WalletAddress;
use sea_orm::entity::prelude::*;

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

impl From<WalletChainId> for Value {
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    fn from(value: WalletChainId) -> Self {
        if value.0.fract() == 0.0 && value.0 >= i64::MIN as f64 && value.0 < i64::MAX as f64 {
            Self::BigInt(Some(value.0 as i64))
        } else {
            Self::Double(Some(value.0))
        }
    }
}

impl sea_orm::sea_query::Nullable for WalletChainId {
    fn null() -> Value {
        Value::Double(None)
    }
}

impl sea_orm::sea_query::ValueType for WalletChainId {
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    fn try_from(v: Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match v {
            Value::Double(Some(v)) => Ok(Self(v)),
            Value::BigInt(Some(v)) => Ok(Self(v as f64)),
            Value::Int(Some(v)) => Ok(Self(f64::from(v))),
            Value::Bool(_)
            | Value::TinyInt(_)
            | Value::SmallInt(_)
            | Value::Int(_)
            | Value::BigInt(_)
            | Value::TinyUnsigned(_)
            | Value::SmallUnsigned(_)
            | Value::Unsigned(_)
            | Value::BigUnsigned(_)
            | Value::Float(_)
            | Value::Double(_)
            | Value::String(_)
            | Value::Char(_)
            | Value::Bytes(_)
            | Value::Json(_)
            | Value::ChronoDate(_)
            | Value::ChronoTime(_)
            | Value::ChronoDateTime(_)
            | Value::ChronoDateTimeUtc(_)
            | Value::ChronoDateTimeLocal(_)
            | Value::ChronoDateTimeWithTimeZone(_)
            | Value::TimeDate(_)
            | Value::TimeTime(_)
            | Value::TimeDateTime(_)
            | Value::TimeDateTimeWithTimeZone(_)
            | Value::Uuid(_)
            | Value::Decimal(_)
            | Value::Enum(_)
            | Value::Array(..) => Err(sea_orm::sea_query::ValueTypeErr),
        }
    }
    fn type_name() -> String {
        "WalletChainId".to_owned()
    }
    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::Double
    }
    fn column_type() -> ColumnType {
        ColumnType::Integer
    }
}

impl sea_orm::TryGetable for WalletChainId {
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
    )]
    fn try_get_by<I: sea_orm::ColIdx>(res: &QueryResult, index: I) -> Result<Self, TryGetError> {
        f64::try_get_by(res, index)
            .map(Self)
            .or_else(|_| i64::try_get_by(res, index).map(|value| Self(value as f64)))
            .or_else(|_| i32::try_get_by(res, index).map(|value| Self(f64::from(value))))
    }
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "wallet_address")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub user_id: String,
    pub address: String,
    pub chain_id: WalletChainId,
    pub is_primary: bool,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for WalletAddress {
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
