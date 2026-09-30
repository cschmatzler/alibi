use sea_orm::entity::prelude::*;

/// Better Auth's number columns use SQLite INTEGER affinity. SQLite may return
/// either an integer or a real for the same column, including large JS chain
/// IDs. PostgreSQL returns its INTEGER as i32. Retain the value as a JS Number
/// without requiring a different persisted column type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WalletChainId(pub f64);

impl From<f64> for WalletChainId {
    fn from(value: f64) -> Self {
        Self(value)
    }
}

impl From<WalletChainId> for sea_orm::Value {
    fn from(value: WalletChainId) -> Self {
        if value.0.fract() == 0.0 && value.0 >= i64::MIN as f64 && value.0 < i64::MAX as f64 {
            Self::BigInt(Some(value.0 as i64))
        } else {
            Self::Double(Some(value.0))
        }
    }
}

impl sea_orm::sea_query::Nullable for WalletChainId {
    fn null() -> sea_orm::Value {
        sea_orm::Value::Double(None)
    }
}

impl sea_orm::sea_query::ValueType for WalletChainId {
    fn try_from(value: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match value {
            sea_orm::Value::Double(Some(value)) => Ok(Self(value)),
            sea_orm::Value::BigInt(Some(value)) => Ok(Self(value as f64)),
            sea_orm::Value::Int(Some(value)) => Ok(Self(f64::from(value))),
            _ => Err(sea_orm::sea_query::ValueTypeErr),
        }
    }
    fn type_name() -> String {
        "WalletChainId".to_owned()
    }
    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::Double
    }
    fn column_type() -> sea_orm::sea_query::ColumnType {
        sea_orm::sea_query::ColumnType::Integer
    }
}

impl sea_orm::TryGetable for WalletChainId {
    fn try_get_by<I: sea_orm::ColIdx>(
        row: &sea_orm::QueryResult,
        index: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        f64::try_get_by(row, index)
            .map(Self)
            .or_else(|_| i64::try_get_by(row, index).map(|value| Self(value as f64)))
            .or_else(|_| i32::try_get_by(row, index).map(|value| Self(f64::from(value))))
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
