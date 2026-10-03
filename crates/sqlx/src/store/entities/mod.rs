//! Internal `SQLx` models for the built-in auth schema.

/// Declare a bundled plugin table model and its column mapping.
macro_rules! bundled_model {
    (
        table = $table:literal, primary_key = $primary:literal;
        $(#[$meta:meta])*
        pub struct Model {
            $( pub $field:ident : $ty:ty = $column:literal ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(sqlx::FromRow)]
        pub struct Model {
            $( #[sqlx(rename = $column)] pub $field: $ty, )*
        }

        impl $crate::model::SqlxModel for Model {
            const TABLE: &'static str = $table;
            const COLUMNS: &'static [$crate::model::ColumnDef] = &[
                $( $crate::model::ColumnDef {
                    name: $column,
                    kind: <$ty as $crate::value::SqlxValue>::KIND,
                }, )*
            ];
            const PRIMARY_KEY: &'static str = $primary;

            fn into_active(self) -> $crate::model::ActiveRow {
                let mut active = $crate::model::ActiveRow::new();
                $( active.unchanged($column, $crate::value::SqlxValue::into_sql_value(self.$field)); )*
                active
            }

            fn from_active(
                mut active: $crate::model::ActiveRow,
            ) -> better_auth_core::error::AuthResult<Self> {
                Ok(Self {
                    $( $field: <$ty as $crate::value::SqlxValue>::from_sql_value(
                        active.take($column).into_value().unwrap_or_else(<$ty as $crate::value::SqlxValue>::null),
                    ).map_err(|_error| better_auth_core::AuthError::internal(
                        concat!("Attribute ", stringify!($field), " is NotSet"),
                    ))?, )*
                })
            }
        }
    };
}

pub mod account;
pub mod api_key;
pub mod api_key_start;
pub mod device_code;
pub mod invitation;
pub mod jwk;
pub mod member;
pub mod organization;
pub mod organization_role;
pub mod passkey;
pub mod session;
pub mod team;
pub mod team_member;
pub mod two_factor;
pub mod user;
pub mod verification;
pub mod wallet_address;
