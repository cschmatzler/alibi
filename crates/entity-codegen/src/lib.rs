//! Backend-neutral code generation shared by the `AuthEntity` derives.
//!
//! The `SeaORM` and `SQLx` derives both generate the `Auth*` entity trait
//! implementations, the secondary-storage snapshot codec and the declared
//! additional-field output here, so the wire-visible accessor behavior of an
//! application model is identical whichever backend persists it.
mod accessors;
mod attributes;
mod fields;
mod secondary;
mod writes;

pub use accessors::auth_account_impl;
pub use accessors::auth_session_impl;
pub use accessors::auth_user_impl;
pub use accessors::auth_verification_impl;
use alibi_schema_registry as registry;
pub use alibi_schema_registry::EntityRole;
pub use attributes::AuthAttributes;
pub use attributes::named_fields;
pub use attributes::parse_auth_attributes;
pub use attributes::validate_core_fields;
pub use fields::EntityField;
pub use fields::additional_output;
pub use fields::camel_case;
pub use fields::has_field;
pub use fields::is_auth_timestamp;
pub use fields::is_known_field;
pub use fields::is_option;
pub use fields::optional_field;
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
pub use secondary::secondary_codec;
use syn::{Data, DeriveInput, Fields, FieldsNamed, LitStr, Type};
pub use writes::Insert;
pub use writes::SetField;
pub use writes::generated_id;
pub use writes::insert_values;
pub use writes::update_statements;
