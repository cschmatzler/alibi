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

pub use accessors::{auth_account_impl, auth_session_impl, auth_user_impl, auth_verification_impl};
pub use alibi_schema_registry::EntityRole;
pub use attributes::{AuthAttributes, named_fields, parse_auth_attributes, validate_core_fields};
pub use fields::{
    EntityField, additional_output, camel_case, has_field, is_auth_timestamp, is_known_field,
    is_option, optional_field,
};
pub use secondary::secondary_codec;
pub use writes::{Insert, SetField, generated_id, insert_values, update_statements};
