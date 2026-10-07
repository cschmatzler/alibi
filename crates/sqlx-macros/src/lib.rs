//! Proc macros for the Alibi `SQLx` integration.
mod columns;
mod entities;
mod model;
mod roots;

use better_auth_entity_codegen::{self as codegen, EntityRole, Insert};
use columns::Column;
use columns::column_of;
use columns::columns;
use columns::physical;
use columns::table_attribute;
use entities::account_impl;
use entities::session_impl;
use entities::user_impl;
use entities::verification_impl;
use model::additional_fields;
use model::model_impl;
use proc_macro::TokenStream as ProcMacroTokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use roots::Roots;
use roots::resolve_roots;
use syn::{DeriveInput, FieldsNamed, LitStr, parse_macro_input};

fn try_generate_model(input: &DeriveInput) -> syn::Result<TokenStream> {
    let roots = resolve_roots();
    let table = table_attribute(input)?;
    let fields = codegen::named_fields(input)?;
    let columns = columns(input, fields)?;
    model_impl(&input.ident, &table, &columns, None, &roots)
}

fn try_generate_entity(input: &DeriveInput) -> syn::Result<TokenStream> {
    let mut roots = resolve_roots();
    let attributes = codegen::parse_auth_attributes(input, true)?;
    roots.id_generator = codegen::generated_id(&attributes, &roots.core);
    let fields = codegen::named_fields(input)?;
    codegen::validate_core_fields(input, attributes.role, fields)?;
    let columns = columns(input, fields)?;
    let entity_fields: Vec<codegen::EntityField> = columns
        .iter()
        .map(|column| codegen::EntityField {
            ident: column.ident.clone(),
            camel: column.camel.clone(),
            physical: column.renamed.then(|| column.physical.clone()),
        })
        .collect();
    let ident = &input.ident;
    let table = attributes.table.clone().unwrap_or_else(|| {
        match attributes.role {
            EntityRole::User => "users",
            EntityRole::Session => "sessions",
            EntityRole::Account => "accounts",
            EntityRole::Verification => "verifications",
        }
        .to_owned()
    });
    let model = model_impl(ident, &table, &columns, Some(attributes.role), &roots)?;
    let secondary = attributes.secondary_storage;
    let core_root = &roots.core;
    let role_impl = match attributes.role {
        EntityRole::User => {
            let auth = codegen::auth_user_impl(ident, fields, &entity_fields, secondary, core_root);
            let model = user_impl(ident, fields, &columns, &roots)?;
            quote! { #auth #model }
        }
        EntityRole::Session => {
            let auth =
                codegen::auth_session_impl(ident, fields, &entity_fields, secondary, core_root);
            let model = session_impl(ident, fields, &columns, &roots)?;
            quote! { #auth #model }
        }
        EntityRole::Account => {
            let auth = codegen::auth_account_impl(ident, &entity_fields, core_root);
            let model = account_impl(ident, fields, &columns, &roots)?;
            quote! { #auth #model }
        }
        EntityRole::Verification => {
            let auth = codegen::auth_verification_impl(ident, core_root);
            let model = verification_impl(ident, fields, &columns, &roots)?;
            quote! { #auth #model }
        }
    };
    Ok(quote! { #model #role_impl })
}

/// Derive macro that generates `Auth*` trait impls and `Sqlx*Model` impls
/// for a `SQLx` model.
///
/// # Usage
///
/// Annotate a struct deriving `sqlx::FromRow` with `#[derive(AuthEntity)]` and
/// `#[auth(role = "...")]` where role is one of `user`, `session`, `account`,
/// or `verification`. `table = "..."` names the physical table and defaults to
/// the bundled table for the role. Physical column names follow
/// `#[sqlx(rename = "...")]` and `#[sqlx(rename_all = "...")]`.
/// `id_generator = "path::to::function"` selects a String ID factory; the default
/// remains a UUID. Use `#[auth(column_type = "bpchar")]` on String fields mapped
/// to PostgreSQL `CHAR(n)` to retain typed parameters and indexed equality.
///
/// ```ignore
/// #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, AuthEntity)]
/// #[auth(role = "user", table = "users")]
/// pub struct User {
///     pub id: String,
///     // ... core fields ...
/// }
/// ```
///
/// # Extra fields
///
/// The struct may contain fields beyond the core set required by the auth
/// role. They are omitted from generated inserts, so the database default
/// applies. Every field type implements `SqlxValue`; override the inferred
/// column category with `#[auth(column_type = "text")]`.
#[proc_macro_derive(AuthEntity, attributes(auth))]
pub fn derive_auth_entity(input: ProcMacroTokenStream) -> ProcMacroTokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    try_generate_entity(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Derive macro that implements `SqlxModel` for a table-backed row type.
///
/// `#[auth(table = "...")]` names the physical table; the `id` field is the
/// primary key. Physical column names follow `#[sqlx(rename = "...")]` and
/// `#[sqlx(rename_all = "...")]`, and `#[auth(column_type = "...")]`
/// overrides a column's inferred category. The struct must also derive
/// `sqlx::FromRow`.
#[proc_macro_derive(SqlxModel, attributes(auth))]
pub fn derive_sqlx_model(input: ProcMacroTokenStream) -> ProcMacroTokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    try_generate_model(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
