//! Proc macros for the Alibi `SeaORM` integration.
mod entities;
mod fields;
mod roots;

use alibi_entity_codegen::{self as codegen, EntityRole};
use entities::{account_impl, session_impl, user_impl, verification_impl};
use fields::model_fields;
use proc_macro::TokenStream as ProcMacroTokenStream;
use proc_macro2::TokenStream;
use quote::quote;
use roots::resolve_roots;
use syn::{DeriveInput, parse_macro_input};

fn try_generate(input: &DeriveInput) -> syn::Result<TokenStream> {
    let mut roots = resolve_roots();
    let attributes = codegen::parse_auth_attributes(input, false)?;
    roots.id_generator = codegen::generated_id(&attributes, &roots.core);
    let fields = codegen::named_fields(input)?;
    codegen::validate_core_fields(input, attributes.role, fields)?;
    let model_fields = model_fields(fields)?;
    let entity_fields: Vec<codegen::EntityField> = model_fields
        .iter()
        .map(|field| codegen::EntityField {
            ident: field.ident.clone(),
            camel: field.camel.clone(),
            physical: field.physical.clone(),
        })
        .collect();
    let ident = &input.ident;
    let secondary = attributes.secondary_storage;
    let core_root = &roots.core;
    Ok(match attributes.role {
        EntityRole::User => {
            let auth = codegen::auth_user_impl(ident, fields, &entity_fields, secondary, core_root);
            let model = user_impl(ident, fields, &model_fields, &roots);
            quote! { #auth #model }
        }
        EntityRole::Session => {
            let auth =
                codegen::auth_session_impl(ident, fields, &entity_fields, secondary, core_root);
            let model = session_impl(ident, fields, &model_fields, &roots);
            quote! { #auth #model }
        }
        EntityRole::Account => {
            let auth = codegen::auth_account_impl(ident, &entity_fields, core_root);
            let model = account_impl(ident, fields, &model_fields, &roots);
            quote! { #auth #model }
        }
        EntityRole::Verification => {
            let auth = codegen::auth_verification_impl(ident, core_root);
            let model = verification_impl(ident, fields, &roots);
            quote! { #auth #model }
        }
    })
}

/// Derive macro that generates `Auth*` trait impls and `SeaOrm*Model` impls
/// for a `SeaORM` entity.
///
/// # Usage
///
/// Annotate a `SeaORM` `Model` struct with `#[derive(AuthEntity)]` and
/// `#[auth(role = "...")]` where role is one of `user`, `session`, `account`,
/// or `verification`. `id_generator = "path::to::function"` selects a String ID
/// factory; the default remains a UUID.
///
/// ```ignore
/// #[derive(DeriveEntityModel, AuthEntity)]
/// #[auth(role = "user")]
/// #[sea_orm(table_name = "users")]
/// pub struct Model {
///     #[sea_orm(primary_key, auto_increment = false)]
///     pub id: String,
///     // ... core fields ...
/// }
/// ```
///
/// # Extra fields
///
/// The struct may contain fields beyond the core set required by the auth
/// role. They are set to `ActiveValue::NotSet` in the generated
/// `new_active()`, so use database defaults or
/// `ActiveModelBehavior::before_save` to populate them.
#[proc_macro_derive(AuthEntity, attributes(auth))]
pub fn derive_auth_entity(input: ProcMacroTokenStream) -> ProcMacroTokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    try_generate(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
