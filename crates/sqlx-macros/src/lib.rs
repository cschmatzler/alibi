//! Proc macros for the Better Auth `SQLx` integration.

use better_auth_entity_codegen::{self as codegen, EntityRole};
use proc_macro::TokenStream as ProcMacroTokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use std::collections::HashMap;
use syn::{DeriveInput, FieldsNamed, LitStr, parse_macro_input};

fn found_crate_tokens(name: &str) -> Option<TokenStream> {
    match crate_name(name).ok()? {
        FoundCrate::Itself => {
            // Examples and integration tests link the crate externally.
            let ident = Ident::new(&name.replace('-', "_"), Span::call_site());
            Some(quote!(::#ident))
        }
        FoundCrate::Name(name) => {
            let ident = Ident::new(&name, Span::call_site());
            Some(quote!(::#ident))
        }
    }
}

fn resolve_roots() -> (TokenStream, TokenStream) {
    if let Some(better_auth_root) = found_crate_tokens("better-auth") {
        return (
            quote!(#better_auth_root::sqlx),
            quote!(#better_auth_root::__private_core),
        );
    }
    match crate_name("better-auth-sqlx") {
        Ok(FoundCrate::Itself) => (quote!(crate), quote!(crate::__private_core)),
        Ok(FoundCrate::Name(name)) => {
            let ident = Ident::new(&name, Span::call_site());
            (quote!(::#ident), quote!(::#ident::__private_core))
        }
        Err(_) => (
            syn::Error::new(
                Span::call_site(),
                "AuthEntity must be used through better_auth::sqlx with the `sqlx` feature enabled",
            )
            .to_compile_error(),
            quote!(::core::compile_error!("unreachable")),
        ),
    }
}

/// One model field with its physical column.
struct Column {
    ident: Ident,
    ty: syn::Type,
    camel: String,
    physical: String,
    renamed: bool,
    kind: Option<Ident>,
}

fn rename_all(input: &DeriveInput) -> syn::Result<Option<String>> {
    let mut rule = None;
    for attribute in input
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("sqlx"))
    {
        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename_all") {
                rule = Some(meta.value()?.parse::<LitStr>()?.value());
            } else {
                drop(
                    meta.value()
                        .and_then(syn::parse::ParseBuffer::parse::<syn::Expr>)
                        .ok(),
                );
            }
            Ok(())
        })?;
    }
    Ok(rule)
}

fn apply_rename_all(rule: &str, name: &str) -> syn::Result<String> {
    let words: Vec<&str> = name.split('_').filter(|word| !word.is_empty()).collect();
    let capitalized = |word: &str| {
        let mut letters = word.chars();
        letters.next().map_or_else(String::new, |first| {
            first.to_uppercase().chain(letters).collect()
        })
    };
    Ok(match rule {
        "snake_case" => name.to_owned(),
        "lowercase" => name.to_lowercase(),
        "UPPERCASE" => name.to_uppercase(),
        "SCREAMING_SNAKE_CASE" => name.to_uppercase(),
        "kebab-case" => name.replace('_', "-"),
        "camelCase" => words
            .iter()
            .enumerate()
            .map(|(index, word)| {
                if index == 0 {
                    (*word).to_owned()
                } else {
                    capitalized(word)
                }
            })
            .collect(),
        "PascalCase" => words.iter().map(|word| capitalized(word)).collect(),
        _ => {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("unsupported sqlx rename_all rule `{rule}`"),
            ));
        }
    })
}

fn columns(input: &DeriveInput, fields: &FieldsNamed) -> syn::Result<Vec<Column>> {
    let rule = rename_all(input)?;
    let mut columns = Vec::new();
    for field in &fields.named {
        let ident = field
            .ident
            .clone()
            .ok_or_else(|| syn::Error::new_spanned(field, "Expected a named field"))?;
        let text = ident.to_string();
        let text = text.trim_start_matches("r#").to_owned();
        let mut rename = None;
        for attribute in field
            .attrs
            .iter()
            .filter(|attribute| attribute.path().is_ident("sqlx"))
        {
            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("rename") {
                    rename = Some(meta.value()?.parse::<LitStr>()?.value());
                    Ok(())
                } else if meta.path.is_ident("skip")
                    || meta.path.is_ident("flatten")
                    || meta.path.is_ident("json")
                    || meta.path.is_ident("try_from")
                {
                    Err(meta.error(
                        "AuthEntity fields map one-to-one to columns; `skip`, `flatten`, `json` and `try_from` are unsupported",
                    ))
                } else {
                    drop(
                        meta.value()
                            .and_then(syn::parse::ParseBuffer::parse::<syn::Expr>)
                            .ok(),
                    );
                    Ok(())
                }
            })?;
        }
        let mut kind = None;
        for attribute in field
            .attrs
            .iter()
            .filter(|attribute| attribute.path().is_ident("auth"))
        {
            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("column_type") {
                    let value = meta.value()?.parse::<LitStr>()?;
                    let variant = match value.value().as_str() {
                        "text" => "Text",
                        "json" => "Json",
                        "double" => "Double",
                        "float" => "Float",
                        "boolean" => "Boolean",
                        "other" => "Other",
                        _ => {
                            return Err(syn::Error::new_spanned(
                                value,
                                "expected text, json, double, float, boolean or other",
                            ));
                        }
                    };
                    kind = Some(Ident::new(variant, Span::call_site()));
                    Ok(())
                } else {
                    Err(meta.error("expected `column_type = \"...\"`"))
                }
            })?;
        }
        let renamed = rename.is_some() || rule.is_some();
        let physical = match (rename, &rule) {
            (Some(rename), _) => rename,
            (None, Some(rule)) => apply_rename_all(rule, &text)?,
            (None, None) => text.clone(),
        };
        columns.push(Column {
            camel: codegen::camel_case(&ident),
            ident,
            ty: field.ty.clone(),
            physical,
            renamed,
            kind,
        });
    }
    Ok(columns)
}

struct Roots {
    sqlx: TokenStream,
    core: TokenStream,
}

fn generate_auth_entity(input: &DeriveInput) -> TokenStream {
    match try_generate(input) {
        Ok(tokens) => tokens,
        Err(error) => error.to_compile_error(),
    }
}

fn try_generate(input: &DeriveInput) -> syn::Result<TokenStream> {
    let (sqlx_root, core_root) = resolve_roots();
    let roots = Roots {
        sqlx: sqlx_root,
        core: core_root,
    };
    let attributes = codegen::parse_auth_attributes(input, true)?;
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
    let model = model_impl(ident, &table, &columns, &roots)?;
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
            let model = account_impl(ident, &columns, &roots)?;
            quote! { #auth #model }
        }
        EntityRole::Verification => {
            let auth = codegen::auth_verification_impl(ident, core_root);
            let model = verification_impl(ident, &columns, &roots)?;
            quote! { #auth #model }
        }
    };
    Ok(quote! { #model #role_impl })
}

fn column_of<'a>(columns: &'a [Column], name: &str) -> syn::Result<&'a Column> {
    columns
        .iter()
        .find(|column| column.ident == name)
        .ok_or_else(|| syn::Error::new(Span::call_site(), format!("missing auth field `{name}`")))
}

fn physical(columns: &[Column], name: &str) -> syn::Result<String> {
    column_of(columns, name).map(|column| column.physical.clone())
}

fn model_impl(
    ident: &Ident,
    table: &str,
    columns: &[Column],
    roots: &Roots,
) -> syn::Result<TokenStream> {
    let sqlx_root = &roots.sqlx;
    let core_root = &roots.core;
    let primary_key = physical(columns, "id")?;
    let definitions = columns.iter().map(|column| {
        let name = &column.physical;
        let ty = &column.ty;
        let kind = column.kind.as_ref().map_or_else(
            || quote! { <#ty as #sqlx_root::value::SqlxValue>::KIND },
            |kind| quote! { #sqlx_root::value::ColumnKind::#kind },
        );
        quote! { #sqlx_root::model::ColumnDef { name: #name, kind: #kind } }
    });
    let unchanged = columns.iter().map(|column| {
        let name = &column.physical;
        let field = &column.ident;
        quote! { active.unchanged(#name, #sqlx_root::value::SqlxValue::into_sql_value(self.#field)); }
    });
    let materialize = columns.iter().map(|column| {
        let name = &column.physical;
        let field = &column.ident;
        let ty = &column.ty;
        let text = field.to_string();
        let absent = if codegen::is_option(ty) {
            quote! { ::std::option::Option::None }
        } else {
            quote! {
                return Err(#core_root::AuthError::internal(concat!("Attribute ", #text, " is NotSet")))
            }
        };
        quote! {
            #field: match active.take(#name).into_value() {
                ::std::option::Option::Some(value) => <#ty as #sqlx_root::value::SqlxValue>::from_sql_value(value)
                    .map_err(|_error| #core_root::AuthError::internal(concat!("Attribute ", #text, " has an incompatible value")))?,
                ::std::option::Option::None => { #absent }
            },
        }
    });
    Ok(quote! {
        impl #sqlx_root::model::SqlxModel for #ident {
            const TABLE: &'static str = #table;
            const COLUMNS: &'static [#sqlx_root::model::ColumnDef] = &[#(#definitions),*];
            const PRIMARY_KEY: &'static str = #primary_key;

            fn into_active(self) -> #sqlx_root::model::ActiveRow {
                let mut active = #sqlx_root::model::ActiveRow::new();
                #(#unchanged)*
                active
            }

            fn from_active(mut active: #sqlx_root::model::ActiveRow) -> #core_root::AuthResult<Self> {
                Ok(Self {
                    #(#materialize)*
                })
            }
        }
    })
}

/// Configured additional-field bindings and staging, keyed by wire and physical names.
fn additional_fields(columns: &[Column], roots: &Roots) -> TokenStream {
    let sqlx_root = &roots.sqlx;
    let core_root = &roots.core;
    let mut bindings = Vec::new();
    let mut stages = Vec::new();
    for column in columns {
        let camel = &column.camel;
        let name = &column.physical;
        let field_ty = &column.ty;
        if column.renamed && name != camel {
            bindings.push(quote! {
                #name => (#name, #sqlx_root::session_fields::raw_value(value)?),
            });
        }
        let ty = quote!(#field_ty).to_string();
        let json_field = ty.contains("JsonMetadata");
        let optional_json = json_field && ty.contains("Option");
        let preparation = if optional_json {
            quote! { if let Some(value) = value { Some(#sqlx_root::json_metadata::prepare_metadata_value(value, backend)?) } else { None } }
        } else if json_field {
            quote! { #sqlx_root::json_metadata::prepare_metadata_value(value, backend)? }
        } else {
            quote!(value)
        };
        stages.push(quote! {
            #name => {
                let value = <#field_ty as #sqlx_root::value::SqlxValue>::from_sql_value(value)
                    .map_err(|_error| #core_root::AuthError::internal("field value cannot be represented by its model column"))?;
                active.set(#name, #sqlx_root::value::SqlxValue::into_sql_value(#preparation));
            }
        });
        bindings.push(quote! {
            #camel => (#name, #sqlx_root::session_fields::raw_value(value)?),
        });
    }
    quote! {
        fn additional_field_bindings(fields: &#core_root::field_policy::FieldValues, _backend: #sqlx_root::pool::SqlxBackend) -> #core_root::AuthResult<Vec<(&'static str, #sqlx_root::value::SqlValue)>> {
            let mut bindings = Vec::new();
            for (name, value) in fields {
                bindings.push(match fields.binding_name(name) {
                    #(#bindings)*
                    _ => return Err(#core_root::AuthError::internal("configured field has no model column")),
                });
            }
            Ok(bindings)
        }
        fn set_additional_field(active: &mut #sqlx_root::model::ActiveRow, column: &'static str, value: #sqlx_root::value::SqlValue, backend: #sqlx_root::pool::SqlxBackend) -> #core_root::AuthResult<()> {
            let _ = backend;
            match column {
                #(#stages)*
                _ => return Err(#core_root::AuthError::internal("configured field has no model column")),
            }
            Ok(())
        }
    }
}

/// A field value converted into the declared field type, as a model literal requires.
fn typed(column: &Column, value: &TokenStream, roots: &Roots) -> TokenStream {
    let ty = &column.ty;
    if codegen::is_auth_timestamp(&column.ident.to_string()) {
        let core_root = &roots.core;
        quote! { <#ty as #core_root::entity::AuthTimestamp>::from_utc(#value) }
    } else {
        quote! { { let value: #ty = ::std::convert::Into::into(#value); value } }
    }
}

/// The declared optional field type's `None`.
fn typed_none(ty: &syn::Type) -> TokenStream {
    quote! { { let value: #ty = ::std::option::Option::None; value } }
}

/// Emit staged values in model field order; fields without a value are omitted.
fn staged(
    columns: &[Column],
    values: &HashMap<&str, TokenStream>,
    roots: &Roots,
) -> Vec<TokenStream> {
    let sqlx_root = &roots.sqlx;
    columns
        .iter()
        .map(|column| {
            let name = &column.physical;
            match values.get(column.ident.to_string().as_str()) {
                Some(value) => {
                    let value = typed(column, value, roots);
                    quote! {
                        active.set(#name, #sqlx_root::value::SqlxValue::into_sql_value(#value));
                    }
                }
                None => quote! { active.not_set(#name); },
            }
        })
        .collect()
}

fn id_value(roots: &Roots) -> TokenStream {
    let sqlx_root = &roots.sqlx;
    let core_root = &roots.core;
    quote! {
        id.unwrap_or_else(|| #sqlx_root::value::SqlValue::Text(Some(#core_root::uuid::Uuid::new_v4().to_string())))
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep the generated SqlxUserModel implementation together as one quoted trait contract"
)]
fn user_impl(
    ident: &Ident,
    fields: &FieldsNamed,
    columns: &[Column],
    roots: &Roots,
) -> syn::Result<TokenStream> {
    let sqlx_root = &roots.sqlx;
    let core_root = &roots.core;
    let has = |name: &str| codegen::has_field(fields, name);
    let optional = |name: &str| codegen::optional_field(fields, name);
    let ty = |name: &str| column_of(columns, name).map(|column| column.ty.clone());

    let mut values: HashMap<&str, TokenStream> = HashMap::new();
    drop(values.insert("email", quote! { create_user.email }));
    drop(values.insert("name", quote! { create_user.name }));
    drop(values.insert("image", quote! { create_user.image }));
    drop(values.insert(
        "email_verified",
        quote! { create_user.email_verified.unwrap_or(false) },
    ));
    drop(values.insert(
        "created_at",
        quote! { create_user.created_at.unwrap_or(now) },
    ));
    drop(values.insert(
        "updated_at",
        quote! { create_user.updated_at.unwrap_or(now) },
    ));
    if has("username") {
        drop(values.insert("username", quote! { create_user.username }));
    }
    if has("display_username") {
        drop(values.insert("display_username", quote! { create_user.display_username }));
    }
    if has("two_factor_enabled") {
        drop(values.insert(
            "two_factor_enabled",
            if optional("two_factor_enabled") {
                quote! { create_user.two_factor_enabled }
            } else {
                quote! { create_user.two_factor_enabled.unwrap_or(false) }
            },
        ));
    }
    if has("role") {
        drop(values.insert("role", quote! { create_user.role }));
    }
    if has("banned") {
        drop(values.insert(
            "banned",
            if optional("banned") {
                quote! { create_user.banned }
            } else {
                quote! { create_user.banned.unwrap_or(false) }
            },
        ));
    }
    let mut none_fields = Vec::new();
    if has("ban_reason") {
        none_fields.push("ban_reason");
    }
    if has("ban_expires") {
        none_fields.push("ban_expires");
    }
    if has("metadata") {
        drop(values.insert(
            "metadata",
            quote! { create_user.metadata.unwrap_or(::serde_json::json!({})) },
        ));
    }
    for name in [
        "is_anonymous",
        "phone_number",
        "phone_number_verified",
        "last_login_method",
    ] {
        if has(name) {
            let field = Ident::new(name, Span::call_site());
            drop(values.insert(name, quote! { create_user.#field }));
        }
    }
    let id = id_value(roots);
    let id_column = physical(columns, "id")?;
    let mut new_active = staged(&without_id(columns), &values, roots);
    for (index, column) in without_id(columns).iter().enumerate() {
        if none_fields.iter().any(|name| column.ident == name) {
            let name = &column.physical;
            let value = typed_none(&column.ty);
            if let Some(slot) = new_active.get_mut(index) {
                *slot = quote! {
                    active.set(#name, #sqlx_root::value::SqlxValue::into_sql_value(#value));
                };
            }
        }
    }

    let set = |name: &str, value: TokenStream| -> syn::Result<TokenStream> {
        let field = column_of(columns, name)?;
        let column = &field.physical;
        let value = typed(field, &value, roots);
        Ok(quote! { active.set(#column, #sqlx_root::value::SqlxValue::into_sql_value(#value)); })
    };
    let clear = |name: &str| -> syn::Result<TokenStream> {
        let field = column_of(columns, name)?;
        let column = &field.physical;
        let value = typed_none(&field.ty);
        Ok(quote! { active.set(#column, #sqlx_root::value::SqlxValue::into_sql_value(#value)); })
    };
    let mut updates = Vec::new();
    for name in ["email", "name", "image"] {
        let field = Ident::new(name, Span::call_site());
        let assign = set(name, quote! { ::std::option::Option::Some(#field) })?;
        updates.push(quote! {
            if let ::std::option::Option::Some(#field) = update.#field { #assign }
        });
    }
    let assign = set("email_verified", quote! { email_verified })?;
    updates.push(quote! {
        if let ::std::option::Option::Some(email_verified) = update.email_verified { #assign }
    });
    for name in ["username", "display_username", "role"] {
        if has(name) {
            let field = Ident::new(name, Span::call_site());
            let assign = set(name, quote! { ::std::option::Option::Some(#field) })?;
            updates.push(quote! {
                if let ::std::option::Option::Some(#field) = update.#field { #assign }
            });
        }
    }
    if has("two_factor_enabled") {
        let assign = set("two_factor_enabled", quote! { two_factor_enabled })?;
        updates.push(quote! {
            if let ::std::option::Option::Some(two_factor_enabled) = update.two_factor_enabled { #assign }
        });
    }
    if has("metadata") {
        let assign = set("metadata", quote! { metadata })?;
        updates.push(quote! {
            if let ::std::option::Option::Some(metadata) = update.metadata { #assign }
        });
    }
    if has("banned") && has("ban_reason") && has("ban_expires") {
        let banned = set("banned", quote! { banned })?;
        let clear_reason = clear("ban_reason")?;
        let clear_expires = clear("ban_expires")?;
        let reason = set(
            "ban_reason",
            quote! { ::std::option::Option::Some(ban_reason) },
        )?;
        let expires = set("ban_expires", quote! { ban_expires })?;
        updates.push(quote! {
            if let ::std::option::Option::Some(banned) = update.banned {
                #banned
                if !banned {
                    #clear_reason
                    #clear_expires
                }
            }
            if update.banned != ::std::option::Option::Some(false) {
                if let ::std::option::Option::Some(ban_reason) = update.ban_reason { #reason }
                if let ::std::option::Option::Some(ban_expires) = update.ban_expires { #expires }
            }
        });
    } else if has("banned") {
        let banned = set("banned", quote! { banned })?;
        updates.push(quote! {
            if let ::std::option::Option::Some(banned) = update.banned { #banned }
        });
    }
    for name in ["is_anonymous", "phone_number_verified"] {
        if has(name) {
            let field = Ident::new(name, Span::call_site());
            let assign = set(name, quote! { ::std::option::Option::Some(value) })?;
            updates.push(quote! {
                if let ::std::option::Option::Some(value) = update.#field { #assign }
            });
        }
    }
    for name in ["phone_number", "last_login_method"] {
        if has(name) {
            let field = Ident::new(name, Span::call_site());
            let assign = set(name, quote! { value })?;
            updates.push(quote! {
                if let ::std::option::Option::Some(value) = update.#field { #assign }
            });
        }
    }
    let updated_at = set("updated_at", quote! { now })?;

    let prepare_json_metadata = if has("metadata") {
        let column = physical(columns, "metadata")?;
        let field_ty = ty("metadata")?;
        quote! {
            fn prepare_json_metadata(active: &mut #sqlx_root::model::ActiveRow, backend: #sqlx_root::pool::SqlxBackend) -> #core_root::AuthResult<()> {
                if let ::std::option::Option::Some(#sqlx_root::model::ActiveValue::Set(value)) = active.get(#column).cloned() {
                    let value = <#field_ty as #sqlx_root::value::SqlxValue>::from_sql_value(value)
                        .map_err(|_error| #core_root::AuthError::internal("Invalid JSON metadata value"))?;
                    active.set(#column, #sqlx_root::value::SqlxValue::into_sql_value(
                        #sqlx_root::json_metadata::prepare_metadata_value(value, backend)?
                    ));
                }
                Ok(())
            }
        }
    } else {
        quote! {}
    };
    let username_column = if has("username") {
        let column = physical(columns, "username")?;
        quote! { fn username_column() -> Option<&'static str> { Some(#column) } }
    } else {
        quote! {}
    };
    let phone_number_column = if has("phone_number") {
        let column = physical(columns, "phone_number")?;
        quote! { fn phone_number_column() -> Option<&'static str> { Some(#column) } }
    } else {
        quote! {}
    };
    let list_columns = columns.iter().map(|column| {
        let camel = &column.camel;
        let name = &column.physical;
        quote! { #camel => Some(#name), }
    });
    let email_column = physical(columns, "email")?;
    let name_column = physical(columns, "name")?;
    let created_at_column = physical(columns, "created_at")?;
    let additional = additional_fields(columns, roots);

    Ok(quote! {
        impl #sqlx_root::SqlxUserModel for #ident {
            #additional
            fn id_column() -> &'static str { #id_column }
            fn email_column() -> &'static str { #email_column }
            #username_column
            #phone_number_column
            #prepare_json_metadata
            fn name_column() -> &'static str { #name_column }
            fn created_at_column() -> &'static str { #created_at_column }
            fn list_users_column(field: &str) -> Option<&'static str> {
                match field { #(#list_columns)* _ => None }
            }
            fn parse_id(id: &str) -> #core_root::AuthResult<#sqlx_root::value::SqlValue> {
                Ok(#sqlx_root::value::SqlValue::Text(Some(id.to_string())))
            }

            fn new_active(
                id: ::std::option::Option<#sqlx_root::value::SqlValue>,
                create_user: #core_root::types::CreateUser,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> #sqlx_root::model::ActiveRow {
                let mut active = #sqlx_root::model::ActiveRow::new();
                active.set(#id_column, #id);
                #(#new_active)*
                active
            }

            fn apply_update(
                active: &mut #sqlx_root::model::ActiveRow,
                update: #core_root::types::UpdateUser,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) {
                #(#updates)*
                #updated_at
            }
        }
    })
}

fn without_id(columns: &[Column]) -> Vec<Column> {
    columns
        .iter()
        .filter(|column| column.ident != "id")
        .map(|column| Column {
            ident: column.ident.clone(),
            ty: column.ty.clone(),
            camel: column.camel.clone(),
            physical: column.physical.clone(),
            renamed: column.renamed,
            kind: column.kind.clone(),
        })
        .collect()
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep the generated SqlxSessionModel implementation together as one quoted trait contract"
)]
fn session_impl(
    ident: &Ident,
    fields: &FieldsNamed,
    columns: &[Column],
    roots: &Roots,
) -> syn::Result<TokenStream> {
    let sqlx_root = &roots.sqlx;
    let core_root = &roots.core;
    let has = |name: &str| codegen::has_field(fields, name);
    let mut values: HashMap<&str, TokenStream> = HashMap::new();
    drop(values.insert("user_id", quote! { create_session.user_id }));
    drop(values.insert("token", quote! { token }));
    drop(values.insert("expires_at", quote! { create_session.expires_at }));
    drop(values.insert("created_at", quote! { now }));
    drop(values.insert("updated_at", quote! { now }));
    drop(values.insert("ip_address", quote! { create_session.ip_address }));
    drop(values.insert("user_agent", quote! { create_session.user_agent }));
    drop(values.insert("active", quote! { true }));
    for name in [
        "impersonated_by",
        "active_organization_id",
        "active_team_id",
    ] {
        if has(name) {
            let field = Ident::new(name, Span::call_site());
            drop(values.insert(name, quote! { create_session.#field }));
        }
    }
    let id = id_value(roots);
    let id_column = physical(columns, "id")?;
    let new_active = staged(&without_id(columns), &values, roots);
    let column = |name: &str| physical(columns, name);
    let token_column = column("token")?;
    let user_id_column = column("user_id")?;
    let active_column = column("active")?;
    let expires_at_column = column("expires_at")?;
    let created_at_column = column("created_at")?;
    let updated_at_column = column("updated_at")?;
    let expires_at = typed(
        column_of(columns, "expires_at")?,
        &quote! { expires_at },
        roots,
    );
    let updated_at = typed(
        column_of(columns, "updated_at")?,
        &quote! { updated_at },
        roots,
    );
    let set_active_org = if has("active_organization_id") {
        let name = column("active_organization_id")?;
        let value = typed(
            column_of(columns, "active_organization_id")?,
            &quote! { organization_id },
            roots,
        );
        quote! {
            fn set_active_organization_id(
                active: &mut #sqlx_root::model::ActiveRow,
                organization_id: ::std::option::Option<::std::string::String>,
            ) {
                active.set(#name, #sqlx_root::value::SqlxValue::into_sql_value(#value));
            }
        }
    } else {
        quote! {
            fn set_active_organization_id(
                _active: &mut #sqlx_root::model::ActiveRow,
                _organization_id: ::std::option::Option<::std::string::String>,
            ) {
                // organization plugin not enabled — no-op
            }
        }
    };
    let set_active_team = if has("active_team_id") {
        let name = column("active_team_id")?;
        let value = typed(
            column_of(columns, "active_team_id")?,
            &quote! { team_id },
            roots,
        );
        quote! {
            fn set_active_team_id(
                active: &mut #sqlx_root::model::ActiveRow,
                team_id: ::std::option::Option<::std::string::String>,
            ) -> #core_root::AuthResult<()> {
                active.set(#name, #sqlx_root::value::SqlxValue::into_sql_value(#value));
                Ok(())
            }
        }
    } else {
        quote! {}
    };
    let additional = additional_fields(columns, roots);
    Ok(quote! {
        impl #sqlx_root::SqlxSessionModel for #ident {
            fn materialize_secondary(active: #sqlx_root::model::ActiveRow) -> #core_root::AuthResult<Self> {
                <Self as #sqlx_root::model::SqlxModel>::from_active(active)
            }
            #additional
            fn id_column() -> &'static str { #id_column }
            fn token_column() -> &'static str { #token_column }
            fn user_id_column() -> &'static str { #user_id_column }
            fn active_column() -> &'static str { #active_column }
            fn expires_at_column() -> &'static str { #expires_at_column }
            fn created_at_column() -> &'static str { #created_at_column }
            fn parse_id(id: &str) -> #core_root::AuthResult<#sqlx_root::value::SqlValue> {
                Ok(#sqlx_root::value::SqlValue::Text(Some(id.to_string())))
            }
            fn parse_user_id(user_id: &str) -> #core_root::AuthResult<#sqlx_root::value::SqlValue> {
                Ok(#sqlx_root::value::SqlValue::Text(Some(user_id.to_string())))
            }

            fn new_active(
                id: ::std::option::Option<#sqlx_root::value::SqlValue>,
                token: ::std::string::String,
                create_session: #core_root::types::CreateSession,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> #sqlx_root::model::ActiveRow {
                let mut active = #sqlx_root::model::ActiveRow::new();
                active.set(#id_column, #id);
                #(#new_active)*
                active
            }

            fn set_expires_at(
                active: &mut #sqlx_root::model::ActiveRow,
                expires_at: ::chrono::DateTime<::chrono::Utc>,
            ) {
                active.set(#expires_at_column, #sqlx_root::value::SqlxValue::into_sql_value(#expires_at));
            }

            fn set_updated_at(
                active: &mut #sqlx_root::model::ActiveRow,
                updated_at: ::chrono::DateTime<::chrono::Utc>,
            ) {
                active.set(#updated_at_column, #sqlx_root::value::SqlxValue::into_sql_value(#updated_at));
            }

            #set_active_org
            #set_active_team
        }
    })
}

fn account_impl(ident: &Ident, columns: &[Column], roots: &Roots) -> syn::Result<TokenStream> {
    let sqlx_root = &roots.sqlx;
    let core_root = &roots.core;
    let mut values: HashMap<&str, TokenStream> = HashMap::new();
    for name in [
        "account_id",
        "provider_id",
        "user_id",
        "access_token",
        "refresh_token",
        "id_token",
        "access_token_expires_at",
        "refresh_token_expires_at",
        "scope",
        "password",
    ] {
        let field = Ident::new(name, Span::call_site());
        drop(values.insert(name, quote! { create_account.#field }));
    }
    drop(values.insert("created_at", quote! { now }));
    drop(values.insert("updated_at", quote! { now }));
    let id = id_value(roots);
    let id_column = physical(columns, "id")?;
    let new_active = staged(&without_id(columns), &values, roots);
    let mut updates = Vec::new();
    for name in [
        "access_token",
        "refresh_token",
        "id_token",
        "access_token_expires_at",
        "refresh_token_expires_at",
        "scope",
        "password",
    ] {
        let field = Ident::new(name, Span::call_site());
        let definition = column_of(columns, name)?;
        let column = &definition.physical;
        let value = typed(
            definition,
            &quote! { ::std::option::Option::Some(#field) },
            roots,
        );
        updates.push(quote! {
            if let ::std::option::Option::Some(#field) = update.#field {
                active.set(#column, #sqlx_root::value::SqlxValue::into_sql_value(#value));
            }
        });
    }
    let column = |name: &str| physical(columns, name);
    let provider_id_column = column("provider_id")?;
    let account_id_column = column("account_id")?;
    let user_id_column = column("user_id")?;
    let created_at_column = column("created_at")?;
    let updated_at = typed(column_of(columns, "updated_at")?, &quote! { now }, roots);
    let updated_at_column = column("updated_at")?;
    let additional = additional_fields(columns, roots);
    Ok(quote! {
        impl #sqlx_root::SqlxAccountModel for #ident {
            #additional
            fn id_column() -> &'static str { #id_column }
            fn provider_id_column() -> &'static str { #provider_id_column }
            fn account_id_column() -> &'static str { #account_id_column }
            fn user_id_column() -> &'static str { #user_id_column }
            fn created_at_column() -> &'static str { #created_at_column }
            fn parse_id(id: &str) -> #core_root::AuthResult<#sqlx_root::value::SqlValue> {
                Ok(#sqlx_root::value::SqlValue::Text(Some(id.to_string())))
            }
            fn parse_user_id(user_id: &str) -> #core_root::AuthResult<#sqlx_root::value::SqlValue> {
                Ok(#sqlx_root::value::SqlValue::Text(Some(user_id.to_string())))
            }

            fn new_active(
                id: ::std::option::Option<#sqlx_root::value::SqlValue>,
                create_account: #core_root::types::CreateAccount,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> #sqlx_root::model::ActiveRow {
                let mut active = #sqlx_root::model::ActiveRow::new();
                active.set(#id_column, #id);
                #(#new_active)*
                active
            }

            fn apply_update(
                active: &mut #sqlx_root::model::ActiveRow,
                update: #core_root::types::UpdateAccount,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) {
                #(#updates)*
                active.set(#updated_at_column, #sqlx_root::value::SqlxValue::into_sql_value(#updated_at));
            }
        }
    })
}

fn verification_impl(ident: &Ident, columns: &[Column], roots: &Roots) -> syn::Result<TokenStream> {
    let sqlx_root = &roots.sqlx;
    let core_root = &roots.core;
    let mut values: HashMap<&str, TokenStream> = HashMap::new();
    drop(values.insert("identifier", quote! { verification.identifier }));
    drop(values.insert("value", quote! { verification.value }));
    drop(values.insert("expires_at", quote! { verification.expires_at }));
    drop(values.insert("created_at", quote! { now }));
    drop(values.insert("updated_at", quote! { now }));
    let id = id_value(roots);
    let id_column = physical(columns, "id")?;
    let new_active = staged(&without_id(columns), &values, roots);
    let column = |name: &str| physical(columns, name);
    let identifier_column = column("identifier")?;
    let value_column = column("value")?;
    let expires_at_column = column("expires_at")?;
    let created_at_column = column("created_at")?;
    let updated_at_column = column("updated_at")?;
    Ok(quote! {
        impl #sqlx_root::SqlxVerificationModel for #ident {
            fn id_column() -> &'static str { #id_column }
            fn identifier_column() -> &'static str { #identifier_column }
            fn value_column() -> &'static str { #value_column }
            fn expires_at_column() -> &'static str { #expires_at_column }
            fn created_at_column() -> &'static str { #created_at_column }
            fn updated_at_column() -> Option<&'static str> { Some(#updated_at_column) }
            fn parse_id(id: &str) -> #core_root::AuthResult<#sqlx_root::value::SqlValue> {
                Ok(#sqlx_root::value::SqlValue::Text(Some(id.to_string())))
            }

            fn new_active(
                id: ::std::option::Option<#sqlx_root::value::SqlValue>,
                verification: #core_root::types::CreateVerification,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> #sqlx_root::model::ActiveRow {
                let mut active = #sqlx_root::model::ActiveRow::new();
                active.set(#id_column, #id);
                #(#new_active)*
                active
            }
        }
    })
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
    generate_auth_entity(&input).into()
}
