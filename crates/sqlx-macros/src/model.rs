use crate::columns::{Column, physical};
use crate::roots::Roots;
use alibi_entity_codegen::{self as codegen, EntityRole};
use proc_macro2::{Ident, TokenStream};
use quote::quote;

pub(crate) fn model_impl(
    ident: &Ident,
    table: &str,
    columns: &[Column],
    role: Option<EntityRole>,
    roots: &Roots,
) -> syn::Result<TokenStream> {
    let verification_column = if matches!(role, Some(EntityRole::User)) {
        let name = physical(columns, "email_verified")?;
        quote! { ::std::option::Option::Some(#name) }
    } else {
        quote! { ::std::option::Option::None }
    };
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
    let field_columns = columns.iter().map(|column| {
        let field = column.ident.to_string();
        let physical = &column.physical;
        quote! { (#field, #physical) }
    });
    let names = columns.iter().map(|column| &column.physical);
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
            const COLUMN_NAMES: &'static [&'static str] = &[#(#names),*];
            const FIELD_COLUMNS: &'static [(&'static str, &'static str)] = &[#(#field_columns),*];
            const PRIMARY_KEY: &'static str = #primary_key;
            const PROVIDER_VERIFICATION_COLUMN: ::std::option::Option<&'static str> = #verification_column;

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
pub(crate) fn additional_fields(columns: &[Column], roots: &Roots) -> TokenStream {
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
                #name => (#name, #sqlx_root::additional_fields::raw_value(value)?),
            });
        }
        stages.push(quote! {
            #name => {
                let value = if backend == #sqlx_root::pool::Engine::Postgres
                    && matches!(<Self as #sqlx_root::model::SqlxModel>::column_kind(#name), #sqlx_root::value::ColumnKind::Text | #sqlx_root::value::ColumnKind::Json)
                    && <#field_ty as #sqlx_root::value::SqlxValue>::KIND == #sqlx_root::value::ColumnKind::Json
                    && matches!(value, #sqlx_root::value::SqlValue::Text(None))
                {
                    <#field_ty as #sqlx_root::value::SqlxValue>::null()
                } else {
                    value
                };
                let value = <#field_ty as #sqlx_root::value::SqlxValue>::from_sql_value(value)
                    .map_err(|_error| #core_root::AuthError::internal("field value cannot be represented by its model column"))?;
                let value = if backend == #sqlx_root::pool::Engine::Postgres
                    && matches!(<Self as #sqlx_root::model::SqlxModel>::column_kind(#name), #sqlx_root::value::ColumnKind::Text | #sqlx_root::value::ColumnKind::Json)
                    && <#field_ty as #sqlx_root::value::SqlxValue>::KIND == #sqlx_root::value::ColumnKind::Json
                {
                    value
                } else {
                    #sqlx_root::value::SqlxValue::prepare(value, backend)?
                };
                active.set(#name, #sqlx_root::value::SqlxValue::into_sql_value(value));
            }
        });
        bindings.push(quote! {
            #camel => (#name, #sqlx_root::additional_fields::raw_value(value)?),
        });
    }
    quote! {
        fn additional_field_bindings(fields: &#core_root::field_policy::FieldValues, _backend: #sqlx_root::pool::Engine) -> #core_root::AuthResult<Vec<(&'static str, #core_root::store::adapter::RawFieldValue)>> {
            let mut bindings = Vec::new();
            for (name, value) in fields {
                if value.is_undefined() { continue; }
                bindings.push(match fields.binding_name(name) {
                    #(#bindings)*
                    _ => return Err(#core_root::AuthError::internal("configured field has no model column")),
                });
            }
            Ok(bindings)
        }
        fn set_additional_field(active: &mut #sqlx_root::model::ActiveRow, column: &'static str, value: #sqlx_root::value::SqlValue, backend: #sqlx_root::pool::Engine) -> #core_root::AuthResult<()> {
            match column {
                #(#stages)*
                _ => return Err(#core_root::AuthError::internal("configured field has no model column")),
            }
            Ok(())
        }
    }
}

pub(crate) fn adapter_output(
    fields: &[Column],
    role: codegen::EntityRole,
    roots: &Roots,
) -> TokenStream {
    let core = &roots.core;
    let adapter = &roots.sqlx;
    let mut values = Vec::new();
    for field in fields {
        let name = &field.ident;
        if codegen::is_known_field(role, name)
            && !(role == codegen::EntityRole::User
                && (name == "username" || name == "display_username"))
        {
            continue;
        }
        let wire = &field.camel;
        let physical = &field.physical;
        let ty = &field.ty;

        let json = quote! { <#ty as #adapter::value::SqlxValue>::KIND == #adapter::value::ColumnKind::Json };
        let bound = quote! { #adapter::value::SqlxValue::into_sql_value(self.#name.clone()) };
        values.push(quote! {
            let value = if #json {
                #adapter::additional_fields::physical_json_value(#bound, exact.contains(#wire) || exact.contains(#physical))?
            } else {
                #core::utils::json::to_js_value(&self.#name)?
            };
            _ = values.insert(#wire.into(), value.clone());
            if #physical != #wire { _ = values.insert(#physical.into(), value); }
        });
    }
    quote! {
        fn adapter_js_fields(&self, exact: &::std::collections::BTreeSet<String>) -> #core::AuthResult<#core::utils::json::JsObject> {
            let mut values = #core::utils::json::JsObject::new();
            #(#values)*
            Ok(values)
        }
    }
}
