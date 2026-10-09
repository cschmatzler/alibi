use crate::columns::{Column, column_of, physical};
use crate::model::additional_fields;
use crate::roots::Roots;
use alibi_entity_codegen::{self as codegen, EntityRole, Insert};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::FieldsNamed;

/// `active.set(column, value)` with `value` converted into the declared field
/// type, so the staged `SqlValue` variant always matches the column.
pub(crate) fn set_field(
    columns: &[Column],
    roots: &Roots,
) -> impl Fn(&Ident, &Insert) -> TokenStream {
    let sqlx_root = roots.sqlx.clone();
    let core_root = roots.core.clone();
    move |field, insert| {
        let Ok(column) = column_of(columns, &field.to_string()) else {
            // `update_statements` only names fields the role validated.
            return quote! {};
        };
        let name = &column.physical;
        let ty = &column.ty;
        let value = match insert {
            // Auth clocks arrive as UTC; the model column decides the wire type.
            Insert::Value(expr) if codegen::is_auth_timestamp(&field.to_string()) => {
                quote! { <#ty as #core_root::entity::AuthTimestamp>::from_utc(#expr) }
            }
            Insert::Value(expr) => {
                quote! { { let value: #ty = ::std::convert::Into::into(#expr); value } }
            }
            Insert::Null | Insert::Default => {
                quote! { { let value: #ty = ::std::option::Option::None; value } }
            }
        };
        quote! { active.set(#name, #sqlx_root::value::SqlxValue::into_sql_value(#value)); }
    }
}

/// The `new_active` body: the identifier, then every other column in model
/// order, staged or left to its database default.
pub(crate) fn new_active(
    role: EntityRole,
    fields: &FieldsNamed,
    columns: &[Column],
    roots: &Roots,
) -> syn::Result<TokenStream> {
    let sqlx_root = &roots.sqlx;
    let id_column = physical(columns, "id")?;
    let generated_id = &roots.id_generator;
    let set = set_field(columns, roots);
    let staged = codegen::insert_values(role, fields)
        .into_iter()
        .map(|(field, insert)| match insert {
            Insert::Default => {
                let name = physical(columns, &field.to_string())?;
                Ok(quote! { active.not_set(#name); })
            }
            insert => Ok(set(&field, &insert)),
        })
        .collect::<syn::Result<Vec<_>>>()?;
    Ok(quote! {
        let mut active = #sqlx_root::model::ActiveRow::new();
        active.set(#id_column, id.unwrap_or_else(|| {
            #sqlx_root::value::SqlValue::Text(Some(#generated_id))
        }));
        #(#staged)*
        active
    })
}

pub(crate) fn user_impl(
    ident: &Ident,
    fields: &FieldsNamed,
    columns: &[Column],
    roots: &Roots,
) -> syn::Result<TokenStream> {
    let sqlx_root = &roots.sqlx;
    let core_root = &roots.core;
    let has = |name: &str| codegen::has_field(fields, name);
    let column = |name: &str| physical(columns, name);
    let new_active = new_active(EntityRole::User, fields, columns, roots)?;
    let updates = codegen::update_statements(EntityRole::User, fields, &set_field(columns, roots));
    let prepare_json_metadata = if has("metadata") {
        let metadata = column("metadata")?;
        let field_ty = &column_of(columns, "metadata")?.ty;
        quote! {
            fn prepare_json_metadata(active: &mut #sqlx_root::model::ActiveRow, backend: #sqlx_root::pool::Engine) -> #core_root::AuthResult<()> {
                if let ::std::option::Option::Some(#sqlx_root::model::ActiveValue::Set(value)) = active.get(#metadata).cloned() {
                    let value = <#field_ty as #sqlx_root::value::SqlxValue>::from_sql_value(value)
                        .map_err(|_error| #core_root::AuthError::internal("Invalid JSON metadata value"))?;
                    active.set(#metadata, #sqlx_root::value::SqlxValue::into_sql_value(
                        #sqlx_root::value::SqlxValue::prepare(value, backend)?
                    ));
                }
                Ok(())
            }
        }
    } else {
        quote! {}
    };
    let username_column = if has("username") {
        let name = column("username")?;
        quote! { fn username_column() -> Option<&'static str> { Some(#name) } }
    } else {
        quote! {}
    };
    let phone_number_column = if has("phone_number") {
        let name = column("phone_number")?;
        quote! { fn phone_number_column() -> Option<&'static str> { Some(#name) } }
    } else {
        quote! {}
    };
    let list_columns = columns.iter().map(|column| {
        let camel = &column.camel;
        let name = &column.physical;
        quote! { #camel => Some(#name), }
    });
    let id_column = column("id")?;
    let email_column = column("email")?;
    let name_column = column("name")?;
    let created_at_column = column("created_at")?;
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
                Ok(<Self as #sqlx_root::model::SqlxModel>::column_value(
                    <Self as #sqlx_root::model::SqlxModel>::PRIMARY_KEY,
                    #sqlx_root::value::SqlValue::Text(Some(id.to_string()))))
            }

            fn new_active(
                id: ::std::option::Option<#sqlx_root::value::SqlValue>,
                create_user: #core_root::types::CreateUser,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> #sqlx_root::model::ActiveRow {
                #new_active
            }

            fn apply_update(
                active: &mut #sqlx_root::model::ActiveRow,
                update: #core_root::types::UpdateUser,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) {
                #updates
            }
        }
    })
}

pub(crate) fn session_impl(
    ident: &Ident,
    fields: &FieldsNamed,
    columns: &[Column],
    roots: &Roots,
) -> syn::Result<TokenStream> {
    let sqlx_root = &roots.sqlx;
    let core_root = &roots.core;
    let has = |name: &str| codegen::has_field(fields, name);
    let column = |name: &str| physical(columns, name);
    let new_active = new_active(EntityRole::Session, fields, columns, roots)?;
    let set = set_field(columns, roots);
    let id_column = column("id")?;
    let token_column = column("token")?;
    let user_id_column = column("user_id")?;
    let active_column = column("active")?;
    let expires_at_column = column("expires_at")?;
    let created_at_column = column("created_at")?;
    let set_expires_at = set(
        &Ident::new("expires_at", Span::call_site()),
        &Insert::Value(quote! { expires_at }),
    );
    let set_updated_at = set(
        &Ident::new("updated_at", Span::call_site()),
        &Insert::Value(quote! { updated_at }),
    );
    let set_active_org = if has("active_organization_id") {
        let assign = set(
            &Ident::new("active_organization_id", Span::call_site()),
            &Insert::Value(quote! { organization_id }),
        );
        quote! {
            fn set_active_organization_id(
                active: &mut #sqlx_root::model::ActiveRow,
                organization_id: ::std::option::Option<::std::string::String>,
            ) {
                #assign
            }
        }
    } else {
        quote! {
            fn set_active_organization_id(
                _active: &mut #sqlx_root::model::ActiveRow,
                _organization_id: ::std::option::Option<::std::string::String>,
            ) {
                // The organization plugin's column is not declared.
            }
        }
    };
    let set_active_team = if has("active_team_id") {
        let assign = set(
            &Ident::new("active_team_id", Span::call_site()),
            &Insert::Value(quote! { team_id }),
        );
        quote! {
            fn set_active_team_id(
                active: &mut #sqlx_root::model::ActiveRow,
                team_id: ::std::option::Option<::std::string::String>,
            ) -> #core_root::AuthResult<()> {
                #assign
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
                Ok(<Self as #sqlx_root::model::SqlxModel>::column_value(
                    <Self as #sqlx_root::model::SqlxModel>::PRIMARY_KEY,
                    #sqlx_root::value::SqlValue::Text(Some(id.to_string()))))
            }
            fn parse_user_id(user_id: &str) -> #core_root::AuthResult<#sqlx_root::value::SqlValue> {
                Ok(<Self as #sqlx_root::model::SqlxModel>::column_value(
                    Self::user_id_column(),
                    #sqlx_root::value::SqlValue::Text(Some(user_id.to_string()))))
            }

            fn new_active(
                id: ::std::option::Option<#sqlx_root::value::SqlValue>,
                token: ::std::string::String,
                create_session: #core_root::types::CreateSession,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> #sqlx_root::model::ActiveRow {
                #new_active
            }

            fn set_expires_at(
                active: &mut #sqlx_root::model::ActiveRow,
                expires_at: ::chrono::DateTime<::chrono::Utc>,
            ) {
                #set_expires_at
            }

            fn set_updated_at(
                active: &mut #sqlx_root::model::ActiveRow,
                updated_at: ::chrono::DateTime<::chrono::Utc>,
            ) {
                #set_updated_at
            }

            #set_active_org
            #set_active_team
        }
    })
}

pub(crate) fn account_impl(
    ident: &Ident,
    fields: &FieldsNamed,
    columns: &[Column],
    roots: &Roots,
) -> syn::Result<TokenStream> {
    let sqlx_root = &roots.sqlx;
    let core_root = &roots.core;
    let column = |name: &str| physical(columns, name);
    let new_active = new_active(EntityRole::Account, fields, columns, roots)?;
    let updates =
        codegen::update_statements(EntityRole::Account, fields, &set_field(columns, roots));
    let id_column = column("id")?;
    let provider_id_column = column("provider_id")?;
    let account_id_column = column("account_id")?;
    let user_id_column = column("user_id")?;
    let created_at_column = column("created_at")?;
    let access_token_column = column("access_token")?;
    let refresh_token_column = column("refresh_token")?;
    let id_token_column = column("id_token")?;
    let additional = additional_fields(columns, roots);
    Ok(quote! {
        impl #sqlx_root::SqlxAccountModel for #ident {
            #additional
            fn oauth_token_columns() -> Option<[&'static str; 3]> {
                Some([#access_token_column, #refresh_token_column, #id_token_column])
            }
            fn id_column() -> &'static str { #id_column }
            fn provider_id_column() -> &'static str { #provider_id_column }
            fn account_id_column() -> &'static str { #account_id_column }
            fn user_id_column() -> &'static str { #user_id_column }
            fn created_at_column() -> &'static str { #created_at_column }
            fn parse_id(id: &str) -> #core_root::AuthResult<#sqlx_root::value::SqlValue> {
                Ok(<Self as #sqlx_root::model::SqlxModel>::column_value(
                    <Self as #sqlx_root::model::SqlxModel>::PRIMARY_KEY,
                    #sqlx_root::value::SqlValue::Text(Some(id.to_string()))))
            }
            fn parse_user_id(user_id: &str) -> #core_root::AuthResult<#sqlx_root::value::SqlValue> {
                Ok(<Self as #sqlx_root::model::SqlxModel>::column_value(
                    Self::user_id_column(),
                    #sqlx_root::value::SqlValue::Text(Some(user_id.to_string()))))
            }

            fn new_active(
                id: ::std::option::Option<#sqlx_root::value::SqlValue>,
                create_account: #core_root::types::CreateAccount,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> #sqlx_root::model::ActiveRow {
                #new_active
            }

            fn apply_update(
                active: &mut #sqlx_root::model::ActiveRow,
                update: #core_root::types::UpdateAccount,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) {
                #updates
            }
        }
    })
}

pub(crate) fn verification_impl(
    ident: &Ident,
    fields: &FieldsNamed,
    columns: &[Column],
    roots: &Roots,
) -> syn::Result<TokenStream> {
    let sqlx_root = &roots.sqlx;
    let core_root = &roots.core;
    let column = |name: &str| physical(columns, name);
    let new_active = new_active(EntityRole::Verification, fields, columns, roots)?;
    let id_column = column("id")?;
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
                Ok(<Self as #sqlx_root::model::SqlxModel>::column_value(
                    <Self as #sqlx_root::model::SqlxModel>::PRIMARY_KEY,
                    #sqlx_root::value::SqlValue::Text(Some(id.to_string()))))
            }

            fn new_active(
                id: ::std::option::Option<#sqlx_root::value::SqlValue>,
                verification: #core_root::types::CreateVerification,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> #sqlx_root::model::ActiveRow {
                #new_active
            }
        }
    })
}
