//! Proc macros for the Better Auth `SQLx` integration.

use better_auth_entity_codegen::{self as codegen, EntityRole, Insert};
use proc_macro::TokenStream as ProcMacroTokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
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

/// Paths to the `SQLx` integration crate and to Better Auth core.
struct Roots {
    sqlx: TokenStream,
    core: TokenStream,
    id_generator: TokenStream,
}

fn resolve_roots() -> Roots {
    if let Some(better_auth_root) = found_crate_tokens("better-auth") {
        return Roots {
            id_generator: quote! {},
            sqlx: quote!(#better_auth_root::sqlx),
            core: quote!(#better_auth_root::__private_core),
        };
    }
    match crate_name("better-auth-sqlx") {
        Ok(FoundCrate::Itself) => Roots {
            id_generator: quote! {},
            sqlx: quote!(crate),
            core: quote!(crate::__private_core),
        },
        Ok(FoundCrate::Name(name)) => {
            let ident = Ident::new(&name, Span::call_site());
            Roots {
                id_generator: quote! {},
                sqlx: quote!(::#ident),
                core: quote!(::#ident::__private_core),
            }
        }
        Err(_) => Roots {
            id_generator: quote! {},
            sqlx: syn::Error::new(
                Span::call_site(),
                "AuthEntity must be used through better_auth::sqlx with the `sqlx` feature enabled",
            )
            .to_compile_error(),
            core: quote!(::core::compile_error!("unreachable")),
        },
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
        "UPPERCASE" | "SCREAMING_SNAKE_CASE" => name.to_uppercase(),
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
                        "model fields map one-to-one to columns; `skip`, `flatten`, `json` and `try_from` are unsupported",
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
                        "bpchar" => "BpChar",
                        "json" => "Json",
                        "double" => "Double",
                        "float" => "Float",
                        "boolean" => "Boolean",
                        "other" => "Other",
                        _ => {
                            return Err(syn::Error::new_spanned(
                                value,
                                "expected text, bpchar, json, double, float, boolean or other",
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

/// `#[auth(table = "...")]` on a plain `SqlxModel` derive.
fn table_attribute(input: &DeriveInput) -> syn::Result<String> {
    let mut table = None;
    for attr in &input.attrs {
        if !attr.path().is_ident("auth") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("table") {
                table = Some(meta.value()?.parse::<LitStr>()?.value());
                Ok(())
            } else {
                Err(meta.error("expected `table = \"...\"`"))
            }
        })?;
    }
    table.ok_or_else(|| {
        syn::Error::new_spanned(
            input,
            "missing #[auth(table = \"...\")] attribute for SqlxModel",
        )
    })
}

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
                #name => (#name, #sqlx_root::additional_fields::raw_value(value)?),
            });
        }
        stages.push(quote! {
            #name => {
                let value = <#field_ty as #sqlx_root::value::SqlxValue>::from_sql_value(value)
                    .map_err(|_error| #core_root::AuthError::internal("field value cannot be represented by its model column"))?;
                active.set(#name, #sqlx_root::value::SqlxValue::into_sql_value(
                    #sqlx_root::value::SqlxValue::prepare(value, backend)?
                ));
            }
        });
        bindings.push(quote! {
            #camel => (#name, #sqlx_root::additional_fields::raw_value(value)?),
        });
    }
    quote! {
        fn additional_field_bindings(fields: &#core_root::field_policy::FieldValues, _backend: #sqlx_root::pool::Engine) -> #core_root::AuthResult<Vec<(&'static str, #sqlx_root::value::SqlValue)>> {
            let mut bindings = Vec::new();
            for (name, value) in fields {
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

/// `active.set(column, value)` with `value` converted into the declared field
/// type, so the staged `SqlValue` variant always matches the column.
fn set_field(columns: &[Column], roots: &Roots) -> impl Fn(&Ident, &Insert) -> TokenStream {
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
fn new_active(
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

fn user_impl(
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

fn session_impl(
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

fn account_impl(
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

fn verification_impl(
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
