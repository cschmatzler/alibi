//! Proc macros for the Better Auth `SeaORM` integration.

use better_auth_entity_codegen::{self as codegen, EntityRole};
use proc_macro::TokenStream as ProcMacroTokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{DeriveInput, LitStr, Type, parse_macro_input};

fn found_crate_tokens(name: &str) -> Option<TokenStream> {
    match crate_name(name).ok()? {
        FoundCrate::Itself => {
            // `Itself` means the Cargo.toml that triggered compilation lists
            // this crate as its own package name.  Examples and integration
            // tests compile as separate binaries that link the crate
            // externally, so `crate::` would be wrong — use the extern name.
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
            quote!(#better_auth_root::seaorm),
            quote!(#better_auth_root::__private_core),
        );
    }

    match crate_name("better-auth-seaorm") {
        Ok(FoundCrate::Itself) => (quote!(crate), quote!(crate::__private_core)),
        _ => (
            syn::Error::new(
                Span::call_site(),
                "AuthEntity must be used through better_auth::seaorm with the `seaorm2` feature enabled",
            )
            .to_compile_error(),
            quote!(::core::compile_error!("unreachable")),
        ),
    }
}

fn generate_auth_entity(input: &DeriveInput) -> TokenStream {
    let (seaorm_root, core_root) = resolve_roots();
    let attributes = match codegen::parse_auth_attributes(input, false) {
        Ok(attributes) => attributes,
        Err(err) => return err.to_compile_error(),
    };
    let (role, secondary) = (attributes.role, attributes.secondary_storage);

    let fields = match codegen::named_fields(input) {
        Ok(fields) => fields,
        Err(err) => return err.to_compile_error(),
    };
    if let Err(err) = codegen::validate_core_fields(input, role, fields) {
        return err.to_compile_error();
    }

    let idents: Vec<_> = fields
        .named
        .iter()
        .filter_map(|field| field.ident.clone())
        .collect();

    let has = |name: &str| codegen::has_field(fields, name);
    let optional = |name: &str| codegen::optional_field(fields, name);

    // Extra fields: not core, not plugin — user-defined.
    let extra_not_set: Vec<_> = idents
        .iter()
        .filter(|ident| !codegen::is_known_field(role, ident))
        .map(|field| {
            quote! { #field: #seaorm_root::sea_orm::ActiveValue::NotSet }
        })
        .collect();

    let ident = &input.ident;

    match role {
        EntityRole::User => gen_user(
            ident,
            &has,
            &optional,
            (fields, secondary),
            &extra_not_set,
            &seaorm_root,
            &core_root,
        ),
        EntityRole::Session => gen_session(
            ident,
            &has,
            (fields, secondary),
            &extra_not_set,
            &seaorm_root,
            &core_root,
        ),
        EntityRole::Account => gen_account(ident, fields, &extra_not_set, &seaorm_root, &core_root),
        EntityRole::Verification => {
            gen_verification(ident, &extra_not_set, &seaorm_root, &core_root)
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep the generated AuthUser implementation together as one quoted trait contract"
)]
fn gen_user(
    ident: &Ident,
    has: &dyn Fn(&str) -> bool,
    optional: &dyn Fn(&str) -> bool,
    fields: (&syn::FieldsNamed, bool),
    extras: &[TokenStream],
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> TokenStream {
    let (fields, secondary) = fields;
    let (auth_impl, additional_bindings) = match entity_fields(fields).and_then(|entity_fields| {
        Ok((
            codegen::auth_user_impl(ident, fields, &entity_fields, secondary, core_root),
            additional_model_fields(fields, seaorm_root, core_root)?,
        ))
    }) {
        Ok(generated) => generated,
        Err(error) => return error.to_compile_error(),
    };
    let mut list_columns = Vec::new();
    for field in &fields.named {
        let Some(name) = field.ident.as_ref() else {
            continue;
        };
        let text = name.to_string();
        let text = text.trim_start_matches("r#");
        let mut parts = text.split('_');
        let mut camel = parts.next().unwrap_or_default().to_owned();
        for part in parts {
            let mut letters = part.chars();
            if let Some(first) = letters.next() {
                camel.extend(first.to_uppercase());
            }
            camel.extend(letters);
        }
        let mut enum_name = None;
        for attribute in field
            .attrs
            .iter()
            .filter(|attribute| attribute.path().is_ident("sea_orm"))
        {
            let parsed = attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("enum_name") {
                    let value = meta.value()?.parse::<LitStr>()?;
                    enum_name = Some(syn::parse_str::<Ident>(&value.value())?);
                } else {
                    // Consume other SeaORM values while preserving bare flags.
                    drop(
                        meta.value()
                            .and_then(syn::parse::ParseBuffer::parse::<syn::Expr>)
                            .ok(),
                    );
                }
                Ok(())
            });
            if let Err(error) = parsed {
                return error.to_compile_error();
            }
        }
        let column = enum_name.map_or_else(
            || quote! { <Column as ::std::str::FromStr>::from_str(#text).ok() },
            |column| quote! { Some(Column::#column) },
        );
        list_columns.push(quote! { #camel => #column, });
    }
    let prepare_json_metadata = if has("metadata") {
        quote! {
            fn prepare_json_metadata(active:&mut Self::ActiveModel,backend:#seaorm_root::sea_orm::DbBackend)->#core_root::AuthResult<()> {
                if let #seaorm_root::sea_orm::ActiveValue::Set(value)=&active.metadata {
                    active.metadata=#seaorm_root::sea_orm::ActiveValue::Set(
                        #seaorm_root::json_metadata::prepare_metadata_value(value.clone(),backend)?
                    );
                }
                Ok(())
            }
        }
    } else {
        quote! {}
    };

    // new_active — plugin fields get Set(default) when present, omitted when absent
    let plugin_new_active = plugin_set_fields_user(has, optional, seaorm_root, core_root);

    // apply_update — only update fields that exist
    let plugin_apply_update = plugin_update_fields_user(has, seaorm_root);

    let username_column_impl = if has("username") {
        quote! { fn username_column() -> Option<Self::Column> { Some(Column::Username) } }
    } else {
        // Use trait default (returns None)
        quote! {}
    };
    let phone_number_column_impl = if has("phone_number") {
        quote! { fn phone_number_column() -> Option<Self::Column> { Some(Column::PhoneNumber) } }
    } else {
        quote! {}
    };

    quote! {
        #auth_impl

        impl #seaorm_root::SeaOrmUserModel for #ident {
            #additional_bindings
            type Id = ::std::string::String;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;

            fn id_column() -> Self::Column { Column::Id }
            fn email_column() -> Self::Column { Column::Email }
            #username_column_impl
            #phone_number_column_impl
            #prepare_json_metadata
            fn name_column() -> Self::Column { Column::Name }
            fn created_at_column() -> Self::Column { Column::CreatedAt }
            fn list_users_column(field: &str) -> Option<Self::Column> {
                match field { #(#list_columns)* _ => None }
            }
            fn parse_id(id: &str) -> #core_root::AuthResult<Self::Id> {
                Ok(id.to_string())
            }

            fn new_active(
                id: ::std::option::Option<Self::Id>,
                create_user: #core_root::types::CreateUser,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self::ActiveModel {
                Self::ActiveModel {
                    id: #seaorm_root::sea_orm::ActiveValue::Set(
                        id.unwrap_or_else(|| #core_root::uuid::Uuid::new_v4().to_string())
                    ),
                    email: #seaorm_root::sea_orm::ActiveValue::Set(create_user.email),
                    name: #seaorm_root::sea_orm::ActiveValue::Set(create_user.name),
                    image: #seaorm_root::sea_orm::ActiveValue::Set(create_user.image),
                    email_verified: #seaorm_root::sea_orm::ActiveValue::Set(create_user.email_verified.unwrap_or(false)),
                    created_at: #seaorm_root::sea_orm::ActiveValue::Set(create_user.created_at.unwrap_or(now)),
                    updated_at: #seaorm_root::sea_orm::ActiveValue::Set(create_user.updated_at.unwrap_or(now)),
                    #(#plugin_new_active,)*
                    #(#extras,)*
                }
            }

            fn apply_update(
                active: &mut Self::ActiveModel,
                update: #core_root::types::UpdateUser,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) {
                if let ::std::option::Option::Some(email) = update.email {
                    active.email = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(email));
                }
                if let ::std::option::Option::Some(name) = update.name {
                    active.name = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(name));
                }
                if let ::std::option::Option::Some(image) = update.image {
                    active.image = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(image));
                }
                if let ::std::option::Option::Some(email_verified) = update.email_verified {
                    active.email_verified = #seaorm_root::sea_orm::ActiveValue::Set(email_verified);
                }
                #(#plugin_apply_update)*
                active.updated_at = #seaorm_root::sea_orm::ActiveValue::Set(now);
            }
        }
    }
}

/// Generate `new_active` field assignments for present plugin fields on User.
fn plugin_set_fields_user(
    has: &dyn Fn(&str) -> bool,
    optional: &dyn Fn(&str) -> bool,
    seaorm_root: &TokenStream,
    _core_root: &TokenStream,
) -> Vec<TokenStream> {
    let mut out = Vec::new();
    if has("username") {
        out.push(
            quote! { username: #seaorm_root::sea_orm::ActiveValue::Set(create_user.username) },
        );
    }
    if has("display_username") {
        out.push(quote! { display_username: #seaorm_root::sea_orm::ActiveValue::Set(create_user.display_username) });
    }
    if has("two_factor_enabled") {
        let value = if optional("two_factor_enabled") {
            quote! { create_user.two_factor_enabled }
        } else {
            quote! { create_user.two_factor_enabled.unwrap_or(false) }
        };
        out.push(quote! { two_factor_enabled: #seaorm_root::sea_orm::ActiveValue::Set(#value) });
    }
    if has("role") {
        out.push(quote! { role: #seaorm_root::sea_orm::ActiveValue::Set(create_user.role) });
    }
    if has("banned") {
        let value = if optional("banned") {
            quote! { create_user.banned }
        } else {
            quote! { create_user.banned.unwrap_or(false) }
        };
        out.push(quote! { banned: #seaorm_root::sea_orm::ActiveValue::Set(#value) });
    }
    if has("ban_reason") {
        out.push(quote! { ban_reason: #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::None) });
    }
    if has("ban_expires") {
        out.push(quote! { ban_expires: #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::None) });
    }
    if has("metadata") {
        // used in the json! path
        out.push(quote! { metadata: #seaorm_root::sea_orm::ActiveValue::Set(create_user.metadata.unwrap_or(::serde_json::json!({})).into()) });
    }
    for name in [
        "is_anonymous",
        "phone_number",
        "phone_number_verified",
        "last_login_method",
    ] {
        if has(name) {
            let field = Ident::new(name, Span::call_site());
            out.push(
                quote! { #field: #seaorm_root::sea_orm::ActiveValue::Set(create_user.#field) },
            );
        }
    }
    out
}

/// Generate `apply_update` statements for present plugin fields on User.
fn plugin_update_fields_user(
    has: &dyn Fn(&str) -> bool,
    seaorm_root: &TokenStream,
) -> Vec<TokenStream> {
    let mut out = Vec::new();
    if has("username") {
        out.push(quote! {
            if let ::std::option::Option::Some(username) = update.username {
                active.username = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(username));
            }
        });
    }
    if has("display_username") {
        out.push(quote! {
            if let ::std::option::Option::Some(display_username) = update.display_username {
                active.display_username = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(display_username));
            }
        });
    }
    if has("role") {
        out.push(quote! {
            if let ::std::option::Option::Some(role) = update.role {
                active.role = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(role));
            }
        });
    }
    if has("two_factor_enabled") {
        out.push(quote! {
            if let ::std::option::Option::Some(two_factor_enabled) = update.two_factor_enabled {
                active.two_factor_enabled = #seaorm_root::sea_orm::ActiveValue::Set(two_factor_enabled.into());
            }
        });
    }
    if has("metadata") {
        out.push(quote! {
            if let ::std::option::Option::Some(metadata) = update.metadata {
                active.metadata = #seaorm_root::sea_orm::ActiveValue::Set(metadata.into());
            }
        });
    }
    if has("banned") && has("ban_reason") && has("ban_expires") {
        out.push(quote! {
            if let ::std::option::Option::Some(banned) = update.banned {
                active.banned = #seaorm_root::sea_orm::ActiveValue::Set(banned.into());
                if !banned {
                    active.ban_reason = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::None);
                    active.ban_expires = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::None);
                }
            }
            if update.banned != ::std::option::Option::Some(false) {
                if let ::std::option::Option::Some(ban_reason) = update.ban_reason {
                    active.ban_reason = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(ban_reason));
                }
                if let ::std::option::Option::Some(ban_expires) = update.ban_expires {
                    active.ban_expires = #seaorm_root::sea_orm::ActiveValue::Set(ban_expires);
                }
            }
        });
    } else if has("banned") {
        out.push(quote! {
            if let ::std::option::Option::Some(banned) = update.banned {
                active.banned = #seaorm_root::sea_orm::ActiveValue::Set(banned.into());
            }
        });
    }
    for name in ["is_anonymous", "phone_number_verified"] {
        if has(name) {
            let field = Ident::new(name, Span::call_site());
            out.push(quote! {
                if let ::std::option::Option::Some(value) = update.#field {
                    active.#field = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(value));
                }
            });
        }
    }
    for name in ["phone_number", "last_login_method"] {
        if has(name) {
            let field = Ident::new(name, Span::call_site());
            out.push(quote! {
                if let ::std::option::Option::Some(value) = update.#field {
                    active.#field = #seaorm_root::sea_orm::ActiveValue::Set(value);
                }
            });
        }
    }
    out
}

fn additional_model_fields(
    fields: &syn::FieldsNamed,
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> syn::Result<TokenStream> {
    let mut additional_binding = Vec::new();
    let mut additional_stage = Vec::new();
    for field in &fields.named {
        let Some(name) = &field.ident else {
            continue;
        };
        let (camel, column, physical) = additional_field_names(field)?;
        if let Some(physical) = physical.as_ref().filter(|physical| *physical != &camel) {
            additional_binding.push(quote! {
                #physical => (Column::#column, #seaorm_root::session_fields::raw_value(value)?),
            });
        }
        let ty = &field.ty;
        let json_field = quote!(#ty).to_string().contains("JsonMetadata");
        let optional_json = json_field && quote!(#ty).to_string().contains("Option");
        let preparation = if optional_json {
            quote! { if let Some(value) = value { Some(#seaorm_root::json_metadata::prepare_metadata_value(value, backend)?) } else { None } }
        } else if json_field {
            quote! { #seaorm_root::json_metadata::prepare_metadata_value(value, backend)? }
        } else {
            quote!(value)
        };
        additional_stage.push(quote! {
            Column::#column => {
                let value = <#ty as #seaorm_root::sea_orm::sea_query::ValueType>::try_from(value)
                    .map_err(|_error| #core_root::AuthError::internal("field value cannot be represented by its model column"))?;
                active.#name = #seaorm_root::sea_orm::ActiveValue::Set(#preparation);
            }
        });
        additional_binding.push(quote! {
            #camel => (Column::#column, #seaorm_root::session_fields::raw_value(value)?),
        });
    }
    let bindings = quote! {
        fn additional_field_bindings(fields: &#core_root::field_policy::FieldValues, _backend: #seaorm_root::sea_orm::DbBackend) -> #core_root::AuthResult<Vec<(Self::Column, #seaorm_root::sea_orm::Value)>> {
            let mut bindings = Vec::new();
            for (name, value) in fields {
                bindings.push(match fields.binding_name(name) {
                    #(#additional_binding)*
                    _ => return Err(#core_root::AuthError::internal("configured field has no model column")),
                });
            }
            Ok(bindings)
        }
        fn set_additional_field(active: &mut Self::ActiveModel, column: Self::Column, value: #seaorm_root::sea_orm::Value, backend: #seaorm_root::sea_orm::DbBackend) -> #core_root::AuthResult<()> {
            let _ = backend;
            match column { #(#additional_stage)* }
            Ok(())
        }
    };
    Ok(bindings)
}

fn entity_fields(fields: &syn::FieldsNamed) -> syn::Result<Vec<codegen::EntityField>> {
    fields
        .named
        .iter()
        .map(|field| {
            let (camel, _column, physical) = additional_field_names(field)?;
            Ok(codegen::EntityField {
                ident: field
                    .ident
                    .clone()
                    .ok_or_else(|| syn::Error::new_spanned(field, "Expected a named field"))?,
                camel,
                physical,
            })
        })
        .collect()
}

fn additional_field_names(field: &syn::Field) -> syn::Result<(String, Ident, Option<String>)> {
    let name = field
        .ident
        .as_ref()
        .ok_or_else(|| syn::Error::new_spanned(field, "Expected a named field"))?;
    let identifier = name.to_string();
    let text = identifier.trim_start_matches("r#");
    let mut components = text.split('_');
    let mut camel = components.next().unwrap_or_default().to_owned();
    let mut pascal = String::new();
    for component in text.split('_') {
        let mut letters = component.chars();
        if let Some(first) = letters.next() {
            pascal.extend(first.to_uppercase());
        }
        pascal.extend(letters);
    }
    for component in components {
        let mut letters = component.chars();
        if let Some(first) = letters.next() {
            camel.extend(first.to_uppercase());
        }
        camel.extend(letters);
    }
    let mut column = Ident::new(&pascal, name.span());
    let mut physical = None;
    for attribute in field
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("sea_orm"))
    {
        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("enum_name") {
                column = syn::parse_str::<Ident>(&meta.value()?.parse::<LitStr>()?.value())?;
            } else if meta.path.is_ident("column_name") {
                physical = Some(meta.value()?.parse::<LitStr>()?.value());
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
    Ok((camel, column, physical))
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep the generated AuthSession implementation together as one quoted trait contract"
)]
fn gen_session(
    ident: &Ident,
    has: &dyn Fn(&str) -> bool,
    fields: (&syn::FieldsNamed, bool),
    extras: &[TokenStream],
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> TokenStream {
    let (fields, secondary) = fields;
    let nullable_defaults: Vec<_> = fields.named.iter().filter_map(|field| {
        if matches!(&field.ty, Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "Option")) {
            field.ident.as_ref().map(|name| quote! {
                if active.#name.is_not_set() {
                    active.#name = #seaorm_root::sea_orm::ActiveValue::Set(None);
                }
            })
        } else {
            None
        }
    }).collect();
    let (auth_impl, additional_bindings) = match entity_fields(fields).and_then(|entity_fields| {
        Ok((
            codegen::auth_session_impl(ident, fields, &entity_fields, secondary, core_root),
            additional_model_fields(fields, seaorm_root, core_root)?,
        ))
    }) {
        Ok(generated) => generated,
        Err(error) => return error.to_compile_error(),
    };
    let mut plugin_new_active = Vec::new();
    if has("impersonated_by") {
        plugin_new_active.push(quote! { impersonated_by: #seaorm_root::sea_orm::ActiveValue::Set(create_session.impersonated_by) });
    }
    if has("active_organization_id") {
        plugin_new_active.push(quote! { active_organization_id: #seaorm_root::sea_orm::ActiveValue::Set(create_session.active_organization_id) });
    }
    if has("active_team_id") {
        plugin_new_active.push(quote! { active_team_id: #seaorm_root::sea_orm::ActiveValue::Set(create_session.active_team_id) });
    }
    let set_active_team = if has("active_team_id") {
        quote! {
            fn set_active_team_id(
                active: &mut Self::ActiveModel,
                team_id: ::std::option::Option<::std::string::String>,
            ) -> #core_root::AuthResult<()> {
                active.active_team_id = #seaorm_root::sea_orm::ActiveValue::Set(team_id);
                Ok(())
            }
        }
    } else {
        quote! {}
    };

    let set_active_org = if has("active_organization_id") {
        quote! {
            fn set_active_organization_id(
                active: &mut Self::ActiveModel,
                organization_id: ::std::option::Option<::std::string::String>,
            ) {
                active.active_organization_id = #seaorm_root::sea_orm::ActiveValue::Set(organization_id);
            }
        }
    } else {
        quote! {
            fn set_active_organization_id(
                _active: &mut Self::ActiveModel,
                _organization_id: ::std::option::Option<::std::string::String>,
            ) {
                // organization plugin not enabled — no-op
            }
        }
    };

    quote! {
        #auth_impl

        impl #seaorm_root::SeaOrmSessionModel for #ident {
            fn materialize_secondary(mut active: Self::ActiveModel) -> #core_root::AuthResult<Self> {
                #(#nullable_defaults)*
                #seaorm_root::sea_orm::TryIntoModel::try_into_model(active)
                    .map_err(|error| #core_root::AuthError::internal(error.to_string()))
            }
            #additional_bindings
            type Id = ::std::string::String;
            type UserId = ::std::string::String;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;

            fn id_column() -> Self::Column { Column::Id }
            fn token_column() -> Self::Column { Column::Token }
            fn user_id_column() -> Self::Column { Column::UserId }
            fn active_column() -> Self::Column { Column::Active }
            fn expires_at_column() -> Self::Column { Column::ExpiresAt }
            fn created_at_column() -> Self::Column { Column::CreatedAt }
            fn parse_id(id: &str) -> #core_root::AuthResult<Self::Id> {
                Ok(id.to_string())
            }
            fn parse_user_id(user_id: &str) -> #core_root::AuthResult<Self::UserId> {
                Ok(user_id.to_string())
            }

            fn new_active(
                id: ::std::option::Option<Self::Id>,
                token: ::std::string::String,
                create_session: #core_root::types::CreateSession,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self::ActiveModel {
                Self::ActiveModel {
                    id: #seaorm_root::sea_orm::ActiveValue::Set(
                        id.unwrap_or_else(|| #core_root::uuid::Uuid::new_v4().to_string())
                    ),
                    user_id: #seaorm_root::sea_orm::ActiveValue::Set(create_session.user_id),
                    token: #seaorm_root::sea_orm::ActiveValue::Set(token),
                    expires_at: #seaorm_root::sea_orm::ActiveValue::Set(create_session.expires_at),
                    created_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    updated_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    ip_address: #seaorm_root::sea_orm::ActiveValue::Set(create_session.ip_address),
                    user_agent: #seaorm_root::sea_orm::ActiveValue::Set(create_session.user_agent),
                    active: #seaorm_root::sea_orm::ActiveValue::Set(true),
                    #(#plugin_new_active,)*
                    #(#extras,)*
                }
            }

            fn set_expires_at(
                active: &mut Self::ActiveModel,
                expires_at: ::chrono::DateTime<::chrono::Utc>,
            ) {
                active.expires_at = #seaorm_root::sea_orm::ActiveValue::Set(expires_at);
            }

            fn set_updated_at(
                active: &mut Self::ActiveModel,
                updated_at: ::chrono::DateTime<::chrono::Utc>,
            ) {
                active.updated_at = #seaorm_root::sea_orm::ActiveValue::Set(updated_at);
            }

            #set_active_org
            #set_active_team
        }
    }
}

fn gen_account(
    ident: &Ident,
    fields: &syn::FieldsNamed,
    extras: &[TokenStream],
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> TokenStream {
    let (auth_impl, additional_bindings) = match entity_fields(fields).and_then(|entity_fields| {
        Ok((
            codegen::auth_account_impl(ident, &entity_fields, core_root),
            additional_model_fields(fields, seaorm_root, core_root)?,
        ))
    }) {
        Ok(generated) => generated,
        Err(error) => return error.to_compile_error(),
    };
    // Account has no plugin-optional fields — all are core.
    quote! {
        #auth_impl

        impl #seaorm_root::SeaOrmAccountModel for #ident {
            #additional_bindings
            type Id = ::std::string::String;
            type UserId = ::std::string::String;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;

            fn id_column() -> Self::Column { Column::Id }
            fn provider_id_column() -> Self::Column { Column::ProviderId }
            fn account_id_column() -> Self::Column { Column::AccountId }
            fn user_id_column() -> Self::Column { Column::UserId }
            fn created_at_column() -> Self::Column { Column::CreatedAt }
            fn parse_id(id: &str) -> #core_root::AuthResult<Self::Id> {
                Ok(id.to_string())
            }
            fn parse_user_id(user_id: &str) -> #core_root::AuthResult<Self::UserId> {
                Ok(user_id.to_string())
            }

            fn new_active(
                id: ::std::option::Option<Self::Id>,
                create_account: #core_root::types::CreateAccount,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self::ActiveModel {
                Self::ActiveModel {
                    id: #seaorm_root::sea_orm::ActiveValue::Set(
                        id.unwrap_or_else(|| #core_root::uuid::Uuid::new_v4().to_string())
                    ),
                    account_id: #seaorm_root::sea_orm::ActiveValue::Set(create_account.account_id),
                    provider_id: #seaorm_root::sea_orm::ActiveValue::Set(create_account.provider_id),
                    user_id: #seaorm_root::sea_orm::ActiveValue::Set(create_account.user_id),
                    access_token: #seaorm_root::sea_orm::ActiveValue::Set(create_account.access_token),
                    refresh_token: #seaorm_root::sea_orm::ActiveValue::Set(create_account.refresh_token),
                    id_token: #seaorm_root::sea_orm::ActiveValue::Set(create_account.id_token),
                    access_token_expires_at: #seaorm_root::sea_orm::ActiveValue::Set(create_account.access_token_expires_at),
                    refresh_token_expires_at: #seaorm_root::sea_orm::ActiveValue::Set(create_account.refresh_token_expires_at),
                    scope: #seaorm_root::sea_orm::ActiveValue::Set(create_account.scope),
                    password: #seaorm_root::sea_orm::ActiveValue::Set(create_account.password),
                    created_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    updated_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    #(#extras,)*
                }
            }

            fn apply_update(
                active: &mut Self::ActiveModel,
                update: #core_root::types::UpdateAccount,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) {
                if let ::std::option::Option::Some(access_token) = update.access_token {
                    active.access_token = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(access_token));
                }
                if let ::std::option::Option::Some(refresh_token) = update.refresh_token {
                    active.refresh_token = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(refresh_token));
                }
                if let ::std::option::Option::Some(id_token) = update.id_token {
                    active.id_token = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(id_token));
                }
                if let ::std::option::Option::Some(access_token_expires_at) = update.access_token_expires_at {
                    active.access_token_expires_at = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(access_token_expires_at));
                }
                if let ::std::option::Option::Some(refresh_token_expires_at) = update.refresh_token_expires_at {
                    active.refresh_token_expires_at = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(refresh_token_expires_at));
                }
                if let ::std::option::Option::Some(scope) = update.scope {
                    active.scope = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(scope));
                }
                if let ::std::option::Option::Some(password) = update.password {
                    active.password = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::Some(password));
                }
                active.updated_at = #seaorm_root::sea_orm::ActiveValue::Set(now);
            }
        }
    }
}

fn gen_verification(
    ident: &Ident,
    extras: &[TokenStream],
    seaorm_root: &TokenStream,
    core_root: &TokenStream,
) -> TokenStream {
    // Verification has no plugin-optional fields.
    let auth_impl = codegen::auth_verification_impl(ident, core_root);
    quote! {
        #auth_impl

        impl #seaorm_root::SeaOrmVerificationModel for #ident {
            type Id = ::std::string::String;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;

            fn id_column() -> Self::Column { Column::Id }
            fn identifier_column() -> Self::Column { Column::Identifier }
            fn value_column() -> Self::Column { Column::Value }
            fn expires_at_column() -> Self::Column { Column::ExpiresAt }
            fn created_at_column() -> Self::Column { Column::CreatedAt }
            fn updated_at_column() -> Option<Self::Column> { Some(Column::UpdatedAt) }
            fn parse_id(id: &str) -> #core_root::AuthResult<Self::Id> {
                Ok(id.to_string())
            }

            fn new_active(
                id: ::std::option::Option<Self::Id>,
                verification: #core_root::types::CreateVerification,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) -> Self::ActiveModel {
                Self::ActiveModel {
                    id: #seaorm_root::sea_orm::ActiveValue::Set(
                        id.unwrap_or_else(|| #core_root::uuid::Uuid::new_v4().to_string())
                    ),
                    identifier: #seaorm_root::sea_orm::ActiveValue::Set(verification.identifier),
                    value: #seaorm_root::sea_orm::ActiveValue::Set(verification.value),
                    expires_at: #seaorm_root::sea_orm::ActiveValue::Set(verification.expires_at),
                    created_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    updated_at: #seaorm_root::sea_orm::ActiveValue::Set(now),
                    #(#extras,)*
                }
            }
        }
    }
}

/// Derive macro that generates `Auth*` trait impls and `SeaOrm*Model` impls
/// for a `SeaORM` entity.
///
/// # Usage
///
/// Annotate a `SeaORM` `Model` struct with `#[derive(AuthEntity)]` and
/// `#[auth(role = "...")]` where role is one of `user`, `session`, `account`,
/// or `verification`.
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
/// role.  These are accepted by the macro and set to `ActiveValue::NotSet`
/// in the generated `new_active()`.  Use database defaults or
/// `ActiveModelBehavior::before_save` to populate them.
///
/// ```ignore
/// #[derive(DeriveEntityModel, AuthEntity)]
/// #[auth(role = "user")]
/// #[sea_orm(table_name = "users")]
/// pub struct Model {
///     // ... core fields ...
///     pub locale: String,     // extra — gets NotSet in new_active
///     pub tenant_id: i64,     // extra — gets NotSet in new_active
/// }
/// ```
#[proc_macro_derive(AuthEntity, attributes(auth))]
pub fn derive_auth_entity(input: ProcMacroTokenStream) -> ProcMacroTokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    generate_auth_entity(&input).into()
}
