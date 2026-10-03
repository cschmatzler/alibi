//! Proc macros for the Better Auth `SeaORM` integration.

use better_auth_entity_codegen::{self as codegen, EntityRole, Insert};
use proc_macro::TokenStream as ProcMacroTokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{DeriveInput, FieldsNamed, LitStr, parse_macro_input};

fn found_crate_tokens(name: &str) -> Option<TokenStream> {
    match crate_name(name).ok()? {
        FoundCrate::Itself => {
            // `Itself` means the Cargo.toml that triggered compilation lists
            // this crate as its own package name. Examples and integration
            // tests compile as separate binaries that link the crate
            // externally, so `crate::` would be wrong: use the extern name.
            let ident = Ident::new(&name.replace('-', "_"), Span::call_site());
            Some(quote!(::#ident))
        }
        FoundCrate::Name(name) => {
            let ident = Ident::new(&name, Span::call_site());
            Some(quote!(::#ident))
        }
    }
}

/// Paths to the `SeaORM` integration crate and to Better Auth core.
struct Roots {
    seaorm: TokenStream,
    core: TokenStream,
}

fn resolve_roots() -> Roots {
    if let Some(better_auth_root) = found_crate_tokens("better-auth") {
        return Roots {
            seaorm: quote!(#better_auth_root::seaorm),
            core: quote!(#better_auth_root::__private_core),
        };
    }
    match crate_name("better-auth-seaorm") {
        Ok(FoundCrate::Itself) => Roots {
            seaorm: quote!(crate),
            core: quote!(crate::__private_core),
        },
        _ => Roots {
            seaorm: syn::Error::new(
                Span::call_site(),
                "AuthEntity must be used through better_auth::seaorm with the `seaorm` feature enabled",
            )
            .to_compile_error(),
            core: quote!(::core::compile_error!("unreachable")),
        },
    }
}

/// One model field with its `Column` variant and explicitly renamed column.
struct Field {
    ident: Ident,
    ty: syn::Type,
    camel: String,
    column: Ident,
    physical: Option<String>,
}

fn pascal_case(name: &Ident) -> String {
    let identifier = name.to_string();
    let mut pascal = String::new();
    for component in identifier.trim_start_matches("r#").split('_') {
        let mut letters = component.chars();
        if let Some(first) = letters.next() {
            pascal.extend(first.to_uppercase());
        }
        pascal.extend(letters);
    }
    pascal
}

/// Read each field's `Column` variant and physical name from its `sea_orm` attributes.
fn model_fields(fields: &FieldsNamed) -> syn::Result<Vec<Field>> {
    fields
        .named
        .iter()
        .map(|field| {
            let ident = field
                .ident
                .clone()
                .ok_or_else(|| syn::Error::new_spanned(field, "Expected a named field"))?;
            let mut column = Ident::new(&pascal_case(&ident), ident.span());
            let mut physical = None;
            for attribute in field
                .attrs
                .iter()
                .filter(|attribute| attribute.path().is_ident("sea_orm"))
            {
                attribute.parse_nested_meta(|meta| {
                    if meta.path.is_ident("enum_name") {
                        column =
                            syn::parse_str::<Ident>(&meta.value()?.parse::<LitStr>()?.value())?;
                    } else if meta.path.is_ident("column_name") {
                        physical = Some(meta.value()?.parse::<LitStr>()?.value());
                    } else {
                        // Consume other SeaORM values while preserving bare flags.
                        drop(
                            meta.value()
                                .and_then(syn::parse::ParseBuffer::parse::<syn::Expr>)
                                .ok(),
                        );
                    }
                    Ok(())
                })?;
            }
            Ok(Field {
                camel: codegen::camel_case(&ident),
                ident,
                ty: field.ty.clone(),
                column,
                physical,
            })
        })
        .collect()
}

fn try_generate(input: &DeriveInput) -> syn::Result<TokenStream> {
    let roots = resolve_roots();
    let attributes = codegen::parse_auth_attributes(input, false)?;
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

/// `active.field = Set(value)`, converting the plan's expression into the
/// declared field type.
fn set_field(roots: &Roots) -> impl Fn(&Ident, &Insert) -> TokenStream {
    let seaorm_root = roots.seaorm.clone();
    move |field, insert| match insert {
        Insert::Value(expr) => quote! {
            active.#field = #seaorm_root::sea_orm::ActiveValue::Set(::std::convert::Into::into(#expr));
        },
        Insert::Null | Insert::Default => quote! {
            active.#field = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::None);
        },
    }
}

/// The `new_active` body: an `ActiveModel` literal over every declared field.
fn new_active(role: EntityRole, fields: &FieldsNamed, roots: &Roots) -> TokenStream {
    let seaorm_root = &roots.seaorm;
    let core_root = &roots.core;
    let assignments = codegen::insert_values(role, fields)
        .into_iter()
        .map(|(field, insert)| match insert {
            Insert::Value(expr) => quote! {
                #field: #seaorm_root::sea_orm::ActiveValue::Set(::std::convert::Into::into(#expr))
            },
            Insert::Null => quote! {
                #field: #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::None)
            },
            Insert::Default => quote! { #field: #seaorm_root::sea_orm::ActiveValue::NotSet },
        });
    quote! {
        Self::ActiveModel {
            id: #seaorm_root::sea_orm::ActiveValue::Set(
                id.unwrap_or_else(|| #core_root::uuid::Uuid::new_v4().to_string())
            ),
            #(#assignments,)*
        }
    }
}

/// Configured additional-field bindings and staging, keyed by wire and physical names.
fn additional_fields(fields: &[Field], roots: &Roots) -> TokenStream {
    let seaorm_root = &roots.seaorm;
    let core_root = &roots.core;
    let mut bindings = Vec::new();
    let mut stages = Vec::new();
    for field in fields {
        let (name, camel, column) = (&field.ident, &field.camel, &field.column);
        if let Some(physical) = field
            .physical
            .as_ref()
            .filter(|physical| *physical != camel)
        {
            bindings.push(quote! {
                #physical => (Column::#column, #seaorm_root::additional_fields::raw_value(value)?),
            });
        }
        bindings.push(quote! {
            #camel => (Column::#column, #seaorm_root::additional_fields::raw_value(value)?),
        });
        // Only metadata documents have a backend-specific binding; other
        // `sea_orm` value types bind as themselves.
        let ty = &field.ty;
        let prepared = if quote!(#ty).to_string().contains("JsonMetadata") {
            quote! { #seaorm_root::json_metadata::MetadataBinding::prepare(value, backend)? }
        } else {
            quote! { value }
        };
        stages.push(quote! {
            Column::#column => {
                let value = <#ty as #seaorm_root::sea_orm::sea_query::ValueType>::try_from(value)
                    .map_err(|_error| #core_root::AuthError::internal("field value cannot be represented by its model column"))?;
                active.#name = #seaorm_root::sea_orm::ActiveValue::Set(#prepared);
            }
        });
    }
    quote! {
        fn additional_field_bindings(fields: &#core_root::field_policy::FieldValues, _backend: #seaorm_root::sea_orm::DbBackend) -> #core_root::AuthResult<Vec<(Self::Column, #seaorm_root::sea_orm::Value)>> {
            let mut bindings = Vec::new();
            for (name, value) in fields {
                bindings.push(match fields.binding_name(name) {
                    #(#bindings)*
                    _ => return Err(#core_root::AuthError::internal("configured field has no model column")),
                });
            }
            Ok(bindings)
        }
        fn set_additional_field(active: &mut Self::ActiveModel, column: Self::Column, value: #seaorm_root::sea_orm::Value, backend: #seaorm_root::sea_orm::DbBackend) -> #core_root::AuthResult<()> {
            match column { #(#stages)* }
            Ok(())
        }
    }
}

fn user_impl(
    ident: &Ident,
    fields: &FieldsNamed,
    model_fields: &[Field],
    roots: &Roots,
) -> TokenStream {
    let seaorm_root = &roots.seaorm;
    let core_root = &roots.core;
    let has = |name: &str| codegen::has_field(fields, name);
    let new_active = new_active(EntityRole::User, fields, roots);
    let updates = codegen::update_statements(EntityRole::User, fields, &set_field(roots));
    let additional = additional_fields(model_fields, roots);
    let list_columns = model_fields.iter().map(|field| {
        let (camel, column) = (&field.camel, &field.column);
        quote! { #camel => Some(Column::#column), }
    });
    let prepare_json_metadata = if has("metadata") {
        quote! {
            fn prepare_json_metadata(active: &mut Self::ActiveModel, backend: #seaorm_root::sea_orm::DbBackend) -> #core_root::AuthResult<()> {
                if let #seaorm_root::sea_orm::ActiveValue::Set(value) = &active.metadata {
                    active.metadata = #seaorm_root::sea_orm::ActiveValue::Set(
                        #seaorm_root::json_metadata::MetadataBinding::prepare(value.clone(), backend)?
                    );
                }
                Ok(())
            }
        }
    } else {
        quote! {}
    };
    let username_column = if has("username") {
        quote! { fn username_column() -> Option<Self::Column> { Some(Column::Username) } }
    } else {
        quote! {}
    };
    let phone_number_column = if has("phone_number") {
        quote! { fn phone_number_column() -> Option<Self::Column> { Some(Column::PhoneNumber) } }
    } else {
        quote! {}
    };
    quote! {
        impl #seaorm_root::SeaOrmUserModel for #ident {
            #additional
            type Id = ::std::string::String;
            type Entity = Entity;
            type ActiveModel = ActiveModel;
            type Column = Column;

            fn id_column() -> Self::Column { Column::Id }
            fn email_column() -> Self::Column { Column::Email }
            #username_column
            #phone_number_column
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
                #new_active
            }

            fn apply_update(
                active: &mut Self::ActiveModel,
                update: #core_root::types::UpdateUser,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) {
                #updates
            }
        }
    }
}

fn session_impl(
    ident: &Ident,
    fields: &FieldsNamed,
    model_fields: &[Field],
    roots: &Roots,
) -> TokenStream {
    let seaorm_root = &roots.seaorm;
    let core_root = &roots.core;
    let has = |name: &str| codegen::has_field(fields, name);
    let new_active = new_active(EntityRole::Session, fields, roots);
    let additional = additional_fields(model_fields, roots);
    let set = set_field(roots);
    // Secondary-only sessions never touch the database, so optional columns
    // the insert would have defaulted materialize as `None`.
    let nullable_defaults = fields.named.iter().filter_map(|field| {
        let name = field.ident.as_ref()?;
        codegen::is_option(&field.ty).then(|| {
            quote! {
                if active.#name.is_not_set() {
                    active.#name = #seaorm_root::sea_orm::ActiveValue::Set(None);
                }
            }
        })
    });
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
                active: &mut Self::ActiveModel,
                organization_id: ::std::option::Option<::std::string::String>,
            ) {
                #assign
            }
        }
    } else {
        quote! {
            fn set_active_organization_id(
                _active: &mut Self::ActiveModel,
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
                active: &mut Self::ActiveModel,
                team_id: ::std::option::Option<::std::string::String>,
            ) -> #core_root::AuthResult<()> {
                #assign
                Ok(())
            }
        }
    } else {
        quote! {}
    };
    quote! {
        impl #seaorm_root::SeaOrmSessionModel for #ident {
            fn materialize_secondary(mut active: Self::ActiveModel) -> #core_root::AuthResult<Self> {
                #(#nullable_defaults)*
                #seaorm_root::sea_orm::TryIntoModel::try_into_model(active)
                    .map_err(|error| #core_root::AuthError::internal(error.to_string()))
            }
            #additional
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
                #new_active
            }

            fn set_expires_at(
                active: &mut Self::ActiveModel,
                expires_at: ::chrono::DateTime<::chrono::Utc>,
            ) {
                #set_expires_at
            }

            fn set_updated_at(
                active: &mut Self::ActiveModel,
                updated_at: ::chrono::DateTime<::chrono::Utc>,
            ) {
                #set_updated_at
            }

            #set_active_org
            #set_active_team
        }
    }
}

fn account_impl(
    ident: &Ident,
    fields: &FieldsNamed,
    model_fields: &[Field],
    roots: &Roots,
) -> TokenStream {
    let seaorm_root = &roots.seaorm;
    let core_root = &roots.core;
    let new_active = new_active(EntityRole::Account, fields, roots);
    let updates = codegen::update_statements(EntityRole::Account, fields, &set_field(roots));
    let additional = additional_fields(model_fields, roots);
    quote! {
        impl #seaorm_root::SeaOrmAccountModel for #ident {
            #additional
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
                #new_active
            }

            fn apply_update(
                active: &mut Self::ActiveModel,
                update: #core_root::types::UpdateAccount,
                now: ::chrono::DateTime<::chrono::Utc>,
            ) {
                #updates
            }
        }
    }
}

fn verification_impl(ident: &Ident, fields: &FieldsNamed, roots: &Roots) -> TokenStream {
    let seaorm_root = &roots.seaorm;
    let core_root = &roots.core;
    let new_active = new_active(EntityRole::Verification, fields, roots);
    quote! {
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
                #new_active
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
