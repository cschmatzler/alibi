use super::{
    EntityRole, Field, FieldsNamed, Ident, Insert, Roots, Span, TokenStream, codegen, quote,
};
/// `active.field = Set(value)`, converting the plan's expression into the
/// declared field type.
pub(crate) fn set_field(roots: &Roots) -> impl Fn(&Ident, &Insert) -> TokenStream {
    let seaorm_root = roots.seaorm.clone();
    let core_root = roots.core.clone();
    move |field, insert| match insert {
        // Auth clocks arrive as UTC; the model column decides the wire type.
        Insert::Value(expr) if codegen::is_auth_timestamp(&field.to_string()) => quote! {
            active.#field = #seaorm_root::sea_orm::ActiveValue::Set(#core_root::entity::AuthTimestamp::from_utc(#expr));
        },
        Insert::Value(expr) => quote! {
            active.#field = #seaorm_root::sea_orm::ActiveValue::Set(::std::convert::Into::into(#expr));
        },
        Insert::Null | Insert::Default => quote! {
            active.#field = #seaorm_root::sea_orm::ActiveValue::Set(::std::option::Option::None);
        },
    }
}

/// The `new_active` body: an `ActiveModel` literal over every declared field.
pub(crate) fn new_active(role: EntityRole, fields: &FieldsNamed, roots: &Roots) -> TokenStream {
    let seaorm_root = &roots.seaorm;
    let core_root = &roots.core;
    let generated_id = &roots.id_generator;
    let assignments = codegen::insert_values(role, fields)
        .into_iter()
        .map(|(field, insert)| match insert {
            Insert::Value(expr) if codegen::is_auth_timestamp(&field.to_string()) => quote! {
                #field: #seaorm_root::sea_orm::ActiveValue::Set(#core_root::entity::AuthTimestamp::from_utc(#expr))
            },
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
                id.unwrap_or_else(|| #generated_id)
            ),
            #(#assignments,)*
        }
    }
}

/// Configured additional-field bindings and staging, keyed by wire and physical names.
pub(crate) fn additional_fields(fields: &[Field], roots: &Roots) -> TokenStream {
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

pub(crate) fn user_impl(
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

pub(crate) fn session_impl(
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

pub(crate) fn account_impl(
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
            fn oauth_token_columns() -> Option<[Self::Column; 3]> {
                Some([Column::AccessToken, Column::RefreshToken, Column::IdToken])
            }
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

pub(crate) fn verification_impl(ident: &Ident, fields: &FieldsNamed, roots: &Roots) -> TokenStream {
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
