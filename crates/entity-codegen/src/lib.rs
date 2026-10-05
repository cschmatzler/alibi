//! Backend-neutral code generation shared by the `AuthEntity` derives.
//!
//! The `SeaORM` and `SQLx` derives both generate the `Auth*` entity trait
//! implementations, the secondary-storage snapshot codec and the declared
//! additional-field output here, so the wire-visible accessor behavior of an
//! application model is identical whichever backend persists it.

use better_auth_schema_registry as registry;
pub use better_auth_schema_registry::EntityRole;
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{Data, DeriveInput, Fields, FieldsNamed, LitStr, Type};

/// Parsed `#[auth(...)]` container attributes.
#[derive(Clone, Debug)]
pub struct AuthAttributes {
    pub role: EntityRole,
    pub secondary_storage: bool,
    pub table: Option<String>,
    /// Application ID factory; returns a String compatible with existing columns.
    pub id_generator: Option<syn::Path>,
}

/// Parse the role, optional ID factory and secondary-storage configuration.
/// SQLx also permits an explicit table name.
///
/// # Errors
///
/// Returns a spanned error for an unknown key or role, or a missing role.
pub fn parse_auth_attributes(
    input: &DeriveInput,
    allow_table: bool,
) -> syn::Result<AuthAttributes> {
    let mut parsed = None;
    let mut secondary = false;
    let mut table = None;
    let mut id_generator = None;
    for attr in &input.attrs {
        if !attr.path().is_ident("auth") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("role") {
                let value = meta.value()?;
                let role: LitStr = value.parse()?;
                parsed = Some(match role.value().as_str() {
                    "user" => EntityRole::User,
                    "session" => EntityRole::Session,
                    "account" => EntityRole::Account,
                    "verification" => EntityRole::Verification,
                    _ => {
                        return Err(syn::Error::new_spanned(
                            role,
                            "unsupported auth role; expected user, session, account, or verification",
                        ));
                    }
                });
                Ok(())
            } else if meta.path.is_ident("id_generator") {
                let path = meta.value()?.parse::<LitStr>()?;
                id_generator = Some(path.parse()?);
                Ok(())
            } else if meta.path.is_ident("secondary_storage") {
                secondary = true;
                Ok(())
            } else if allow_table && meta.path.is_ident("table") {
                table = Some(meta.value()?.parse::<LitStr>()?.value());
                Ok(())
            } else if allow_table {
                Err(meta.error(
                    "expected `role = \"...\"`, `table = \"...\"`, `id_generator = \"...\"` or `secondary_storage`",
                ))
            } else {
                Err(meta.error("expected `role = \"...\"` or `secondary_storage`"))
            }
        })?;
    }

    parsed
        .map(|role| AuthAttributes {
            role,
            secondary_storage: secondary,
            table,
            id_generator,
        })
        .ok_or_else(|| {
            syn::Error::new_spanned(
                input,
                "missing #[auth(role = \"...\")] attribute for AuthEntity",
            )
        })
}

/// The derive input's named fields.
///
/// # Errors
///
/// Returns a spanned error for enums, unions, tuple and unit structs.
pub fn named_fields(input: &DeriveInput) -> syn::Result<&FieldsNamed> {
    match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => Ok(fields),
            Fields::Unnamed(_) | Fields::Unit => Err(syn::Error::new_spanned(
                &input.ident,
                "AuthEntity requires a struct with named fields",
            )),
        },
        Data::Enum(_) | Data::Union(_) => Err(syn::Error::new_spanned(
            &input.ident,
            "AuthEntity requires a struct",
        )),
    }
}

/// Require every core field of the role.
///
/// # Errors
///
/// Returns a spanned error naming the first missing core field.
pub fn validate_core_fields(
    input: &DeriveInput,
    role: EntityRole,
    fields: &FieldsNamed,
) -> syn::Result<()> {
    if let Some(missing) = registry::core_field_names(role)
        .iter()
        .find(|required| !has_field(fields, required))
    {
        return Err(syn::Error::new_spanned(
            &input.ident,
            format!("missing required auth field `{missing}` for this role"),
        ));
    }
    Ok(())
}

#[must_use]
pub fn has_field(fields: &FieldsNamed, name: &str) -> bool {
    fields
        .named
        .iter()
        .any(|field| field.ident.as_ref().is_some_and(|ident| ident == name))
}

#[must_use]
pub fn is_option(ty: &Type) -> bool {
    matches!(ty, Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "Option"))
}

/// Whether the named field exists with an `Option` type.
#[must_use]
pub fn optional_field(fields: &FieldsNamed, name: &str) -> bool {
    fields.named.iter().any(|field| {
        field.ident.as_ref().is_some_and(|ident| ident == name) && is_option(&field.ty)
    })
}

/// Whether a field name is a core or plugin field of the role.
#[must_use]
pub fn is_known_field(role: EntityRole, name: &Ident) -> bool {
    registry::core_field_names(role)
        .iter()
        .chain(registry::plugin_field_names(role).iter())
        .any(|known| name == known)
}

/// The `lowerCamelCase` wire name of a snake-case Rust field.
#[must_use]
pub fn camel_case(name: &Ident) -> String {
    let identifier = name.to_string();
    let text = identifier.trim_start_matches("r#");
    let mut components = text.split('_');
    let mut camel = components.next().unwrap_or_default().to_owned();
    for component in components {
        let mut letters = component.chars();
        if let Some(first) = letters.next() {
            camel.extend(first.to_uppercase());
        }
        camel.extend(letters);
    }
    camel
}

/// A model field with its wire name and explicitly renamed physical column.
#[derive(Clone)]
pub struct EntityField {
    pub ident: Ident,
    pub camel: String,
    /// The physical column when it is explicitly renamed.
    pub physical: Option<String>,
}

/// Generate `fn additional_fields(&self)`: undeclared fields and nullable
/// username values reach configured output transforms under their wire and
/// physical names.
#[must_use]
pub fn additional_output(
    role: EntityRole,
    fields: &[EntityField],
    core_root: &TokenStream,
) -> TokenStream {
    let mut output = Vec::new();
    for field in fields {
        let name = &field.ident;
        let camel = &field.camel;
        // Nullable username columns must reach configured output transforms as
        // actual stored values, even though canonical wire DTOs omit None.
        // Only declared model fields qualify; missing plugin columns stay absent.
        let physical_output = !is_known_field(role, name)
            || matches!(role, EntityRole::User)
                && (name == "username" || name == "display_username");
        if physical_output {
            output.push(quote! {
                if let Ok(value) = #core_root::utils::json::to_value(&self.#name) {
                    let _ = fields.insert(#camel.into(), value);
                }
            });
        }
        if let Some(physical) = field
            .physical
            .as_ref()
            .filter(|physical| *physical != camel)
            && physical_output
        {
            output.push(quote! {
                if let Ok(value) = #core_root::utils::json::to_value(&self.#name) {
                    let _ = fields.insert(#physical.into(), value);
                }
            });
        }
    }
    quote! {
        fn additional_fields(&self) -> #core_root::field_policy::FieldOutput {
            let mut fields = #core_root::field_policy::FieldOutput::new();
            #(#output)*
            fields
        }
    }
}

/// Generate the secondary-storage snapshot codec over every model field.
#[must_use]
pub fn secondary_codec(fields: &FieldsNamed, core_root: &TokenStream) -> TokenStream {
    let names: Vec<_> = fields
        .named
        .iter()
        .filter_map(|field| field.ident.as_ref())
        .collect();
    let keys: Vec<_> = names.iter().map(|name| name.to_string()).collect();
    quote! {
        fn secondary_snapshot(&self) -> #core_root::AuthResult<::serde_json::Value> {
            let mut snapshot = ::serde_json::Map::new();
            #(drop(snapshot.insert(#keys.to_owned(), ::serde_json::to_value(&self.#names)?));)*
            Ok(::serde_json::Value::Object(snapshot))
        }
        fn from_secondary_snapshot(snapshot: ::serde_json::Value) -> #core_root::AuthResult<Self> {
            let ::serde_json::Value::Object(mut fields) = snapshot else {
                return Err(#core_root::AuthError::internal("Invalid secondary model snapshot"));
            };
            Ok(Self {
                #(#names: ::serde_json::from_value(fields.remove(#keys).ok_or_else(||
                    #core_root::AuthError::internal("Incomplete secondary model snapshot"))?)?,)*
            })
        }
    }
}

/// `impl AuthUser`: absent plugin fields return their defaults.
#[expect(
    clippy::too_many_lines,
    reason = "Keep the generated AuthUser implementation together as one quoted trait contract"
)]
#[must_use]
pub fn auth_user_impl(
    ident: &Ident,
    fields: &FieldsNamed,
    entity_fields: &[EntityField],
    secondary: bool,
    core_root: &TokenStream,
) -> TokenStream {
    let has = |name: &str| has_field(fields, name);
    let optional = |name: &str| optional_field(fields, name);
    let secondary_codec = if secondary {
        secondary_codec(fields, core_root)
    } else {
        quote! {}
    };
    let additional_output = additional_output(EntityRole::User, entity_fields, core_root);
    let string_getter = |name: &str| {
        let field = Ident::new(name, Span::call_site());
        if optional(name) {
            quote! { fn #field(&self) -> Option<&str> { self.#field.as_deref() } }
        } else {
            quote! { fn #field(&self) -> Option<&str> { Some(&self.#field) } }
        }
    };
    let email_impl = string_getter("email");
    let name_impl = string_getter("name");
    let username_impl = if has("username") {
        quote! { fn username(&self) -> Option<&str> { self.username.as_deref() } }
    } else {
        quote! { fn username(&self) -> Option<&str> { None } }
    };
    let display_username_impl = if has("display_username") {
        quote! { fn display_username(&self) -> Option<&str> { self.display_username.as_deref() } }
    } else {
        quote! { fn display_username(&self) -> Option<&str> { None } }
    };
    let two_factor_impl = if has("two_factor_enabled") {
        if optional("two_factor_enabled") {
            quote! {
                fn two_factor_enabled(&self) -> bool { self.two_factor_enabled.unwrap_or(false) }
                fn two_factor_enabled_value(&self) -> Option<bool> { self.two_factor_enabled }
            }
        } else {
            quote! { fn two_factor_enabled(&self) -> bool { self.two_factor_enabled } }
        }
    } else {
        quote! {
            fn two_factor_enabled(&self) -> bool { false }
            fn two_factor_enabled_value(&self) -> Option<bool> { None }
        }
    };
    let role_impl = if has("role") {
        quote! { fn role(&self) -> Option<&str> { self.role.as_deref() } }
    } else {
        quote! { fn role(&self) -> Option<&str> { None } }
    };
    let banned_impl = if has("banned") {
        if optional("banned") {
            quote! {
                fn banned(&self) -> bool { self.banned.unwrap_or(false) }
                fn banned_value(&self) -> Option<bool> { self.banned }
            }
        } else {
            quote! { fn banned(&self) -> bool { self.banned } }
        }
    } else {
        quote! {
            fn banned(&self) -> bool { false }
            fn banned_value(&self) -> Option<bool> { None }
        }
    };
    let ban_reason_impl = if has("ban_reason") {
        quote! { fn ban_reason(&self) -> Option<&str> { self.ban_reason.as_deref() } }
    } else {
        quote! { fn ban_reason(&self) -> Option<&str> { None } }
    };
    let ban_expires_impl = if has("ban_expires") {
        quote! { fn ban_expires(&self) -> Option<::chrono::DateTime<::chrono::Utc>> { #core_root::entity::AuthTimestamp::into_utc(self.ban_expires) } }
    } else {
        quote! { fn ban_expires(&self) -> Option<::chrono::DateTime<::chrono::Utc>> { None } }
    };
    let metadata_impl = if has("metadata") {
        quote! { fn metadata(&self) -> &::serde_json::Value { &self.metadata } }
    } else {
        quote! { fn metadata(&self) -> &::serde_json::Value {
            static EMPTY: ::std::sync::LazyLock<::serde_json::Value> =
                ::std::sync::LazyLock::new(|| ::serde_json::json!({}));
            &EMPTY
        } }
    };
    let mut optional_user_getters = Vec::new();
    for name in ["is_anonymous", "phone_number_verified"] {
        if has(name) {
            let field = Ident::new(name, Span::call_site());
            optional_user_getters.push(quote! { fn #field(&self) -> Option<bool> { self.#field } });
        }
    }
    for name in ["phone_number", "last_login_method"] {
        if has(name) {
            let field = Ident::new(name, Span::call_site());
            optional_user_getters
                .push(quote! { fn #field(&self) -> Option<&str> { self.#field.as_deref() } });
        }
    }
    quote! {
        impl #core_root::entity::AuthUser for #ident {
            #secondary_codec
            #additional_output
            fn id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.id) }
            #email_impl
            #name_impl
            fn email_verified(&self) -> bool { self.email_verified }
            fn image(&self) -> Option<&str> { self.image.as_deref() }
            fn created_at(&self) -> ::chrono::DateTime<::chrono::Utc> { #core_root::entity::AuthTimestamp::into_utc(self.created_at) }
            fn updated_at(&self) -> ::chrono::DateTime<::chrono::Utc> { #core_root::entity::AuthTimestamp::into_utc(self.updated_at) }
            #username_impl
            #display_username_impl
            #two_factor_impl
            #role_impl
            #banned_impl
            #ban_reason_impl
            #ban_expires_impl
            #metadata_impl
            #(#optional_user_getters)*
        }
    }
}

/// `impl AuthSession`: absent plugin fields return their defaults.
#[must_use]
pub fn auth_session_impl(
    ident: &Ident,
    fields: &FieldsNamed,
    entity_fields: &[EntityField],
    secondary: bool,
    core_root: &TokenStream,
) -> TokenStream {
    let has = |name: &str| has_field(fields, name);
    let secondary_codec = if secondary {
        secondary_codec(fields, core_root)
    } else {
        quote! {}
    };
    let additional_output = additional_output(EntityRole::Session, entity_fields, core_root);
    let impersonated_by_impl = if has("impersonated_by") {
        quote! { fn impersonated_by(&self) -> Option<&str> { self.impersonated_by.as_deref() } }
    } else {
        quote! { fn impersonated_by(&self) -> Option<&str> { None } }
    };
    let active_org_impl = if has("active_organization_id") {
        quote! { fn active_organization_id(&self) -> Option<&str> { self.active_organization_id.as_deref() } }
    } else {
        quote! { fn active_organization_id(&self) -> Option<&str> { None } }
    };
    let active_team_impl = if has("active_team_id") {
        quote! { fn active_team_id(&self) -> Option<&str> { self.active_team_id.as_deref() } }
    } else {
        quote! {}
    };
    quote! {
        impl #core_root::entity::AuthSession for #ident {
            #secondary_codec
            #additional_output
            fn id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.id) }
            fn expires_at(&self) -> ::chrono::DateTime<::chrono::Utc> { #core_root::entity::AuthTimestamp::into_utc(self.expires_at) }
            fn token(&self) -> &str { &self.token }
            fn created_at(&self) -> ::chrono::DateTime<::chrono::Utc> { #core_root::entity::AuthTimestamp::into_utc(self.created_at) }
            fn updated_at(&self) -> ::chrono::DateTime<::chrono::Utc> { #core_root::entity::AuthTimestamp::into_utc(self.updated_at) }
            fn ip_address(&self) -> Option<&str> { self.ip_address.as_deref() }
            fn user_agent(&self) -> Option<&str> { self.user_agent.as_deref() }
            fn user_id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.user_id) }
            #impersonated_by_impl
            #active_org_impl
            #active_team_impl
            fn active(&self) -> bool { self.active }
        }
    }
}

/// `impl AuthAccount`: account fields are all core fields.
#[must_use]
pub fn auth_account_impl(
    ident: &Ident,
    entity_fields: &[EntityField],
    core_root: &TokenStream,
) -> TokenStream {
    let additional_output = additional_output(EntityRole::Account, entity_fields, core_root);
    quote! {
        impl #core_root::entity::AuthAccount for #ident {
            #additional_output
            fn id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.id) }
            fn account_id(&self) -> &str { &self.account_id }
            fn provider_id(&self) -> &str { &self.provider_id }
            fn user_id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.user_id) }
            fn access_token(&self) -> Option<&str> { self.access_token.as_deref() }
            fn refresh_token(&self) -> Option<&str> { self.refresh_token.as_deref() }
            fn id_token(&self) -> Option<&str> { self.id_token.as_deref() }
            fn access_token_expires_at(&self) -> Option<::chrono::DateTime<::chrono::Utc>> { #core_root::entity::AuthTimestamp::into_utc(self.access_token_expires_at) }
            fn refresh_token_expires_at(&self) -> Option<::chrono::DateTime<::chrono::Utc>> { #core_root::entity::AuthTimestamp::into_utc(self.refresh_token_expires_at) }
            fn scope(&self) -> Option<&str> { self.scope.as_deref() }
            fn password(&self) -> Option<&str> { self.password.as_deref() }
            fn created_at(&self) -> ::chrono::DateTime<::chrono::Utc> { #core_root::entity::AuthTimestamp::into_utc(self.created_at) }
            fn updated_at(&self) -> ::chrono::DateTime<::chrono::Utc> { #core_root::entity::AuthTimestamp::into_utc(self.updated_at) }
        }
    }
}

/// `impl AuthVerification`: verification fields are all core fields.
#[must_use]
pub fn auth_verification_impl(ident: &Ident, core_root: &TokenStream) -> TokenStream {
    quote! {
        impl #core_root::entity::AuthVerification for #ident {
            fn id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.id) }
            fn identifier(&self) -> &str { &self.identifier }
            fn value(&self) -> &str { &self.value }
            fn expires_at(&self) -> ::chrono::DateTime<::chrono::Utc> { #core_root::entity::AuthTimestamp::into_utc(self.expires_at) }
            fn created_at(&self) -> ::chrono::DateTime<::chrono::Utc> { #core_root::entity::AuthTimestamp::into_utc(self.created_at) }
            fn updated_at(&self) -> ::chrono::DateTime<::chrono::Utc> { #core_root::entity::AuthTimestamp::into_utc(self.updated_at) }
        }
    }
}

/// What a fresh row stores in one declared field.
#[derive(Clone)]
pub enum Insert {
    /// An expression over the role's creation input, `now` and (for
    /// sessions) `token`, convertible into the field type with `Into`.
    Value(TokenStream),
    /// SQL `NULL` of the field's optional type.
    Null,
    /// Omitted, so the database default applies.
    Default,
}

/// The value a fresh row stores in every declared field except `id`, in
/// declaration order. Each backend binds its own identifier type.
#[must_use]
pub fn insert_values(role: EntityRole, fields: &FieldsNamed) -> Vec<(Ident, Insert)> {
    let has = |name: &str| has_field(fields, name);
    let optional = |name: &str| optional_field(fields, name);
    let mut values: Vec<(&str, Insert)> = Vec::new();
    let mut value =
        |name: &'static str, expr: TokenStream| values.push((name, Insert::Value(expr)));
    match role {
        EntityRole::User => {
            for name in ["email", "name"] {
                let field = Ident::new(name, Span::call_site());
                value(
                    name,
                    if optional(name) {
                        quote! { create_user.#field }
                    } else {
                        quote! { create_user.#field.unwrap_or_default() }
                    },
                );
            }
            value("image", quote! { create_user.image });
            value(
                "email_verified",
                quote! { create_user.email_verified.unwrap_or(false) },
            );
            value(
                "created_at",
                quote! { create_user.created_at.unwrap_or(now) },
            );
            value(
                "updated_at",
                quote! { create_user.updated_at.unwrap_or(now) },
            );
            for name in [
                "username",
                "display_username",
                "role",
                "is_anonymous",
                "phone_number",
                "phone_number_verified",
                "last_login_method",
            ] {
                let field = Ident::new(name, Span::call_site());
                value(name, quote! { create_user.#field });
            }
            // Flags that may be nullable columns keep the caller's `Option`;
            // non-null columns default to `false`.
            for name in ["two_factor_enabled", "banned"] {
                let field = Ident::new(name, Span::call_site());
                if optional(name) {
                    value(name, quote! { create_user.#field });
                } else {
                    value(name, quote! { create_user.#field.unwrap_or(false) });
                }
            }
            value(
                "metadata",
                quote! { create_user.metadata.unwrap_or(::serde_json::json!({})) },
            );
            values.push(("ban_reason", Insert::Null));
            values.push(("ban_expires", Insert::Null));
        }
        EntityRole::Session => {
            value("token", quote! { token });
            value("created_at", quote! { now });
            value("updated_at", quote! { now });
            value("active", quote! { true });
            for name in [
                "user_id",
                "expires_at",
                "ip_address",
                "user_agent",
                "impersonated_by",
                "active_organization_id",
                "active_team_id",
            ] {
                let field = Ident::new(name, Span::call_site());
                value(name, quote! { create_session.#field });
            }
        }
        EntityRole::Account => {
            value("created_at", quote! { now });
            value("updated_at", quote! { now });
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
                value(name, quote! { create_account.#field });
            }
        }
        EntityRole::Verification => {
            value("created_at", quote! { now });
            value("updated_at", quote! { now });
            for name in ["identifier", "value", "expires_at"] {
                let field = Ident::new(name, Span::call_site());
                value(name, quote! { verification.#field });
            }
        }
    }
    fields
        .named
        .iter()
        .filter_map(|field| field.ident.clone())
        .filter(|ident| ident != "id")
        .map(|ident| {
            let insert = values
                .iter()
                .find(|(name, _)| ident == name && has(name))
                .map_or(Insert::Default, |(_, insert)| insert.clone());
            (ident, insert)
        })
        .collect()
}

/// Renders `field = value` on the active row, where `Insert::Value` is
/// convertible into the field type with `Into`. `Insert::Default` is never
/// passed.
pub type SetField<'a> = &'a dyn Fn(&Ident, &Insert) -> TokenStream;

/// The `apply_update` body of the role over `update` and `now`: every field
/// present in `update` is written; absent plugin fields are skipped.
#[must_use]
pub fn update_statements(role: EntityRole, fields: &FieldsNamed, set: SetField<'_>) -> TokenStream {
    let has = |name: &str| has_field(fields, name);
    let ident = |name: &str| Ident::new(name, Span::call_site());
    // `if let Some(x) = update.x { set(x, <wrap>(x)) }`
    let some = |name: &str, wrap: fn(&Ident) -> TokenStream| {
        let field = ident(name);
        let value = wrap(&field);
        let assign = set(&field, &Insert::Value(value));
        quote! { if let ::std::option::Option::Some(#field) = update.#field { #assign } }
    };
    let wrapped = |field: &Ident| quote! { ::std::option::Option::Some(#field) };
    let direct = |field: &Ident| quote! { #field };
    let mut statements = Vec::new();
    match role {
        EntityRole::User => {
            for name in ["email", "name", "image"] {
                statements.push(some(
                    name,
                    if optional_field(fields, name) {
                        wrapped
                    } else {
                        direct
                    },
                ));
            }
            statements.push(some("email_verified", direct));
            for name in ["username", "display_username", "role"] {
                if has(name) {
                    statements.push(some(name, wrapped));
                }
            }
            for name in ["two_factor_enabled", "metadata"] {
                if has(name) {
                    statements.push(some(name, direct));
                }
            }
            if has("banned") && has("ban_reason") && has("ban_expires") {
                let banned = set(&ident("banned"), &Insert::Value(quote! { banned }));
                let clear_reason = set(&ident("ban_reason"), &Insert::Null);
                let clear_expires = set(&ident("ban_expires"), &Insert::Null);
                let reason = set(
                    &ident("ban_reason"),
                    &Insert::Value(quote! { ::std::option::Option::Some(ban_reason) }),
                );
                let expires = set(
                    &ident("ban_expires"),
                    &Insert::Value(quote! { ban_expires }),
                );
                statements.push(quote! {
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
                statements.push(some("banned", direct));
            }
            for name in ["is_anonymous", "phone_number_verified"] {
                if has(name) {
                    statements.push(some(name, wrapped));
                }
            }
            for name in ["phone_number", "last_login_method"] {
                if has(name) {
                    statements.push(some(name, direct));
                }
            }
        }
        EntityRole::Account => {
            for (index, name) in ["access_token", "refresh_token", "id_token"]
                .into_iter()
                .enumerate()
            {
                let clear = set(&ident(name), &Insert::Null);
                statements.push(quote! { if update.provider_token_nulls[#index] { #clear } });
            }
            for name in [
                "access_token",
                "refresh_token",
                "id_token",
                "access_token_expires_at",
                "refresh_token_expires_at",
                "scope",
                "password",
            ] {
                statements.push(some(name, wrapped));
            }
        }
        EntityRole::Session | EntityRole::Verification => {}
    }
    let updated_at = set(&ident("updated_at"), &Insert::Value(quote! { now }));
    quote! { #(#statements)* #updated_at }
}

/// Auth date fields whose mutations arrive in the core UTC representation.
#[must_use]
pub fn is_auth_timestamp(name: &str) -> bool {
    matches!(
        name,
        "created_at"
            | "updated_at"
            | "expires_at"
            | "ban_expires"
            | "access_token_expires_at"
            | "refresh_token_expires_at"
    )
}

/// Generate an application-selected auth identifier, retaining UUID defaults.
#[must_use]
pub fn generated_id(attributes: &AuthAttributes, core_root: &TokenStream) -> TokenStream {
    attributes.id_generator.as_ref().map_or_else(
        || quote! { #core_root::uuid::Uuid::new_v4().to_string() },
        |generator| quote! { #generator() },
    )
}
