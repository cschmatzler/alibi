use super::*;
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
                let expression = if optional(name) {
                    quote! { create_user.#field }
                } else {
                    quote! { create_user.#field.unwrap_or_default() }
                };
                value(name, expression);
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
                let wrap = if optional_field(fields, name) {
                    wrapped
                } else {
                    direct
                };
                statements.push(some(name, wrap));
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

/// Generate an application-selected auth identifier, retaining UUID defaults.
#[must_use]
pub fn generated_id(attributes: &AuthAttributes, core_root: &TokenStream) -> TokenStream {
    attributes.id_generator.as_ref().map_or_else(
        || quote! { #core_root::uuid::Uuid::new_v4().to_string() },
        |generator| quote! { #generator() },
    )
}
