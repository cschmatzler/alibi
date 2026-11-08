use crate::{EntityField, EntityRole, additional_output, has_field, optional_field};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::FieldsNamed;

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
    adapter_output: &TokenStream,
) -> TokenStream {
    let has = |name: &str| has_field(fields, name);
    let optional = |name: &str| optional_field(fields, name);
    let secondary_codec = if secondary {
        crate::user_secondary_codec(fields, entity_fields, core_root)
    } else {
        quote! {}
    };
    let additional_output = additional_output(EntityRole::User, entity_fields, core_root);
    let text_getter = |name: &str| {
        let field = Ident::new(name, Span::call_site());
        if optional(name) {
            quote! { fn #field(&self) -> Option<&str> { self.#field.as_deref() } }
        } else {
            quote! { fn #field(&self) -> Option<&str> { Some(self.#field.as_str()) } }
        }
    };
    let email_impl = text_getter("email");
    let name_impl = text_getter("name");
    let username_impl = optional_str_getter(fields, "username");
    let display_username_impl = optional_str_getter(fields, "display_username");
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
    let role_impl = optional_str_getter(fields, "role");
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
    let ban_reason_impl = optional_str_getter(fields, "ban_reason");
    let ban_expires_impl = if has("ban_expires") {
        quote! { fn ban_expires(&self) -> Option<::chrono::DateTime<::chrono::Utc>> { #core_root::entity::AuthTimestamp::into_utc(self.ban_expires) } }
    } else {
        quote! { fn ban_expires(&self) -> Option<::chrono::DateTime<::chrono::Utc>> { None } }
    };
    let metadata_impl = if has("metadata") {
        if optional("metadata") {
            quote! { fn metadata(&self) -> #core_root::utils::json::JsValue {
                self.metadata.as_ref().map_or(#core_root::utils::json::JsValue::Null, ::std::convert::Into::into)
            } }
        } else {
            quote! { fn metadata(&self) -> #core_root::utils::json::JsValue { (&self.metadata).into() } }
        }
    } else {
        quote! { fn metadata(&self) -> #core_root::utils::json::JsValue {
            #core_root::utils::json::JsValue::Object(Default::default())
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
            #adapter_output
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
    adapter_output: &TokenStream,
) -> TokenStream {
    let has = |name: &str| has_field(fields, name);
    let secondary_codec = if secondary {
        let codec = crate::secondary::session_secondary_codec(fields, entity_fields, core_root);
        let created_at_field = fields
            .named
            .iter()
            .find(|field| {
                field
                    .ident
                    .as_ref()
                    .is_some_and(|name| name == "created_at")
            })
            .expect("validated session created_at field");
        let created_at_type = &created_at_field.ty;
        let created_at_key = &entity_fields
            .iter()
            .find(|field| field.ident == "created_at")
            .expect("validated session created_at metadata")
            .camel;
        quote! {
            #codec
            fn secondary_snapshot_for_creation(
                &self,
                created_at: ::chrono::DateTime<::chrono::Utc>,
            ) -> #core_root::AuthResult<#core_root::utils::json::JsValue> {
                let mut model = self.clone();
                model.created_at = <#created_at_type as #core_root::entity::AuthTimestamp>::from_utc(created_at);
                model.secondary_snapshot()
            }
            fn secondary_snapshot_for_creation_with_native_output(
                &self,
                created_at: ::chrono::DateTime<::chrono::Utc>,
                native: &#core_root::AdapterOutput,
            ) -> #core_root::AuthResult<#core_root::utils::json::JsValue> {
                let mut snapshot = self.secondary_snapshot_with_native_output(native)?;
                snapshot[#created_at_key] = #core_root::utils::json::to_js_value(
                    &<#created_at_type as #core_root::entity::AuthTimestamp>::from_utc(created_at),
                )?;
                Ok(snapshot)
            }
        }
    } else {
        quote! {}
    };
    let additional_output = additional_output(EntityRole::Session, entity_fields, core_root);
    let impersonated_by_impl = optional_str_getter(fields, "impersonated_by");
    let active_org_impl = optional_str_getter(fields, "active_organization_id");
    let active_team_impl = if has("active_team_id") {
        quote! { fn active_team_id(&self) -> Option<&str> { self.active_team_id.as_deref() } }
    } else {
        quote! {}
    };
    quote! {
        impl #core_root::entity::AuthSession for #ident {
            #secondary_codec
            #additional_output
            #adapter_output
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
        }
    }
}

/// `impl AuthAccount`: account fields are all core fields.
#[must_use]
pub fn auth_account_impl(
    ident: &Ident,
    entity_fields: &[EntityField],
    core_root: &TokenStream,
    adapter_output: &TokenStream,
) -> TokenStream {
    let additional_output = additional_output(EntityRole::Account, entity_fields, core_root);
    quote! {
        impl #core_root::entity::AuthAccount for #ident {
            #additional_output
            #adapter_output
            fn id(&self) -> ::std::borrow::Cow<'_, str> { ::std::borrow::Cow::Borrowed(&self.id) }
            fn account_id(&self) -> #core_root::utils::json::JsString { self.account_id.clone().into() }
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

/// `fn name(&self) -> Option<&str>` over an optional text field, or `None` when
/// the model does not declare the field.
fn optional_str_getter(fields: &FieldsNamed, name: &str) -> TokenStream {
    let field = Ident::new(name, Span::call_site());
    if has_field(fields, name) {
        quote! { fn #field(&self) -> Option<&str> { self.#field.as_deref() } }
    } else {
        quote! { fn #field(&self) -> Option<&str> { None } }
    }
}
