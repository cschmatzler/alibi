use proc_macro2::TokenStream;
use quote::quote;
use syn::FieldsNamed;

/// Generate the secondary-storage snapshot codec over every model field.
#[must_use]
pub fn secondary_codec(fields: &FieldsNamed, core_root: &TokenStream) -> TokenStream {
    let names: Vec<_> = fields
        .named
        .iter()
        .filter_map(|field| field.ident.as_ref())
        .collect();
    let keys: Vec<_> = names.iter().map(std::string::ToString::to_string).collect();
    quote! {
        fn secondary_snapshot(&self) -> #core_root::AuthResult<#core_root::utils::json::JsValue> {
            let mut snapshot = #core_root::utils::json::JsObject::new();
            #(_ = snapshot.insert(#keys.into(), #core_root::utils::json::to_js_value(&self.#names)?);)*
            Ok(#core_root::utils::json::JsValue::Object(snapshot))
        }
        fn from_secondary_snapshot(snapshot: #core_root::utils::json::JsValue) -> #core_root::AuthResult<Self> {
            let #core_root::utils::json::JsValue::Object(mut fields) = snapshot else {
                return Err(#core_root::AuthError::internal("Invalid secondary model snapshot"));
            };
            Ok(Self {
                #(#names: #core_root::utils::json::from_value(fields.shift_remove(#keys).ok_or_else(||
                    #core_root::AuthError::internal("Incomplete secondary model snapshot"))?)?,)*
            })
        }
    }
}

/// Encode logical session properties independently of Rust and SQL column names.
#[must_use]
pub(crate) fn session_secondary_codec(
    fields: &FieldsNamed,
    entity_fields: &[crate::EntityField],
    core_root: &TokenStream,
) -> TokenStream {
    let names: Vec<_> = fields
        .named
        .iter()
        .filter_map(|field| field.ident.as_ref())
        .collect();
    let key = |ident: &syn::Ident| {
        entity_fields
            .iter()
            .find(|field| field.ident == *ident)
            .expect("validated session field metadata")
            .camel
            .clone()
    };
    let keys: Vec<_> = names.iter().map(|ident| key(ident)).collect();
    let decode = fields.named.iter().map(|field| {
        let name = field.ident.as_ref().expect("named field");
        let key = key(name);
        if crate::is_option(&field.ty) {
            quote! { #name: fields.shift_remove(#key).map(#core_root::utils::json::from_value).transpose()?.flatten(), }
        } else {
            quote! { #name: #core_root::utils::json::from_value(fields.shift_remove(#key).ok_or_else(||
                #core_root::AuthError::internal("Incomplete secondary session snapshot"))?)?, }
        }
    });
    let absent = entity_fields.iter().map(|field| {
        let wire = &field.camel;
        quote! { if !fields.contains_key(#wire) { output.insert(#wire.to_owned(), None); } }
    });
    quote! {
        fn secondary_snapshot(&self) -> #core_root::AuthResult<#core_root::utils::json::JsValue> {
            let mut snapshot = #core_root::utils::json::JsObject::new();
            #(_ = snapshot.insert(#keys.into(), #core_root::utils::json::to_js_value(&self.#names)?);)*
            Ok(#core_root::utils::json::JsValue::Object(snapshot))
        }
        fn from_secondary_snapshot(snapshot: #core_root::utils::json::JsValue) -> #core_root::AuthResult<Self> {
            let #core_root::utils::json::JsValue::Object(mut fields) = snapshot else {
                return Err(#core_root::AuthError::internal("Invalid secondary session snapshot"));
            };
            Ok(Self { #(#decode)* })
        }
        fn output_from_secondary_snapshot(snapshot: #core_root::utils::json::JsValue) -> #core_root::AuthResult<#core_root::AdapterOutput> {
            let #core_root::utils::json::JsValue::Object(fields) = snapshot else {
                return Err(#core_root::AuthError::internal("Invalid secondary session snapshot"));
            };
            let mut output = #core_root::AdapterOutput::default();
            for (key, value) in &fields {
                output.insert_js(key.clone(), value.clone());
            }
            #(#absent)*
            Ok(output)
        }
        fn secondary_snapshot_with_native_output(
            &self,
            native: &#core_root::AdapterOutput,
        ) -> #core_root::AuthResult<#core_root::utils::json::JsValue> {
            let #core_root::utils::json::JsValue::Object(mut snapshot) = self.secondary_snapshot()? else {
                return Err(#core_root::AuthError::internal("Invalid secondary session snapshot"));
            };
            for (name, value) in native.values() {
                if value.is_undefined() {
                    _ = snapshot.shift_remove(name);
                } else {
                    _ = snapshot.insert(name.clone(), value.clone());
                }
            }
            Ok(#core_root::utils::json::JsValue::Object(snapshot))
        }
    }
}

/// Generate a user-only codec retaining native boolean/date output separately
/// from the typed model used by authorization code.
#[must_use]
pub fn user_secondary_codec(
    fields: &FieldsNamed,
    entity_fields: &[crate::EntityField],
    core_root: &TokenStream,
) -> TokenStream {
    let mut overlay = Vec::new();
    let mut capture = Vec::new();
    let mut normalize = Vec::new();
    for (wire, key, date) in [
        ("emailVerified", "email_verified", false),
        ("banned", "banned", false),
        ("twoFactorEnabled", "two_factor_enabled", false),
        ("isAnonymous", "is_anonymous", false),
        ("phoneNumberVerified", "phone_number_verified", false),
        ("createdAt", "created_at", true),
        ("updatedAt", "updated_at", true),
        ("banExpires", "ban_expires", true),
    ] {
        let Some(field) = fields
            .named
            .iter()
            .find(|field| field.ident.as_ref().is_some_and(|ident| ident == key))
        else {
            continue;
        };
        let optional = crate::optional_field(fields, key);
        overlay.push(quote! {
            if native.field_is_undefined(#wire) {
                _ = snapshot.shift_remove(#key);
            } else if let Some(value) = native.values().get(#wire) {
                _ = snapshot.insert(#key.into(), value.clone());
            }
        });
        capture.push(quote! {
            native.insert(#wire.to_owned(), source.get(#key).cloned());
        });
        let conversion = if date {
            let ty = &field.ty;
            let utc = if optional {
                quote! { Some(typed) }
            } else {
                quote! { typed }
            };
            quote! {
                let millis = match value {
                    #core_root::utils::json::JsValue::Date(value) => Some(value.timestamp_millis()),
                    #core_root::utils::json::JsValue::String(value) => value.as_str().and_then(#core_root::utils::datetime::parse_date_millis),
                    #core_root::utils::json::JsValue::Number(value) => Some(*value)
                        .filter(|value| value.abs() <= 8_640_000_000_000_000.0)
                        .map(|value| value.trunc() as i64),
                    #core_root::utils::json::JsValue::Bool(value) => Some(i64::from(*value)),
                    #core_root::utils::json::JsValue::Null => Some(0),
                    _ => None,
                };
                // Unrepresentable native dates remain in the retained output;
                // the typed model alone cannot represent Invalid Date.
                let typed = millis.and_then(::chrono::DateTime::<::chrono::Utc>::from_timestamp_millis)
                    .unwrap_or(::chrono::DateTime::<::chrono::Utc>::UNIX_EPOCH);
                *value = #core_root::utils::json::to_js_value(&<#ty as #core_root::entity::AuthTimestamp>::from_utc(#utc))?;
            }
        } else {
            quote! {
                *value = #core_root::utils::json::JsValue::Bool(#core_root::utils::json::JsValue::from(value.clone()).is_truthy());
            }
        };
        normalize.push(quote! {
            if let Some(value) = fields.get_mut(#key) {
                if !(#optional && value.is_null()) {
                    #conversion
                }
            }
        });
    }
    for field in entity_fields {
        let key = field.ident.to_string();
        if key == "id" {
            continue;
        }
        let optional = crate::optional_field(fields, &key);
        let text = fields.named.iter().find(|candidate| candidate.ident.as_ref() == Some(&field.ident))
            .is_some_and(|field| {
                let syn::Type::Path(path) = &field.ty else { return false };
                let Some(segment) = path.path.segments.last() else { return false };
                if segment.ident == "String" {
                    return true;
                }
                if segment.ident != "Option" {
                    return false;
                }
                let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else { return false };
                matches!(arguments.args.first(), Some(syn::GenericArgument::Type(syn::Type::Path(inner)))
                    if inner.path.segments.last().is_some_and(|segment| segment.ident == "String"))
            });
        if optional || key == "metadata" {
            normalize.push(quote! {
                if !fields.contains_key(#key) {
                    _ = fields.insert(#key.into(), #core_root::utils::json::JsValue::Null);
                }
            });
        }
        if text {
            let surrogate = if optional {
                quote! { #core_root::utils::json::JsValue::Null }
            } else {
                quote! { #core_root::utils::json::JsValue::String(Default::default()) }
            };
            normalize.push(quote! {
                if fields.get(#key).is_none_or(|value| value.as_str().is_none()) {
                    _ = fields.insert(#key.into(), #surrogate);
                }
            });
        }
        if !(optional || text || key == "metadata")
            || matches!(
                key.as_str(),
                "email_verified"
                    | "banned"
                    | "two_factor_enabled"
                    | "is_anonymous"
                    | "phone_number_verified"
                    | "created_at"
                    | "updated_at"
                    | "ban_expires"
            )
        {
            continue;
        }
        let wire = &field.camel;
        overlay.push(quote! {
            if native.field_is_undefined(#wire) {
                _ = snapshot.shift_remove(#key);
            } else if let Some(value) = native.values().get(#wire) {
                _ = snapshot.insert(#key.into(), value.clone());
            }
        });
        capture.push(quote! {
            native.insert(#wire.to_owned(), source.get(#key).cloned());
        });
    }
    let names: Vec<_> = fields
        .named
        .iter()
        .filter_map(|field| field.ident.as_ref())
        .collect();
    let keys: Vec<_> = names.iter().map(std::string::ToString::to_string).collect();
    quote! {
        fn secondary_snapshot(&self) -> #core_root::AuthResult<#core_root::utils::json::JsValue> {
            let mut snapshot = #core_root::utils::json::JsObject::new();
            #(_ = snapshot.insert(#keys.into(), #core_root::utils::json::to_js_value(&self.#names)?);)*
            Ok(#core_root::utils::json::JsValue::Object(snapshot))
        }
        fn secondary_snapshot_with_native_output(
            &self,
            native: &#core_root::AdapterOutput,
        ) -> #core_root::AuthResult<#core_root::utils::json::JsValue> {
            let #core_root::utils::json::JsValue::Object(mut snapshot) = self.secondary_snapshot()? else {
                return Err(#core_root::AuthError::internal("Invalid secondary user snapshot"));
            };
            #(#overlay)*
            Ok(#core_root::utils::json::JsValue::Object(snapshot))
        }
        fn from_secondary_snapshot(snapshot: #core_root::utils::json::JsValue) -> #core_root::AuthResult<Self> {
            let #core_root::utils::json::JsValue::Object(mut fields) = snapshot else {
                return Err(#core_root::AuthError::internal("Invalid secondary user snapshot"));
            };
            #(#normalize)*
            Ok(Self {
                #(#names: #core_root::utils::json::from_value(fields.shift_remove(#keys).ok_or_else(||
                    #core_root::AuthError::internal("Incomplete secondary user snapshot"))?)?,)*
            })
        }
        fn from_secondary_snapshot_record(snapshot: #core_root::utils::json::JsValue) -> #core_root::AuthResult<#core_root::AdapterRecord<Self>> {
            let #core_root::utils::json::JsValue::Object(source) = &snapshot else {
                return Err(#core_root::AuthError::internal("Invalid secondary user snapshot"));
            };
            let mut native = #core_root::AdapterOutput::default();
            #(#capture)*
            #core_root::AdapterRecord::with_native_output(Self::from_secondary_snapshot(snapshot)?, native)
        }
    }
}
