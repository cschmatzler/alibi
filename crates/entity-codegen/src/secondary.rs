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
        fn secondary_snapshot(&self) -> #core_root::AuthResult<::serde_json::Value> {
            let mut snapshot = ::serde_json::Map::new();
            #(_ = snapshot.insert(#keys.to_owned(), ::serde_json::to_value(&self.#names)?);)*
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
                _ = snapshot.remove(#key);
            } else if let Some(value) = native.values().get(#wire) {
                _ = snapshot.insert(#key.to_owned(), value.clone());
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
                    ::serde_json::Value::String(value) => #core_root::utils::datetime::parse_date_millis(value),
                    ::serde_json::Value::Number(value) => value.as_f64()
                        .filter(|value| value.abs() <= 8_640_000_000_000_000.0)
                        .map(|value| value.trunc() as i64),
                    ::serde_json::Value::Bool(value) => Some(i64::from(*value)),
                    ::serde_json::Value::Null => Some(0),
                    _ => None,
                };
                // Unrepresentable native dates remain in the retained output;
                // the typed model alone cannot represent Invalid Date.
                let typed = millis.and_then(::chrono::DateTime::<::chrono::Utc>::from_timestamp_millis)
                    .unwrap_or(::chrono::DateTime::<::chrono::Utc>::UNIX_EPOCH);
                *value = ::serde_json::to_value(<#ty as #core_root::entity::AuthTimestamp>::from_utc(#utc))?;
            }
        } else {
            quote! {
                *value = ::serde_json::Value::Bool(#core_root::utils::json::JsValue::from(value.clone()).is_truthy());
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
        if optional {
            normalize.push(quote! {
                if !fields.contains_key(#key) {
                    _ = fields.insert(#key.to_owned(), ::serde_json::Value::Null);
                }
            });
        }
        if text {
            let surrogate = if optional {
                quote! { ::serde_json::Value::Null }
            } else {
                quote! { ::serde_json::Value::String(::std::string::String::new()) }
            };
            normalize.push(quote! {
                if fields.get(#key).is_none_or(|value| !value.is_string()) {
                    _ = fields.insert(#key.to_owned(), #surrogate);
                }
            });
        }
        if !(optional || text)
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
                _ = snapshot.remove(#key);
            } else if let Some(value) = native.values().get(#wire) {
                _ = snapshot.insert(#key.to_owned(), value.clone());
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
        fn secondary_snapshot(&self) -> #core_root::AuthResult<::serde_json::Value> {
            let mut snapshot = ::serde_json::Map::new();
            #(_ = snapshot.insert(#keys.to_owned(), ::serde_json::to_value(&self.#names)?);)*
            Ok(::serde_json::Value::Object(snapshot))
        }
        fn secondary_snapshot_with_native_output(
            &self,
            native: &#core_root::AdapterOutput,
        ) -> #core_root::AuthResult<::serde_json::Value> {
            let ::serde_json::Value::Object(mut snapshot) = self.secondary_snapshot()? else {
                return Err(#core_root::AuthError::internal("Invalid secondary user snapshot"));
            };
            #(#overlay)*
            Ok(::serde_json::Value::Object(snapshot))
        }
        fn from_secondary_snapshot(snapshot: ::serde_json::Value) -> #core_root::AuthResult<Self> {
            let ::serde_json::Value::Object(mut fields) = snapshot else {
                return Err(#core_root::AuthError::internal("Invalid secondary user snapshot"));
            };
            #(#normalize)*
            Ok(Self {
                #(#names: ::serde_json::from_value(fields.remove(#keys).ok_or_else(||
                    #core_root::AuthError::internal("Incomplete secondary user snapshot"))?)?,)*
            })
        }
        fn from_secondary_snapshot_record(snapshot: ::serde_json::Value) -> #core_root::AuthResult<#core_root::AdapterRecord<Self>> {
            let ::serde_json::Value::Object(source) = &snapshot else {
                return Err(#core_root::AuthError::internal("Invalid secondary user snapshot"));
            };
            let mut native = #core_root::AdapterOutput::default();
            #(#capture)*
            #core_root::AdapterRecord::with_native_output(Self::from_secondary_snapshot(snapshot)?, native)
        }
    }
}
