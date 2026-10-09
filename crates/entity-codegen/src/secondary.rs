use super::{FieldsNamed, TokenStream, quote};
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
