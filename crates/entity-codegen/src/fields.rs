use super::*;
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
