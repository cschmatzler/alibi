use super::*;
/// One model field with its `Column` variant and explicitly renamed column.
pub(crate) struct Field {
    pub(crate) ident: Ident,
    pub(crate) ty: syn::Type,
    pub(crate) camel: String,
    pub(crate) column: Ident,
    pub(crate) physical: Option<String>,
}

pub(crate) fn pascal_case(name: &Ident) -> String {
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
pub(crate) fn model_fields(fields: &FieldsNamed) -> syn::Result<Vec<Field>> {
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
