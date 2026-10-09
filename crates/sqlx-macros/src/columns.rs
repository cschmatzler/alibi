use super::{DeriveInput, FieldsNamed, Ident, LitStr, Span, codegen};
/// One model field with its physical column.
pub(crate) struct Column {
    pub(crate) ident: Ident,
    pub(crate) ty: syn::Type,
    pub(crate) camel: String,
    pub(crate) physical: String,
    pub(crate) renamed: bool,
    pub(crate) kind: Option<Ident>,
}

pub(crate) fn rename_all(input: &DeriveInput) -> syn::Result<Option<String>> {
    let mut rule = None;
    for attribute in input
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("sqlx"))
    {
        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename_all") {
                rule = Some(meta.value()?.parse::<LitStr>()?.value());
            } else {
                drop(
                    meta.value()
                        .and_then(syn::parse::ParseBuffer::parse::<syn::Expr>)
                        .ok(),
                );
            }
            Ok(())
        })?;
    }
    Ok(rule)
}

pub(crate) fn apply_rename_all(rule: &str, name: &str) -> syn::Result<String> {
    let words: Vec<&str> = name.split('_').filter(|word| !word.is_empty()).collect();
    let capitalized = |word: &str| {
        let mut letters = word.chars();
        letters.next().map_or_else(String::new, |first| {
            first.to_uppercase().chain(letters).collect()
        })
    };
    Ok(match rule {
        "snake_case" => name.to_owned(),
        "lowercase" => name.to_lowercase(),
        "UPPERCASE" | "SCREAMING_SNAKE_CASE" => name.to_uppercase(),
        "kebab-case" => name.replace('_', "-"),
        "camelCase" => words
            .iter()
            .enumerate()
            .map(|(index, word)| {
                if index == 0 {
                    (*word).to_owned()
                } else {
                    capitalized(word)
                }
            })
            .collect(),
        "PascalCase" => words.iter().map(|word| capitalized(word)).collect(),
        _ => {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("unsupported sqlx rename_all rule `{rule}`"),
            ));
        }
    })
}

pub(crate) fn columns(input: &DeriveInput, fields: &FieldsNamed) -> syn::Result<Vec<Column>> {
    let rule = rename_all(input)?;
    let mut columns = Vec::new();
    for field in &fields.named {
        let ident = field
            .ident
            .clone()
            .ok_or_else(|| syn::Error::new_spanned(field, "Expected a named field"))?;
        let text = ident.to_string();
        let text = text.trim_start_matches("r#").to_owned();
        let mut rename = None;
        for attribute in field
            .attrs
            .iter()
            .filter(|attribute| attribute.path().is_ident("sqlx"))
        {
            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("rename") {
                    rename = Some(meta.value()?.parse::<LitStr>()?.value());
                    Ok(())
                } else if meta.path.is_ident("skip")
                    || meta.path.is_ident("flatten")
                    || meta.path.is_ident("json")
                    || meta.path.is_ident("try_from")
                {
                    Err(meta.error(
                        "model fields map one-to-one to columns; `skip`, `flatten`, `json` and `try_from` are unsupported",
                    ))
                } else {
                    drop(
                        meta.value()
                            .and_then(syn::parse::ParseBuffer::parse::<syn::Expr>)
                            .ok(),
                    );
                    Ok(())
                }
            })?;
        }
        let mut kind = None;
        for attribute in field
            .attrs
            .iter()
            .filter(|attribute| attribute.path().is_ident("auth"))
        {
            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("column_type") {
                    let value = meta.value()?.parse::<LitStr>()?;
                    let variant = match value.value().as_str() {
                        "text" => "Text",
                        "bpchar" => "BpChar",
                        "json" => "Json",
                        "double" => "Double",
                        "float" => "Float",
                        "boolean" => "Boolean",
                        "other" => "Other",
                        _ => {
                            return Err(syn::Error::new_spanned(
                                value,
                                "expected text, bpchar, json, double, float, boolean or other",
                            ));
                        }
                    };
                    kind = Some(Ident::new(variant, Span::call_site()));
                    Ok(())
                } else {
                    Err(meta.error("expected `column_type = \"...\"`"))
                }
            })?;
        }
        let renamed = rename.is_some() || rule.is_some();
        let physical = match (rename, &rule) {
            (Some(rename), _) => rename,
            (None, Some(rule)) => apply_rename_all(rule, &text)?,
            (None, None) => text.clone(),
        };
        columns.push(Column {
            camel: codegen::camel_case(&ident),
            ident,
            ty: field.ty.clone(),
            physical,
            renamed,
            kind,
        });
    }
    Ok(columns)
}

/// `#[auth(table = "...")]` on a plain `SqlxModel` derive.
pub(crate) fn table_attribute(input: &DeriveInput) -> syn::Result<String> {
    let mut table = None;
    for attr in &input.attrs {
        if !attr.path().is_ident("auth") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("table") {
                table = Some(meta.value()?.parse::<LitStr>()?.value());
                Ok(())
            } else {
                Err(meta.error("expected `table = \"...\"`"))
            }
        })?;
    }
    table.ok_or_else(|| {
        syn::Error::new_spanned(
            input,
            "missing #[auth(table = \"...\")] attribute for SqlxModel",
        )
    })
}

pub(crate) fn column_of<'a>(columns: &'a [Column], name: &str) -> syn::Result<&'a Column> {
    columns
        .iter()
        .find(|column| column.ident == name)
        .ok_or_else(|| syn::Error::new(Span::call_site(), format!("missing auth field `{name}`")))
}

pub(crate) fn physical(columns: &[Column], name: &str) -> syn::Result<String> {
    column_of(columns, name).map(|column| column.physical.clone())
}
