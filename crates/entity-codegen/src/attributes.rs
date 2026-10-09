use crate::has_field;
use alibi_schema_registry::{self as registry, EntityRole};
use syn::{Data, DeriveInput, Fields, FieldsNamed, LitStr};

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
/// `SQLx` also permits an explicit table name.
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
