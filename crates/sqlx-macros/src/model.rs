use super::{Column, EntityRole, Ident, Roots, TokenStream, codegen, physical, quote};
pub(crate) fn model_impl(
    ident: &Ident,
    table: &str,
    columns: &[Column],
    role: Option<EntityRole>,
    roots: &Roots,
) -> syn::Result<TokenStream> {
    let verification_column = if matches!(role, Some(EntityRole::User)) {
        let name = physical(columns, "email_verified")?;
        quote! { ::std::option::Option::Some(#name) }
    } else {
        quote! { ::std::option::Option::None }
    };
    let sqlx_root = &roots.sqlx;
    let core_root = &roots.core;
    let primary_key = physical(columns, "id")?;
    let definitions = columns.iter().map(|column| {
        let name = &column.physical;
        let ty = &column.ty;
        let kind = column.kind.as_ref().map_or_else(
            || quote! { <#ty as #sqlx_root::value::SqlxValue>::KIND },
            |kind| quote! { #sqlx_root::value::ColumnKind::#kind },
        );
        quote! { #sqlx_root::model::ColumnDef { name: #name, kind: #kind } }
    });
    let field_columns = columns.iter().map(|column| {
        let field = column.ident.to_string();
        let physical = &column.physical;
        quote! { (#field, #physical) }
    });
    let names = columns.iter().map(|column| &column.physical);
    let unchanged = columns.iter().map(|column| {
        let name = &column.physical;
        let field = &column.ident;
        quote! { active.unchanged(#name, #sqlx_root::value::SqlxValue::into_sql_value(self.#field)); }
    });
    let materialize = columns.iter().map(|column| {
        let name = &column.physical;
        let field = &column.ident;
        let ty = &column.ty;
        let text = field.to_string();
        let absent = if codegen::is_option(ty) {
            quote! { ::std::option::Option::None }
        } else {
            quote! {
                return Err(#core_root::AuthError::internal(concat!("Attribute ", #text, " is NotSet")))
            }
        };
        quote! {
            #field: match active.take(#name).into_value() {
                ::std::option::Option::Some(value) => <#ty as #sqlx_root::value::SqlxValue>::from_sql_value(value)
                    .map_err(|_error| #core_root::AuthError::internal(concat!("Attribute ", #text, " has an incompatible value")))?,
                ::std::option::Option::None => { #absent }
            },
        }
    });
    Ok(quote! {
        impl #sqlx_root::model::SqlxModel for #ident {
            const TABLE: &'static str = #table;
            const COLUMNS: &'static [#sqlx_root::model::ColumnDef] = &[#(#definitions),*];
            const COLUMN_NAMES: &'static [&'static str] = &[#(#names),*];
            const FIELD_COLUMNS: &'static [(&'static str, &'static str)] = &[#(#field_columns),*];
            const PRIMARY_KEY: &'static str = #primary_key;
            const PROVIDER_VERIFICATION_COLUMN: ::std::option::Option<&'static str> = #verification_column;

            fn into_active(self) -> #sqlx_root::model::ActiveRow {
                let mut active = #sqlx_root::model::ActiveRow::new();
                #(#unchanged)*
                active
            }

            fn from_active(mut active: #sqlx_root::model::ActiveRow) -> #core_root::AuthResult<Self> {
                Ok(Self {
                    #(#materialize)*
                })
            }
        }
    })
}

/// Configured additional-field bindings and staging, keyed by wire and physical names.
pub(crate) fn additional_fields(columns: &[Column], roots: &Roots) -> TokenStream {
    let sqlx_root = &roots.sqlx;
    let core_root = &roots.core;
    let mut bindings = Vec::new();
    let mut stages = Vec::new();
    for column in columns {
        let camel = &column.camel;
        let name = &column.physical;
        let field_ty = &column.ty;
        if column.renamed && name != camel {
            bindings.push(quote! {
                #name => (#name, #sqlx_root::additional_fields::raw_value(value)?),
            });
        }
        stages.push(quote! {
            #name => {
                let value = <#field_ty as #sqlx_root::value::SqlxValue>::from_sql_value(value)
                    .map_err(|_error| #core_root::AuthError::internal("field value cannot be represented by its model column"))?;
                active.set(#name, #sqlx_root::value::SqlxValue::into_sql_value(
                    #sqlx_root::value::SqlxValue::prepare(value, backend)?
                ));
            }
        });
        bindings.push(quote! {
            #camel => (#name, #sqlx_root::additional_fields::raw_value(value)?),
        });
    }
    quote! {
        fn additional_field_bindings(fields: &#core_root::field_policy::FieldValues, _backend: #sqlx_root::pool::Engine) -> #core_root::AuthResult<Vec<(&'static str, #sqlx_root::value::SqlValue)>> {
            let mut bindings = Vec::new();
            for (name, value) in fields {
                bindings.push(match fields.binding_name(name) {
                    #(#bindings)*
                    _ => return Err(#core_root::AuthError::internal("configured field has no model column")),
                });
            }
            Ok(bindings)
        }
        fn set_additional_field(active: &mut #sqlx_root::model::ActiveRow, column: &'static str, value: #sqlx_root::value::SqlValue, backend: #sqlx_root::pool::Engine) -> #core_root::AuthResult<()> {
            match column {
                #(#stages)*
                _ => return Err(#core_root::AuthError::internal("configured field has no model column")),
            }
            Ok(())
        }
    }
}
