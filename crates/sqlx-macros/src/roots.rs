use super::{FoundCrate, Ident, Span, TokenStream, crate_name, quote};
pub(crate) fn found_crate_tokens(package_name: &str) -> Option<TokenStream> {
    match crate_name(package_name).ok()? {
        FoundCrate::Itself => {
            // Examples and integration tests link the crate externally.
            let ident = Ident::new("alibi", Span::call_site());
            Some(quote!(::#ident))
        }
        FoundCrate::Name(name) => {
            let ident = Ident::new(&name, Span::call_site());
            Some(quote!(::#ident))
        }
    }
}

/// Paths to the `SQLx` integration crate and to Better Auth core.
pub(crate) struct Roots {
    pub(crate) sqlx: TokenStream,
    pub(crate) core: TokenStream,
    pub(crate) id_generator: TokenStream,
}

pub(crate) fn resolve_roots() -> Roots {
    if let Some(alibi_root) = found_crate_tokens("alibi") {
        return Roots {
            id_generator: quote! {},
            sqlx: quote!(#alibi_root::sqlx),
            core: quote!(#alibi_root::__private_core),
        };
    }
    match crate_name("alibi-sqlx") {
        Ok(FoundCrate::Itself) => Roots {
            id_generator: quote! {},
            sqlx: quote!(crate),
            core: quote!(crate::__private_core),
        },
        Ok(FoundCrate::Name(name)) => {
            let ident = Ident::new(&name, Span::call_site());
            Roots {
                id_generator: quote! {},
                sqlx: quote!(::#ident),
                core: quote!(::#ident::__private_core),
            }
        }
        Err(_) => Roots {
            id_generator: quote! {},
            sqlx: syn::Error::new(
                Span::call_site(),
                "AuthEntity must be used through alibi::sqlx with the `sqlx` feature enabled",
            )
            .to_compile_error(),
            core: quote!(::core::compile_error!("unreachable")),
        },
    }
}
