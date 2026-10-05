use super::*;
pub(crate) fn found_crate_tokens(name: &str) -> Option<TokenStream> {
    match crate_name(name).ok()? {
        FoundCrate::Itself => {
            // Examples and integration tests link the crate externally.
            let ident = Ident::new(&name.replace('-', "_"), Span::call_site());
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
    if let Some(better_auth_root) = found_crate_tokens("better-auth") {
        return Roots {
            id_generator: quote! {},
            sqlx: quote!(#better_auth_root::sqlx),
            core: quote!(#better_auth_root::__private_core),
        };
    }
    match crate_name("better-auth-sqlx") {
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
                "AuthEntity must be used through better_auth::sqlx with the `sqlx` feature enabled",
            )
            .to_compile_error(),
            core: quote!(::core::compile_error!("unreachable")),
        },
    }
}
