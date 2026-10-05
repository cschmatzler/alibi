use super::*;
pub(crate) fn found_crate_tokens(name: &str) -> Option<TokenStream> {
    match crate_name(name).ok()? {
        FoundCrate::Itself => {
            // `Itself` means the Cargo.toml that triggered compilation lists
            // this crate as its own package name. Examples and integration
            // tests compile as separate binaries that link the crate
            // externally, so `crate::` would be wrong: use the extern name.
            let ident = Ident::new(&name.replace('-', "_"), Span::call_site());
            Some(quote!(::#ident))
        }
        FoundCrate::Name(name) => {
            let ident = Ident::new(&name, Span::call_site());
            Some(quote!(::#ident))
        }
    }
}

/// Paths to the `SeaORM` integration crate and to Better Auth core.
pub(crate) struct Roots {
    pub(crate) seaorm: TokenStream,
    pub(crate) core: TokenStream,
    pub(crate) id_generator: TokenStream,
}

pub(crate) fn resolve_roots() -> Roots {
    if let Some(better_auth_root) = found_crate_tokens("better-auth") {
        return Roots {
            id_generator: quote! {},
            seaorm: quote!(#better_auth_root::seaorm),
            core: quote!(#better_auth_root::__private_core),
        };
    }
    match crate_name("better-auth-seaorm") {
        Ok(FoundCrate::Itself) => Roots {
            id_generator: quote! {},
            seaorm: quote!(crate),
            core: quote!(crate::__private_core),
        },
        _ => Roots {
            id_generator: quote! {},
            seaorm: syn::Error::new(
                Span::call_site(),
                "AuthEntity must be used through better_auth::seaorm with the `seaorm` feature enabled",
            )
            .to_compile_error(),
            core: quote!(::core::compile_error!("unreachable")),
        },
    }
}
