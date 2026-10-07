use super::*;
pub(crate) fn found_crate_tokens(package_name: &str) -> Option<TokenStream> {
    match crate_name(package_name).ok()? {
        FoundCrate::Itself => {
            // `Itself` means the Cargo.toml that triggered compilation lists
            // this crate as its own package name. Examples and integration
            // tests compile as separate binaries that link the crate
            // externally, so `crate::` would be wrong: use the extern name.
            let ident = Ident::new("alibi", Span::call_site());
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
    if let Some(alibi_root) = found_crate_tokens("alibi") {
        return Roots {
            id_generator: quote! {},
            seaorm: quote!(#alibi_root::seaorm),
            core: quote!(#alibi_root::__private_core),
        };
    }
    match crate_name("alibi-seaorm") {
        Ok(FoundCrate::Itself) => Roots {
            id_generator: quote! {},
            seaorm: quote!(crate),
            core: quote!(crate::__private_core),
        },
        _ => Roots {
            id_generator: quote! {},
            seaorm: syn::Error::new(
                Span::call_site(),
                "AuthEntity must be used through alibi::seaorm with the `seaorm` feature enabled",
            )
            .to_compile_error(),
            core: quote!(::core::compile_error!("unreachable")),
        },
    }
}
