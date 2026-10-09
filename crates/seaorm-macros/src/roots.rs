use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;

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
