use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;

#[derive(Clone, Copy)]
pub enum Integration {
    Sqlx,
    SeaOrm,
}

pub struct ExpansionPaths {
    pub adapter: TokenStream,
    pub core: TokenStream,
}

impl Integration {
    #[must_use]
    pub fn expansion_paths(self) -> ExpansionPaths {
        let name = match self {
            Self::Sqlx => "sqlx",
            Self::SeaOrm => "seaorm",
        };
        if let Ok(found) = crate_name("alibi") {
            let facade = match found {
                FoundCrate::Itself => Ident::new("alibi", Span::call_site()),
                FoundCrate::Name(name) => Ident::new(&name, Span::call_site()),
            };
            let adapter = Ident::new(name, Span::call_site());
            return ExpansionPaths {
                adapter: quote!(::#facade::#adapter),
                core: quote!(::#facade::__private_core),
            };
        }

        match crate_name(&format!("alibi-{name}")) {
            Ok(FoundCrate::Itself) => ExpansionPaths {
                adapter: quote!(crate),
                core: quote!(crate::__private_core),
            },
            Ok(FoundCrate::Name(alias)) if matches!(self, Self::Sqlx) => {
                let alias = Ident::new(&alias, Span::call_site());
                ExpansionPaths {
                    adapter: quote!(::#alias),
                    core: quote!(::#alias::__private_core),
                }
            }
            _ => ExpansionPaths {
                adapter: syn::Error::new(
                    Span::call_site(),
                    format!("AuthEntity must be used through alibi::{name} with the `{name}` feature enabled"),
                )
                .to_compile_error(),
                core: quote!(::core::compile_error!("unreachable")),
            },
        }
    }
}
