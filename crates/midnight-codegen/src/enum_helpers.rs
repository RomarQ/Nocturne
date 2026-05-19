//! Generated helpers for user-defined unit-variant enums.
//!
//! For every `enum E { A, B, C }` registered in `ContractIR.user_enums`,
//! this codegen emits:
//!
//! ```ignore
//! impl E {
//!     pub fn discriminant(&self) -> u8 {
//!         match self {
//!             E::A => 0,
//!             E::B => 1,
//!             E::C => 2,
//!         }
//!     }
//!
//!     pub fn from_discriminant(d: u8) -> Self {
//!         match d {
//!             0 => E::A,
//!             1 => E::B,
//!             2 => E::C,
//!             _ => panic!("from_discriminant: out-of-range u8"),
//!         }
//!     }
//! }
//! ```
//!
//! The runtime side (transcript codegen) reads the discriminant via
//! `.discriminant()` when computing AlignedValues; the reverse mapping
//! is reserved for popeq result computation when Cell<E>::get() lands.

use midnight_ir::ContractIR;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

/// Emit `impl <Enum> { fn discriminant(); fn from_discriminant() }` for
/// every user enum in the contract. Returns an empty stream when the
/// contract has no enums.
pub fn generate_enum_helpers(contract: &ContractIR) -> TokenStream {
    let impls: Vec<TokenStream> = contract
        .user_enums
        .iter()
        .map(|(name, variants)| {
            let enum_ident = format_ident!("{}", name);
            let disc_arms: Vec<TokenStream> = variants
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let v_ident = v.name.clone();
                    let i = i as u8;
                    quote! { #enum_ident::#v_ident => #i }
                })
                .collect();
            let from_arms: Vec<TokenStream> = variants
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let v_ident = v.name.clone();
                    let i = i as u8;
                    quote! { #i => #enum_ident::#v_ident }
                })
                .collect();
            quote! {
                impl #enum_ident {
                    pub fn discriminant(&self) -> u8 {
                        match self {
                            #(#disc_arms),*
                        }
                    }
                    pub fn from_discriminant(__d: u8) -> Self {
                        match __d {
                            #(#from_arms),*,
                            _ => panic!(
                                concat!(
                                    "from_discriminant on ",
                                    stringify!(#enum_ident),
                                    ": out-of-range u8"
                                )
                            ),
                        }
                    }
                }
            }
        })
        .collect();
    quote! { #(#impls)* }
}
