//! Generated helpers for user-defined enums.
//!
//! For unit-only enums:
//! ```ignore
//! impl E {
//!     pub fn discriminant(&self) -> u8 { match self { E::A => 0, ... } }
//!     pub fn from_discriminant(d: u8) -> Self { match d { 0 => E::A, ... } }
//! }
//! ```
//!
//! For homogeneous-payload enums `enum E { V1(T), V2(T), ... }` we emit
//! `discriminant()` only — the variant tag is a real on-chain concept.
//! Payload extraction happens via plain Rust pattern matching at the
//! call site (the transcript codegen emits inline `match` expressions
//! over the user enum); there's no synthetic `.payload()` accessor
//! because Rust enums don't have one and shouldn't grow one.
//! `from_discriminant` isn't sensible for payload enums (a u8 can't
//! manufacture a payload), so we skip it there too.

use midnight_ir::ContractIR;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

/// Emit `impl <Enum> { fn discriminant(); ... }` for every user enum
/// in the contract. Returns an empty stream when the contract has no
/// enums.
pub fn generate_enum_helpers(contract: &ContractIR) -> TokenStream {
    let impls: Vec<TokenStream> = contract
        .user_enums
        .iter()
        .map(|(name, variants)| {
            let enum_ident = format_ident!("{}", name);
            let payload_ty = variants.first().and_then(|v| v.payload.clone());

            let disc_arms: Vec<TokenStream> = variants
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let v_ident = v.name.clone();
                    let i = i as u8;
                    if v.payload.is_some() {
                        quote! { #enum_ident::#v_ident(_) => #i }
                    } else {
                        quote! { #enum_ident::#v_ident => #i }
                    }
                })
                .collect();

            // Unit-only enums get the inverse `from_discriminant`; the
            // payload-carrying form can't manufacture a payload value
            // from just a u8, so we skip the helper there.
            let from_discriminant = if payload_ty.is_none() {
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
            } else {
                quote! {}
            };

            // No `payload()` accessor — payload extraction is handled
            // by inline `match` expressions in the transcript codegen,
            // matching how a user would extract via pattern matching.
            // The unused `payload_ty` binding stays as a marker that
            // homogeneous-payload enums are recognized; future
            // additions (e.g. a derived From impl for the
            // single-payload-type case) would consume it here.
            let _ = &payload_ty;

            quote! {
                impl #enum_ident {
                    pub fn discriminant(&self) -> u8 {
                        match self {
                            #(#disc_arms),*
                        }
                    }
                    #from_discriminant
                }
            }
        })
        .collect();
    quote! { #(#impls)* }
}
