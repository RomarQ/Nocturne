//! Deployment codegen: generates Rust code for constructing the initial
//! contract state (StateValue tree) for deployment.
//!
//! The strategy is to call the user's constructor at runtime (no arguments;
//! constructor args aren't propagated yet) and then encode each ledger field
//! into a `StateValue` using the field's declared Rust type. This sidesteps
//! the complexity of statically lowering arbitrary constructor body
//! expressions — anything that compiles as plain Rust on the host side
//! works as a Cell initializer.

use std::collections::HashMap;

use midnight_ir::{ContractIR, LedgerTypeKind, UserEnumVariant};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

/// Generate the deployment module for a contract.
pub fn generate_deploy_module(contract: &ContractIR) -> TokenStream {
    let ledger_name = &contract.ledger.name;
    let constructor = contract.constructors.first();
    let constructor_name = constructor
        .map(|c| c.name.clone())
        .unwrap_or_else(|| format_ident!("new"));

    // Forward the constructor's own parameter list into initial_state(_)
    // so contracts that need deploy-time inputs (admin address, fee
    // rate, ...) can plumb them through without the caller having to
    // hand-roll the encoding.
    let ctor_params: Vec<(syn::Ident, syn::Type)> = constructor
        .map(|c| c.params.iter().map(|p| (p.name.clone(), p.ty.clone())).collect())
        .unwrap_or_default();
    let param_decls: Vec<TokenStream> = ctor_params
        .iter()
        .map(|(n, ty)| quote! { #n: #ty })
        .collect();
    let param_idents: Vec<TokenStream> = ctor_params
        .iter()
        .map(|(n, _)| quote! { #n })
        .collect();

    let user_enums = &contract.user_enums;

    let field_pushes: Vec<TokenStream> = contract
        .ledger
        .fields
        .iter()
        .map(|field| {
            let field_ident = field.name.clone();
            match &field.type_kind {
                LedgerTypeKind::Counter => quote! {
                    fields.push(StateValue::from(__state.#field_ident.value()));
                },
                LedgerTypeKind::Cell => {
                    let inner = extract_cell_inner_type(&field.ty);
                    let accessor = quote! { __state.#field_ident.get() };
                    let aligned = cell_aligned_value_expr(inner.as_ref(), &accessor, user_enums);
                    quote! {
                        {
                            use midnight::runtime::base_crypto::fab::AlignedValue;
                            use midnight::runtime::onchain_state::state::StateValue;
                            use midnight::runtime::storage::arena::Sp;
                            fields.push(StateValue::Cell(Sp::new(AlignedValue::from(#aligned))));
                        }
                    }
                }
                LedgerTypeKind::Map | LedgerTypeKind::Set => quote! {
                    fields.push(StateValue::Map(Default::default()));
                },
                LedgerTypeKind::MerkleTree => {
                    // The on-chain shape for `MerkleTree<H, T>` is a 2-element
                    // StateValue::Array of `[BoundedMerkleTree<()>, Cell<u64>(0)]`
                    // — first the height-H blank tree (rehashed), then the
                    // next-index counter starting at 0. This matches compactc
                    // 0.30.0's emission and what `MerkleTree::insert` operates
                    // on at runtime.
                    let height = parse_merkle_tree_height(&field.ty)
                        .expect("MerkleTree<H, T> field must declare H as a const literal");
                    quote! {
                        {
                            use midnight::runtime::base_crypto::fab::AlignedValue;
                            use midnight::runtime::onchain_state::state::StateValue;
                            use midnight::runtime::storage::arena::Sp;
                            let blank_tree = midnight::runtime::transient_crypto::merkle_tree::MerkleTree::<()>::blank(#height).rehash();
                            let inner: Vec<StateValue> = vec![
                                StateValue::BoundedMerkleTree(blank_tree),
                                StateValue::Cell(Sp::new(AlignedValue::from(0u64))),
                            ];
                            fields.push(StateValue::Array(inner.into_iter().collect()));
                        }
                    }
                }
                LedgerTypeKind::Array => quote! {
                    fields.push(StateValue::Array(Default::default()));
                },
                LedgerTypeKind::Unknown(_) => quote! {
                    fields.push(StateValue::Null);
                },
            }
        })
        .collect();

    let num_fields = contract.ledger.fields.len();

    quote! {
        /// Generated deployment helpers.
        pub mod deploy {
            #[allow(unused_imports)]
            use midnight::types::*;
            use midnight::runtime::onchain_state::state::StateValue;

            /// Construct the initial contract state by calling the user
            /// constructor and encoding each ledger field as a
            /// `StateValue::Array` entry, in declaration order. The
            /// constructor's own parameters are forwarded verbatim so
            /// deploy-time inputs (admin address, fee, ...) plumb through.
            pub fn initial_state(#(#param_decls),*) -> StateValue {
                let __state = super::#ledger_name::#constructor_name(#(#param_idents),*);
                let mut fields: Vec<StateValue> = Vec::with_capacity(#num_fields);

                #(#field_pushes)*

                StateValue::Array(fields.into_iter().collect())
            }
        }
    }
}

/// Build the expression passed to `AlignedValue::from(_)` for a Cell field's
/// inner value. `accessor` is the token expression for the runtime value
/// (typically `__state.<field>.get()`). Returns a token that, when wrapped
/// in `AlignedValue::from(_)`, produces the same wire shape Cell::set would
/// push at runtime.
fn cell_aligned_value_expr(
    inner: Option<&syn::Type>,
    accessor: &TokenStream,
    user_enums: &HashMap<String, Vec<UserEnumVariant>>,
) -> TokenStream {
    let Some(t) = inner else {
        return quote! { (#accessor) };
    };
    let s = quote!(#t).to_string().replace(' ', "");
    if s.starts_with("Bytes<") {
        return quote! { *(#accessor).as_bytes() };
    }
    if s == "Field" {
        return quote! { midnight::runtime::transient_crypto::curve::Fr::from((#accessor).value()) };
    }
    if s == "MerkleTreeDigest" {
        return quote! {
            midnight::runtime::transient_crypto::curve::Fr::from_le_bytes(&(#accessor).as_le_bytes())
                .expect("MerkleTreeDigest bytes round-trip through Fr")
        };
    }
    if s == "Boolean" {
        return quote! { (#accessor).value() };
    }
    if s == "bool" {
        return quote! { (#accessor) };
    }
    // User enum: encode as its u8 discriminant.
    if let syn::Type::Path(tp) = t
        && tp.qself.is_none()
        && let Some(seg) = tp.path.segments.last()
        && user_enums.contains_key(&seg.ident.to_string())
    {
        return quote! { (#accessor).discriminant() };
    }
    // `Uint<N>` is a wrapper exposing `.value()`; raw `u*` primitives don't
    // have `.value()`. Branch on which we're looking at so the cast applies
    // to the right base expression.
    if s.starts_with("Uint<") {
        if let Some(cast) = primitive_cast_for_type(t) {
            return quote! { ((#accessor).value() #cast) };
        }
        return quote! { (#accessor).value() };
    }
    if matches!(s.as_str(), "u8" | "u16" | "u32" | "u64") {
        if let Some(cast) = primitive_cast_for_type(t) {
            return quote! { ((#accessor) #cast) };
        }
        return quote! { (#accessor) };
    }
    quote! { (#accessor) }
}

/// Pick the `as u<N>` cast appropriate for fixed-width integer Cell types so
/// the emitted `AlignedValue::from(_)` chooses the matching `Bytes<N>` atom
/// width. Mirrors `primitive_cast_for_type` in `transcript_codegen.rs` —
/// kept local here to avoid a cross-crate visibility shuffle for one
/// helper.
fn primitive_cast_for_type(ty: &syn::Type) -> Option<TokenStream> {
    let s = quote!(#ty).to_string().replace(' ', "");
    if let Some(bits) = s.strip_prefix("Uint<").and_then(|t| t.strip_suffix(">")) {
        let bits: u32 = bits.parse().ok()?;
        return Some(match bits {
            1..=8 => quote! { as u8 },
            9..=16 => quote! { as u16 },
            17..=32 => quote! { as u32 },
            _ => quote! { as u64 },
        });
    }
    match s.as_str() {
        "u8" => Some(quote! { as u8 }),
        "u16" => Some(quote! { as u16 }),
        "u32" => Some(quote! { as u32 }),
        "u64" => Some(quote! { as u64 }),
        _ => None,
    }
}

/// Pull the `T` out of a `Cell<T>` field declaration. Returns None if
/// the type isn't `Cell<...>`.
fn extract_cell_inner_type(ty: &syn::Type) -> Option<syn::Type> {
    let syn::Type::Path(tp) = ty else {
        return None;
    };
    let seg = tp.path.segments.last()?;
    if seg.ident != "Cell" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    match args.args.first()? {
        syn::GenericArgument::Type(t) => Some(t.clone()),
        _ => None,
    }
}

/// Extract the height `H` from a `MerkleTree<H, T>` field type. The
/// `H` is a `usize` const generic on the user-facing storage type; on
/// the wire it becomes a `u8` (BoundedMerkleTree's height parameter).
fn parse_merkle_tree_height(ty: &syn::Type) -> Option<u8> {
    let syn::Type::Path(tp) = ty else {
        return None;
    };
    let seg = tp.path.segments.last()?;
    if seg.ident != "MerkleTree" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    // First generic argument may surface as `GenericArgument::Const`
    // (typical for `MerkleTree<10, _>`) or, when syn parses an ambiguous
    // path, as a `GenericArgument::Type` whose path resolves to an
    // integer literal. Handle both.
    let first = args.args.first()?;
    let expr = match first {
        syn::GenericArgument::Const(e) => e,
        syn::GenericArgument::Type(syn::Type::Path(tp)) => {
            let s = tp.path.segments.last()?.ident.to_string();
            return s.parse::<u8>().ok();
        }
        _ => return None,
    };
    let syn::Expr::Lit(lit) = expr else { return None };
    let syn::Lit::Int(int) = &lit.lit else {
        return None;
    };
    int.base10_parse::<u8>().ok()
}
