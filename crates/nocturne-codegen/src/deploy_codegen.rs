//! Deployment codegen: generates Rust code for constructing the initial
//! contract state (StateValue tree) for deployment.
//!
//! The strategy is to call the user's constructor at runtime (no arguments;
//! constructor args aren't propagated yet) and then encode each ledger field
//! into a `StateValue` using the field's declared Rust type. This sidesteps
//! the complexity of statically lowering arbitrary constructor body
//! expressions — anything that compiles as plain Rust on the host side
//! works as a Cell initializer.

use nocturne_ir::{ContractIR, LedgerTypeKind};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::aligned::accessor_aligned_value_expr;
use crate::containers::extract_cell_inner_type;

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
        .map(|c| {
            c.params
                .iter()
                .map(|p| (p.name.clone(), p.ty.clone()))
                .collect()
        })
        .unwrap_or_default();
    let param_decls: Vec<TokenStream> = ctor_params
        .iter()
        .map(|(n, ty)| quote! { #n: #ty })
        .collect();
    let param_idents: Vec<TokenStream> = ctor_params.iter().map(|(n, _)| quote! { #n }).collect();

    let user_enums = &contract.user_enums;
    let user_structs = &contract.user_structs;

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
                    let aligned = accessor_aligned_value_expr(
                        inner.as_ref(),
                        &accessor,
                        user_enums,
                        user_structs,
                    );
                    quote! {
                        {
                            use nocturne::runtime::base_crypto::fab::AlignedValue;
                            use nocturne::runtime::onchain_state::state::StateValue;
                            use nocturne::runtime::storage::arena::Sp;
                            fields.push(StateValue::Cell(Sp::new(AlignedValue::from(#aligned))));
                        }
                    }
                }
                // Map/Set deploy as an EMPTY container regardless of what
                // the constructor inserted — statically encoding
                // constructor-populated entries into the StateValue tree
                // isn't implemented yet. Until it is, fail LOUDLY at
                // deploy-state construction instead of silently dropping
                // the entries (which would desync on-chain state from the
                // constructor's view). Implementing it needs the shared
                // resolved-type encoder (the planned `NocturneType` refactor)
                // so each entry serializes with the same K/V AlignedValue
                // encoding the transcript side uses — not a fourth copy of
                // the per-type encoding stack.
                LedgerTypeKind::Map | LedgerTypeKind::Set => {
                    let msg = format!(
                        "nocturne: constructor-populated Map/Set fields are not yet \
                         encoded into deploy state; field `{}` must start empty",
                        field.name
                    );
                    quote! {
                        assert!(__state.#field_ident.is_empty(), #msg);
                        fields.push(StateValue::Map(Default::default()));
                    }
                }
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
                            use nocturne::runtime::base_crypto::fab::AlignedValue;
                            use nocturne::runtime::onchain_state::state::StateValue;
                            use nocturne::runtime::storage::arena::Sp;
                            let blank_tree = nocturne::runtime::transient_crypto::merkle_tree::MerkleTree::<()>::blank(#height).rehash();
                            let inner: Vec<StateValue> = vec![
                                StateValue::BoundedMerkleTree(blank_tree),
                                StateValue::Cell(Sp::new(AlignedValue::from(0u64))),
                            ];
                            fields.push(StateValue::Array(inner.into_iter().collect()));
                        }
                    }
                }
                // Same loud guard as Map/Set: Array fields deploy empty.
                LedgerTypeKind::Array => {
                    let msg = format!(
                        "nocturne: constructor-populated Array fields are not yet \
                         encoded into deploy state; field `{}` must start empty",
                        field.name
                    );
                    quote! {
                        assert!(__state.#field_ident.is_empty(), #msg);
                        fields.push(StateValue::Array(Default::default()));
                    }
                }
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
            // Pull in `nocturne::types` (Bytes / Uint / Field / ...) and the
            // user's contract module so generated patterns can name the user's
            // own enums and structs (e.g. `Action::Mint` in a payload-enum
            // initializer). Without `use super::*` deploy can't resolve the
            // user-defined types.
            #[allow(unused_imports)]
            use nocturne::types::*;
            #[allow(unused_imports)]
            use super::*;
            use nocturne::runtime::onchain_state::state::StateValue;

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
    let syn::Expr::Lit(lit) = expr else {
        return None;
    };
    let syn::Lit::Int(int) = &lit.lit else {
        return None;
    };
    int.base10_parse::<u8>().ok()
}
