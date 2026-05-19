//! Deployment codegen: generates Rust code for constructing the initial
//! contract state (StateValue tree) for deployment.

use midnight_ir::ContractIR;
use midnight_ir::LedgerTypeKind;
use proc_macro2::TokenStream;
use quote::quote;

/// Generate the deployment module for a contract.
pub fn generate_deploy_module(contract: &ContractIR) -> TokenStream {
    let field_inits: Vec<TokenStream> = contract
        .ledger
        .fields
        .iter()
        .map(|field| match &field.type_kind {
            LedgerTypeKind::Counter => quote! {
                fields.push(StateValue::from(0u64));
            },
            LedgerTypeKind::Cell => quote! {
                fields.push(StateValue::from(0u64));
            },
            LedgerTypeKind::Map | LedgerTypeKind::Set => quote! {
                fields.push(StateValue::Map(Default::default()));
            },
            LedgerTypeKind::MerkleTree => {
                // The on-chain shape for `MerkleTree<H, T>` is a 2-element
                // StateValue::Array of `[BoundedMerkleTree<()>, Cell<u64>(0)]`
                // — first the height-H blank tree (rehashed), then the
                // next-index counter starting at 0. This matches compactc
                // 0.30.0's emission (`/tmp/mt-experiments/out/contract/index.js:191-195`)
                // and what `MerkleTree::insert` operates on at runtime.
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
        })
        .collect();

    let num_fields = contract.ledger.fields.len();

    quote! {
        /// Generated deployment helpers.
        pub mod deploy {
            use midnight::runtime::onchain_state::state::StateValue;

            /// Construct the initial contract state as a StateValue::Array
            /// containing one entry per ledger field.
            pub fn initial_state() -> StateValue {
                let mut fields: Vec<StateValue> = Vec::with_capacity(#num_fields);

                #(#field_inits)*

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
    let syn::Expr::Lit(lit) = expr else { return None };
    let syn::Lit::Int(int) = &lit.lit else {
        return None;
    };
    int.base10_parse::<u8>().ok()
}
