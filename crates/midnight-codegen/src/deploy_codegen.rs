//! Deployment codegen: generates Rust code for constructing the initial
//! contract state (StateValue tree) for deployment.

use std::collections::HashMap;

use midnight_ir::expr::{ExprIR, LiteralIR};
use midnight_ir::{ContractIR, LedgerTypeKind, UserEnumVariant};
use proc_macro2::TokenStream;
use quote::quote;

/// Generate the deployment module for a contract.
pub fn generate_deploy_module(contract: &ContractIR) -> TokenStream {
    let init_map = collect_constructor_field_inits(contract);
    let user_enums = &contract.user_enums;

    let field_inits: Vec<TokenStream> = contract
        .ledger
        .fields
        .iter()
        .map(|field| {
            let init_expr = init_map.get(&field.name.to_string()).copied();
            match &field.type_kind {
                LedgerTypeKind::Counter => counter_state_value(init_expr),
                LedgerTypeKind::Cell => cell_state_value(&field.ty, init_expr, user_enums),
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
            }
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

/// Walk the (first) constructor body looking for a `Self { f: init, ... }`
/// expression and return a map from each named field to its initializer.
/// Constructors that don't end with a struct-init expression (e.g. they
/// build via `let` bindings and return a name) get a best-effort empty
/// map, falling back to the per-kind defaults.
fn collect_constructor_field_inits(contract: &ContractIR) -> HashMap<String, &ExprIR> {
    let mut out = HashMap::new();
    let Some(constructor) = contract.constructors.first() else {
        return out;
    };
    let struct_init = constructor.body.iter().find_map(|e| match e {
        ExprIR::StructInit { fields, .. } => Some(fields),
        // `return Self { .. }` wraps the StructInit; peek through.
        ExprIR::Return { value: Some(v), .. } => match v.as_ref() {
            ExprIR::StructInit { fields, .. } => Some(fields),
            _ => None,
        },
        _ => None,
    });
    if let Some(fields) = struct_init {
        for (name, expr) in fields {
            out.insert(name.to_string(), expr);
        }
    }
    out
}

/// Generate the `StateValue::Cell(_)` push for a `Counter` ledger field.
/// Today we only support `Counter::zero()` and missing initializers (both
/// emit a zero counter); anything else compile-errors so the user can't
/// silently get an off-by-one initial value.
fn counter_state_value(init: Option<&ExprIR>) -> TokenStream {
    let is_zero = match init {
        None => true,
        Some(ExprIR::FnCall { name, args, .. }) => name == "zero" && args.is_empty(),
        _ => false,
    };
    if is_zero {
        return quote! { fields.push(StateValue::from(0u64)); };
    }
    let msg = format!(
        "Counter initial value not supported yet: {:?} \
         (only `Counter::zero()` works)",
        init.unwrap()
    );
    quote! { compile_error!(#msg); }
}

/// Generate the `StateValue::Cell(_)` push for a `Cell<T>` ledger field.
/// Recognizes `Cell::new(<const-literal-or-enum-variant>)` and lowers the
/// literal to its on-chain AlignedValue. Falls back to a zero Cell when
/// the initializer is missing or unrecognized, matching the previous
/// always-zero behavior.
fn cell_state_value(
    field_ty: &syn::Type,
    init: Option<&ExprIR>,
    user_enums: &HashMap<String, Vec<UserEnumVariant>>,
) -> TokenStream {
    let aligned_arg = match init {
        Some(ExprIR::FnCall { name, args, .. }) if name == "new" && args.len() == 1 => {
            cell_init_aligned_arg(&args[0], field_ty, user_enums)
        }
        _ => None,
    };
    match aligned_arg {
        Some(arg) => quote! {
            {
                use midnight::runtime::base_crypto::fab::AlignedValue;
                use midnight::runtime::onchain_state::state::StateValue;
                use midnight::runtime::storage::arena::Sp;
                fields.push(StateValue::Cell(Sp::new(AlignedValue::from(#arg))));
            }
        },
        None => quote! { fields.push(StateValue::from(0u64)); },
    }
}

/// Lower a `Cell::new(<init>)` argument into an expression suitable for
/// `AlignedValue::from(_)`. Returns `None` if we don't recognize the
/// shape so the caller can fall back to the zero default.
fn cell_init_aligned_arg(
    expr: &ExprIR,
    field_ty: &syn::Type,
    user_enums: &HashMap<String, Vec<UserEnumVariant>>,
) -> Option<TokenStream> {
    match expr {
        ExprIR::Literal { value, .. } => match value {
            LiteralIR::Int(n) => {
                // Match the inner type's wire shape so the AlignedValue we
                // build matches what `Cell::set` would push at runtime.
                let inner = extract_cell_inner_type(field_ty);
                let cast = inner
                    .as_ref()
                    .and_then(int_cell_init_cast)
                    .unwrap_or_else(|| quote! { as u64 });
                let n = *n as u64;
                Some(quote! { (#n #cast) })
            }
            LiteralIR::Bool(b) => Some(quote! { #b }),
            LiteralIR::Str(_) => None,
        },
        ExprIR::Path { path, .. } => {
            // Enum variant literal: `Cell::new(Status::Open)`.
            // Resolve via user_enums; emit the variant's u8 discriminant.
            let segs: Vec<String> = path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if segs.len() < 2 {
                return None;
            }
            let enum_name = &segs[segs.len() - 2];
            let variant_name = &segs[segs.len() - 1];
            let variants = user_enums.get(enum_name)?;
            let disc = variants.iter().position(|v| v.name == *variant_name)? as u8;
            Some(quote! { #disc })
        }
        _ => None,
    }
}

/// Pick the integer cast (`as u8`, `as u32`, ...) appropriate for a
/// `Cell<T>` whose `T` is a fixed-width integer wrapper, so the
/// `AlignedValue::from` we emit matches the wire alignment the contract
/// expects.
fn int_cell_init_cast(inner: &syn::Type) -> Option<TokenStream> {
    let s = quote!(#inner).to_string().replace(' ', "");
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
