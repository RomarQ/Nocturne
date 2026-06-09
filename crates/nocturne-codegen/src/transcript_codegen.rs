//! Transcript codegen: generates Rust code that builds transcript `Op` programs
//! at runtime. This replaces Compact's TypeScript runtime.
//!
//! The generated code:
//! - Accepts typed witness structs (not `dyn Any`)
//! - Evaluates conditions at runtime to select active branches
//! - Only emits ops for the active branch (matching ZKIR's pi_skip behavior)
//! - Converts witness values to `Fr` for the private transcript

use nocturne_ir::{CircuitIR, ContractIR, ExprIR, UserEnumVariant, UserStructField, WitnessIR};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashMap;

/// Cross-cutting state every transcript-codegen helper threads through.
/// Bundling these into one borrow lets helpers stay readable instead of
/// growing 5–8 parameter lists, and matches the shape of the per-contract
/// information the proc macro already collects once at the top.
struct TranscriptCtx<'a> {
    field_names: &'a [String],
    field_types: &'a [syn::Type],
    witness_types: &'a HashMap<String, syn::Type>,
    user_structs: &'a HashMap<String, Vec<UserStructField>>,
    user_enums: &'a HashMap<String, Vec<UserEnumVariant>>,
}

/// Generate the transcript builder module for a contract.
pub fn generate_transcript_module(contract: &ContractIR) -> TokenStream {
    let field_names: Vec<String> = contract
        .ledger
        .fields
        .iter()
        .map(|f| f.name.to_string())
        .collect();

    let field_types: Vec<syn::Type> = contract
        .ledger
        .fields
        .iter()
        .map(|f| f.ty.clone())
        .collect();

    let witnesses_name = contract.witnesses.as_ref().map(|w| &w.name);
    let ledger_name = &contract.ledger.name;
    let witness_types: HashMap<String, syn::Type> = contract
        .witnesses
        .as_ref()
        .map(witness_type_map)
        .unwrap_or_default();

    let ctx = TranscriptCtx {
        field_names: &field_names,
        field_types: &field_types,
        witness_types: &witness_types,
        user_structs: &contract.user_structs,
        user_enums: &contract.user_enums,
    };

    let circuit_fns: Vec<TokenStream> = contract
        .circuits
        .iter()
        .map(|circuit| generate_circuit_transcript_fn(circuit, witnesses_name, ledger_name, &ctx))
        .collect();

    quote! {
        /// Generated transcript builders for contract circuits.
        pub mod transcript {
            use super::*;
            use nocturne::runtime::onchain_vm::result_mode::ResultModeVerify;
            use nocturne::runtime::onchain_vm::ops::{Op, Key};
            use nocturne::runtime::onchain_state::state::StateValue;
            use nocturne::runtime::transient_crypto::curve::Fr;
            use nocturne::runtime::base_crypto::fab::AlignedValue;
            use nocturne::runtime::storage::arena::Sp;

            /// Type alias for verify-mode operations.
            pub type VmOp = Op<ResultModeVerify>;

            /// The result of building a transcript for a circuit call.
            pub struct TranscriptResult {
                /// VM operations for the transcript.
                pub ops: Vec<VmOp>,
                /// Private transcript values (witnesses as field elements).
                pub private_transcript: Vec<Fr>,
            }

            #(#circuit_fns)*
        }
    }
}

/// Generate a transcript builder function for a single circuit.
///
/// When the circuit body contains ledger reads that need the live state to
/// compute their expected results (today: `Map::contains`), the generated
/// function takes an extra `state: &<LedgerStructName>` parameter so the
/// transcript builder can call back into the runtime stub and bake the
/// result into `Op::Popeq { result }`. Circuits that don't read keep the
/// minimal signature for backwards compatibility with existing call sites.
fn generate_circuit_transcript_fn(
    circuit: &CircuitIR,
    witnesses_name: Option<&syn::Ident>,
    ledger_name: &syn::Ident,
    ctx: &TranscriptCtx<'_>,
) -> TokenStream {
    let fn_name = format_ident!("build_{}_transcript", circuit.name);
    let doc = format!("Build the transcript for the `{}` circuit.", circuit.name);

    let body_stmts: Vec<TokenStream> = circuit
        .body
        .iter()
        .map(|expr| generate_op_stmt(expr, ctx))
        .collect();

    let needs_state = circuit_needs_state(&circuit.body);
    let state_param = if needs_state {
        quote! { state: &#ledger_name, }
    } else {
        quote! {}
    };

    if circuit.takes_witnesses {
        let param_name = circuit
            .witnesses_param_name
            .as_ref()
            .map(|n| format_ident!("{}", n))
            .unwrap_or_else(|| format_ident!("witnesses"));

        let witnesses_ty = witnesses_name
            .map(|n| quote! { &#n })
            .unwrap_or_else(|| quote! { &() });

        quote! {
            #[doc = #doc]
            pub fn #fn_name(#state_param #param_name: #witnesses_ty) -> TranscriptResult {
                let mut ops: Vec<VmOp> = Vec::new();
                let mut private_transcript: Vec<Fr> = Vec::new();

                #(#body_stmts)*

                TranscriptResult { ops, private_transcript }
            }
        }
    } else if needs_state {
        quote! {
            #[doc = #doc]
            pub fn #fn_name(state: &#ledger_name) -> TranscriptResult {
                let mut ops: Vec<VmOp> = Vec::new();
                let mut private_transcript: Vec<Fr> = Vec::new();

                #(#body_stmts)*

                TranscriptResult { ops, private_transcript }
            }
        }
    } else {
        quote! {
            #[doc = #doc]
            pub fn #fn_name() -> TranscriptResult {
                let mut ops: Vec<VmOp> = Vec::new();
                let mut private_transcript: Vec<Fr> = Vec::new();

                #(#body_stmts)*

                TranscriptResult { ops, private_transcript }
            }
        }
    }
}

/// Returns true if any sub-expression in the body is a ledger read that
/// requires the live state to compute its expected result (currently:
/// `Map::contains`). Lookup/get on `Cell` don't currently bake a state-
/// dependent value into the transcript so they're excluded here.
fn circuit_needs_state(body: &[ExprIR]) -> bool {
    body.iter().any(expr_needs_state)
}

fn expr_needs_state(expr: &ExprIR) -> bool {
    match expr {
        ExprIR::LedgerAccess { method, args, .. } => {
            let m = method.to_string();
            matches!(
                m.as_str(),
                "contains"
                    | "member"
                    | "lookup"
                    | "get"
                    | "value"
                    | "__direct_access"
                    | "check_root"
            ) || args.iter().any(expr_needs_state)
        }
        ExprIR::If {
            cond,
            then_branch,
            else_branch,
            ..
        } => {
            expr_needs_state(cond)
                || then_branch.iter().any(expr_needs_state)
                || else_branch
                    .as_ref()
                    .is_some_and(|b| b.iter().any(expr_needs_state))
        }
        ExprIR::Block { stmts, .. } => stmts.iter().any(expr_needs_state),
        ExprIR::Let { value, .. } => expr_needs_state(value),
        ExprIR::MethodCall { receiver, args, .. } => {
            expr_needs_state(receiver) || args.iter().any(expr_needs_state)
        }
        ExprIR::BinaryOp { lhs, rhs, .. } => expr_needs_state(lhs) || expr_needs_state(rhs),
        ExprIR::UnaryOp { expr: inner, .. } => expr_needs_state(inner),
        ExprIR::Reference { expr: inner, .. } => expr_needs_state(inner),
        ExprIR::Disclose { value, .. } => expr_needs_state(value),
        _ => false,
    }
}

/// Generate Rust statements that push VM Ops.
fn generate_op_stmt(expr: &ExprIR, ctx: &TranscriptCtx<'_>) -> TokenStream {
    let field_names = ctx.field_names;
    let field_types = ctx.field_types;
    let witness_types = ctx.witness_types;
    let user_structs = ctx.user_structs;
    match expr {
        ExprIR::LedgerAccess {
            field,
            method,
            args,
            ..
        } => {
            let field_name = field.to_string();
            let method_name = method.to_string();
            // Internal invariant: rustc rejects typos on the real ledger
            // struct, so an unknown name here is a parser/codegen bug.
            // Falling back to field 0 would emit a verified-but-wrong
            // transcript write.
            let field_idx = field_names
                .iter()
                .position(|f| f == &field_name)
                .unwrap_or_else(|| {
                    panic!(
                        "nocturne internal error: ledger field `{field_name}` not \
                         found among {field_names:?}"
                    )
                }) as u8;
            let field_ty = field_types.get(field_idx as usize);

            match method_name.as_str() {
                "increment" | "increment_by" => {
                    // `Counter::increment()` (no arg) or
                    // `Counter::increment_by(N)` for a const literal N
                    // emit the same Addi { immediate: N }. Non-literal
                    // arguments are rejected as a compile error in the
                    // generated module so the user sees a real diagnostic.
                    let n: u32 = match args.first() {
                        None => 1,
                        Some(ExprIR::Literal {
                            value: nocturne_ir::expr::LiteralIR::Int(v),
                            ..
                        }) if *v <= u32::MAX as u128 => *v as u32,
                        Some(_) => {
                            return quote! {
                                compile_error!(
                                    "Counter::increment_by(n) currently only \
                                     supports a const integer literal for n"
                                );
                            };
                        }
                    };
                    quote! {
                        ops.push(Op::Idx {
                            cached: false,
                            push_path: true,
                            path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
                        });
                        ops.push(Op::Addi { immediate: #n });
                        ops.push(Op::Ins { cached: true, n: 1 });
                    }
                }
                "get" | "value" | "__direct_access" => {
                    // On-chain read pattern: Dup + Idx + Popeq{cached:true, result}.
                    // The `result` must be the actual value the on-chain VM will
                    // compute, so compute it from `state` here. Counter uses
                    // `.value()` (returns u64), Cell<T> uses `.get()` (returns T).
                    let field_ident = format_ident!("{}", field_name);
                    let (accessor, result_ty) = match field_ty {
                        Some(t) if is_counter_type(t) => (
                            quote! { state.#field_ident.value() },
                            Some(syn::parse_quote!(u64)),
                        ),
                        Some(t) if extract_cell_inner_type(t).is_some() => (
                            quote! { state.#field_ident.get() },
                            extract_cell_inner_type(t),
                        ),
                        // Unknown field type — emit a compile_error so the
                        // user sees the source of the mismatch instead of
                        // an on-chain verifier rejection. The previous
                        // `0u8` placeholder produced a passing build whose
                        // Popeq result didn't match the live state.
                        _ => {
                            let kind = field_ty
                                .map(|t| quote!(#t).to_string())
                                .unwrap_or_else(|| "<missing>".to_string());
                            let msg = format!(
                                "nocturne: ledger read on field `{}` (type `{}`) — only Counter and Cell<T> are supported",
                                field_name, kind,
                            );
                            return quote! { compile_error!(#msg); };
                        }
                    };
                    // Choose the AlignedValue construction expression based
                    // on whether T is a multi-Fr `Bytes<N>` or a single-Fr
                    // primitive. Same logic as Cell::set's value side, but
                    // here the input is `state.<f>.get()` (a wrapper) rather
                    // than a user argument.
                    let aligned_arg = match result_ty.as_ref() {
                        Some(t)
                            if {
                                let s = quote!(#t).to_string().replace(' ', "");
                                s.starts_with("Bytes<")
                            } =>
                        {
                            quote! { *(#accessor).as_bytes() }
                        }
                        // Fixed-size array `[U; N]`: build the same N-tuple
                        // shape `aligned_value_arg_expr` produces for arrays,
                        // so the Popeq's AlignedValue lines up with the
                        // ZKIR Popeq's multi-Fr per-element layout.
                        Some(t) if extract_array_type(t).is_some() => {
                            let (elem_ty, n) = extract_array_type(t).unwrap();
                            let comps: Vec<TokenStream> = (0..n as usize)
                                .map(|i| {
                                    let idx = syn::Index::from(i);
                                    tuple_component_aligned_repr(&elem_ty, &quote! { __a[#idx] })
                                })
                                .collect();
                            let trailing = if n == 1 {
                                quote! { , }
                            } else {
                                quote! {}
                            };
                            quote! {
                                {
                                    let __a = #accessor;
                                    (#(#comps),* #trailing)
                                }
                            }
                        }
                        Some(t) if quote!(#t).to_string().replace(' ', "") == "Field" => {
                            // `Cell<Field>::get()` returns Field; convert to
                            // Fr for AlignedValue::from (which picks the
                            // Field alignment via Fr's Aligned impl).
                            quote! { Fr::from((#accessor).value()) }
                        }
                        // User enum: discriminant alone for unit-only enums,
                        // or `(discriminant, payload)` tuple for homogeneous
                        // payload enums. The payload is extracted with an
                        // inline match — same shape used in the deploy
                        // codegen and the set/AlignedValue paths.
                        Some(t) if is_enum_like(t, ctx.user_enums) => {
                            match enum_like_payload_type(t, ctx.user_enums) {
                                None => {
                                    let disc = enum_like_discriminant_expr(&accessor, t);
                                    quote! { #disc }
                                }
                                Some(p) => {
                                    let payload_match =
                                        enum_payload_match_expr(&quote! { __e.clone() }, t, ctx)
                                            .unwrap_or_else(|| quote! { unreachable!() });
                                    let payload_repr =
                                        tuple_component_aligned_repr(&p, &quote! { __payload });
                                    let disc = enum_like_discriminant_expr(&quote! { __e }, t);
                                    quote! {
                                        {
                                            let __e = #accessor;
                                            let __payload = #payload_match;
                                            (#disc, #payload_repr)
                                        }
                                    }
                                }
                            }
                        }
                        Some(t) => match primitive_cast_for_type(t) {
                            Some(c) => quote! { (#accessor) #c },
                            None => quote! { #accessor },
                        },
                        None => quote! { #accessor },
                    };
                    quote! {
                        ops.push(Op::Dup { n: 0 });
                        ops.push(Op::Idx {
                            cached: false,
                            push_path: false,
                            path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
                        });
                        ops.push(Op::Popeq {
                            cached: true,
                            result: AlignedValue::from(#aligned_arg),
                        });
                    }
                }
                "contains" | "member" => {
                    // Statement context: emit the contains ops and discard
                    // the bool result. The shared `generate_map_contains_block`
                    // builds a block expression that pushes ops and evaluates
                    // to the bool — when used as a statement, the bool is
                    // dropped; when used inside `if cond { ... }` as the cond
                    // (via `generate_runtime_cond`), the bool drives branching.
                    // Works for both Map and Set fields (same Member opcode,
                    // K type resolved via extract_field_key_type).
                    let block =
                        generate_map_contains_block(field_idx, &field_name, args, field_ty, ctx);
                    quote! { let _ = #block; }
                }
                "insert" => {
                    // Dispatch by field type: Map → Map::insert (k, v),
                    // Set → Set::insert (k, Null), MerkleTree → 10-op
                    // append-and-rehash sequence, Cell → Cell::set (v).
                    if field_ty.and_then(extract_map_kv_types).is_some() {
                        generate_map_insert(field_idx, args, field_ty, ctx)
                    } else if field_ty.and_then(extract_set_inner_type).is_some() {
                        generate_set_insert(field_idx, args, field_ty, ctx)
                    } else if field_ty.and_then(extract_merkle_tree_type).is_some() {
                        generate_merkle_tree_insert(field_idx, args)
                    } else {
                        generate_cell_set(field_idx, args, field_ty, ctx)
                    }
                }
                "set" => {
                    // `set` is also used as an alias for Map::insert. Route
                    // based on the field type.
                    if field_ty.and_then(extract_map_kv_types).is_some() {
                        generate_map_insert(field_idx, args, field_ty, ctx)
                    } else {
                        generate_cell_set(field_idx, args, field_ty, ctx)
                    }
                }
                "remove" if field_ty.and_then(extract_map_kv_types).is_some() => {
                    generate_map_remove(field_idx, args, field_ty, ctx)
                }
                "remove" if field_ty.and_then(extract_set_inner_type).is_some() => {
                    // Set::remove has the same on-chain pattern as Map::remove.
                    generate_set_remove(field_idx, args, field_ty, ctx)
                }
                "lookup" if field_ty.and_then(extract_map_kv_types).is_some() => {
                    generate_map_lookup(field_idx, &field_name, args, field_ty, ctx)
                }
                "check_root" if field_ty.and_then(extract_merkle_tree_type).is_some() => {
                    generate_merkle_tree_check_root(field_idx, &field_name, args)
                }
                other => {
                    // Unknown ledger-method call — emit a compile_error
                    // pointing at the call site instead of silently
                    // dropping the op. Silent fallthrough produces a
                    // transcript that doesn't match what ZKIR emitted,
                    // which only surfaces at on-chain verify with no
                    // hint at the source.
                    let msg = format!(
                        "nocturne: unknown ledger method `{}` on field `{}` (or wrong field kind for this method)",
                        other, field_name
                    );
                    quote! { compile_error!(#msg); }
                }
            }
        }

        ExprIR::If {
            cond,
            then_branch,
            else_branch,
            ..
        } => {
            // Collect witness values used in the condition for private_transcript.
            let witness_adds = collect_witness_private_inputs(cond, ctx);
            let cond_expr = generate_runtime_cond(cond, ctx);
            let then_stmts: Vec<TokenStream> = then_branch
                .iter()
                .map(|e| generate_op_stmt(e, ctx))
                .collect();

            if let Some(else_exprs) = else_branch {
                let else_stmts: Vec<TokenStream> = else_exprs
                    .iter()
                    .map(|e| generate_op_stmt(e, ctx))
                    .collect();
                quote! {
                    #witness_adds
                    if #cond_expr {
                        #(#then_stmts)*
                    } else {
                        #(#else_stmts)*
                    }
                }
            } else {
                quote! {
                    #witness_adds
                    if #cond_expr {
                        #(#then_stmts)*
                    }
                }
            }
        }

        ExprIR::Let { name, value, .. } => {
            // The block form lets `generate_op_stmt`'s trailing
            // expression (e.g. `merkle_tree_path_root(arg)` for that
            // FnCall arm) flow into the binding. Plain witness reads
            // produce `()` because `WitnessAccess` is statement-only;
            // we patch that single case below so `let v = w.f; ...
            // cell.set(v);` binds to the real witness value instead of
            // unit.
            let var_name = format_ident!("{}", name.to_string());
            let val_stmt = generate_op_stmt(value, ctx);
            // Pull the witness binding out separately so the block
            // evaluates to a real value rather than `()`. Handles bare
            // `witnesses.f` and `witnesses.f.<method>()` (most commonly
            // `.clone()`) — both produce statement-only side effects
            // in `generate_op_stmt` so the let block otherwise binds
            // unit.
            if let Some(expr) = let_binding_runtime_value(value, ctx) {
                return quote! {
                    #val_stmt
                    #[allow(non_snake_case, unused_variables)]
                    let #var_name = #expr;
                };
            }
            // Cell::get() / Counter::value() reads — bind to the live
            // state's accessor so `let v = self.f.get(); ...; use v`
            // works downstream. The ops side (Dup+Idx+Popeq) is
            // already emitted via `val_stmt`.
            if let Some(expr) = let_binding_value_for_ledger_read(value, ctx) {
                return quote! {
                    #val_stmt
                    #[allow(non_snake_case, unused_variables)]
                    let #var_name = #expr;
                };
            }
            quote! {
                #[allow(non_snake_case, unused_variables)]
                let #var_name = {
                    #val_stmt
                };
            }
        }

        ExprIR::WitnessAccess { field, .. } => {
            // Read the witness value and add it to the private transcript.
            // The pushed Frs must match the IR's PrivateInputs in count
            // AND order — see `witness_fr_layout` in zkir_emitter.rs.
            //
            // Single-Fr witnesses (Boolean/Field/Uint) push
            // `Fr::from(value())` directly. Multi-Fr witnesses (`Bytes<N>`)
            // build an AlignedValue from the underlying [u8; N] and use
            // `AlignedValueExt::value_only_field_repr`. `MerkleTreeDigest`
            // is a newtype around `Field` so reach through `.field().value()`.
            // `MerkleTreePath<H, T>` deconstructs into leaf + path entries.
            let field_ident = format_ident!("{}", field.to_string());
            let field_str = field.to_string();
            let witness_ty = witness_types.get(&field_str);
            if witness_ty.map(is_bytes_witness).unwrap_or(false) {
                quote! {
                    {
                        use nocturne::runtime::transient_crypto::fab::AlignedValueExt;
                        let __av = AlignedValue::from(*witnesses.#field_ident.as_bytes());
                        __av.value_only_field_repr(&mut private_transcript);
                    }
                }
            } else if witness_ty.map(is_merkle_tree_digest).unwrap_or(false) {
                // Reconstruct the full Fr from the digest's 32-byte LE
                // representation. Truncating through `.field().value()`
                // would discard the upper bits and break proof
                // verification when the digest came from a real Merkle
                // computation (e.g. `MerkleTree::root()`).
                quote! {
                    private_transcript.push(
                        Fr::from_le_bytes(&witnesses.#field_ident.as_le_bytes())
                            .expect("MerkleTreeDigest bytes round-trip through Fr"),
                    );
                }
            } else if witness_ty.map(is_merkle_tree_path).unwrap_or(false) {
                quote! {
                    {
                        use nocturne::runtime::transient_crypto::fab::AlignedValueExt;
                        // Leaf: same multi-Fr push as a Bytes<N> witness.
                        let __av = AlignedValue::from(
                            *witnesses.#field_ident.leaf.as_bytes()
                        );
                        __av.value_only_field_repr(&mut private_transcript);
                        // Each entry: full-Fr sibling + 1 Fr goes_left.
                        for __entry in witnesses.#field_ident.path.iter() {
                            private_transcript.push(
                                Fr::from_le_bytes(&__entry.sibling.as_le_bytes())
                                    .expect("MerkleTreeDigest bytes round-trip through Fr"),
                            );
                            private_transcript.push(Fr::from(__entry.goes_left.value() as u64));
                        }
                    }
                }
            } else if let Some((_elem_ty, _n)) = witness_ty.and_then(extract_array_type) {
                // Fixed-size array witness `[T; N]`: push N elements in
                // index order. `component_private_push`'s Array arm
                // handles the per-element walk; we just hand it the
                // base accessor.
                let ty = witness_ty.unwrap();
                component_private_push(ty, &quote! { witnesses.#field_ident }, ctx)
            } else if let Some(fields) =
                witness_ty.and_then(|t| user_struct_fields(t, user_structs))
            {
                // User-defined struct witness: project each field by
                // name and push its per-component Fr in declaration
                // order. Mirrors the tuple expansion in
                // `aligned_value_arg_expr` but for named structs.
                let pushes: Vec<TokenStream> = fields
                    .iter()
                    .map(|f| {
                        let fname = f.name.clone();
                        let accessor = quote! { witnesses.#field_ident.#fname };
                        component_private_push(&f.ty, &accessor, ctx)
                    })
                    .collect();
                quote! { #(#pushes)* }
            } else if witness_ty
                .map(|t| is_enum_like(t, ctx.user_enums))
                .unwrap_or(false)
            {
                // Enum-like witness (`Option<T>` or a user enum): push
                // the discriminant first, then for homogeneous payloads
                // also push the payload's per-component Frs. The
                // payload is extracted via an inline `match` over the
                // witness value — the same way user code would extract
                // it via pattern matching.
                let payload = witness_ty.and_then(|t| enum_like_payload_type(t, ctx.user_enums));
                let ty = witness_ty.unwrap();
                let disc = enum_like_discriminant_expr(&quote! { witnesses.#field_ident }, ty);
                match payload {
                    Some(p) => {
                        let payload_match = enum_payload_match_expr(
                            &quote! { witnesses.#field_ident.clone() },
                            ty,
                            ctx,
                        )
                        .unwrap_or_else(|| quote! { unreachable!() });
                        let payload_pushes = component_private_push(&p, &quote! { __payload }, ctx);
                        quote! {
                            private_transcript.push(Fr::from((#disc) as u64));
                            {
                                let __payload = #payload_match;
                                #payload_pushes
                            }
                        }
                    }
                    None => quote! {
                        private_transcript.push(Fr::from((#disc) as u64));
                    },
                }
            } else {
                quote! {
                    private_transcript.push(Fr::from(witnesses.#field_ident.value()));
                }
            }
        }

        ExprIR::Block { stmts, .. } => {
            let inner: Vec<TokenStream> = stmts.iter().map(|s| generate_op_stmt(s, ctx)).collect();
            quote! { #(#inner)* }
        }

        ExprIR::MethodCall { receiver, .. } => {
            // Always forward to the receiver so any side-effecting
            // sub-expressions (e.g. witness reads that push to
            // `private_transcript`) are emitted. Method-specific runtime
            // behavior is generated elsewhere; this arm is just about
            // side effects on the transcript builder's state.
            generate_op_stmt(receiver, ctx)
        }

        // Free-function calls used as RHS of `let` or as standalone
        // statements. The transcript side must:
        //   (a) emit private-transcript pushes for any witness args, and
        //   (b) yield a runtime Rust expression that evaluates to the
        //       same value the IR computes — so the resulting `let` binds
        //       a real value the surrounding code can pass into ledger
        //       method calls (e.g. `check_root(&computed)`).
        ExprIR::FnCall { name, args, .. } => {
            // Emit witness pushes from any path-typed args first.
            let witness_emits: Vec<TokenStream> =
                args.iter().map(|a| generate_op_stmt(a, ctx)).collect();
            let name_str = name.to_string();
            let value_expr = match name_str.as_str() {
                "merkle_tree_path_root" => {
                    let arg = args
                        .first()
                        .map(arg_to_runtime_raw_expr)
                        .unwrap_or_else(|| quote! { () });
                    quote! { nocturne::types::merkle_tree_path_root(&#arg) }
                }
                _ => quote! { () },
            };
            quote! {
                #(#witness_emits)*
                #value_expr
            }
        }

        // Reference (`&expr`) forwards to its inner so side effects
        // bubble up through `&witnesses.path` etc.
        ExprIR::Reference { expr: inner, .. } => generate_op_stmt(inner, ctx),

        // BinaryOp at statement level only carries side effects via
        // witness reads on either side; the arithmetic itself doesn't
        // affect the transcript. Forward to each operand so the
        // private-transcript pushes still get emitted in operand order.
        ExprIR::BinaryOp { lhs, rhs, .. } => {
            let l = generate_op_stmt(lhs, ctx);
            let r = generate_op_stmt(rhs, ctx);
            quote! { #l #r }
        }
        ExprIR::UnaryOp { expr: inner, .. } => generate_op_stmt(inner, ctx),

        // An expression the IR couldn't lower (e.g. a Rust pattern Nocturne
        // doesn't model yet). Emit a `compile_error!` carrying the IR's
        // description so the user gets a real diagnostic instead of a
        // silently-zero side-effect.
        ExprIR::Unsupported { description, .. } => {
            let msg = format!("nocturne: unsupported expression in circuit body: {description}");
            quote! { compile_error!(#msg); }
        }

        // `assert!(cond)` / `assert_eq!(a, b)` — at transcript-build
        // time we evaluate the same condition in plain Rust so the
        // builder fails fast when a witness violates the invariant,
        // before the prover wastes work on an impossible proof. The
        // ZKIR side emits the in-circuit constraint separately.
        ExprIR::Assert { kind, .. } => match kind {
            nocturne_ir::expr::AssertKind::Assert(cond) => {
                let witness_pushes = collect_witness_private_inputs(cond, ctx);
                let cond_expr = generate_runtime_cond(cond, ctx);
                quote! {
                    #witness_pushes
                    assert!(#cond_expr, "nocturne: circuit assertion failed");
                }
            }
            nocturne_ir::expr::AssertKind::AssertEq(a, b) => {
                let wa = collect_witness_private_inputs(a, ctx);
                let wb = collect_witness_private_inputs(b, ctx);
                let la = generate_runtime_cond(a, ctx);
                let lb = generate_runtime_cond(b, ctx);
                quote! {
                    #wa
                    #wb
                    assert_eq!(#la, #lb, "nocturne: circuit assert_eq! failed");
                }
            }
        },

        _ => quote! {},
    }
}

/// If `value` is a `self.<field>.<get|value>()` ledger read, build the
/// Rust expression that fetches the same value from the live `state`.
/// Returns `None` for other shapes.
fn let_binding_value_for_ledger_read(
    value: &ExprIR,
    ctx: &TranscriptCtx<'_>,
) -> Option<TokenStream> {
    let field_names = ctx.field_names;
    let ExprIR::LedgerAccess { field, method, .. } = value else {
        return None;
    };
    if !field_names.iter().any(|f| f == &field.to_string()) {
        return None;
    }
    let f_ident = format_ident!("{}", field.to_string());
    match method.to_string().as_str() {
        "get" => Some(quote! { state.#f_ident.get() }),
        "value" | "__direct_access" => Some(quote! { state.#f_ident.value() }),
        _ => None,
    }
}

/// Build the right-hand side Rust expression for a `let` binding when
/// the value has a usable Rust shape — covers witness reads (and
/// method chains rooted at them), bare locals, literals, references,
/// arithmetic, and enum-payload projections. Returns `None` for any
/// shape we don't model, so the caller falls back to the historical
/// block-wrapping path that captures `generate_op_stmt`'s trailing
/// expression instead.
fn let_binding_runtime_value(value: &ExprIR, ctx: &TranscriptCtx<'_>) -> Option<TokenStream> {
    let user_enums = ctx.user_enums;
    match value {
        ExprIR::WitnessAccess { field, .. } => {
            let f = format_ident!("{}", field.to_string());
            Some(quote! { witnesses.#f.clone() })
        }
        // Parametric witness call as a let RHS: `let v = witnesses.foo(args);`
        // becomes `let v = witnesses.foo(arg1, ...)` at runtime.
        ExprIR::WitnessCall { name, args, .. } => {
            let m = format_ident!("{}", name.to_string());
            let arg_exprs: Vec<TokenStream> = args.iter().map(arg_to_runtime_raw_expr).collect();
            Some(quote! { witnesses.#m(#(#arg_exprs),*) })
        }
        // Match-arm payload binding: `let amount = EnumPayload(scrutinee, EnumName)`
        // lowers to an inline Rust `match` over the scrutinee, binding the
        // homogeneous payload from whichever variant carries it. No synthetic
        // accessor on the enum — the user-facing surface is plain pattern
        // matching, and the generated code uses the same construct.
        ExprIR::EnumPayload {
            scrutinee,
            enum_name,
            ..
        } => {
            let scrutinee_expr = let_binding_runtime_value(scrutinee, ctx)?;
            // `Option` is the synthetic marker the parser uses for
            // single-segment `Some`/`None` patterns; codegen knows the
            // arm names without a user_enums lookup.
            if enum_name == "Option" {
                return Some(quote! {
                    match #scrutinee_expr {
                        ::core::option::Option::Some(__p) => __p,
                        ::core::option::Option::None => ::core::default::Default::default(),
                    }
                });
            }
            let variants = user_enums.get(&enum_name.to_string())?;
            let arms: Vec<TokenStream> = variants
                .iter()
                .map(|v| {
                    let v_ident = v.name.clone();
                    quote! { #enum_name::#v_ident(__p) => __p }
                })
                .collect();
            Some(quote! {
                match #scrutinee_expr {
                    #(#arms),*
                }
            })
        }
        ExprIR::MethodCall {
            receiver,
            method,
            args,
            ..
        } => {
            let recv = let_binding_runtime_value(receiver, ctx)?;
            let m = format_ident!("{}", method.to_string());
            // Each method-call argument needs its own runtime value; we
            // recurse through the same `let_binding_runtime_value`
            // dispatch so witness reads, vars, references, and the
            // rest stay consistent with how the let binding evaluates
            // its own RHS. Bail if any arg has no usable shape so the
            // outer caller falls back to the block-wrapping path.
            let mut arg_exprs: Vec<TokenStream> = Vec::with_capacity(args.len());
            for a in args {
                arg_exprs.push(let_binding_runtime_value(a, ctx)?);
            }
            Some(quote! { (#recv).#m(#(#arg_exprs),*) })
        }
        ExprIR::Reference { expr, .. } => {
            let inner = let_binding_runtime_value(expr, ctx)?;
            Some(quote! { (#inner) })
        }
        // Arithmetic over witness reads: bind to the equivalent Rust
        // expression so e.g. `let s = w.a + w.b;` works downstream.
        ExprIR::BinaryOp { op, lhs, rhs, .. } => {
            let l = let_binding_runtime_value(lhs, ctx)?;
            let r = let_binding_runtime_value(rhs, ctx)?;
            let tokens = match op {
                syn::BinOp::Add(_) => quote! { #l + #r },
                syn::BinOp::Sub(_) => quote! { #l - #r },
                syn::BinOp::Mul(_) => quote! { #l * #r },
                syn::BinOp::BitAnd(_) => quote! { #l & #r },
                syn::BinOp::BitOr(_) => quote! { #l | #r },
                syn::BinOp::BitXor(_) => quote! { #l ^ #r },
                _ => return None,
            };
            Some(tokens)
        }
        ExprIR::Literal { value, .. } => match value {
            nocturne_ir::expr::LiteralIR::Int(n) => Some(int_literal_tokens(*n)),
            nocturne_ir::expr::LiteralIR::Bool(b) => Some(quote! { #b }),
            nocturne_ir::expr::LiteralIR::Str(_) => None,
        },
        // Var ident from an earlier let binding — re-bind by cloning so the
        // downstream consumer treats it as an owned value.
        ExprIR::Var { name, .. } => {
            let ident = format_ident!("{}", name.to_string());
            Some(quote! { #ident.clone() })
        }
        // `let x = arr[i];` — emit a Rust index expression over the
        // array sub-expression's runtime value.
        ExprIR::Index { array, index, .. } => {
            let arr = let_binding_runtime_value(array, ctx)?;
            let idx = syn::Index::from(*index as usize);
            Some(quote! { (#arr)[#idx].clone() })
        }
        // `let x = if c { a } else { b };` — mirror the ZKIR's
        // cond_select multiplex with a Rust `if`-expression that
        // evaluates the last statement of each branch and selects
        // based on the condition. Falls back to `None` if either
        // branch's terminal expression has no usable value shape
        // (caller drops into the block-wrap path which still
        // captures side effects but yields `()`).
        ExprIR::If {
            cond,
            then_branch,
            else_branch,
            ..
        } => {
            let else_stmts = else_branch.as_ref()?;
            let then_last = then_branch.last()?;
            let else_last = else_stmts.last()?;
            let then_value = let_binding_runtime_value(then_last, ctx)?;
            let else_value = let_binding_runtime_value(else_last, ctx)?;
            let cond_expr = generate_runtime_cond(cond, ctx);
            Some(quote! {
                if #cond_expr { #then_value } else { #else_value }
            })
        }
        _ => None,
    }
}

/// Collect witness field accesses in a condition expression and
/// generate code to add their values to private_transcript. Type-aware
/// so enum and Bytes/digest witnesses use the same push shape as the
/// `WitnessAccess` arm of `generate_op_stmt`.
fn collect_witness_private_inputs(expr: &ExprIR, ctx: &TranscriptCtx<'_>) -> TokenStream {
    let witness_types = ctx.witness_types;
    match expr {
        ExprIR::WitnessAccess { field, .. } => {
            let field_ident = format_ident!("{}", field.to_string());
            let field_str = field.to_string();
            let witness_ty = witness_types.get(&field_str);
            if witness_ty
                .map(|t| is_enum_like(t, ctx.user_enums))
                .unwrap_or(false)
            {
                let disc = enum_like_discriminant_expr(
                    &quote! { witnesses.#field_ident },
                    witness_ty.unwrap(),
                );
                quote! {
                    private_transcript.push(Fr::from((#disc) as u64));
                }
            } else if witness_ty.and_then(extract_array_type).is_some() {
                // Fixed-size array witness: ZKIR pre-allocated N slots
                // on first witness touch, so the condition collector
                // has to push the same N values.
                let ty = witness_ty.unwrap();
                component_private_push(ty, &quote! { witnesses.#field_ident }, ctx)
            } else {
                quote! {
                    private_transcript.push(Fr::from(witnesses.#field_ident.value() as u64));
                }
            }
        }
        ExprIR::MethodCall { receiver, .. } => collect_witness_private_inputs(receiver, ctx),
        ExprIR::Index { array, .. } => {
            // `witnesses.arr[i]` in a condition: the WitnessAccess
            // allocates ALL N*len(T) wires on first touch, so we must
            // push the entire array's contents — not just the indexed
            // element. Delegate to the inner WitnessAccess and push it
            // as an array.
            collect_witness_private_inputs(array, ctx)
        }
        ExprIR::BinaryOp { lhs, rhs, .. } => {
            let l = collect_witness_private_inputs(lhs, ctx);
            let r = collect_witness_private_inputs(rhs, ctx);
            quote! { #l #r }
        }
        ExprIR::UnaryOp { expr: inner, .. } => collect_witness_private_inputs(inner, ctx),
        ExprIR::Reference { expr: inner, .. } => collect_witness_private_inputs(inner, ctx),
        ExprIR::Disclose { value: inner, .. } => collect_witness_private_inputs(inner, ctx),
        ExprIR::FnCall { args, .. } => {
            // `merkle_tree_path_root(&witnesses.path)` and similar
            // builtins recurse into their args so the witness reads
            // they carry get pushed before the condition evaluates.
            let pushes: Vec<TokenStream> = args
                .iter()
                .map(|a| collect_witness_private_inputs(a, ctx))
                .collect();
            quote! { #(#pushes)* }
        }
        _ => quote! {},
    }
}

/// Tokens for an integer literal carried in the IR as `u128`. Values
/// fitting `u64` keep the `u64`-suffixed form (existing inference
/// behavior); larger values emit a `u128`-suffixed literal so the
/// runtime transcript carries the full value the circuit's `LoadImm`
/// declares — truncating through `as u64` here would make prove fail
/// (or worse, silently disagree) for any literal above `u64::MAX`.
fn int_literal_tokens(n: u128) -> TokenStream {
    match u64::try_from(n) {
        Ok(v) => quote! { #v },
        Err(_) => quote! { #n },
    }
}

/// Generate a runtime Rust expression that evaluates to the value of an
/// argument expression, suitable for wrapping in `AlignedValue::from(...)`.
///
/// Used by the `set` arm above to materialize the value being written into a
/// `Cell<T>` at runtime. Handles the cases the IR currently emits for
/// arguments: literals, `disclose(...)`, witness reads, and local variables.
fn arg_to_runtime_expr(expr: &ExprIR) -> TokenStream {
    match expr {
        ExprIR::Literal { value, .. } => match value {
            nocturne_ir::expr::LiteralIR::Bool(b) => quote! { #b },
            nocturne_ir::expr::LiteralIR::Int(n) => int_literal_tokens(*n),
            nocturne_ir::expr::LiteralIR::Str(s) => quote! { #s },
        },
        ExprIR::Disclose { value, .. } => arg_to_runtime_expr(value),
        ExprIR::WitnessAccess { field, .. } => {
            let field_ident = format_ident!("{}", field.to_string());
            quote! { witnesses.#field_ident.value() }
        }
        // Parametric witness call. Evaluate args at runtime and invoke
        // the user's method on `witnesses`, then unwrap to the
        // primitive via `.value()` for the surrounding cast.
        ExprIR::WitnessCall { name, args, .. } => {
            let m = format_ident!("{}", name.to_string());
            let arg_exprs: Vec<TokenStream> = args.iter().map(arg_to_runtime_raw_expr).collect();
            quote! { witnesses.#m(#(#arg_exprs),*).value() }
        }
        ExprIR::Var { name, .. } => {
            let ident = format_ident!("{}", name.to_string());
            quote! { #ident }
        }
        ExprIR::Path { path, .. } => {
            quote! { #path }
        }
        ExprIR::MethodCall {
            receiver, method, ..
        } => {
            let m = method.to_string();
            match m.as_str() {
                // `.into()` / `.value()` are transparent: forward the receiver.
                "into" | "value" => arg_to_runtime_expr(receiver),
                _ => {
                    let r = arg_to_runtime_expr(receiver);
                    let m_ident = format_ident!("{}", m);
                    quote! { #r.#m_ident() }
                }
            }
        }
        ExprIR::Reference { expr: inner, .. } => arg_to_runtime_expr(inner),
        // `arr[i]` in argument position — emit a Rust index expression,
        // then `.value()` so the indexed wrapper type unwraps to its
        // primitive for the surrounding cast/AlignedValue::from path.
        ExprIR::Index { array, index, .. } => {
            let arr_expr = arg_to_runtime_raw_expr(array);
            let idx = syn::Index::from(*index as usize);
            quote! { (#arr_expr)[#idx].value() }
        }
        // Arithmetic in argument position — e.g. `cell.set(w.a + w.b)`.
        // Compose each operand's value expression so the bare argument
        // form works without the user having to introduce a let
        // binding. Witness pushes still fire through the surrounding
        // `generate_op_stmt` BinaryOp arm.
        ExprIR::BinaryOp { op, lhs, rhs, .. } => {
            let l = arg_to_runtime_expr(lhs);
            let r = arg_to_runtime_expr(rhs);
            match op {
                syn::BinOp::Add(_) => quote! { (#l + #r) },
                syn::BinOp::Sub(_) => quote! { (#l - #r) },
                syn::BinOp::Mul(_) => quote! { (#l * #r) },
                syn::BinOp::BitAnd(_) => quote! { (#l & #r) },
                syn::BinOp::BitOr(_) => quote! { (#l | #r) },
                syn::BinOp::BitXor(_) => quote! { (#l ^ #r) },
                _ => quote! { () },
            }
        }
        // Inline tuple literal — reconstruct the tuple from its
        // components. Mirrors the existing `arg_to_runtime_raw_expr`
        // Tuple arm so a tuple in non-Bytes argument position still
        // composes its values instead of silently collapsing to `()`.
        ExprIR::Tuple { elements, .. } => {
            let parts: Vec<TokenStream> = elements.iter().map(arg_to_runtime_expr).collect();
            let trailing = if elements.len() == 1 {
                quote! { , }
            } else {
                quote! {}
            };
            quote! { (#(#parts),* #trailing) }
        }
        // Array literal — same shape as the raw form. The arms that
        // wrap the result (`aligned_value_arg_expr` → Array arm) walk
        // each element individually, so producing a Rust array literal
        // here is the correct hand-off.
        ExprIR::ArrayLit { elements, .. } => {
            let parts: Vec<TokenStream> = elements.iter().map(arg_to_runtime_raw_expr).collect();
            quote! { [#(#parts),*] }
        }
        // Struct literal — same shape as the raw form. The Cell<T>::set
        // path eventually wraps this through `aligned_value_arg_expr`'s
        // user-struct-fields arm which projects each field by name.
        ExprIR::StructInit { name, fields, .. } => {
            let inits: Vec<TokenStream> = fields
                .iter()
                .map(|(fname, expr)| {
                    let f = fname.clone();
                    let v = arg_to_runtime_raw_expr(expr);
                    quote! { #f: #v }
                })
                .collect();
            quote! { #name { #(#inits),* } }
        }
        // Unary minus / not — compose the inner expression.
        ExprIR::UnaryOp {
            op, expr: inner, ..
        } => {
            let i = arg_to_runtime_expr(inner);
            match op {
                syn::UnOp::Neg(_) => quote! { (-#i) },
                syn::UnOp::Not(_) => quote! { (!#i) },
                _ => quote! { () },
            }
        }
        // Free-function calls in value-unwrap position. Same path
        // reconstruction as `arg_to_runtime_raw_expr`, then `.value()`
        // so the surrounding primitive cast (`as u64`, etc.) has a
        // bare integer to work with. The args themselves go through
        // the raw form because they need to be the constructor's
        // declared types, not value-unwrapped versions.
        ExprIR::FnCall { path, args, .. } => {
            let arg_exprs: Vec<TokenStream> = args.iter().map(arg_to_runtime_raw_expr).collect();
            quote! { #path(#(#arg_exprs),*).value() }
        }
        // Anything else falls back to `()` and will fail to compile with a
        // clear "the trait `From<()>` is not implemented" message, which
        // points the user at an unsupported argument shape.
        _ => quote! { () },
    }
}

/// Generate a block expression that emits the on-chain Map::contains ops
/// (Dup + Idx + Push + Member + Popeq) and evaluates to the contains-result
/// bool. The block has side effects on `ops` (and reads `state`/`witnesses`),
/// so the caller must be inside the transcript builder fn body where those
/// names are in scope.
///
/// Shared between the statement-context "contains" arm (where the bool is
/// discarded) and the condition-context use in `generate_runtime_cond`
/// (where the bool drives `if cond { ... }`).
fn generate_map_contains_block(
    field_idx: u8,
    field_name: &str,
    args: &[ExprIR],
    field_ty: Option<&syn::Type>,
    ctx: &TranscriptCtx<'_>,
) -> TokenStream {
    let field_ident = format_ident!("{}", field_name);
    let raw_key = args
        .first()
        .map(arg_to_runtime_raw_expr)
        .unwrap_or_else(|| quote! { () });
    // K-type for the AlignedValue alignment: Map<K, V> → K, Set<T> → T.
    // Both expose `.contains(&K)` so the runtime method name is shared.
    let k_ty = field_ty.and_then(extract_field_key_type);
    let key_aligned = args
        .first()
        .map(|a| aligned_value_arg_expr(a, k_ty.as_ref(), ctx))
        .unwrap_or_else(|| quote! { () });

    quote! {
        {
            let __key = #raw_key;
            ops.push(Op::Dup { n: 0 });
            ops.push(Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
            });
            ops.push(Op::Push {
                storage: false,
                value: StateValue::Cell(Sp::new(AlignedValue::from(#key_aligned))),
            });
            ops.push(Op::Member);
            let __result: bool = state.#field_ident.contains(&__key);
            ops.push(Op::Popeq {
                cached: true,
                result: AlignedValue::from(__result),
            });
            __result
        }
    }
}

/// Emit the runtime ops for `Cell<T>::set(v)` — see comment in the
/// `set`/`insert` arm above for the on-chain pattern.
fn generate_cell_set(
    field_idx: u8,
    args: &[ExprIR],
    field_ty: Option<&syn::Type>,
    ctx: &TranscriptCtx<'_>,
) -> TokenStream {
    // `Counter::set` shares the Cell<u64> wire shape (both deploy as
    // `StateValue::Cell(AlignedValue<u64>)`), so route Counter through
    // the same code with `u64` as the implicit inner type.
    let t_ty = field_ty.and_then(extract_cell_inner_type).or_else(|| {
        field_ty.and_then(|t| {
            if is_counter_type(t) {
                Some(syn::parse_quote!(u64))
            } else {
                None
            }
        })
    });
    let value_aligned = args
        .first()
        .map(|a| aligned_value_arg_expr(a, t_ty.as_ref(), ctx))
        .unwrap_or_else(|| quote! { () });
    quote! {
        ops.push(Op::Push {
            storage: false,
            value: StateValue::Cell(Sp::new(AlignedValue::from(#field_idx))),
        });
        ops.push(Op::Push {
            storage: true,
            value: StateValue::Cell(Sp::new(AlignedValue::from(#value_aligned))),
        });
        ops.push(Op::Ins { cached: false, n: 1 });
    }
}

/// Build the inline `match` expression that pulls the payload out of
/// a homogeneous-payload enum value. Mirrors what plain Rust pattern
/// matching looks like: one arm per variant, all binding the same
/// payload (homogeneity guarantees the inner type is identical).
/// Returns `None` if the type isn't a known user enum or the enum has
/// no payload — caller falls back to whatever non-payload path applies.
///
/// Replaces a previous `.payload()` accessor that lived on the enum
/// itself: Rust enums don't have a `.payload()` method, and threading
/// the match through the call site leaves the user-facing surface as
/// plain pattern matching.
fn enum_payload_match_expr(
    scrutinee: &TokenStream,
    ty: &syn::Type,
    ctx: &TranscriptCtx<'_>,
) -> Option<TokenStream> {
    // Option<T> first: it's a stdlib type, no user_enums entry. The
    // None case has no payload to bind, so synthesize the default
    // value of T (`<T as Default>::default()`). For types that aren't
    // `Default` the user gets a clear compile error pointing here.
    if let Some(payload_ty) = option_payload_type(ty) {
        return Some(quote! {
            match #scrutinee {
                Some(__p) => __p,
                None => <#payload_ty as ::core::default::Default>::default(),
            }
        });
    }

    let user_enums = ctx.user_enums;
    let syn::Type::Path(tp) = ty else { return None };
    let seg = tp.path.segments.last()?;
    let enum_ident = seg.ident.clone();
    let variants = user_enums.get(&enum_ident.to_string())?;
    variants.first().and_then(|v| v.payload.clone())?;
    let arms: Vec<TokenStream> = variants
        .iter()
        .map(|v| {
            let v_ident = v.name.clone();
            quote! { #enum_ident::#v_ident(__p) => __p }
        })
        .collect();
    Some(quote! {
        match #scrutinee {
            #(#arms),*
        }
    })
}

fn user_enum_payload_type(
    ty: &syn::Type,
    user_enums: &HashMap<String, Vec<UserEnumVariant>>,
) -> Option<syn::Type> {
    let syn::Type::Path(tp) = ty else { return None };
    if tp.qself.is_some() {
        return None;
    }
    let seg = tp.path.segments.last()?;
    let variants = user_enums.get(&seg.ident.to_string())?;
    variants.first().and_then(|v| v.payload.clone())
}

/// True if `ty` is the path of a user-defined unit-variant enum.
fn is_user_enum(ty: &syn::Type, user_enums: &HashMap<String, Vec<UserEnumVariant>>) -> bool {
    let syn::Type::Path(tp) = ty else {
        return false;
    };
    if tp.qself.is_some() {
        return false;
    }
    tp.path
        .segments
        .last()
        .map(|s| user_enums.contains_key(&s.ident.to_string()))
        .unwrap_or(false)
}

/// True if `ty` is Rust's stdlib `Option<T>`. We treat it like a
/// homogeneous-payload enum (`(Bytes<1>, T)` wire shape) without
/// requiring the user to declare it — same encoding as Compact's
/// `Maybe<T>`, same shape upstream's `impl<T: Aligned> Aligned for
/// Option<T>` produces.
fn is_option_type(ty: &syn::Type) -> bool {
    option_payload_type(ty).is_some()
}

/// If `ty` is `Option<T>`, return `T`. The path may be `Option`,
/// `std::option::Option`, or `core::option::Option`; only the final
/// segment + its single type argument matter.
fn option_payload_type(ty: &syn::Type) -> Option<syn::Type> {
    let syn::Type::Path(tp) = ty else { return None };
    if tp.qself.is_some() {
        return None;
    }
    let seg = tp.path.segments.last()?;
    if seg.ident != "Option" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    if args.args.len() != 1 {
        return None;
    }
    match args.args.first()? {
        syn::GenericArgument::Type(t) => Some(t.clone()),
        _ => None,
    }
}

/// True if `ty` is either a user enum (any number of variants, with or
/// without payload) or `Option<T>`. Sites that fan out by enum-ness
/// route through this rather than `is_user_enum` directly.
fn is_enum_like(ty: &syn::Type, user_enums: &HashMap<String, Vec<UserEnumVariant>>) -> bool {
    is_option_type(ty) || is_user_enum(ty, user_enums)
}

/// True if `ty` is a homogeneous-payload enum-like — either a user
/// enum with a payload, or `Option<T>`. Used by the codegen sites that
/// need to short-circuit through the same `(Bytes<1>, T)` wire path
/// regardless of source-level spelling.
#[allow(dead_code)]
fn is_enum_like_with_payload(
    ty: &syn::Type,
    user_enums: &HashMap<String, Vec<UserEnumVariant>>,
) -> bool {
    is_option_type(ty)
        || (is_user_enum(ty, user_enums) && user_enum_payload_type(ty, user_enums).is_some())
}

/// Combined payload-type lookup. Returns `Some(T)` for `Option<T>` and
/// for user enums with a payload; `None` otherwise.
fn enum_like_payload_type(
    ty: &syn::Type,
    user_enums: &HashMap<String, Vec<UserEnumVariant>>,
) -> Option<syn::Type> {
    option_payload_type(ty).or_else(|| user_enum_payload_type(ty, user_enums))
}

/// Build the runtime expression that yields an enum-like value's u8
/// discriminant. User enums delegate to the macro-generated
/// `.discriminant()` method; `Option<T>` synthesizes a `match` since
/// it has no such method.
fn enum_like_discriminant_expr(accessor: &TokenStream, ty: &syn::Type) -> TokenStream {
    if is_option_type(ty) {
        quote! { match #accessor { ::core::option::Option::Some(_) => 1u8, ::core::option::Option::None => 0u8 } }
    } else {
        quote! { (#accessor).discriminant() }
    }
}

/// If `ty` is a user-defined struct registered in `user_structs`,
/// return its fields. Otherwise None. Lets WitnessAccess and other
/// arg helpers dispatch on struct shape the same way they dispatch on
/// tuples.
fn user_struct_fields<'a>(
    ty: &syn::Type,
    user_structs: &'a HashMap<String, Vec<UserStructField>>,
) -> Option<&'a Vec<UserStructField>> {
    let syn::Type::Path(tp) = ty else {
        return None;
    };
    if tp.qself.is_some() {
        return None;
    }
    let ident = &tp.path.segments.last()?.ident;
    user_structs.get(&ident.to_string())
}

/// Push the per-component Fr value of a struct field (or tuple
/// component) onto `private_transcript`. Mirrors the per-type pushes in
/// the `WitnessAccess` arm, but takes a token accessor (e.g.
/// `witnesses.key.a`) instead of a witness ident.
fn component_private_push(
    ty: &syn::Type,
    accessor: &TokenStream,
    ctx: &TranscriptCtx<'_>,
) -> TokenStream {
    let ty_str = quote!(#ty).to_string().replace(' ', "");
    if ty_str.starts_with("Bytes<") {
        return quote! {
            {
                use nocturne::runtime::transient_crypto::fab::AlignedValueExt;
                let __av = AlignedValue::from(*(#accessor).as_bytes());
                __av.value_only_field_repr(&mut private_transcript);
            }
        };
    }
    if ty_str == "Field" {
        return quote! {
            private_transcript.push(Fr::from((#accessor).value()));
        };
    }
    if ty_str == "MerkleTreeDigest" {
        return quote! {
            private_transcript.push(
                Fr::from_le_bytes(&(#accessor).as_le_bytes())
                    .expect("MerkleTreeDigest bytes round-trip through Fr"),
            );
        };
    }
    if ty_str == "Boolean" || ty_str == "bool" {
        return quote! {
            private_transcript.push(Fr::from((#accessor).value() as u64));
        };
    }
    if let Some((elem_ty, n)) = extract_array_type(ty) {
        // Walk the array element-by-element, recursing through
        // component_private_push so nested arrays / tuples / enums
        // all push in declaration order. The accessor must be a
        // place expression that supports `[i]` indexing — the
        // callers (witnesses access, ledger Cell::get) already
        // bind it to a Rust value of type `[T; N]`.
        let pushes: Vec<TokenStream> = (0..n as usize)
            .map(|i| {
                let idx = syn::Index::from(i);
                component_private_push(&elem_ty, &quote! { (#accessor)[#idx] }, ctx)
            })
            .collect();
        return quote! { #(#pushes)* };
    }
    if is_enum_like(ty, ctx.user_enums) {
        let payload = enum_like_payload_type(ty, ctx.user_enums);
        let disc = enum_like_discriminant_expr(accessor, ty);
        return match payload {
            None => quote! {
                private_transcript.push(Fr::from((#disc) as u64));
            },
            Some(p) => {
                // Discriminant first, then the payload's own per-Fr
                // pushes via the regular tuple-component path. Pull
                // the payload out with an inline match — same shape
                // as user-facing pattern matching, no synthetic
                // accessor.
                let payload_match =
                    enum_payload_match_expr(&quote! { (#accessor).clone() }, ty, ctx)
                        .unwrap_or_else(|| quote! { unreachable!() });
                let payload_pushes = component_private_push(&p, &quote! { __payload }, ctx);
                quote! {
                    private_transcript.push(Fr::from((#disc) as u64));
                    {
                        let __payload = #payload_match;
                        #payload_pushes
                    }
                }
            }
        };
    }
    // Uint<N> / primitive integer: cast to u64 for Fr::from.
    quote! {
        private_transcript.push(Fr::from((#accessor).value() as u64));
    }
}

/// Produce a runtime Rust expression suitable for passing into
/// `AlignedValue::from(_)` for a value of the given expected type.
/// Handles `Bytes<N>` (unwrap to `[u8; N]`), `Field` (lift to `Fr`),
/// `MerkleTreeDigest` (full Fr via `as_le_bytes`), tuples, user
/// structs, and single-Fr primitives via `primitive_cast_for_type`.
fn aligned_value_arg_expr(
    expr: &ExprIR,
    ty: Option<&syn::Type>,
    ctx: &TranscriptCtx<'_>,
) -> TokenStream {
    let user_structs = ctx.user_structs;
    if let Some(t) = ty {
        // Tuple keys / values: build the upstream tuple shape that
        // `AlignedValue::from(_)` accepts via `Aligned for (T1, .., Tn)`.
        // Each component gets its own per-type conversion (Field → Fr,
        // Uint<N> → primitive, etc.) and we cons up the tuple in
        // declaration order so the on-wire layout matches
        // `aligned_value_encoding`'s concatenated alignment.
        if let syn::Type::Tuple(tt) = t {
            let raw = arg_to_runtime_raw_expr(expr);
            let n = tt.elems.len();
            let comps: Vec<TokenStream> = tt
                .elems
                .iter()
                .enumerate()
                .map(|(i, elem)| {
                    let idx = syn::Index::from(i);
                    tuple_component_aligned_repr(elem, &quote! { __t.#idx })
                })
                .collect();
            // A 1-tuple needs the trailing comma so Rust parses it as
            // a tuple type and the upstream `Aligned for (T,)` kicks in.
            let trailing = if n == 1 {
                quote! { , }
            } else {
                quote! {}
            };
            return quote! {
                {
                    let __t = #raw;
                    (#(#comps),* #trailing)
                }
            };
        }
        // Fixed-size array `[T; N]`: build an N-tuple of T from the
        // array's elements. Upstream's tuple `Aligned` impl gives us
        // the wire shape that matches Compact's `Vector<N, T>`. N ≤ 11
        // (the upstream tuple cap); larger N is rejected at parse.
        if let Some((elem_ty, n)) = extract_array_type(t) {
            let raw = arg_to_runtime_raw_expr(expr);
            let comps: Vec<TokenStream> = (0..n as usize)
                .map(|i| {
                    let idx = syn::Index::from(i);
                    tuple_component_aligned_repr(&elem_ty, &quote! { __a[#idx] })
                })
                .collect();
            let trailing = if n == 1 {
                quote! { , }
            } else {
                quote! {}
            };
            return quote! {
                {
                    let __a = #raw;
                    (#(#comps),* #trailing)
                }
            };
        }
        let ty_str = quote!(#t).to_string().replace(' ', "");
        if ty_str.starts_with("Bytes<") {
            // Bytes<N>: need [u8; N] for AlignedValue::from.
            let raw = arg_to_runtime_raw_expr(expr);
            return quote! { *(#raw).as_bytes() };
        }
        if ty_str == "Field" {
            // Field: `AlignedValue::from` accepts `Fr` (via Aligned impl in
            // `transient-crypto/src/curve.rs:291`), producing an AlignedValue
            // with `AlignmentAtom::Field`. Convert our user-side `Field`
            // (currently a u128 wrapper) to `Fr` via `Fr::from(field.value())`.
            let raw = arg_to_runtime_raw_expr(expr);
            return quote! { Fr::from((#raw).value()) };
        }
        if ty_str == "MerkleTreeDigest" {
            // MerkleTreeDigest is Field-aligned but carries the full
            // 32-byte LE Fr (so chained Merkle computations round-trip
            // through Root). Reconstruct the Fr via from_le_bytes — never
            // through `.field().value()` (that's the u128 truncation).
            let raw = arg_to_runtime_raw_expr(expr);
            return quote! {
                Fr::from_le_bytes(&(#raw).as_le_bytes())
                    .expect("MerkleTreeDigest bytes round-trip through Fr")
            };
        }
        // User-defined struct: same tuple-shape construction as
        // syn::Type::Tuple, except components project by field name.
        if let Some(fields) = user_struct_fields(t, user_structs) {
            let raw = arg_to_runtime_raw_expr(expr);
            let comps: Vec<TokenStream> = fields
                .iter()
                .map(|f| {
                    let fname = f.name.clone();
                    tuple_component_aligned_repr(&f.ty, &quote! { __t.#fname })
                })
                .collect();
            let trailing = if fields.len() == 1 {
                quote! { , }
            } else {
                quote! {}
            };
            return quote! {
                {
                    let __t = #raw;
                    (#(#comps),* #trailing)
                }
            };
        }
        // User-defined enum:
        //   - All-unit variants → just the u8 discriminant.
        //   - Homogeneous payload `enum E { V(T), ... }` → the
        //     `(Bytes<1>, T)` tuple `AlignedValue::from(_)` accepts
        //     via the upstream `Aligned for (A, B)` impl. The payload
        //     is extracted with an inline `match` over the enum value
        //     — no synthetic accessor; same shape as user-facing
        //     pattern matching.
        if is_enum_like(t, ctx.user_enums) {
            let raw = arg_to_runtime_raw_expr(expr);
            let payload_ty = enum_like_payload_type(t, ctx.user_enums);
            return match payload_ty {
                None => {
                    let disc = enum_like_discriminant_expr(&raw, t);
                    quote! { (#disc) }
                }
                Some(p) => {
                    let payload_match = enum_payload_match_expr(&quote! { __e.clone() }, t, ctx)
                        .unwrap_or_else(|| quote! { unreachable!() });
                    let payload_repr = tuple_component_aligned_repr(&p, &quote! { __payload });
                    let disc = enum_like_discriminant_expr(&quote! { __e }, t);
                    quote! {
                        {
                            let __e = #raw;
                            let __payload = #payload_match;
                            (#disc, #payload_repr)
                        }
                    }
                }
            };
        }
    }
    let value_expr = arg_to_runtime_expr(expr);
    match ty.and_then(primitive_cast_for_type) {
        Some(cast) => {
            // `arg_to_runtime_expr` returns a bare identifier for
            // `ExprIR::Var`. If the cell's wrapper type is `Uint<N>`,
            // the bare var is the wrapper itself, so we need `.value()`
            // before the `as u<N>` cast — `Uint<N> as u64` doesn't
            // type-check. Witness reads emit `.value()` directly so
            // they don't need this adjustment.
            let needs_unwrap = matches!(expr, ExprIR::Var { .. })
                && ty
                    .map(|t| quote!(#t).to_string().replace(' ', ""))
                    .map(|s| s.starts_with("Uint<"))
                    .unwrap_or(false);
            if needs_unwrap {
                quote! { (#value_expr).value() #cast }
            } else {
                quote! { (#value_expr) #cast }
            }
        }
        None => value_expr,
    }
}

/// Convert a single tuple-component expression `accessor` (e.g.
/// `__t.0`) of declared type `ty` into the form `AlignedValue::from`
/// accepts directly. Mirrors the per-type arms of
/// `aligned_value_arg_expr` but takes a token-tree accessor instead of
/// an `ExprIR` because tuple elements aren't first-class IR exprs —
/// they're field projections on a temporary binding.
fn tuple_component_aligned_repr(ty: &syn::Type, accessor: &TokenStream) -> TokenStream {
    let ty_str = quote!(#ty).to_string().replace(' ', "");
    if ty_str.starts_with("Bytes<") {
        return quote! { *(#accessor).as_bytes() };
    }
    if ty_str == "Field" {
        return quote! { Fr::from((#accessor).value()) };
    }
    if ty_str == "MerkleTreeDigest" {
        return quote! {
            Fr::from_le_bytes(&(#accessor).as_le_bytes())
                .expect("MerkleTreeDigest bytes round-trip through Fr")
        };
    }
    if ty_str == "Boolean" || ty_str == "bool" {
        return quote! { (#accessor).value() };
    }
    // Uint<N> / primitive integers: snap to the matching Rust primitive
    // so the upstream Aligned-for-primitive impl picks the right Bytes<n>
    //
    // Note: tuple_component_aligned_repr doesn't take user_enums today,
    // so enum-valued tuple components fall through to the integer path
    // — fine for now since the per-component accessor's primitive cast
    // pulls in `.discriminant()` when the type is recognized at the
    // top-level dispatch. Nested enum-in-tuple-in-struct would need
    // user_enums plumbed here too.
    // alignment.
    match primitive_cast_for_type(ty) {
        Some(cast) => quote! { (#accessor).value() #cast },
        None => quote! { (#accessor).value() },
    }
}

/// Emit the runtime ops for `Map<K, V>::insert(k, v)`. The on-chain pattern
/// (matches compactc 0.30.0):
///
///   Idx{cached:false, push_path:true, [Bytes<1>(field_idx)]}  // navigate into Map
///   Push{storage:false, Cell(key)}
///   Push{storage:true,  Cell(value)}
///   Ins{cached:false, n:1}   // insert (k, v) into the Map
///   Ins{cached:true,  n:1}   // write modified Map back to the Array
fn generate_map_insert(
    field_idx: u8,
    args: &[ExprIR],
    field_ty: Option<&syn::Type>,
    ctx: &TranscriptCtx<'_>,
) -> TokenStream {
    let kv = field_ty.and_then(extract_map_kv_types);
    let k_ty = kv.as_ref().map(|(k, _)| k.clone());
    let v_ty = kv.as_ref().map(|(_, v)| v.clone());

    // K and V both need the Bytes-aware expression so multi-Fr types
    // (`Bytes<N>`) build the AlignedValue from the underlying `[u8; N]`
    // while primitives still get the right `as u<N>` cast.
    let key_aligned = args
        .first()
        .map(|a| aligned_value_arg_expr(a, k_ty.as_ref(), ctx))
        .unwrap_or_else(|| quote! { () });
    let val_aligned = args
        .get(1)
        .map(|a| aligned_value_arg_expr(a, v_ty.as_ref(), ctx))
        .unwrap_or_else(|| quote! { () });

    quote! {
        ops.push(Op::Idx {
            cached: false,
            push_path: true,
            path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
        });
        ops.push(Op::Push {
            storage: false,
            value: StateValue::Cell(Sp::new(AlignedValue::from(#key_aligned))),
        });
        ops.push(Op::Push {
            storage: true,
            value: StateValue::Cell(Sp::new(AlignedValue::from(#val_aligned))),
        });
        ops.push(Op::Ins { cached: false, n: 1 });
        ops.push(Op::Ins { cached: true, n: 1 });
    }
}

/// Emit the runtime ops for `Map<K, V>::lookup(&k) -> V`. The Popeq result
/// must be the actual stored value the on-chain VM will compute, so call
/// the runtime stub on `state`. Mirrors compactc 0.30.0's lookup emission:
///
///   Dup{n:0}
///   Idx{cached:false, push_path:false, [Bytes<1>(field_idx)]}   // navigate to Map
///   Idx{cached:false, push_path:false, [Key::Value(key)]}        // index by key
///   Popeq{cached:false, result: AlignedValue::from(state.<f>.lookup(&k))}
fn generate_map_lookup(
    field_idx: u8,
    field_name: &str,
    args: &[ExprIR],
    field_ty: Option<&syn::Type>,
    ctx: &TranscriptCtx<'_>,
) -> TokenStream {
    let field_ident = format_ident!("{}", field_name);
    let raw_key = args
        .first()
        .map(arg_to_runtime_raw_expr)
        .unwrap_or_else(|| quote! { () });

    let kv = field_ty.and_then(extract_map_kv_types);
    let k_ty = kv.as_ref().map(|(k, _)| k.clone());

    // The second `Idx`'s key path needs the same Bytes-aware AlignedValue
    // build as `Push` does — multi-Fr K must use `*<raw>.as_bytes()`.
    let key_aligned = args
        .first()
        .map(|a| aligned_value_arg_expr(a, k_ty.as_ref(), ctx))
        .unwrap_or_else(|| quote! { () });

    // Popeq result: V comes back from the runtime (a wrapper like Boolean
    // / Uint<N> / Bytes<N>). Unwrap to the form AlignedValue::from accepts.
    let val_expr = match kv.as_ref().map(|(_, v)| v) {
        Some(v_ty) => {
            unwrap_to_aligned_primitive(quote! { state.#field_ident.lookup(&__key) }, v_ty)
        }
        None => quote! { state.#field_ident.lookup(&__key) },
    };

    quote! {
        {
            let __key = #raw_key;
            ops.push(Op::Dup { n: 0 });
            ops.push(Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
            });
            ops.push(Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(AlignedValue::from(#key_aligned))].into_iter().collect(),
            });
            ops.push(Op::Popeq {
                cached: false,
                result: AlignedValue::from(#val_expr),
            });
        }
    }
}

/// Emit the runtime ops for `Map<K, V>::remove(&k)`. Same Idx + Push pattern
/// as `insert`, but with `Rem` instead of `Push(value) + Ins(first)` — the
/// VM-level `Rem` pops `[key, container]` and pushes back the modified
/// container in one step.
///
///   Idx{cached:false, push_path:true, [Bytes<1>(field_idx)]}
///   Push{storage:false, Cell(key)}
///   Rem{cached:false}        // remove k from the Map
///   Ins{cached:true, n:1}    // write modified Map back to the Array
fn generate_map_remove(
    field_idx: u8,
    args: &[ExprIR],
    field_ty: Option<&syn::Type>,
    ctx: &TranscriptCtx<'_>,
) -> TokenStream {
    let k_ty = field_ty.and_then(extract_map_key_type);
    let key_aligned = args
        .first()
        .map(|a| aligned_value_arg_expr(a, k_ty.as_ref(), ctx))
        .unwrap_or_else(|| quote! { () });

    quote! {
        ops.push(Op::Idx {
            cached: false,
            push_path: true,
            path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
        });
        ops.push(Op::Push {
            storage: false,
            value: StateValue::Cell(Sp::new(AlignedValue::from(#key_aligned))),
        });
        ops.push(Op::Rem { cached: false });
        ops.push(Op::Ins { cached: true, n: 1 });
    }
}

/// Wrap `expr` to produce a value `AlignedValue::from(_)` can accept for
/// type `ty`. Handles wrapper types (`Boolean` → `.value()`, `Uint<N>` →
/// `.value() as u<N>`) and raw primitives (identity cast). Returns the
/// raw expression if the type isn't recognized.
fn unwrap_to_aligned_primitive(expr: TokenStream, ty: &syn::Type) -> TokenStream {
    let ty_str = quote!(#ty).to_string().replace(' ', "");
    if ty_str == "Boolean" {
        return quote! { (#expr).value() };
    }
    // Bytes<N>: `AlignedValue::from(_)` accepts `[u8; N]`, so unwrap the
    // wrapper to its byte array. Mirrors the Cell::set/get side.
    if ty_str.starts_with("Bytes<") {
        return quote! { *(#expr).as_bytes() };
    }
    if ty_str.starts_with("Uint<")
        && let Some(c) = primitive_cast_for_type(ty)
    {
        return quote! { (#expr).value() #c };
    }
    if let Some(c) = primitive_cast_for_type(ty) {
        return quote! { (#expr) #c };
    }
    expr
}

/// Build a `field_name -> field_type` map from a `WitnessIR`. Used by
/// `generate_op_stmt` to dispatch on the witness type at codegen time.
fn witness_type_map(w: &WitnessIR) -> HashMap<String, syn::Type> {
    w.fields
        .iter()
        .map(|f| (f.name.to_string(), f.ty.clone()))
        .collect()
}

/// True if `ty` is `Bytes<N>` for some N (the only multi-Fr witness type
/// we currently support).
fn is_bytes_witness(ty: &syn::Type) -> bool {
    let ty_str = quote!(#ty).to_string().replace(' ', "");
    ty_str.starts_with("Bytes<")
}

/// True if `ty` is `MerkleTreeDigest`. The witness push reaches through
/// `.as_le_bytes()` (canonical 32-byte LE Fr) so the in-circuit
/// PrivateInput sees the full 254-bit Fr, not a u128 truncation.
fn is_merkle_tree_digest(ty: &syn::Type) -> bool {
    let ty_str = quote!(#ty).to_string().replace(' ', "");
    ty_str == "MerkleTreeDigest"
}

/// True if `ty` is `MerkleTreePath<H, T>` for some H, T. The witness push
/// deconstructs into the leaf's Fr stream followed by H × (sibling Fr +
/// goes_left Fr) — matching the IR's `witness_fr_layout` expansion.
fn is_merkle_tree_path(ty: &syn::Type) -> bool {
    let ty_str = quote!(#ty).to_string().replace(' ', "");
    ty_str.starts_with("MerkleTreePath<")
}

/// Map a Rust type that flows into `AlignedValue::from(_)` to the primitive
/// cast suffix the runtime needs to match the IR's alignment table.
///
/// Why this matters: `Uint<64>::value()` returns `u128`, and
/// `AlignedValue::from(u128)` uses `Bytes{16}` alignment, but our IR emits
/// `Bytes{8}` for a `Uint<64>` field. Without an explicit `as u64` cast the
/// transcript and the IR disagree on the alignment atom and `prove` rejects
/// the transcript with a "Public transcript input mismatch" error.
///
/// Returns `None` for types where no cast is needed (`bool`/`Boolean`) or
/// for types we don't yet support (`Bytes<N>`, `Field`, custom ADTs).
fn primitive_cast_for_type(ty: &syn::Type) -> Option<TokenStream> {
    let ty_str = quote!(#ty).to_string().replace(' ', "");

    // Boolean wrapper and raw bool: `AlignedValue::from(bool)` already
    // uses Bytes{1}, no cast needed.
    if ty_str == "Boolean" || ty_str == "bool" {
        return None;
    }

    // Raw primitive integers — the cast is a no-op but keeping it makes
    // the generated code uniform regardless of where the value comes from.
    if ty_str == "u8" {
        return Some(quote! { as u8 });
    }
    if ty_str == "u16" {
        return Some(quote! { as u16 });
    }
    if ty_str == "u32" {
        return Some(quote! { as u32 });
    }
    if ty_str == "u64" {
        return Some(quote! { as u64 });
    }
    if ty_str == "u128" {
        return Some(quote! { as u128 });
    }

    // Uint<N>: snap to the narrowest primitive that holds N bits, matching
    // `aligned_value_encoding`'s `bytes = ceil(N/8)` choice.
    if let Some(n) = ty_str
        .strip_prefix("Uint<")
        .and_then(|s| s.strip_suffix('>'))
        .and_then(|s| s.parse::<u32>().ok())
    {
        return Some(if n <= 8 {
            quote! { as u8 }
        } else if n <= 16 {
            quote! { as u16 }
        } else if n <= 32 {
            quote! { as u32 }
        } else if n <= 64 {
            quote! { as u64 }
        } else {
            quote! { as u128 }
        });
    }

    None
}

/// True if `ty` is the `Counter` ledger primitive.
fn is_counter_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
    {
        return seg.ident == "Counter";
    }
    false
}

/// If `ty` is `[T; N]`, return `(T, N)`. Used by array-aware emitters
/// to walk fixed-size array payloads as N-tuples of T (which is the
/// wire shape upstream's `Aligned for (T1, …, Tn)` produces).
fn extract_array_type(ty: &syn::Type) -> Option<(syn::Type, u32)> {
    if let syn::Type::Array(arr) = ty
        && let syn::Expr::Lit(lit) = &arr.len
        && let syn::Lit::Int(int) = &lit.lit
        && let Ok(n) = int.base10_parse::<u32>()
    {
        return Some(((*arr.elem).clone(), n));
    }
    None
}

/// If `ty` is `Cell<T>`, return `T`. Mirrors `zkir_emitter::extract_cell_inner_type`.
fn extract_cell_inner_type(ty: &syn::Type) -> Option<syn::Type> {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
        && seg.ident == "Cell"
        && let syn::PathArguments::AngleBracketed(args) = &seg.arguments
        && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
    {
        return Some(inner.clone());
    }
    None
}

/// Emit the runtime ops for `Set<T>::insert(k)`. Same shape as
/// `Map::insert` except the value Push pushes `StateValue::Null` instead
/// of `StateValue::Cell(value)` — see the IR-side `emit_set_insert` for
/// the full encoding and the empirical compactc reference.
fn generate_set_insert(
    field_idx: u8,
    args: &[ExprIR],
    field_ty: Option<&syn::Type>,
    ctx: &TranscriptCtx<'_>,
) -> TokenStream {
    let t_ty = field_ty.and_then(extract_set_inner_type);
    let key_aligned = args
        .first()
        .map(|a| aligned_value_arg_expr(a, t_ty.as_ref(), ctx))
        .unwrap_or_else(|| quote! { () });

    quote! {
        ops.push(Op::Idx {
            cached: false,
            push_path: true,
            path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
        });
        ops.push(Op::Push {
            storage: false,
            value: StateValue::Cell(Sp::new(AlignedValue::from(#key_aligned))),
        });
        ops.push(Op::Push {
            storage: true,
            value: StateValue::Null,
        });
        ops.push(Op::Ins { cached: false, n: 1 });
        ops.push(Op::Ins { cached: true, n: 1 });
    }
}

/// Emit the runtime ops for `Set<T>::remove(&k)`. Identical to
/// `Map::remove` — Set reuses Map's on-chain Rem+Ins pattern.
fn generate_set_remove(
    field_idx: u8,
    args: &[ExprIR],
    field_ty: Option<&syn::Type>,
    ctx: &TranscriptCtx<'_>,
) -> TokenStream {
    let t_ty = field_ty.and_then(extract_set_inner_type);
    let key_aligned = args
        .first()
        .map(|a| aligned_value_arg_expr(a, t_ty.as_ref(), ctx))
        .unwrap_or_else(|| quote! { () });

    quote! {
        ops.push(Op::Idx {
            cached: false,
            push_path: true,
            path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
        });
        ops.push(Op::Push {
            storage: false,
            value: StateValue::Cell(Sp::new(AlignedValue::from(#key_aligned))),
        });
        ops.push(Op::Rem { cached: false });
        ops.push(Op::Ins { cached: true, n: 1 });
    }
}

/// Emit the runtime ops for `MerkleTree::check_root(&digest) -> bool`.
/// Mirrors compactc 0.30.0's emission for `entries.checkRoot(disclose(r))`
/// — 7 ops, ending with a Popeq whose `result` is the actual bool the
/// on-chain VM will compute. Off-chain we read it via
/// `state.<field>.check_root(&__digest)`.
///
///   Dup{n:0}
///   Idx{cached:false, push_path:false, [Bytes<1>(field_idx)]}   // entries field
///   Idx{cached:false, push_path:false, [Bytes<1>(0)]}            // entries[0] = BMT
///   Root                                                          // pop BMT, push Cell(Field(root))
///   Push{storage:false, Cell(Field(digest.field))}               // user-supplied digest
///   Eq                                                            // pop 2 Cells, push bool
///   Popeq{cached:true, result: bool}
fn generate_merkle_tree_check_root(
    field_idx: u8,
    field_name: &str,
    args: &[ExprIR],
) -> TokenStream {
    let field_ident = format_ident!("{}", field_name);
    let raw_digest = args
        .first()
        .map(arg_to_runtime_raw_expr)
        .unwrap_or_else(|| quote! { () });
    // Push the user's `&MerkleTreeDigest` as the full 254-bit Fr (NOT
    // the u128 truncation), so the on-chain `Eq` compares the same
    // value the verifier reconstructs from the Root opcode.
    quote! {
        {
            let __digest = #raw_digest;
            let __digest_fr = Fr::from_le_bytes(&(&__digest).as_le_bytes())
                .expect("MerkleTreeDigest bytes round-trip through Fr");
            ops.push(Op::Dup { n: 0 });
            ops.push(Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
            });
            ops.push(Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(AlignedValue::from(0u8))].into_iter().collect(),
            });
            ops.push(Op::Root);
            ops.push(Op::Push {
                storage: false,
                value: StateValue::Cell(Sp::new(AlignedValue::from(__digest_fr))),
            });
            ops.push(Op::Eq);
            let __result: bool = state.#field_ident.check_root(&__digest);
            ops.push(Op::Popeq {
                cached: true,
                result: AlignedValue::from(__result),
            });
        }
    }
}

/// Emit the runtime ops for `MerkleTree::insert(leaf)`. Mirrors compactc
/// 0.30.0's emission for `entries.insert(disclose(leaf))` and the
/// IR-side `emit_merkle_tree_insert` — 10 ops total:
///
///   Idx{push_path:true, [field_idx]}   // navigate to entries
///   Idx{push_path:true, [0]}            // navigate into entries[0] (BMT)
///   Dup{n:2}                            // copy entries Array from stack pos 2
///   Idx{push_path:false, [1]}           // read entries[1] (next-index)
///   Push{storage:true, Cell(Bytes<32>(leafHash(leaf)))}
///   Ins{cached:false, n:1}              // insert (next_index, hash) into BMT
///   Ins{cached:true, n:1}               // write BMT back to entries[0]
///   Idx{push_path:true, [1]}            // navigate to entries[1]
///   Addi{1}                             // increment counter
///   Ins{cached:true, n:2}               // write counter back, 2 levels deep
fn generate_merkle_tree_insert(field_idx: u8, args: &[ExprIR]) -> TokenStream {
    let raw_leaf = args
        .first()
        .map(arg_to_runtime_raw_expr)
        .unwrap_or_else(|| quote! { () });
    quote! {
        {
            let __leaf = #raw_leaf;
            // leafHash(__leaf) — upstream::leaf_hash applies the "mdn:lh"
            // domain separator and persistent_hash. The HashOutput is
            // [u8; 32]; AlignedValue::from([u8; 32]) gives the Bytes<32>
            // alignment the IR's Push declares expect.
            let __leaf_hash: [u8; 32] = nocturne::runtime::transient_crypto::merkle_tree::leaf_hash(
                __leaf.as_bytes().as_slice()
            ).0;
            ops.push(Op::Idx {
                cached: false,
                push_path: true,
                path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
            });
            ops.push(Op::Idx {
                cached: false,
                push_path: true,
                path: vec![Key::Value(AlignedValue::from(0u8))].into_iter().collect(),
            });
            ops.push(Op::Dup { n: 2 });
            ops.push(Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(AlignedValue::from(1u8))].into_iter().collect(),
            });
            ops.push(Op::Push {
                storage: true,
                value: StateValue::Cell(Sp::new(AlignedValue::from(__leaf_hash))),
            });
            ops.push(Op::Ins { cached: false, n: 1 });
            ops.push(Op::Ins { cached: true, n: 1 });
            ops.push(Op::Idx {
                cached: false,
                push_path: true,
                path: vec![Key::Value(AlignedValue::from(1u8))].into_iter().collect(),
            });
            ops.push(Op::Addi { immediate: 1 });
            ops.push(Op::Ins { cached: true, n: 2 });
        }
    }
}

/// If `ty` is `MerkleTree<H, T>`, return `T`. Mirrors
/// `zkir_emitter::extract_merkle_tree_type` — used to detect MerkleTree
/// fields in the dispatcher.
fn extract_merkle_tree_type(ty: &syn::Type) -> Option<syn::Type> {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
        && seg.ident == "MerkleTree"
        && let syn::PathArguments::AngleBracketed(args) = &seg.arguments
    {
        for a in &args.args {
            if let syn::GenericArgument::Type(t) = a {
                return Some(t.clone());
            }
        }
    }
    None
}

/// If `ty` is `Set<T>`, return `T`. Mirrors `zkir_emitter::extract_set_inner_type`.
fn extract_set_inner_type(ty: &syn::Type) -> Option<syn::Type> {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
        && seg.ident == "Set"
        && let syn::PathArguments::AngleBracketed(args) = &seg.arguments
        && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
    {
        return Some(inner.clone());
    }
    None
}

/// Return the K type for any keyed ledger field (Map<K, V> → K, Set<T> → T).
/// Used by the shared contains/member emission helper to choose the right
/// AlignedValue alignment for the key Push.
fn extract_field_key_type(ty: &syn::Type) -> Option<syn::Type> {
    extract_map_key_type(ty).or_else(|| extract_set_inner_type(ty))
}

/// If `ty` is `Map<K, V>`, return `K`. Mirrors `zkir_emitter::extract_map_kv_types`.
fn extract_map_key_type(ty: &syn::Type) -> Option<syn::Type> {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
        && seg.ident == "Map"
        && let syn::PathArguments::AngleBracketed(args) = &seg.arguments
    {
        for a in &args.args {
            if let syn::GenericArgument::Type(t) = a {
                return Some(t.clone());
            }
        }
    }
    None
}

/// If `ty` is `Map<K, V>`, return `(K, V)`.
fn extract_map_kv_types(ty: &syn::Type) -> Option<(syn::Type, syn::Type)> {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
        && seg.ident == "Map"
        && let syn::PathArguments::AngleBracketed(args) = &seg.arguments
    {
        let mut type_args = args.args.iter().filter_map(|a| {
            if let syn::GenericArgument::Type(t) = a {
                Some(t.clone())
            } else {
                None
            }
        });
        let k = type_args.next()?;
        let v = type_args.next()?;
        return Some((k, v));
    }
    None
}

/// Like [`arg_to_runtime_expr`], but preserves the receiver's *typed*
/// wrapper instead of unwrapping to its primitive value. Used when the
/// generated code needs the original `Boolean`/`Uint<N>`/`Field` value so
/// it can be passed to a method like `Map::contains(&K)` whose K type is
/// the wrapper, not the inner primitive.
fn arg_to_runtime_raw_expr(expr: &ExprIR) -> TokenStream {
    match expr {
        ExprIR::Reference { expr: inner, .. } => arg_to_runtime_raw_expr(inner),
        // Tuple literal in argument position — e.g. an inline
        // `(witnesses.k, witnesses.epoch)` passed as a Map key.
        // Reconstruct the Rust tuple so the `__t.0` / `__t.1`
        // projections downstream in `aligned_value_arg_expr` see a
        // real tuple instead of falling through to `()`.
        ExprIR::Tuple { elements, .. } => {
            let parts: Vec<TokenStream> = elements.iter().map(arg_to_runtime_raw_expr).collect();
            let trailing = if elements.len() == 1 {
                quote! { , }
            } else {
                quote! {}
            };
            quote! { (#(#parts),* #trailing) }
        }
        // Array literal `[a, b, c]` in argument position. Reconstruct
        // the Rust array literal so `aligned_value_arg_expr`'s Array
        // arm has a real `[T; N]` value to project from.
        ExprIR::ArrayLit { elements, .. } => {
            let parts: Vec<TokenStream> = elements.iter().map(arg_to_runtime_raw_expr).collect();
            quote! { [#(#parts),*] }
        }
        // Struct literal `MyStruct { a: …, b: … }` in argument position.
        // Emit a Rust struct literal so `aligned_value_arg_expr`'s
        // user-struct-fields arm has a real `MyStruct` value to project
        // through `__t.a` / `__t.b`.
        ExprIR::StructInit { name, fields, .. } => {
            let inits: Vec<TokenStream> = fields
                .iter()
                .map(|(fname, expr)| {
                    let f = fname.clone();
                    let v = arg_to_runtime_raw_expr(expr);
                    quote! { #f: #v }
                })
                .collect();
            quote! { #name { #(#inits),* } }
        }
        ExprIR::WitnessAccess { field, .. } => {
            let field_ident = format_ident!("{}", field.to_string());
            // `Clone` is fine for the small types we currently support
            // (Boolean, Uint<N>, Bytes<N>) — they're all `Clone`.
            quote! { witnesses.#field_ident.clone() }
        }
        // Parametric witness call in raw arg position. Same shape as
        // a field read but invokes the user's method.
        ExprIR::WitnessCall { name, args, .. } => {
            let m = format_ident!("{}", name.to_string());
            let arg_exprs: Vec<TokenStream> = args.iter().map(arg_to_runtime_raw_expr).collect();
            quote! { witnesses.#m(#(#arg_exprs),*) }
        }
        // `arr[i]` in argument position: lift to a Rust index expr
        // over the cloned array. Element types in scope today are all
        // `Copy`/`Clone` so the projection is straightforward.
        ExprIR::Index { array, index, .. } => {
            let arr_expr = arg_to_runtime_raw_expr(array);
            let idx = syn::Index::from(*index as usize);
            quote! { (#arr_expr)[#idx].clone() }
        }
        ExprIR::Disclose { value, .. } => arg_to_runtime_raw_expr(value),
        ExprIR::Var { name, .. } => {
            let ident = format_ident!("{}", name.to_string());
            quote! { #ident.clone() }
        }
        ExprIR::Path { path, .. } => {
            // Multi-segment paths are constants (enum variants, assoc
            // constants); cloning is a no-op for `Copy` enum variants.
            quote! { #path }
        }
        // Preserve method chains (e.g. `.clone()`, `.into_inner()`) on the
        // raw wrapper. Without this, MethodCall falls through to
        // `arg_to_runtime_expr` which unwraps to `.value()` — wrong for
        // wrapper types like `Bytes<N>` that don't expose `value()`.
        ExprIR::MethodCall {
            receiver,
            method,
            args,
            ..
        } => {
            let m = method.to_string();
            match m.as_str() {
                "into" | "value" => arg_to_runtime_raw_expr(receiver),
                _ => {
                    let r = arg_to_runtime_raw_expr(receiver);
                    let m_ident = format_ident!("{}", m);
                    let arg_exprs: Vec<TokenStream> =
                        args.iter().map(arg_to_runtime_raw_expr).collect();
                    quote! { #r.#m_ident(#(#arg_exprs),*) }
                }
            }
        }
        // Free-function calls — map known builtins to their Rust form,
        // otherwise reconstruct the call verbatim from the parsed path.
        // The parser stores the full path (e.g. `Uint::<64>::from`)
        // on `ExprIR::FnCall::path`, so calls like `Uint::<64>::from(0u64)`
        // in `Cell::set` argument position now flow through instead of
        // silently collapsing to `()`.
        ExprIR::FnCall {
            name, path, args, ..
        } => {
            let name_str = name.to_string();
            match name_str.as_str() {
                "merkle_tree_path_root" => {
                    let arg = args
                        .first()
                        .map(arg_to_runtime_raw_expr)
                        .unwrap_or_else(|| quote! { () });
                    // The off-chain helper lives in nocturne-storage; the
                    // umbrella crate re-exports it via `nocturne::types`.
                    quote! { nocturne::types::merkle_tree_path_root(&#arg) }
                }
                _ => {
                    let arg_exprs: Vec<TokenStream> =
                        args.iter().map(arg_to_runtime_raw_expr).collect();
                    quote! { #path(#(#arg_exprs),*) }
                }
            }
        }
        // For anything else, fall back to the value-unwrapped form.
        other => arg_to_runtime_expr(other),
    }
}

/// Generate a runtime Rust expression for a condition.
///
/// For `LedgerAccess` conditions (currently just `Map::contains`), the
/// returned expression is a *block with side effects* — it pushes the
/// contains-pattern ops onto `ops`, computes the bool from `state`, and
/// evaluates to that bool. This lets `if self.map.contains(&k) { ... }`
/// emit the contains transcript ops in cond position the same way it
/// would as a statement.
/// True if `expr` is `ExprIR::Path` whose path resolves (by the last two
/// segments) to a known unit-variant enum like `Status::Open`.
fn is_enum_variant_path_expr(
    expr: &ExprIR,
    user_enums: &HashMap<String, Vec<UserEnumVariant>>,
) -> bool {
    let ExprIR::Path { path, .. } = expr else {
        return false;
    };
    // `Some` and `None` (single-segment) are recognized as Option's
    // variants. The match-lowering in parse.rs produces these paths
    // for `match opt { Some(x) => ..., None => ... }`.
    if path.segments.len() == 1
        && matches!(path.segments[0].ident.to_string().as_str(), "Some" | "None")
    {
        return true;
    }
    let n = path.segments.len();
    if n < 2 {
        return false;
    }
    let enum_name = path.segments[n - 2].ident.to_string();
    let variant_name = path.segments[n - 1].ident.to_string();
    user_enums
        .get(&enum_name)
        .map(|vs| vs.iter().any(|v| v.name == variant_name))
        .unwrap_or(false)
}

/// Lower an operand of an enum equality comparison to a `u64`-typed
/// discriminant expression. The macro-generated `discriminant()` method
/// is in scope for every user enum, so this works uniformly on witness
/// reads (`witnesses.f`), local bindings, and variant literals.
fn runtime_enum_disc_expr(expr: &ExprIR, ctx: &TranscriptCtx<'_>) -> TokenStream {
    let user_enums = ctx.user_enums;
    match expr {
        ExprIR::Path { path, .. } => {
            // `Some` / `None` are single-segment Option variants —
            // resolve to literal `1u64` / `0u64`. Some(_) is also a
            // constructor function with no `.discriminant()` method,
            // so the literal route is the only valid one.
            if path.segments.len() == 1 {
                match path.segments[0].ident.to_string().as_str() {
                    "Some" => return quote! { 1u64 },
                    "None" => return quote! { 0u64 },
                    _ => {}
                }
            }
            // Payload-carrying variants like `Action::Mint` are
            // constructor functions, not values — calling
            // `.discriminant()` on them doesn't compile. Resolve to
            // the literal discriminant when we recognize the path as a
            // payload variant. Unit variants still go through the
            // method call so the generated impl gets exercised.
            let n = path.segments.len();
            if n >= 2 {
                let enum_name = path.segments[n - 2].ident.to_string();
                let variant_name = path.segments[n - 1].ident.to_string();
                if let Some(variants) = user_enums.get(&enum_name)
                    && let Some(idx) = variants.iter().position(|v| v.name == variant_name)
                    && variants[idx].payload.is_some()
                {
                    let d = idx as u64;
                    return quote! { (#d as u64) };
                }
            }
            quote! { ((#path).discriminant() as u64) }
        }
        ExprIR::WitnessAccess { field, .. } => {
            let f = format_ident!("{}", field.to_string());
            // For Option-typed witnesses, route through the same
            // `match { Some(_) => 1u8, None => 0u8 }` discriminant
            // form. For user enums the `.discriminant()` method is
            // present.
            let witness_ty = ctx.witness_types.get(&field.to_string());
            if witness_ty.map(is_option_type).unwrap_or(false) {
                quote! {
                    (match witnesses.#f {
                        ::core::option::Option::Some(_) => 1u64,
                        ::core::option::Option::None => 0u64,
                    })
                }
            } else {
                quote! { (witnesses.#f.discriminant() as u64) }
            }
        }
        ExprIR::Var { name, .. } => {
            let n = format_ident!("{}", name.to_string());
            quote! { (#n.discriminant() as u64) }
        }
        ExprIR::Reference { expr: inner, .. } => runtime_enum_disc_expr(inner, ctx),
        // Method calls (e.g. `witnesses.action.clone()`) — recurse
        // into the receiver and ask for its discriminant.
        ExprIR::MethodCall { receiver, .. } => runtime_enum_disc_expr(receiver, ctx),
        // Fallback: trust that the underlying expression evaluates to
        // the user-facing enum type so `.discriminant()` resolves.
        other => {
            let raw = arg_to_runtime_raw_expr(other);
            quote! { ((#raw).discriminant() as u64) }
        }
    }
}

fn generate_runtime_cond(expr: &ExprIR, ctx: &TranscriptCtx<'_>) -> TokenStream {
    let field_names = ctx.field_names;
    let field_types = ctx.field_types;
    match expr {
        ExprIR::WitnessAccess { field, .. } => {
            let field_ident = format_ident!("{}", field.to_string());
            quote! { witnesses.#field_ident.value() }
        }
        ExprIR::LedgerAccess {
            field,
            method,
            args,
            ..
        } => {
            let field_name = field.to_string();
            let method_name = method.to_string();
            if matches!(method_name.as_str(), "contains" | "member") {
                // Same internal invariant as `generate_op_stmt`: never
                // silently fall back to field 0.
                let field_idx = field_names
                    .iter()
                    .position(|f| f == &field_name)
                    .unwrap_or_else(|| {
                        panic!(
                            "nocturne internal error: ledger field `{field_name}` not \
                             found among {field_names:?}"
                        )
                    }) as u8;
                let field_ty = field_types.get(field_idx as usize);
                return generate_map_contains_block(field_idx, &field_name, args, field_ty, ctx);
            }
            // Other LedgerAccess methods aren't bool-typed (lookup returns V,
            // get/value return T, increment returns nothing). The IR parser
            // doesn't actually reject these, so a user writing
            // `if self.cell.get() { ... }` would silently take the
            // always-true branch. Surface it as a real diagnostic.
            let msg = format!(
                "nocturne: ledger method `{}` on field `{}` doesn't return bool — not usable as an `if` condition",
                method, field_name
            );
            quote! { { compile_error!(#msg); true } }
        }
        ExprIR::MethodCall {
            receiver, method, ..
        } => {
            let method_name = method.to_string();
            match method_name.as_str() {
                "into" | "value" => generate_runtime_cond(receiver, ctx),
                _ => {
                    let recv = generate_runtime_cond(receiver, ctx);
                    let m = format_ident!("{}", method_name);
                    quote! { #recv.#m() }
                }
            }
        }
        ExprIR::Var { name, .. } => {
            let ident = format_ident!("{}", name.to_string());
            quote! { #ident }
        }
        ExprIR::Path { path, .. } => {
            quote! { #path }
        }
        ExprIR::Literal { value, .. } => match value {
            nocturne_ir::expr::LiteralIR::Bool(b) => quote! { #b },
            nocturne_ir::expr::LiteralIR::Int(n) => {
                let n = *n as u64;
                quote! { #n != 0 }
            }
            _ => quote! { true },
        },
        ExprIR::BinaryOp { op, lhs, rhs, .. } => {
            // If either side is an enum-variant path, the other side is a
            // value of that enum and bare `==` won't type-check (witnesses
            // expose `.value()`, not the raw enum). Compare discriminants
            // on both sides instead.
            if matches!(op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_))
                && (is_enum_variant_path_expr(lhs, ctx.user_enums)
                    || is_enum_variant_path_expr(rhs, ctx.user_enums))
            {
                let l = runtime_enum_disc_expr(lhs, ctx);
                let r = runtime_enum_disc_expr(rhs, ctx);
                return match op {
                    syn::BinOp::Eq(_) => quote! { #l == #r },
                    syn::BinOp::Ne(_) => quote! { #l != #r },
                    _ => unreachable!(),
                };
            }
            let l = generate_runtime_cond(lhs, ctx);
            let r = generate_runtime_cond(rhs, ctx);
            match op {
                syn::BinOp::Eq(_) => quote! { #l == #r },
                syn::BinOp::Ne(_) => quote! { #l != #r },
                syn::BinOp::Lt(_) => quote! { #l < #r },
                syn::BinOp::Gt(_) => quote! { #l > #r },
                syn::BinOp::Le(_) => quote! { #l <= #r },
                syn::BinOp::Ge(_) => quote! { #l >= #r },
                syn::BinOp::And(_) => quote! { #l && #r },
                syn::BinOp::Or(_) => quote! { #l || #r },
                other => {
                    let msg = format!(
                        "nocturne: binary operator `{other:?}` not supported in `if` conditions"
                    );
                    quote! { { compile_error!(#msg); true } }
                }
            }
        }
        ExprIR::UnaryOp {
            op, expr: inner, ..
        } => {
            let i = generate_runtime_cond(inner, ctx);
            match op {
                syn::UnOp::Not(_) => quote! { (!#i) },
                syn::UnOp::Neg(_) => quote! { (-#i) },
                other => {
                    let msg = format!(
                        "nocturne: unary operator `{other:?}` not supported in `if` conditions"
                    );
                    quote! { { compile_error!(#msg); true } }
                }
            }
        }
        ExprIR::Reference { expr: inner, .. } => generate_runtime_cond(inner, ctx),
        ExprIR::Disclose { value, .. } => generate_runtime_cond(value, ctx),
        other => {
            // Unsupported expression in cond position — silent `true` would
            // make the branch always fire. Surface the IR shape so the user
            // can see what's wrong.
            let msg = format!(
                "nocturne: unsupported expression in `if` condition: {:?}",
                std::mem::discriminant(other)
            );
            quote! { { compile_error!(#msg); true } }
        }
    }
}
