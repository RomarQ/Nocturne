//! Transcript codegen: generates Rust code that builds transcript `Op` programs
//! at runtime. This replaces Compact's TypeScript runtime.
//!
//! The generated code:
//! - Accepts typed witness structs (not `dyn Any`)
//! - Evaluates conditions at runtime to select active branches
//! - Only emits ops for the active branch (matching ZKIR's pi_skip behavior)
//! - Converts witness values to `Fr` for the private transcript

use midnight_ir::{CircuitIR, ContractIR, ExprIR, WitnessIR};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashMap;

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

    let circuit_fns: Vec<TokenStream> = contract
        .circuits
        .iter()
        .map(|circuit| {
            generate_circuit_transcript_fn(
                circuit,
                &field_names,
                &field_types,
                witnesses_name,
                ledger_name,
                &witness_types,
            )
        })
        .collect();

    quote! {
        /// Generated transcript builders for contract circuits.
        pub mod transcript {
            use super::*;
            use midnight::runtime::onchain_vm::result_mode::ResultModeVerify;
            use midnight::runtime::onchain_vm::ops::{Op, Key};
            use midnight::runtime::onchain_state::state::StateValue;
            use midnight::runtime::transient_crypto::curve::Fr;
            use midnight::runtime::base_crypto::fab::AlignedValue;
            use midnight::runtime::storage::arena::Sp;

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
    field_names: &[String],
    field_types: &[syn::Type],
    witnesses_name: Option<&syn::Ident>,
    ledger_name: &syn::Ident,
    witness_types: &HashMap<String, syn::Type>,
) -> TokenStream {
    let fn_name = format_ident!("build_{}_transcript", circuit.name);
    let doc = format!("Build the transcript for the `{}` circuit.", circuit.name);

    let body_stmts: Vec<TokenStream> = circuit
        .body
        .iter()
        .map(|expr| generate_op_stmt(expr, field_names, field_types, witness_types))
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
                "contains" | "member" | "lookup" | "get" | "value" | "__direct_access"
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
fn generate_op_stmt(
    expr: &ExprIR,
    field_names: &[String],
    field_types: &[syn::Type],
    witness_types: &HashMap<String, syn::Type>,
) -> TokenStream {
    match expr {
        ExprIR::LedgerAccess {
            field,
            method,
            args,
            ..
        } => {
            let field_name = field.to_string();
            let method_name = method.to_string();
            let field_idx = field_names
                .iter()
                .position(|f| f == &field_name)
                .unwrap_or(0) as u8;
            let field_ty = field_types.get(field_idx as usize);

            match method_name.as_str() {
                "increment" => quote! {
                    ops.push(Op::Idx {
                        cached: false,
                        push_path: true,
                        path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
                    });
                    ops.push(Op::Addi { immediate: 1 });
                    ops.push(Op::Ins { cached: true, n: 1 });
                },
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
                        // Unknown field type — best-effort placeholder. Will
                        // not match on-chain encoding; user-visible if it ever
                        // surfaces because the verifier will reject the proof.
                        _ => (quote! { 0u8 }, None),
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
                    // On-chain pattern for `Map<K, V>::contains(k) -> bool`:
                    //   Dup{n:0} + Idx{[Bytes<1>(field_idx)]} + Push{storage:false, Cell(key)}
                    //   + Member + Popeq{cached:true, result: bool}
                    //
                    // The bool result is computed at transcript-build time by
                    // calling the runtime stub on `state`, so the prover and
                    // verifier agree on what the on-chain VM will compute when
                    // it executes `Member`.
                    let field_ident = format_ident!("{}", field_name);
                    let raw_key = args
                        .first()
                        .map(arg_to_runtime_raw_expr)
                        .unwrap_or_else(|| quote! { () });
                    // The key expression must match the IR's alignment for K.
                    // For Bytes<N> this is `*<raw>.as_bytes()`; for primitives
                    // it's `<value> as u<N>` so Uint<64> emits Bytes{8} (not
                    // the Bytes{16} that AlignedValue::from(u128) produces).
                    let k_ty = field_ty.and_then(extract_map_key_type);
                    let key_aligned = args
                        .first()
                        .map(|a| aligned_value_arg_expr(a, k_ty.as_ref()))
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
                        }
                    }
                }
                "insert" => {
                    // `insert` on a Map field — see the Map::insert arm below.
                    // If the field happens to be a Cell, fall through to set.
                    if field_ty.and_then(extract_map_kv_types).is_some() {
                        generate_map_insert(field_idx, args, field_ty)
                    } else {
                        generate_cell_set(field_idx, args, field_ty)
                    }
                }
                "set" => {
                    // `set` is also used as an alias for Map::insert. Route
                    // based on the field type.
                    if field_ty.and_then(extract_map_kv_types).is_some() {
                        generate_map_insert(field_idx, args, field_ty)
                    } else {
                        generate_cell_set(field_idx, args, field_ty)
                    }
                }
                "remove" if field_ty.and_then(extract_map_kv_types).is_some() => {
                    generate_map_remove(field_idx, args, field_ty)
                }
                "lookup" if field_ty.and_then(extract_map_kv_types).is_some() => {
                    generate_map_lookup(field_idx, &field_name, args, field_ty)
                }
                _ => quote! {},
            }
        }

        ExprIR::If {
            cond,
            then_branch,
            else_branch,
            ..
        } => {
            // Collect witness values used in the condition for private_transcript.
            let witness_adds = collect_witness_private_inputs(cond);
            let cond_expr = generate_runtime_cond(cond);
            let then_stmts: Vec<TokenStream> = then_branch
                .iter()
                .map(|e| generate_op_stmt(e, field_names, field_types, witness_types))
                .collect();

            if let Some(else_exprs) = else_branch {
                let else_stmts: Vec<TokenStream> = else_exprs
                    .iter()
                    .map(|e| generate_op_stmt(e, field_names, field_types, witness_types))
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
            // Strip leading underscores from the user-side name before
            // prefixing with `_let_`, otherwise `let _v = ...` becomes the
            // identifier `_let__v` and trips the `non_snake_case` lint with
            // its double underscore.
            let stripped = name.to_string();
            let stripped = stripped.trim_start_matches('_');
            let var_name = format_ident!("_let_{}", stripped);
            let val_stmt = generate_op_stmt(value, field_names, field_types, witness_types);
            quote! {
                let #var_name = {
                    #val_stmt
                };
            }
        }

        ExprIR::WitnessAccess { field, .. } => {
            // Read the witness value and add it to the private transcript.
            //
            // Single-Fr witnesses (Boolean/Field/Uint) push `Fr::from(value())`
            // directly. Multi-Fr witnesses (`Bytes<N>`) build an AlignedValue
            // from the underlying [u8; N] and use
            // `AlignedValueExt::value_only_field_repr` to push the right
            // number of Frs in the same order the IR's PrivateInputs expect
            // (high-bytes chunk first, then full 31-byte chunks).
            let field_ident = format_ident!("{}", field.to_string());
            let field_str = field.to_string();
            if witness_types
                .get(&field_str)
                .map(is_bytes_witness)
                .unwrap_or(false)
            {
                quote! {
                    {
                        use midnight::runtime::transient_crypto::fab::AlignedValueExt;
                        let __av = AlignedValue::from(*witnesses.#field_ident.as_bytes());
                        __av.value_only_field_repr(&mut private_transcript);
                    }
                }
            } else {
                quote! {
                    private_transcript.push(Fr::from(witnesses.#field_ident.value()));
                }
            }
        }

        ExprIR::Block { stmts, .. } => {
            let inner: Vec<TokenStream> = stmts
                .iter()
                .map(|s| generate_op_stmt(s, field_names, field_types, witness_types))
                .collect();
            quote! { #(#inner)* }
        }

        ExprIR::MethodCall { receiver, .. } => {
            // Always forward to the receiver so any side-effecting
            // sub-expressions (e.g. witness reads that push to
            // `private_transcript`) are emitted. Method-specific runtime
            // behavior is generated elsewhere; this arm is just about
            // side effects on the transcript builder's state.
            generate_op_stmt(receiver, field_names, field_types, witness_types)
        }

        _ => quote! {},
    }
}

/// Collect witness field accesses in a condition expression and
/// generate code to add their values to private_transcript.
fn collect_witness_private_inputs(expr: &ExprIR) -> TokenStream {
    match expr {
        ExprIR::WitnessAccess { field, .. } => {
            let field_ident = format_ident!("{}", field.to_string());
            quote! {
                private_transcript.push(Fr::from(witnesses.#field_ident.value() as u64));
            }
        }
        ExprIR::MethodCall { receiver, .. } => collect_witness_private_inputs(receiver),
        ExprIR::BinaryOp { lhs, rhs, .. } => {
            let l = collect_witness_private_inputs(lhs);
            let r = collect_witness_private_inputs(rhs);
            quote! { #l #r }
        }
        ExprIR::UnaryOp { expr: inner, .. } => collect_witness_private_inputs(inner),
        _ => quote! {},
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
            midnight_ir::expr::LiteralIR::Bool(b) => quote! { #b },
            midnight_ir::expr::LiteralIR::Int(n) => {
                // u128 → u64 is safe for everything we currently support
                // (Boolean, Uint<N> with N ≤ 64). Larger Uint values are
                // a future-work concern tracked alongside multi-Fr value
                // encoding.
                let n = *n as u64;
                quote! { #n }
            }
            midnight_ir::expr::LiteralIR::Str(s) => quote! { #s },
        },
        ExprIR::Disclose { value, .. } => arg_to_runtime_expr(value),
        ExprIR::WitnessAccess { field, .. } => {
            let field_ident = format_ident!("{}", field.to_string());
            quote! { witnesses.#field_ident.value() }
        }
        ExprIR::Var { name, .. } => {
            let ident = format_ident!("{}", name.to_string());
            quote! { #ident }
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
        // Anything else falls back to `()` and will fail to compile with a
        // clear "the trait `From<()>` is not implemented" message, which
        // points the user at an unsupported argument shape.
        _ => quote! { () },
    }
}

/// Emit the runtime ops for `Cell<T>::set(v)` — see comment in the
/// `set`/`insert` arm above for the on-chain pattern.
fn generate_cell_set(field_idx: u8, args: &[ExprIR], field_ty: Option<&syn::Type>) -> TokenStream {
    let t_ty = field_ty.and_then(extract_cell_inner_type);
    let value_aligned = args
        .first()
        .map(|a| aligned_value_arg_expr(a, t_ty.as_ref()))
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

/// Produce a runtime Rust expression suitable for passing into
/// `AlignedValue::from(_)` for a value of the given expected type.
///
/// - `Bytes<N>` → unwrap to `[u8; N]` via `*<raw>.as_bytes()`.
/// - Single-Fr primitives (Boolean / Uint<N> / u8..u128) → `.value()` if
///   the expression is a witness/wrapper, then apply the primitive cast
///   from `primitive_cast_for_type`.
/// - Unknown type → fall back to the raw `.value()`-style expression.
fn aligned_value_arg_expr(expr: &ExprIR, ty: Option<&syn::Type>) -> TokenStream {
    if let Some(t) = ty {
        let ty_str = quote!(#t).to_string().replace(' ', "");
        if ty_str.starts_with("Bytes<") {
            // Bytes<N>: need [u8; N] for AlignedValue::from.
            let raw = arg_to_runtime_raw_expr(expr);
            return quote! { *(#raw).as_bytes() };
        }
    }
    let value_expr = arg_to_runtime_expr(expr);
    match ty.and_then(primitive_cast_for_type) {
        Some(cast) => quote! { (#value_expr) #cast },
        None => value_expr,
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
) -> TokenStream {
    let kv = field_ty.and_then(extract_map_kv_types);
    let k_ty = kv.as_ref().map(|(k, _)| k.clone());
    let v_ty = kv.as_ref().map(|(_, v)| v.clone());

    // K and V both need the Bytes-aware expression so multi-Fr types
    // (`Bytes<N>`) build the AlignedValue from the underlying `[u8; N]`
    // while primitives still get the right `as u<N>` cast.
    let key_aligned = args
        .first()
        .map(|a| aligned_value_arg_expr(a, k_ty.as_ref()))
        .unwrap_or_else(|| quote! { () });
    let val_aligned = args
        .get(1)
        .map(|a| aligned_value_arg_expr(a, v_ty.as_ref()))
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
        .map(|a| aligned_value_arg_expr(a, k_ty.as_ref()))
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
) -> TokenStream {
    let k_ty = field_ty.and_then(extract_map_key_type);
    let key_aligned = args
        .first()
        .map(|a| aligned_value_arg_expr(a, k_ty.as_ref()))
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
        ExprIR::WitnessAccess { field, .. } => {
            let field_ident = format_ident!("{}", field.to_string());
            // `Clone` is fine for the small types we currently support
            // (Boolean, Uint<N>, Bytes<N>) — they're all `Clone`.
            quote! { witnesses.#field_ident.clone() }
        }
        ExprIR::Disclose { value, .. } => arg_to_runtime_raw_expr(value),
        ExprIR::Var { name, .. } => {
            let ident = format_ident!("{}", name.to_string());
            quote! { #ident.clone() }
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
        // For anything else, fall back to the value-unwrapped form.
        other => arg_to_runtime_expr(other),
    }
}

/// Generate a runtime Rust expression for a condition.
fn generate_runtime_cond(expr: &ExprIR) -> TokenStream {
    match expr {
        ExprIR::WitnessAccess { field, .. } => {
            let field_ident = format_ident!("{}", field.to_string());
            quote! { witnesses.#field_ident.value() }
        }
        ExprIR::MethodCall {
            receiver, method, ..
        } => {
            let method_name = method.to_string();
            match method_name.as_str() {
                "into" | "value" => generate_runtime_cond(receiver),
                _ => {
                    let recv = generate_runtime_cond(receiver);
                    let m = format_ident!("{}", method_name);
                    quote! { #recv.#m() }
                }
            }
        }
        ExprIR::Var { name, .. } => {
            let ident = format_ident!("{}", name.to_string());
            quote! { #ident }
        }
        ExprIR::Literal { value, .. } => match value {
            midnight_ir::expr::LiteralIR::Bool(b) => quote! { #b },
            midnight_ir::expr::LiteralIR::Int(n) => {
                let n = *n as u64;
                quote! { #n != 0 }
            }
            _ => quote! { true },
        },
        ExprIR::BinaryOp { op, lhs, rhs, .. } => {
            let l = generate_runtime_cond(lhs);
            let r = generate_runtime_cond(rhs);
            match op {
                syn::BinOp::Eq(_) => quote! { #l == #r },
                syn::BinOp::Ne(_) => quote! { #l != #r },
                syn::BinOp::Lt(_) => quote! { #l < #r },
                syn::BinOp::Gt(_) => quote! { #l > #r },
                syn::BinOp::And(_) => quote! { #l && #r },
                syn::BinOp::Or(_) => quote! { #l || #r },
                _ => quote! { true },
            }
        }
        _ => quote! { true },
    }
}
