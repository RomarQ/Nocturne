//! Transcript codegen: generates Rust code that builds transcript `Op` programs
//! at runtime. This replaces Compact's TypeScript runtime.
//!
//! The generated code:
//! - Accepts typed witness structs (not `dyn Any`)
//! - Evaluates conditions at runtime to select active branches
//! - Only emits ops for the active branch (matching ZKIR's pi_skip behavior)
//! - Converts witness values to `Fr` for the private transcript

use crate::aligned::accessor_aligned_value_expr;
use crate::private_events::{FirstTouchTracker, PrivateEvent, walk_expr_events};
use crate::typing::{is_transparent_wrapper, parse_uint_type, uint_max_value};
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
    /// Parametric witness method name → return type, for the per-call-site
    /// private-transcript pushes (`WitnessCall` events).
    witness_methods: &'a HashMap<String, syn::Type>,
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
    let witness_methods: HashMap<String, syn::Type> = contract
        .witnesses
        .as_ref()
        .map(|w| {
            w.methods
                .iter()
                .map(|m| (m.name.to_string(), m.return_type.clone()))
                .collect()
        })
        .unwrap_or_default();

    let ctx = TranscriptCtx {
        field_names: &field_names,
        field_types: &field_types,
        witness_types: &witness_types,
        witness_methods: &witness_methods,
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
                /// Private transcript values (witnesses as field elements),
                /// in the circuit's `PrivateInput` allocation order. This is
                /// exactly the `value_only_field_repr` flattening of
                /// `private_transcript_outputs` — both are built from the
                /// same pushes.
                pub private_transcript: Vec<Fr>,
                /// One `AlignedValue` per witness invocation, in IR order —
                /// the shape `ContractCallPrototype::private_transcript_outputs`
                /// expects (the ledger flattens it with
                /// `value_only_field_repr` when constructing the proof
                /// preimage; see midnight-ledger `construct.rs`).
                pub private_transcript_outputs: Vec<AlignedValue>,
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

    // One first-touch tracker per circuit: the generated pushes mirror
    // the ZKIR emitter's witness-field cache, so a field pushes exactly
    // once — at its statically-known first touch in IR walk order.
    let mut tracker = FirstTouchTracker::default();
    let body_stmts: Vec<TokenStream> = circuit
        .body
        .iter()
        .map(|expr| generate_op_stmt(expr, ctx, &mut tracker))
        .collect();

    let needs_state = circuit_needs_state(&circuit.body);
    let state_param = if needs_state {
        quote! { __nocturne_state: &#ledger_name, }
    } else {
        quote! {}
    };

    // The generated parameter is ALWAYS named `witnesses`, regardless of
    // what the user called their circuit parameter: every helper in this
    // module emits `witnesses.<field>` accessors, and this is a fresh
    // generated fn whose signature is part of the documented contract —
    // nothing requires mirroring the user's local parameter name.
    if circuit.takes_witnesses {
        let witnesses_ty = witnesses_name
            .map(|n| quote! { &#n })
            .unwrap_or_else(|| quote! { &() });

        quote! {
            #[doc = #doc]
            pub fn #fn_name(#state_param witnesses: #witnesses_ty) -> TranscriptResult {
                let mut __nocturne_ops: Vec<VmOp> = Vec::new();
                let mut __nocturne_private_transcript: Vec<Fr> = Vec::new();
                let mut __nocturne_private_transcript_outputs: Vec<AlignedValue> = Vec::new();

                #(#body_stmts)*

                TranscriptResult {
                    ops: __nocturne_ops,
                    private_transcript: __nocturne_private_transcript,
                    private_transcript_outputs: __nocturne_private_transcript_outputs,
                }
            }
        }
    } else if needs_state {
        quote! {
            #[doc = #doc]
            pub fn #fn_name(__nocturne_state: &#ledger_name) -> TranscriptResult {
                let mut __nocturne_ops: Vec<VmOp> = Vec::new();
                let mut __nocturne_private_transcript: Vec<Fr> = Vec::new();
                let mut __nocturne_private_transcript_outputs: Vec<AlignedValue> = Vec::new();

                #(#body_stmts)*

                TranscriptResult {
                    ops: __nocturne_ops,
                    private_transcript: __nocturne_private_transcript,
                    private_transcript_outputs: __nocturne_private_transcript_outputs,
                }
            }
        }
    } else {
        quote! {
            #[doc = #doc]
            pub fn #fn_name() -> TranscriptResult {
                let mut __nocturne_ops: Vec<VmOp> = Vec::new();
                let mut __nocturne_private_transcript: Vec<Fr> = Vec::new();
                let mut __nocturne_private_transcript_outputs: Vec<AlignedValue> = Vec::new();

                #(#body_stmts)*

                TranscriptResult {
                    ops: __nocturne_ops,
                    private_transcript: __nocturne_private_transcript,
                    private_transcript_outputs: __nocturne_private_transcript_outputs,
                }
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
        // `assert!(self.allowed.contains(&k))` bakes the contains result
        // from `state` — without this arm the generated fn lacks the
        // `state` param while its body references it.
        ExprIR::Assert { kind, .. } => match kind {
            nocturne_ir::expr::AssertKind::Assert(cond) => expr_needs_state(cond),
            nocturne_ir::expr::AssertKind::AssertEq(a, b) => {
                expr_needs_state(a) || expr_needs_state(b)
            }
        },
        // Payload projection over a ledger read (`match self.f.get() { … }`).
        ExprIR::EnumPayload { scrutinee, .. } => expr_needs_state(scrutinee),
        // Arg-bearing shapes: any argument may carry a ledger read.
        ExprIR::FnCall { args, .. } | ExprIR::WitnessCall { args, .. } => {
            args.iter().any(expr_needs_state)
        }
        ExprIR::Tuple { elements, .. } | ExprIR::ArrayLit { elements, .. } => {
            elements.iter().any(expr_needs_state)
        }
        ExprIR::StructInit { fields, .. } => fields.iter().any(|(_, e)| expr_needs_state(e)),
        ExprIR::Index { array, .. } => expr_needs_state(array),
        ExprIR::Return { value, .. } => value.as_deref().is_some_and(expr_needs_state),
        _ => false,
    }
}

/// Generate Rust statements for one circuit-body statement: the
/// private-transcript pushes for every private-input event the statement
/// carries (at the event's IR walk position), followed by / interleaved
/// with the VM-op pushes.
///
/// Structural statements (`if`, `let`, blocks, asserts) are handled here
/// because they decide WHERE the event pushes land (a condition's events
/// fire before the runtime `if`; a branch body's events fire inside it).
/// Everything else delegates to `private_event_pushes` (the canonical
/// event walk) + `generate_expr_ops` (ops only).
fn generate_op_stmt(
    expr: &ExprIR,
    ctx: &TranscriptCtx<'_>,
    tracker: &mut FirstTouchTracker,
) -> TokenStream {
    match expr {
        ExprIR::If {
            cond,
            then_branch,
            else_branch,
            ..
        } => {
            // The condition's witness events fire BEFORE the runtime
            // `if` — mirroring the emitter, which evaluates the cond
            // before the branch guard activates (unguarded, cached).
            // Branch-body events fire inside the runtime branch: the
            // emitter allocates them guarded, and the zkir VM skips
            // their transcript slot on the inactive path — a guarded
            // `PrivateInput`/`PublicInput` whose guard is 0 pushes 0
            // WITHOUT advancing the transcript index (midnight-ledger
            // ledger-8, zkir/src/ir_vm.rs:325-355).
            let witness_adds = private_event_pushes(cond, ctx, tracker);
            let cond_expr = generate_runtime_cond(cond, ctx);
            let outer_in_branch = tracker.in_branch;
            tracker.in_branch = true;
            let then_stmts: Vec<TokenStream> = then_branch
                .iter()
                .map(|e| generate_op_stmt(e, ctx, tracker))
                .collect();
            let else_stmts: Option<Vec<TokenStream>> = else_branch.as_ref().map(|exprs| {
                exprs
                    .iter()
                    .map(|e| generate_op_stmt(e, ctx, tracker))
                    .collect()
            });
            tracker.in_branch = outer_in_branch;

            if let Some(else_stmts) = else_stmts {
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
            // The block form lets the ops generator's trailing
            // expression (e.g. `merkle_tree_path_root(arg)` for that
            // FnCall arm) flow into the binding. Plain witness reads
            // produce `()` because their effects are private-transcript
            // pushes; we patch that case below so `let v = w.f; ...
            // cell.set(v);` binds to the real witness value instead of
            // unit.
            let var_name = format_ident!("{}", name.to_string());
            // RHS events fire once, at the binding — matching the
            // emitter, which evaluates (and caches) the RHS wire here.
            // If-shaped RHS handles its own event placement (cond
            // outside the runtime if, branch bodies inside).
            let val_stmt = match &**value {
                v @ (ExprIR::If { .. } | ExprIR::Block { .. }) => generate_op_stmt(v, ctx, tracker),
                v => {
                    let pushes = private_event_pushes(v, ctx, tracker);
                    let ops = generate_expr_ops(v, ctx);
                    quote! { #pushes #ops }
                }
            };
            // Pull the witness binding out separately so the block
            // evaluates to a real value rather than `()`. Handles bare
            // `witnesses.f` and `witnesses.f.<method>()` (most commonly
            // `.clone()`) — both produce statement-only side effects
            // so the let block otherwise binds unit.
            if let Some(expr) = let_binding_runtime_value(value, ctx) {
                return quote! {
                    #val_stmt
                    #[allow(non_snake_case, unused_variables)]
                    let #var_name = #expr;
                };
            }
            // Cell::get() / Counter::value() / Map::lookup() reads —
            // bind to the live state's accessor so `let v =
            // self.f.get(); ...; use v` works downstream. The ops side
            // (Dup+Idx+Popeq) is already emitted via `val_stmt`.
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

        ExprIR::Block { stmts, .. } => {
            let inner: Vec<TokenStream> = stmts
                .iter()
                .map(|s| generate_op_stmt(s, ctx, tracker))
                .collect();
            quote! { #(#inner)* }
        }

        // `assert!(cond)` / `assert_eq!(a, b)` — at transcript-build
        // time we evaluate the same condition in plain Rust so the
        // builder fails fast when a witness violates the invariant,
        // before the prover wastes work on an impossible proof. The
        // ZKIR side emits the in-circuit constraint separately.
        ExprIR::Assert { kind, .. } => match kind {
            nocturne_ir::expr::AssertKind::Assert(cond) => {
                let witness_pushes = private_event_pushes(cond, ctx, tracker);
                // `generate_runtime_cond` already emits the transcript
                // ops for ledger reads in cond position (contains/get
                // produce side-effecting blocks), so no separate op
                // emission here — it would double-emit.
                let cond_expr = generate_runtime_cond(cond, ctx);
                quote! {
                    #witness_pushes
                    assert!(#cond_expr, "nocturne: circuit assertion failed");
                }
            }
            nocturne_ir::expr::AssertKind::AssertEq(a, b) => {
                let wa = private_event_pushes(a, ctx, tracker);
                let wb = private_event_pushes(b, ctx, tracker);
                let la = generate_runtime_cond(a, ctx);
                let lb = generate_runtime_cond(b, ctx);
                quote! {
                    #wa
                    #wb
                    assert_eq!(#la, #lb, "nocturne: circuit assert_eq! failed");
                }
            }
        },

        other => {
            let pushes = private_event_pushes(other, ctx, tracker);
            let ops = generate_expr_ops(other, ctx);
            quote! { #pushes #ops }
        }
    }
}

/// Find an `ExprIR::If` nested anywhere inside an expression-position
/// tree (an `if` whose VALUE flows into a surrounding expression, e.g.
/// `self.value.set(if c { witnesses.a } else { witnesses.b })`).
///
/// Why this must be rejected: `generate_op_stmt` only places branch-body
/// event pushes inside a runtime `if` for STATEMENT-position `if`s (and
/// `let`-RHS `if`s, which route through the same arm). An `if` reached
/// through `private_event_pushes`'s walk would push BOTH branches'
/// private-transcript entries unconditionally, while the circuit's
/// guarded `PrivateInput`s consume only the active branch's slot at
/// prove time (a guard of 0 pushes 0 without advancing the transcript
/// index, zkir/src/ir_vm.rs:325-355) — the zkir VM then bails with
/// "Transcripts not fully consumed"
/// (midnight-ledger ledger-8, zkir/src/ir_vm.rs:472).
fn find_expression_position_if(expr: &ExprIR) -> Option<proc_macro2::Span> {
    match expr {
        ExprIR::If { span, .. } => Some(*span),
        ExprIR::LedgerAccess { args, .. }
        | ExprIR::WitnessCall { args, .. }
        | ExprIR::FnCall { args, .. } => args.iter().find_map(find_expression_position_if),
        ExprIR::MethodCall { receiver, args, .. } => find_expression_position_if(receiver)
            .or_else(|| args.iter().find_map(find_expression_position_if)),
        ExprIR::BinaryOp { lhs, rhs, .. } => {
            find_expression_position_if(lhs).or_else(|| find_expression_position_if(rhs))
        }
        ExprIR::UnaryOp { expr: inner, .. }
        | ExprIR::Reference { expr: inner, .. }
        | ExprIR::Disclose { value: inner, .. } => find_expression_position_if(inner),
        ExprIR::Let { value, .. } => find_expression_position_if(value),
        // A block nested inside an expression still yields its value to
        // the surrounding expression, so an `if` anywhere inside it has
        // the same both-branches-pushed hazard.
        ExprIR::Block { stmts, .. } => stmts.iter().find_map(find_expression_position_if),
        ExprIR::Assert { kind, .. } => match kind {
            nocturne_ir::expr::AssertKind::Assert(cond) => find_expression_position_if(cond),
            nocturne_ir::expr::AssertKind::AssertEq(a, b) => {
                find_expression_position_if(a).or_else(|| find_expression_position_if(b))
            }
        },
        ExprIR::EnumPayload { scrutinee, .. } => find_expression_position_if(scrutinee),
        ExprIR::Index { array, .. } => find_expression_position_if(array),
        ExprIR::Tuple { elements, .. } | ExprIR::ArrayLit { elements, .. } => {
            elements.iter().find_map(find_expression_position_if)
        }
        ExprIR::StructInit { fields, .. } => fields
            .iter()
            .find_map(|(_, e)| find_expression_position_if(e)),
        ExprIR::Return { value, .. } => value.as_deref().and_then(find_expression_position_if),
        ExprIR::WitnessAccess { .. }
        | ExprIR::Literal { .. }
        | ExprIR::Var { .. }
        | ExprIR::Path { .. }
        | ExprIR::Unsupported { .. } => None,
    }
}

/// Emit the private-transcript pushes for every private-input event in
/// `expr`, in canonical IR walk order (see `crate::private_events`).
/// Witness-field first touches push once (the tracker mirrors the
/// emitter's cache); `WitnessCall`s push per call site.
///
/// Every call site hands this function an expression-position tree
/// (statement-position `if`s are intercepted by `generate_op_stmt`), so
/// any `ExprIR::If` found here would break private-transcript parity —
/// reject it with a `compile_error!` instead of silently pushing both
/// branches' events.
fn private_event_pushes(
    expr: &ExprIR,
    ctx: &TranscriptCtx<'_>,
    tracker: &mut FirstTouchTracker,
) -> TokenStream {
    if let Some(span) = find_expression_position_if(expr) {
        let msg = "nocturne: `if` is not supported in expression position (e.g. \
                   `self.x.set(if c { a } else { b })`) — the transcript builder would \
                   push private-transcript entries for both branches while the circuit \
                   consumes only the active branch's. Use a statement-position `if` \
                   instead: `if c { self.x.set(a); } else { self.x.set(b); }`";
        return quote::quote_spanned! {span=> compile_error!(#msg); };
    }
    let mut pushes: Vec<TokenStream> = Vec::new();
    walk_expr_events(expr, ctx.user_structs, tracker, &mut |_, ev| {
        pushes.push(match ev {
            PrivateEvent::FieldTouch { field } => witness_field_push(field, ctx),
            PrivateEvent::Call { name, args } => witness_call_push(name, args, ctx),
        });
    });
    quote! { #(#pushes)* }
}

/// The push code for a witness field's first touch.
fn witness_field_push(field: &syn::Ident, ctx: &TranscriptCtx<'_>) -> TokenStream {
    let field_str = field.to_string();
    let Some(ty) = ctx.witness_types.get(&field_str) else {
        // Parse-time validation guarantees every `witnesses.<f>` names a
        // declared field, so a missing type here is an internal bug.
        // Guessing a single-Fr push would silently desynchronize the
        // private transcript from the circuit's PrivateInput count.
        let msg =
            format!("nocturne internal error: witness field `{field_str}` has no registered type");
        return quote! { compile_error!(#msg); };
    };
    // `.clone()` because the aligned-repr recursion binds the value
    // (`let __s = <accessor>`), which would otherwise move out of the
    // shared `&Witnesses` borrow for non-Copy types (user structs,
    // Bytes<N>, MerkleTreePath). Same convention as
    // `arg_to_runtime_raw_expr`'s witness arm.
    private_value_push(ty, &quote! { witnesses.#field.clone() }, ctx)
}

/// The push code for a parametric witness call site. Evaluates the args
/// and invokes the user's method once, binding the result so the pushes
/// derive from a single invocation.
///
/// NOTE: when the same call also appears in argument position (e.g.
/// `self.cell.set(witnesses.next_nonce())`), the op side evaluates the
/// method again — witness methods must be deterministic for the circuit
/// and the transcript to agree (same contract the hand-rolled test
/// harnesses already rely on).
fn witness_call_push(name: &syn::Ident, args: &[ExprIR], ctx: &TranscriptCtx<'_>) -> TokenStream {
    let Some(ret_ty) = ctx.witness_methods.get(&name.to_string()) else {
        let msg = format!(
            "nocturne internal error: witness method `{name}` has no registered return type"
        );
        return quote! { compile_error!(#msg); };
    };
    let arg_exprs: Vec<TokenStream> = args.iter().map(arg_to_runtime_raw_expr).collect();
    let push = private_value_push(ret_ty, &quote! { __wc }, ctx);
    quote! {
        {
            let __wc = witnesses.#name(#(#arg_exprs),*);
            #push
        }
    }
}

/// Push one witness invocation's value: build the typed `AlignedValue`
/// once, append it to `private_transcript_outputs`, and flatten its
/// value Frs into `private_transcript` via `value_only_field_repr` —
/// the exact flattening midnight-ledger's `construct_proof` applies to
/// `private_transcript_outputs` (construct.rs), so the two vectors agree
/// by construction.
///
/// `MerkleTreePath<H, T>` is the one shape that can't be a single
/// `AlignedValue` (its entry count exceeds the upstream tuple-Aligned
/// cap for tall trees): it pushes leaf + per-entry sibling/goes_left as
/// a sequence of AlignedValues, whose flattening matches the emitter's
/// `witness_fr_layout` expansion.
fn private_value_push(
    ty: &syn::Type,
    accessor: &TokenStream,
    ctx: &TranscriptCtx<'_>,
) -> TokenStream {
    if is_merkle_tree_path(ty) {
        let leaf_ty = extract_merkle_tree_path_leaf_type(ty);
        let leaf_comps = accessor_aligned_value_expr(
            leaf_ty.as_ref(),
            &quote! { (#accessor).leaf },
            ctx.user_enums,
            ctx.user_structs,
        );
        return quote! {
            {
                use nocturne::runtime::transient_crypto::fab::AlignedValueExt;
                let __av = AlignedValue::from(#leaf_comps);
                __av.value_only_field_repr(&mut __nocturne_private_transcript);
                __nocturne_private_transcript_outputs.push(__av);
                for __entry in (#accessor).path.iter() {
                    // Full-Fr sibling: reconstruct from the digest's
                    // 32-byte LE representation; truncating through
                    // `.field().value()` would discard the upper bits.
                    let __sib = AlignedValue::from(
                        Fr::from_le_bytes(&__entry.sibling.as_le_bytes())
                            .expect("MerkleTreeDigest bytes round-trip through Fr"),
                    );
                    __sib.value_only_field_repr(&mut __nocturne_private_transcript);
                    __nocturne_private_transcript_outputs.push(__sib);
                    let __gl = AlignedValue::from(__entry.goes_left.value());
                    __gl.value_only_field_repr(&mut __nocturne_private_transcript);
                    __nocturne_private_transcript_outputs.push(__gl);
                }
            }
        };
    }
    let comps = accessor_aligned_value_expr(Some(ty), accessor, ctx.user_enums, ctx.user_structs);
    quote! {
        {
            use nocturne::runtime::transient_crypto::fab::AlignedValueExt;
            let __av = AlignedValue::from(#comps);
            __av.value_only_field_repr(&mut __nocturne_private_transcript);
            __nocturne_private_transcript_outputs.push(__av);
        }
    }
}

/// Generate the VM-op statements for a non-structural expression. Does
/// NOT emit private-transcript pushes — those are owned by
/// `private_event_pushes`, which the statement-level dispatcher runs at
/// each expression's walk position.
fn generate_expr_ops(expr: &ExprIR, ctx: &TranscriptCtx<'_>) -> TokenStream {
    let field_names = ctx.field_names;
    let field_types = ctx.field_types;
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
                        __nocturne_ops.push(Op::Idx {
                            cached: false,
                            push_path: true,
                            path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
                        });
                        __nocturne_ops.push(Op::Addi { immediate: #n });
                        __nocturne_ops.push(Op::Ins { cached: true, n: 1 });
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
                            quote! { __nocturne_state.#field_ident.value() },
                            Some(syn::parse_quote!(u64)),
                        ),
                        Some(t) if extract_cell_inner_type(t).is_some() => (
                            quote! { __nocturne_state.#field_ident.get() },
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
                                    tuple_component_aligned_repr(
                                        &elem_ty,
                                        &quote! { __a[#idx] },
                                        ctx,
                                    )
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
                                    let payload_repr = tuple_component_aligned_repr(
                                        &p,
                                        &quote! { __payload },
                                        ctx,
                                    );
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
                        __nocturne_ops.push(Op::Dup { n: 0 });
                        __nocturne_ops.push(Op::Idx {
                            cached: false,
                            push_path: false,
                            path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
                        });
                        __nocturne_ops.push(Op::Popeq {
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

        // Witness reads and parametric witness calls have NO op-side
        // lowering: their effect is the private-transcript push, which
        // `private_event_pushes` owns (first-touch for fields, per call
        // site for calls).
        ExprIR::WitnessAccess { .. } | ExprIR::WitnessCall { .. } => quote! {},

        ExprIR::MethodCall { receiver, args, .. } => {
            // Forward to the receiver (and args) so any op-bearing
            // sub-expressions (e.g. ledger reads under a method chain)
            // are emitted. Method-specific runtime behavior is generated
            // elsewhere; this arm is just about transcript ops.
            let recv = generate_expr_ops(receiver, ctx);
            let arg_ops: Vec<TokenStream> =
                args.iter().map(|a| generate_expr_ops(a, ctx)).collect();
            quote! { #recv #(#arg_ops)* }
        }

        // Free-function calls used as RHS of `let` or as standalone
        // statements: yield a runtime Rust expression that evaluates to
        // the same value the IR computes — so the resulting `let` binds
        // a real value the surrounding code can pass into ledger
        // method calls (e.g. `check_root(&computed)`). Witness pushes
        // for the args are handled by the event walk, not here.
        ExprIR::FnCall { name, args, .. } => {
            let arg_ops: Vec<TokenStream> =
                args.iter().map(|a| generate_expr_ops(a, ctx)).collect();
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
                #(#arg_ops)*
                #value_expr
            }
        }

        // Wrappers forward to their inner so op-bearing sub-expressions
        // bubble up through `&expr` / `disclose(expr)` / `-expr`.
        ExprIR::Reference { expr: inner, .. }
        | ExprIR::Disclose { value: inner, .. }
        | ExprIR::UnaryOp { expr: inner, .. } => generate_expr_ops(inner, ctx),

        // BinaryOp at statement level: the arithmetic itself doesn't
        // produce ops, but either operand may (e.g. a ledger read).
        ExprIR::BinaryOp { lhs, rhs, .. } => {
            let l = generate_expr_ops(lhs, ctx);
            let r = generate_expr_ops(rhs, ctx);
            quote! { #l #r }
        }

        // Payload projection: the op side is whatever the scrutinee
        // emits (a `Cell<Option<T>>` read emits its Dup+Idx+Popeq here;
        // a witness scrutinee emits nothing). The value side is handled
        // by `let_binding_runtime_value`'s EnumPayload arm.
        ExprIR::EnumPayload { scrutinee, .. } => generate_expr_ops(scrutinee, ctx),

        // `arr[i]` / `return v` / composite literals: no ops of their
        // own, but their sub-expressions may carry op-bearing reads.
        ExprIR::Index { array, .. } => generate_expr_ops(array, ctx),
        ExprIR::Return { value, .. } => match value {
            Some(v) => generate_expr_ops(v, ctx),
            None => quote! {},
        },
        ExprIR::Tuple { elements, .. } | ExprIR::ArrayLit { elements, .. } => {
            let inner: Vec<TokenStream> =
                elements.iter().map(|e| generate_expr_ops(e, ctx)).collect();
            quote! { #(#inner)* }
        }
        ExprIR::StructInit { fields, .. } => {
            let inner: Vec<TokenStream> = fields
                .iter()
                .map(|(_, e)| generate_expr_ops(e, ctx))
                .collect();
            quote! { #(#inner)* }
        }

        // An expression the IR couldn't lower (e.g. a Rust pattern Nocturne
        // doesn't model yet). Emit a `compile_error!` carrying the IR's
        // description so the user gets a real diagnostic instead of a
        // silently-zero side-effect.
        ExprIR::Unsupported { description, span } => {
            let msg = format!("nocturne: unsupported expression in circuit body: {description}");
            // `quote_spanned!` points the diagnostic at the offending
            // source expression instead of the macro invocation site.
            quote::quote_spanned! {*span=> compile_error!(#msg); }
        }

        // Pure value shapes: no transcript ops.
        ExprIR::Literal { .. } | ExprIR::Var { .. } | ExprIR::Path { .. } => quote! {},

        // Structural statements never reach the ops-only generator —
        // `generate_op_stmt` intercepts them so it can place each
        // region's private-event pushes correctly. Defensively emit
        // nothing (their sub-statements would be mis-placed here).
        ExprIR::If { .. } | ExprIR::Let { .. } | ExprIR::Block { .. } | ExprIR::Assert { .. } => {
            quote! {}
        }
    }
}

/// If `value` is a `self.<field>.<get|value|lookup>()` ledger read,
/// build the Rust expression that fetches the same value from the live
/// `state`. Returns `None` for other shapes.
fn let_binding_value_for_ledger_read(
    value: &ExprIR,
    ctx: &TranscriptCtx<'_>,
) -> Option<TokenStream> {
    let field_names = ctx.field_names;
    let ExprIR::LedgerAccess {
        field,
        method,
        args,
        ..
    } = value
    else {
        return None;
    };
    let field_pos = field_names.iter().position(|f| f == &field.to_string())?;
    let field_ty = ctx.field_types.get(field_pos);
    let f_ident = format_ident!("{}", field.to_string());
    match method.to_string().as_str() {
        "get" => Some(quote! { __nocturne_state.#f_ident.get() }),
        // `__direct_access` is the parser's marker for a bare
        // `self.<field>` read — its accessor depends on the field kind:
        // Cell exposes `.get()`, Counter exposes `.value()`. Routing
        // both through `.value()` broke Cell fields (no such method).
        "value" | "__direct_access" => {
            if field_ty.map(|t| extract_cell_inner_type(t).is_some()) == Some(true) {
                Some(quote! { __nocturne_state.#f_ident.get() })
            } else {
                Some(quote! { __nocturne_state.#f_ident.value() })
            }
        }
        // `let v = self.map.lookup(&k);` — the parser rewrites the
        // canonical `if let Some(v) = map.get(&k)` sugar to
        // contains + lookup, because the on-chain VM has no `Option<V>`
        // (`Popeq.as_cell` rejects `StateValue::Null`, so a missing-key
        // lookup aborts the proof instead of returning None). The bound
        // name must therefore carry the real value, not `()`.
        "lookup" => {
            let key = args.first().map(arg_to_runtime_raw_expr)?;
            Some(quote! { __nocturne_state.#f_ident.lookup(&#key) })
        }
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
            // A ledger-read scrutinee (`match self.opt_cell.get() { … }`)
            // binds through the state accessor; everything else through
            // the regular runtime-value recursion.
            let scrutinee_expr = let_binding_runtime_value(scrutinee, ctx)
                .or_else(|| let_binding_value_for_ledger_read(scrutinee, ctx))?;
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

/// The compile-time integer value of an argument expression, reaching
/// through the same transparent wrappers `arg_to_runtime_expr` forwards
/// (`disclose(...)`, `&x`, `.into()`, `.value()`). `None` when the
/// argument's value isn't an integer literal known at codegen time.
fn literal_int_value(expr: &ExprIR) -> Option<u128> {
    match expr {
        ExprIR::Literal {
            value: nocturne_ir::expr::LiteralIR::Int(n),
            ..
        } => Some(*n),
        ExprIR::Disclose { value, .. } => literal_int_value(value),
        ExprIR::Reference { expr: inner, .. } => literal_int_value(inner),
        ExprIR::MethodCall {
            receiver, method, ..
        } if is_transparent_wrapper(&method.to_string()) => literal_int_value(receiver),
        _ => None,
    }
}

/// Maximum value an integer-like target type can hold (`u8`..`u128`,
/// `Uint<N>`), `None` for non-integer types (`Field`, `Bytes<N>`,
/// booleans, user ADTs). References unwrap so a `&Uint<32>` map-key
/// position checks like `Uint<32>`. Uses the declared `Uint<N>` bit
/// width, NOT the primitive `primitive_cast_for_type` snaps to: the
/// circuit range-constrains the wire to N bits, so anything above
/// `2^N - 1` can never prove even when it fits the runtime primitive.
fn int_type_max(ty: &syn::Type) -> Option<u128> {
    let mut t = ty;
    while let syn::Type::Reference(r) = t {
        t = &r.elem;
    }
    let ty_str = quote!(#t).to_string().replace(' ', "");
    parse_uint_type(&ty_str).map(uint_max_value)
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
                s if is_transparent_wrapper(s) => arg_to_runtime_expr(receiver),
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
        // Anything else falls back to `()`. NOTE: this is NOT a
        // compile-time guard — upstream implements `Aligned for ()`
        // (base-crypto/src/fab/alignments.rs, `tuple_aligned!`) and
        // `From<()> for Value` (base-crypto/src/fab/conversions.rs,
        // `tuple_conversions!`), so `AlignedValue::from(())` compiles to
        // an EMPTY (zero-atom) value. Shapes that would desync the
        // transcript must be rejected explicitly before reaching here,
        // the way `private_event_pushes` rejects expression-position
        // `if`. `()` only fails to compile in positions that demand a
        // concrete primitive (arithmetic, `as` casts).
        _ => quote! { () },
    }
}

/// True when an argument expression's value is a compile-time literal
/// (possibly behind `disclose(...)`, `&x`, or a transparent wrapper).
/// Literal keys have no double-evaluation hazard and their raw runtime
/// form is a bare primitive (no `.value()` accessor), so they keep the
/// expression-based aligned path — which also carries the literal-range
/// compile check.
fn is_literal_arg(expr: &ExprIR) -> bool {
    match expr {
        ExprIR::Literal { .. } => true,
        ExprIR::Disclose { value, .. } => is_literal_arg(value),
        ExprIR::Reference { expr: inner, .. } => is_literal_arg(inner),
        ExprIR::MethodCall {
            receiver, method, ..
        } if is_transparent_wrapper(&method.to_string()) => is_literal_arg(receiver),
        _ => false,
    }
}

/// The aligned-value expression for a keyed-container key, derived from
/// the ALREADY-BOUND `__key` binding when possible so the key expression
/// runs exactly once (a `WitnessCall` key used to run twice: once for
/// the runtime `contains`/`lookup` call and once inside the op's
/// AlignedValue). Literal keys (and keys whose K type is unknown) keep
/// the expression-based path.
fn bound_key_aligned_expr(
    args: &[ExprIR],
    k_ty: Option<&syn::Type>,
    ctx: &TranscriptCtx<'_>,
) -> TokenStream {
    match (args.first(), k_ty) {
        (Some(a), Some(kt)) if !is_literal_arg(a) => accessor_aligned_value_expr(
            Some(kt),
            &quote! { __key.clone() },
            ctx.user_enums,
            ctx.user_structs,
        ),
        (Some(a), _) => aligned_value_arg_expr(a, k_ty, ctx),
        (None, _) => quote! { () },
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
    let key_aligned = bound_key_aligned_expr(args, k_ty.as_ref(), ctx);

    quote! {
        {
            let __key = #raw_key;
            __nocturne_ops.push(Op::Dup { n: 0 });
            __nocturne_ops.push(Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
            });
            __nocturne_ops.push(Op::Push {
                storage: false,
                value: StateValue::Cell(Sp::new(AlignedValue::from(#key_aligned))),
            });
            __nocturne_ops.push(Op::Member);
            let __result: bool = __nocturne_state.#field_ident.contains(&__key);
            __nocturne_ops.push(Op::Popeq {
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
        __nocturne_ops.push(Op::Push {
            storage: false,
            value: StateValue::Cell(Sp::new(AlignedValue::from(#field_idx))),
        });
        __nocturne_ops.push(Op::Push {
            storage: true,
            value: StateValue::Cell(Sp::new(AlignedValue::from(#value_aligned))),
        });
        __nocturne_ops.push(Op::Ins { cached: false, n: 1 });
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
    // Over-range literal: the circuit's LoadImm carries the full
    // literal while the runtime cast at the bottom of this function
    // would silently truncate (`(5000000000u64) as u32` for a
    // `Cell<Uint<32>>`), so the two sides disagree and prove fails —
    // or worse, the on-chain write holds a truncated value. Both the
    // literal and the target width are known here (this function is
    // the single chokepoint for Cell/Map/Set key & value positions),
    // so reject at compile time instead.
    if let Some(t) = ty
        && let Some(n) = literal_int_value(expr)
        && let Some(max) = int_type_max(t)
        && n > max
    {
        let ty_str = quote!(#t).to_string().replace(' ', "");
        let msg = format!("literal {n} exceeds {ty_str} range (max {max})");
        return quote! { { compile_error!(#msg); 0u8 } };
    }
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
                    tuple_component_aligned_repr(elem, &quote! { __t.#idx }, ctx)
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
                    tuple_component_aligned_repr(&elem_ty, &quote! { __a[#idx] }, ctx)
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
                    tuple_component_aligned_repr(&f.ty, &quote! { __t.#fname }, ctx)
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
                    let payload_repr = tuple_component_aligned_repr(&p, &quote! { __payload }, ctx);
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
/// accepts directly. Takes a token-tree accessor instead of an `ExprIR`
/// because tuple elements aren't first-class IR exprs — they're field
/// projections on a temporary binding.
///
/// Delegates to `crate::aligned::accessor_aligned_value_expr` (the one
/// recursion shared with the deploy codegen and the witness pushes) so
/// the per-type dispatch can't drift from the other accessor-shaped
/// sites. This also gives nested enum/struct/tuple components the full
/// recursion a previous hand-rolled copy here didn't have.
fn tuple_component_aligned_repr(
    ty: &syn::Type,
    accessor: &TokenStream,
    ctx: &TranscriptCtx<'_>,
) -> TokenStream {
    accessor_aligned_value_expr(Some(ty), accessor, ctx.user_enums, ctx.user_structs)
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
        __nocturne_ops.push(Op::Idx {
            cached: false,
            push_path: true,
            path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
        });
        __nocturne_ops.push(Op::Push {
            storage: false,
            value: StateValue::Cell(Sp::new(AlignedValue::from(#key_aligned))),
        });
        __nocturne_ops.push(Op::Push {
            storage: true,
            value: StateValue::Cell(Sp::new(AlignedValue::from(#val_aligned))),
        });
        __nocturne_ops.push(Op::Ins { cached: false, n: 1 });
        __nocturne_ops.push(Op::Ins { cached: true, n: 1 });
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
    // Derived from the bound `__key` so the key expression runs once.
    let key_aligned = bound_key_aligned_expr(args, k_ty.as_ref(), ctx);

    // Popeq result: V comes back from the runtime (a wrapper like Boolean
    // / Uint<N> / Bytes<N>). Unwrap to the form AlignedValue::from accepts.
    let val_expr = match kv.as_ref().map(|(_, v)| v) {
        Some(v_ty) => unwrap_to_aligned_primitive(
            quote! { __nocturne_state.#field_ident.lookup(&__key) },
            v_ty,
            ctx,
        ),
        None => quote! { __nocturne_state.#field_ident.lookup(&__key) },
    };

    quote! {
        {
            let __key = #raw_key;
            __nocturne_ops.push(Op::Dup { n: 0 });
            __nocturne_ops.push(Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
            });
            __nocturne_ops.push(Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(AlignedValue::from(#key_aligned))].into_iter().collect(),
            });
            __nocturne_ops.push(Op::Popeq {
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
        __nocturne_ops.push(Op::Idx {
            cached: false,
            push_path: true,
            path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
        });
        __nocturne_ops.push(Op::Push {
            storage: false,
            value: StateValue::Cell(Sp::new(AlignedValue::from(#key_aligned))),
        });
        __nocturne_ops.push(Op::Rem { cached: false });
        __nocturne_ops.push(Op::Ins { cached: true, n: 1 });
    }
}

/// Wrap `expr` to produce a value `AlignedValue::from(_)` can accept for
/// type `ty`. Handles wrapper types (`Boolean` → `.value()`, `Uint<N>` →
/// `.value() as u<N>`, `Field`/`MerkleTreeDigest` → full-Fr lift) and raw
/// primitives (identity cast). Composite types (tuples, user structs,
/// enums, Option) get a pointed `compile_error!` — their multi-Fr Popeq
/// lowering isn't wired through this path yet, and silently passing the
/// raw expression produced an unreadable `From` trait error at best.
fn unwrap_to_aligned_primitive(
    expr: TokenStream,
    ty: &syn::Type,
    ctx: &TranscriptCtx<'_>,
) -> TokenStream {
    let ty_str = quote!(#ty).to_string().replace(' ', "");
    if ty_str == "Boolean" {
        return quote! { (#expr).value() };
    }
    // Bytes<N>: `AlignedValue::from(_)` accepts `[u8; N]`, so unwrap the
    // wrapper to its byte array. Mirrors the Cell::set/get side.
    if ty_str.starts_with("Bytes<") {
        return quote! { *(#expr).as_bytes() };
    }
    // Field: lift to Fr via the value (mirrors the get-side read arm) so
    // `AlignedValue::from(Fr)` picks the Field alignment atom.
    if ty_str == "Field" {
        return quote! { Fr::from((#expr).value()) };
    }
    // MerkleTreeDigest: reconstruct the full 254-bit Fr from the 32-byte
    // LE representation — `.field().value()` would truncate to u128.
    if ty_str == "MerkleTreeDigest" {
        return quote! {
            Fr::from_le_bytes(&(#expr).as_le_bytes())
                .expect("MerkleTreeDigest bytes round-trip through Fr")
        };
    }
    if ty_str.starts_with("Uint<")
        && let Some(c) = primitive_cast_for_type(ty)
    {
        return quote! { (#expr).value() #c };
    }
    if let Some(c) = primitive_cast_for_type(ty) {
        return quote! { (#expr) #c };
    }
    if matches!(ty, syn::Type::Tuple(_))
        || user_struct_fields(ty, ctx.user_structs).is_some()
        || is_enum_like(ty, ctx.user_enums)
    {
        let msg = format!(
            "nocturne: `Map::lookup` with composite value type `{ty_str}` is not \
             supported yet — store the components in separate maps or use a \
             `Bytes<N>` encoding"
        );
        return quote! { { compile_error!(#msg); 0u8 } };
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

/// True if `ty` is `MerkleTreePath<H, T>` for some H, T. The witness push
/// deconstructs into the leaf's Fr stream followed by H × (sibling Fr +
/// goes_left Fr) — matching the IR's `witness_fr_layout` expansion.
fn is_merkle_tree_path(ty: &syn::Type) -> bool {
    let ty_str = quote!(#ty).to_string().replace(' ', "");
    ty_str.starts_with("MerkleTreePath<")
}

/// If `ty` is `MerkleTreePath<H, T>`, return the leaf type `T` (the
/// LAST type argument — the first generic is the const height `H`).
fn extract_merkle_tree_path_leaf_type(ty: &syn::Type) -> Option<syn::Type> {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
        && seg.ident == "MerkleTreePath"
        && let syn::PathArguments::AngleBracketed(args) = &seg.arguments
    {
        return args
            .args
            .iter()
            .filter_map(|a| {
                if let syn::GenericArgument::Type(t) = a {
                    Some(t.clone())
                } else {
                    None
                }
            })
            .next_back();
    }
    None
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
        __nocturne_ops.push(Op::Idx {
            cached: false,
            push_path: true,
            path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
        });
        __nocturne_ops.push(Op::Push {
            storage: false,
            value: StateValue::Cell(Sp::new(AlignedValue::from(#key_aligned))),
        });
        __nocturne_ops.push(Op::Push {
            storage: true,
            value: StateValue::Null,
        });
        __nocturne_ops.push(Op::Ins { cached: false, n: 1 });
        __nocturne_ops.push(Op::Ins { cached: true, n: 1 });
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
        __nocturne_ops.push(Op::Idx {
            cached: false,
            push_path: true,
            path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
        });
        __nocturne_ops.push(Op::Push {
            storage: false,
            value: StateValue::Cell(Sp::new(AlignedValue::from(#key_aligned))),
        });
        __nocturne_ops.push(Op::Rem { cached: false });
        __nocturne_ops.push(Op::Ins { cached: true, n: 1 });
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
            __nocturne_ops.push(Op::Dup { n: 0 });
            __nocturne_ops.push(Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
            });
            __nocturne_ops.push(Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(AlignedValue::from(0u8))].into_iter().collect(),
            });
            __nocturne_ops.push(Op::Root);
            __nocturne_ops.push(Op::Push {
                storage: false,
                value: StateValue::Cell(Sp::new(AlignedValue::from(__digest_fr))),
            });
            __nocturne_ops.push(Op::Eq);
            let __result: bool = __nocturne_state.#field_ident.check_root(&__digest);
            __nocturne_ops.push(Op::Popeq {
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
            __nocturne_ops.push(Op::Idx {
                cached: false,
                push_path: true,
                path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
            });
            __nocturne_ops.push(Op::Idx {
                cached: false,
                push_path: true,
                path: vec![Key::Value(AlignedValue::from(0u8))].into_iter().collect(),
            });
            __nocturne_ops.push(Op::Dup { n: 2 });
            __nocturne_ops.push(Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(AlignedValue::from(1u8))].into_iter().collect(),
            });
            __nocturne_ops.push(Op::Push {
                storage: true,
                value: StateValue::Cell(Sp::new(AlignedValue::from(__leaf_hash))),
            });
            __nocturne_ops.push(Op::Ins { cached: false, n: 1 });
            __nocturne_ops.push(Op::Ins { cached: true, n: 1 });
            __nocturne_ops.push(Op::Idx {
                cached: false,
                push_path: true,
                path: vec![Key::Value(AlignedValue::from(1u8))].into_iter().collect(),
            });
            __nocturne_ops.push(Op::Addi { immediate: 1 });
            __nocturne_ops.push(Op::Ins { cached: true, n: 2 });
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
                s if is_transparent_wrapper(s) => arg_to_runtime_raw_expr(receiver),
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
            if matches!(method_name.as_str(), "contains" | "member") {
                return generate_map_contains_block(field_idx, &field_name, args, field_ty, ctx);
            }
            // `Cell<Boolean>` / `Cell<bool>` reads ARE bool-typed and
            // usable as conditions: bake the live state's value into a
            // Dup+Idx+Popeq block (the same ops the statement-position
            // read emits) and evaluate to the bool — mirroring
            // `generate_map_contains_block`'s shape.
            if matches!(method_name.as_str(), "get" | "value" | "__direct_access") {
                let inner = field_ty.and_then(extract_cell_inner_type);
                let inner_str = inner
                    .as_ref()
                    .map(|t| quote!(#t).to_string().replace(' ', ""));
                if let Some(s) = inner_str.as_deref()
                    && matches!(s, "Boolean" | "bool")
                {
                    let field_ident = format_ident!("{}", field_name);
                    let result_expr = if s == "Boolean" {
                        quote! { __nocturne_state.#field_ident.get().value() }
                    } else {
                        quote! { __nocturne_state.#field_ident.get() }
                    };
                    return quote! {
                        {
                            __nocturne_ops.push(Op::Dup { n: 0 });
                            __nocturne_ops.push(Op::Idx {
                                cached: false,
                                push_path: false,
                                path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
                            });
                            let __result: bool = #result_expr;
                            __nocturne_ops.push(Op::Popeq {
                                cached: true,
                                result: AlignedValue::from(__result),
                            });
                            __result
                        }
                    };
                }
            }
            // Other LedgerAccess methods aren't bool-typed (lookup returns V,
            // get/value return non-bool T, increment returns nothing). The IR
            // parser doesn't actually reject these, so a user writing
            // `if self.cell.get() { ... }` on a non-bool cell would silently
            // take the always-true branch. Surface it as a real diagnostic.
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
                s if is_transparent_wrapper(s) => generate_runtime_cond(receiver, ctx),
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
