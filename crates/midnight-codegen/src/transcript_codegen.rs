//! Transcript codegen: generates Rust code that builds transcript `Op` programs
//! at runtime. This replaces Compact's TypeScript runtime.
//!
//! The generated code:
//! - Accepts typed witness structs (not `dyn Any`)
//! - Evaluates conditions at runtime to select active branches
//! - Only emits ops for the active branch (matching ZKIR's pi_skip behavior)
//! - Converts witness values to `Fr` for the private transcript

use midnight_ir::{CircuitIR, ContractIR, ExprIR};
use proc_macro2::TokenStream;
use quote::{quote, format_ident};

/// Generate the transcript builder module for a contract.
pub fn generate_transcript_module(contract: &ContractIR) -> TokenStream {
    let field_names: Vec<String> = contract
        .ledger
        .fields
        .iter()
        .map(|f| f.name.to_string())
        .collect();

    let witnesses_name = contract
        .witnesses
        .as_ref()
        .map(|w| &w.name);

    let circuit_fns: Vec<TokenStream> = contract
        .circuits
        .iter()
        .map(|circuit| generate_circuit_transcript_fn(circuit, &field_names, witnesses_name))
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
fn generate_circuit_transcript_fn(
    circuit: &CircuitIR,
    field_names: &[String],
    witnesses_name: Option<&syn::Ident>,
) -> TokenStream {
    let fn_name = format_ident!("build_{}_transcript", circuit.name);
    let doc = format!("Build the transcript for the `{}` circuit.", circuit.name);

    let body_stmts: Vec<TokenStream> = circuit
        .body
        .iter()
        .map(|expr| generate_op_stmt(expr, field_names))
        .collect();

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
            pub fn #fn_name(#param_name: #witnesses_ty) -> TranscriptResult {
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

/// Generate Rust statements that push VM Ops.
fn generate_op_stmt(expr: &ExprIR, field_names: &[String]) -> TokenStream {
    match expr {
        ExprIR::LedgerAccess { field, method, args, .. } => {
            let field_name = field.to_string();
            let method_name = method.to_string();
            let field_idx = field_names
                .iter()
                .position(|f| f == &field_name)
                .unwrap_or(0) as u8;

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
                "get" | "value" | "__direct_access" => quote! {
                    ops.push(Op::Dup { n: 0 });
                    ops.push(Op::Idx {
                        cached: false,
                        push_path: false,
                        path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
                    });
                    ops.push(Op::Popeq {
                        cached: true,
                        result: AlignedValue::from(0u8),
                    });
                },
                "set" => {
                    let inner: Vec<TokenStream> = args
                        .iter()
                        .map(|a| generate_op_stmt(a, field_names))
                        .collect();
                    quote! {
                        ops.push(Op::Idx {
                            cached: false,
                            push_path: true,
                            path: vec![Key::Value(AlignedValue::from(#field_idx))].into_iter().collect(),
                        });
                        #(#inner)*
                        ops.push(Op::Ins { cached: true, n: 1 });
                    }
                }
                _ => quote! {},
            }
        }

        ExprIR::If { cond, then_branch, else_branch, .. } => {
            // Collect witness values used in the condition for private_transcript.
            let witness_adds = collect_witness_private_inputs(cond);
            let cond_expr = generate_runtime_cond(cond);
            let then_stmts: Vec<TokenStream> = then_branch
                .iter()
                .map(|e| generate_op_stmt(e, field_names))
                .collect();

            if let Some(else_exprs) = else_branch {
                let else_stmts: Vec<TokenStream> = else_exprs
                    .iter()
                    .map(|e| generate_op_stmt(e, field_names))
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
            let var_name = format_ident!("_let_{}", name);
            let val_stmt = generate_op_stmt(value, field_names);
            quote! {
                let #var_name = {
                    #val_stmt
                };
            }
        }

        ExprIR::WitnessAccess { field, .. } => {
            let field_ident = format_ident!("{}", field.to_string());
            // Read the witness value and add to private transcript as Fr.
            quote! {
                private_transcript.push(Fr::from(witnesses.#field_ident.value() as u64));
            }
        }

        ExprIR::Block { stmts, .. } => {
            let inner: Vec<TokenStream> = stmts
                .iter()
                .map(|s| generate_op_stmt(s, field_names))
                .collect();
            quote! { #(#inner)* }
        }

        ExprIR::MethodCall { receiver, method, .. } => {
            let method_name = method.to_string();
            match method_name.as_str() {
                "into" | "value" => generate_op_stmt(receiver, field_names),
                _ => quote! {},
            }
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

/// Generate a runtime Rust expression for a condition.
fn generate_runtime_cond(expr: &ExprIR) -> TokenStream {
    match expr {
        ExprIR::WitnessAccess { field, .. } => {
            let field_ident = format_ident!("{}", field.to_string());
            quote! { witnesses.#field_ident.value() }
        }
        ExprIR::MethodCall { receiver, method, .. } => {
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
        ExprIR::Literal { value, .. } => {
            match value {
                midnight_ir::expr::LiteralIR::Bool(b) => quote! { #b },
                midnight_ir::expr::LiteralIR::Int(n) => {
                    let n = *n as u64;
                    quote! { #n != 0 }
                }
                _ => quote! { true },
            }
        }
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
