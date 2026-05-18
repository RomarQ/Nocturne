use proc_macro2::Span;
use syn::{
    Expr, ExprCall, ExprField, ExprMethodCall, ExprPath, FnArg, ImplItem, ImplItemFn, Item,
    ItemImpl, ItemMod, ItemStruct, Pat, ReturnType, Stmt,
    parse::Parser,
};

use crate::attrs::{MidnightAttr, find_midnight_attr};
use crate::contract::*;
use crate::error::*;
use crate::expr::*;

/// Parse a `#[midnight::contract]` module into a `ContractIR`.
pub fn parse_contract(module: ItemMod) -> MidnightResult<ContractIR> {
    let name = module.ident.clone();
    let span = Span::call_site();

    let items = module
        .content
        .map(|(_, items)| items)
        .unwrap_or_default();

    let mut ledger: Option<LedgerIR> = None;
    let mut witnesses: Option<WitnessIR> = None;
    let mut constructors: Vec<ConstructorIR> = Vec::new();
    let mut circuits: Vec<CircuitIR> = Vec::new();
    let mut queries: Vec<QueryIR> = Vec::new();
    let mut other_items: Vec<Item> = Vec::new();
    let mut diagnostics = Diagnostics::new();

    for item in items {
        match &item {
            Item::Struct(s) => {
                match find_midnight_attr(&s.attrs) {
                    Some((MidnightAttr::Ledger, _attr_span)) => {
                        if ledger.is_some() {
                            diagnostics.push(MidnightError::new(
                                s.ident.span(),
                                ErrorCode::DuplicateLedger,
                                "only one #[midnight(ledger)] struct is allowed per contract",
                            ));
                        } else {
                            ledger = Some(parse_ledger_struct(s)?);
                        }
                    }
                    Some((MidnightAttr::Witnesses, _attr_span)) => {
                        if witnesses.is_some() {
                            diagnostics.push(MidnightError::new(
                                s.ident.span(),
                                ErrorCode::DuplicateWitnesses,
                                "only one #[midnight(witnesses)] struct is allowed per contract",
                            ));
                        } else {
                            witnesses = Some(parse_witnesses_struct(s)?);
                        }
                    }
                    _ => {
                        other_items.push(item);
                    }
                }
            }
            Item::Impl(impl_block) => {
                parse_impl_block(
                    impl_block,
                    &mut constructors,
                    &mut circuits,
                    &mut queries,
                    &mut other_items,
                    &mut diagnostics,
                )?;
            }
            _ => {
                other_items.push(item);
            }
        }
    }

    // Validation
    let ledger = match ledger {
        Some(l) => l,
        None => {
            return Err(MidnightError::new(
                span,
                ErrorCode::MissingLedger,
                "contract must contain exactly one #[midnight(ledger)] struct",
            ));
        }
    };

    if constructors.is_empty() && circuits.is_empty() {
        diagnostics.push(MidnightError::new(
            span,
            ErrorCode::MissingCircuit,
            "contract must contain at least one #[midnight(circuit)] or #[midnight(constructor)] function",
        ));
    }

    if diagnostics.has_errors() {
        // Return the first specific error for better diagnostics.
        return Err(diagnostics.into_first_error());
    }

    Ok(ContractIR {
        name,
        span,
        ledger,
        witnesses,
        constructors,
        circuits,
        queries,
        other_items,
    })
}

fn parse_ledger_struct(s: &ItemStruct) -> MidnightResult<LedgerIR> {
    let mut fields = Vec::new();

    let named_fields = match &s.fields {
        syn::Fields::Named(named) => &named.named,
        _ => {
            return Err(MidnightError::new(
                s.ident.span(),
                ErrorCode::InvalidType,
                "ledger struct must have named fields",
            ));
        }
    };

    for field in named_fields {
        let field_name = field.ident.clone().unwrap();
        let type_kind = extract_type_kind(&field.ty);

        fields.push(LedgerFieldIR {
            span: field_name.span(),
            name: field_name,
            ty: field.ty.clone(),
            type_kind,
        });
    }

    Ok(LedgerIR {
        span: s.ident.span(),
        name: s.ident.clone(),
        fields,
    })
}

fn parse_witnesses_struct(s: &ItemStruct) -> MidnightResult<WitnessIR> {
    let mut fields = Vec::new();

    let named_fields = match &s.fields {
        syn::Fields::Named(named) => &named.named,
        _ => {
            return Err(MidnightError::new(
                s.ident.span(),
                ErrorCode::InvalidType,
                "witnesses struct must have named fields",
            ));
        }
    };

    for field in named_fields {
        let field_name = field.ident.clone().unwrap();

        // Reject witness types we don't yet support. The transcript builder
        // currently emits one `Fr` per witness via `Fr::from(field.value())`,
        // which requires the value to fit in a single field element. Multi-Fr
        // witnesses (e.g. `Bytes<N>`) need additional codegen — see
        // `memories/conditional-branch-cond-select-zeroing.md` for the
        // surrounding architecture and the open follow-up.
        let ty_str = quote::quote!(#field.ty).to_string().replace(' ', "");
        if ty_str.contains("Bytes<") {
            return Err(MidnightError::new(
                field_name.span(),
                ErrorCode::InvalidType,
                "Bytes<N> as a witness type is not yet supported; the transcript builder emits one Fr per witness via Fr::from(value()), which Bytes<N> doesn't satisfy. Use Boolean, Field, or Uint<N> for now.",
            ));
        }

        fields.push(WitnessFieldIR {
            span: field_name.span(),
            name: field_name,
            ty: field.ty.clone(),
        });
    }

    Ok(WitnessIR {
        span: s.ident.span(),
        name: s.ident.clone(),
        fields,
    })
}

/// Extract the outer type name from a syn::Type to classify ledger field types.
fn extract_type_kind(ty: &syn::Type) -> LedgerTypeKind {
    match ty {
        syn::Type::Path(type_path) => {
            if let Some(segment) = type_path.path.segments.last() {
                LedgerTypeKind::from_type_name(&segment.ident.to_string())
            } else {
                LedgerTypeKind::Unknown("empty path".to_string())
            }
        }
        _ => LedgerTypeKind::Unknown(quote::quote!(#ty).to_string()),
    }
}

fn parse_impl_block(
    impl_block: &ItemImpl,
    constructors: &mut Vec<ConstructorIR>,
    circuits: &mut Vec<CircuitIR>,
    queries: &mut Vec<QueryIR>,
    other_items: &mut Vec<Item>,
    diagnostics: &mut Diagnostics,
) -> MidnightResult<()> {
    let mut has_midnight_methods = false;

    for item in &impl_block.items {
        if let ImplItem::Fn(method) = item {
            match find_midnight_attr(&method.attrs) {
                Some((MidnightAttr::Constructor, _)) => {
                    has_midnight_methods = true;
                    match parse_constructor(method) {
                        Ok(c) => constructors.push(c),
                        Err(e) => diagnostics.push(e),
                    }
                }
                Some((MidnightAttr::Circuit, _)) => {
                    has_midnight_methods = true;
                    match parse_circuit(method) {
                        Ok(c) => circuits.push(c),
                        Err(e) => diagnostics.push(e),
                    }
                }
                Some((MidnightAttr::Query, _)) => {
                    has_midnight_methods = true;
                    match parse_query(method) {
                        Ok(q) => queries.push(q),
                        Err(e) => diagnostics.push(e),
                    }
                }
                _ => {}
            }
        }
    }

    if !has_midnight_methods {
        other_items.push(Item::Impl(impl_block.clone()));
    }

    Ok(())
}

fn parse_constructor(method: &ImplItemFn) -> MidnightResult<ConstructorIR> {
    let name = method.sig.ident.clone();
    let params = parse_fn_params(&method.sig)?;
    let body = parse_block_stmts(&method.block)?;

    Ok(ConstructorIR {
        span: name.span(),
        name,
        params,
        body,
    })
}

fn parse_circuit(method: &ImplItemFn) -> MidnightResult<CircuitIR> {
    let name = method.sig.ident.clone();
    let (mutates_ledger, takes_witnesses, witnesses_param_name, params) =
        parse_circuit_params(&method.sig)?;
    let body = parse_block_stmts(&method.block)?;
    let return_type = match &method.sig.output {
        ReturnType::Default => None,
        ReturnType::Type(_, ty) => Some(*ty.clone()),
    };

    Ok(CircuitIR {
        span: name.span(),
        name,
        params,
        takes_witnesses,
        witnesses_param_name,
        mutates_ledger,
        body,
        return_type,
    })
}

fn parse_query(method: &ImplItemFn) -> MidnightResult<QueryIR> {
    let name = method.sig.ident.clone();

    // Validate: query must take &self, not &mut self.
    if let Some(FnArg::Receiver(recv)) = method.sig.inputs.first() {
        if recv.mutability.is_some() {
            return Err(MidnightError::new(
                name.span(),
                ErrorCode::QueryMustBeImmutable,
                "query functions must take &self, not &mut self",
            ));
        }
    }

    let params = parse_fn_params(&method.sig)?;
    let body = parse_block_stmts(&method.block)?;
    let return_type = match &method.sig.output {
        ReturnType::Default => None,
        ReturnType::Type(_, ty) => Some(*ty.clone()),
    };

    Ok(QueryIR {
        span: name.span(),
        name,
        params,
        return_type,
        body,
    })
}

/// Parse function parameters, skipping `self` and witness params.
fn parse_fn_params(sig: &syn::Signature) -> MidnightResult<Vec<ParamIR>> {
    let mut params = Vec::new();
    for arg in &sig.inputs {
        if let FnArg::Typed(pat_type) = arg {
            if let Pat::Ident(pat_ident) = &*pat_type.pat {
                let name = &pat_ident.ident;
                // Skip witness parameters (detected by type containing "Witnesses").
                let ty_str = quote::quote!(#pat_type.ty).to_string();
                if ty_str.contains("Witnesses") {
                    continue;
                }
                params.push(ParamIR {
                    span: name.span(),
                    name: name.clone(),
                    ty: *pat_type.ty.clone(),
                });
            }
        }
    }
    Ok(params)
}

/// Parse circuit parameters, extracting self receiver info and witness detection.
fn parse_circuit_params(
    sig: &syn::Signature,
) -> MidnightResult<(bool, bool, Option<syn::Ident>, Vec<ParamIR>)> {
    let mut mutates_ledger = false;
    let mut takes_witnesses = false;
    let mut witnesses_param_name = None;
    let mut params = Vec::new();

    for arg in &sig.inputs {
        match arg {
            FnArg::Receiver(recv) => {
                mutates_ledger = recv.mutability.is_some();
            }
            FnArg::Typed(pat_type) => {
                if let Pat::Ident(pat_ident) = &*pat_type.pat {
                    let name = &pat_ident.ident;
                    let name_str = name.to_string();
                    let ty_str = quote::quote!(#pat_type.ty).to_string();

                    // Detect witness parameter by:
                    // 1. Parameter name is "witnesses" or ends with "_witnesses"
                    // 2. Type name contains "Witnesses" or "W" (the witnesses struct)
                    let is_witness_param = name_str == "witnesses"
                        || name_str.ends_with("_witnesses")
                        || ty_str.contains("Witnesses");

                    if is_witness_param {
                        takes_witnesses = true;
                        witnesses_param_name = Some(name.clone());
                        continue;
                    }
                    params.push(ParamIR {
                        span: name.span(),
                        name: name.clone(),
                        ty: *pat_type.ty.clone(),
                    });
                }
            }
        }
    }

    Ok((mutates_ledger, takes_witnesses, witnesses_param_name, params))
}

// ---------------------------------------------------------------------------
// Expression tree parsing (syn::Expr -> ExprIR)
// ---------------------------------------------------------------------------

fn parse_block_stmts(block: &syn::Block) -> MidnightResult<Vec<ExprIR>> {
    let mut exprs = Vec::new();
    for stmt in &block.stmts {
        exprs.push(parse_stmt(stmt)?);
    }
    Ok(exprs)
}

fn parse_stmt(stmt: &Stmt) -> MidnightResult<ExprIR> {
    match stmt {
        Stmt::Local(local) => {
            let name = match &local.pat {
                Pat::Ident(pat_ident) => pat_ident.ident.clone(),
                Pat::Type(pat_type) => {
                    if let Pat::Ident(pat_ident) = &*pat_type.pat {
                        pat_ident.ident.clone()
                    } else {
                        return Ok(ExprIR::Unsupported {
                            span: Span::call_site(),
                            description: "complex pattern in let binding".to_string(),
                        });
                    }
                }
                _ => {
                    return Ok(ExprIR::Unsupported {
                        span: Span::call_site(),
                        description: "complex pattern in let binding".to_string(),
                    });
                }
            };

            let value = if let Some(init) = &local.init {
                parse_expr(&init.expr)?
            } else {
                ExprIR::Unsupported {
                    span: name.span(),
                    description: "let binding without initializer".to_string(),
                }
            };

            Ok(ExprIR::Let {
                span: name.span(),
                name,
                value: Box::new(value),
            })
        }
        Stmt::Expr(expr, _semi) => parse_expr(expr),
        Stmt::Item(_) => Ok(ExprIR::Unsupported {
            span: Span::call_site(),
            description: "item inside function body".to_string(),
        }),
        Stmt::Macro(macro_stmt) => parse_macro_expr(&macro_stmt.mac),
    }
}

fn parse_expr(expr: &Expr) -> MidnightResult<ExprIR> {
    match expr {
        Expr::Lit(lit) => {
            if let Some(value) = LiteralIR::from_lit(&lit.lit) {
                Ok(ExprIR::Literal {
                    span: Span::call_site(),
                    value,
                })
            } else {
                Ok(ExprIR::Unsupported {
                    span: Span::call_site(),
                    description: "unsupported literal type".to_string(),
                })
            }
        }

        Expr::Path(ExprPath { path, .. }) => {
            if let Some(ident) = path.get_ident() {
                Ok(ExprIR::Var {
                    span: ident.span(),
                    name: ident.clone(),
                })
            } else {
                // Could be a qualified path like Self or midnight::disclose.
                let full_path = quote::quote!(#path).to_string();
                Ok(ExprIR::Var {
                    span: Span::call_site(),
                    name: syn::Ident::new(
                        &full_path.replace(' ', ""),
                        Span::call_site(),
                    ),
                })
            }
        }

        Expr::Binary(bin) => {
            let lhs = parse_expr(&bin.left)?;
            let rhs = parse_expr(&bin.right)?;
            Ok(ExprIR::BinaryOp {
                span: Span::call_site(),
                op: bin.op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            })
        }

        Expr::Unary(un) => {
            let inner = parse_expr(&un.expr)?;
            Ok(ExprIR::UnaryOp {
                span: Span::call_site(),
                op: un.op,
                expr: Box::new(inner),
            })
        }

        Expr::MethodCall(ExprMethodCall {
            receiver,
            method,
            args,
            ..
        }) => {
            let parsed_args: Vec<ExprIR> = args
                .iter()
                .map(parse_expr)
                .collect::<MidnightResult<_>>()?;

            // Detect `self.field.method(args)` pattern for ledger access.
            if let Expr::Field(ExprField { base, member, .. }) = &**receiver {
                if is_self_expr(base) {
                    if let syn::Member::Named(field_name) = member {
                        return Ok(ExprIR::LedgerAccess {
                            span: method.span(),
                            field: field_name.clone(),
                            method: method.clone(),
                            args: parsed_args,
                        });
                    }
                }
            }

            let parsed_receiver = parse_expr(receiver)?;
            Ok(ExprIR::MethodCall {
                span: method.span(),
                receiver: Box::new(parsed_receiver),
                method: method.clone(),
                args: parsed_args,
            })
        }

        Expr::Field(ExprField { base, member, .. }) => {
            // Detect `witnesses.field` pattern.
            if let Expr::Path(ExprPath { path, .. }) = &**base {
                if let Some(ident) = path.get_ident() {
                    let name = ident.to_string();
                    if name == "witnesses" || name.ends_with("witnesses") {
                        if let syn::Member::Named(field_name) = member {
                            return Ok(ExprIR::WitnessAccess {
                                span: field_name.span(),
                                field: field_name.clone(),
                            });
                        }
                    }
                }
            }

            // Detect `self.field` (ledger read without method call).
            if is_self_expr(base) {
                if let syn::Member::Named(field_name) = member {
                    return Ok(ExprIR::LedgerAccess {
                        span: field_name.span(),
                        field: field_name.clone(),
                        method: syn::Ident::new("__direct_access", Span::call_site()),
                        args: vec![],
                    });
                }
            }

            // Generic field access.
            let parsed_base = parse_expr(base)?;
            let field_ident = match member {
                syn::Member::Named(n) => n.clone(),
                syn::Member::Unnamed(idx) => {
                    syn::Ident::new(&format!("_{}", idx.index), idx.span)
                }
            };
            Ok(ExprIR::MethodCall {
                span: field_ident.span(),
                receiver: Box::new(parsed_base),
                method: field_ident,
                args: vec![],
            })
        }

        Expr::Call(ExprCall { func, args, .. }) => {
            let parsed_args: Vec<ExprIR> = args
                .iter()
                .map(parse_expr)
                .collect::<MidnightResult<_>>()?;

            // Extract function name.
            if let Expr::Path(ExprPath { path, .. }) = &**func {
                let func_name = path
                    .segments
                    .last()
                    .map(|s| s.ident.clone())
                    .unwrap_or_else(|| syn::Ident::new("unknown", Span::call_site()));

                // Detect special functions.
                let full_path = quote::quote!(#path).to_string().replace(' ', "");
                if full_path.contains("disclose") {
                    if let Some(arg) = parsed_args.into_iter().next() {
                        return Ok(ExprIR::Disclose {
                            span: func_name.span(),
                            value: Box::new(arg),
                        });
                    }
                    return Ok(ExprIR::Unsupported {
                        span: func_name.span(),
                        description: "disclose() requires an argument".to_string(),
                    });
                }

                return Ok(ExprIR::FnCall {
                    span: func_name.span(),
                    name: func_name,
                    args: parsed_args,
                });
            }

            Ok(ExprIR::Unsupported {
                span: Span::call_site(),
                description: "complex function call expression".to_string(),
            })
        }

        Expr::If(expr_if) => {
            let cond = parse_expr(&expr_if.cond)?;
            let then_branch = parse_block_stmts(&expr_if.then_branch)?;
            let else_branch = if let Some((_, else_expr)) = &expr_if.else_branch {
                match &**else_expr {
                    Expr::Block(block) => Some(parse_block_stmts(&block.block)?),
                    other => Some(vec![parse_expr(other)?]),
                }
            } else {
                None
            };

            Ok(ExprIR::If {
                span: Span::call_site(),
                cond: Box::new(cond),
                then_branch,
                else_branch,
            })
        }

        Expr::Block(block) => {
            let stmts = parse_block_stmts(&block.block)?;
            Ok(ExprIR::Block {
                span: Span::call_site(),
                stmts,
            })
        }

        Expr::Struct(s) => {
            let name = s
                .path
                .segments
                .last()
                .map(|seg| seg.ident.clone())
                .unwrap_or_else(|| syn::Ident::new("Unknown", Span::call_site()));

            let fields = s
                .fields
                .iter()
                .map(|f| {
                    let field_name = match &f.member {
                        syn::Member::Named(n) => n.clone(),
                        syn::Member::Unnamed(idx) => {
                            syn::Ident::new(&format!("_{}", idx.index), idx.span)
                        }
                    };
                    let value = parse_expr(&f.expr)?;
                    Ok((field_name, value))
                })
                .collect::<MidnightResult<Vec<_>>>()?;

            Ok(ExprIR::StructInit {
                span: Span::call_site(),
                name,
                fields,
            })
        }

        Expr::Return(ret) => {
            let value = if let Some(expr) = &ret.expr {
                Some(Box::new(parse_expr(expr)?))
            } else {
                None
            };
            Ok(ExprIR::Return {
                span: Span::call_site(),
                value,
            })
        }

        Expr::Tuple(tuple) => {
            let elements = tuple
                .elems
                .iter()
                .map(parse_expr)
                .collect::<MidnightResult<_>>()?;
            Ok(ExprIR::Tuple {
                span: Span::call_site(),
                elements,
            })
        }

        Expr::Reference(r) => {
            let inner = parse_expr(&r.expr)?;
            Ok(ExprIR::Reference {
                span: Span::call_site(),
                expr: Box::new(inner),
            })
        }

        Expr::Paren(p) => parse_expr(&p.expr),

        Expr::Macro(m) => parse_macro_expr(&m.mac),

        Expr::While(_) | Expr::Loop(_) => Ok(ExprIR::Unsupported {
            span: Span::call_site(),
            description: "while/loop not supported in circuits (use for with const bounds)"
                .to_string(),
        }),

        Expr::ForLoop(_) => {
            Ok(ExprIR::Unsupported {
                span: Span::call_site(),
                description: "for loops not yet supported (will support const-bounded in Phase 6)"
                    .to_string(),
            })
        }

        _ => Ok(ExprIR::Unsupported {
            span: Span::call_site(),
            description: format!("unsupported expression: {}", quote::quote!(#expr)),
        }),
    }
}

fn parse_macro_expr(mac: &syn::Macro) -> MidnightResult<ExprIR> {
    let path = &mac.path;
    let path_str = quote::quote!(#path).to_string().replace(' ', "");
    let tokens = &mac.tokens;

    if path_str == "assert" || path_str.ends_with("::assert") {
        // Parse assert!(cond).
        let cond: Expr = syn::parse2(tokens.clone()).map_err(|e| {
            MidnightError::new(
                Span::call_site(),
                ErrorCode::UnsupportedExpression,
                format!("failed to parse assert condition: {e}"),
            )
        })?;
        Ok(ExprIR::Assert {
            span: Span::call_site(),
            kind: AssertKind::Assert(Box::new(parse_expr(&cond)?)),
        })
    } else if path_str == "assert_eq" || path_str.ends_with("::assert_eq") {
        // Parse assert_eq!(a, b).
        let args: syn::punctuated::Punctuated<Expr, syn::Token![,]> =
            syn::punctuated::Punctuated::parse_terminated
                .parse2(tokens.clone())
                .map_err(|e| {
                    MidnightError::new(
                        Span::call_site(),
                        ErrorCode::UnsupportedExpression,
                        format!("failed to parse assert_eq arguments: {e}"),
                    )
                })?;

        let mut iter = args.into_iter();
        let a = iter.next().ok_or_else(|| {
            MidnightError::new(
                Span::call_site(),
                ErrorCode::UnsupportedExpression,
                "assert_eq! requires two arguments",
            )
        })?;
        let b = iter.next().ok_or_else(|| {
            MidnightError::new(
                Span::call_site(),
                ErrorCode::UnsupportedExpression,
                "assert_eq! requires two arguments",
            )
        })?;

        Ok(ExprIR::Assert {
            span: Span::call_site(),
            kind: AssertKind::AssertEq(Box::new(parse_expr(&a)?), Box::new(parse_expr(&b)?)),
        })
    } else {
        Ok(ExprIR::Unsupported {
            span: Span::call_site(),
            description: format!("unsupported macro: {path_str}"),
        })
    }
}

/// Check if an expression is `self`.
fn is_self_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Path(ExprPath { path, .. }) if path.is_ident("self"))
}
