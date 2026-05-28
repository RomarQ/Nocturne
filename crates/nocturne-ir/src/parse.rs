use proc_macro2::Span;
use syn::{
    Expr, ExprCall, ExprField, ExprMethodCall, ExprPath, FnArg, ImplItem, ImplItemFn, Item,
    ItemImpl, ItemMod, ItemStruct, Pat, ReturnType, Stmt, parse::Parser,
};

use crate::attrs::{MidnightAttr, find_midnight_attr};
use crate::contract::*;
use crate::error::*;
use crate::expr::*;

/// Parse a `#[nocturne::contract]` module into a `ContractIR`.
pub fn parse_contract(module: ItemMod) -> MidnightResult<ContractIR> {
    let name = module.ident.clone();
    let span = Span::call_site();

    let items = module.content.map(|(_, items)| items).unwrap_or_default();

    let mut ledger: Option<LedgerIR> = None;
    let mut witnesses: Option<WitnessIR> = None;
    let mut constructors: Vec<ConstructorIR> = Vec::new();
    let mut circuits: Vec<CircuitIR> = Vec::new();
    let mut queries: Vec<QueryIR> = Vec::new();
    let mut other_items: Vec<Item> = Vec::new();
    let mut user_structs: std::collections::HashMap<String, Vec<UserStructField>> =
        std::collections::HashMap::new();
    let mut user_enums: std::collections::HashMap<String, Vec<UserEnumVariant>> =
        std::collections::HashMap::new();
    let mut diagnostics = Diagnostics::new();

    for item in items {
        match &item {
            Item::Struct(s) => match find_midnight_attr(&s.attrs) {
                Some((MidnightAttr::Ledger, _attr_span)) => {
                    if ledger.is_some() {
                        diagnostics.push(MidnightError::new(
                            s.ident.span(),
                            ErrorCode::DuplicateLedger,
                            "only one #[nocturne(ledger)] struct is allowed per contract",
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
                            "only one #[nocturne(witnesses)] struct is allowed per contract",
                        ));
                    } else {
                        witnesses = Some(parse_witnesses_struct(s)?);
                    }
                }
                _ => {
                    // Plain user struct — record its named fields if any
                    // so codegen can treat it as a Map/Set key. Tuple
                    // structs and unit structs are left as opaque.
                    if let syn::Fields::Named(named) = &s.fields {
                        let fields: Vec<UserStructField> = named
                            .named
                            .iter()
                            .filter_map(|f| {
                                Some(UserStructField {
                                    name: f.ident.clone()?,
                                    ty: f.ty.clone(),
                                })
                            })
                            .collect();
                        user_structs.insert(s.ident.to_string(), fields);
                    }
                    other_items.push(item);
                }
            },
            Item::Impl(impl_block) => {
                parse_impl_block(
                    impl_block,
                    &mut constructors,
                    &mut circuits,
                    &mut queries,
                    witnesses.as_mut(),
                    &mut other_items,
                    &mut diagnostics,
                )?;
            }
            Item::Enum(e) => {
                // Only unit-variant enums are supported for now —
                // anything carrying a payload would need ADT
                // encoding work and bumps from Bytes<1> discriminant.
                // Two shapes are accepted:
                //   - All unit variants (encoded as `Bytes<1>` discriminant).
                //   - Homogeneous single-payload variants (encoded as a
                //     `(Bytes<1>, T)` tuple where every variant carries
                //     the same `T`).
                // Anything else surfaces as a parse error at the offending
                // variant — heterogeneous payloads, named-field variants,
                // and multi-field tuple variants all need a separate
                // encoding ADR. See memories/scope-blockers.md.
                let mut variants: Vec<UserEnumVariant> = Vec::new();
                let mut payload_ty: Option<syn::Type> = None;
                let mut rejected: Option<(syn::Ident, String)> = None;
                for v in &e.variants {
                    let this_payload = match &v.fields {
                        syn::Fields::Unit => None,
                        syn::Fields::Unnamed(u) if u.unnamed.len() == 1 => {
                            Some(u.unnamed.first().unwrap().ty.clone())
                        }
                        syn::Fields::Unnamed(_) => {
                            rejected =
                                Some((v.ident.clone(), "multi-field tuple variants".to_string()));
                            break;
                        }
                        syn::Fields::Named(_) => {
                            rejected = Some((v.ident.clone(), "named-field variants".to_string()));
                            break;
                        }
                    };
                    // Enforce homogeneity: every variant has to agree
                    // with the first variant's payload shape.
                    if variants.is_empty() {
                        payload_ty = this_payload.clone();
                    } else {
                        let want = payload_ty
                            .as_ref()
                            .map(|t| quote::quote!(#t).to_string().replace(' ', ""));
                        let got = this_payload
                            .as_ref()
                            .map(|t| quote::quote!(#t).to_string().replace(' ', ""));
                        if want != got {
                            rejected = Some((
                                v.ident.clone(),
                                format!(
                                    "heterogeneous payloads (expected `{}`, found `{}`)",
                                    want.unwrap_or_else(|| "unit".to_string()),
                                    got.unwrap_or_else(|| "unit".to_string()),
                                ),
                            ));
                            break;
                        }
                    }
                    variants.push(UserEnumVariant {
                        name: v.ident.clone(),
                        payload: this_payload,
                    });
                }
                if let Some((bad, reason)) = rejected {
                    diagnostics.push(MidnightError::new(
                        bad.span(),
                        ErrorCode::UnsupportedExpression,
                        format!(
                            "enum `{}` variant `{}` rejected: {}. Only \
                             homogeneous single-payload or all-unit enums \
                             are supported. See memories/scope-blockers.md.",
                            e.ident, bad, reason
                        ),
                    ));
                } else if !variants.is_empty() {
                    user_enums.insert(e.ident.to_string(), variants);
                }
                other_items.push(item);
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
                "contract must contain exactly one #[nocturne(ledger)] struct",
            ));
        }
    };

    if constructors.is_empty() && circuits.is_empty() {
        diagnostics.push(MidnightError::new(
            span,
            ErrorCode::MissingCircuit,
            "contract must contain at least one #[nocturne(circuit)] or #[nocturne(constructor)] function",
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
        user_structs,
        user_enums,
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
        let exported = !matches!(
            find_midnight_attr(&field.attrs),
            Some((MidnightAttr::Private, _))
        );

        fields.push(LedgerFieldIR {
            span: field_name.span(),
            name: field_name,
            ty: field.ty.clone(),
            type_kind,
            exported,
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

    // Three shapes accepted:
    //   - Named struct with field list (the original shape; field
    //     witnesses).
    //   - Empty named struct `pub struct W {}` (parametric witnesses
    //     only, declared in an `impl W` block).
    //   - Unit struct `pub struct W;` (same).
    match &s.fields {
        syn::Fields::Named(named) => {
            for field in &named.named {
                let field_name = field.ident.clone().unwrap();
                fields.push(WitnessFieldIR {
                    span: field_name.span(),
                    name: field_name,
                    ty: field.ty.clone(),
                });
            }
        }
        syn::Fields::Unit => {}
        syn::Fields::Unnamed(_) => {
            return Err(MidnightError::new(
                s.ident.span(),
                ErrorCode::InvalidType,
                "witnesses struct must use named fields or be a unit struct",
            ));
        }
    }

    Ok(WitnessIR {
        span: s.ident.span(),
        name: s.ident.clone(),
        fields,
        methods: Vec::new(),
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
    witnesses: Option<&mut WitnessIR>,
    other_items: &mut Vec<Item>,
    diagnostics: &mut Diagnostics,
) -> MidnightResult<()> {
    let mut has_midnight_methods = false;

    // If the impl targets the witnesses struct (by last-segment ident
    // match against `witnesses.name`), every `pub fn` becomes a
    // parametric witness method declaration. The body stays in the
    // user's impl block.
    let witnesses_target_match = witnesses
        .as_ref()
        .map(|w| impl_targets_ident(impl_block, &w.name))
        .unwrap_or(false);
    if witnesses_target_match && let Some(w) = witnesses {
        for item in &impl_block.items {
            if let ImplItem::Fn(method) = item {
                match parse_witness_method(method) {
                    Ok(m) => w.methods.push(m),
                    Err(e) => diagnostics.push(e),
                }
            }
        }
        // Keep the impl block in the user's output so the method
        // bodies are actually compiled — the user's code is what
        // provides the runtime implementation.
        other_items.push(Item::Impl(impl_block.clone()));
        return Ok(());
    }

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

fn impl_targets_ident(impl_block: &ItemImpl, ident: &syn::Ident) -> bool {
    // `impl Witnesses { ... }` parses as `ItemImpl` with `self_ty`
    // being `Type::Path(...)`. We match by the last segment's ident,
    // which is what compactc-style witness declarations expect (one
    // impl block per witnesses struct, no generics).
    if impl_block.trait_.is_some() {
        return false;
    }
    if let syn::Type::Path(tp) = &*impl_block.self_ty
        && let Some(seg) = tp.path.segments.last()
    {
        return &seg.ident == ident;
    }
    false
}

fn parse_witness_method(method: &ImplItemFn) -> MidnightResult<WitnessMethodIR> {
    let name = method.sig.ident.clone();
    let params = parse_fn_params(&method.sig)?;
    let return_type = match &method.sig.output {
        ReturnType::Default => {
            return Err(MidnightError::new(
                name.span(),
                ErrorCode::InvalidType,
                "parametric witness method must declare a return type",
            ));
        }
        ReturnType::Type(_, ty) => (**ty).clone(),
    };
    Ok(WitnessMethodIR {
        span: name.span(),
        name,
        params,
        return_type,
    })
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
    if let Some(FnArg::Receiver(recv)) = method.sig.inputs.first()
        && recv.mutability.is_some()
    {
        return Err(MidnightError::new(
            name.span(),
            ErrorCode::QueryMustBeImmutable,
            "query functions must take &self, not &mut self",
        ));
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
        if let FnArg::Typed(pat_type) = arg
            && let Pat::Ident(pat_ident) = &*pat_type.pat
        {
            let name = &pat_ident.ident;
            // Skip witness parameters (detected by type containing "Witnesses").
            // `quote!(#pat_type.ty)` renders the whole `PatType` followed by
            // a literal `. ty` token sequence — not the type. Reach into the
            // parsed field instead.
            let ty = &*pat_type.ty;
            let ty_str = quote::quote!(#ty).to_string();
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
                    // `quote!(#pat_type.ty)` renders the whole `PatType` followed by
                    // a literal `. ty` token sequence — not the type. Reach into the
                    // parsed field instead.
                    let ty = &*pat_type.ty;
                    let ty_str = quote::quote!(#ty).to_string();

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

    Ok((
        mutates_ledger,
        takes_witnesses,
        witnesses_param_name,
        params,
    ))
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
                // Multi-segment path like `Status::Open`, `Self::CONST`, or
                // `nocturne::disclose`. Stash the `syn::Path` itself so codegen
                // can emit it verbatim — flattening to an `Ident` panics.
                Ok(ExprIR::Path {
                    span: Span::call_site(),
                    path: path.clone(),
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
            let parsed_args: Vec<ExprIR> =
                args.iter().map(parse_expr).collect::<MidnightResult<_>>()?;

            // Detect `self.field.method(args)` pattern for ledger access.
            if let Expr::Field(ExprField { base, member, .. }) = &**receiver
                && is_self_expr(base)
                && let syn::Member::Named(field_name) = member
            {
                return Ok(ExprIR::LedgerAccess {
                    span: method.span(),
                    field: field_name.clone(),
                    method: method.clone(),
                    args: parsed_args,
                });
            }

            // Detect `witnesses.method(args)` — a parametric witness
            // call. The receiver is a bare `witnesses` identifier (same
            // shape `WitnessAccess` recognises for field reads). Routes
            // to `WitnessCall` so the codegen treats it as a witness
            // value source (PrivateInput allocation, transcript push),
            // not a regular method call on a Rust value.
            if let Expr::Path(ExprPath {
                path: recv_path, ..
            }) = &**receiver
                && let Some(recv_ident) = recv_path.get_ident()
            {
                let recv_name = recv_ident.to_string();
                if recv_name == "witnesses" || recv_name.ends_with("witnesses") {
                    return Ok(ExprIR::WitnessCall {
                        span: method.span(),
                        name: method.clone(),
                        args: parsed_args,
                    });
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
            if let Expr::Path(ExprPath { path, .. }) = &**base
                && let Some(ident) = path.get_ident()
            {
                let name = ident.to_string();
                if (name == "witnesses" || name.ends_with("witnesses"))
                    && let syn::Member::Named(field_name) = member
                {
                    return Ok(ExprIR::WitnessAccess {
                        span: field_name.span(),
                        field: field_name.clone(),
                    });
                }
            }

            // Detect `self.field` (ledger read without method call).
            if is_self_expr(base)
                && let syn::Member::Named(field_name) = member
            {
                return Ok(ExprIR::LedgerAccess {
                    span: field_name.span(),
                    field: field_name.clone(),
                    method: syn::Ident::new("__direct_access", Span::call_site()),
                    args: vec![],
                });
            }

            // Generic field access.
            let parsed_base = parse_expr(base)?;
            let field_ident = match member {
                syn::Member::Named(n) => n.clone(),
                syn::Member::Unnamed(idx) => syn::Ident::new(&format!("_{}", idx.index), idx.span),
            };
            Ok(ExprIR::MethodCall {
                span: field_ident.span(),
                receiver: Box::new(parsed_base),
                method: field_ident,
                args: vec![],
            })
        }

        Expr::Call(ExprCall { func, args, .. }) => {
            let parsed_args: Vec<ExprIR> =
                args.iter().map(parse_expr).collect::<MidnightResult<_>>()?;

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
                    path: path.clone(),
                    args: parsed_args,
                });
            }

            Ok(ExprIR::Unsupported {
                span: Span::call_site(),
                description: "complex function call expression".to_string(),
            })
        }

        Expr::If(expr_if) => {
            // Sugar: `if let Some(v) = self.<map>.get(&k) { body }` rewrites
            // to `if self.<map>.contains(&k) { let v = self.<map>.lookup(&k);
            // body }`. `Map::get` returns `Option<V>` at the type level (so
            // the user's source compiles as plain Rust), but on-chain there's
            // no Option<V> primitive — the on-chain VM panics on missing-key
            // `Popeq.as_cell(StateValue::Null)`. The contains-then-lookup
            // shape is the canonical Map::get expansion, and both
            // `conditional-branch-cond-select-zeroing` and
            // `conditional-io-guards` keep its inactive-branch reads zeroed.
            if let Some((var_name, map_field, key_expr)) = match_if_let_some_get(&expr_if.cond) {
                // Parse the key twice so both the contains and the lookup
                // get their own owned ExprIR (no Clone on ExprIR today).
                // The two parses produce equivalent trees because the
                // source expr is the same.
                let contains = ExprIR::LedgerAccess {
                    span: Span::call_site(),
                    field: map_field.clone(),
                    method: syn::Ident::new("contains", Span::call_site()),
                    args: vec![parse_expr(key_expr)?],
                };
                let lookup = ExprIR::LedgerAccess {
                    span: Span::call_site(),
                    field: map_field,
                    method: syn::Ident::new("lookup", Span::call_site()),
                    args: vec![parse_expr(key_expr)?],
                };
                let let_stmt = ExprIR::Let {
                    span: Span::call_site(),
                    name: var_name,
                    value: Box::new(lookup),
                };
                let mut then_branch = vec![let_stmt];
                then_branch.extend(parse_block_stmts(&expr_if.then_branch)?);
                let else_branch = if let Some((_, else_expr)) = &expr_if.else_branch {
                    match &**else_expr {
                        Expr::Block(block) => Some(parse_block_stmts(&block.block)?),
                        other => Some(vec![parse_expr(other)?]),
                    }
                } else {
                    None
                };
                return Ok(ExprIR::If {
                    span: Span::call_site(),
                    cond: Box::new(contains),
                    then_branch,
                    else_branch,
                });
            }

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

        // Sugar: `match self.<map>.get(&k) { Some(v) => some_body, None|_ => none_body }`
        // rewrites to the same contains+lookup if-else the if-let-Some
        // matcher produces. Both arms must be present; arm order doesn't
        // matter (Some-first and None-first both work).
        Expr::Match(expr_match) => {
            // `match self.<map>.get(&k) { Some(v) => ..., None => ... }`
            // sugar runs first: the new Option-aware `lower_enum_match`
            // also accepts `Some`/`None` patterns, but for map-get the
            // user wants the contains+lookup rewrite, not generic
            // Option lowering against an opaque LedgerAccess scrutinee.
            if let Some((var_name, map_field, key_expr, some_body, none_body)) =
                match_match_on_get(expr_match)
            {
                let contains = ExprIR::LedgerAccess {
                    span: Span::call_site(),
                    field: map_field.clone(),
                    method: syn::Ident::new("contains", Span::call_site()),
                    args: vec![parse_expr(key_expr)?],
                };
                let lookup = ExprIR::LedgerAccess {
                    span: Span::call_site(),
                    field: map_field,
                    method: syn::Ident::new("lookup", Span::call_site()),
                    args: vec![parse_expr(key_expr)?],
                };
                let let_stmt = ExprIR::Let {
                    span: Span::call_site(),
                    name: var_name,
                    value: Box::new(lookup),
                };
                let mut then_branch = vec![let_stmt];
                then_branch.extend(parse_arm_body(some_body)?);
                let else_branch = Some(parse_arm_body(none_body)?);

                return Ok(ExprIR::If {
                    span: Span::call_site(),
                    cond: Box::new(contains),
                    then_branch,
                    else_branch,
                });
            }
            // Otherwise, fall through to the generic enum-match
            // lowering — handles user enums and stdlib `Option<T>`
            // alike via discriminant comparisons.
            if let Some(chain) = lower_enum_match(expr_match)? {
                return Ok(chain);
            }
            Ok(ExprIR::Unsupported {
                span: Span::call_site(),
                description: "unsupported match shape (only `match self.<map>.get(&k) { Some(v) => ..., None => ... }`, \
                              unit-variant enums, and homogeneous-payload enums / Option<T> are supported)"
                    .to_string(),
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

        Expr::Array(array) => {
            let elements = array
                .elems
                .iter()
                .map(parse_expr)
                .collect::<MidnightResult<_>>()?;
            Ok(ExprIR::ArrayLit {
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

        Expr::ForLoop(for_expr) => parse_const_for_loop(for_expr),

        // `x as u64` / `x as Field` etc. — Nocturne treats the cast as
        // transparent for IR purposes (the wire-side encoding is
        // determined by the surrounding consumer's expected type, not
        // by the cast itself). Lower to the inner expression so
        // downstream codegen handles the Rust-side `as` verbatim where
        // it needs to.
        Expr::Cast(c) => parse_expr(&c.expr),

        // `arr[idx]` — only const integer literal indices (`arr[0]`,
        // `arr[1]`, ...). After `parse_const_for_loop` unrolls a const
        // for-loop, the loop variable substitutes to a literal int, so
        // `arr[i]` inside `for i in 0..N { ... }` parses to this arm.
        // Non-literal indices return Unsupported and surface as a
        // compile_error pointing at the call site.
        Expr::Index(idx) => {
            let array = parse_expr(&idx.expr)?;
            let index_expr: &Expr = &idx.index;
            if let Expr::Lit(lit) = index_expr
                && let syn::Lit::Int(int) = &lit.lit
                && let Ok(n) = int.base10_parse::<u32>()
            {
                Ok(ExprIR::Index {
                    span: Span::call_site(),
                    array: Box::new(array),
                    index: n,
                })
            } else {
                Ok(ExprIR::Unsupported {
                    span: Span::call_site(),
                    description: format!(
                        "array index must be a compile-time integer literal (got `{}`); \
                         use a `for i in 0..N` loop so the index unrolls to a literal",
                        quote::quote!(#index_expr)
                    ),
                })
            }
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
        // `assert!(cond)` or `assert!(cond, "msg", ...)`. The message
        // is informational only — we only enforce the condition. Drop
        // any extra args after the first.
        let args: syn::punctuated::Punctuated<Expr, syn::Token![,]> =
            syn::punctuated::Punctuated::parse_terminated
                .parse2(tokens.clone())
                .map_err(|e| {
                    MidnightError::new(
                        Span::call_site(),
                        ErrorCode::UnsupportedExpression,
                        format!("failed to parse assert arguments: {e}"),
                    )
                })?;
        let cond = args.into_iter().next().ok_or_else(|| {
            MidnightError::new(
                Span::call_site(),
                ErrorCode::UnsupportedExpression,
                "assert! requires a condition argument",
            )
        })?;
        Ok(ExprIR::Assert {
            span: Span::call_site(),
            kind: AssertKind::Assert(Box::new(parse_expr(&cond)?)),
        })
    } else if path_str == "assert_eq" || path_str.ends_with("::assert_eq") {
        // `assert_eq!(a, b)` or `assert_eq!(a, b, "msg", ...)`. Extra
        // args after `b` are dropped — they're only used for messaging
        // at runtime, not for constraint generation.
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
        // Carry the macro's own span so the diagnostic points at the
        // call site instead of `Span::call_site()`.
        Ok(ExprIR::Unsupported {
            span: mac
                .path
                .segments
                .last()
                .map(|s| s.ident.span())
                .unwrap_or_else(Span::call_site),
            description: format!("unsupported macro: {path_str}"),
        })
    }
}

/// Check if an expression is `self`.
fn is_self_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Path(ExprPath { path, .. }) if path.is_ident("self"))
}

/// Lower a `match` over unit-variant enum patterns into a nested `if`
/// chain. Returns `Some(if_chain)` when every arm is either a path
/// pattern (e.g. `Status::Open`) or `_`/identifier wildcard, otherwise
/// `None` so the caller can try other match shapes.
fn lower_enum_match(expr_match: &syn::ExprMatch) -> MidnightResult<Option<ExprIR>> {
    use syn::Pat;
    if expr_match.arms.is_empty() {
        return Ok(None);
    }
    // Classify arms. `Variant` carries the discriminator path; the
    // optional payload binding name comes from a single-ident tuple-
    // struct sub-pattern (`Action::Mint(amount)`). Wildcard payloads
    // (`Action::Mint(_)`) drop into `Variant` with `payload: None`.
    #[derive(Debug)]
    enum ArmShape<'a> {
        Variant {
            path: &'a syn::Path,
            payload: Option<syn::Ident>,
        },
        Wild,
    }
    let mut shapes: Vec<(ArmShape<'_>, &syn::Expr)> = Vec::with_capacity(expr_match.arms.len());
    for arm in &expr_match.arms {
        if arm.guard.is_some() {
            return Ok(None);
        }
        // `Some` / `None` are the stdlib Option variants — single-
        // segment paths that the rest of the match lowering treats as
        // qualified variant paths. The codegen recognizes the
        // path-segment text "Some" / "None" downstream.
        let is_option_variant_path = |path: &syn::Path| -> bool {
            path.segments.len() == 1
                && matches!(path.segments[0].ident.to_string().as_str(), "Some" | "None")
        };
        match &arm.pat {
            Pat::Path(p) if p.path.segments.len() >= 2 || is_option_variant_path(&p.path) => {
                shapes.push((
                    ArmShape::Variant {
                        path: &p.path,
                        payload: None,
                    },
                    arm.body.as_ref(),
                ));
            }
            Pat::TupleStruct(ts)
                if (ts.path.segments.len() >= 2 || is_option_variant_path(&ts.path))
                    && ts.elems.len() == 1 =>
            {
                // `Variant(ident)` or `Variant(_)`. Multi-field tuple
                // and named-field variants need a separate encoding
                // ADR and fall through to the generic `None` return.
                let inner = ts.elems.first().unwrap();
                let payload = match inner {
                    Pat::Wild(_) => None,
                    Pat::Ident(pi) if pi.subpat.is_none() && pi.by_ref.is_none() => {
                        Some(pi.ident.clone())
                    }
                    _ => return Ok(None),
                };
                shapes.push((
                    ArmShape::Variant {
                        path: &ts.path,
                        payload,
                    },
                    arm.body.as_ref(),
                ));
            }
            Pat::Wild(_) => shapes.push((ArmShape::Wild, arm.body.as_ref())),
            Pat::Ident(pi) if pi.subpat.is_none() => {
                // Catch-all identifier (no `@` sub-pattern) acts as wildcard.
                shapes.push((ArmShape::Wild, arm.body.as_ref()));
            }
            _ => return Ok(None),
        }
    }
    let scrutinee = parse_expr(&expr_match.expr)?;

    // Find the wildcard arm if any; it becomes the final else branch. If no
    // wildcard, the final variant arm's body is used directly as the bare
    // else (the user is responsible for exhaustiveness).
    let wild_idx = shapes.iter().position(|(s, _)| matches!(s, ArmShape::Wild));
    type VariantArm<'a> = (&'a syn::Path, Option<syn::Ident>, &'a syn::Expr);
    let (variant_arms, default_body): (Vec<VariantArm<'_>>, Option<Vec<ExprIR>>) =
        if let Some(idx) = wild_idx {
            let default_body = parse_arm_body(shapes[idx].1)?;
            let variants: Vec<VariantArm<'_>> = shapes
                .iter()
                .enumerate()
                .filter_map(|(i, (s, body))| match s {
                    ArmShape::Variant { path, payload } if i != idx => {
                        Some((*path, payload.clone(), *body))
                    }
                    _ => None,
                })
                .collect();
            (variants, Some(default_body))
        } else {
            let variants: Vec<VariantArm<'_>> = shapes
                .iter()
                .filter_map(|(s, body)| match s {
                    ArmShape::Variant { path, payload } => Some((*path, payload.clone(), *body)),
                    ArmShape::Wild => None,
                })
                .collect();
            (variants, None)
        };

    if variant_arms.is_empty() {
        return Ok(None);
    }

    // Build the if chain from the last variant outward. Payload-binding
    // arms prepend `let <name> = EnumPayload { scrutinee, enum_name }`
    // to the arm body — the discriminant check still happens via the
    // discriminant equality comparison; the binding is a separate
    // projection that codegen handles per-target.
    let mut else_branch: Option<Vec<ExprIR>> = default_body;
    for (path, payload, body) in variant_arms.iter().rev() {
        let mut then_branch = Vec::new();
        if let Some(binding) = payload {
            // The enum name is the second-to-last path segment for
            // qualified user-enum variants (`Action::Mint` → `Action`).
            // For single-segment stdlib paths (`Some(x)` / `None`) we
            // emit `Option` as the synthetic enum name; the codegen
            // routes Option through its own helpers and only inspects
            // the scrutinee's type for variant info, so this name is
            // a marker rather than a lookup key.
            let n = path.segments.len();
            let enum_name = if n >= 2 {
                path.segments[n - 2].ident.clone()
            } else {
                syn::Ident::new("Option", Span::call_site())
            };
            then_branch.push(ExprIR::Let {
                span: Span::call_site(),
                name: binding.clone(),
                value: Box::new(ExprIR::EnumPayload {
                    span: Span::call_site(),
                    scrutinee: Box::new(scrutinee.clone()),
                    enum_name,
                }),
            });
        }
        then_branch.extend(parse_arm_body(body)?);
        let cond = ExprIR::BinaryOp {
            span: Span::call_site(),
            op: syn::BinOp::Eq(syn::token::EqEq(Span::call_site())),
            lhs: Box::new(scrutinee.clone()),
            rhs: Box::new(ExprIR::Path {
                span: Span::call_site(),
                path: (*path).clone(),
            }),
        };
        let if_expr = ExprIR::If {
            span: Span::call_site(),
            cond: Box::new(cond),
            then_branch,
            else_branch: else_branch.take(),
        };
        else_branch = Some(vec![if_expr]);
    }
    // `else_branch` now holds a single-element vec with the outermost If.
    Ok(else_branch.and_then(|mut v| v.pop()))
}

/// Parse a match arm's body, which is either a block or a bare expression.
fn parse_arm_body(body: &Expr) -> MidnightResult<Vec<ExprIR>> {
    match body {
        Expr::Block(b) => parse_block_stmts(&b.block),
        other => Ok(vec![parse_expr(other)?]),
    }
}

/// Decompose the scrutinee `self.<field>.get(<key>)` of an if-let cond or
/// match expression. Returns the map-field ident and the (unparsed) key
/// expression for the caller to parse.
fn match_self_field_get_scrutinee(expr: &Expr) -> Option<(syn::Ident, &Expr)> {
    let Expr::MethodCall(ExprMethodCall {
        receiver,
        method,
        args,
        ..
    }) = expr
    else {
        return None;
    };
    if method != "get" || args.len() != 1 {
        return None;
    }
    let Expr::Field(ExprField { base, member, .. }) = &**receiver else {
        return None;
    };
    if !is_self_expr(base) {
        return None;
    }
    let syn::Member::Named(field_name) = member else {
        return None;
    };
    Some((field_name.clone(), args.first()?))
}

/// Match `match self.<map>.get(&k) { Some(v) => some_body, None|_ => none_body }`
/// or with the arms reversed. Returns the variable bound by `Some(v)`, the
/// map-field ident, the key expression, and the bodies of the Some and None
/// arms (in canonical Some-then-None order). The caller rewrites to the
/// contains+lookup if-else.
fn match_match_on_get(
    expr_match: &syn::ExprMatch,
) -> Option<(syn::Ident, syn::Ident, &Expr, &Expr, &Expr)> {
    if expr_match.arms.len() != 2 {
        return None;
    }
    let (map_field, key_expr) = match_self_field_get_scrutinee(&expr_match.expr)?;

    // Classify each arm as Some(v), None, or wildcard.
    enum Kind {
        Some(syn::Ident),
        NoneOrWild,
        Other,
    }
    let classify = |pat: &Pat| -> Kind {
        match pat {
            Pat::TupleStruct(pt)
                if pt.path.segments.last().is_some_and(|s| s.ident == "Some")
                    && pt.elems.len() == 1 =>
            {
                if let Pat::Ident(pi) = pt.elems.first().unwrap() {
                    return Kind::Some(pi.ident.clone());
                }
                Kind::Other
            }
            Pat::Path(pp) if pp.path.segments.last().is_some_and(|s| s.ident == "None") => {
                Kind::NoneOrWild
            }
            // `None` as an Ident path falls through to here in some syn versions.
            Pat::Ident(pi) if pi.ident == "None" => Kind::NoneOrWild,
            Pat::Wild(_) => Kind::NoneOrWild,
            _ => Kind::Other,
        }
    };

    let arm0 = &expr_match.arms[0];
    let arm1 = &expr_match.arms[1];
    // Arms must have no guard for the rewrite to be sound (a guard could
    // refuse the lookup despite contains=true).
    if arm0.guard.is_some() || arm1.guard.is_some() {
        return None;
    }
    let (var, some_body, none_body) = match (classify(&arm0.pat), classify(&arm1.pat)) {
        (Kind::Some(v), Kind::NoneOrWild) => (v, &*arm0.body, &*arm1.body),
        (Kind::NoneOrWild, Kind::Some(v)) => (v, &*arm1.body, &*arm0.body),
        _ => return None,
    };

    Some((var, map_field, key_expr, some_body, none_body))
}

/// Match `if let Some(v) = self.<map>.get(&k)`-style conditions. Returns
/// `(v_ident, map_field_ident, key_expr)` on a hit, `None` otherwise. The
/// callee rewrites the surrounding `if` into the contains+lookup pattern.
fn match_if_let_some_get(cond: &Expr) -> Option<(syn::Ident, syn::Ident, &Expr)> {
    let Expr::Let(syn::ExprLet { pat, expr, .. }) = cond else {
        return None;
    };
    // Match `Some(<ident>)` pattern.
    let Pat::TupleStruct(pat_ts) = &**pat else {
        return None;
    };
    if pat_ts.path.segments.last()?.ident != "Some" || pat_ts.elems.len() != 1 {
        return None;
    }
    let Pat::Ident(var_pat) = pat_ts.elems.first()? else {
        return None;
    };
    let var_name = var_pat.ident.clone();

    let (field_name, key_expr) = match_self_field_get_scrutinee(expr)?;
    Some((var_name, field_name, key_expr))
}

/// Parse `for <ident> in <lit>..<lit> { body }` (or `..=`) and unroll
/// inline. Both bounds must be integer literals known at compile time;
/// anything else (variable bounds, non-range iterators) is rejected so
/// the codegen never has to deal with dynamic iteration in a circuit.
///
/// Unrolling = N copies of the body with `<ident>` substituted by the
/// iteration value at each step, wrapped in `ExprIR::Block` so call
/// sites that expect a single expression keep working. Each iteration
/// gets its own nested Block so user `let` bindings shadow cleanly
/// across copies without leaking between them.
fn parse_const_for_loop(for_expr: &syn::ExprForLoop) -> MidnightResult<ExprIR> {
    let Pat::Ident(pat) = &*for_expr.pat else {
        return Ok(ExprIR::Unsupported {
            span: Span::call_site(),
            description: "for-loop pattern must be a single identifier".to_string(),
        });
    };
    let loop_var = pat.ident.clone();

    let Expr::Range(range) = &*for_expr.expr else {
        return Ok(ExprIR::Unsupported {
            span: Span::call_site(),
            description: "for-loop iterator must be a literal `<lit>..<lit>` range".to_string(),
        });
    };
    let Some(start_expr) = &range.start else {
        return Ok(ExprIR::Unsupported {
            span: Span::call_site(),
            description: "for-loop range must have an explicit lower bound".to_string(),
        });
    };
    let Some(end_expr) = &range.end else {
        return Ok(ExprIR::Unsupported {
            span: Span::call_site(),
            description: "for-loop range must have an explicit upper bound".to_string(),
        });
    };
    let start = parse_int_literal(start_expr).ok_or_else(|| {
        MidnightError::new(
            Span::call_site(),
            ErrorCode::UnsupportedExpression,
            "for-loop lower bound must be an integer literal",
        )
    })?;
    let end = parse_int_literal(end_expr).ok_or_else(|| {
        MidnightError::new(
            Span::call_site(),
            ErrorCode::UnsupportedExpression,
            "for-loop upper bound must be an integer literal",
        )
    })?;
    let inclusive = matches!(range.limits, syn::RangeLimits::Closed(_));

    let last = if inclusive {
        end
    } else {
        end.saturating_sub(1)
    };
    if (inclusive && end < start) || (!inclusive && end <= start) {
        return Ok(ExprIR::Block {
            span: Span::call_site(),
            stmts: Vec::new(),
        });
    }

    let mut iterations: Vec<ExprIR> = Vec::new();
    let mut i = start;
    loop {
        let mut body = for_expr.body.clone();
        substitute_ident_with_int(&mut body, &loop_var, i);
        let stmts = parse_block_stmts(&body)?;
        iterations.push(ExprIR::Block {
            span: Span::call_site(),
            stmts,
        });
        if i == last {
            break;
        }
        i += 1;
    }

    Ok(ExprIR::Block {
        span: Span::call_site(),
        stmts: iterations,
    })
}

/// Parse a `usize`-valued integer literal (with or without a suffix).
/// Returns `None` for anything that isn't an integer literal — including
/// `1 + 1` and other expressions that *evaluate* to a constant; const
/// evaluation isn't worth the complexity here.
fn parse_int_literal(expr: &Expr) -> Option<u64> {
    let Expr::Lit(lit) = expr else {
        return None;
    };
    let syn::Lit::Int(int) = &lit.lit else {
        return None;
    };
    int.base10_parse::<u64>().ok()
}

/// Walk `block` and replace every `Expr::Path` whose single-ident path
/// equals `target` with the integer literal `value`. Used to inline the
/// for-loop variable into each unrolled iteration. Doesn't try to be
/// clever about shadowing — Rust's normal scoping would let inner
/// bindings shadow the loop var, but in practice circuit bodies don't
/// reuse names that way, and a paranoid substitution is simpler than
/// tracking scope at this layer.
fn substitute_ident_with_int(block: &mut syn::Block, target: &syn::Ident, value: u64) {
    use syn::visit_mut::{self, VisitMut};

    struct Subst<'a> {
        target: &'a syn::Ident,
        value: u64,
    }

    impl<'a> VisitMut for Subst<'a> {
        fn visit_expr_mut(&mut self, e: &mut Expr) {
            if let Expr::Path(p) = e
                && p.qself.is_none()
                && let Some(ident) = p.path.get_ident()
                && ident == self.target
            {
                let v = self.value;
                *e = syn::parse_quote!(#v);
                return;
            }
            visit_mut::visit_expr_mut(self, e);
        }
    }

    let mut subst = Subst { target, value };
    subst.visit_block_mut(block);
}
