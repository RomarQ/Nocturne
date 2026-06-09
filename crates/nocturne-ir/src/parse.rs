use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::{
    Expr, ExprCall, ExprField, ExprMethodCall, ExprPath, FnArg, ImplItem, ImplItemFn, Item, ItemFn,
    ItemImpl, ItemMod, ItemStruct, Pat, ReturnType, Stmt, parse::Parser,
};

use crate::attrs::{MidnightAttr, find_midnight_attr};
use crate::contract::*;
use crate::error::*;
use crate::expr::*;

/// Contract-level declarations available while parsing function bodies.
/// Built after the declaration pass so body parsing can resolve the
/// witnesses struct (exact param-type matching), ledger field types,
/// and user enums regardless of item order in the module.
struct ContractCtx<'a> {
    ledger: Option<&'a LedgerIR>,
    witnesses: Option<&'a WitnessIR>,
    user_enums: &'a std::collections::HashMap<String, Vec<UserEnumVariant>>,
}

impl<'a> ContractCtx<'a> {
    fn witnesses_struct_name(&self) -> Option<&'a syn::Ident> {
        self.witnesses.map(|w| &w.name)
    }
}

/// Per-function context for body parsing. `witnesses_param` is the
/// ident of the function's witnesses-typed parameter (matched by exact
/// type against the registered `#[nocturne(witnesses)]` struct); body
/// parsing classifies `recv.field` / `recv.method(..)` as witness
/// reads/calls only when `recv` is exactly that ident.
struct BodyCtx<'a> {
    contract: &'a ContractCtx<'a>,
    witnesses_param: Option<syn::Ident>,
    /// Declared types of the function's public params, used for
    /// `as`-cast width inference (`x as u64` with `x: u32`).
    param_types: std::collections::HashMap<String, syn::Type>,
    /// Monotonic counter for synthetic match-scrutinee bindings, so
    /// nested matches inside one function body never collide in the
    /// emitters' flat variable maps.
    scrutinee_counter: std::cell::Cell<u32>,
}

impl BodyCtx<'_> {
    fn is_witnesses_receiver(&self, ident: &syn::Ident) -> bool {
        self.witnesses_param.as_ref() == Some(ident)
    }

    fn param_types_of(params: &[ParamIR]) -> std::collections::HashMap<String, syn::Type> {
        params
            .iter()
            .map(|p| (p.name.to_string(), p.ty.clone()))
            .collect()
    }

    fn fresh_scrutinee_ident(&self, span: Span) -> syn::Ident {
        let n = self.scrutinee_counter.get();
        self.scrutinee_counter.set(n + 1);
        syn::Ident::new(&format!("__nocturne_scrutinee_{n}"), span)
    }
}

/// Parse a `#[nocturne::contract]` module into a `ContractIR`.
///
/// On failure, returns ALL collected diagnostics — the macro entry
/// emits one `compile_error!` per error so the user sees every problem
/// in a single build.
pub fn parse_contract(module: ItemMod) -> Result<ContractIR, Diagnostics> {
    let name = module.ident.clone();
    let span = name.span();

    let Some((_, items)) = module.content else {
        // `mod foo;` has no inline content — the proc macro never sees
        // the out-of-line file, so this can't be compiled as a
        // contract. Without the dedicated error this would surface as
        // a misleading MissingLedger.
        let mut diagnostics = Diagnostics::new();
        diagnostics.push(MidnightError::new(
            span,
            ErrorCode::EmptyContractModule,
            "contract module must have inline content (`mod foo { ... }`); \
             `mod foo;` out-of-line modules are not supported by #[nocturne::contract]",
        ));
        return Err(diagnostics);
    };

    let mut ledger: Option<LedgerIR> = None;
    let mut ledger_seen = false;
    let mut witnesses: Option<WitnessIR> = None;
    let mut witnesses_seen = false;
    let mut constructors: Vec<ConstructorIR> = Vec::new();
    let mut circuits: Vec<CircuitIR> = Vec::new();
    let mut queries: Vec<QueryIR> = Vec::new();
    let mut helpers: Vec<HelperIR> = Vec::new();
    let mut other_items: Vec<Item> = Vec::new();
    let mut user_structs: std::collections::HashMap<String, Vec<UserStructField>> =
        std::collections::HashMap::new();
    let mut user_enums: std::collections::HashMap<String, Vec<UserEnumVariant>> =
        std::collections::HashMap::new();
    let mut diagnostics = Diagnostics::new();

    // Indices of items consumed as nocturne declarations in pass 1
    // (the ledger/witnesses structs); pass 2 skips them so they don't
    // double up in `other_items`.
    let mut declaration_indices: std::collections::HashSet<usize> =
        std::collections::HashSet::new();

    // ---- Pass 1: declarations (structs and enums). Item order in the
    // module must not matter — an `impl Witnesses` block above the
    // witnesses struct declaration has to register its methods all the
    // same — so declarations are collected before any body parsing.
    for (i, item) in items.iter().enumerate() {
        match item {
            Item::Struct(s) => match find_midnight_attr(&s.attrs) {
                Err(e) => diagnostics.push(e),
                Ok(Some((MidnightAttr::Ledger, _attr_span))) => {
                    declaration_indices.insert(i);
                    if ledger_seen {
                        diagnostics.push(MidnightError::new(
                            s.ident.span(),
                            ErrorCode::DuplicateLedger,
                            "only one #[nocturne(ledger)] struct is allowed per contract",
                        ));
                    } else {
                        ledger_seen = true;
                        match parse_ledger_struct(s) {
                            Ok(l) => ledger = Some(l),
                            Err(e) => diagnostics.push(e),
                        }
                    }
                }
                Ok(Some((MidnightAttr::Witnesses, _attr_span))) => {
                    declaration_indices.insert(i);
                    if witnesses_seen {
                        diagnostics.push(MidnightError::new(
                            s.ident.span(),
                            ErrorCode::DuplicateWitnesses,
                            "only one #[nocturne(witnesses)] struct is allowed per contract",
                        ));
                    } else {
                        witnesses_seen = true;
                        match parse_witnesses_struct(s) {
                            Ok(w) => witnesses = Some(w),
                            Err(e) => diagnostics.push(e),
                        }
                    }
                }
                Ok(_) => {
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
                }
            },
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
            }
            _ => {}
        }
    }

    // ---- Pass 1.5: parametric witness methods. Any non-trait impl
    // block whose self type's last segment matches the registered
    // witnesses struct contributes method declarations, regardless of
    // where it appears relative to the struct.
    if let Some(w) = witnesses.as_mut() {
        for item in &items {
            if let Item::Impl(impl_block) = item
                && impl_targets_ident(impl_block, &w.name)
            {
                for impl_item in &impl_block.items {
                    if let ImplItem::Fn(method) = impl_item {
                        match parse_witness_method(method) {
                            Ok(m) => w.methods.push(m),
                            Err(e) => diagnostics.push(e),
                        }
                    }
                }
            }
        }
    }

    // ---- Pass 2: function bodies (constructors, circuits, queries,
    // helpers), with all declarations resolved.
    let ctx = ContractCtx {
        ledger: ledger.as_ref(),
        witnesses: witnesses.as_ref(),
        user_enums: &user_enums,
    };

    for (i, item) in items.into_iter().enumerate() {
        match &item {
            // Ledger/witnesses structs were consumed in pass 1 and are
            // (as before) not part of `other_items`.
            Item::Struct(_) if declaration_indices.contains(&i) => {}
            Item::Impl(impl_block) => {
                if ctx
                    .witnesses
                    .map(|w| impl_targets_ident(impl_block, &w.name))
                    .unwrap_or(false)
                {
                    // Witness method declarations were registered in
                    // pass 1.5. Keep the impl block in the user's
                    // output so the method bodies are actually
                    // compiled — the user's code is what provides the
                    // runtime implementation.
                    other_items.push(item);
                } else {
                    parse_impl_block(
                        impl_block,
                        &ctx,
                        &mut constructors,
                        &mut circuits,
                        &mut queries,
                        &mut other_items,
                        &mut diagnostics,
                    );
                }
            }
            Item::Fn(item_fn) => {
                // Free `fn` items inside the contract module are
                // helper candidates. Try parsing into HelperIR; if the
                // signature uses references (`&self`, `&Witnesses`) or
                // the body contains shapes the IR doesn't recognise,
                // we silently leave the fn alone — the user's Rust
                // code keeps compiling and the existing path-preserving
                // FnCall arm still handles transcript-side calls. The
                // ZKIR side has no way to constrain non-inlinable
                // calls but that was already true before this commit.
                if let Some(helper) = try_parse_helper(item_fn, &ctx) {
                    helpers.push(helper);
                }
                other_items.push(item);
            }
            _ => {
                other_items.push(item);
            }
        }
    }

    // Every witness read/call in every body must resolve against the
    // registered witnesses struct. A typo'd field or a non-registered
    // method (`witnesses.clone()`) would otherwise silently become a
    // fresh PrivateInput block with a guessed layout downstream.
    validate_witness_resolution(
        ctx.witnesses,
        constructors
            .iter()
            .map(|c| c.body.as_slice())
            .chain(circuits.iter().map(|c| c.body.as_slice()))
            .chain(queries.iter().map(|q| q.body.as_slice()))
            .chain(helpers.iter().map(|h| h.body.as_slice())),
        &mut diagnostics,
    );

    // Reject recursive helpers BEFORE downstream consumption — the
    // inliner's termination depends on the call graph being acyclic.
    if let Err(e) = validate_helpers_acyclic(&helpers) {
        diagnostics.push(e);
    }

    // Validation
    let ledger = match ledger {
        Some(l) => l,
        None => {
            // Only report MissingLedger when no ledger struct was
            // declared at all; if one was declared but failed to
            // parse, that error is already in the diagnostics.
            if !ledger_seen {
                diagnostics.push(MidnightError::new(
                    span,
                    ErrorCode::MissingLedger,
                    "contract must contain exactly one #[nocturne(ledger)] struct",
                ));
            }
            return Err(diagnostics);
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
        return Err(diagnostics);
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
        helpers,
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
            find_midnight_attr(&field.attrs)?,
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
    ctx: &ContractCtx<'_>,
    constructors: &mut Vec<ConstructorIR>,
    circuits: &mut Vec<CircuitIR>,
    queries: &mut Vec<QueryIR>,
    other_items: &mut Vec<Item>,
    diagnostics: &mut Diagnostics,
) {
    let mut has_midnight_methods = false;

    for item in &impl_block.items {
        if let ImplItem::Fn(method) = item {
            match find_midnight_attr(&method.attrs) {
                Ok(Some((MidnightAttr::Constructor, _))) => {
                    has_midnight_methods = true;
                    match parse_constructor(method, ctx) {
                        Ok(c) => constructors.push(c),
                        Err(e) => diagnostics.push(e),
                    }
                }
                Ok(Some((MidnightAttr::Circuit, _))) => {
                    has_midnight_methods = true;
                    match parse_circuit(method, ctx) {
                        Ok(c) => circuits.push(c),
                        Err(e) => diagnostics.push(e),
                    }
                }
                Ok(Some((MidnightAttr::Query, _))) => {
                    has_midnight_methods = true;
                    match parse_query(method, ctx) {
                        Ok(q) => queries.push(q),
                        Err(e) => diagnostics.push(e),
                    }
                }
                Ok(_) => {}
                Err(e) => diagnostics.push(e),
            }
        }
    }

    if !has_midnight_methods {
        other_items.push(Item::Impl(impl_block.clone()));
    }
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

/// Try parsing a free `fn` item as a helper. Returns `None` on any
/// shape we don't yet inline (referenced parameters, missing return
/// type, builtin-name shadow, body the IR can't model). The original
/// `Item::Fn` stays in `other_items` so the user's Rust code is
/// untouched and the transcript-side codegen still calls it as Rust;
/// the only effect of `None` is "no ZKIR inlining for this fn".
fn try_parse_helper(item_fn: &ItemFn, ctx: &ContractCtx<'_>) -> Option<HelperIR> {
    let name = item_fn.sig.ident.clone();

    // Generic, async, const, and unsafe fns can't be inlined into a
    // circuit body (no monomorphisation or effect model at the IR
    // layer) — leave them as plain Rust fns.
    let sig = &item_fn.sig;
    if sig.asyncness.is_some()
        || sig.constness.is_some()
        || sig.unsafety.is_some()
        || !sig.generics.params.is_empty()
        || sig.generics.where_clause.is_some()
    {
        return None;
    }

    // Don't shadow builtins recognised by the codegen.
    let n = name.to_string();
    if matches!(
        n.as_str(),
        "persistent_hash" | "transient_hash" | "merkle_tree_path_root" | "disclose"
    ) {
        return None;
    }

    // v1: reject reference params. Owned types only (Uint<N>, Bytes<N>,
    // user structs, tuples, etc.). `&Self` / `&Witnesses` require
    // separate plumbing tracked as v2.
    let mut params: Vec<ParamIR> = Vec::new();
    for arg in &item_fn.sig.inputs {
        match arg {
            FnArg::Receiver(_) => return None,
            FnArg::Typed(pat_type) => {
                if matches!(&*pat_type.ty, syn::Type::Reference(_)) {
                    return None;
                }
                let Pat::Ident(pat_ident) = &*pat_type.pat else {
                    return None;
                };
                params.push(ParamIR {
                    span: pat_ident.ident.span(),
                    name: pat_ident.ident.clone(),
                    ty: *pat_type.ty.clone(),
                });
            }
        }
    }

    let return_type = match &item_fn.sig.output {
        ReturnType::Default => return None,
        ReturnType::Type(_, ty) => {
            if matches!(&**ty, syn::Type::Reference(_)) {
                return None;
            }
            (**ty).clone()
        }
    };

    // Parse the body. If anything inside lowers to `Unsupported`,
    // we'd produce broken inlined IR — better to leave the fn alone
    // and let the user notice the runtime failure. Helpers never take
    // a witnesses param (reference params are rejected above), so the
    // body parses without a witnesses receiver in scope.
    let body_ctx = BodyCtx {
        contract: ctx,
        witnesses_param: None,
        param_types: BodyCtx::param_types_of(&params),
        scrutinee_counter: std::cell::Cell::new(0),
    };
    let body = parse_block_stmts(&item_fn.block, &body_ctx).ok()?;
    if body.iter().any(contains_unsupported) {
        return None;
    }

    Some(HelperIR {
        span: name.span(),
        name,
        params,
        return_type,
        body,
    })
}

/// Recursive `Unsupported` check for helper body acceptance. A helper
/// containing any unsupported node would inline broken IR into a
/// caller; rejecting up-front gives the user a clearer failure mode
/// (the transcript-side Rust call still works) than silently
/// miscompiling.
fn contains_unsupported(expr: &ExprIR) -> bool {
    match expr {
        ExprIR::Unsupported { .. } => true,
        ExprIR::BinaryOp { lhs, rhs, .. } => contains_unsupported(lhs) || contains_unsupported(rhs),
        ExprIR::UnaryOp { expr, .. } | ExprIR::Reference { expr, .. } => contains_unsupported(expr),
        ExprIR::FnCall { args, .. } | ExprIR::MethodCall { args, .. } => {
            args.iter().any(contains_unsupported)
        }
        ExprIR::Let { value, .. } => contains_unsupported(value),
        ExprIR::If {
            cond,
            then_branch,
            else_branch,
            ..
        } => {
            contains_unsupported(cond)
                || then_branch.iter().any(contains_unsupported)
                || else_branch
                    .as_ref()
                    .is_some_and(|b| b.iter().any(contains_unsupported))
        }
        ExprIR::Assert { kind, .. } => match kind {
            AssertKind::Assert(e) => contains_unsupported(e),
            AssertKind::AssertEq(a, b) => contains_unsupported(a) || contains_unsupported(b),
        },
        ExprIR::Disclose { value, .. } => contains_unsupported(value),
        ExprIR::EnumPayload { scrutinee, .. } => contains_unsupported(scrutinee),
        ExprIR::Block { stmts, .. } => stmts.iter().any(contains_unsupported),
        ExprIR::StructInit { fields, .. } => fields.iter().any(|(_, e)| contains_unsupported(e)),
        ExprIR::Return { value, .. } => value.as_deref().is_some_and(contains_unsupported),
        ExprIR::Tuple { elements, .. } | ExprIR::ArrayLit { elements, .. } => {
            elements.iter().any(contains_unsupported)
        }
        ExprIR::Index { array, .. } => contains_unsupported(array),
        ExprIR::LedgerAccess { args, .. } | ExprIR::WitnessCall { args, .. } => {
            args.iter().any(contains_unsupported)
        }
        // Leaf nodes.
        ExprIR::Literal { .. }
        | ExprIR::Var { .. }
        | ExprIR::Path { .. }
        | ExprIR::WitnessAccess { .. } => false,
    }
}

/// DFS cycle check over the helper call graph. compactc's inliner
/// asserts acyclicity instead of detecting it; the equivalent
/// guarantee in Nocturne lives here. Reports the cycle by listing
/// the helpers on the back-edge path.
fn validate_helpers_acyclic(helpers: &[HelperIR]) -> MidnightResult<()> {
    use std::collections::HashMap;

    let names: HashMap<String, usize> = helpers
        .iter()
        .enumerate()
        .map(|(i, h)| (h.name.to_string(), i))
        .collect();

    // Adjacency: helper i → helpers j whose name appears in i's body
    // as a FnCall callee.
    let edges: Vec<Vec<usize>> = helpers
        .iter()
        .map(|h| {
            let mut called: Vec<String> = Vec::new();
            for stmt in &h.body {
                collect_fncall_names(stmt, &mut called);
            }
            called
                .into_iter()
                .filter_map(|n| names.get(&n).copied())
                .collect()
        })
        .collect();

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Colour {
        White,
        Gray,
        Black,
    }

    let mut colour = vec![Colour::White; helpers.len()];
    let mut path: Vec<usize> = Vec::new();

    fn dfs(
        node: usize,
        edges: &[Vec<usize>],
        colour: &mut [Colour],
        path: &mut Vec<usize>,
    ) -> Option<Vec<usize>> {
        colour[node] = Colour::Gray;
        path.push(node);
        for &next in &edges[node] {
            match colour[next] {
                Colour::Gray => {
                    // Back-edge — cycle. Slice the path from the
                    // first occurrence of `next` to the end, then
                    // append `next` again to close it visually.
                    let mut cycle: Vec<usize> =
                        path.iter().skip_while(|&&i| i != next).copied().collect();
                    cycle.push(next);
                    return Some(cycle);
                }
                Colour::White => {
                    if let Some(c) = dfs(next, edges, colour, path) {
                        return Some(c);
                    }
                }
                Colour::Black => {}
            }
        }
        path.pop();
        colour[node] = Colour::Black;
        None
    }

    for i in 0..helpers.len() {
        if colour[i] == Colour::White
            && let Some(cycle) = dfs(i, &edges, &mut colour, &mut path)
        {
            let chain: Vec<String> = cycle
                .into_iter()
                .map(|i| helpers[i].name.to_string())
                .collect();
            return Err(MidnightError::new(
                helpers[i].name.span(),
                ErrorCode::UnsupportedExpression,
                format!("recursive helper: {}", chain.join(" → ")),
            ));
        }
    }
    Ok(())
}

fn collect_fncall_names(expr: &ExprIR, out: &mut Vec<String>) {
    match expr {
        ExprIR::FnCall { name, args, .. } => {
            out.push(name.to_string());
            for a in args {
                collect_fncall_names(a, out);
            }
        }
        ExprIR::BinaryOp { lhs, rhs, .. } => {
            collect_fncall_names(lhs, out);
            collect_fncall_names(rhs, out);
        }
        ExprIR::UnaryOp { expr, .. } | ExprIR::Reference { expr, .. } => {
            collect_fncall_names(expr, out);
        }
        ExprIR::MethodCall { receiver, args, .. } => {
            collect_fncall_names(receiver, out);
            for a in args {
                collect_fncall_names(a, out);
            }
        }
        ExprIR::Let { value, .. } => collect_fncall_names(value, out),
        ExprIR::If {
            cond,
            then_branch,
            else_branch,
            ..
        } => {
            collect_fncall_names(cond, out);
            for s in then_branch {
                collect_fncall_names(s, out);
            }
            if let Some(b) = else_branch {
                for s in b {
                    collect_fncall_names(s, out);
                }
            }
        }
        ExprIR::Assert { kind, .. } => match kind {
            AssertKind::Assert(e) => collect_fncall_names(e, out),
            AssertKind::AssertEq(a, b) => {
                collect_fncall_names(a, out);
                collect_fncall_names(b, out);
            }
        },
        ExprIR::Disclose { value, .. } => collect_fncall_names(value, out),
        ExprIR::EnumPayload { scrutinee, .. } => collect_fncall_names(scrutinee, out),
        ExprIR::Block { stmts, .. } => {
            for s in stmts {
                collect_fncall_names(s, out);
            }
        }
        ExprIR::StructInit { fields, .. } => {
            for (_, e) in fields {
                collect_fncall_names(e, out);
            }
        }
        ExprIR::Return { value, .. } => {
            if let Some(v) = value {
                collect_fncall_names(v, out);
            }
        }
        ExprIR::Tuple { elements, .. } | ExprIR::ArrayLit { elements, .. } => {
            for e in elements {
                collect_fncall_names(e, out);
            }
        }
        ExprIR::Index { array, .. } => collect_fncall_names(array, out),
        ExprIR::LedgerAccess { args, .. } | ExprIR::WitnessCall { args, .. } => {
            for a in args {
                collect_fncall_names(a, out);
            }
        }
        // Leaves.
        ExprIR::Literal { .. }
        | ExprIR::Var { .. }
        | ExprIR::Path { .. }
        | ExprIR::WitnessAccess { .. }
        | ExprIR::Unsupported { .. } => {}
    }
}

fn parse_witness_method(method: &ImplItemFn) -> MidnightResult<WitnessMethodIR> {
    let name = method.sig.ident.clone();
    let (_, params) = parse_fn_params(&method.sig, None)?;
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

fn parse_constructor(method: &ImplItemFn, ctx: &ContractCtx<'_>) -> MidnightResult<ConstructorIR> {
    let name = method.sig.ident.clone();

    // A constructor must produce the ledger state: its return type is
    // `Self` or the ledger struct's name. Anything else would make the
    // generated deploy code call a function that doesn't build the
    // state. Skipped when the ledger failed to parse (that error is
    // already reported).
    if let Some(ledger) = ctx.ledger {
        let returns_ledger = match &method.sig.output {
            ReturnType::Type(_, ty) => {
                if let syn::Type::Path(tp) = &**ty
                    && let Some(seg) = tp.path.segments.last()
                {
                    seg.ident == "Self" || seg.ident == ledger.name
                } else {
                    false
                }
            }
            ReturnType::Default => false,
        };
        if !returns_ledger {
            return Err(MidnightError::new(
                name.span(),
                ErrorCode::InvalidConstructorReturn,
                format!(
                    "constructor `{name}` must return `Self` or `{}` (the ledger struct)",
                    ledger.name
                ),
            ));
        }
    }

    let (witnesses_param, params) = parse_fn_params(&method.sig, ctx.witnesses_struct_name())?;
    let body_ctx = BodyCtx {
        contract: ctx,
        witnesses_param,
        param_types: BodyCtx::param_types_of(&params),
        scrutinee_counter: std::cell::Cell::new(0),
    };
    let body = parse_block_stmts(&method.block, &body_ctx)?;

    Ok(ConstructorIR {
        span: name.span(),
        name,
        params,
        body,
    })
}

fn parse_circuit(method: &ImplItemFn, ctx: &ContractCtx<'_>) -> MidnightResult<CircuitIR> {
    let name = method.sig.ident.clone();
    let (mutates_ledger, takes_witnesses, witnesses_param_name, params) =
        parse_circuit_params(&method.sig, ctx.witnesses_struct_name())?;
    let body_ctx = BodyCtx {
        contract: ctx,
        witnesses_param: witnesses_param_name.clone(),
        param_types: BodyCtx::param_types_of(&params),
        scrutinee_counter: std::cell::Cell::new(0),
    };
    let body = parse_block_stmts(&method.block, &body_ctx)?;
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

fn parse_query(method: &ImplItemFn, ctx: &ContractCtx<'_>) -> MidnightResult<QueryIR> {
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

    let (witnesses_param, params) = parse_fn_params(&method.sig, ctx.witnesses_struct_name())?;
    let body_ctx = BodyCtx {
        contract: ctx,
        witnesses_param,
        param_types: BodyCtx::param_types_of(&params),
        scrutinee_counter: std::cell::Cell::new(0),
    };
    let body = parse_block_stmts(&method.block, &body_ctx)?;
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

/// True when `ty` (after stripping any number of references) is a path
/// type whose last segment is exactly the registered witnesses struct
/// ident. This is the ONLY way a parameter is classified as the
/// witnesses param — no name or substring heuristics.
fn is_witnesses_type(ty: &syn::Type, witnesses_struct: &syn::Ident) -> bool {
    let mut t = ty;
    while let syn::Type::Reference(r) = t {
        t = &r.elem;
    }
    if let syn::Type::Path(tp) = t
        && let Some(seg) = tp.path.segments.last()
    {
        return &seg.ident == witnesses_struct;
    }
    false
}

/// Bit width of a type the IR models as an unsigned integer wire:
/// `u8`..`u128`, `Uint<N>`, and `bool`/`Boolean` (1 bit). `None` for
/// everything else (Field, Bytes<N>, user types) — the caller treats
/// those as "width unknown".
fn type_bit_width(ty: &syn::Type) -> Option<u32> {
    let mut t = ty;
    while let syn::Type::Reference(r) = t {
        t = &r.elem;
    }
    let type_str = quote::quote!(#t).to_string().replace(' ', "");
    match type_str.as_str() {
        "bool" | "Boolean" => Some(1),
        "u8" => Some(8),
        "u16" => Some(16),
        "u32" => Some(32),
        "u64" => Some(64),
        "u128" => Some(128),
        _ => type_str
            .strip_prefix("Uint<")
            .and_then(|rest| rest.strip_suffix('>'))
            .and_then(|n| n.parse::<u32>().ok()),
    }
}

/// Infer the bit width of an already-parsed expression where the
/// declared types make it knowable: int literals, witness reads/calls,
/// typed params, and pure value reads off ledger fields. `None` means
/// "not provable" — the cast rule then only allows widening to u128.
fn infer_expr_width(expr: &ExprIR, ctx: &BodyCtx<'_>) -> Option<u32> {
    match expr {
        ExprIR::Literal { value, .. } => match value {
            LiteralIR::Int(n) => Some((128 - n.leading_zeros()).max(1)),
            LiteralIR::Bool(_) => Some(1),
            LiteralIR::Str(_) => None,
        },
        ExprIR::WitnessAccess { field, .. } => ctx
            .contract
            .witnesses
            .and_then(|w| w.fields.iter().find(|f| f.name == *field))
            .and_then(|f| type_bit_width(&f.ty)),
        ExprIR::WitnessCall { name, .. } => ctx
            .contract
            .witnesses
            .and_then(|w| w.methods.iter().find(|m| m.name == *name))
            .and_then(|m| type_bit_width(&m.return_type)),
        ExprIR::Var { name, .. } => ctx
            .param_types
            .get(&name.to_string())
            .and_then(type_bit_width),
        // `.value()` / `.clone()` / `.into()` on a width-known receiver
        // preserve the value's width.
        ExprIR::MethodCall {
            receiver,
            method,
            args,
            ..
        } if args.is_empty()
            && matches!(method.to_string().as_str(), "value" | "clone" | "into") =>
        {
            infer_expr_width(receiver, ctx)
        }
        // Pure reads off ledger fields: Counter holds a u64; Cell<T>
        // holds a T.
        ExprIR::LedgerAccess { field, method, .. }
            if matches!(
                method.to_string().as_str(),
                "value" | "get" | "__direct_access"
            ) =>
        {
            let f = ctx
                .contract
                .ledger
                .and_then(|l| l.fields.iter().find(|f| f.name == *field))?;
            match &f.type_kind {
                LedgerTypeKind::Counter => Some(64),
                LedgerTypeKind::Cell => cell_inner_type(&f.ty).and_then(|t| type_bit_width(&t)),
                _ => None,
            }
        }
        ExprIR::Reference { expr: inner, .. } | ExprIR::Disclose { value: inner, .. } => {
            infer_expr_width(inner, ctx)
        }
        _ => None,
    }
}

/// Extract `T` from `Cell<T>`.
fn cell_inner_type(ty: &syn::Type) -> Option<syn::Type> {
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
    args.args.iter().find_map(|a| match a {
        syn::GenericArgument::Type(t) => Some(t.clone()),
        _ => None,
    })
}

/// Parse function parameters, skipping `self`. A param whose type
/// resolves to the registered witnesses struct is returned separately
/// (first tuple element) instead of joining the public params.
fn parse_fn_params(
    sig: &syn::Signature,
    witnesses_struct: Option<&syn::Ident>,
) -> MidnightResult<(Option<syn::Ident>, Vec<ParamIR>)> {
    let mut witnesses_param = None;
    let mut params = Vec::new();
    for arg in &sig.inputs {
        if let FnArg::Typed(pat_type) = arg {
            let Pat::Ident(pat_ident) = &*pat_type.pat else {
                // Silently skipping a destructuring pattern would drop
                // the parameter from the circuit's public inputs while
                // the runtime function still takes it.
                return Err(MidnightError::new(
                    pat_type.pat.span(),
                    ErrorCode::UnsupportedExpression,
                    "parameter patterns must be plain identifiers; \
                     destructuring patterns are not supported in nocturne functions",
                ));
            };
            let name = &pat_ident.ident;
            if let Some(w) = witnesses_struct
                && is_witnesses_type(&pat_type.ty, w)
            {
                witnesses_param = Some(name.clone());
                continue;
            }
            params.push(ParamIR {
                span: name.span(),
                name: name.clone(),
                ty: *pat_type.ty.clone(),
            });
        }
    }
    Ok((witnesses_param, params))
}

/// Parse circuit parameters, extracting self receiver info and witness detection.
fn parse_circuit_params(
    sig: &syn::Signature,
    witnesses_struct: Option<&syn::Ident>,
) -> MidnightResult<(bool, bool, Option<syn::Ident>, Vec<ParamIR>)> {
    let mut mutates_ledger = false;

    for arg in &sig.inputs {
        if let FnArg::Receiver(recv) = arg {
            mutates_ledger = recv.mutability.is_some();
        }
    }

    let (witnesses_param_name, params) = parse_fn_params(sig, witnesses_struct)?;
    let takes_witnesses = witnesses_param_name.is_some();

    Ok((
        mutates_ledger,
        takes_witnesses,
        witnesses_param_name,
        params,
    ))
}

/// Validate that every witness read (`WitnessAccess`) and parametric
/// witness call (`WitnessCall`) in the given bodies resolves against
/// the registered witnesses struct. An unresolved node would otherwise
/// reach the emitters, which can't know its wire layout.
fn validate_witness_resolution<'a>(
    witnesses: Option<&WitnessIR>,
    bodies: impl Iterator<Item = &'a [ExprIR]>,
    diagnostics: &mut Diagnostics,
) {
    for body in bodies {
        for stmt in body {
            for_each_expr(stmt, &mut |expr| match expr {
                ExprIR::WitnessAccess { span, field } => {
                    let known = witnesses
                        .map(|w| w.fields.iter().any(|f| f.name == *field))
                        .unwrap_or(false);
                    if !known {
                        let name = witnesses
                            .map(|w| w.name.to_string())
                            .unwrap_or_else(|| "<witnesses>".to_string());
                        diagnostics.push(MidnightError::new(
                            *span,
                            ErrorCode::WitnessTypeMismatch,
                            format!(
                                "unknown witness field `{field}` — `{name}` declares no such field"
                            ),
                        ));
                    }
                }
                ExprIR::WitnessCall { span, name, .. } => {
                    let known = witnesses
                        .map(|w| w.methods.iter().any(|m| m.name == *name))
                        .unwrap_or(false);
                    if !known {
                        let wname = witnesses
                            .map(|w| w.name.to_string())
                            .unwrap_or_else(|| "<witnesses>".to_string());
                        diagnostics.push(MidnightError::new(
                            *span,
                            ErrorCode::WitnessTypeMismatch,
                            format!(
                                "`{name}` is not a parametric witness method on `{wname}`; \
                                 only methods declared in `impl {wname}` can be called on the \
                                 witnesses parameter"
                            ),
                        ));
                    }
                }
                _ => {}
            });
        }
    }
}

/// Depth-first walk over an `ExprIR` tree, calling `f` on every node
/// (including the root).
pub(crate) fn for_each_expr(expr: &ExprIR, f: &mut impl FnMut(&ExprIR)) {
    f(expr);
    match expr {
        ExprIR::BinaryOp { lhs, rhs, .. } => {
            for_each_expr(lhs, f);
            for_each_expr(rhs, f);
        }
        ExprIR::UnaryOp { expr: inner, .. } | ExprIR::Reference { expr: inner, .. } => {
            for_each_expr(inner, f);
        }
        ExprIR::FnCall { args, .. }
        | ExprIR::LedgerAccess { args, .. }
        | ExprIR::WitnessCall { args, .. } => {
            for a in args {
                for_each_expr(a, f);
            }
        }
        ExprIR::MethodCall { receiver, args, .. } => {
            for_each_expr(receiver, f);
            for a in args {
                for_each_expr(a, f);
            }
        }
        ExprIR::Let { value, .. } | ExprIR::Disclose { value, .. } => for_each_expr(value, f),
        ExprIR::If {
            cond,
            then_branch,
            else_branch,
            ..
        } => {
            for_each_expr(cond, f);
            for s in then_branch {
                for_each_expr(s, f);
            }
            if let Some(b) = else_branch {
                for s in b {
                    for_each_expr(s, f);
                }
            }
        }
        ExprIR::Assert { kind, .. } => match kind {
            AssertKind::Assert(e) => for_each_expr(e, f),
            AssertKind::AssertEq(a, b) => {
                for_each_expr(a, f);
                for_each_expr(b, f);
            }
        },
        ExprIR::EnumPayload { scrutinee, .. } => for_each_expr(scrutinee, f),
        ExprIR::Block { stmts, .. } => {
            for s in stmts {
                for_each_expr(s, f);
            }
        }
        ExprIR::StructInit { fields, .. } => {
            for (_, e) in fields {
                for_each_expr(e, f);
            }
        }
        ExprIR::Return { value, .. } => {
            if let Some(v) = value {
                for_each_expr(v, f);
            }
        }
        ExprIR::Tuple { elements, .. } | ExprIR::ArrayLit { elements, .. } => {
            for e in elements {
                for_each_expr(e, f);
            }
        }
        ExprIR::Index { array, .. } => for_each_expr(array, f),
        // Leaves.
        ExprIR::Literal { .. }
        | ExprIR::Var { .. }
        | ExprIR::Path { .. }
        | ExprIR::WitnessAccess { .. }
        | ExprIR::Unsupported { .. } => {}
    }
}

// ---------------------------------------------------------------------------
// Expression tree parsing (syn::Expr -> ExprIR)
// ---------------------------------------------------------------------------

fn parse_block_stmts(block: &syn::Block, ctx: &BodyCtx<'_>) -> MidnightResult<Vec<ExprIR>> {
    let mut exprs = Vec::new();
    for stmt in &block.stmts {
        exprs.push(parse_stmt(stmt, ctx)?);
    }
    Ok(exprs)
}

fn parse_stmt(stmt: &Stmt, ctx: &BodyCtx<'_>) -> MidnightResult<ExprIR> {
    match stmt {
        Stmt::Local(local) => {
            let name = match &local.pat {
                Pat::Ident(pat_ident) => pat_ident.ident.clone(),
                Pat::Type(pat_type) => {
                    if let Pat::Ident(pat_ident) = &*pat_type.pat {
                        pat_ident.ident.clone()
                    } else {
                        return Ok(ExprIR::Unsupported {
                            span: pat_type.pat.span(),
                            description: "complex pattern in let binding".to_string(),
                        });
                    }
                }
                _ => {
                    return Ok(ExprIR::Unsupported {
                        span: local.pat.span(),
                        description: "complex pattern in let binding".to_string(),
                    });
                }
            };

            let value = if let Some(init) = &local.init {
                parse_expr(&init.expr, ctx)?
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
        Stmt::Expr(expr, _semi) => parse_expr(expr, ctx),
        Stmt::Item(item) => Ok(ExprIR::Unsupported {
            span: item.span(),
            description: "item inside function body".to_string(),
        }),
        Stmt::Macro(macro_stmt) => parse_macro_expr(&macro_stmt.mac, ctx),
    }
}

fn parse_expr(expr: &Expr, ctx: &BodyCtx<'_>) -> MidnightResult<ExprIR> {
    match expr {
        Expr::Lit(lit) => {
            if let Some(value) = LiteralIR::from_lit(&lit.lit) {
                Ok(ExprIR::Literal {
                    span: lit.span(),
                    value,
                })
            } else {
                Ok(ExprIR::Unsupported {
                    span: lit.span(),
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
                    span: path.span(),
                    path: path.clone(),
                })
            }
        }

        Expr::Binary(bin) => {
            // Compound assignments would parse into a BinaryOp whose
            // result is silently dropped (the rebinding never happens
            // in the IR), so the circuit and the user's Rust would
            // disagree. Hard error instead.
            use syn::BinOp;
            if matches!(
                bin.op,
                BinOp::AddAssign(_)
                    | BinOp::SubAssign(_)
                    | BinOp::MulAssign(_)
                    | BinOp::DivAssign(_)
                    | BinOp::RemAssign(_)
                    | BinOp::BitXorAssign(_)
                    | BinOp::BitAndAssign(_)
                    | BinOp::BitOrAssign(_)
                    | BinOp::ShlAssign(_)
                    | BinOp::ShrAssign(_)
            ) {
                return Err(MidnightError::new(
                    bin.op.span(),
                    ErrorCode::UnsupportedExpression,
                    "compound assignment operators are not supported in circuits; \
                     rebind with `let x = x + y;` or use ledger methods like `increment_by`",
                ));
            }
            let lhs = parse_expr(&bin.left, ctx)?;
            let rhs = parse_expr(&bin.right, ctx)?;
            Ok(ExprIR::BinaryOp {
                span: bin.op.span(),
                op: bin.op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            })
        }

        Expr::Unary(un) => {
            let inner = parse_expr(&un.expr, ctx)?;
            Ok(ExprIR::UnaryOp {
                span: un.span(),
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
                .map(|a| parse_expr(a, ctx))
                .collect::<MidnightResult<_>>()?;

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

            // Detect `<witnesses_param>.method(args)` — a parametric
            // witness call. The receiver must be exactly the
            // function's witnesses param ident (same shape
            // `WitnessAccess` recognises for field reads). Routes to
            // `WitnessCall` so the codegen treats it as a witness
            // value source (PrivateInput allocation, transcript push),
            // not a regular method call on a Rust value.
            if let Expr::Path(ExprPath {
                path: recv_path, ..
            }) = &**receiver
                && let Some(recv_ident) = recv_path.get_ident()
                && ctx.is_witnesses_receiver(recv_ident)
            {
                return Ok(ExprIR::WitnessCall {
                    span: method.span(),
                    name: method.clone(),
                    args: parsed_args,
                });
            }

            let parsed_receiver = parse_expr(receiver, ctx)?;
            Ok(ExprIR::MethodCall {
                span: method.span(),
                receiver: Box::new(parsed_receiver),
                method: method.clone(),
                args: parsed_args,
            })
        }

        Expr::Field(ExprField { base, member, .. }) => {
            // Detect `<witnesses_param>.field` — exact ident match
            // against the function's witnesses param.
            if let Expr::Path(ExprPath { path, .. }) = &**base
                && let Some(ident) = path.get_ident()
                && ctx.is_witnesses_receiver(ident)
                && let syn::Member::Named(field_name) = member
            {
                return Ok(ExprIR::WitnessAccess {
                    span: field_name.span(),
                    field: field_name.clone(),
                });
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
            let parsed_base = parse_expr(base, ctx)?;
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
            let parsed_args: Vec<ExprIR> = args
                .iter()
                .map(|a| parse_expr(a, ctx))
                .collect::<MidnightResult<_>>()?;

            // Extract function name.
            if let Expr::Path(ExprPath { path, .. }) = &**func {
                let func_name = path
                    .segments
                    .last()
                    .map(|s| s.ident.clone())
                    .unwrap_or_else(|| syn::Ident::new("unknown", Span::call_site()));

                // Detect the disclose builtin — exact path match only
                // (`disclose` or `nocturne::disclose`), so a user
                // helper like `disclose_amount(a, b)` is NOT hijacked
                // (and its extra args NOT dropped).
                let full_path = quote::quote!(#path).to_string().replace(' ', "");
                if full_path == "disclose" || full_path == "nocturne::disclose" {
                    if parsed_args.len() != 1 {
                        return Err(MidnightError::new(
                            func_name.span(),
                            ErrorCode::UnsupportedExpression,
                            format!(
                                "disclose() takes exactly one argument, got {}",
                                parsed_args.len()
                            ),
                        ));
                    }
                    let arg = parsed_args.into_iter().next().expect("checked len == 1");
                    return Ok(ExprIR::Disclose {
                        span: func_name.span(),
                        value: Box::new(arg),
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
                span: expr.span(),
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
                // The key is parsed once and cloned so the contains and
                // the lookup share an identical tree.
                let key = parse_expr(key_expr, ctx)?;
                let contains = ExprIR::LedgerAccess {
                    span: expr_if.cond.span(),
                    field: map_field.clone(),
                    method: syn::Ident::new("contains", Span::call_site()),
                    args: vec![key.clone()],
                };
                let lookup = ExprIR::LedgerAccess {
                    span: expr_if.cond.span(),
                    field: map_field,
                    method: syn::Ident::new("lookup", Span::call_site()),
                    args: vec![key],
                };
                let let_stmt = ExprIR::Let {
                    span: var_name.span(),
                    name: var_name,
                    value: Box::new(lookup),
                };
                let mut then_branch = vec![let_stmt];
                then_branch.extend(parse_block_stmts(&expr_if.then_branch, ctx)?);
                let else_branch = if let Some((_, else_expr)) = &expr_if.else_branch {
                    match &**else_expr {
                        Expr::Block(block) => Some(parse_block_stmts(&block.block, ctx)?),
                        other => Some(vec![parse_expr(other, ctx)?]),
                    }
                } else {
                    None
                };
                return Ok(ExprIR::If {
                    span: expr_if.if_token.span(),
                    cond: Box::new(contains),
                    then_branch,
                    else_branch,
                });
            }

            let cond = parse_expr(&expr_if.cond, ctx)?;
            let then_branch = parse_block_stmts(&expr_if.then_branch, ctx)?;
            let else_branch = if let Some((_, else_expr)) = &expr_if.else_branch {
                match &**else_expr {
                    Expr::Block(block) => Some(parse_block_stmts(&block.block, ctx)?),
                    other => Some(vec![parse_expr(other, ctx)?]),
                }
            } else {
                None
            };

            Ok(ExprIR::If {
                span: expr_if.if_token.span(),
                cond: Box::new(cond),
                then_branch,
                else_branch,
            })
        }

        Expr::Block(block) => {
            let stmts = parse_block_stmts(&block.block, ctx)?;
            Ok(ExprIR::Block {
                span: block.span(),
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
                let key = parse_expr(key_expr, ctx)?;
                let contains = ExprIR::LedgerAccess {
                    span: expr_match.expr.span(),
                    field: map_field.clone(),
                    method: syn::Ident::new("contains", Span::call_site()),
                    args: vec![key.clone()],
                };
                let lookup = ExprIR::LedgerAccess {
                    span: expr_match.expr.span(),
                    field: map_field,
                    method: syn::Ident::new("lookup", Span::call_site()),
                    args: vec![key],
                };
                let let_stmt = ExprIR::Let {
                    span: var_name.span(),
                    name: var_name,
                    value: Box::new(lookup),
                };
                let mut then_branch = vec![let_stmt];
                then_branch.extend(parse_arm_body(some_body, ctx)?);
                let else_branch = Some(parse_arm_body(none_body, ctx)?);

                return Ok(ExprIR::If {
                    span: expr_match.match_token.span(),
                    cond: Box::new(contains),
                    then_branch,
                    else_branch,
                });
            }
            // Otherwise, fall through to the generic enum-match
            // lowering — handles user enums and stdlib `Option<T>`
            // alike via discriminant comparisons.
            if let Some(chain) = lower_enum_match(expr_match, ctx)? {
                return Ok(chain);
            }
            Ok(ExprIR::Unsupported {
                span: expr_match.match_token.span(),
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
                    let value = parse_expr(&f.expr, ctx)?;
                    Ok((field_name, value))
                })
                .collect::<MidnightResult<Vec<_>>>()?;

            Ok(ExprIR::StructInit {
                span: s.span(),
                name,
                fields,
            })
        }

        Expr::Return(ret) => {
            let value = if let Some(expr) = &ret.expr {
                Some(Box::new(parse_expr(expr, ctx)?))
            } else {
                None
            };
            Ok(ExprIR::Return {
                span: ret.span(),
                value,
            })
        }

        Expr::Tuple(tuple) => {
            let elements = tuple
                .elems
                .iter()
                .map(|e| parse_expr(e, ctx))
                .collect::<MidnightResult<_>>()?;
            Ok(ExprIR::Tuple {
                span: tuple.span(),
                elements,
            })
        }

        Expr::Array(array) => {
            let elements = array
                .elems
                .iter()
                .map(|e| parse_expr(e, ctx))
                .collect::<MidnightResult<_>>()?;
            Ok(ExprIR::ArrayLit {
                span: array.span(),
                elements,
            })
        }

        Expr::Reference(r) => {
            let inner = parse_expr(&r.expr, ctx)?;
            Ok(ExprIR::Reference {
                span: r.span(),
                expr: Box::new(inner),
            })
        }

        Expr::Paren(p) => parse_expr(&p.expr, ctx),

        Expr::Macro(m) => parse_macro_expr(&m.mac, ctx),

        Expr::While(_) | Expr::Loop(_) => Ok(ExprIR::Unsupported {
            span: expr.span(),
            description: "while/loop not supported in circuits (use for with const bounds)"
                .to_string(),
        }),

        Expr::ForLoop(for_expr) => parse_const_for_loop(for_expr, ctx),

        // `x as u64` — Nocturne treats the cast as transparent for IR
        // purposes (the wire-side encoding is determined by the
        // surrounding consumer's expected type, not by the cast
        // itself). That is only sound when the cast cannot narrow: a
        // Rust-side truncation the circuit doesn't model would make
        // the proof and the runtime disagree. The cast stays
        // transparent when the source's bit width is inferable and
        // <= the target width, or when the target is u128 (nothing
        // the IR models exceeds 128 bits); everything else errors.
        Expr::Cast(c) => {
            let inner = parse_expr(&c.expr, ctx)?;
            let target = type_bit_width(&c.ty);
            let source = infer_expr_width(&inner, ctx);
            let ty = &c.ty;
            let target_str = quote::quote!(#ty).to_string().replace(' ', "");
            match (source, target) {
                (Some(s), Some(t)) if s <= t => Ok(inner),
                (Some(s), Some(t)) => Err(MidnightError::new(
                    c.as_token.span(),
                    ErrorCode::UnsupportedExpression,
                    format!(
                        "narrowing `as` cast: the source is {s} bits wide but `{target_str}` \
                         is only {t} bits. Nocturne casts are transparent on the wire, so the \
                         circuit would not perform the truncation the Rust code performs"
                    ),
                )),
                (None, Some(t)) if t >= 128 => Ok(inner),
                (None, Some(_)) => Err(MidnightError::new(
                    c.as_token.span(),
                    ErrorCode::UnsupportedExpression,
                    format!(
                        "cannot prove this `as {target_str}` cast is non-narrowing: the \
                         source expression's bit width is not inferable. Bind the value with \
                         a typed source (witness field, typed param, literal) or cast to u128"
                    ),
                )),
                (_, None) => Err(MidnightError::new(
                    c.as_token.span(),
                    ErrorCode::UnsupportedExpression,
                    format!(
                        "unsupported `as` cast target `{target_str}`; \
                         only u8, u16, u32, u64, and u128 are supported"
                    ),
                )),
            }
        }

        // `arr[idx]` — only const integer literal indices (`arr[0]`,
        // `arr[1]`, ...). After `parse_const_for_loop` unrolls a const
        // for-loop, the loop variable substitutes to a literal int, so
        // `arr[i]` inside `for i in 0..N { ... }` parses to this arm.
        // Non-literal indices return Unsupported and surface as a
        // compile_error pointing at the call site.
        Expr::Index(idx) => {
            let array = parse_expr(&idx.expr, ctx)?;
            let index_expr: &Expr = &idx.index;
            if let Expr::Lit(lit) = index_expr
                && let syn::Lit::Int(int) = &lit.lit
                && let Ok(n) = int.base10_parse::<u32>()
            {
                Ok(ExprIR::Index {
                    span: idx.span(),
                    array: Box::new(array),
                    index: n,
                })
            } else {
                Ok(ExprIR::Unsupported {
                    span: index_expr.span(),
                    description: format!(
                        "array index must be a compile-time integer literal (got `{}`); \
                         use a `for i in 0..N` loop so the index unrolls to a literal",
                        quote::quote!(#index_expr)
                    ),
                })
            }
        }

        _ => Ok(ExprIR::Unsupported {
            span: expr.span(),
            description: format!("unsupported expression: {}", quote::quote!(#expr)),
        }),
    }
}

fn parse_macro_expr(mac: &syn::Macro, ctx: &BodyCtx<'_>) -> MidnightResult<ExprIR> {
    let path = &mac.path;
    let path_str = quote::quote!(#path).to_string().replace(' ', "");
    let tokens = &mac.tokens;

    let mac_span = mac.path.span();
    if path_str == "assert" || path_str.ends_with("::assert") {
        // `assert!(cond)` or `assert!(cond, "msg", ...)`. The message
        // is informational only — we only enforce the condition. Drop
        // any extra args after the first.
        let args: syn::punctuated::Punctuated<Expr, syn::Token![,]> =
            syn::punctuated::Punctuated::parse_terminated
                .parse2(tokens.clone())
                .map_err(|e| {
                    MidnightError::new(
                        mac_span,
                        ErrorCode::UnsupportedExpression,
                        format!("failed to parse assert arguments: {e}"),
                    )
                })?;
        let cond = args.into_iter().next().ok_or_else(|| {
            MidnightError::new(
                mac_span,
                ErrorCode::UnsupportedExpression,
                "assert! requires a condition argument",
            )
        })?;
        Ok(ExprIR::Assert {
            span: mac_span,
            kind: AssertKind::Assert(Box::new(parse_expr(&cond, ctx)?)),
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
                        mac_span,
                        ErrorCode::UnsupportedExpression,
                        format!("failed to parse assert_eq arguments: {e}"),
                    )
                })?;

        let mut iter = args.into_iter();
        let a = iter.next().ok_or_else(|| {
            MidnightError::new(
                mac_span,
                ErrorCode::UnsupportedExpression,
                "assert_eq! requires two arguments",
            )
        })?;
        let b = iter.next().ok_or_else(|| {
            MidnightError::new(
                mac_span,
                ErrorCode::UnsupportedExpression,
                "assert_eq! requires two arguments",
            )
        })?;

        Ok(ExprIR::Assert {
            span: mac_span,
            kind: AssertKind::AssertEq(
                Box::new(parse_expr(&a, ctx)?),
                Box::new(parse_expr(&b, ctx)?),
            ),
        })
    } else {
        // Carry the macro's own span so the diagnostic points at the
        // call site.
        Ok(ExprIR::Unsupported {
            span: mac_span,
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
fn lower_enum_match(
    expr_match: &syn::ExprMatch,
    ctx: &BodyCtx<'_>,
) -> MidnightResult<Option<ExprIR>> {
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
                // Catch-all identifier (no `@` sub-pattern) acts as a
                // wildcard — EXCEPT when the ident is itself a known
                // enum variant name (glob-imported `use Status::*`
                // style). Rust would match that as the variant; the
                // wildcard lowering would silently match everything.
                // `Some`/`None` are exempt: the Option lowering treats
                // a bare `None` arm as the catch-all it is.
                let ident_str = pi.ident.to_string();
                if ident_str != "Some"
                    && ident_str != "None"
                    && let Some((enum_name, _)) = ctx
                        .contract
                        .user_enums
                        .iter()
                        .find(|(_, vs)| vs.iter().any(|v| v.name == pi.ident))
                {
                    return Err(MidnightError::new(
                        pi.ident.span(),
                        ErrorCode::UnsupportedExpression,
                        format!(
                            "match arm pattern `{ident_str}` is a bare identifier and would \
                             lower to a catch-all, but `{enum_name}::{ident_str}` is an enum \
                             variant; qualify it as `{enum_name}::{ident_str}`"
                        ),
                    ));
                }
                shapes.push((ArmShape::Wild, arm.body.as_ref()));
            }
            _ => return Ok(None),
        }
    }
    let scrutinee = parse_expr(&expr_match.expr, ctx)?;

    // H2: bind an effectful scrutinee ONCE. The if-chain below clones
    // the scrutinee into every arm's discriminant comparison (and
    // payload projection); for a `WitnessCall` scrutinee each clone
    // would be a fresh, unconstrained-against-each-other witness draw —
    // the arms could each see a different value. Pure reads (vars,
    // witness/ledger field reads, paths) are left in place: they're
    // cached/idempotent in both emitters, and the transcript codegen
    // resolves their enum handling from the access shape itself.
    let mut scrutinee_binding: Option<ExprIR> = None;
    let scrutinee = if contains_witness_call(&scrutinee) {
        let span = expr_match.expr.span();
        let ident = ctx.fresh_scrutinee_ident(span);
        scrutinee_binding = Some(ExprIR::Let {
            span,
            name: ident.clone(),
            value: Box::new(scrutinee),
        });
        ExprIR::Var { span, name: ident }
    } else {
        scrutinee
    };

    // Find the wildcard arm if any; it becomes the final else branch.
    // Without a wildcard the innermost `if` simply has no else — every
    // variant arm gets its own discriminant comparison (the user is
    // responsible for exhaustiveness, which Rust already enforces on
    // the original match).
    let wild_idx = shapes.iter().position(|(s, _)| matches!(s, ArmShape::Wild));
    type VariantArm<'a> = (&'a syn::Path, Option<syn::Ident>, &'a syn::Expr);
    let (variant_arms, default_body): (Vec<VariantArm<'_>>, Option<Vec<ExprIR>>) =
        if let Some(idx) = wild_idx {
            let default_body = parse_arm_body(shapes[idx].1, ctx)?;
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
                span: binding.span(),
                name: binding.clone(),
                value: Box::new(ExprIR::EnumPayload {
                    span: binding.span(),
                    scrutinee: Box::new(scrutinee.clone()),
                    enum_name,
                }),
            });
        }
        then_branch.extend(parse_arm_body(body, ctx)?);
        let cond = ExprIR::BinaryOp {
            span: path.span(),
            op: syn::BinOp::Eq(syn::token::EqEq(Span::call_site())),
            lhs: Box::new(scrutinee.clone()),
            rhs: Box::new(ExprIR::Path {
                span: path.span(),
                path: (*path).clone(),
            }),
        };
        let if_expr = ExprIR::If {
            span: expr_match.match_token.span(),
            cond: Box::new(cond),
            then_branch,
            else_branch: else_branch.take(),
        };
        else_branch = Some(vec![if_expr]);
    }
    // `else_branch` now holds a single-element vec with the outermost If.
    let chain = else_branch.and_then(|mut v| v.pop());
    match (scrutinee_binding, chain) {
        (Some(binding), Some(chain)) => Ok(Some(ExprIR::Block {
            span: expr_match.match_token.span(),
            stmts: vec![binding, chain],
        })),
        (_, chain) => Ok(chain),
    }
}

/// True when the expression tree contains a parametric witness call —
/// the one IR node whose every evaluation draws a fresh witness value.
fn contains_witness_call(expr: &ExprIR) -> bool {
    let mut found = false;
    for_each_expr(expr, &mut |e| {
        if matches!(e, ExprIR::WitnessCall { .. }) {
            found = true;
        }
    });
    found
}

/// Parse a match arm's body, which is either a block or a bare expression.
fn parse_arm_body(body: &Expr, ctx: &BodyCtx<'_>) -> MidnightResult<Vec<ExprIR>> {
    match body {
        Expr::Block(b) => parse_block_stmts(&b.block, ctx),
        other => Ok(vec![parse_expr(other, ctx)?]),
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
fn parse_const_for_loop(for_expr: &syn::ExprForLoop, ctx: &BodyCtx<'_>) -> MidnightResult<ExprIR> {
    let Pat::Ident(pat) = &*for_expr.pat else {
        return Ok(ExprIR::Unsupported {
            span: for_expr.pat.span(),
            description: "for-loop pattern must be a single identifier".to_string(),
        });
    };
    let loop_var = pat.ident.clone();

    let Expr::Range(range) = &*for_expr.expr else {
        return Ok(ExprIR::Unsupported {
            span: for_expr.expr.span(),
            description: "for-loop iterator must be a literal `<lit>..<lit>` range".to_string(),
        });
    };
    let Some(start_expr) = &range.start else {
        return Ok(ExprIR::Unsupported {
            span: range.span(),
            description: "for-loop range must have an explicit lower bound".to_string(),
        });
    };
    let Some(end_expr) = &range.end else {
        return Ok(ExprIR::Unsupported {
            span: range.span(),
            description: "for-loop range must have an explicit upper bound".to_string(),
        });
    };
    let start = parse_int_literal(start_expr).ok_or_else(|| {
        MidnightError::new(
            start_expr.span(),
            ErrorCode::UnsupportedExpression,
            "for-loop lower bound must be an integer literal",
        )
    })?;
    let end = parse_int_literal(end_expr).ok_or_else(|| {
        MidnightError::new(
            end_expr.span(),
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
            span: for_expr.for_token.span(),
            stmts: Vec::new(),
        });
    }

    // Cap the unroll: every iteration is a full copy of the body in
    // the circuit, so a huge bound would explode constraint count and
    // compile time long before anything useful happens.
    const MAX_UNROLL: u64 = 1024;
    let count = (last - start).saturating_add(1);
    if count > MAX_UNROLL {
        return Err(MidnightError::new(
            for_expr.for_token.span(),
            ErrorCode::UnsupportedLoop,
            format!(
                "for-loop unrolls to {count} iterations, exceeding the {MAX_UNROLL}-iteration \
                 cap; restructure the circuit to do less work per proof"
            ),
        ));
    }

    let mut iterations: Vec<ExprIR> = Vec::new();
    let mut i = start;
    loop {
        let mut body = for_expr.body.clone();
        substitute_ident_with_int(&mut body, &loop_var, i);
        let stmts = parse_block_stmts(&body, ctx)?;
        iterations.push(ExprIR::Block {
            span: for_expr.for_token.span(),
            stmts,
        });
        if i == last {
            break;
        }
        i += 1;
    }

    Ok(ExprIR::Block {
        span: for_expr.for_token.span(),
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
