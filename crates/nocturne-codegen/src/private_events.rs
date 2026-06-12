//! The canonical walk over a circuit body that defines the ordered
//! sequence of *private-input events* — the single source of truth both
//! sides of the private transcript derive from:
//!
//! - The ZKIR emitter allocates `PrivateInput`s in this order
//!   (`zkir_emitter::emit_expr`'s recursion visits sub-expressions in
//!   exactly this order; the parity is asserted by the tests in this
//!   module).
//! - The transcript codegen emits its `private_transcript` /
//!   `private_transcript_outputs` pushes at each event's walk position
//!   (see `transcript_codegen::private_event_pushes`).
//!
//! An event is either:
//!
//! - **FieldTouch**: the FIRST touch of a witness *field*. The emitter
//!   caches the field's wires on first unguarded touch, so later touches
//!   allocate nothing and the builder must push nothing. First touches
//!   inside a conditional branch allocate guarded wires that are NOT
//!   cached — a second touch of such a field anywhere is rejected by the
//!   emitter, so the tracker only has to mirror that semantics, not
//!   recover from it.
//! - **Call**: a parametric witness call (`witnesses.method(args)`),
//!   one event per call site (no caching, by design).

use std::collections::{HashMap, HashSet};

use nocturne_ir::expr::AssertKind;
use nocturne_ir::{ExprIR, UserStructField};

/// One private-input event in IR walk order.
pub(crate) enum PrivateEvent<'a> {
    /// First touch of a witness field.
    FieldTouch { field: &'a syn::Ident },
    /// A parametric witness call site.
    Call {
        name: &'a syn::Ident,
        args: &'a [ExprIR],
    },
}

/// Mirrors the emitter's witness-field cache semantics
/// (`zkir_emitter`'s `variables["witness.<f>"]` cache plus its
/// `guarded_witness_fields` set):
///
/// - first touch with no active branch guard → event, cached;
/// - first touch inside a branch → event, NOT cached (the emitter
///   rejects any later touch of the same field, so suppressing the
///   would-be duplicate event here keeps the builder consistent with
///   the single allocation the emitter performed before erroring);
/// - any later touch of a cached field → no event.
#[derive(Default)]
pub(crate) struct FirstTouchTracker {
    seen: HashSet<String>,
    guarded: HashSet<String>,
    pub(crate) in_branch: bool,
}

impl FirstTouchTracker {
    /// Record a touch of `field`; returns true when this touch is the
    /// allocating one (i.e. the builder must push the field's value).
    pub(crate) fn touch(&mut self, field: &str) -> bool {
        if self.seen.contains(field) || self.guarded.contains(field) {
            return false;
        }
        if self.in_branch {
            self.guarded.insert(field.to_string());
        } else {
            self.seen.insert(field.to_string());
        }
        true
    }
}

/// Walk `expr` in the ZKIR emitter's evaluation order, reporting each
/// private-input event to `visit`. `user_structs` is needed because the
/// emitter evaluates `StructInit` fields in *declared* order, not
/// textual order.
pub(crate) fn walk_expr_events<'a>(
    expr: &'a ExprIR,
    user_structs: &HashMap<String, Vec<UserStructField>>,
    tracker: &mut FirstTouchTracker,
    visit: &mut dyn FnMut(&mut FirstTouchTracker, PrivateEvent<'a>),
) {
    match expr {
        ExprIR::WitnessAccess { field, .. } => {
            if tracker.touch(&field.to_string()) {
                visit(tracker, PrivateEvent::FieldTouch { field });
            }
        }
        // Args are evaluated first (each may carry witness reads), then
        // the call itself allocates a fresh PrivateInput block — same
        // order as the emitter's `WitnessCall` arm.
        ExprIR::WitnessCall { name, args, .. } => {
            for a in args {
                walk_expr_events(a, user_structs, tracker, visit);
            }
            visit(tracker, PrivateEvent::Call { name, args });
        }
        // Every ledger method evaluates its args left to right before
        // emitting the transcript-op instructions (key before value for
        // `Map::insert`), matching `emit_map_method`/`emit_set_method`/
        // `emit_merkle_tree_method` and the Cell/Counter arms.
        ExprIR::LedgerAccess { args, .. } => {
            for a in args {
                walk_expr_events(a, user_structs, tracker, visit);
            }
        }
        // Builtins (`persistent_hash`, `merkle_tree_path_root`),
        // wrapper constructors (`Uint::<N>::from`), and inlined helpers
        // all evaluate their args left to right; helper bodies cannot
        // touch witnesses (free `fn`s have no `witnesses` receiver).
        ExprIR::FnCall { args, .. } => {
            for a in args {
                walk_expr_events(a, user_structs, tracker, visit);
            }
        }
        ExprIR::MethodCall { receiver, args, .. } => {
            walk_expr_events(receiver, user_structs, tracker, visit);
            for a in args {
                walk_expr_events(a, user_structs, tracker, visit);
            }
        }
        ExprIR::BinaryOp { lhs, rhs, .. } => {
            walk_expr_events(lhs, user_structs, tracker, visit);
            walk_expr_events(rhs, user_structs, tracker, visit);
        }
        ExprIR::UnaryOp { expr: inner, .. }
        | ExprIR::Reference { expr: inner, .. }
        | ExprIR::Disclose { value: inner, .. } => {
            walk_expr_events(inner, user_structs, tracker, visit);
        }
        ExprIR::Let { value, .. } => {
            walk_expr_events(value, user_structs, tracker, visit);
        }
        ExprIR::Block { stmts, .. } => {
            for s in stmts {
                walk_expr_events(s, user_structs, tracker, visit);
            }
        }
        ExprIR::Assert { kind, .. } => match kind {
            AssertKind::Assert(cond) => walk_expr_events(cond, user_structs, tracker, visit),
            AssertKind::AssertEq(a, b) => {
                walk_expr_events(a, user_structs, tracker, visit);
                walk_expr_events(b, user_structs, tracker, visit);
            }
        },
        // The condition is evaluated BEFORE the branch guard activates
        // (so its witness reads are unguarded and cached); the branch
        // bodies are evaluated with the guard active.
        ExprIR::If {
            cond,
            then_branch,
            else_branch,
            ..
        } => {
            walk_expr_events(cond, user_structs, tracker, visit);
            let outer = tracker.in_branch;
            tracker.in_branch = true;
            for s in then_branch {
                walk_expr_events(s, user_structs, tracker, visit);
            }
            if let Some(else_stmts) = else_branch {
                for s in else_stmts {
                    walk_expr_events(s, user_structs, tracker, visit);
                }
            }
            tracker.in_branch = outer;
        }
        ExprIR::EnumPayload { scrutinee, .. } => {
            walk_expr_events(scrutinee, user_structs, tracker, visit);
        }
        ExprIR::Index { array, .. } => {
            walk_expr_events(array, user_structs, tracker, visit);
        }
        ExprIR::Tuple { elements, .. } | ExprIR::ArrayLit { elements, .. } => {
            for e in elements {
                walk_expr_events(e, user_structs, tracker, visit);
            }
        }
        // The emitter evaluates struct-literal fields in DECLARED order
        // (falling back to textual order when the struct isn't
        // registered) — mirror that exactly.
        ExprIR::StructInit { name, fields, .. } => match user_structs.get(&name.to_string()) {
            Some(decl) => {
                for f in decl {
                    if let Some((_, e)) = fields.iter().find(|(fname, _)| fname == &f.name) {
                        walk_expr_events(e, user_structs, tracker, visit);
                    }
                }
            }
            None => {
                for (_, e) in fields {
                    walk_expr_events(e, user_structs, tracker, visit);
                }
            }
        },
        ExprIR::Return { value, .. } => {
            if let Some(v) = value {
                walk_expr_events(v, user_structs, tracker, visit);
            }
        }
        ExprIR::Literal { .. }
        | ExprIR::Var { .. }
        | ExprIR::Path { .. }
        | ExprIR::Unsupported { .. } => {}
    }
}

/// Owned form of an event, for tests: what fired and whether a branch
/// guard was active at the event's position.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RecordedEvent {
    pub(crate) name: String,
    pub(crate) is_call: bool,
    pub(crate) in_branch: bool,
}

/// Collect the full ordered event sequence for a circuit body.
#[cfg(test)]
pub(crate) fn body_private_events(
    body: &[ExprIR],
    user_structs: &HashMap<String, Vec<UserStructField>>,
) -> Vec<RecordedEvent> {
    let mut tracker = FirstTouchTracker::default();
    let mut events = Vec::new();
    for stmt in body {
        walk_expr_events(stmt, user_structs, &mut tracker, &mut |t, ev| {
            events.push(match ev {
                PrivateEvent::FieldTouch { field } => RecordedEvent {
                    name: field.to_string(),
                    is_call: false,
                    in_branch: t.in_branch,
                },
                PrivateEvent::Call { name, .. } => RecordedEvent {
                    name: name.to_string(),
                    is_call: true,
                    in_branch: t.in_branch,
                },
            });
        });
    }
    events
}
