//! ZKIR emitter: converts CircuitIR into midnight_zkir::ir::IrSource.
//!
//! ## How ZKIR works in Midnight
//!
//! The ZKIR circuit does NOT encode "circuit logic" in the traditional sense.
//! Instead, it encodes the **transcript VM program** as public inputs and
//! proves that the prover's private computation is consistent with those
//! public inputs.
//!
//! Each VM operation's field representation (`FieldRepr`) becomes a sequence
//! of `DeclarePubInput` instructions in the ZKIR. The on-chain verifier
//! reconstructs the public inputs from the submitted transcript and checks
//! that the proof matches.
//!
//! ### VM opcode → ZKIR encoding pattern:
//!
//! For a VM op like `Dup { n: 0 }` (field repr = 0x30):
//! ```text
//! load_imm 0x30           // the opcode as a field element
//! declare_pub_input var:X  // add it to public inputs
//! pi_skip guard:G count:1  // group marker
//! ```
//!
//! For `Idx { cached: false, push_path: false, path: [value(0)] }` (field repr = 0x50, key):
//! ```text
//! load_imm 0x50            // opcode
//! declare_pub_input var:X1  // opcode field
//! declare_pub_input var:G   // guard/padding
//! declare_pub_input var:G   // guard/padding
//! declare_pub_input var:K   // key value
//! pi_skip guard:G count:4   // group marker
//! ```

use crate::containers::{
    extract_cell_inner_type, extract_map_kv_types, extract_merkle_tree_type, extract_set_inner_type,
};
use crate::nocturne_type::{
    AlignedEncoding as AlignedValueEncoding, FR_BYTES_STORED, FrLayout, TypeCtx, bytes_n_layout,
    resolve,
};
use crate::typing::{is_transparent_wrapper, parse_uint_type};
use midnight_transient_crypto::curve::Fr;
use midnight_zkir::{Instruction, IrSource};
use nocturne_ir::expr::{AssertKind, LiteralIR};
use nocturne_ir::{CircuitIR, ContractIR, ExprIR};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

type Index = u32;

/// ZKIR format version `(major, minor)` stamped into every emitted
/// `.zkir` artifact. `IrSource::load()` requires a `version` field but
/// `IrSource` itself doesn't serialize one, so the writer (the
/// `#[nocturne::contract]` macro) splices this in. Lives here, next to
/// the `IrSource` construction, because it must track the opcode set
/// this emitter targets: bump it when the emitter moves to a new
/// upstream ZKIR revision, not independently.
pub const ZKIR_VERSION: (u64, u64) = (2, 0);

/// Result of ZKIR emission for a single circuit.
pub struct ZkirOutput {
    pub circuit_name: String,
    pub ir_source: IrSource,
    /// Instruction-index ranges of conditional branch bodies, in
    /// emission order (then-branch and else-branch each get their own
    /// span; nested branches nest). Ground-truth metadata for the
    /// structural-invariant tests: an instruction is "inside a
    /// conditional" iff its position falls in one of these spans, so
    /// the tests can assert every `PrivateInput`/`PublicInput` emitted
    /// there carries `guard: Some(_)` (an unguarded read inside a branch
    /// would consume a transcript entry the runtime builder never
    /// produces on the inactive path; midnight-ledger ledger-8,
    /// zkir/src/ir_vm.rs:325-355). Not part of the `.zkir` artifact.
    pub branch_spans: Vec<std::ops::Range<usize>>,
}

/// Result of full contract emission.
pub struct ContractZkirOutput {
    pub circuits: Vec<ZkirOutput>,
    /// Emission errors collected across all circuits. Non-empty means
    /// at least one circuit's ZKIR is incomplete or wrong — callers
    /// (`generate_artifacts` → the proc macro) MUST fail compilation
    /// instead of using the circuits. Emitting a circuit that silently
    /// drops a construct (worst case: an `assert!`) produces a proof
    /// that verifies while enforcing less than the contract source.
    pub errors: Vec<String>,
}

/// Emit ZKIR for all circuits in a contract.
pub fn emit_contract(contract: &ContractIR) -> ContractZkirOutput {
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

    // Collect witness field types for type constraints on PrivateInput.
    let witness_types: HashMap<String, syn::Type> = contract
        .witnesses
        .as_ref()
        .map(|w| {
            w.fields
                .iter()
                .map(|f| (f.name.to_string(), f.ty.clone()))
                .collect()
        })
        .unwrap_or_default();
    // Parametric witness methods: name → return type. Each `WitnessCall`
    // emit allocates PrivateInputs sized by this return type's layout.
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
    // Inlinable helpers: name → full HelperIR (params, return type,
    // body). When the FnCall emit arm sees a name in this table it
    // splices the body into the call site rather than returning a
    // wrong wire.
    let helpers: HashMap<String, nocturne_ir::HelperIR> = contract
        .helpers
        .iter()
        .map(|h| (h.name.to_string(), h.clone()))
        .collect();

    let mut circuits = Vec::with_capacity(contract.circuits.len());
    let mut errors = Vec::new();
    for circuit in &contract.circuits {
        let mut emitter = ZkirEmitter::new(
            &field_names,
            &field_types,
            &witness_types,
            &witness_methods,
            &helpers,
            &contract.user_structs,
            &contract.user_enums,
        );
        let output = emitter.emit_circuit(circuit);
        errors.extend(
            emitter
                .errors
                .drain(..)
                .map(|e| format!("circuit `{}`: {e}", circuit.name)),
        );
        circuits.push(output);
    }

    ContractZkirOutput { circuits, errors }
}

struct ZkirEmitter {
    instructions: Vec<Instruction>,
    next_index: Index,
    variables: HashMap<String, Index>,
    /// Type tag for let-bound names whose RHS shape is known. Lets
    /// `ExprIR::Index` look up the element width when its `array`
    /// source is a `Var` (e.g. `let arr = self.cell.get(); arr[i]`).
    /// Missing entries mean "type is not inferable from the IR" — the
    /// indexing call falls back to the unsupported path.
    variable_types: HashMap<String, syn::Type>,
    num_inputs: u32,
    guard: Index,
    /// True when emitting inside a conditional branch. `DeclarePubInput`
    /// values must be multiplexed against zero via `CondSelect(guard, value, 0)`
    /// so the inactive-branch slot is zero — matching `Op::Noop`'s zero
    /// `field_repr` that the ledger interleaves at verify time
    /// (midnight-ledger ledger-8: `ContractCall::prove` splices
    /// `Op::Noop { n }` over inactive segments, ledger/src/prove.rs:263-289,
    /// and Noop field_reprs as `n` zeros, onchain-vm/src/ops.rs:403).
    /// The zeroing must happen at emit time because `DeclarePubInput`
    /// pushes `memory[var]` unconditionally (zkir/src/ir_vm.rs:339-342).
    in_conditional: bool,
    /// Cached `LoadImm 0` to avoid re-emitting for every guarded declare.
    zero_var: Option<Index>,
    field_names: Vec<String>,
    /// Ledger field types, parallel-indexed with `field_names`. Used to
    /// dispatch on the inner type of `Cell<T>`/`Map<K, V>`/etc. when
    /// emitting StateValue encodings.
    field_types: Vec<syn::Type>,
    /// Witness field name → type, for emitting type constraints on PrivateInput.
    witness_types: HashMap<String, syn::Type>,
    /// Parametric witness method name → return type. Each `WitnessCall`
    /// allocates fresh `PrivateInput`s sized by this type's wire layout.
    witness_methods: HashMap<String, syn::Type>,
    /// Helper functions inlinable at each call site (compactc's model
    /// per `LFDT-Minokawa/compact:compiler/circuit-passes.ss`). Lookup
    /// by the call's last-segment name; on a hit the body is
    /// alpha-renamed and emitted in place. Acyclicity is the parser's
    /// responsibility (`validate_helpers_acyclic` in nocturne-ir).
    helpers: HashMap<String, nocturne_ir::HelperIR>,
    /// Per-circuit counter used to generate fresh names for helper
    /// param + let bindings during inlining. Increments on every
    /// helper call so nested and repeated inlines never collide.
    helper_counter: u32,
    /// User-defined struct definitions (name → fields in declaration
    /// order). Lets `Map<MyStruct, _>` / `Set<MyStruct>` etc. layout the
    /// struct as a tuple-of-fields for alignment + witness expansion.
    user_structs: HashMap<String, Vec<nocturne_ir::UserStructField>>,
    /// User-defined unit-variant enums (name → variants). Encoded
    /// on-chain as `Bytes<1>` carrying the variant discriminant.
    user_enums: HashMap<String, Vec<nocturne_ir::UserEnumVariant>>,
    /// Emission errors. Every construct the emitter cannot lower
    /// soundly records a message here instead of silently returning
    /// `None` from `emit_expr`. `None` is reserved for statements that
    /// legitimately produce no wire.
    errors: Vec<String>,
    /// Names of `let` bindings whose RHS failed to lower (the failure's
    /// error is already in `errors`). The `Var` arm stays silent for
    /// these instead of cascading a misleading "variable `x` has no
    /// circuit wire" error per use — compilation already fails on the
    /// root cause.
    poisoned: HashSet<String>,
    /// Witness fields whose FIRST read happened inside a conditional
    /// branch. Such reads allocate a guarded `PrivateInput` and are
    /// deliberately NOT cached (the cache would leak a guarded wire
    /// into unguarded contexts, desynchronizing the circuit from the
    /// runtime builder's branch-local `private_transcript` push). Any
    /// second touch of the field anywhere in the circuit is an error;
    /// the user must hoist the read to a `let` before the `if`.
    guarded_witness_fields: HashSet<String>,
    /// Depth of helper inlining currently in progress. `return` inside
    /// an inlined helper body is rejected (the inliner splices the body
    /// into the caller, so `return` would not mean what it says).
    helper_inline_depth: u32,
    /// Instruction-index ranges of conditional branch bodies (one span
    /// per then/else body, recorded by the `If` arm). Surfaced through
    /// `ZkirOutput::branch_spans` so the structural-invariant tests
    /// know exactly which instructions were emitted under a branch
    /// guard.
    branch_spans: Vec<std::ops::Range<usize>>,
}

impl ZkirEmitter {
    fn new(
        field_names: &[String],
        field_types: &[syn::Type],
        witness_types: &HashMap<String, syn::Type>,
        witness_methods: &HashMap<String, syn::Type>,
        helpers: &HashMap<String, nocturne_ir::HelperIR>,
        user_structs: &HashMap<String, Vec<nocturne_ir::UserStructField>>,
        user_enums: &HashMap<String, Vec<nocturne_ir::UserEnumVariant>>,
    ) -> Self {
        Self {
            instructions: Vec::new(),
            next_index: 0,
            variables: HashMap::new(),
            variable_types: HashMap::new(),
            num_inputs: 0,
            guard: 0,
            in_conditional: false,
            zero_var: None,
            field_names: field_names.to_vec(),
            field_types: field_types.to_vec(),
            witness_types: witness_types.clone(),
            witness_methods: witness_methods.clone(),
            helpers: helpers.clone(),
            helper_counter: 0,
            user_structs: user_structs.clone(),
            user_enums: user_enums.clone(),
            errors: Vec::new(),
            poisoned: HashSet::new(),
            guarded_witness_fields: HashSet::new(),
            helper_inline_depth: 0,
            branch_spans: Vec::new(),
        }
    }

    /// Record an emission error and return `None`. Route every "can't
    /// lower this" site through here so unsupported constructs fail
    /// compilation instead of being silently dropped from the circuit.
    fn unsupported(&mut self, what: impl Into<String>) -> Option<Index> {
        self.errors.push(what.into());
        None
    }

    /// Guard for `PrivateInput`/`PublicInput` when inside a conditional
    /// branch. Returns `Some(branch_guard)` so the zkir VM skips the
    /// transcript-consuming read when the branch is inactive (pushing 0
    /// to memory instead — see `zkir/src/ir_vm.rs:325-355`). Outside
    /// conditionals, returns `None` so the read is unconditional.
    ///
    /// Without this, the IR's `PrivateInput`/`PublicInput` would try to
    /// consume an entry from the corresponding transcript even on an
    /// inactive branch — but the transcript builder only writes those
    /// entries for the active branch, so prove fails with "Ran out of
    /// {private,public} transcript outputs".
    fn current_io_guard(&self) -> Option<Index> {
        if self.in_conditional {
            Some(self.guard)
        } else {
            None
        }
    }

    /// Type inference for the limited set of expressions whose source
    /// type we can recover from the IR alone. Used by the `Index` emit
    /// arm (to recover the array element type), the `Let` arm and
    /// helper inlining (to populate `variable_types` for downstream
    /// `Var` lookups), and `expr_comparison_width` (to pick a sound
    /// `LessThan` bit width).
    ///
    /// This is intentionally conservative — when a shape isn't covered
    /// here, callers get `None` and fall back to whatever default the
    /// callsite has (usually an emit-time `None` that surfaces as a
    /// downstream compile_error rather than silently miscompiling).
    fn infer_expr_type(&self, expr: &ExprIR) -> Option<syn::Type> {
        match expr {
            ExprIR::WitnessAccess { field, .. } => {
                self.witness_types.get(&field.to_string()).cloned()
            }
            ExprIR::Var { name, .. } => self.variable_types.get(&name.to_string()).cloned(),
            ExprIR::LedgerAccess { field, method, .. } => {
                let m = method.to_string();
                if m == "get" || m == "value" || m == "__direct_access" {
                    let idx = self.field_index(&field.to_string());
                    let field_ty = self.field_types.get(idx as usize)?;
                    extract_cell_inner_type(field_ty)
                } else {
                    None
                }
            }
            // `arr[i]` has the array's element type, recovered by
            // chasing `array`'s type and extracting `T` from `[T; N]`.
            ExprIR::Index { array, .. } => {
                let arr_ty = self.infer_expr_type(array)?;
                crate::containers::extract_array_type(&arr_ty).map(|(t, _)| t)
            }
            _ => None,
        }
    }

    /// Pick the bit width to constrain `LessThan` to: the MAX of both
    /// operands' inferred widths. Upstream's `LessThan` documents "UB
    /// if a or b exceed bits", so getting this right is a correctness
    /// requirement, not just an optimisation — a `Uint<128>` operand
    /// compared at `bits: 64` silently misverifies whenever its high
    /// half is non-zero.
    ///
    /// Returns `None` when either operand is `Field`-typed or its
    /// width cannot be inferred; callers must record an error rather
    /// than guess a default width.
    fn comparison_bits(&self, lhs: &ExprIR, rhs: &ExprIR) -> Option<u32> {
        let l = self.expr_comparison_width(lhs)?;
        let r = self.expr_comparison_width(rhs)?;
        Some(l.max(r))
    }

    /// Bit width of one comparison operand. Integer literals are bound
    /// by their value (a literal `300` needs 9 bits); typed expressions
    /// use the declared `Uint<N>`/`uN`/`Boolean` width. `Field` and
    /// uninferable shapes yield `None` — there is no sound `bits`
    /// argument for them.
    fn expr_comparison_width(&self, expr: &ExprIR) -> Option<u32> {
        match expr {
            ExprIR::Literal { value, .. } => match value {
                LiteralIR::Int(n) => Some((128 - n.leading_zeros()).max(1)),
                LiteralIR::Bool(_) => Some(1),
                LiteralIR::Str(_) => None,
            },
            // `.value()` / `.into()` are transparent wrappers around
            // the receiver's declared type (shared rule in `crate::typing`).
            ExprIR::MethodCall {
                receiver, method, ..
            } if is_transparent_wrapper(&method.to_string()) => {
                self.expr_comparison_width(receiver)
            }
            ExprIR::Reference { expr: inner, .. } => self.expr_comparison_width(inner),
            _ => {
                let t = self.infer_expr_type(expr)?;
                let s = quote::quote!(#t).to_string().replace(' ', "");
                if s == "Boolean" || s == "bool" {
                    return Some(1);
                }
                parse_uint_type(&s)
            }
        }
    }

    /// Emit (or reuse a cached) `LoadImm 0`.
    fn emit_load_zero(&mut self) -> Index {
        if let Some(z) = self.zero_var {
            return z;
        }
        let z = self.emit_load_imm(Fr::from(0u64));
        self.zero_var = Some(z);
        z
    }

    /// Emit a `DeclarePubInput`, wrapping the value in `CondSelect(guard, value, 0)`
    /// when inside a conditional branch. See memory file referenced above for the
    /// on-chain protocol invariant this enforces.
    fn push_declare_pub_input(&mut self, value: Index) {
        let final_var = if self.in_conditional {
            let zero = self.emit_load_zero();
            self.emit_instruction(Instruction::CondSelect {
                bit: self.guard,
                a: value,
                b: zero,
            })
        } else {
            value
        };
        self.instructions
            .push(Instruction::DeclarePubInput { var: final_var });
    }

    fn emit_circuit(&mut self, circuit: &CircuitIR) -> ZkirOutput {
        // Allocate memory slots for public circuit arguments.
        for param in &circuit.params {
            let idx = self.next_index;
            self.next_index += 1;
            self.num_inputs += 1;
            self.variables.insert(param.name.to_string(), idx);
        }

        // Guard value (0x01) comes after inputs.
        self.guard = self.emit_load_imm(Fr::from(1u64));

        // Emit type constraints for circuit arguments.
        for (i, param) in circuit.params.iter().enumerate() {
            let idx = i as u32;
            self.emit_type_constraint(idx, &param.ty);
        }

        // `return` is only supported in tail position (the final
        // statement, or the tail of the final statement's branches).
        // The `Return` emit arm yields the value's wire WITHOUT
        // emitting `Output` — the single `Output` below comes from the
        // last statement's wire, so a trailing `return x;` and a
        // trailing `x` expression produce identical circuits.
        let body_len = circuit.body.len();
        for (i, expr) in circuit.body.iter().enumerate() {
            check_return_positions(expr, i + 1 == body_len, &mut self.errors);
        }

        // Process circuit body, capturing the LAST statement's wire.
        // Using `next_index - 1` here would be wrong: a trailing
        // cache-hit expression (e.g. a let-bound witness re-reference)
        // returns an earlier wire, not the most recently allocated one.
        let mut last_wire: Option<Index> = None;
        for expr in &circuit.body {
            last_wire = self.emit_expr(expr);
        }

        // If the circuit has a return type, emit exactly one Output for
        // the value of the last statement.
        if circuit.return_type.is_some() {
            match last_wire {
                Some(var) => self.instructions.push(Instruction::Output { var }),
                None => {
                    // Only report when nothing else failed: with earlier
                    // errors the missing value is almost always their
                    // cascade (a failed final expression), and this
                    // message would just bury the root cause.
                    if self.errors.is_empty() {
                        self.errors.push(
                            "circuit declares a return type but its final statement \
                             produces no value"
                                .to_string(),
                        );
                    }
                }
            }
        }

        // Always emit communications commitment to match compactc behavior.
        let ir_source = IrSource {
            num_inputs: self.num_inputs,
            do_communications_commitment: true,
            instructions: Arc::new(std::mem::take(&mut self.instructions)),
        };

        ZkirOutput {
            circuit_name: circuit.name.to_string(),
            ir_source,
            branch_spans: std::mem::take(&mut self.branch_spans),
        }
    }

    /// Inline a helper at the call site. Implements compactc's
    /// `let* args; rename(body)` pattern (`circuit-passes.ss:358-376`):
    /// each parameter is bound to its arg expression's resulting wire
    /// under a fresh name, then the body is alpha-renamed against the
    /// resulting substitution map and emitted statement-by-statement.
    /// The last statement's wire is the helper's return value.
    fn emit_inlined_helper(
        &mut self,
        helper: &nocturne_ir::HelperIR,
        args: &[ExprIR],
    ) -> Option<Index> {
        if helper.params.len() != args.len() {
            return self.unsupported(format!(
                "helper `{}` called with {} argument(s) but declares {} parameter(s)",
                helper.name,
                args.len(),
                helper.params.len()
            ));
        }
        let counter = self.helper_counter;
        self.helper_counter += 1;
        let mut subst: HashMap<String, String> = HashMap::new();
        let mut seq: u32 = 0;
        for (param, arg) in helper.params.iter().zip(args) {
            let fresh = format!("__h{counter}_{seq}_{}", param.name);
            seq += 1;
            subst.insert(param.name.to_string(), fresh.clone());
            let arg_ty = self.infer_expr_type(arg);
            let wire = self.emit_expr(arg)?;
            self.variables.insert(fresh.clone(), wire);
            if let Some(t) = arg_ty {
                self.variable_types.insert(fresh, t);
            }
        }
        let mut last: Option<Index> = None;
        self.helper_inline_depth += 1;
        for stmt in &helper.body {
            let renamed = alpha_rename(stmt.clone(), &mut subst, counter, &mut seq);
            last = self.emit_expr(&renamed);
        }
        self.helper_inline_depth -= 1;
        last
    }

    /// Evaluate a builtin call's arguments strictly, in order. A failing
    /// argument has already recorded its own emission error; propagating
    /// `None` keeps the builtin from being emitted with fewer inputs
    /// than the source call has (a `filter_map` here would silently
    /// drop the failing argument from e.g. a hash input list).
    fn emit_builtin_args(&mut self, args: &[ExprIR]) -> Option<Vec<Index>> {
        args.iter().map(|a| self.emit_expr(a)).collect()
    }

    /// Emit instructions for an expression, returning the memory index of the result (if any).
    fn emit_expr(&mut self, expr: &ExprIR) -> Option<Index> {
        match expr {
            ExprIR::LedgerAccess {
                field,
                method,
                args,
                ..
            } => {
                let method_name = method.to_string();
                let field_idx = self.field_index(&field.to_string());

                // Inspect the field type to choose the right emitter. Map
                // and Set dispatch separately from Counter/Cell because
                // their methods (contains/get/set/insert/remove/member)
                // take a user-typed key.
                let field_ty = self.field_types.get(field_idx as usize).cloned();
                let map_kv = field_ty.as_ref().and_then(extract_map_kv_types);

                if let Some((k_ty, v_ty)) = map_kv {
                    return self.emit_map_method(field_idx, &method_name, args, &k_ty, &v_ty);
                }

                let set_t = field_ty.as_ref().and_then(extract_set_inner_type);
                if let Some(t_ty) = set_t {
                    return self.emit_set_method(field_idx, &method_name, args, &t_ty);
                }

                if field_ty
                    .as_ref()
                    .and_then(extract_merkle_tree_type)
                    .is_some()
                {
                    return self.emit_merkle_tree_method(field_idx, &method_name, args);
                }

                match method_name.as_str() {
                    "increment" | "increment_by" => {
                        // `increment()` = +1 (no arg) and
                        // `increment_by(N)` = +N for a const literal N
                        // fitting Addi's u32 immediate. Non-literal
                        // arguments are rejected (would need an `Add`
                        // opcode pulling from a witness).
                        let n = match args.first() {
                            None => 1u32,
                            Some(ExprIR::Literal {
                                value: LiteralIR::Int(v),
                                ..
                            }) if *v <= u32::MAX as u128 => *v as u32,
                            Some(_) => {
                                return self.unsupported(format!(
                                    "`{field}.increment_by(n)` requires a const integer \
                                     literal `n` fitting u32"
                                ));
                            }
                        };
                        self.emit_counter_increment(field_idx, n)
                    }
                    "get" | "value" | "__direct_access" => {
                        // Resolve the read result type (u64 for Counter,
                        // T for Cell<T>). When unresolved, falls back to
                        // the legacy 1-declare Popeq for backwards-compat,
                        // but that emission is NOT on-chain compatible.
                        let result_ty = field_ty.as_ref().and_then(extract_ledger_read_result_type);
                        self.emit_ledger_read(field_idx, result_ty.as_ref())
                    }
                    "set" => {
                        // Resolve Cell<T> → T, then compute how many Frs T
                        // occupies so we can collect the contiguous range of
                        // PrivateInputs the WitnessAccess emitted. For
                        // single-Fr T this collapses to one element; for
                        // multi-Fr (e.g. Bytes<32>) we pass the full chunked
                        // index list to emit_push_cell.
                        let val_first = args.first().and_then(|a| self.emit_expr(a));
                        let value_vars = self.gather_value_vars(field_idx, val_first);
                        self.emit_ledger_write(field_idx, &value_vars)
                    }
                    "insert" => {
                        let val_first = args.first().and_then(|a| self.emit_expr(a));
                        let value_vars = self.gather_value_vars(field_idx, val_first);
                        self.emit_ledger_write(field_idx, &value_vars)
                    }
                    other => self.unsupported(format!(
                        "unsupported ledger method `{other}` on field `{field}`"
                    )),
                }
            }

            ExprIR::WitnessAccess { field, .. } => {
                let key = format!("witness.{field}");
                if let Some(&idx) = self.variables.get(&key) {
                    return Some(idx);
                }
                let field_str = field.to_string();
                // A field whose FIRST read happened inside a branch was
                // allocated guarded and deliberately not cached. A second
                // touch would allocate ANOTHER PrivateInput block while
                // the runtime builder pushes per-branch — the circuit and
                // the private transcript desynchronize. Reject loudly;
                // the sound shapes are "hoist before the if" or
                // "touch exactly once inside one branch".
                if self.guarded_witness_fields.contains(&field_str) {
                    return self.unsupported(format!(
                        "witness field `{field}` is first read inside a conditional \
                         branch and used again elsewhere; hoist it to a `let` before \
                         the `if`"
                    ));
                }
                let ty = self.witness_types.get(&field_str).cloned();

                // Each Fr of the witness gets its own PrivateInput plus a
                // per-Fr constraint. Mixed-shape witnesses (e.g.
                // `MerkleTreePath<H, T>`) emit a different constraint per
                // Fr — bits for the leaf chunks, none for sibling fields,
                // boolean for goes_left flags — so the layout describes
                // each Fr's constraint type rather than a uniform width.
                //
                // Parse-time validation guarantees the field exists on
                // the registered witnesses struct, so a missing type here
                // is an internal inconsistency: guessing a single-Field
                // layout would silently change the circuit's PI count.
                let layout = match ty.as_ref() {
                    Some(t) => witness_fr_layout(t, &self.user_structs, &self.user_enums),
                    None => {
                        return self.unsupported(format!(
                            "witness field `{field}` has no registered type at ZKIR \
                             emit time; its wire layout cannot be determined"
                        ));
                    }
                };
                let mut first_idx = None;
                for entry in layout {
                    let var = self.emit_instruction(Instruction::PrivateInput {
                        guard: self.current_io_guard(),
                    });
                    if first_idx.is_none() {
                        first_idx = Some(var);
                    }
                    match entry {
                        FrLayout::Bits(b) => self
                            .instructions
                            .push(Instruction::ConstrainBits { var, bits: b }),
                        FrLayout::Boolean => self
                            .instructions
                            .push(Instruction::ConstrainToBoolean { var }),
                        FrLayout::Field => {}
                    }
                }
                let first = first_idx.expect("at least one PrivateInput per witness");
                if self.in_conditional {
                    // First touch inside a branch: guarded wire, no cache.
                    // The runtime builder pushes this field's value inside
                    // the same runtime branch; the guard makes the zkir VM
                    // skip the transcript read on the inactive path
                    // (guard 0 pushes 0 without advancing the transcript
                    // index; midnight-ledger ledger-8,
                    // zkir/src/ir_vm.rs:325-355).
                    self.guarded_witness_fields.insert(field_str);
                } else {
                    self.variables.insert(key, first);
                }
                Some(first)
            }

            // Parametric witness call `witnesses.method(args)`. Args
            // are emitted first so any witness reads they contain
            // allocate their own PrivateInputs; the call itself then
            // allocates a fresh block of PrivateInputs sized by the
            // method's return type. No cache key — each call site is
            // a distinct witness value.
            ExprIR::WitnessCall { name, args, .. } => {
                for arg in args {
                    let _ = self.emit_expr(arg);
                }
                let ret_ty = self.witness_methods.get(&name.to_string()).cloned();
                let layout = match ret_ty.as_ref() {
                    Some(t) => witness_fr_layout(t, &self.user_structs, &self.user_enums),
                    // Parse-time validation in nocturne-ir rejects calls
                    // to unregistered witness methods, so macro-built IR
                    // never reaches this arm unresolved. Guessing a
                    // single-Field layout here would silently change the
                    // circuit's PI count, so fail loudly instead.
                    None => {
                        return self.unsupported(format!(
                            "witness method `{name}` has no registered return type at \
                             ZKIR emit time; its wire layout cannot be determined"
                        ));
                    }
                };
                let mut first_idx = None;
                for entry in layout {
                    let var = self.emit_instruction(Instruction::PrivateInput {
                        guard: self.current_io_guard(),
                    });
                    if first_idx.is_none() {
                        first_idx = Some(var);
                    }
                    match entry {
                        FrLayout::Bits(b) => self
                            .instructions
                            .push(Instruction::ConstrainBits { var, bits: b }),
                        FrLayout::Boolean => self
                            .instructions
                            .push(Instruction::ConstrainToBoolean { var }),
                        FrLayout::Field => {}
                    }
                }
                first_idx
            }

            ExprIR::Literal { value, .. } => {
                let fr = match value {
                    // Full u128 range: `impl From<u128> for Fr` exists
                    // upstream (transient-crypto/src/curve.rs:285).
                    // Truncating through u64 would silently halve large
                    // literals' width in the circuit.
                    LiteralIR::Int(n) => Fr::from(*n),
                    LiteralIR::Bool(b) => Fr::from(*b),
                    LiteralIR::Str(_) => {
                        return self.unsupported("string literals have no circuit representation");
                    }
                };
                Some(self.emit_load_imm(fr))
            }

            ExprIR::Var { name, .. } => {
                let key = name.to_string();
                match self.variables.get(&key).copied() {
                    Some(idx) => Some(idx),
                    // The binding's initializer already failed and
                    // recorded the root-cause error — stay silent here
                    // instead of adding one misleading "no circuit
                    // wire" error per use.
                    None if self.poisoned.contains(&key) => None,
                    None => self.unsupported(format!(
                        "variable `{name}` has no circuit wire (binding shape not supported \
                         by the ZKIR emitter)"
                    )),
                }
            }

            // A `Path` like `Status::Open` is a compile-time constant.
            // When it names a known user enum variant, lower to a
            // LoadImm of the variant's discriminant so `BinaryOp::Eq`
            // can compare it directly against an enum wire. For other
            // paths (assoc constants, etc.) there's no wire backing —
            // record an error so they don't vanish from the circuit.
            ExprIR::Path { path, .. } => match self.resolve_enum_variant_discriminant(path) {
                Some(d) => Some(self.emit_load_imm(Fr::from(d as u64))),
                None => self.unsupported(format!(
                    "path expression `{}` does not name a known enum variant",
                    quote::quote!(#path)
                )),
            },

            // Payload projection from a homogeneous-payload enum value.
            // The enum's `WitnessAccess` / `LedgerAccess` allocates the
            // discriminant wire first, then the payload wires
            // (`witness_fr_layout` for `enum E { V(T) }` returns
            // `[Bits(8), …T_layout]`). The payload's first wire is
            // therefore offset 1 from the scrutinee's first wire.
            ExprIR::EnumPayload { scrutinee, .. } => {
                self.emit_expr(scrutinee).map(|first| first + 1)
            }

            ExprIR::BinaryOp { op, lhs, rhs, .. } => {
                // Resolve the comparison bit width BEFORE emitting the
                // operands, so a cache-hit re-read doesn't reshape what
                // `infer_expr_type` sees. The width is a property of the
                // operand types, not the wires.
                let cmp_bits = self.comparison_bits(lhs, rhs);
                let a = self.emit_expr(lhs)?;
                let b = self.emit_expr(rhs)?;
                use syn::BinOp;
                // Ordered comparisons need a sound bit width for
                // `LessThan` (UB above `bits` per upstream docs); the
                // other operators don't.
                let require_bits = |emitter: &mut Self| -> Option<u32> {
                    match cmp_bits {
                        Some(bits) => Some(bits),
                        None => {
                            emitter.errors.push(format!(
                                "cannot infer a bit width for the comparison `{}` — \
                                 Field-typed or untyped operands have no sound \
                                 `LessThan` width; compare typed `Uint`s instead",
                                quote::quote!(#op)
                            ));
                            None
                        }
                    }
                };
                match op {
                    BinOp::Add(_) | BinOp::AddAssign(_) => {
                        Some(self.emit_instruction(Instruction::Add { a, b }))
                    }
                    BinOp::Sub(_) | BinOp::SubAssign(_) => {
                        let neg_b = self.emit_instruction(Instruction::Neg { a: b });
                        Some(self.emit_instruction(Instruction::Add { a, b: neg_b }))
                    }
                    BinOp::Mul(_) | BinOp::MulAssign(_) => {
                        Some(self.emit_instruction(Instruction::Mul { a, b }))
                    }
                    BinOp::Eq(_) => Some(self.emit_instruction(Instruction::TestEq { a, b })),
                    BinOp::Ne(_) => {
                        let eq = self.emit_instruction(Instruction::TestEq { a, b });
                        Some(self.emit_instruction(Instruction::Not { a: eq }))
                    }
                    BinOp::Lt(_) => {
                        let bits = require_bits(self)?;
                        Some(self.emit_instruction(Instruction::LessThan { a, b, bits }))
                    }
                    BinOp::Gt(_) => {
                        let bits = require_bits(self)?;
                        Some(self.emit_instruction(Instruction::LessThan { a: b, b: a, bits }))
                    }
                    BinOp::Le(_) => {
                        let bits = require_bits(self)?;
                        let gt = self.emit_instruction(Instruction::LessThan { a: b, b: a, bits });
                        Some(self.emit_instruction(Instruction::Not { a: gt }))
                    }
                    BinOp::Ge(_) => {
                        let bits = require_bits(self)?;
                        let lt = self.emit_instruction(Instruction::LessThan { a, b, bits });
                        Some(self.emit_instruction(Instruction::Not { a: lt }))
                    }
                    BinOp::And(_) => Some(self.emit_instruction(Instruction::Mul { a, b })),
                    BinOp::Or(_) => {
                        let ab = self.emit_instruction(Instruction::Mul { a, b });
                        let sum = self.emit_instruction(Instruction::Add { a, b });
                        let neg_ab = self.emit_instruction(Instruction::Neg { a: ab });
                        Some(self.emit_instruction(Instruction::Add { a: sum, b: neg_ab }))
                    }
                    other => self.unsupported(format!(
                        "unsupported binary operator `{}` in circuit",
                        quote::quote!(#other)
                    )),
                }
            }

            ExprIR::UnaryOp {
                op, expr: inner, ..
            } => {
                let a = self.emit_expr(inner)?;
                match op {
                    syn::UnOp::Neg(_) => Some(self.emit_instruction(Instruction::Neg { a })),
                    syn::UnOp::Not(_) => Some(self.emit_instruction(Instruction::Not { a })),
                    other => self.unsupported(format!(
                        "unsupported unary operator `{}` in circuit",
                        quote::quote!(#other)
                    )),
                }
            }

            ExprIR::Let { name, value, .. } => {
                // Infer the RHS's type BEFORE emitting (emit can mutate
                // the variables map and the RHS may reference other
                // bindings whose type tag we want to chain). For RHS
                // shapes we can't type-infer (arithmetic, FnCall, …)
                // the entry stays absent and downstream `Var` lookups
                // gracefully fall back.
                let ty = self.infer_expr_type(value);
                let Some(idx) = self.emit_expr(value) else {
                    // The RHS produced no wire. With errors already
                    // recorded this is (transitively) their cascade —
                    // poison the name so later uses stay silent instead
                    // of piling a misleading message per use on top of
                    // the root cause. On an otherwise clean circuit the
                    // RHS returned `None` legitimately (e.g. a ledger
                    // write used as an initializer) — record THAT as
                    // the binding's error; the uses are still poisoned
                    // so it surfaces exactly once.
                    if self.errors.is_empty() {
                        self.errors.push(format!(
                            "let binding `{name}`'s initializer produces no circuit value"
                        ));
                    }
                    self.poisoned.insert(name.to_string());
                    // A failed rebind also shadows: drop any earlier
                    // binding (and its type tag) of the same name.
                    self.variables.remove(&name.to_string());
                    self.variable_types.remove(&name.to_string());
                    return None;
                };
                self.variables.insert(name.to_string(), idx);
                self.poisoned.remove(&name.to_string());
                if let Some(t) = ty {
                    self.variable_types.insert(name.to_string(), t);
                }
                Some(idx)
            }

            ExprIR::Assert { kind, .. } => {
                match kind {
                    AssertKind::Assert(cond) => {
                        let idx = self.emit_expr(cond)?;
                        self.instructions.push(Instruction::Assert { cond: idx });
                    }
                    AssertKind::AssertEq(a, b) => {
                        let idx_a = self.emit_expr(a)?;
                        let idx_b = self.emit_expr(b)?;
                        self.instructions
                            .push(Instruction::ConstrainEq { a: idx_a, b: idx_b });
                    }
                }
                None
            }

            ExprIR::If {
                cond,
                then_branch,
                else_branch,
                ..
            } => {
                let cond_idx = self.emit_expr(cond)?;
                let outer_guard = self.guard;
                let outer_in_conditional = self.in_conditional;

                // For nested conditionals, the effective guard is `outer AND cond`,
                // computed as `cond_select(cond, outer_guard, 0)` (returns outer_guard
                // when cond=true, 0 when cond=false). At top level, the outer guard is
                // the always-true constant, so we can just use cond directly.
                let then_guard = if outer_in_conditional {
                    let zero = self.emit_load_zero();
                    self.emit_instruction(Instruction::CondSelect {
                        bit: cond_idx,
                        a: outer_guard,
                        b: zero,
                    })
                } else {
                    cond_idx
                };
                self.guard = then_guard;
                self.in_conditional = true;

                // Track the last sub-expression's wire so an
                // `if`-as-expression can multiplex the branch results
                // via `cond_select` further down. Statement-only
                // branches (every entry returns `None`) leave
                // `then_result` as `None` and we fall back to the
                // legacy `Some(cond_idx)` return so existing
                // if-as-statement behaviour is unchanged.
                let then_start = self.instructions.len();
                let mut then_result: Option<Index> = None;
                for expr in then_branch {
                    then_result = self.emit_expr(expr).or(then_result);
                }
                // Record the branch-body span for the structural
                // invariant tests: every instruction in it was emitted
                // with `in_conditional == true`, so its IO guards must
                // be `Some(_)`.
                self.branch_spans.push(then_start..self.instructions.len());

                let mut else_result: Option<Index> = None;
                if let Some(else_stmts) = else_branch {
                    // Else branch: `outer AND NOT cond`, computed as
                    // `cond_select(cond, 0, outer_guard)`. At top level, just `!cond`.
                    let else_guard = if outer_in_conditional {
                        let zero = self.emit_load_zero();
                        self.emit_instruction(Instruction::CondSelect {
                            bit: cond_idx,
                            a: zero,
                            b: outer_guard,
                        })
                    } else {
                        self.emit_instruction(Instruction::Not { a: cond_idx })
                    };
                    self.guard = else_guard;

                    let else_start = self.instructions.len();
                    for expr in else_stmts {
                        else_result = self.emit_expr(expr).or(else_result);
                    }
                    self.branch_spans.push(else_start..self.instructions.len());
                }

                self.guard = outer_guard;
                self.in_conditional = outer_in_conditional;

                // When both branches yielded a value, this `if` is
                // being used as an expression — multiplex the
                // branch wires via `cond_select(cond, then, else)`.
                // The mux happens at the outer guard so its own
                // result wire is unconstrained by the branch
                // guards (the values it pulls from are already
                // zeroed by the guard machinery on the inactive
                // side).
                if let (Some(t), Some(e)) = (then_result, else_result) {
                    return Some(self.emit_instruction(Instruction::CondSelect {
                        bit: cond_idx,
                        a: t,
                        b: e,
                    }));
                }

                Some(cond_idx)
            }

            ExprIR::FnCall {
                name, path, args, ..
            } => {
                let name_str = name.to_string();

                // `merkle_tree_path_root(&path)` must inspect args[0]
                // BEFORE evaluating it, because the unrolled fold needs
                // to know the path height (H) from the witness type.
                // Evaluating args[0] only yields the first var Index;
                // it doesn't carry the type.
                if name_str == "merkle_tree_path_root" {
                    return self.emit_merkle_tree_path_root(args);
                }

                // Inlinable helper. The call site is replaced with the
                // helper's body after alpha-renaming and per-arg
                // let-binding (compactc's `let* args; rename(body)`
                // pattern at `circuit-passes.ss:358-376`). Recursive
                // helper calls inside the body lower through this
                // same arm; acyclicity (rejected at parse time) keeps
                // it terminating.
                if let Some(helper) = self.helpers.get(&name_str).cloned() {
                    return self.emit_inlined_helper(&helper, args);
                }

                // `Uint::<N>::from(x)` and the other wrapper-type
                // constructors are transparent: the constructed value's
                // circuit wire IS the argument's wire, the FnCall twin
                // of the `.into()`/`.value()` rule in `crate::typing`.
                // (The runtime side reconstructs the call verbatim.)
                if args.len() == 1 && is_wrapper_from_call(path) {
                    return self.emit_expr(&args[0]);
                }

                match name_str.as_str() {
                    "persistent_hash" => {
                        use midnight_base_crypto::fab::{
                            Alignment, AlignmentAtom, AlignmentSegment,
                        };
                        let inputs = self.emit_builtin_args(args)?;
                        let alignment =
                            Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Field)]);
                        Some(
                            self.emit_instruction(Instruction::PersistentHash {
                                alignment,
                                inputs,
                            }),
                        )
                    }
                    "transient_hash" => {
                        let inputs = self.emit_builtin_args(args)?;
                        Some(self.emit_instruction(Instruction::TransientHash { inputs }))
                    }
                    // Any other callee has NO circuit lowering. Falling
                    // back to "last arg's wire" here (the old behavior)
                    // would silently drop whatever constraint the call
                    // was supposed to enforce — e.g. `std::cmp::max`,
                    // or a contract `fn` that helper collection skipped
                    // (reference params, generics, missing return type).
                    other => self.unsupported(format!(
                        "call to `{other}` cannot be lowered to circuit \
                         instructions: it is neither a ZKIR builtin \
                         (`persistent_hash`, `transient_hash`, \
                         `merkle_tree_path_root`) nor an inlinable helper \
                         (helpers must be free `fn`s in the contract module \
                         with owned parameters, a return type, and no \
                         generics)"
                    )),
                }
            }

            // `disclose(v)` is a marker, not an emission: the disclosed
            // value reaches the public view through whatever ledger op
            // consumes it (Cell::set, Map::insert, ...). Emitting a
            // DeclarePubInput + PiSkip here would create a PI group that
            // no transcript op backs — the ledger builds verifier PIs
            // exclusively as `[binding_input, comm,
            // ..field_repr(transcript ops)]` (midnight-ledger ledger-8,
            // ledger/src/verify.rs:1869), so any active-path disclose
            // would fail at prove time.
            ExprIR::Disclose { value, .. } => self.emit_expr(value),

            ExprIR::MethodCall { receiver, args, .. } => {
                let recv = self.emit_expr(receiver);
                for arg in args {
                    self.emit_expr(arg);
                }
                recv
            }

            ExprIR::Block { stmts, .. } => {
                let mut last = None;
                for stmt in stmts {
                    last = self.emit_expr(stmt);
                }
                last
            }

            // `return` does NOT emit `Output` itself — `emit_circuit`
            // emits exactly one `Output` from the final statement's
            // wire. Tail position is validated by
            // `check_return_positions` before the body is emitted.
            ExprIR::Return { value, .. } => {
                if self.helper_inline_depth > 0 {
                    return self.unsupported(
                        "`return` inside an inlined helper is not supported; make the \
                         returned value the helper's final expression instead",
                    );
                }
                if let Some(val) = value {
                    self.emit_expr(val)
                } else {
                    None
                }
            }

            // Tuple literal in value position (e.g. a tuple-typed Map
            // key). Same contiguity contract as `ArrayLit`: each element
            // must allocate fresh wires immediately after its
            // predecessor, and the FIRST element's wire is returned so
            // `gather_n_vars` can read the whole block.
            ExprIR::Tuple { elements, .. } => self.emit_contiguous_elements(
                elements.iter().collect::<Vec<_>>().as_slice(),
                "tuple literal",
            ),

            // Array literal `[a, b, c]`. Emit each element in order and
            // return the first element's wire index — downstream
            // `gather_value_vars` reads N contiguous wires starting
            // there to build the multi-Fr ledger Push. Contiguity is
            // enforced: a cache-hit Var or witness re-reference would
            // make the gathered range read the wrong wires.
            ExprIR::ArrayLit { elements, .. } => self.emit_contiguous_elements(
                elements.iter().collect::<Vec<_>>().as_slice(),
                "array literal",
            ),

            ExprIR::Reference { expr: inner, .. } => self.emit_expr(inner),

            // `arr[i]` — emit the array's first wire and shift by
            // `i * layout_len(T)`. The array's element type comes from
            // the source: `witnesses.<f>[i]` resolves `T` via
            // `self.witness_types`; `self.<f>[i]` resolves via
            // `self.field_types`. Other shapes (let-bound arrays, etc.)
            // aren't supported in this pass — they need wire-type
            // tracking on local bindings.
            ExprIR::Index { array, index, .. } => {
                let first = self.emit_expr(array)?;
                let arr_ty = match self.infer_expr_type(array) {
                    Some(t) => t,
                    None => {
                        return self.unsupported(
                            "cannot infer the element type of an indexed expression; \
                             only witness arrays and typed let-bound arrays support \
                             indexing",
                        );
                    }
                };
                let Some((elem_ty, len)) = crate::containers::extract_array_type(&arr_ty) else {
                    return self.unsupported(format!(
                        "indexed expression has non-array type `{}`",
                        quote::quote!(#arr_ty)
                    ));
                };
                if *index >= len {
                    return self.unsupported(format!(
                        "array index {index} out of bounds for `[_; {len}]`"
                    ));
                }
                let stride = witness_fr_layout(&elem_ty, &self.user_structs, &self.user_enums).len()
                    as Index;
                Some(first + (*index) * stride)
            }

            // Struct literal `MyStruct { a, b, c }` in a value-producing
            // position (today: `Cell<MyStruct>::set(MyStruct { … })`).
            // Emit the fields in their declared order (matching the
            // user-struct fields list registered with the IR, not the
            // textual order — same convention `aligned_value_encoding`
            // uses to compose the tuple of fields). Return the first
            // field's wire; `gather_value_vars` walks the remaining
            // contiguous wires when the surrounding Cell::set lowers.
            //
            // Like `ArrayLit`, field emission must produce contiguous
            // wires — enforced by `emit_contiguous_elements`.
            ExprIR::StructInit { name, fields, .. } => {
                let struct_fields = self.user_structs.get(&name.to_string()).cloned();
                let ordered: Vec<&ExprIR> = match struct_fields {
                    Some(decl) => decl
                        .iter()
                        .filter_map(|f| {
                            fields
                                .iter()
                                .find(|(fname, _)| fname == &f.name)
                                .map(|(_, expr)| expr)
                        })
                        .collect(),
                    // No registered struct entry — fall back to textual
                    // order so we still emit something coherent, even if
                    // the wire alignment can't be trusted downstream.
                    None => fields.iter().map(|(_, expr)| expr).collect(),
                };
                self.emit_contiguous_elements(&ordered, "struct literal")
            }
            ExprIR::Unsupported { description, .. } => {
                self.unsupported(format!("unsupported expression: {description}"))
            }
        }
    }

    /// Emit the elements of an array/tuple/struct literal, enforcing
    /// that each element allocates fresh wires starting exactly at the
    /// current `next_index`. Downstream consumers (`gather_value_vars`,
    /// `gather_n_vars`) read a contiguous wire range from the FIRST
    /// element's wire, so a cache-hit Var, a witness re-reference, or
    /// any element whose value wire isn't its first allocation would
    /// make them read the wrong wires. Until `emit_expr` returns
    /// multi-wire values, the only sound option is a loud error.
    fn emit_contiguous_elements(&mut self, elements: &[&ExprIR], what: &str) -> Option<Index> {
        let mut first: Option<Index> = None;
        for elem in elements {
            let before = self.next_index;
            let w = self.emit_expr(elem)?;
            if w != before {
                return self.unsupported(format!(
                    "{what} element does not allocate fresh contiguous wires (it is a \
                     repeated witness read, an earlier binding, or a computed value); \
                     the multi-Fr encoding would read the wrong wires — use each \
                     witness element at most once per literal"
                ));
            }
            if first.is_none() {
                first = Some(w);
            }
        }
        first
    }

    // -----------------------------------------------------------------------
    // Transcript VM op encoding as ZKIR public inputs
    // -----------------------------------------------------------------------

    /// Emit the field representation of a Uint<8> key (field index).
    ///
    /// AlignedValue for Bytes<1>:
    ///   alignment.field_repr = [segment_count=1, Bytes{length=1}=1] → 2 fields
    ///   value = [field_idx] → 1 field
    ///   Total: 3 fields
    ///
    /// Since segment_count=1 and Bytes{1}=1 both equal 0x01, the Compact
    /// compiler reuses the guard variable (also 0x01) for these. We do the same.
    fn emit_key_field_repr(&mut self, field_idx: u8) {
        let g = self.guard; // guard = 0x01, matches alignment [1, 1]
        let key_val = self.emit_load_imm(Fr::from(field_idx as u64));

        // alignment.field_repr: [segment_count=1, atom(Bytes{1})=1]
        self.push_declare_pub_input(g);
        self.push_declare_pub_input(g);
        // value: [field_idx]
        self.push_declare_pub_input(key_val);
    }

    /// Emit ZKIR for Counter.increment(1): Idx(push_path) + Addi(1) + Ins.
    ///
    /// Matches Compact's `Counter.increment`:
    ///   idx [pushPath: true] [path: f]
    ///   addi [immediate: amount]
    ///   ins [cached: true] [n: len(f)]
    fn emit_counter_increment(&mut self, field_idx: u8, n: u32) -> Option<Index> {
        let g = self.guard;

        // Idx { cached: false, push_path: true, path: [Value(field_idx)] }
        // Opcode: 0x70 | (path.len() - 1) = 0x70
        let idx_op = self.emit_load_imm(Fr::from(0x70u64));
        self.push_declare_pub_input(idx_op);
        self.emit_key_field_repr(field_idx);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // Addi { immediate: n } → field repr: [0x0e, n]
        let addi_op = self.emit_load_imm(Fr::from(0x0eu64));
        let n_var = self.emit_load_imm(Fr::from(n as u64));
        self.push_declare_pub_input(addi_op);
        self.push_declare_pub_input(n_var);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 2,
        });

        // Ins { cached: true, n: 1 } → field repr: [0xa1]
        let ins_op = self.emit_load_imm(Fr::from(0xa1u64));
        self.push_declare_pub_input(ins_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        Some(n_var)
    }

    /// Emit ZKIR for reading a ledger field: Dup + Idx + Popeq.
    ///
    /// On-chain encoding (matches the compactc 0.30.0 read pattern, the
    /// same shape `Map::contains` uses for its trailing Popeq):
    ///
    /// ```text
    /// Dup  { n: 0 }                                        // [0x30]
    /// Idx  { cached: false, push_path: false, [Bytes<1>(field_idx)] }
    ///                                                       // [0x50, align(2), field_idx(1)]
    /// Popeq { cached: false, result: AlignedValue<T> }     // [0x0c, align(2), result(1)]
    /// ```
    ///
    /// `result_ty` carries the read-result type (`u64` for Counter,
    /// `T` for `Cell<T>`). When `Some` with a single-Fr encoding, emit the
    /// full 4-declare Popeq the on-chain VM expects. When `None` or
    /// multi-Fr, fall back to the legacy 1-declare Popeq — that path is
    /// internally consistent with our transcript codegen (so unit tests
    /// pass) but is NOT on-chain compatible.
    fn emit_ledger_read(&mut self, field_idx: u8, result_ty: Option<&syn::Type>) -> Option<Index> {
        let g = self.guard;

        // Dup { n: 0 } → field repr: [0x30]
        let dup_op = self.emit_load_imm(Fr::from(0x30u64));
        self.push_declare_pub_input(dup_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        // Idx { cached: false, push_path: false, path: [Value(field_idx)] }
        // Opcode: 0x50 | 0 = 0x50
        let idx_op = self.emit_load_imm(Fr::from(0x50u64));
        self.push_declare_pub_input(idx_op);
        self.emit_key_field_repr(field_idx);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // Popeq { cached: true, result: AlignedValue<T> } → 0x0d. Reads use
        // the cached form because the value the prover claims is in the
        // transcript; the VM just verifies it matches the slot it walked to.
        //
        // For multi-Fr results (e.g. Bytes<32> → 2 Frs), the Popeq value
        // field is itself multi-Fr: one PublicInput + DeclarePubInput per
        // chunk. The chunks come back from `public_transcript_outputs` in
        // the same order `AlignedValueExt::value_only_field_repr` writes
        // them on the construct_proof side, which mirrors the IR's
        // sequential PublicInput consumption.
        let result_enc =
            result_ty.and_then(|t| aligned_value_encoding(t, &self.user_structs, &self.user_enums));
        let popeq_op = self.emit_load_imm(Fr::from(0x0du64));
        self.push_declare_pub_input(popeq_op);

        match result_enc {
            Some(enc) if enc.value_field_count >= 1 => {
                let value_layout = result_ty
                    .map(|t| read_result_fr_layout(t, &self.user_structs, &self.user_enums))
                    .unwrap_or_else(|| vec![None; enc.value_field_count]);
                // Defensive cross-check of the two type-recursion stacks:
                // a Fr-count disagreement between the layout and the
                // alignment encoding would emit fewer PublicInputs than
                // PiSkip claims (the H4 bug class). Fail loudly.
                if value_layout.len() != enc.value_field_count {
                    return self.unsupported(format!(
                        "ledger read result wire layout ({} Frs) disagrees with its \
                         value encoding ({} Frs); this type cannot be read soundly",
                        value_layout.len(),
                        enc.value_field_count
                    ));
                }
                for atom in &enc.alignment_atoms {
                    let v = self.emit_load_imm(Fr::from(*atom));
                    self.push_declare_pub_input(v);
                }
                let mut first_value: Option<Index> = None;
                for bits in value_layout.iter().take(enc.value_field_count) {
                    let pi = self.emit_instruction(Instruction::PublicInput {
                        guard: self.current_io_guard(),
                    });
                    if first_value.is_none() {
                        first_value = Some(pi);
                    }
                    if let Some(b) = bits {
                        self.instructions
                            .push(Instruction::ConstrainBits { var: pi, bits: *b });
                    }
                    self.push_declare_pub_input(pi);
                }
                let count = 1 + enc.alignment_atoms.len() + enc.value_field_count;
                self.instructions.push(Instruction::PiSkip {
                    guard: Some(g),
                    count: count as u32,
                });
                first_value
            }
            _ => {
                // Legacy 1-declare fallback. Not on-chain compatible — only
                // for unknown result types. Emits one PublicInput so the
                // existing internal-consistency tests keep working.
                let pi = self.emit_instruction(Instruction::PublicInput {
                    guard: self.current_io_guard(),
                });
                self.instructions.push(Instruction::PiSkip {
                    guard: Some(g),
                    count: 1,
                });
                Some(pi)
            }
        }
    }

    /// Dispatch a method call on a `Map<K, V>` ledger field to the
    /// per-operation emitter. The dispatcher knows the `K` type so it can
    /// compute the right key encoding. Unsupported methods log a warning
    /// (via `Unsupported` token) and fall through to a no-op.
    fn emit_map_method(
        &mut self,
        field_idx: u8,
        method_name: &str,
        args: &[nocturne_ir::ExprIR],
        k_ty: &syn::Type,
        v_ty: &syn::Type,
    ) -> Option<Index> {
        let Some(key_enc) = aligned_value_encoding(k_ty, &self.user_structs, &self.user_enums)
        else {
            return self.unsupported(format!(
                "Map key type `{}` has no supported on-chain encoding",
                quote::quote!(#k_ty)
            ));
        };

        match method_name {
            "contains" => {
                let first = args.first().and_then(|a| self.emit_expr(a))?;
                let key_vars = gather_n_vars(first, key_enc.value_field_count);
                self.emit_map_member(field_idx, &key_vars, &key_enc)
            }
            "insert" | "set" => {
                let Some(val_enc) =
                    aligned_value_encoding(v_ty, &self.user_structs, &self.user_enums)
                else {
                    return self.unsupported(format!(
                        "Map value type `{}` has no supported on-chain encoding",
                        quote::quote!(#v_ty)
                    ));
                };
                let k_first = args.first().and_then(|a| self.emit_expr(a))?;
                let v_first = args.get(1).and_then(|a| self.emit_expr(a))?;
                let key_vars = gather_n_vars(k_first, key_enc.value_field_count);
                let val_vars = gather_n_vars(v_first, val_enc.value_field_count);
                self.emit_map_insert(field_idx, &key_vars, &key_enc, &val_vars, &val_enc)
            }
            "remove" => {
                let first = args.first().and_then(|a| self.emit_expr(a))?;
                let key_vars = gather_n_vars(first, key_enc.value_field_count);
                self.emit_map_remove(field_idx, &key_vars, &key_enc)
            }
            "lookup" => {
                let Some(val_enc) =
                    aligned_value_encoding(v_ty, &self.user_structs, &self.user_enums)
                else {
                    return self.unsupported(format!(
                        "Map value type `{}` has no supported on-chain encoding",
                        quote::quote!(#v_ty)
                    ));
                };
                let first = args.first().and_then(|a| self.emit_expr(a))?;
                let key_vars = gather_n_vars(first, key_enc.value_field_count);
                self.emit_map_lookup(field_idx, &key_vars, &key_enc, v_ty, &val_enc)
            }
            // `get` returns Option<V> outside the parser's
            // `if let Some(v) = map.get(&k)` sugar — Popeq cannot
            // represent Null, so a raw `get` has no on-chain lowering.
            other => self.unsupported(format!(
                "unsupported Map method `{other}` (use the `if let Some(v) = \
                 map.get(&k)` form for optional reads)"
            )),
        }
    }

    /// Emit ZKIR for `Map::insert(k, v)` at `field_idx`.
    ///
    /// On-chain encoding (matches compactc 0.30.0 for `m.insert(k, v)`):
    ///
    /// ```text
    /// Idx  { cached: false, push_path: true, path: [field_idx] }  // [0x70, align(2), field_idx(1)]
    /// Push { storage: false, value: Cell(key) }                    // [0x10, Cell disc(1), K-align, K-value]
    /// Push { storage: true,  value: Cell(value) }                  // [0x11, Cell disc(1), V-align, V-value]
    /// Ins  { cached: false, n: 1 }                                 // [0x91]  insert (k, v) into Map
    /// Ins  { cached: true,  n: 1 }                                 // [0xa1]  write modified Map back to Array
    /// ```
    ///
    /// `Idx { push_path: true }` navigates into the Map field while keeping
    /// the parent Array on the stack (so the second `Ins` can put the
    /// modified Map back). The first `Ins` pops `[value, key, map]` and
    /// inserts. The second `Ins` pops `[modified_map, path, array]` and
    /// restores the field. Sequence matches compactc 0.30.0's emission
    /// for `Map::insert`; opcode field_reprs per midnight-ledger
    /// ledger-8, onchain-vm/src/ops.rs:400-462.
    fn emit_map_insert(
        &mut self,
        field_idx: u8,
        key_vars: &[Index],
        key_encoding: &AlignedValueEncoding,
        val_vars: &[Index],
        val_encoding: &AlignedValueEncoding,
    ) -> Option<Index> {
        let g = self.guard;

        // Idx { cached: false, push_path: true, path: [Bytes<1>(field_idx)] } → 0x70.
        let idx_op = self.emit_load_imm(Fr::from(0x70u64));
        self.push_declare_pub_input(idx_op);
        self.emit_key_field_repr(field_idx);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // Push { storage: false, value: Cell(key) } — the K side.
        self.emit_push_cell(key_vars, Some(key_encoding), /* storage = */ false);

        // Push { storage: true, value: Cell(value) } — the V side.
        self.emit_push_cell(val_vars, Some(val_encoding), /* storage = */ true);

        // Ins { cached: false, n: 1 } → 0x91 — first Ins: (k, v) into Map.
        let ins1_op = self.emit_load_imm(Fr::from(0x91u64));
        self.push_declare_pub_input(ins1_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        // Ins { cached: true, n: 1 } → 0xa1 — second Ins: write Map back to Array.
        let ins2_op = self.emit_load_imm(Fr::from(0xa1u64));
        self.push_declare_pub_input(ins2_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        // Insert returns no value to the circuit.
        None
    }

    /// Emit ZKIR for `Map::contains(k) -> Boolean` at `field_idx`.
    ///
    /// On-chain encoding (verified empirically against compactc 0.30.0 for
    /// `Map<Bytes<32>, Uint<64>>`; opcode field_reprs per midnight-ledger
    /// ledger-8, onchain-vm/src/ops.rs:400-462):
    ///
    /// ```text
    /// Dup  { n: 0 }                                        // [0x30]
    /// Idx  { cached: false, push_path: false, path: [k] }  // [0x50, align(2), field_idx(1)]
    /// Push { storage: false, value: Cell(user_key) }       // [0x10, Cell disc(1), align(2), value]
    /// Member                                                // [0x18]
    /// Popeq { cached: true, result: Boolean }              // [0x0d, align(2), bool_result]
    /// ```
    ///
    /// `Member` pops `[key, container]` and pushes a boolean. `Popeq` then
    /// pops the boolean and the runtime fills its `result` slot via the
    /// transcript outputs (read via `PublicInput` on the prover side).
    fn emit_map_member(
        &mut self,
        field_idx: u8,
        key_vars: &[Index],
        key_encoding: &AlignedValueEncoding,
    ) -> Option<Index> {
        let g = self.guard;

        // Dup { n: 0 } → 0x30.
        let dup_op = self.emit_load_imm(Fr::from(0x30u64));
        self.push_declare_pub_input(dup_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        // Idx { cached: false, push_path: false, len: 1 } selecting the Map
        // field by its ledger-struct index. Key is Bytes<1>.
        let idx_op = self.emit_load_imm(Fr::from(0x50u64));
        self.push_declare_pub_input(idx_op);
        self.emit_key_field_repr(field_idx);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // Push { storage: false, value: StateValue::Cell(AlignedValue(user_key)) }.
        // Uses emit_push_cell which handles the [opcode, Cell disc, alignment,
        // value] structure — supports multi-Fr K (e.g. Bytes<32>).
        self.emit_push_cell(key_vars, Some(key_encoding), /* storage = */ false);

        // Member → 0x18.
        let member_op = self.emit_load_imm(Fr::from(0x18u64));
        self.push_declare_pub_input(member_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        // Popeq { cached: true, result: Boolean } → [0x0d, 1 (align seg_count),
        // 1 (Bytes<1> atom), bool_result]. PublicInput reads the result Fr
        // from the transcript outputs into memory; that same value is then
        // declared as the fourth field of the Popeq encoding.
        let popeq_op = self.emit_load_imm(Fr::from(0x0du64));
        let result_var = self.emit_instruction(Instruction::PublicInput {
            guard: self.current_io_guard(),
        });
        self.push_declare_pub_input(popeq_op);
        let align_one = self.emit_load_imm(Fr::from(1u64));
        self.push_declare_pub_input(align_one);
        self.push_declare_pub_input(align_one);
        self.push_declare_pub_input(result_var);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // The Boolean result is in the verifier's view, so emit a
        // ConstrainToBoolean over it for safety.
        self.instructions
            .push(Instruction::ConstrainToBoolean { var: result_var });

        Some(result_var)
    }

    /// Emit ZKIR for `Map::lookup(&k) -> V` at `field_idx`.
    ///
    /// Mirrors compactc 0.30.0 emission for `m.lookup(k)` (see
    /// `/tmp/cond-experiments/map_out/zkir/lookup.zkir`):
    ///
    /// ```text
    /// Dup  { n: 0 }                                          // [0x30]
    /// Idx  { cached: false, push_path: false, [Bytes<1>(f)]} // [0x50, 1, 1, field_idx]
    /// Idx  { cached: false, push_path: false, [Cell(key)]}   // [0x50, 1, K-align, K-value]
    /// Popeq { cached: false, result: AlignedValue<V> }       // [0x0c, 1, V-align, value]
    /// ```
    ///
    /// `lookup` is assert-exists: if the key is missing, the on-chain VM
    /// puts `StateValue::Null` on the stack at the second `Idx`, then the
    /// `Popeq` fails at `.as_cell()`. Callers that may not have the key
    /// should `contains` first or use `Map::get` (Option<V>) when that
    /// arrives.
    ///
    /// The second `Idx` (the one indexing by the user key) drops `push_path`
    /// because we don't need to write back — `lookup` is read-only.
    fn emit_map_lookup(
        &mut self,
        field_idx: u8,
        key_vars: &[Index],
        key_encoding: &AlignedValueEncoding,
        v_ty: &syn::Type,
        val_encoding: &AlignedValueEncoding,
    ) -> Option<Index> {
        let g = self.guard;

        // Dup { n: 0 } → 0x30.
        let dup_op = self.emit_load_imm(Fr::from(0x30u64));
        self.push_declare_pub_input(dup_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        // Idx { cached: false, push_path: false, path: [Bytes<1>(field_idx)] }
        // navigates into the contract Array to land on the Map slot.
        let idx_op = self.emit_load_imm(Fr::from(0x50u64));
        self.push_declare_pub_input(idx_op);
        self.emit_key_field_repr(field_idx);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // Second Idx: same opcode, but with the user-typed key as path. The
        // path entry is `Key::Value(av)` whose field_repr is
        // `[seg_count, ..atoms, ..value_frs]`. For multi-Fr K (Bytes<N> with
        // N>31), value_frs spans `key_encoding.value_field_count` Frs and
        // matches the contiguous PrivateInputs produced for the key witness.
        let idx_op2 = self.emit_load_imm(Fr::from(0x50u64));
        self.push_declare_pub_input(idx_op2);
        for atom in &key_encoding.alignment_atoms {
            let v = self.emit_load_imm(Fr::from(*atom));
            self.push_declare_pub_input(v);
        }
        for &kv in key_vars {
            self.push_declare_pub_input(kv);
        }
        // Total: opcode (1) + alignment atoms (N) + value frs (M)
        let count2 = 1 + key_encoding.alignment_atoms.len() + key_vars.len();
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: count2 as u32,
        });

        // Popeq { cached: false, result: AlignedValue<V> } → 0x0c.
        // Compactc uses 0x0c (cached:false) for lookup specifically —
        // distinct from member's cached:true — because the actual read
        // happens here. For multi-Fr V (e.g. Bytes<32>), the value field is
        // itself multi-Fr: one PublicInput + DeclarePubInput per chunk,
        // matching `read_result_fr_layout`.
        let value_layout = read_result_fr_layout(v_ty, &self.user_structs, &self.user_enums);
        // Same defensive cross-check as `emit_ledger_read`: the layout's
        // Fr count and the alignment encoding's Fr count must agree or
        // the PI window misaligns.
        if value_layout.len() != val_encoding.value_field_count {
            return self.unsupported(format!(
                "Map lookup value wire layout ({} Frs) disagrees with its value \
                 encoding ({} Frs); this value type cannot be read soundly",
                value_layout.len(),
                val_encoding.value_field_count
            ));
        }
        let popeq_op = self.emit_load_imm(Fr::from(0x0cu64));
        self.push_declare_pub_input(popeq_op);
        for atom in &val_encoding.alignment_atoms {
            let v = self.emit_load_imm(Fr::from(*atom));
            self.push_declare_pub_input(v);
        }
        let mut first_value: Option<Index> = None;
        for bits in value_layout.iter().take(val_encoding.value_field_count) {
            let pi = self.emit_instruction(Instruction::PublicInput {
                guard: self.current_io_guard(),
            });
            if first_value.is_none() {
                first_value = Some(pi);
            }
            if let Some(b) = bits {
                self.instructions
                    .push(Instruction::ConstrainBits { var: pi, bits: *b });
            }
            self.push_declare_pub_input(pi);
        }
        let count3 = 1 + val_encoding.alignment_atoms.len() + val_encoding.value_field_count;
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: count3 as u32,
        });

        first_value
    }

    /// Emit ZKIR for `Map::remove(&k)` at `field_idx`. The return value
    /// (`Option<V>` at the runtime level) is currently discarded by the
    /// circuit — `get`/`lookup` will plumb it through once Option alignment
    /// encoding lands.
    ///
    /// On-chain encoding mirrors `insert` minus the value Push and minus
    /// one Ins, since `Rem` pops `[key, container]` and pushes back the
    /// modified container in one step:
    ///
    /// ```text
    /// Idx  { cached: false, push_path: true, path: [field_idx] }  // [0x70, align(2), field_idx(1)]
    /// Push { storage: false, value: Cell(key) }                    // [0x10, Cell disc(1), K-align, K-value]
    /// Rem  { cached: false }                                       // [0x19]  remove k from Map
    /// Ins  { cached: true,  n: 1 }                                 // [0xa1]  write modified Map back to Array
    /// ```
    fn emit_map_remove(
        &mut self,
        field_idx: u8,
        key_vars: &[Index],
        key_encoding: &AlignedValueEncoding,
    ) -> Option<Index> {
        let g = self.guard;

        // Idx { cached: false, push_path: true, path: [Bytes<1>(field_idx)] } → 0x70.
        let idx_op = self.emit_load_imm(Fr::from(0x70u64));
        self.push_declare_pub_input(idx_op);
        self.emit_key_field_repr(field_idx);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // Push { storage: false, value: Cell(key) }. Supports multi-Fr K.
        self.emit_push_cell(key_vars, Some(key_encoding), /* storage = */ false);

        // Rem { cached: false } → 0x19.
        let rem_op = self.emit_load_imm(Fr::from(0x19u64));
        self.push_declare_pub_input(rem_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        // Ins { cached: true, n: 1 } → 0xa1 — restore parent Array.
        let ins_op = self.emit_load_imm(Fr::from(0xa1u64));
        self.push_declare_pub_input(ins_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        None
    }

    /// Dispatch a method call on a `Set<T>` ledger field. Set reuses
    /// `Map`'s on-chain ops with `StateValue::Null` as the placeholder
    /// value — `contains`/`member` and `remove` are identical to their
    /// Map counterparts; `insert` differs only in pushing Null instead
    /// of `Cell(value)` for the value slot.
    ///
    /// Empirically verified against compactc 0.22 for `Set<Bytes<32>>`
    /// (`/tmp/set-experiments/out/zkir/{add,check,erase}.zkir`).
    fn emit_set_method(
        &mut self,
        field_idx: u8,
        method_name: &str,
        args: &[nocturne_ir::ExprIR],
        t_ty: &syn::Type,
    ) -> Option<Index> {
        let Some(key_enc) = aligned_value_encoding(t_ty, &self.user_structs, &self.user_enums)
        else {
            return self.unsupported(format!(
                "Set element type `{}` has no supported on-chain encoding",
                quote::quote!(#t_ty)
            ));
        };
        match method_name {
            "contains" | "member" => {
                let first = args.first().and_then(|a| self.emit_expr(a))?;
                let key_vars = gather_n_vars(first, key_enc.value_field_count);
                self.emit_map_member(field_idx, &key_vars, &key_enc)
            }
            "insert" => {
                let first = args.first().and_then(|a| self.emit_expr(a))?;
                let key_vars = gather_n_vars(first, key_enc.value_field_count);
                self.emit_set_insert(field_idx, &key_vars, &key_enc)
            }
            "remove" => {
                let first = args.first().and_then(|a| self.emit_expr(a))?;
                let key_vars = gather_n_vars(first, key_enc.value_field_count);
                self.emit_map_remove(field_idx, &key_vars, &key_enc)
            }
            other => self.unsupported(format!("unsupported Set method `{other}`")),
        }
    }

    /// Emit ZKIR for `Set<T>::insert(k)` at `field_idx`. Same shape as
    /// `Map::insert` except the value Push pushes `StateValue::Null`
    /// instead of `StateValue::Cell(value)`:
    ///
    /// ```text
    /// Idx  { cached: false, push_path: true, [field_idx] }  // navigate to Set
    /// Push { storage: false, Cell(key) }                     // K bytes
    /// Push { storage: true,  Null }                          // [0x11, 0]
    /// Ins  { cached: false, n: 1 }                           // insert (k, Null)
    /// Ins  { cached: true,  n: 1 }                           // restore parent
    /// ```
    fn emit_set_insert(
        &mut self,
        field_idx: u8,
        key_vars: &[Index],
        key_encoding: &AlignedValueEncoding,
    ) -> Option<Index> {
        let g = self.guard;

        // Idx { cached: false, push_path: true, path: [Bytes<1>(field_idx)] } → 0x70.
        let idx_op = self.emit_load_imm(Fr::from(0x70u64));
        self.push_declare_pub_input(idx_op);
        self.emit_key_field_repr(field_idx);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // Push { storage: false, value: Cell(key) }.
        self.emit_push_cell(key_vars, Some(key_encoding), /* storage = */ false);

        // Push { storage: true, value: Null } → [0x11, 0]. 2 declares total.
        self.emit_push_null(/* storage = */ true);

        // Ins { cached: false, n: 1 } → 0x91.
        let ins1_op = self.emit_load_imm(Fr::from(0x91u64));
        self.push_declare_pub_input(ins1_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        // Ins { cached: true, n: 1 } → 0xa1.
        let ins2_op = self.emit_load_imm(Fr::from(0xa1u64));
        self.push_declare_pub_input(ins2_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        None
    }

    /// Emit ZKIR for `merkle_tree_path_root(&witnesses.path)`. Pure
    /// circuit primitive (no ledger ops, no transcript declares) — just
    /// computes the Merkle root from the path's leaf and sibling chain.
    ///
    /// Matches compactc 0.30.0's emission for `merkleTreePathRoot<H, T>`
    /// (see `/tmp/mt-experiments/out2/zkir/check_path.zkir`):
    ///
    /// ```text
    /// persistent_hash([Bytes{6}, Bytes{32}], [domain_sep, leaf_0, leaf_1])  // → 2 Frs
    /// acc = persistent_hash_result[1]                                        // degrade_to_transient
    /// for i in 0..H:
    ///   left  = cond_select(goes_left[i], acc, sibling[i])
    ///   right = cond_select(goes_left[i], sibling[i], acc)
    ///   acc   = transient_hash(left, right)
    /// // acc is the root
    /// ```
    ///
    /// Today this is specialized to `Bytes<32>` leaves — same as
    /// `emit_merkle_tree_insert`. The argument must be a witness of
    /// type `MerkleTreePath<H, Bytes<N>>` whose layout the IR can
    /// parse from `self.witness_types`.
    fn emit_merkle_tree_path_root(&mut self, args: &[nocturne_ir::ExprIR]) -> Option<Index> {
        use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment};

        // Single lookup of the argument — reused below to emit the
        // witness wires, so there's no second (silently failing) fetch.
        let Some(arg) = args.first() else {
            return self.unsupported(
                "merkle_tree_path_root takes exactly one argument \
                 (`&witnesses.<field>` of type `MerkleTreePath<H, Bytes<N>>`)",
            );
        };
        // Drill through `Reference` to find the WitnessAccess.
        let resolved = find_witness_field(arg).and_then(|field| {
            let ty = self.witness_types.get(&field).cloned()?;
            let ty_str = quote::quote!(#ty).to_string().replace(' ', "");
            parse_merkle_tree_path_type(&ty_str)
        });
        let Some((height, leaf_ty_str)) = resolved else {
            return self.unsupported(
                "merkle_tree_path_root's argument must be a witness field of type \
                 `MerkleTreePath<H, Bytes<N>>`",
            );
        };
        // Any `Bytes<N>` leaf is supported. The leaf is hashed with
        // `persistent_hash` under alignment `[Bytes{6}, Bytes{N}]`,
        // matching upstream's `leaf_hash` byte-stream concatenation. The
        // storage helper accepts any `MerkleLeaf` (broader than Bytes<N>).
        let Some(leaf_n) = parse_bytes_n_type(&leaf_ty_str) else {
            return self
                .unsupported("merkle_tree_path_root currently supports `Bytes<N>` leaves only");
        };
        let leaf_fr_count = leaf_n.div_ceil(FR_BYTES_STORED) as usize;

        // Emit the witness PrivateInputs by evaluating the arg.
        let first_var = self.emit_expr(arg)?;
        // Layout (matching `witness_fr_layout`):
        //   first_var + 0..leaf_fr_count             → leaf chunks
        //   first_var + leaf_fr_count + 2i           → sibling i (Field, no constraint)
        //   first_var + leaf_fr_count + 2i + 1       → goes_left i (Boolean)
        let leaf_chunks = gather_n_vars(first_var, leaf_fr_count);
        let mut entry_vars = Vec::with_capacity(height as usize);
        for i in 0..(height as usize) {
            let base = first_var + (leaf_fr_count as u32) + 2 * (i as u32);
            entry_vars.push((base, base + 1)); // (sibling, goes_left)
        }

        // persistent_hash with the "mdn:lh" domain separator.
        // Alignment [Bytes{6}, Bytes{leaf_n}], inputs [domain_sep, leaf...].
        let domain_sep = self.emit_load_imm(domain_sep_fr_mdn_lh());
        let alignment = Alignment(vec![
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 6 }),
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: leaf_n }),
        ]);
        let mut hash_inputs = vec![domain_sep];
        hash_inputs.extend(leaf_chunks.iter().copied());
        let hash_first = self.emit_instruction(Instruction::PersistentHash {
            alignment,
            inputs: hash_inputs,
        });
        // PersistentHash outputs 2 Frs; degrade_to_transient picks the
        // SECOND one (`persistent.field_vec()[1]`, see
        // `transient-crypto/src/hash.rs:71-73`).
        let mut acc = hash_first + 1;

        // Unrolled fold: for each entry, cond_select-swap then transient_hash.
        for (sibling, goes_left) in entry_vars {
            let left = self.emit_instruction(Instruction::CondSelect {
                bit: goes_left,
                a: acc,
                b: sibling,
            });
            let right = self.emit_instruction(Instruction::CondSelect {
                bit: goes_left,
                a: sibling,
                b: acc,
            });
            acc = self.emit_instruction(Instruction::TransientHash {
                inputs: vec![left, right],
            });
        }

        Some(acc)
    }

    /// Emit a `Push { storage, value: StateValue::Null }` group — used by
    /// Set::insert for the value slot. `Null` encodes as a single field
    /// element `0` (`state.rs::field_repr` line 176), so the group is
    /// just `[opcode, 0]` — 2 declares total.
    fn emit_push_null(&mut self, storage: bool) {
        let g = self.guard;
        let push_op = self.emit_load_imm(Fr::from(if storage { 0x11u64 } else { 0x10u64 }));
        let null_disc = self.emit_load_imm(Fr::from(0u64));
        self.push_declare_pub_input(push_op);
        self.push_declare_pub_input(null_disc);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 2,
        });
    }

    /// Dispatch a method call on a `MerkleTree<H, T>` ledger field
    /// (`check_root` and `insert`). Encodings verified against compactc
    /// 0.30.0's emission for `MerkleTree<10, Bytes<32>>`; the
    /// tree-specific opcodes are `Root` (0x0a, pops a BoundedMerkleTree
    /// and pushes its root) and `Eq` (0x02) — midnight-ledger ledger-8,
    /// onchain-vm/src/vm.rs:562-577 and vm.rs:408-413.
    fn emit_merkle_tree_method(
        &mut self,
        field_idx: u8,
        method_name: &str,
        args: &[nocturne_ir::ExprIR],
    ) -> Option<Index> {
        match method_name {
            "check_root" => {
                // The argument is `&MerkleTreeDigest` (or anything that
                // evaluates to a Field-typed Fr). emit_expr yields the
                // Index where that Fr lives in memory; we Push it as a
                // `Cell(Field(...))` for the on-chain Eq comparison.
                let digest_var = args.first().and_then(|a| self.emit_expr(a))?;
                self.emit_merkle_tree_check_root(field_idx, digest_var)
            }
            "insert" => {
                // The argument is `Bytes<N>` (the leaf). emit_expr returns
                // the first PrivateInput var; we gather the contiguous
                // `ceil(N/31)` Frs and feed them into the leafHash
                // persistent_hash call. Pull N from the field type so
                // emission tracks the user-declared leaf size.
                let leaf_ty = self
                    .field_types
                    .get(field_idx as usize)
                    .and_then(extract_merkle_tree_type);
                let leaf_n = leaf_ty.as_ref().and_then(|t| {
                    let s = quote::quote!(#t).to_string().replace(' ', "");
                    parse_bytes_n_type(&s)
                });
                let Some(leaf_n) = leaf_n else {
                    return self.unsupported(
                        "MerkleTree::insert leaf type must be `Bytes<N>`".to_string(),
                    );
                };
                let leaf_first = args.first().and_then(|a| self.emit_expr(a))?;
                self.emit_merkle_tree_insert(field_idx, leaf_first, leaf_n)
            }
            other => self.unsupported(format!("unsupported MerkleTree method `{other}`")),
        }
    }

    /// Emit ZKIR for `MerkleTree::insert(leaf)` at `field_idx`. Matches
    /// compactc 0.30.0's emission for `entries.insert(disclose(leaf))`
    /// (see `/tmp/mt-experiments/out/zkir/add.zkir`):
    ///
    /// ```text
    /// Idx  { cached:false, push_path:true,  [Bytes<1>(field_idx)] }   // navigate to entries field
    /// Idx  { cached:false, push_path:true,  [Bytes<1>(0)] }            // navigate into entries[0] (BMT)
    /// Dup  { n: 2 }                                                     // copy entries Array from stack pos 2
    /// Idx  { cached:false, push_path:false, [Bytes<1>(1)] }            // read entries[1] (next-index counter)
    /// Push { storage:true, Cell(Bytes<32>(leafHash(leaf))) }            // hashed leaf
    /// Ins  { cached:false, n: 1 }                                       // insert (next_index, leaf_hash) into BMT
    /// Ins  { cached:true,  n: 1 }                                       // write modified BMT back to entries[0]
    /// Idx  { cached:false, push_path:true,  [Bytes<1>(1)] }            // navigate to entries[1]
    /// Addi { immediate: 1 }                                              // increment counter
    /// Ins  { cached:true,  n: 2 }                                       // write back counter, 2 levels deep
    /// ```
    ///
    /// `leafHash` is `persistent_hash(["mdn:lh", leaf_bytes])` —
    /// alignment `[Bytes{6}, Bytes{32}]`, inputs `[domain_sep_imm,
    /// leaf_chunk_0, leaf_chunk_1]`. The result is 2 Frs (the 32-byte
    /// hash chunked) that flow into the Push as the Bytes<32> value.
    ///
    /// Supports any `Bytes<N>` leaf type: `leaf_n` is the byte length of
    /// the leaf and `leaf_fr_count = ceil(leaf_n / FR_BYTES_STORED)` is
    /// the number of Fr chunks the witness expands into. The leafHash
    /// `persistent_hash` uses alignment `[Bytes{6}, Bytes{leaf_n}]`
    /// (matching upstream's `leaf_hash`-as-byte-stream); the resulting
    /// hash is always Bytes<32> regardless of leaf size.
    fn emit_merkle_tree_insert(
        &mut self,
        field_idx: u8,
        leaf_first: Index,
        leaf_n: u32,
    ) -> Option<Index> {
        use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment};
        let g = self.guard;

        // Idx { push_path:true, [Bytes<1>(field_idx)] } → 0x70.
        let idx_op = self.emit_load_imm(Fr::from(0x70u64));
        self.push_declare_pub_input(idx_op);
        self.emit_key_field_repr(field_idx);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // Idx { push_path:true, [Bytes<1>(0)] } — navigate into entries[0] (BMT).
        let idx_op_2 = self.emit_load_imm(Fr::from(0x70u64));
        self.push_declare_pub_input(idx_op_2);
        self.emit_key_field_repr(0);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // Dup { n: 2 } → 0x32.
        let dup_op = self.emit_load_imm(Fr::from(0x32u64));
        self.push_declare_pub_input(dup_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        // Idx { push_path:false, [Bytes<1>(1)] } — read entries[1] (counter slot).
        let idx_op_3 = self.emit_load_imm(Fr::from(0x50u64));
        self.push_declare_pub_input(idx_op_3);
        self.emit_key_field_repr(1);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // Compute leafHash via persistent_hash with the "mdn:lh" domain
        // separator. The hash output is 2 Frs (32-byte hash chunked).
        // Domain separator immediate: ASCII "mdn:lh" → 6 bytes →
        // little-endian Fr = 0x686C3A6E646D. (Compact emits it in
        // big-endian byte order; our LoadImm parses Fr in whichever
        // direction the value flows through.)
        let domain_sep = self.emit_load_imm(domain_sep_fr_mdn_lh());
        let leaf_fr_count = leaf_n.div_ceil(FR_BYTES_STORED) as usize;
        let leaf_chunks = gather_n_vars(leaf_first, leaf_fr_count);
        let hash_align = Alignment(vec![
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 6 }),
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: leaf_n }),
        ]);
        let mut hash_inputs = vec![domain_sep];
        hash_inputs.extend(leaf_chunks);
        let hash_first = self.emit_instruction(Instruction::PersistentHash {
            alignment: hash_align,
            inputs: hash_inputs,
        });
        // PersistentHash outputs 2 Frs; both are needed for the Push.
        let hash_chunks = gather_n_vars(hash_first, 2);

        // Push { storage:true, Cell(Bytes<32>(leaf_hash)) }. The value
        // is 2 Frs (the chunked hash); alignment is [1, 32].
        let push_op = self.emit_load_imm(Fr::from(0x11u64));
        let cell_disc = self.emit_load_imm(Fr::from(1u64));
        let bytes32_atom = self.emit_load_imm(Fr::from(32u64));
        self.push_declare_pub_input(push_op);
        self.push_declare_pub_input(cell_disc);
        self.push_declare_pub_input(cell_disc);
        self.push_declare_pub_input(bytes32_atom);
        for chunk in &hash_chunks {
            self.push_declare_pub_input(*chunk);
        }
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 6,
        });

        // Ins { cached:false, n: 1 } → 0x91. Insert (next_index, hash) into BMT.
        let ins1 = self.emit_load_imm(Fr::from(0x91u64));
        self.push_declare_pub_input(ins1);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        // Ins { cached:true, n: 1 } → 0xa1. Write BMT back into entries[0].
        let ins2 = self.emit_load_imm(Fr::from(0xa1u64));
        self.push_declare_pub_input(ins2);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        // Idx { push_path:true, [Bytes<1>(1)] } — navigate to entries[1].
        let idx_op_4 = self.emit_load_imm(Fr::from(0x70u64));
        self.push_declare_pub_input(idx_op_4);
        self.emit_key_field_repr(1);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // Addi { immediate: 1 } → [0x0e, 1]. Increment counter.
        let addi_op = self.emit_load_imm(Fr::from(0x0eu64));
        let one = self.emit_load_imm(Fr::from(1u64));
        self.push_declare_pub_input(addi_op);
        self.push_declare_pub_input(one);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 2,
        });

        // Ins { cached:true, n: 2 } → 0xa2. Write back counter; n:2 because
        // we navigated `entries` then `[1]` — two `Idx{push_path:true}`
        // levels deep — so the trailing Ins must unwind both levels.
        let ins3 = self.emit_load_imm(Fr::from(0xa2u64));
        self.push_declare_pub_input(ins3);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        None
    }

    /// Emit ZKIR for `MerkleTree::check_root(&digest) -> bool` at
    /// `field_idx`. Matches compactc 0.30.0's emission for
    /// `entries.checkRoot(disclose(r))` (see
    /// `/tmp/mt-experiments/out/zkir/check_root.zkir`):
    ///
    /// ```text
    /// Dup  { n: 0 }                                                   // [0x30]
    /// Idx  { cached:false, push_path:false, [Bytes<1>(field_idx)] }  // [0x50, 1, 1, field_idx]
    /// Idx  { cached:false, push_path:false, [Bytes<1>(0)] }           // [0x50, 1, 1, 0]
    /// Root                                                              // [0x0a]
    /// Push { storage:false, Cell(Field(user_digest)) }                 // [0x10, 1, 1, -2, digest_fr]
    /// Eq                                                                // [0x02]
    /// Popeq { cached:true, result:bool }                                // [0x0d, 1, 1, bool]
    /// ```
    ///
    /// The two Idx ops navigate `entries` (the user's field) and then
    /// `entries[0]` (the BoundedMerkleTree inside the 2-element Array
    /// — the second element is the `next_index: Cell<u64>` counter,
    /// which checkRoot doesn't touch). `Root` pops the BMT and pushes
    /// its root as `AlignedValue<Field>`. `Eq` compares two
    /// `StateValue::Cell` operands and pushes a bool.
    fn emit_merkle_tree_check_root(&mut self, field_idx: u8, digest_var: Index) -> Option<Index> {
        let g = self.guard;

        // Dup { n: 0 }.
        let dup_op = self.emit_load_imm(Fr::from(0x30u64));
        self.push_declare_pub_input(dup_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        // Idx into the user's field.
        let idx_op_1 = self.emit_load_imm(Fr::from(0x50u64));
        self.push_declare_pub_input(idx_op_1);
        self.emit_key_field_repr(field_idx);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // Idx into entries[0] = BoundedMerkleTree.
        let idx_op_2 = self.emit_load_imm(Fr::from(0x50u64));
        self.push_declare_pub_input(idx_op_2);
        self.emit_key_field_repr(0);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // Root { 0x0a } pops the BMT, pushes Cell(Field(root_fr)).
        let root_op = self.emit_load_imm(Fr::from(0x0au64));
        self.push_declare_pub_input(root_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        // Push { storage:false, Cell(Field(user_digest)) }. Reuse
        // emit_push_cell with the Field encoding from Phase A.
        let field_ty: syn::Type = syn::parse_quote!(Field);
        let enc = aligned_value_encoding(&field_ty, &self.user_structs, &self.user_enums)
            .expect("Field encoding must exist");
        self.emit_push_cell(&[digest_var], Some(&enc), /* storage = */ false);

        // Eq { 0x02 } compares the two Cells on the stack and pushes a bool.
        let eq_op = self.emit_load_imm(Fr::from(0x02u64));
        self.push_declare_pub_input(eq_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 1,
        });

        // Popeq { cached:true, result: bool }. Single PublicInput for
        // the bool result (1 Fr, no alignment chunking).
        let popeq_op = self.emit_load_imm(Fr::from(0x0du64));
        let result_var = self.emit_instruction(Instruction::PublicInput {
            guard: self.current_io_guard(),
        });
        self.push_declare_pub_input(popeq_op);
        let align_one = self.emit_load_imm(Fr::from(1u64));
        self.push_declare_pub_input(align_one);
        self.push_declare_pub_input(align_one);
        self.push_declare_pub_input(result_var);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: 4,
        });

        // The Boolean result is in the verifier's view; constrain to
        // boolean for safety, matching the Map::contains path.
        self.instructions
            .push(Instruction::ConstrainToBoolean { var: result_var });

        Some(result_var)
    }

    /// Emit ZKIR for `Cell::set(value)` at `field_idx`.
    ///
    /// On-chain encoding (verified empirically against compactc 0.30.0):
    /// the contract state is a `StateValue::Array` of ledger fields, sitting
    /// at the top of the VM stack on circuit entry. Writing one field is an
    /// array element assignment expressed as three VM ops:
    ///
    /// ```text
    /// Push { storage: false, value: Cell(field_idx) }   // key
    /// Push { storage: true,  value: Cell(new_value) }   // value
    /// Ins  { cached: false, n: 1 }                      // arr[key] = value
    /// ```
    ///
    /// The two `Push` ops differ in `storage` so the VM tags them with
    /// `Weak` vs `Strong` strength (`onchain-vm/src/vm.rs:631`); `Ins`
    /// pops `[value, key, container]` and inserts. No `Idx` is needed —
    /// the array `Ins` indexes by the key directly.
    /// Given the first var index for a Cell::set/Map::insert value and the
    /// field's outer type (`Cell<T>` or `Map<K, V>` — we only care about T
    /// here), gather the contiguous range of var indices that hold the
    /// value's multi-Fr representation.
    ///
    /// Relies on the invariant that `WitnessAccess` for a multi-Fr witness
    /// emits its `ceil(N/31)` PrivateInputs contiguously and uninterrupted.
    fn gather_value_vars(&self, field_idx: u8, first: Option<Index>) -> Vec<Index> {
        let Some(first) = first else {
            return Vec::new();
        };
        let inner_ty = self
            .field_types
            .get(field_idx as usize)
            .and_then(extract_cell_inner_type);
        let n_fr = inner_ty
            .as_ref()
            .and_then(|t| aligned_value_encoding(t, &self.user_structs, &self.user_enums))
            .map(|e| e.value_field_count)
            .unwrap_or(1);
        (first..first + n_fr as Index).collect()
    }

    fn emit_ledger_write(&mut self, field_idx: u8, value_vars: &[Index]) -> Option<Index> {
        // The KEY: Push(storage: false, Cell(Bytes<1>(field_idx))).
        let key_var = self.emit_load_imm(Fr::from(field_idx as u64));
        let key_encoding = aligned_value_encoding_bytes(1);
        self.emit_push_cell(&[key_var], Some(&key_encoding), /* storage = */ false);

        // The VALUE: Push(storage: true, Cell(<value-typed AlignedValue>)).
        if !value_vars.is_empty() {
            let field_ty = self.field_types.get(field_idx as usize);
            // Counter shares Cell<u64>'s wire shape (deploys as
            // `StateValue::Cell(AlignedValue<u64>)`). Use `u64` as the
            // implicit inner type so `Counter::set(_)` emits the same
            // 8-byte alignment the runtime side produces.
            let inner_ty = field_ty.and_then(extract_cell_inner_type).or_else(|| {
                field_ty.and_then(|t| {
                    if is_counter_type(t) {
                        Some(syn::parse_quote!(u64))
                    } else {
                        None
                    }
                })
            });
            let value_encoding = inner_ty
                .as_ref()
                .and_then(|t| aligned_value_encoding(t, &self.user_structs, &self.user_enums));
            self.emit_push_cell(
                value_vars,
                value_encoding.as_ref(),
                /* storage = */ true,
            );
        }

        // The Ins: Ins { cached: false, n: 1 } → opcode 0x91.
        let ins_op = self.emit_load_imm(Fr::from(0x91u64));
        self.push_declare_pub_input(ins_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(self.guard),
            count: 1,
        });

        value_vars.first().copied()
    }

    /// Emit a `Push { storage, value: StateValue::Cell(AlignedValue) }` group.
    /// Shared by Cell::set, the Map/Set primitives, and MerkleTree
    /// (multi-Fr aware: one `DeclarePubInput` per Fr the value occupies).
    ///
    /// The on-chain transcript op encodes as
    /// `[Push opcode (0x10|0x11), Cell discriminant (1), ..alignment.field_repr,
    /// ..value.field_repr]`. See `StateValue::field_repr` in
    /// `onchain-state/src/state.rs:172` and `AlignedValue::field_repr` in
    /// `transient-crypto/src/fab.rs:381`. If the value's type isn't recognized
    /// (`encoding` is `None`), falls back to the legacy 2-declare emission —
    /// this preserves behavior for types the encoding table doesn't yet cover.
    fn emit_push_cell(
        &mut self,
        value_vars: &[Index],
        encoding: Option<&AlignedValueEncoding>,
        storage: bool,
    ) {
        let g = self.guard;
        let push_op = self.emit_load_imm(Fr::from(if storage { 0x11u64 } else { 0x10u64 }));
        self.push_declare_pub_input(push_op);

        match encoding {
            Some(enc) if value_vars.len() == enc.value_field_count => {
                // Cell discriminant (1) + alignment.field_repr + N-Fr value.
                let cell_disc = self.emit_load_imm(Fr::from(1u64));
                self.push_declare_pub_input(cell_disc);
                for atom in &enc.alignment_atoms {
                    let v = self.emit_load_imm(Fr::from(*atom));
                    self.push_declare_pub_input(v);
                }
                for &var in value_vars {
                    self.push_declare_pub_input(var);
                }
                // Push opcode (1) + Cell disc (1) + alignment.len + value_vars.len
                let count = 2 + enc.alignment_atoms.len() + value_vars.len();
                self.instructions.push(Instruction::PiSkip {
                    guard: Some(g),
                    count: count as u32,
                });
            }
            _ => {
                // Fallback: legacy 2-declare emission. Used when the value
                // type isn't in the encoding table or the caller didn't
                // supply enough Frs. Not on-chain compatible.
                if let Some(&v) = value_vars.first() {
                    self.push_declare_pub_input(v);
                }
                self.instructions.push(Instruction::PiSkip {
                    guard: Some(g),
                    count: 2,
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn emit_load_imm(&mut self, value: Fr) -> Index {
        self.emit_instruction(Instruction::LoadImm { imm: value })
    }

    /// If `path` names a known unit-variant enum like `Status::Open`,
    /// return the variant's discriminant (its index in declaration
    /// order). Matches on the last two segments so paths qualified with
    /// `self::`, `crate::`, etc. still resolve.
    fn resolve_enum_variant_discriminant(&self, path: &syn::Path) -> Option<u8> {
        let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        // `Some` / `None` are single-segment stdlib variants.
        if segs.len() == 1 {
            return match segs[0].as_str() {
                "None" => Some(0),
                "Some" => Some(1),
                _ => None,
            };
        }
        if segs.len() < 2 {
            return None;
        }
        let enum_name = &segs[segs.len() - 2];
        let variant_name = &segs[segs.len() - 1];
        let variants = self.user_enums.get(enum_name)?;
        variants
            .iter()
            .position(|v| v.name == *variant_name)
            .map(|i| i as u8)
    }

    fn emit_instruction(&mut self, instruction: Instruction) -> Index {
        let idx = self.next_index;
        let outputs = instruction_output_count(&instruction);
        self.next_index += outputs;
        self.instructions.push(instruction);
        idx
    }

    /// Emit a type constraint for a public circuit parameter based on
    /// its syn::Type. Each parameter is ONE wire, so multi-Fr types
    /// (large `Bytes<N>`, tuples, user structs) cannot be public
    /// parameters yet — record an error instead of constraining one
    /// wire to a width the value doesn't fit.
    fn emit_type_constraint(&mut self, var: Index, ty: &syn::Type) {
        let type_str = quote::quote!(#ty).to_string().replace(' ', "");

        if matches!(ty, syn::Type::Tuple(_)) {
            let _ = self.unsupported(format!(
                "tuple-typed public circuit parameters are not supported yet \
                 (`{type_str}`)"
            ));
            return;
        }
        if let syn::Type::Path(tp) = ty
            && tp.qself.is_none()
            && let Some(seg) = tp.path.segments.last()
            && self.user_structs.contains_key(&seg.ident.to_string())
        {
            let _ = self.unsupported(format!(
                "struct-typed public circuit parameters are not supported yet \
                 (`{type_str}`)"
            ));
            return;
        }

        if type_str == "Boolean" || type_str == "bool" {
            self.instructions
                .push(Instruction::ConstrainToBoolean { var });
        } else if type_str.starts_with("Uint<") || parse_uint_type(&type_str).is_some() {
            let Some(bits) = parse_uint_type(&type_str) else {
                let _ = self.unsupported(format!(
                    "cannot parse the bit width of public parameter type `{type_str}`"
                ));
                return;
            };
            if bits == 0 || bits > 253 {
                let _ = self.unsupported(format!(
                    "public parameter type `{type_str}` does not fit one field \
                     element (max 253 bits)"
                ));
                return;
            }
            self.instructions
                .push(Instruction::ConstrainBits { var, bits });
        } else if type_str.starts_with("Bytes<") {
            // Bytes<N> → constrain to N*8 bits; one wire holds at most
            // 31 bytes.
            let Some(n) = parse_bytes_n_type(&type_str) else {
                let _ = self.unsupported(format!(
                    "cannot parse the byte length of public parameter type `{type_str}`"
                ));
                return;
            };
            if n > FR_BYTES_STORED {
                let _ = self.unsupported(format!(
                    "multi-Fr public parameter type `{type_str}` is not supported \
                     yet (Bytes<N> parameters require N ≤ {FR_BYTES_STORED})"
                ));
                return;
            }
            self.instructions
                .push(Instruction::ConstrainBits { var, bits: n * 8 });
        }
        // Field type: no constraint needed (native field element).
    }

    fn field_index(&self, field_name: &str) -> u8 {
        self.field_names
            .iter()
            .position(|f| f == field_name)
            .unwrap_or_else(|| {
                // Internal invariant: rustc rejects typos on the real
                // struct in the stripped module, so an unknown name here
                // is an emitter/parser bug. Falling back to field 0
                // would turn that bug into a verified-but-wrong write.
                panic!(
                    "nocturne internal error: ledger field `{field_name}` not found \
                     among {:?}",
                    self.field_names
                )
            }) as u8
    }
}

/// Encoding for `AlignedValue<Bytes<N>>`: alignment `[1, N]`, value width 1 Fr
/// (callers must ensure `N * 8 ≤ 253` for the value to fit in one Fr).
fn aligned_value_encoding_bytes(n: u32) -> AlignedValueEncoding {
    AlignedValueEncoding {
        alignment_atoms: vec![1, n as i32],
        value_field_count: 1,
    }
}

/// Compute the `AlignedValueEncoding` for a supported Rust type.
///
/// Returns `None` for types not yet handled (multi-Fr value layouts like
/// large `Bytes<N>`, custom ADTs). Callers fall back to the legacy
/// 2-declare emission path.
///
/// Derives entirely from the shared `NocturneType` resolver: walk the
/// `syn::Type` once, then compute the encoding from the resolved variant
/// (`crate::nocturne_type::resolve` + `aligned_encoding`). The precedence
/// (Option, enum, tuple, array, struct, primitives) and the `None` guards
/// (Uint > 253, witness-only types) live in that one place so this and
/// `witness_fr_layout` cannot drift on a composite type's Fr count.
fn aligned_value_encoding(
    ty: &syn::Type,
    user_structs: &HashMap<String, Vec<nocturne_ir::UserStructField>>,
    user_enums: &HashMap<String, Vec<nocturne_ir::UserEnumVariant>>,
) -> Option<AlignedValueEncoding> {
    resolve(ty, &TypeCtx::new(user_structs, user_enums)).and_then(|t| t.aligned_encoding())
}

/// Per-Fr layout for a witness type, in the order PrivateInputs are
/// emitted (matching `AlignedValueExt::value_only_field_repr` on the
/// runtime side).
///
/// `Bytes<N>` uses `FieldRepr` chunk-and-reverse semantics: `chunks(31)`
/// then `.rev()`. The first emitted Fr is the high-bytes chunk (the
/// tail of the original byte string), whose size is `N % 31` if that's
/// non-zero, otherwise `31`. Each subsequent Fr is a full 31-byte chunk.
///
/// `MerkleTreePath<H, T>` expands as `T`'s leaf layout followed by H
/// repetitions of `[Field, Boolean]` (one sibling + one goes_left per
/// path entry).
/// Number of Frs (PrivateInputs) one witness invocation of type `ty`
/// expands to. Test-only mirror used by the private-event parity tests
/// to convert the canonical event walk into an expected PrivateInput
/// count.
#[cfg(test)]
pub(crate) fn witness_fr_width(
    ty: &syn::Type,
    user_structs: &HashMap<String, Vec<nocturne_ir::UserStructField>>,
    user_enums: &HashMap<String, Vec<nocturne_ir::UserEnumVariant>>,
) -> usize {
    witness_fr_layout(ty, user_structs, user_enums).len()
}

fn witness_fr_layout(
    ty: &syn::Type,
    user_structs: &HashMap<String, Vec<nocturne_ir::UserStructField>>,
    user_enums: &HashMap<String, Vec<nocturne_ir::UserEnumVariant>>,
) -> Vec<FrLayout> {
    // Aligned-value types (tuples, arrays, structs, Option, enums, and
    // the primitives) share their per-Fr layout with the on-chain
    // encoding, so derive it from the same `NocturneType` resolver that
    // drives `aligned_value_encoding`. `fr_layout().len()` equals the
    // resolved type's `value_field_count` by construction (the H4
    // invariant), so the two can no longer drift.
    if let Some(t) = resolve(ty, &TypeCtx::new(user_structs, user_enums)) {
        return t.fr_layout();
    }

    // Witness-only types `resolve` deliberately does NOT cover (they
    // never become an on-chain `AlignedValue`): the Merkle path shapes
    // and the unknown-type fallback.
    let ty_str = quote::quote!(#ty).to_string().replace(' ', "");

    if let Some((h, t)) = parse_merkle_tree_path_type(&ty_str) {
        let mut layout = witness_fr_layout_for_leaf_type(&t);
        // Each path entry: 1 sibling Field + 1 goes_left Boolean.
        for _ in 0..h {
            layout.push(FrLayout::Field);
            layout.push(FrLayout::Boolean);
        }
        return layout;
    }

    if ty_str == "MerkleTreePathEntry" {
        return vec![FrLayout::Field, FrLayout::Boolean];
    }

    // Unknown type → single Fr with no constraint. Callers can still
    // emit something, but the prover side likely won't agree.
    vec![FrLayout::Field]
}

/// Layout for a `Bytes<N>` value used as a Merkle tree leaf.
fn witness_fr_layout_for_leaf_type(t_str: &str) -> Vec<FrLayout> {
    if let Some(n) = parse_bytes_n_type(t_str) {
        bytes_n_layout(n)
    } else {
        vec![FrLayout::Field]
    }
}

fn parse_bytes_n_type(ty_str: &str) -> Option<u32> {
    ty_str
        .strip_prefix("Bytes<")
        .and_then(|s| s.strip_suffix('>'))
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|n| *n > 0)
}

/// True when a `FnCall` path is a transparent wrapper constructor:
/// `Uint::<N>::from(x)`, `Field::from(x)`, `Boolean::from(x)`,
/// `Bytes::<N>::from(x)`, or a primitive `uN::from(x)`. These construct
/// an eDSL value type around the argument without changing the value
/// the circuit carries, so (with exactly one argument) the call lowers
/// to the argument's wire — the `FnCall` twin of the `.into()` /
/// `.value()` transparency rule in `crate::typing`.
fn is_wrapper_from_call(path: &syn::Path) -> bool {
    let segs = &path.segments;
    if segs.len() < 2 || segs[segs.len() - 1].ident != "from" {
        return false;
    }
    let qualifier = segs[segs.len() - 2].ident.to_string();
    matches!(
        qualifier.as_str(),
        "Uint" | "Field" | "Boolean" | "Bytes" | "u8" | "u16" | "u32" | "u64" | "u128"
    )
}

/// Parse `MerkleTreePath<H, T>` → `(H, T_str)`. Returns `None` if `ty_str`
/// doesn't have that shape.
fn parse_merkle_tree_path_type(ty_str: &str) -> Option<(u32, String)> {
    let inner = ty_str
        .strip_prefix("MerkleTreePath<")
        .and_then(|s| s.strip_suffix('>'))?;
    // Inner is "H,T" where T may itself contain commas (e.g. for nested
    // generics). For our cases T is `Bytes<N>` which has angle brackets
    // but no top-level commas, so a simple find-first works.
    let comma_pos = inner.find(',')?;
    let h: u32 = inner[..comma_pos].trim().parse().ok()?;
    let t = inner[comma_pos + 1..].trim().to_string();
    Some((h, t))
}

/// Build a contiguous `[first, first + n)` slice of var indices. Used by
/// dispatch sites that know they want N Frs starting at the first var the
/// expression emitted. Relies on the multi-Fr WitnessAccess invariant that
/// PrivateInputs are emitted contiguously and uninterrupted.
fn gather_n_vars(first: Index, n: usize) -> Vec<Index> {
    (first..first + n as Index).collect()
}

/// Like `witness_fr_layout` but for Popeq read-result types. Returns
/// per-Fr `ConstrainBits` widths in the order
/// `AlignedValueExt::value_only_field_repr` emits them (high-bytes chunk
/// first after `.rev()`).
///
/// Derives directly from `witness_fr_layout`'s recursion (the single
/// source of truth for per-type Fr counts) so tuples, user structs,
/// `Option`, payload enums, and arrays all yield the SAME Fr count the
/// runtime-side `AlignedValue` produces. A divergent count here is
/// exactly the H4 bug class: the PI loop emits fewer `PublicInput`s
/// than `PiSkip` claims and the verifier's comparison window shifts.
fn read_result_fr_layout(
    ty: &syn::Type,
    user_structs: &HashMap<String, Vec<nocturne_ir::UserStructField>>,
    user_enums: &HashMap<String, Vec<nocturne_ir::UserEnumVariant>>,
) -> Vec<Option<u32>> {
    witness_fr_layout(ty, user_structs, user_enums)
        .into_iter()
        .map(|entry| match entry {
            FrLayout::Bits(b) => Some(b),
            // ConstrainBits(1) is the bits-shaped equivalent of a
            // boolean constraint for a transcript-read value.
            FrLayout::Boolean => Some(1),
            FrLayout::Field => None,
        })
        .collect()
}

/// Return the value type read by `self.<field>.get()` / `.value()` for a
/// given ledger field type. Maps `Counter` → `u64` and `Cell<T>` → `T`.
/// Returns `None` for types where direct reads don't apply (`Map<_,_>`)
/// or that we don't yet handle.
fn extract_ledger_read_result_type(ty: &syn::Type) -> Option<syn::Type> {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
    {
        if seg.ident == "Counter" {
            return Some(syn::parse_quote!(u64));
        }
        if seg.ident == "Cell"
            && let syn::PathArguments::AngleBracketed(args) = &seg.arguments
            && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
        {
            return Some(inner.clone());
        }
    }
    None
}

/// True if `ty` is the `Counter` storage type.
fn is_counter_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
    {
        return seg.ident == "Counter";
    }
    false
}

/// Drill through `ExprIR::Reference` wrappers to find the `WitnessAccess`
/// field name. Used by `emit_merkle_tree_path_root` to look up the
/// witness's declared type and parse the path height.
fn find_witness_field(expr: &nocturne_ir::ExprIR) -> Option<String> {
    use nocturne_ir::ExprIR;
    match expr {
        ExprIR::WitnessAccess { field, .. } => Some(field.to_string()),
        ExprIR::Reference { expr: inner, .. } => find_witness_field(inner),
        _ => None,
    }
}

/// The Fr immediate compactc emits for the `"mdn:lh"` leaf-hash domain
/// separator. The bytes `m, d, n, :, l, h` little-endian-encode to the
/// integer `0x686C3A6E646D` — that's the value stored in the LoadImm we
/// see in the compactc IR (the hex literal `0x6D646E3A6C68` printed in
/// big-endian byte order).
///
/// Going through `value_atom_as_field` would also work but pulling a
/// u64 constant is simpler — the 6 bytes fit in a u64.
fn domain_sep_fr_mdn_lh() -> Fr {
    let bytes = b"mdn:lh"; // 6 bytes
    let mut acc: u64 = 0;
    for &b in bytes.iter().rev() {
        acc = (acc << 8) | (b as u64);
    }
    Fr::from(acc)
}

fn instruction_output_count(instruction: &Instruction) -> u32 {
    match instruction {
        Instruction::Assert { .. }
        | Instruction::ConstrainBits { .. }
        | Instruction::ConstrainEq { .. }
        | Instruction::ConstrainToBoolean { .. }
        | Instruction::DeclarePubInput { .. }
        | Instruction::PiSkip { .. }
        | Instruction::Output { .. } => 0,

        Instruction::EcAdd { .. }
        | Instruction::EcMul { .. }
        | Instruction::EcMulGenerator { .. }
        | Instruction::HashToCurve { .. }
        | Instruction::DivModPowerOfTwo { .. }
        // PersistentHash pushes `hash.field_vec()` to memory
        // (`zkir/src/ir_vm.rs:419`). The hash output is 32 bytes →
        // `field_vec()` yields 2 Frs, so the op produces 2 outputs.
        | Instruction::PersistentHash { .. } => 2,

        _ => 1,
    }
}

/// Validate that `return` only appears in tail position: the final
/// statement of the circuit body, or the tail of the final statement's
/// `if`/block branches (where the branch results multiplex into one
/// output wire). A non-tail `return` would NOT short-circuit the rest
/// of the body — both "paths" execute in a circuit — so the emitted
/// semantics would silently diverge from Rust's.
fn check_return_positions(expr: &ExprIR, tail: bool, errors: &mut Vec<String>) {
    const MSG: &str = "`return` is only supported as the final statement of a circuit \
                       body (or the tail of the final statement's branches)";
    match expr {
        ExprIR::Return { value, .. } => {
            if !tail {
                errors.push(MSG.to_string());
            }
            if let Some(v) = value
                && contains_return(v)
            {
                errors.push(MSG.to_string());
            }
        }
        ExprIR::Block { stmts, .. } => {
            let n = stmts.len();
            for (i, s) in stmts.iter().enumerate() {
                check_return_positions(s, tail && i + 1 == n, errors);
            }
        }
        ExprIR::If {
            cond,
            then_branch,
            else_branch,
            ..
        } => {
            if contains_return(cond) {
                errors.push(MSG.to_string());
            }
            let n = then_branch.len();
            for (i, s) in then_branch.iter().enumerate() {
                check_return_positions(s, tail && i + 1 == n, errors);
            }
            if let Some(eb) = else_branch {
                let n = eb.len();
                for (i, s) in eb.iter().enumerate() {
                    check_return_positions(s, tail && i + 1 == n, errors);
                }
            }
        }
        other => {
            if contains_return(other) {
                errors.push(MSG.to_string());
            }
        }
    }
}

/// True if any node in the expression tree is `ExprIR::Return`.
fn contains_return(expr: &ExprIR) -> bool {
    match expr {
        ExprIR::Return { .. } => true,
        ExprIR::Let { value, .. } => contains_return(value),
        ExprIR::BinaryOp { lhs, rhs, .. } => contains_return(lhs) || contains_return(rhs),
        ExprIR::UnaryOp { expr: inner, .. }
        | ExprIR::Reference { expr: inner, .. }
        | ExprIR::Disclose { value: inner, .. } => contains_return(inner),
        ExprIR::Assert { kind, .. } => match kind {
            AssertKind::Assert(c) => contains_return(c),
            AssertKind::AssertEq(a, b) => contains_return(a) || contains_return(b),
        },
        ExprIR::If {
            cond,
            then_branch,
            else_branch,
            ..
        } => {
            contains_return(cond)
                || then_branch.iter().any(contains_return)
                || else_branch
                    .as_ref()
                    .is_some_and(|b| b.iter().any(contains_return))
        }
        ExprIR::Block { stmts, .. } => stmts.iter().any(contains_return),
        ExprIR::FnCall { args, .. } | ExprIR::WitnessCall { args, .. } => {
            args.iter().any(contains_return)
        }
        ExprIR::MethodCall { receiver, args, .. } => {
            contains_return(receiver) || args.iter().any(contains_return)
        }
        ExprIR::LedgerAccess { args, .. } => args.iter().any(contains_return),
        ExprIR::Tuple { elements, .. } | ExprIR::ArrayLit { elements, .. } => {
            elements.iter().any(contains_return)
        }
        ExprIR::StructInit { fields, .. } => fields.iter().any(|(_, e)| contains_return(e)),
        ExprIR::Index { array, .. } => contains_return(array),
        ExprIR::EnumPayload { scrutinee, .. } => contains_return(scrutinee),
        ExprIR::Literal { .. }
        | ExprIR::Var { .. }
        | ExprIR::Path { .. }
        | ExprIR::WitnessAccess { .. }
        | ExprIR::Unsupported { .. } => false,
    }
}

/// Recursive alpha-renamer over `ExprIR` used by the helper inliner.
/// Walks the tree replacing `Var { name }` references via `subst` and
/// generating fresh names for each `Let { name, ... }` binding. The
/// fresh-name convention `__h{counter}_{seq}_{name}` ensures every
/// inlined binding is unique across nested + repeated helper calls.
///
/// Scoping: `subst` snapshots are saved/restored around If branches
/// and Block statement lists so let bindings local to one branch /
/// inner block don't leak into the sibling branch / outer body. The
/// top-level helper body's lets DO persist through the body — the
/// caller iterates the body Vec without save/restore.
fn alpha_rename(
    expr: ExprIR,
    subst: &mut std::collections::HashMap<String, String>,
    counter: u32,
    seq: &mut u32,
) -> ExprIR {
    use proc_macro2::Ident;
    match expr {
        ExprIR::Var { span, name } => {
            let new_name = subst
                .get(&name.to_string())
                .map(|s| Ident::new(s, name.span()))
                .unwrap_or(name);
            ExprIR::Var {
                span,
                name: new_name,
            }
        }
        ExprIR::Let { span, name, value } => {
            // Rename RHS in the OLD subst (let RHS can't see its own
            // binding), then add the fresh mapping for the body of
            // any following statements.
            let new_value = Box::new(alpha_rename(*value, subst, counter, seq));
            let fresh = format!("__h{counter}_{seq}_{}", name);
            *seq += 1;
            subst.insert(name.to_string(), fresh.clone());
            let new_name = Ident::new(&fresh, name.span());
            ExprIR::Let {
                span,
                name: new_name,
                value: new_value,
            }
        }
        ExprIR::BinaryOp { span, op, lhs, rhs } => ExprIR::BinaryOp {
            span,
            op,
            lhs: Box::new(alpha_rename(*lhs, subst, counter, seq)),
            rhs: Box::new(alpha_rename(*rhs, subst, counter, seq)),
        },
        ExprIR::UnaryOp { span, op, expr } => ExprIR::UnaryOp {
            span,
            op,
            expr: Box::new(alpha_rename(*expr, subst, counter, seq)),
        },
        ExprIR::FnCall {
            span,
            name,
            path,
            args,
        } => ExprIR::FnCall {
            span,
            name,
            path,
            args: args
                .into_iter()
                .map(|a| alpha_rename(a, subst, counter, seq))
                .collect(),
        },
        ExprIR::MethodCall {
            span,
            receiver,
            method,
            args,
        } => ExprIR::MethodCall {
            span,
            receiver: Box::new(alpha_rename(*receiver, subst, counter, seq)),
            method,
            args: args
                .into_iter()
                .map(|a| alpha_rename(a, subst, counter, seq))
                .collect(),
        },
        ExprIR::If {
            span,
            cond,
            then_branch,
            else_branch,
        } => {
            // Cond is evaluated in the surrounding scope; rename in
            // the live subst. Branches scope their own lets — snapshot
            // subst before each, restore after.
            let cond = Box::new(alpha_rename(*cond, subst, counter, seq));
            let snapshot = subst.clone();
            let then_branch: Vec<ExprIR> = then_branch
                .into_iter()
                .map(|s| alpha_rename(s, subst, counter, seq))
                .collect();
            *subst = snapshot.clone();
            let else_branch = else_branch.map(|b| {
                let renamed: Vec<ExprIR> = b
                    .into_iter()
                    .map(|s| alpha_rename(s, subst, counter, seq))
                    .collect();
                *subst = snapshot;
                renamed
            });
            ExprIR::If {
                span,
                cond,
                then_branch,
                else_branch,
            }
        }
        ExprIR::Assert { span, kind } => {
            use nocturne_ir::expr::AssertKind;
            let new_kind = match kind {
                AssertKind::Assert(e) => {
                    AssertKind::Assert(Box::new(alpha_rename(*e, subst, counter, seq)))
                }
                AssertKind::AssertEq(a, b) => AssertKind::AssertEq(
                    Box::new(alpha_rename(*a, subst, counter, seq)),
                    Box::new(alpha_rename(*b, subst, counter, seq)),
                ),
            };
            ExprIR::Assert {
                span,
                kind: new_kind,
            }
        }
        ExprIR::Disclose { span, value } => ExprIR::Disclose {
            span,
            value: Box::new(alpha_rename(*value, subst, counter, seq)),
        },
        ExprIR::EnumPayload {
            span,
            scrutinee,
            enum_name,
        } => ExprIR::EnumPayload {
            span,
            scrutinee: Box::new(alpha_rename(*scrutinee, subst, counter, seq)),
            enum_name,
        },
        ExprIR::ArrayLit { span, elements } => ExprIR::ArrayLit {
            span,
            elements: elements
                .into_iter()
                .map(|e| alpha_rename(e, subst, counter, seq))
                .collect(),
        },
        ExprIR::Index { span, array, index } => ExprIR::Index {
            span,
            array: Box::new(alpha_rename(*array, subst, counter, seq)),
            index,
        },
        ExprIR::Block { span, stmts } => {
            let snapshot = subst.clone();
            let stmts: Vec<ExprIR> = stmts
                .into_iter()
                .map(|s| alpha_rename(s, subst, counter, seq))
                .collect();
            *subst = snapshot;
            ExprIR::Block { span, stmts }
        }
        ExprIR::StructInit { span, name, fields } => ExprIR::StructInit {
            span,
            name,
            fields: fields
                .into_iter()
                .map(|(f, e)| (f, alpha_rename(e, subst, counter, seq)))
                .collect(),
        },
        ExprIR::Return { span, value } => ExprIR::Return {
            span,
            value: value.map(|v| Box::new(alpha_rename(*v, subst, counter, seq))),
        },
        ExprIR::Tuple { span, elements } => ExprIR::Tuple {
            span,
            elements: elements
                .into_iter()
                .map(|e| alpha_rename(e, subst, counter, seq))
                .collect(),
        },
        ExprIR::Reference { span, expr } => ExprIR::Reference {
            span,
            expr: Box::new(alpha_rename(*expr, subst, counter, seq)),
        },
        ExprIR::LedgerAccess {
            span,
            field,
            method,
            args,
        } => ExprIR::LedgerAccess {
            span,
            field,
            method,
            args: args
                .into_iter()
                .map(|a| alpha_rename(a, subst, counter, seq))
                .collect(),
        },
        ExprIR::WitnessCall { span, name, args } => ExprIR::WitnessCall {
            span,
            name,
            args: args
                .into_iter()
                .map(|a| alpha_rename(a, subst, counter, seq))
                .collect(),
        },
        // Leaves — nothing to rename.
        ExprIR::Literal { .. }
        | ExprIR::Path { .. }
        | ExprIR::WitnessAccess { .. }
        | ExprIR::Unsupported { .. } => expr,
    }
}
