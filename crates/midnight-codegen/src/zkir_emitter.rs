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

use midnight_ir::expr::{AssertKind, LiteralIR};
use midnight_ir::{CircuitIR, ContractIR, ExprIR};
use midnight_transient_crypto::curve::Fr;
use midnight_zkir::{Instruction, IrSource};
use std::collections::HashMap;
use std::sync::Arc;

type Index = u32;

/// Result of ZKIR emission for a single circuit.
pub struct ZkirOutput {
    pub circuit_name: String,
    pub ir_source: IrSource,
}

/// Result of full contract emission.
pub struct ContractZkirOutput {
    pub circuits: Vec<ZkirOutput>,
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

    let circuits = contract
        .circuits
        .iter()
        .map(|circuit| {
            let mut emitter = ZkirEmitter::new(&field_names, &field_types, &witness_types);
            emitter.emit_circuit(circuit)
        })
        .collect();

    ContractZkirOutput { circuits }
}

struct ZkirEmitter {
    instructions: Vec<Instruction>,
    next_index: Index,
    variables: HashMap<String, Index>,
    num_inputs: u32,
    guard: Index,
    /// True when emitting inside a conditional branch. `DeclarePubInput`
    /// values must be multiplexed against zero via `CondSelect(guard, value, 0)`
    /// so the inactive-branch slot is zero — matching `Op::Noop`'s zero
    /// `field_repr` that the ledger interleaves at verify time. See
    /// `memories/conditional-branch-cond-select-zeroing.md`.
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
}

impl ZkirEmitter {
    fn new(
        field_names: &[String],
        field_types: &[syn::Type],
        witness_types: &HashMap<String, syn::Type>,
    ) -> Self {
        Self {
            instructions: Vec::new(),
            next_index: 0,
            variables: HashMap::new(),
            num_inputs: 0,
            guard: 0,
            in_conditional: false,
            zero_var: None,
            field_names: field_names.to_vec(),
            field_types: field_types.to_vec(),
            witness_types: witness_types.clone(),
        }
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

        // Process circuit body.
        for expr in &circuit.body {
            self.emit_expr(expr);
        }

        // If the circuit has a return type, emit Output for the last computed value.
        // This enables communications commitment.
        if circuit.return_type.is_some() {
            // The last value in memory is the return value.
            if self.next_index > 0 {
                let last_idx = self.next_index - 1;
                self.instructions
                    .push(Instruction::Output { var: last_idx });
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
        }
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

                if field_ty.as_ref().and_then(extract_merkle_tree_type).is_some() {
                    return self.emit_merkle_tree_method(field_idx, &method_name, args);
                }

                match method_name.as_str() {
                    "increment" => self.emit_counter_increment(field_idx),
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
                    _ => {
                        for arg in args {
                            self.emit_expr(arg);
                        }
                        None
                    }
                }
            }

            ExprIR::WitnessAccess { field, .. } => {
                let key = format!("witness.{field}");
                if let Some(&idx) = self.variables.get(&key) {
                    return Some(idx);
                }
                let ty = self.witness_types.get(&field.to_string()).cloned();

                // Multi-Fr witnesses (currently just `Bytes<N>` for N>0)
                // expand to one PrivateInput per Fr the value's
                // `value_only_field_repr` emits, with a per-chunk ConstrainBits
                // that matches the corresponding byte width. The chunk order
                // mirrors `field_repr_unchecked` for `Bytes{N}` (which
                // reverses 31-byte chunks), so the IR's PrivateInputs and the
                // transcript's `value_only_field_repr` output land in the
                // same order.
                let layout = ty
                    .as_ref()
                    .map(witness_fr_layout)
                    .unwrap_or_else(|| vec![None]);
                let mut first_idx = None;
                for bits in layout {
                    let var = self.emit_instruction(Instruction::PrivateInput {
                        guard: self.current_io_guard(),
                    });
                    if first_idx.is_none() {
                        first_idx = Some(var);
                    }
                    if let Some(b) = bits {
                        self.instructions
                            .push(Instruction::ConstrainBits { var, bits: b });
                    } else if let Some(t) = &ty {
                        // Fall back to type-dispatched constraint for single-Fr
                        // types (Boolean → ConstrainToBoolean, etc.).
                        self.emit_type_constraint(var, t);
                    }
                }
                let first = first_idx.expect("at least one PrivateInput per witness");
                self.variables.insert(key, first);
                Some(first)
            }

            ExprIR::Literal { value, .. } => {
                let fr = match value {
                    LiteralIR::Int(n) => Fr::from(*n as u64),
                    LiteralIR::Bool(b) => Fr::from(*b),
                    LiteralIR::Str(_) => Fr::from(0u64),
                };
                Some(self.emit_load_imm(fr))
            }

            ExprIR::Var { name, .. } => self.variables.get(&name.to_string()).copied(),

            ExprIR::BinaryOp { op, lhs, rhs, .. } => {
                let a = self.emit_expr(lhs)?;
                let b = self.emit_expr(rhs)?;
                use syn::BinOp;
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
                        Some(self.emit_instruction(Instruction::LessThan { a, b, bits: 64 }))
                    }
                    BinOp::Gt(_) => Some(self.emit_instruction(Instruction::LessThan {
                        a: b,
                        b: a,
                        bits: 64,
                    })),
                    BinOp::Le(_) => {
                        let gt = self.emit_instruction(Instruction::LessThan {
                            a: b,
                            b: a,
                            bits: 64,
                        });
                        Some(self.emit_instruction(Instruction::Not { a: gt }))
                    }
                    BinOp::Ge(_) => {
                        let lt = self.emit_instruction(Instruction::LessThan { a, b, bits: 64 });
                        Some(self.emit_instruction(Instruction::Not { a: lt }))
                    }
                    BinOp::And(_) => Some(self.emit_instruction(Instruction::Mul { a, b })),
                    BinOp::Or(_) => {
                        let ab = self.emit_instruction(Instruction::Mul { a, b });
                        let sum = self.emit_instruction(Instruction::Add { a, b });
                        let neg_ab = self.emit_instruction(Instruction::Neg { a: ab });
                        Some(self.emit_instruction(Instruction::Add { a: sum, b: neg_ab }))
                    }
                    _ => None,
                }
            }

            ExprIR::UnaryOp {
                op, expr: inner, ..
            } => {
                let a = self.emit_expr(inner)?;
                match op {
                    syn::UnOp::Neg(_) => Some(self.emit_instruction(Instruction::Neg { a })),
                    syn::UnOp::Not(_) => Some(self.emit_instruction(Instruction::Not { a })),
                    _ => None,
                }
            }

            ExprIR::Let { name, value, .. } => {
                let idx = self.emit_expr(value)?;
                self.variables.insert(name.to_string(), idx);
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

                for expr in then_branch {
                    self.emit_expr(expr);
                }

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

                    for expr in else_stmts {
                        self.emit_expr(expr);
                    }
                }

                self.guard = outer_guard;
                self.in_conditional = outer_in_conditional;
                Some(cond_idx)
            }

            ExprIR::FnCall { name, args, .. } => {
                let name_str = name.to_string();
                let arg_indices: Vec<Index> =
                    args.iter().filter_map(|a| self.emit_expr(a)).collect();

                match name_str.as_str() {
                    "persistent_hash" => {
                        use midnight_base_crypto::fab::{
                            Alignment, AlignmentAtom, AlignmentSegment,
                        };
                        let alignment =
                            Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Field)]);
                        Some(self.emit_instruction(Instruction::PersistentHash {
                            alignment,
                            inputs: arg_indices,
                        }))
                    }
                    "transient_hash" => Some(self.emit_instruction(Instruction::TransientHash {
                        inputs: arg_indices,
                    })),
                    _ => arg_indices.last().copied(),
                }
            }

            ExprIR::Disclose { value, .. } => {
                let idx = self.emit_expr(value)?;
                self.push_declare_pub_input(idx);
                self.instructions.push(Instruction::PiSkip {
                    guard: Some(self.guard),
                    count: 1,
                });
                Some(idx)
            }

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

            ExprIR::Return { value, .. } => {
                if let Some(val) = value {
                    let idx = self.emit_expr(val)?;
                    self.instructions.push(Instruction::Output { var: idx });
                    Some(idx)
                } else {
                    None
                }
            }

            ExprIR::Tuple { elements, .. } => {
                let mut last = None;
                for elem in elements {
                    last = self.emit_expr(elem);
                }
                last
            }

            ExprIR::Reference { expr: inner, .. } => self.emit_expr(inner),
            ExprIR::StructInit { .. } | ExprIR::Unsupported { .. } => None,
        }
    }

    // -----------------------------------------------------------------------
    // Transcript VM op encoding as ZKIR public inputs
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Emit a key's AlignedValue field representation as declare_pub_input
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

    // -----------------------------------------------------------------------
    // Transcript VM op encoding as ZKIR public inputs
    // -----------------------------------------------------------------------

    /// Emit ZKIR for Counter.increment(1): Idx(push_path) + Addi(1) + Ins.
    ///
    /// Matches Compact's `Counter.increment`:
    ///   idx [pushPath: true] [path: f]
    ///   addi [immediate: amount]
    ///   ins [cached: true] [n: len(f)]
    fn emit_counter_increment(&mut self, field_idx: u8) -> Option<Index> {
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

        // Addi { immediate: 1 } → field repr: [0x0e, 1]
        let addi_op = self.emit_load_imm(Fr::from(0x0eu64));
        let one = self.emit_load_imm(Fr::from(1u64));
        self.push_declare_pub_input(addi_op);
        self.push_declare_pub_input(one);
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

        Some(one)
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
        let result_enc = result_ty.and_then(aligned_value_encoding);
        let popeq_op = self.emit_load_imm(Fr::from(0x0du64));
        self.push_declare_pub_input(popeq_op);

        match result_enc {
            Some(enc) if enc.value_field_count >= 1 => {
                for atom in &enc.alignment_atoms {
                    let v = self.emit_load_imm(Fr::from(*atom));
                    self.push_declare_pub_input(v);
                }
                let mut first_value: Option<Index> = None;
                let value_layout = result_ty
                    .map(read_result_fr_layout)
                    .unwrap_or_else(|| vec![None; enc.value_field_count]);
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
        args: &[midnight_ir::ExprIR],
        k_ty: &syn::Type,
        v_ty: &syn::Type,
    ) -> Option<Index> {
        let key_enc = aligned_value_encoding(k_ty)?;

        match method_name {
            "contains" => {
                let first = args.first().and_then(|a| self.emit_expr(a))?;
                let key_vars = gather_n_vars(first, key_enc.value_field_count);
                self.emit_map_member(field_idx, &key_vars, &key_enc)
            }
            "insert" | "set" => {
                let val_enc = aligned_value_encoding(v_ty)?;
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
                let val_enc = aligned_value_encoding(v_ty)?;
                let first = args.first().and_then(|a| self.emit_expr(a))?;
                let key_vars = gather_n_vars(first, key_enc.value_field_count);
                self.emit_map_lookup(field_idx, &key_vars, &key_enc, v_ty, &val_enc)
            }
            // `get` returns Option<V> and would require Option alignment
            // encoding plus higher-level expansion (contains + conditional
            // lookup); leave it to fall through until that work lands.
            _ => {
                for arg in args {
                    self.emit_expr(arg);
                }
                None
            }
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
    /// restores the field. See `memories/map-ledger-field-encoding.md`.
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
    /// `Map<Bytes<32>, Uint<64>>`; see
    /// `/tmp/cond-experiments/map_out/zkir/member.zkir` and
    /// `memories/map-ledger-field-encoding.md`):
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
        let popeq_op = self.emit_load_imm(Fr::from(0x0cu64));
        self.push_declare_pub_input(popeq_op);
        for atom in &val_encoding.alignment_atoms {
            let v = self.emit_load_imm(Fr::from(*atom));
            self.push_declare_pub_input(v);
        }
        let value_layout = read_result_fr_layout(v_ty);
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
        args: &[midnight_ir::ExprIR],
        t_ty: &syn::Type,
    ) -> Option<Index> {
        let key_enc = aligned_value_encoding(t_ty)?;
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
            _ => {
                for arg in args {
                    self.emit_expr(arg);
                }
                None
            }
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

    /// Dispatch a method call on a `MerkleTree<H, T>` ledger field.
    /// Today only `check_root` is implemented (Phase C of the staged
    /// plan in `memories/merkle-tree-encoding.md`); `insert` lands in
    /// Phase D.
    fn emit_merkle_tree_method(
        &mut self,
        field_idx: u8,
        method_name: &str,
        args: &[midnight_ir::ExprIR],
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
                // The argument is `Bytes<32>` (the leaf). emit_expr
                // returns the first PrivateInput var; we gather the
                // contiguous 2 Frs via gather_n_vars and feed them into
                // the leafHash persistent_hash call.
                let leaf_first = args.first().and_then(|a| self.emit_expr(a))?;
                self.emit_merkle_tree_insert(field_idx, leaf_first)
            }
            _ => {
                for arg in args {
                    self.emit_expr(arg);
                }
                None
            }
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
    /// Today this is specialized to `Bytes<32>` leaves — matches the
    /// only Compact use case we've encountered. Generalizing to other
    /// leaf types means parameterizing both the leaf alignment and the
    /// persistent_hash alignment on `T`.
    fn emit_merkle_tree_insert(
        &mut self,
        field_idx: u8,
        leaf_first: Index,
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
        let leaf_chunks = gather_n_vars(leaf_first, 2);
        let hash_align = Alignment(vec![
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 6 }),
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
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
    fn emit_merkle_tree_check_root(
        &mut self,
        field_idx: u8,
        digest_var: Index,
    ) -> Option<Index> {
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
        let enc = aligned_value_encoding(&field_ty).expect("Field encoding must exist");
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
            .and_then(aligned_value_encoding)
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
            let inner_ty = self
                .field_types
                .get(field_idx as usize)
                .and_then(extract_cell_inner_type);
            let value_encoding = inner_ty.as_ref().and_then(aligned_value_encoding);
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
    ///
    /// NOT YET WIRED UP: held as scaffolding for the next-stage Cell::set
    /// and Map::insert work. See `memories/storage-cell-encoding-gap.md`
    /// for the remaining alignment + two-Push-pattern questions.
    #[allow(dead_code)]
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

    fn emit_instruction(&mut self, instruction: Instruction) -> Index {
        let idx = self.next_index;
        let outputs = instruction_output_count(&instruction);
        self.next_index += outputs;
        self.instructions.push(instruction);
        idx
    }

    /// Emit a type constraint for a variable based on its syn::Type.
    fn emit_type_constraint(&mut self, var: Index, ty: &syn::Type) {
        let type_str = quote::quote!(#ty).to_string().replace(' ', "");

        if type_str == "Boolean" || type_str == "bool" {
            self.instructions
                .push(Instruction::ConstrainToBoolean { var });
        } else if type_str.starts_with("Uint<")
            || type_str == "u8"
            || type_str == "u16"
            || type_str == "u32"
            || type_str == "u64"
            || type_str == "u128"
        {
            // Extract bit count from Uint<N>.
            let bits = if type_str == "u8" {
                8
            } else if type_str == "u16" {
                16
            } else if type_str == "u32" {
                32
            } else if type_str == "u64" {
                64
            } else if type_str == "u128" {
                128
            } else if let Some(n) = type_str
                .strip_prefix("Uint<")
                .and_then(|s| s.strip_suffix('>'))
            {
                n.parse::<u32>().unwrap_or(64)
            } else {
                64
            };
            self.instructions
                .push(Instruction::ConstrainBits { var, bits });
        } else if type_str.starts_with("Bytes<") {
            // Bytes<N> → constrain to N*8 bits.
            if let Some(n) = type_str
                .strip_prefix("Bytes<")
                .and_then(|s| s.strip_suffix('>'))
            {
                let bytes: u32 = n.parse().unwrap_or(32);
                self.instructions.push(Instruction::ConstrainBits {
                    var,
                    bits: bytes * 8,
                });
            }
        }
        // Field type: no constraint needed (native field element).
    }

    fn field_index(&self, field_name: &str) -> u8 {
        self.field_names
            .iter()
            .position(|f| f == field_name)
            .unwrap_or(0) as u8
    }
}

/// Encoding parameters for an `AlignedValue<T>` of a known Rust type.
///
/// Mirrors `AlignedValue::field_repr` (`transient-crypto/src/fab.rs:381`):
/// alignment metadata first, then the value's field elements.
///
/// - `alignment_atoms`: the LoadImm-able sequence emitted for
///   `alignment.field_repr` (`fab.rs:368-374`). For a single-atom alignment
///   `[AlignmentSegment::Atom(AlignmentAtom::Bytes{N})]`, this is `[1, N]`
///   (one segment, then the atom's encoded length).
/// - `value_field_count`: number of `Fr` elements occupied by the value
///   itself. Today we only encode single-Fr value types — multi-Fr
///   (e.g., `Bytes<N>` for N giving > 1 Fr) is unsupported and falls
///   through to the legacy emission.
#[derive(Debug, Clone)]
struct AlignedValueEncoding {
    /// Each entry is a signed Fr atom (i32 in the IR, but materialized via
    /// `Fr::from(i32)` which routes through `derive_signed!` to handle
    /// negative atoms). Positive values are the segment count (1) and
    /// `Bytes{N}` length; `-2` is the on-chain encoding of
    /// `AlignmentAtom::Field` (`transient-crypto/src/fab.rs:605`).
    /// `-1` would be `AlignmentAtom::Compress` but we don't use it yet.
    alignment_atoms: Vec<i32>,
    value_field_count: usize,
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
fn aligned_value_encoding(ty: &syn::Type) -> Option<AlignedValueEncoding> {
    let ty_str = quote::quote!(#ty).to_string().replace(' ', "");

    // Boolean and bool: encoded as Bytes<1>.
    if ty_str == "Boolean" || ty_str == "bool" {
        return Some(AlignedValueEncoding {
            alignment_atoms: vec![1, 1],
            value_field_count: 1,
        });
    }

    // Field: encoded with `AlignmentAtom::Field` (`-2` after field_repr).
    // The value occupies a single Fr — no bit-width chunking.
    if ty_str == "Field" {
        return Some(AlignedValueEncoding {
            alignment_atoms: vec![1, -2],
            value_field_count: 1,
        });
    }

    // Uint<N> and primitive integer types: encoded as Bytes<ceil(N/8)>.
    // For N ≤ 64 the value fits in one Fr.
    let int_bits = if ty_str == "u8" {
        Some(8u32)
    } else if ty_str == "u16" {
        Some(16)
    } else if ty_str == "u32" {
        Some(32)
    } else if ty_str == "u64" {
        Some(64)
    } else if ty_str == "u128" {
        Some(128)
    } else if let Some(n) = ty_str
        .strip_prefix("Uint<")
        .and_then(|s| s.strip_suffix('>'))
    {
        n.parse::<u32>().ok()
    } else {
        None
    };
    if let Some(bits) = int_bits {
        let bytes = bits.div_ceil(8);
        // The Fr field is ~253 bits — anything up to that fits in one Fr.
        if bits > 0 && bits <= 253 {
            return Some(AlignedValueEncoding {
                alignment_atoms: vec![1, bytes as i32],
                value_field_count: 1,
            });
        }
    }

    // Bytes<N>: alignment `[1, N]`, multi-Fr value when N > 31.
    // `value_field_count = ceil(N / FR_BYTES_STORED)`. Compatible with
    // single-Fr Bytes<N> (N ≤ 31) too.
    if let Some(n) = ty_str
        .strip_prefix("Bytes<")
        .and_then(|s| s.strip_suffix('>'))
        .and_then(|s| s.parse::<u32>().ok())
        && n > 0
    {
        return Some(AlignedValueEncoding {
            alignment_atoms: vec![1, n as i32],
            value_field_count: n.div_ceil(FR_BYTES_STORED) as usize,
        });
    }

    // Field: encoded as AlignmentAtom::Field (-2 in two's complement, but
    // we don't yet support raw Field cells — needs the unsigned wraparound
    // encoded into the LoadImm).
    // Bytes<N>: similarly deferred until we add multi-Fr value emission.
    None
}

/// Number of bytes that fit in a single Fr's field representation
/// (must mirror `transient_crypto::curve::FR_BYTES_STORED` = `FR_BYTES - 1`).
const FR_BYTES_STORED: u32 = 31;

/// Per-Fr bit layout for a witness type, in the order PrivateInputs are
/// emitted (matching `AlignedValueExt::value_only_field_repr`).
///
/// Returns `Some(bits)` to apply `ConstrainBits { var, bits }` to that Fr.
/// Returns `None` to use the generic type-dispatched constraint (for
/// Boolean/Field/Uint).
///
/// `Bytes<N>` uses `FieldRepr` chunk-and-reverse semantics: `chunks(31)`
/// then `.rev()`. The first emitted Fr is the high-bytes chunk (the tail
/// of the original byte string), whose size is `N % 31` if that's
/// non-zero, otherwise `31`. Each subsequent Fr is a full 31-byte chunk.
fn witness_fr_layout(ty: &syn::Type) -> Vec<Option<u32>> {
    let ty_str = quote::quote!(#ty).to_string().replace(' ', "");
    if let Some(n) = ty_str
        .strip_prefix("Bytes<")
        .and_then(|s| s.strip_suffix('>'))
        .and_then(|s| s.parse::<u32>().ok())
    {
        let mut layout = Vec::new();
        let chunks = n.div_ceil(FR_BYTES_STORED);
        // First chunk (high portion after .rev()).
        let first_bytes = n % FR_BYTES_STORED;
        let first_bytes = if first_bytes == 0 {
            FR_BYTES_STORED
        } else {
            first_bytes
        };
        layout.push(Some(first_bytes * 8));
        // Remaining chunks are always full FR_BYTES_STORED bytes.
        for _ in 1..chunks {
            layout.push(Some(FR_BYTES_STORED * 8));
        }
        return layout;
    }
    // Single-Fr fallback: delegate to emit_type_constraint via None.
    vec![None]
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
/// first after `.rev()`). Single-Fr types get `Some(bits)` matching
/// `aligned_value_encoding`'s `atoms[1] * 8`.
fn read_result_fr_layout(ty: &syn::Type) -> Vec<Option<u32>> {
    let ty_str = quote::quote!(#ty).to_string().replace(' ', "");
    if let Some(n) = ty_str
        .strip_prefix("Bytes<")
        .and_then(|s| s.strip_suffix('>'))
        .and_then(|s| s.parse::<u32>().ok())
        && n > 0
    {
        let chunks = n.div_ceil(FR_BYTES_STORED);
        let mut layout = Vec::with_capacity(chunks as usize);
        let first_bytes = if n % FR_BYTES_STORED == 0 {
            FR_BYTES_STORED
        } else {
            n % FR_BYTES_STORED
        };
        layout.push(Some(first_bytes * 8));
        for _ in 1..chunks {
            layout.push(Some(FR_BYTES_STORED * 8));
        }
        return layout;
    }
    vec![None]
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

/// If `ty` is `Cell<T>`, return `T`. Otherwise `None`.
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

/// If `ty` is `MerkleTree<H, T>`, return `T` (the leaf type). The height
/// `H` is encoded into the storage type's const generic and doesn't
/// affect the IR emission — checkRoot's on-chain ops are independent of
/// `H` because the height lives inside the upstream
/// `BoundedMerkleTree` value itself. Returns `Some(_)` so callers know
/// the field is a MerkleTree even when they don't need the leaf type.
fn extract_merkle_tree_type(ty: &syn::Type) -> Option<syn::Type> {
    if let syn::Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
        && seg.ident == "MerkleTree"
        && let syn::PathArguments::AngleBracketed(args) = &seg.arguments
    {
        // Skip the const-generic height; pick the first type-position arg.
        for a in &args.args {
            if let syn::GenericArgument::Type(t) = a {
                return Some(t.clone());
            }
        }
    }
    None
}

/// If `ty` is `Set<T>`, return `T`. Otherwise `None`.
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

/// If `ty` is `Map<K, V>`, return `(K, V)`. Otherwise `None`.
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
