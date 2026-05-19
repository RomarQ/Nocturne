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
                // dispatches separately from Counter/Cell because its
                // methods (contains/get/set/remove) take a user-typed key.
                let field_ty = self.field_types.get(field_idx as usize).cloned();
                let map_kv = field_ty.as_ref().and_then(extract_map_kv_types);

                if let Some((k_ty, v_ty)) = map_kv {
                    return self.emit_map_method(field_idx, &method_name, args, &k_ty, &v_ty);
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
                        let val = args.first().and_then(|a| self.emit_expr(a));
                        self.emit_ledger_write(field_idx, val)
                    }
                    "insert" => {
                        let val = args.first().and_then(|a| self.emit_expr(a));
                        self.emit_ledger_write(field_idx, val)
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
                let idx = self.emit_instruction(Instruction::PrivateInput { guard: None });
                // Emit type constraint based on witness field type.
                let ty = self.witness_types.get(&field.to_string()).cloned();
                if let Some(ty) = &ty {
                    self.emit_type_constraint(idx, ty);
                }
                self.variables.insert(key, idx);
                Some(idx)
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
        let result_enc = result_ty.and_then(aligned_value_encoding);
        let read_value = self.emit_instruction(Instruction::PublicInput { guard: None });
        let popeq_op = self.emit_load_imm(Fr::from(0x0du64));
        self.push_declare_pub_input(popeq_op);

        match result_enc {
            Some(enc) if enc.value_field_count == 1 => {
                // [opcode, ..alignment_atoms, result] — alignment.field_repr
                // for a single-segment Bytes{N} is [segment_count=1, N], so
                // the full Popeq is [0x0c, 1, N, value].
                for atom in &enc.alignment_atoms {
                    let v = self.emit_load_imm(Fr::from(*atom as u64));
                    self.push_declare_pub_input(v);
                }
                self.push_declare_pub_input(read_value);
                // opcode (1) + alignment atoms (N) + value (1)
                let count = 2 + enc.alignment_atoms.len();
                self.instructions.push(Instruction::PiSkip {
                    guard: Some(g),
                    count: count as u32,
                });
            }
            _ => {
                // Legacy 1-declare fallback. Not on-chain compatible — only
                // for unknown / multi-Fr result types. Logged in the memory
                // file alongside the Cell::set work.
                self.instructions.push(Instruction::PiSkip {
                    guard: Some(g),
                    count: 1,
                });
            }
        }

        Some(read_value)
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
        // Compute the key encoding once. Map<K, V> with K that doesn't fit
        // in a single Fr (e.g. Bytes<32>) is rejected here — see
        // memories/map-ledger-field-encoding.md for the multi-Fr work.
        let key_enc = aligned_value_encoding(k_ty)?;
        if key_enc.value_field_count != 1 {
            return None;
        }

        match method_name {
            "contains" => {
                let key_var = args.first().and_then(|a| self.emit_expr(a))?;
                self.emit_map_member(field_idx, key_var, &key_enc)
            }
            "insert" | "set" => {
                // Value encoding requires V to fit in a single Fr too.
                let val_enc = aligned_value_encoding(v_ty)?;
                if val_enc.value_field_count != 1 {
                    return None;
                }
                let key_var = args.first().and_then(|a| self.emit_expr(a))?;
                let val_var = args.get(1).and_then(|a| self.emit_expr(a))?;
                self.emit_map_insert(field_idx, key_var, &key_enc, val_var, &val_enc)
            }
            "remove" => {
                let key_var = args.first().and_then(|a| self.emit_expr(a))?;
                self.emit_map_remove(field_idx, key_var, &key_enc)
            }
            "lookup" => {
                // Value encoding requires V to fit in a single Fr today.
                // Multi-Fr V is tracked alongside the Bytes<N>-as-value work.
                let val_enc = aligned_value_encoding(v_ty)?;
                if val_enc.value_field_count != 1 {
                    return None;
                }
                let key_var = args.first().and_then(|a| self.emit_expr(a))?;
                self.emit_map_lookup(field_idx, key_var, &key_enc, &val_enc)
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
        key_var: Index,
        key_encoding: &AlignedValueEncoding,
        val_var: Index,
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
        self.emit_push_cell(key_var, Some(key_encoding), /* storage = */ false);

        // Push { storage: true, value: Cell(value) } — the V side.
        self.emit_push_cell(val_var, Some(val_encoding), /* storage = */ true);

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
        key_var: Index,
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
        // value] structure. Only single-Fr key values are supported here
        // today; multi-Fr keys (e.g. Bytes<32>) need extended encoding work.
        self.emit_push_cell(key_var, Some(key_encoding), /* storage = */ false);

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
        let result_var = self.emit_instruction(Instruction::PublicInput { guard: None });
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
        key_var: Index,
        key_encoding: &AlignedValueEncoding,
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
        // emit path mirrors emit_push_cell's per-type alignment but the
        // opcode is 0x50 (Idx) instead of 0x10 (Push), and there's no
        // Cell-discriminant byte — the path entry is just `Key::Value(av)`
        // whose field_repr is `av.field_repr` = [seg_count, ..atoms, value].
        let idx_op2 = self.emit_load_imm(Fr::from(0x50u64));
        self.push_declare_pub_input(idx_op2);
        for atom in &key_encoding.alignment_atoms {
            let v = self.emit_load_imm(Fr::from(*atom as u64));
            self.push_declare_pub_input(v);
        }
        self.push_declare_pub_input(key_var);
        // Total: opcode (1) + alignment atoms (N) + value (1)
        let count2 = 2 + key_encoding.alignment_atoms.len();
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: count2 as u32,
        });

        // Popeq { cached: false, result: AlignedValue<V> } → 0x0c.
        // Compactc uses 0x0c (cached:false) for lookup specifically —
        // distinct from member's cached:true — because the actual read
        // happens here.
        let read_value = self.emit_instruction(Instruction::PublicInput { guard: None });
        let popeq_op = self.emit_load_imm(Fr::from(0x0cu64));
        self.push_declare_pub_input(popeq_op);
        for atom in &val_encoding.alignment_atoms {
            let v = self.emit_load_imm(Fr::from(*atom as u64));
            self.push_declare_pub_input(v);
        }
        self.push_declare_pub_input(read_value);
        let count3 = 2 + val_encoding.alignment_atoms.len();
        self.instructions.push(Instruction::PiSkip {
            guard: Some(g),
            count: count3 as u32,
        });

        Some(read_value)
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
        key_var: Index,
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
        self.emit_push_cell(key_var, Some(key_encoding), /* storage = */ false);

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
    fn emit_ledger_write(&mut self, field_idx: u8, value: Option<Index>) -> Option<Index> {
        // The KEY: Push(storage: false, Cell(Bytes<1>(field_idx))).
        let key_var = self.emit_load_imm(Fr::from(field_idx as u64));
        let key_encoding = aligned_value_encoding_bytes(1);
        self.emit_push_cell(key_var, Some(&key_encoding), /* storage = */ false);

        // The VALUE: Push(storage: true, Cell(<value-typed AlignedValue>)).
        if let Some(val_idx) = value {
            let inner_ty = self
                .field_types
                .get(field_idx as usize)
                .and_then(extract_cell_inner_type);
            let value_encoding = inner_ty.as_ref().and_then(aligned_value_encoding);
            self.emit_push_cell(val_idx, value_encoding.as_ref(), /* storage = */ true);
        }

        // The Ins: Ins { cached: false, n: 1 } → opcode 0x91.
        let ins_op = self.emit_load_imm(Fr::from(0x91u64));
        self.push_declare_pub_input(ins_op);
        self.instructions.push(Instruction::PiSkip {
            guard: Some(self.guard),
            count: 1,
        });

        value
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
        value_var: Index,
        encoding: Option<&AlignedValueEncoding>,
        storage: bool,
    ) {
        let g = self.guard;
        let push_op = self.emit_load_imm(Fr::from(if storage { 0x11u64 } else { 0x10u64 }));
        self.push_declare_pub_input(push_op);

        match encoding {
            Some(enc) if enc.value_field_count == 1 => {
                // Cell discriminant (1) + alignment.field_repr + 1-Fr value.
                let cell_disc = self.emit_load_imm(Fr::from(1u64));
                self.push_declare_pub_input(cell_disc);
                for atom in &enc.alignment_atoms {
                    let v = self.emit_load_imm(Fr::from(*atom as u64));
                    self.push_declare_pub_input(v);
                }
                self.push_declare_pub_input(value_var);
                // Total: Push opcode (1) + Cell disc (1) + alignment (1 + N atoms) + value (1)
                //      = 4 + alignment_atoms.len()
                let count = 3 + enc.alignment_atoms.len();
                self.instructions.push(Instruction::PiSkip {
                    guard: Some(g),
                    count: count as u32,
                });
            }
            _ => {
                // Fallback: legacy 2-declare emission. Used when the value
                // type isn't in the encoding table yet (e.g., multi-Fr types
                // like Bytes<N>). Not on-chain compatible — a TODO until the
                // encoding table covers all supported value types.
                self.push_declare_pub_input(value_var);
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
    alignment_atoms: Vec<u32>,
    value_field_count: usize,
}

/// Encoding for `AlignedValue<Bytes<N>>`: alignment `[1, N]`, value width 1 Fr
/// (callers must ensure `N * 8 ≤ 253` for the value to fit in one Fr).
fn aligned_value_encoding_bytes(n: u32) -> AlignedValueEncoding {
    AlignedValueEncoding {
        alignment_atoms: vec![1, n],
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
                alignment_atoms: vec![1, bytes],
                value_field_count: 1,
            });
        }
    }

    // Field: encoded as AlignmentAtom::Field (-2 in two's complement, but
    // we don't yet support raw Field cells — needs the unsigned wraparound
    // encoded into the LoadImm).
    // Bytes<N>: similarly deferred until we add multi-Fr value emission.
    None
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
        | Instruction::DivModPowerOfTwo { .. } => 2,

        _ => 1,
    }
}
