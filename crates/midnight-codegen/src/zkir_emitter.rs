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

use midnight_ir::{CircuitIR, ContractIR, ExprIR};
use midnight_ir::expr::{AssertKind, LiteralIR};
use midnight_zkir::{Instruction, IrSource};
use midnight_transient_crypto::curve::Fr;
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
            let mut emitter = ZkirEmitter::new(&field_names, &witness_types);
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
    /// Witness field name → type, for emitting type constraints on PrivateInput.
    witness_types: HashMap<String, syn::Type>,
}

impl ZkirEmitter {
    fn new(field_names: &[String], witness_types: &HashMap<String, syn::Type>) -> Self {
        Self {
            instructions: Vec::new(),
            next_index: 0,
            variables: HashMap::new(),
            num_inputs: 0,
            guard: 0,
            in_conditional: false,
            zero_var: None,
            field_names: field_names.to_vec(),
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
        self.instructions.push(Instruction::DeclarePubInput { var: final_var });
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
                self.instructions.push(Instruction::Output { var: last_idx });
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
            ExprIR::LedgerAccess { field, method, args, .. } => {
                let method_name = method.to_string();
                let field_idx = self.field_index(&field.to_string());

                match method_name.as_str() {
                    "increment" => self.emit_counter_increment(field_idx),
                    "get" | "value" | "__direct_access" => self.emit_ledger_read(field_idx),
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
                    BinOp::Gt(_) => {
                        Some(self.emit_instruction(Instruction::LessThan { a: b, b: a, bits: 64 }))
                    }
                    BinOp::Le(_) => {
                        let gt = self.emit_instruction(Instruction::LessThan { a: b, b: a, bits: 64 });
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

            ExprIR::UnaryOp { op, expr: inner, .. } => {
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
                        self.instructions.push(Instruction::ConstrainEq { a: idx_a, b: idx_b });
                    }
                }
                None
            }

            ExprIR::If { cond, then_branch, else_branch, .. } => {
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
                let arg_indices: Vec<Index> = args
                    .iter()
                    .filter_map(|a| self.emit_expr(a))
                    .collect();

                match name_str.as_str() {
                    "persistent_hash" => {
                        use midnight_base_crypto::fab::{
                            Alignment, AlignmentAtom, AlignmentSegment,
                        };
                        let alignment = Alignment(vec![
                            AlignmentSegment::Atom(AlignmentAtom::Field),
                        ]);
                        Some(self.emit_instruction(Instruction::PersistentHash {
                            alignment,
                            inputs: arg_indices,
                        }))
                    }
                    "transient_hash" => {
                        Some(self.emit_instruction(Instruction::TransientHash {
                            inputs: arg_indices,
                        }))
                    }
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
        self.instructions.push(Instruction::PiSkip { guard: Some(g), count: 4 });

        // Addi { immediate: 1 } → field repr: [0x0e, 1]
        let addi_op = self.emit_load_imm(Fr::from(0x0eu64));
        let one = self.emit_load_imm(Fr::from(1u64));
        self.push_declare_pub_input(addi_op);
        self.push_declare_pub_input(one);
        self.instructions.push(Instruction::PiSkip { guard: Some(g), count: 2 });

        // Ins { cached: true, n: 1 } → field repr: [0xa1]
        let ins_op = self.emit_load_imm(Fr::from(0xa1u64));
        self.push_declare_pub_input(ins_op);
        self.instructions.push(Instruction::PiSkip { guard: Some(g), count: 1 });

        Some(one)
    }

    /// Emit ZKIR for reading a ledger field: Dup + Idx + Popeq.
    ///
    /// Matches Compact's ledger read pattern:
    ///   dup [n: 0]
    ///   idx [cached: false] [pushPath: false] [path: f]
    ///   popeq [cached: true] [result: void]
    fn emit_ledger_read(&mut self, field_idx: u8) -> Option<Index> {
        let g = self.guard;

        // Dup { n: 0 } → field repr: [0x30]
        let dup_op = self.emit_load_imm(Fr::from(0x30u64));
        self.push_declare_pub_input(dup_op);
        self.instructions.push(Instruction::PiSkip { guard: Some(g), count: 1 });

        // Idx { cached: false, push_path: false, path: [Value(field_idx)] }
        // Opcode: 0x50 | 0 = 0x50
        let idx_op = self.emit_load_imm(Fr::from(0x50u64));
        self.push_declare_pub_input(idx_op);
        self.emit_key_field_repr(field_idx);
        self.instructions.push(Instruction::PiSkip { guard: Some(g), count: 4 });

        // Popeq { cached: false } → field repr: [0x0c, result_fields...]
        // The read result comes from the transcript as public_input.
        let popeq_op = self.emit_load_imm(Fr::from(0x0cu64));
        self.push_declare_pub_input(popeq_op);
        let read_value = self.emit_instruction(Instruction::PublicInput { guard: None });
        self.instructions.push(Instruction::PiSkip { guard: Some(g), count: 1 });

        Some(read_value)
    }

    /// Emit ZKIR for writing a ledger field: Idx(push_path) + Push(value) + Ins.
    fn emit_ledger_write(&mut self, field_idx: u8, value: Option<Index>) -> Option<Index> {
        let g = self.guard;

        // Idx { cached: false, push_path: true, path: [Value(field_idx)] }
        let idx_op = self.emit_load_imm(Fr::from(0x70u64));
        self.push_declare_pub_input(idx_op);
        self.emit_key_field_repr(field_idx);
        self.instructions.push(Instruction::PiSkip { guard: Some(g), count: 4 });

        // Push { storage: false, value } → [0x10, value_fields...]
        if let Some(val_idx) = value {
            let push_op = self.emit_load_imm(Fr::from(0x10u64));
            self.push_declare_pub_input(push_op);
            self.push_declare_pub_input(val_idx);
            self.instructions.push(Instruction::PiSkip { guard: Some(g), count: 2 });
        }

        // Ins { cached: true, n: 1 } → [0xa1]
        let ins_op = self.emit_load_imm(Fr::from(0xa1u64));
        self.push_declare_pub_input(ins_op);
        self.instructions.push(Instruction::PiSkip { guard: Some(g), count: 1 });

        value
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
            self.instructions.push(Instruction::ConstrainToBoolean { var });
        } else if type_str.starts_with("Uint<")
            || type_str == "u8" || type_str == "u16" || type_str == "u32"
            || type_str == "u64" || type_str == "u128"
        {
            // Extract bit count from Uint<N>.
            let bits = if type_str == "u8" { 8 }
            else if type_str == "u16" { 16 }
            else if type_str == "u32" { 32 }
            else if type_str == "u64" { 64 }
            else if type_str == "u128" { 128 }
            else if let Some(n) = type_str.strip_prefix("Uint<").and_then(|s| s.strip_suffix('>')) {
                n.parse::<u32>().unwrap_or(64)
            } else {
                64
            };
            self.instructions.push(Instruction::ConstrainBits { var, bits });
        } else if type_str.starts_with("Bytes<") {
            // Bytes<N> → constrain to N*8 bits.
            if let Some(n) = type_str.strip_prefix("Bytes<").and_then(|s| s.strip_suffix('>')) {
                let bytes: u32 = n.parse().unwrap_or(32);
                self.instructions.push(Instruction::ConstrainBits { var, bits: bytes * 8 });
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
