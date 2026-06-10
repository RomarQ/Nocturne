#[cfg(test)]
mod tests {
    use crate::zkir_emitter;
    use midnight_zkir::{Instruction, IrSource};
    use nocturne_ir::parse_contract;

    fn compile_circuits(input: proc_macro2::TokenStream) -> Vec<(String, IrSource)> {
        compile_circuits_with_spans(input)
            .into_iter()
            .map(|(name, ir, _)| (name, ir))
            .collect()
    }

    type CircuitWithSpans = (String, IrSource, Vec<std::ops::Range<usize>>);

    /// Like `compile_circuits` but keeps the emitter's recorded
    /// conditional branch spans alongside each circuit — the ground
    /// truth `assert_structural_invariants` uses to decide which
    /// instructions were emitted inside a conditional.
    fn compile_circuits_with_spans(input: proc_macro2::TokenStream) -> Vec<CircuitWithSpans> {
        let module: syn::ItemMod = syn::parse2(input).expect("parse module");
        let contract = parse_contract(module).expect("parse contract");
        let output = zkir_emitter::emit_contract(&contract);
        assert!(
            output.errors.is_empty(),
            "circuit emission recorded unexpected errors: {:?}",
            output.errors
        );
        output
            .circuits
            .into_iter()
            .map(|c| (c.circuit_name, c.ir_source, c.branch_spans))
            .collect()
    }

    /// Emit a contract and return ONLY the recorded emission errors.
    fn emit_errors(input: proc_macro2::TokenStream) -> Vec<String> {
        let module: syn::ItemMod = syn::parse2(input).expect("parse module");
        let contract = parse_contract(module).expect("parse contract");
        zkir_emitter::emit_contract(&contract).errors
    }

    /// Wire index produced by the instruction at `position`, computed
    /// by replaying allocation the same way the emitter does (inputs
    /// first, then one block of indices per instruction's outputs).
    fn wire_of(ir: &IrSource, position: usize) -> u32 {
        let mut next = ir.num_inputs;
        for (i, instr) in ir.instructions.iter().enumerate() {
            if i == position {
                return next;
            }
            next += test_output_count(instr);
        }
        panic!("instruction position {position} out of range");
    }

    /// Mirror of the emitter's `instruction_output_count` for tests.
    fn test_output_count(instruction: &Instruction) -> u32 {
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
            | Instruction::PersistentHash { .. } => 2,
            _ => 1,
        }
    }

    #[test]
    fn counter_increment_encodes_transcript_ops() {
        let circuits = compile_circuits(quote::quote! {
            mod counter {
                #[nocturne(ledger)]
                pub struct CounterState {
                    count: Counter,
                }

                impl CounterState {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { count: Counter::zero() }
                    }

                    #[nocturne(circuit)]
                    pub fn increment(&mut self) {
                        self.count.increment();
                    }
                }
            }
        });

        let (name, ir) = &circuits[0];
        assert_eq!(name, "increment");
        // do_communications_commitment is always emitted to match compactc.
        assert!(ir.do_communications_commitment);

        let instrs = ir.instructions.as_ref();

        // First instruction: load_imm 0x01 (guard)
        assert!(matches!(&instrs[0], Instruction::LoadImm { .. }));

        // Should contain DeclarePubInput instructions (encoding transcript ops)
        let pub_input_count = instrs
            .iter()
            .filter(|i| matches!(i, Instruction::DeclarePubInput { .. }))
            .count();
        assert!(
            pub_input_count > 0,
            "should emit DeclarePubInput for transcript ops"
        );

        // Should contain PiSkip instructions (grouping transcript ops)
        let pi_skip_count = instrs
            .iter()
            .filter(|i| matches!(i, Instruction::PiSkip { .. }))
            .count();
        assert!(pi_skip_count > 0, "should emit PiSkip to group ops");

        // Should contain LoadImm values matching VM opcodes:
        // 0x30 (Dup), 0x70 (Idx push_path), 0x0e (Addi), 0xa1 (Ins cached)
        let load_imms: Vec<&Instruction> = instrs
            .iter()
            .filter(|i| matches!(i, Instruction::LoadImm { .. }))
            .collect();
        assert!(
            load_imms.len() >= 5,
            "should have LoadImm for guard + 4 VM opcodes, got {}",
            load_imms.len()
        );
    }

    #[test]
    fn print_counter_zkir() {
        let circuits = compile_circuits(quote::quote! {
            mod counter {
                #[nocturne(ledger)]
                pub struct CounterState {
                    count: Counter,
                }
                impl CounterState {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn increment(&mut self) { self.count.increment(); }
                }
            }
        });
        let (_, ir) = &circuits[0];
        let json = serde_json::to_string_pretty(ir).expect("serialize");
        println!("=== Counter increment ZKIR ===\n{json}");
    }

    #[test]
    fn zkir_roundtrip_json() {
        let circuits = compile_circuits(quote::quote! {
            mod counter {
                #[nocturne(ledger)]
                pub struct CounterState {
                    count: Counter,
                }

                impl CounterState {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { count: Counter::zero() }
                    }

                    #[nocturne(circuit)]
                    pub fn increment(&mut self) {
                        self.count.increment();
                    }
                }
            }
        });

        let (_, ir) = &circuits[0];
        let json = serde_json::to_string_pretty(ir).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse JSON");

        assert_eq!(parsed["do_communications_commitment"], true);

        // Verify instruction ops are correct
        let instrs = parsed["instructions"].as_array().unwrap();
        assert_eq!(instrs[0]["op"], "load_imm");

        // Roundtrip
        let roundtripped: IrSource = serde_json::from_str(&json).expect("roundtrip");
        assert_eq!(roundtripped.instructions.len(), ir.instructions.len());
    }

    #[test]
    fn witness_access_emits_private_input() {
        let circuits = compile_circuits(quote::quote! {
            mod secret {
                #[nocturne(ledger)]
                pub struct State {
                    value: Cell,
                }

                #[nocturne(witnesses)]
                pub struct Witnesses {
                    secret: Field,
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { value: Cell::new(0) }
                    }

                    #[nocturne(circuit)]
                    pub fn use_secret(&mut self, witnesses: &Witnesses) {
                        let s = witnesses.secret;
                        self.value.set(s);
                    }
                }
            }
        });

        let (_, ir) = &circuits[0];
        let instrs = ir.instructions.as_ref();

        let has_private_input = instrs
            .iter()
            .any(|i| matches!(i, Instruction::PrivateInput { .. }));
        assert!(has_private_input, "witness access should emit PrivateInput");
    }

    #[test]
    fn assert_eq_emits_constrain_eq() {
        let circuits = compile_circuits(quote::quote! {
            mod constrained {
                #[nocturne(ledger)]
                pub struct State {
                    x: Counter,
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { x: Counter::zero() }
                    }

                    #[nocturne(circuit)]
                    pub fn check(&mut self) {
                        let a = 42;
                        let b = 42;
                        assert_eq!(a, b);
                    }
                }
            }
        });

        let (_, ir) = &circuits[0];
        let instrs = ir.instructions.as_ref();

        let has_constrain_eq = instrs
            .iter()
            .any(|i| matches!(i, Instruction::ConstrainEq { .. }));
        assert!(has_constrain_eq, "assert_eq! should emit ConstrainEq");
    }

    #[test]
    fn persistent_hash_emits_instruction() {
        let circuits = compile_circuits(quote::quote! {
            mod hashing {
                #[nocturne(ledger)]
                pub struct State {
                    commitment: Cell,
                }

                #[nocturne(witnesses)]
                pub struct Witnesses {
                    secret: Field,
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { commitment: Cell::new(0) }
                    }

                    #[nocturne(circuit)]
                    pub fn commit(&mut self, witnesses: &Witnesses) {
                        let hash = persistent_hash(witnesses.secret);
                        self.commitment.set(hash);
                    }
                }
            }
        });

        let (_, ir) = &circuits[0];
        let instrs = ir.instructions.as_ref();

        let has_persistent_hash = instrs
            .iter()
            .any(|i| matches!(i, Instruction::PersistentHash { .. }));
        assert!(has_persistent_hash, "should emit PersistentHash");
    }

    #[test]
    fn ledger_read_emits_public_input() {
        let circuits = compile_circuits(quote::quote! {
            mod reader {
                #[nocturne(ledger)]
                pub struct State {
                    value: Cell,
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { value: Cell::new(0) }
                    }

                    #[nocturne(circuit)]
                    pub fn read_it(&mut self) {
                        let v = self.value.get();
                    }
                }
            }
        });

        let (_, ir) = &circuits[0];
        let instrs = ir.instructions.as_ref();

        // Ledger read should produce PublicInput (to receive the value from transcript)
        let has_public_input = instrs
            .iter()
            .any(|i| matches!(i, Instruction::PublicInput { .. }));
        assert!(has_public_input, "ledger read should emit PublicInput");

        // And DeclarePubInput for the Popeq op encoding
        let has_declare = instrs
            .iter()
            .any(|i| matches!(i, Instruction::DeclarePubInput { .. }));
        assert!(
            has_declare,
            "ledger read should emit DeclarePubInput for VM ops"
        );
    }

    /// `disclose(v)` is a marker, not an emission: the disclosed value
    /// reaches the public view through the ledger op that consumes it.
    /// A disclose-emitted DeclarePubInput group has no backing
    /// transcript op, so the ledger-reconstructed verifier PIs would
    /// never contain it and any active-path disclose would fail at
    /// prove time. The circuit must be IDENTICAL with and without the
    /// marker.
    #[test]
    fn disclose_is_transparent_in_zkir() {
        let with_disclose = compile_circuits(quote::quote! {
            mod disclosing {
                #[nocturne(ledger)]
                pub struct State { threshold: Cell<u64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { threshold: Cell::new(0u64) } }
                    #[nocturne(circuit)]
                    pub fn reveal(&mut self) {
                        self.threshold.set(nocturne::disclose(42));
                    }
                }
            }
        });
        let without_disclose = compile_circuits(quote::quote! {
            mod disclosing {
                #[nocturne(ledger)]
                pub struct State { threshold: Cell<u64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { threshold: Cell::new(0u64) } }
                    #[nocturne(circuit)]
                    pub fn reveal(&mut self) {
                        self.threshold.set(42);
                    }
                }
            }
        });

        let a = serde_json::to_string(&with_disclose[0].1).expect("serialize");
        let b = serde_json::to_string(&without_disclose[0].1).expect("serialize");
        assert_eq!(
            a, b,
            "disclose must not add any instruction (DeclarePubInput/PiSkip) to the circuit"
        );
    }

    /// End-to-end pin for the bind-once match-scrutinee fix.
    ///
    /// `match witnesses.choice() { ... }` lowers to a synthetic
    /// `let __nocturne_scrutinee_N = witnesses.choice();` followed by an
    /// if-chain comparing the bound Var against each variant. Each
    /// `WitnessCall` the emitter sees allocates a fresh PrivateInput
    /// block (no cache key), so if the scrutinee were cloned into every
    /// arm's comparison the circuit would draw one witness PER ARM —
    /// the arms could each see a different value. A unit-only enum
    /// return is exactly one Fr (the 8-bit discriminant), so the whole
    /// circuit must allocate exactly one PrivateInput.
    #[test]
    fn match_on_witness_call_allocates_one_private_input_block() {
        let circuits = compile_circuits(quote::quote! {
            mod scrutinee_once {
                pub enum Vote { For, Against, Abstain }

                #[nocturne(ledger)]
                pub struct State { a: Counter, b: Counter }

                #[nocturne(witnesses)]
                pub struct W;

                impl W {
                    pub fn choice(&self) -> Vote { Vote::For }
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { a: Counter::zero(), b: Counter::zero() }
                    }

                    #[nocturne(circuit)]
                    pub fn cast(&mut self, witnesses: &W) {
                        match witnesses.choice() {
                            Vote::For => { self.a.increment(); }
                            Vote::Against => { self.b.increment(); }
                            _ => { self.a.increment(); }
                        }
                    }
                }
            }
        });

        let (name, ir) = &circuits[0];
        assert_eq!(name, "cast");
        let instrs = ir.instructions.as_ref();

        let private_input_count = instrs
            .iter()
            .filter(|i| matches!(i, Instruction::PrivateInput { .. }))
            .count();
        assert_eq!(
            private_input_count, 1,
            "one witness call behind a synthetic scrutinee binding must \
             allocate exactly one PrivateInput, not one per match arm"
        );
    }

    /// Regression guard for the on-chain public-input layout.
    ///
    /// `midnight_ledger::verify::ContractCall::public_inputs` unconditionally
    /// pushes `[binding_input, communication_commitment, ..transcript]`. If a
    /// circuit is emitted with `do_communications_commitment = false`, its
    /// verifier key only reserves a slot for `binding_input`, and the ledger's
    /// extra commitment input causes a Plonk PI-count mismatch at verify time.
    ///
    /// Every Nocturne-emitted circuit must therefore opt in to the commitment
    /// slot — including circuits without a return value.
    #[test]
    fn every_circuit_emits_communications_commitment_slot() {
        // A grab bag of circuit shapes: no return, return value, witness +
        // conditional branches, public arg, multi-circuit contract.
        let circuits = compile_circuits(quote::quote! {
            mod shapes {
                #[nocturne(ledger)]
                pub struct State {
                    count: Counter,
                    flag: Cell<bool>,
                }

                #[nocturne(witnesses)]
                pub struct Witnesses {
                    pub choice: Boolean,
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { count: Counter::zero(), flag: Cell::new(false) }
                    }

                    #[nocturne(circuit)]
                    pub fn increment(&mut self) {
                        self.count.increment();
                    }

                    #[nocturne(circuit)]
                    pub fn cast(&mut self, witnesses: &Witnesses) {
                        if witnesses.choice.value() {
                            self.count.increment();
                        } else {
                            self.flag.set(true);
                        }
                    }

                    #[nocturne(circuit)]
                    pub fn get_count(&self) -> u64 {
                        self.count.value()
                    }
                }
            }
        });

        assert!(!circuits.is_empty(), "test contract must produce circuits");
        for (name, ir) in &circuits {
            assert!(
                ir.do_communications_commitment,
                "circuit '{name}' has do_communications_commitment=false; \
                 this would fail on-chain verify due to ledger PI count mismatch"
            );
        }
    }

    // -------------------------------------------------------------------
    // Task 2.1: error channel — unsupported constructs fail artifact
    // generation instead of being silently dropped from the circuit.
    // -------------------------------------------------------------------

    #[test]
    fn unsupported_div_fails_artifact_generation() {
        let module: syn::ItemMod = syn::parse2(quote::quote! {
            mod divider {
                #[nocturne(ledger)]
                pub struct State { x: Counter }
                #[nocturne(witnesses)]
                pub struct W { a: Uint<64>, b: Uint<64>, c: Uint<64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { x: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn check(&mut self, witnesses: &W) {
                        assert!(witnesses.a / witnesses.b == witnesses.c);
                    }
                }
            }
        })
        .expect("parse module");
        let contract = parse_contract(module).expect("parse contract");

        let errors = crate::codegen::generate_artifacts(&contract)
            .err()
            .expect("an unsupported Div inside assert! must fail artifact generation");
        assert!(
            errors.iter().any(|e| e.contains('/')),
            "error must mention the unsupported operator, got: {errors:?}"
        );
    }

    // -------------------------------------------------------------------
    // Task 2.2: Output lowering.
    // -------------------------------------------------------------------

    /// A trailing cache-hit expression (a let-bound witness
    /// re-reference) must drive `Output` with the WITNESS wire, not
    /// whatever wire happened to be allocated last by the preceding
    /// ledger write.
    #[test]
    fn trailing_cache_hit_var_outputs_witness_wire() {
        let circuits = compile_circuits(quote::quote! {
            mod ret_cache {
                #[nocturne(ledger)]
                pub struct State { cell: Cell<Field> }
                #[nocturne(witnesses)]
                pub struct W { secret: Field }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { cell: Cell::new(Field::from(0u64)) } }
                    #[nocturne(circuit)]
                    pub fn store(&mut self, witnesses: &W) -> Field {
                        let s = witnesses.secret;
                        self.cell.set(s);
                        s
                    }
                }
            }
        });

        let (_, ir) = &circuits[0];
        let instrs = ir.instructions.as_ref();

        let private_input_pos = instrs
            .iter()
            .position(|i| matches!(i, Instruction::PrivateInput { .. }))
            .expect("witness allocates a PrivateInput");
        let witness_wire = wire_of(ir, private_input_pos);

        let outputs: Vec<u32> = instrs
            .iter()
            .filter_map(|i| match i {
                Instruction::Output { var } => Some(*var),
                _ => None,
            })
            .collect();
        assert_eq!(outputs.len(), 1, "exactly one Output expected");
        assert_eq!(
            outputs[0], witness_wire,
            "Output must reference the cached witness wire, not the last-allocated wire"
        );
    }

    /// An explicit trailing `return x;` must emit exactly one Output
    /// (previously the Return arm AND the epilogue both emitted one).
    #[test]
    fn explicit_final_return_emits_single_output() {
        let circuits = compile_circuits(quote::quote! {
            mod ret_explicit {
                #[nocturne(ledger)]
                pub struct State { count: Counter }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn get_count(&self) -> u64 {
                        return self.count.value();
                    }
                }
            }
        });

        let (_, ir) = &circuits[0];
        let output_count = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Output { .. }))
            .count();
        assert_eq!(
            output_count, 1,
            "trailing `return x;` must emit exactly one Output"
        );
    }

    #[test]
    fn return_inside_helper_errors() {
        let errors = emit_errors(quote::quote! {
            mod helper_ret {
                #[nocturne(ledger)]
                pub struct State { cell: Cell<Uint<64>> }
                #[nocturne(witnesses)]
                pub struct W { a: Uint<64> }

                fn pass_through(v: Uint<64>) -> Uint<64> {
                    return v;
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { cell: Cell::new(Uint::<64>::from(0u64)) } }
                    #[nocturne(circuit)]
                    pub fn run(&mut self, witnesses: &W) {
                        let d = pass_through(witnesses.a);
                        self.cell.set(d);
                    }
                }
            }
        });
        assert!(
            errors.iter().any(|e| e.contains("inlined helper")),
            "`return` inside an inlined helper must be rejected, got: {errors:?}"
        );
    }

    #[test]
    fn non_tail_return_errors() {
        let errors = emit_errors(quote::quote! {
            mod ret_mid {
                #[nocturne(ledger)]
                pub struct State { count: Counter }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn early(&mut self) -> u64 {
                        return self.count.value();
                        self.count.increment();
                    }
                }
            }
        });
        assert!(
            errors.iter().any(|e| e.contains("final statement")),
            "non-tail `return` must be rejected, got: {errors:?}"
        );
    }

    // -------------------------------------------------------------------
    // Task 2.4: comparison_bits soundness.
    // -------------------------------------------------------------------

    #[test]
    fn comparison_widens_to_max_operand_width() {
        let circuits = compile_circuits(quote::quote! {
            mod widths {
                #[nocturne(ledger)]
                pub struct State { x: Counter }
                #[nocturne(witnesses)]
                pub struct W { small: Uint<8>, big: Uint<128> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { x: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn check(&mut self, witnesses: &W) {
                        assert!(witnesses.small < witnesses.big);
                    }
                }
            }
        });

        let (_, ir) = &circuits[0];
        let less_than_bits: Vec<u32> = ir
            .instructions
            .iter()
            .filter_map(|i| match i {
                Instruction::LessThan { bits, .. } => Some(*bits),
                _ => None,
            })
            .collect();
        assert_eq!(
            less_than_bits,
            vec![128],
            "Uint<8> vs Uint<128> comparison must constrain at the MAX width (128)"
        );
    }

    #[test]
    fn comparison_with_field_witness_errors() {
        let errors = emit_errors(quote::quote! {
            mod field_cmp {
                #[nocturne(ledger)]
                pub struct State { x: Counter }
                #[nocturne(witnesses)]
                pub struct W { f: Field, b: Uint<64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { x: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn check(&mut self, witnesses: &W) {
                        assert!(witnesses.b < witnesses.f);
                    }
                }
            }
        });
        assert!(
            errors.iter().any(|e| e.contains("bit width")),
            "comparison against a Field-typed witness must error, got: {errors:?}"
        );
    }

    // -------------------------------------------------------------------
    // Task 2.5: u128 literals load their full value.
    // -------------------------------------------------------------------

    #[test]
    fn u128_literal_loads_full_value() {
        use midnight_transient_crypto::curve::Fr;
        const BIG: u128 = 18446744073709551617; // 2^64 + 1

        let circuits = compile_circuits(quote::quote! {
            mod big_lit {
                #[nocturne(ledger)]
                pub struct State { big: Cell<Uint<128>> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { big: Cell::new(Uint::<128>::from(0u64)) } }
                    #[nocturne(circuit)]
                    pub fn set_big(&mut self) {
                        self.big.set(18446744073709551617u128);
                    }
                }
            }
        });

        let (_, ir) = &circuits[0];
        let has_full_value = ir
            .instructions
            .iter()
            .any(|i| matches!(i, Instruction::LoadImm { imm } if *imm == Fr::from(BIG)));
        assert!(
            has_full_value,
            "a literal above u64::MAX must LoadImm its full 128-bit value, \
             not a u64 truncation"
        );
    }

    // -------------------------------------------------------------------
    // Task 2.6: multi-Fr read layout.
    // -------------------------------------------------------------------

    #[test]
    fn cell_tuple_read_emits_one_public_input_per_fr() {
        let circuits = compile_circuits(quote::quote! {
            mod pair_reader {
                #[nocturne(ledger)]
                pub struct State { pair: Cell<(u64, u64)> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { pair: Cell::new((0u64, 0u64)) } }
                    #[nocturne(circuit)]
                    pub fn read_pair(&self) {
                        let _p = self.pair.get();
                    }
                }
            }
        });

        let (_, ir) = &circuits[0];
        let public_inputs = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::PublicInput { .. }))
            .count();
        assert_eq!(
            public_inputs, 2,
            "Cell<(u64, u64)> read must emit one PublicInput per value Fr"
        );

        // Popeq group: opcode (1) + alignment atoms [2, 8, 8] (3) + value Frs (2).
        let has_popeq_skip = ir
            .instructions
            .iter()
            .any(|i| matches!(i, Instruction::PiSkip { count: 6, .. }));
        assert!(
            has_popeq_skip,
            "Popeq PiSkip must claim 1 + alignment atoms + value Frs = 6"
        );
    }

    // -------------------------------------------------------------------
    // Task 2.7: witness cache vs branch guards.
    // -------------------------------------------------------------------

    #[test]
    fn witness_first_read_in_branch_reused_errors() {
        let errors = emit_errors(quote::quote! {
            mod cond_reuse {
                #[nocturne(ledger)]
                pub struct State { a: Cell<Uint<64>>, b: Cell<Uint<64>> }
                #[nocturne(witnesses)]
                pub struct W { c: Boolean, x: Uint<64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self {
                            a: Cell::new(Uint::<64>::from(0u64)),
                            b: Cell::new(Uint::<64>::from(0u64)),
                        }
                    }
                    #[nocturne(circuit)]
                    pub fn pick(&mut self, witnesses: &W) {
                        if witnesses.c.value() {
                            self.a.set(witnesses.x);
                        } else {
                            self.b.set(witnesses.x);
                        }
                    }
                }
            }
        });
        assert!(
            errors.iter().any(|e| e.contains("hoist")),
            "a witness field first read inside a branch and reused in the sibling \
             must be rejected with the hoist message, got: {errors:?}"
        );
    }

    #[test]
    fn let_hoisted_witness_in_branches_is_allowed() {
        let circuits = compile_circuits(quote::quote! {
            mod cond_hoisted {
                #[nocturne(ledger)]
                pub struct State { a: Cell<Uint<64>>, b: Cell<Uint<64>> }
                #[nocturne(witnesses)]
                pub struct W { c: Boolean, x: Uint<64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self {
                            a: Cell::new(Uint::<64>::from(0u64)),
                            b: Cell::new(Uint::<64>::from(0u64)),
                        }
                    }
                    #[nocturne(circuit)]
                    pub fn pick(&mut self, witnesses: &W) {
                        let x = witnesses.x;
                        if witnesses.c.value() {
                            self.a.set(x);
                        } else {
                            self.b.set(x);
                        }
                    }
                }
            }
        });
        // The hoisted read allocates exactly ONE PrivateInput for `x`
        // (+1 for the condition Boolean), reused by both branches.
        let (_, ir) = &circuits[0];
        let private_inputs = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::PrivateInput { .. }))
            .count();
        assert_eq!(private_inputs, 2, "x (hoisted, shared) + c (condition)");
    }

    /// The condition-read shape stays allowed: the read happens before
    /// the branch guard activates (unguarded, cached) and the branch
    /// body reuses the cached wire.
    #[test]
    fn condition_read_reused_in_body_is_allowed() {
        let circuits = compile_circuits(quote::quote! {
            mod cond_self {
                #[nocturne(ledger)]
                pub struct State { flag: Cell<Boolean> }
                #[nocturne(witnesses)]
                pub struct W { flag: Boolean }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { flag: Cell::new(Boolean::from(false)) } }
                    #[nocturne(circuit)]
                    pub fn maybe_store(&mut self, witnesses: &W) {
                        if witnesses.flag.value() {
                            self.flag.set(witnesses.flag);
                        }
                    }
                }
            }
        });
        let (_, ir) = &circuits[0];
        let private_inputs = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::PrivateInput { .. }))
            .count();
        assert_eq!(
            private_inputs, 1,
            "condition read is cached and reused in the body"
        );
    }

    // -------------------------------------------------------------------
    // Task 2.8: small emitter guards.
    // -------------------------------------------------------------------

    #[test]
    fn array_index_out_of_bounds_errors() {
        let errors = emit_errors(quote::quote! {
            mod oob {
                #[nocturne(ledger)]
                pub struct State { cell: Cell<Uint<64>> }
                #[nocturne(witnesses)]
                pub struct W { arr: [Uint<64>; 4] }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { cell: Cell::new(Uint::<64>::from(0u64)) } }
                    #[nocturne(circuit)]
                    pub fn read(&mut self, witnesses: &W) {
                        let _v = witnesses.arr[7];
                    }
                }
            }
        });
        assert!(
            errors.iter().any(|e| e.contains("out of bounds")),
            "constant index past the array length must error, got: {errors:?}"
        );
    }

    #[test]
    fn multi_fr_public_param_errors() {
        let errors = emit_errors(quote::quote! {
            mod wide_param {
                #[nocturne(ledger)]
                pub struct State { x: Counter }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { x: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn take(&mut self, data: Bytes<64>) {
                        self.x.increment();
                    }
                }
            }
        });
        assert!(
            errors.iter().any(|e| e.contains("multi-Fr")),
            "Bytes<64> public param (2 Frs) must be rejected, got: {errors:?}"
        );
    }

    #[test]
    fn repeated_witness_in_array_literal_errors() {
        let errors = emit_errors(quote::quote! {
            mod repeat_lit {
                #[nocturne(ledger)]
                pub struct State { pair: Cell<[Uint<64>; 2]> }
                #[nocturne(witnesses)]
                pub struct W { a: Uint<64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { pair: Cell::new([Uint::<64>::from(0u64), Uint::<64>::from(0u64)]) }
                    }
                    #[nocturne(circuit)]
                    pub fn store(&mut self, witnesses: &W) {
                        self.pair.set([witnesses.a, witnesses.a]);
                    }
                }
            }
        });
        assert!(
            errors.iter().any(|e| e.contains("contiguous")),
            "repeating the same witness element in one literal must error, got: {errors:?}"
        );
    }

    // -------------------------------------------------------------------
    // Task 2.9: structural invariants over the emitted instruction
    // stream. Applied to representative circuit shapes; would have
    // caught the disclose-PI (H3) and multi-Fr-read (H4) bugs.
    // -------------------------------------------------------------------

    /// Check the per-circuit structural invariants:
    /// (a) #DeclarePubInput == Σ PiSkip.count — every declared PI
    ///     belongs to exactly one transcript-op group;
    /// (b) inside a conditional declare group (PiSkip guard != the
    ///     top-level guard wire), every PublicInput carries the group's
    ///     guard and every DeclarePubInput value is produced by a
    ///     CondSelect (the inactive-path zeroing mux);
    /// (c) EVERY `PrivateInput`/`PublicInput` emitted inside a
    ///     conditional branch carries `guard: Some(_)`, and every one
    ///     emitted outside carries `guard: None`. "Inside" comes from
    ///     `branch_spans`, the emitter's record of the instruction
    ///     ranges it emitted while a branch guard was active — the
    ///     instruction stream alone can't recover branch extents (a
    ///     branch whose condition was hoisted to a `let` and whose body
    ///     only reads a witness leaves no other trace), so the spans
    ///     are the ground truth. See
    ///     `memories/conditional-io-guards.md` for why a missing guard
    ///     desynchronizes transcript consumption.
    fn assert_structural_invariants(
        name: &str,
        ir: &IrSource,
        branch_spans: &[std::ops::Range<usize>],
    ) {
        let instrs = ir.instructions.as_ref();

        // Map wire index -> producing instruction position.
        let mut producer: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
        let mut next = ir.num_inputs;
        for (pos, instr) in instrs.iter().enumerate() {
            for k in 0..test_output_count(instr) {
                producer.insert(next + k, pos);
            }
            next += test_output_count(instr);
        }

        // The top-level guard is the LoadImm(1) emitted right after the
        // circuit params — wire index == num_inputs.
        let top_guard = ir.num_inputs;

        // (a)
        let declares = instrs
            .iter()
            .filter(|i| matches!(i, Instruction::DeclarePubInput { .. }))
            .count() as u64;
        let skip_sum: u64 = instrs
            .iter()
            .filter_map(|i| match i {
                Instruction::PiSkip { count, .. } => Some(*count as u64),
                _ => None,
            })
            .sum();
        assert_eq!(
            declares, skip_sum,
            "circuit '{name}': DeclarePubInput count must equal the sum of PiSkip counts"
        );

        // (b): walk PiSkip-delimited groups.
        let mut group: Vec<usize> = Vec::new();
        for (pos, instr) in instrs.iter().enumerate() {
            match instr {
                Instruction::PiSkip { guard, .. } => {
                    let conditional = *guard != Some(top_guard);
                    if conditional {
                        for &p in &group {
                            match &instrs[p] {
                                Instruction::DeclarePubInput { var } => {
                                    let producer_pos = producer.get(var).unwrap_or_else(|| {
                                        panic!(
                                            "circuit '{name}': DeclarePubInput references \
                                             wire {var} with no producer"
                                        )
                                    });
                                    assert!(
                                        matches!(
                                            instrs[*producer_pos],
                                            Instruction::CondSelect { .. }
                                        ),
                                        "circuit '{name}': conditional DeclarePubInput (wire \
                                         {var}) must be zeroed via CondSelect"
                                    );
                                }
                                Instruction::PublicInput { guard: g } => {
                                    assert_eq!(
                                        *g, *guard,
                                        "circuit '{name}': PublicInput inside a conditional \
                                         group must carry the group guard"
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                    group.clear();
                }
                _ => group.push(pos),
            }
        }

        // (c): every IO instruction inside a branch span must carry a
        // guard; every one outside must not. Together with the
        // emitter-recorded spans this is exact in both directions —
        // it subsumes the old "PrivateInput between two conditional
        // PiSkip groups" heuristic, which never checked the first
        // conditional group.
        for (pos, instr) in instrs.iter().enumerate() {
            let (kind, g) = match instr {
                Instruction::PrivateInput { guard } => ("PrivateInput", guard),
                Instruction::PublicInput { guard } => ("PublicInput", guard),
                _ => continue,
            };
            let in_branch = branch_spans.iter().any(|s| s.contains(&pos));
            if in_branch {
                assert!(
                    g.is_some(),
                    "circuit '{name}': {kind} at instruction {pos} was emitted inside a \
                     conditional branch but carries no guard — the zkir VM would consume \
                     a transcript entry even when the branch is inactive"
                );
            } else {
                assert!(
                    g.is_none(),
                    "circuit '{name}': {kind} at instruction {pos} was emitted outside \
                     any conditional branch but carries guard {g:?}"
                );
            }
        }
    }

    #[test]
    fn structural_invariants_hold_for_representative_circuits() {
        // Conditional map read: witness first-touched inside a branch
        // (guarded PrivateInput) + a conditional Popeq (guarded
        // PublicInput + CondSelect-zeroed declares).
        let cond_map_read = compile_circuits_with_spans(quote::quote! {
            mod cond_read {
                #[nocturne(ledger)]
                pub struct State { members: Map<Uint<64>, Boolean> }
                #[nocturne(witnesses)]
                pub struct W { flag: Boolean, user_id: Uint<64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { members: Map::empty() } }
                    #[nocturne(circuit)]
                    pub fn maybe_check(&self, witnesses: &W) {
                        if witnesses.flag.value() {
                            let _exists = self.members.contains(&witnesses.user_id);
                        }
                    }
                }
            }
        });

        // Nested conditionals: composed guards.
        let nested_if = compile_circuits_with_spans(quote::quote! {
            mod nested {
                #[nocturne(ledger)]
                pub struct State { count: Counter }
                #[nocturne(witnesses)]
                pub struct W { a: Boolean, b: Boolean }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[nocturne(circuit)]
                    pub fn tick(&mut self, witnesses: &W) {
                        if witnesses.a.value() {
                            self.count.increment();
                            if witnesses.b.value() {
                                self.count.increment();
                            }
                        } else {
                            self.count.increment();
                        }
                    }
                }
            }
        });

        // Multi-Fr Bytes<48> write + read (2 Frs per value).
        let multi_fr_bytes = compile_circuits_with_spans(quote::quote! {
            mod wide_bytes {
                #[nocturne(ledger)]
                pub struct State { digest: Cell<Bytes<48>> }
                #[nocturne(witnesses)]
                pub struct W { new_digest: Bytes<48> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { digest: Cell::new(Bytes::<48>::zeroed()) } }
                    #[nocturne(circuit)]
                    pub fn rotate(&mut self, witnesses: &W) {
                        self.digest.set(witnesses.new_digest);
                    }
                    #[nocturne(circuit)]
                    pub fn peek(&self) {
                        let _d = self.digest.get();
                    }
                }
            }
        });

        // Multi-Fr Popeq through a payload-enum Cell (the H4 shape).
        let enum_cell_read = compile_circuits_with_spans(quote::quote! {
            mod enum_cell {
                pub enum Action { Mint(Uint<64>), Burn(Uint<64>) }
                #[nocturne(ledger)]
                pub struct State { last: Cell<Action>, amount: Cell<Uint<64>> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self {
                            last: Cell::new(Action::Mint(Uint::<64>::from(0u64))),
                            amount: Cell::new(Uint::<64>::from(0u64)),
                        }
                    }
                    #[nocturne(circuit)]
                    pub fn apply(&mut self) {
                        let action = self.last.get();
                        match action {
                            Action::Mint(amount) => { self.amount.set(amount); }
                            Action::Burn(amount) => { self.amount.set(amount); }
                        }
                    }
                }
            }
        });

        // Sanity: the conditional circuits must actually record branch
        // spans, otherwise invariant (c) would pass vacuously.
        assert!(
            cond_map_read.iter().all(|(_, _, spans)| !spans.is_empty()),
            "cond_map_read must record at least one conditional branch span"
        );

        for (name, ir, spans) in cond_map_read
            .iter()
            .chain(nested_if.iter())
            .chain(multi_fr_bytes.iter())
            .chain(enum_cell_read.iter())
        {
            assert_structural_invariants(name, ir, spans);
        }
    }
}
