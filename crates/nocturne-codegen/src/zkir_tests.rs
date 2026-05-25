#[cfg(test)]
mod tests {
    use crate::zkir_emitter;
    use nocturne_ir::parse_contract;
    use midnight_zkir::{Instruction, IrSource};

    fn compile_circuits(input: proc_macro2::TokenStream) -> Vec<(String, IrSource)> {
        let module: syn::ItemMod = syn::parse2(input).expect("parse module");
        let contract = parse_contract(module).expect("parse contract");
        let output = zkir_emitter::emit_contract(&contract);
        output
            .circuits
            .into_iter()
            .map(|c| (c.circuit_name, c.ir_source))
            .collect()
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

    #[test]
    fn disclose_emits_declare_pub_input() {
        let circuits = compile_circuits(quote::quote! {
            mod disclosing {
                #[nocturne(ledger)]
                pub struct State {
                    threshold: Cell,
                }

                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { threshold: Cell::new(0) }
                    }

                    #[nocturne(circuit)]
                    pub fn reveal(&mut self) {
                        self.threshold.set(nocturne::disclose(42));
                    }
                }
            }
        });

        let (_, ir) = &circuits[0];
        let instrs = ir.instructions.as_ref();

        // disclose should emit DeclarePubInput + PiSkip for the disclosed value
        let declare_count = instrs
            .iter()
            .filter(|i| matches!(i, Instruction::DeclarePubInput { .. }))
            .count();
        // At least one for disclose + several for ledger write ops
        assert!(
            declare_count >= 2,
            "should have DeclarePubInput for disclose + ops"
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
}
