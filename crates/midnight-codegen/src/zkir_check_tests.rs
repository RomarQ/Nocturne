//! Tests that validate emitted ZKIR circuits are satisfiable by
//! constructing ProofPreimage and running IrSource::check().

#[cfg(test)]
mod tests {
    use crate::zkir_emitter;
    use midnight_ir::parse_contract;
    use midnight_transient_crypto::curve::Fr;
    use midnight_transient_crypto::hash::transient_commit;
    use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};

    /// Compute a valid (commitment, opening) pair over `inputs ++ outputs`.
    /// Mirrors the check in `ir_vm.rs::preprocess` so check() accepts it.
    fn comm_for(inputs: &[Fr], outputs: &[Fr]) -> (Fr, Fr) {
        let opening = Fr::from(0u64);
        let mut preimage = inputs.to_vec();
        preimage.extend_from_slice(outputs);
        (transient_commit::<[Fr]>(&preimage, opening), opening)
    }

    #[allow(dead_code)] // kept as a reusable helper for future check-based tests
    fn compile_and_check(input: proc_macro2::TokenStream) {
        let module: syn::ItemMod = syn::parse2(input).expect("parse module");
        let contract = parse_contract(module).expect("parse contract");
        let output = zkir_emitter::emit_contract(&contract);

        for circuit in &output.circuits {
            let ir = &circuit.ir_source;
            println!(
                "Checking circuit '{}': num_inputs={}, instructions={}",
                circuit.circuit_name,
                ir.num_inputs,
                ir.instructions.len()
            );

            // Build a ProofPreimage.
            let preimage = ProofPreimage {
                inputs: vec![Fr::from(0u64); ir.num_inputs as usize],
                private_transcript: vec![],
                public_transcript_inputs: vec![],
                public_transcript_outputs: vec![],
                binding_input: Fr::from(42u64),
                communications_commitment: if ir.do_communications_commitment {
                    Some(comm_for(&vec![Fr::from(0u64); ir.num_inputs as usize], &[]))
                } else {
                    None
                },
                key_location: KeyLocation(std::borrow::Cow::Borrowed("test")),
            };

            match ir.check(&preimage) {
                Ok(pi_skips) => {
                    println!(
                        "  ✓ Circuit '{}' is satisfiable (pi_skips: {:?})",
                        circuit.circuit_name, pi_skips
                    );
                }
                Err(e) => {
                    // Print the ZKIR for debugging.
                    let json = serde_json::to_string_pretty(ir).unwrap_or_default();
                    panic!(
                        "Circuit '{}' failed check: {}\n\nZKIR:\n{}",
                        circuit.circuit_name, e, json
                    );
                }
            }
        }
    }

    fn compile_first_circuit(input: proc_macro2::TokenStream) -> (String, midnight_zkir::IrSource) {
        let module: syn::ItemMod = syn::parse2(input).expect("parse");
        let contract = parse_contract(module).expect("contract");
        let output = zkir_emitter::emit_contract(&contract);
        let c = &output.circuits[0];
        (c.circuit_name.clone(), c.ir_source.clone())
    }

    fn print_zkir(name: &str, ir: &midnight_zkir::IrSource) {
        let json = serde_json::to_string_pretty(ir).unwrap();
        println!("=== {name} ZKIR ===\n{json}\n");
    }

    #[test]
    fn counter_increment_is_satisfiable() {
        let module: syn::ItemMod = syn::parse2(quote::quote! {
            mod counter {
                #[midnight(ledger)]
                pub struct CounterState {
                    count: Counter,
                }
                impl CounterState {
                    #[midnight(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[midnight(circuit)]
                    pub fn increment(&mut self) { self.count.increment(); }
                }
            }
        })
        .expect("parse");
        let contract = parse_contract(module).expect("contract");
        let output = zkir_emitter::emit_contract(&contract);
        let circuit = &output.circuits[0];
        let ir = &circuit.ir_source;

        // The public_transcript_inputs must contain the field repr of
        // the transcript VM ops, matching our declare_pub_input values.
        //
        // Counter.increment ops:
        //   Idx(push_path=true, field=0): [0x70, alignment(1,1), key(0)] = 4 fields
        //   Addi(1): [0x0e, 0x01] = 2 fields
        //   Ins(cached=true, n=1): [0xa1] = 1 field
        let public_transcript_inputs: Vec<Fr> = vec![
            Fr::from(0x70u64), // Idx opcode
            Fr::from(0x01u64), // alignment: segment_count = 1
            Fr::from(0x01u64), // alignment: Bytes{1} = 1
            Fr::from(0x00u64), // key: field index = 0
            Fr::from(0x0eu64), // Addi opcode
            Fr::from(0x01u64), // Addi immediate = 1
            Fr::from(0xa1u64), // Ins opcode
        ];

        let preimage = ProofPreimage {
            inputs: vec![],
            private_transcript: vec![],
            public_transcript_inputs,
            public_transcript_outputs: vec![],
            binding_input: Fr::from(42u64),
            communications_commitment: if ir.do_communications_commitment {
                Some(comm_for(&[], &[]))
            } else {
                None
            },
            key_location: KeyLocation(std::borrow::Cow::Borrowed("test")),
        };

        match ir.check(&preimage) {
            Ok(pi_skips) => {
                println!(
                    "✓ Circuit '{}' satisfiable! pi_skips: {:?}",
                    circuit.circuit_name, pi_skips
                );
            }
            Err(e) => {
                let json = serde_json::to_string_pretty(ir).unwrap_or_default();
                panic!(
                    "Circuit '{}' check failed: {}\n\nZKIR:\n{}",
                    circuit.circuit_name, e, json
                );
            }
        }
    }

    #[test]
    fn ledger_read_is_satisfiable() {
        let (name, ir) = compile_first_circuit(quote::quote! {
            mod reader {
                #[midnight(ledger)]
                pub struct State {
                    value: Cell,
                }
                impl State {
                    #[midnight(constructor)]
                    pub fn new() -> Self { Self { value: Cell::new(0) } }
                    #[midnight(circuit)]
                    pub fn read_value(&mut self) {
                        let _v = self.value.get();
                    }
                }
            }
        });
        print_zkir(&name, &ir);

        // Ledger read ops: Dup(0x30) + Idx(0x50, key) + Popeq(0x0c)
        // The PublicInput instruction reads from public_transcript_outputs.
        //
        // public_transcript_inputs = field repr of the VM ops:
        //   Dup: [0x30] = 1 field
        //   Idx(push_path=false, field=0): [0x50, align(1,1), key(0)] = 4 fields
        //   Popeq: [0x0c] = 1 field (result comes via PublicInput separately)
        let public_transcript_inputs: Vec<Fr> = vec![
            Fr::from(0x30u64), // Dup
            Fr::from(0x50u64), // Idx opcode
            Fr::from(0x01u64), // alignment: segment_count
            Fr::from(0x01u64), // alignment: Bytes{1}
            Fr::from(0x00u64), // key: field 0
            Fr::from(0x0cu64), // Popeq opcode
        ];

        // The Popeq result value comes via PublicInput from transcript_outputs.
        let public_transcript_outputs: Vec<Fr> = vec![
            Fr::from(99u64), // the value read from ledger (arbitrary test value)
        ];

        let preimage = ProofPreimage {
            inputs: vec![],
            private_transcript: vec![],
            public_transcript_inputs,
            public_transcript_outputs,
            binding_input: Fr::from(42u64),
            communications_commitment: if ir.do_communications_commitment {
                Some(comm_for(&[], &[]))
            } else {
                None
            },
            key_location: KeyLocation(std::borrow::Cow::Borrowed("test")),
        };

        match ir.check(&preimage) {
            Ok(pi_skips) => {
                println!("✓ Circuit '{name}' satisfiable! pi_skips: {pi_skips:?}");
            }
            Err(e) => {
                panic!("Circuit '{name}' check failed: {e}");
            }
        }
    }

    #[test]
    fn witness_circuit_is_satisfiable() {
        let (name, ir) = compile_first_circuit(quote::quote! {
            mod secret {
                #[midnight(ledger)]
                pub struct State {
                    stored: Cell,
                }
                #[midnight(witnesses)]
                pub struct W {
                    secret: Field,
                }
                impl State {
                    #[midnight(constructor)]
                    pub fn new() -> Self { Self { stored: Cell::new(0) } }
                    #[midnight(circuit)]
                    pub fn store_secret(&mut self, witnesses: &W) {
                        let s = witnesses.secret;
                        self.stored.set(s);
                    }
                }
            }
        });
        print_zkir(&name, &ir);

        // This circuit:
        // 1. PrivateInput for witness.secret
        // 2. Ledger write (Idx + Push + Ins)
        //
        // The PrivateInput reads from private_transcript.
        // The ledger write encodes as public_transcript_inputs.

        // Count declare_pub_input entries from the ZKIR to build matching inputs.
        // Let binding produces a PrivateInput.
        // Then set produces: Idx(0x70, key) + Push(0x10, val) + Ins(0xa1)
        let secret_value = Fr::from(777u64);

        let public_transcript_inputs: Vec<Fr> = vec![
            // Idx(push_path=true, field=0): [0x70, 1, 1, 0]
            Fr::from(0x70u64),
            Fr::from(0x01u64),
            Fr::from(0x01u64),
            Fr::from(0x00u64),
            // Push(storage=false): [0x10, value]
            Fr::from(0x10u64),
            secret_value, // the witness value being written
            // Ins(cached=true, n=1): [0xa1]
            Fr::from(0xa1u64),
        ];

        let preimage = ProofPreimage {
            inputs: vec![],
            private_transcript: vec![secret_value],
            public_transcript_inputs,
            public_transcript_outputs: vec![],
            binding_input: Fr::from(42u64),
            communications_commitment: if ir.do_communications_commitment {
                Some(comm_for(&[], &[]))
            } else {
                None
            },
            key_location: KeyLocation(std::borrow::Cow::Borrowed("test")),
        };

        match ir.check(&preimage) {
            Ok(pi_skips) => {
                println!("✓ Circuit '{name}' satisfiable! pi_skips: {pi_skips:?}");
            }
            Err(e) => {
                panic!("Circuit '{name}' check failed: {e}");
            }
        }
    }

    #[test]
    fn voting_cast_vote_is_satisfiable() {
        let module: syn::ItemMod = syn::parse2(quote::quote! {
            mod ballot {
                #[midnight(ledger)]
                pub struct Ballot {
                    votes_for: Counter,
                    votes_against: Counter,
                }
                #[midnight(witnesses)]
                pub struct W {
                    choice: Boolean,
                }
                impl Ballot {
                    #[midnight(constructor)]
                    pub fn new() -> Self {
                        Self { votes_for: Counter::zero(), votes_against: Counter::zero() }
                    }
                    #[midnight(circuit)]
                    pub fn cast_vote(&mut self, witnesses: &W) {
                        if witnesses.choice.into() {
                            self.votes_for.increment();
                        } else {
                            self.votes_against.increment();
                        }
                    }
                }
            }
        })
        .expect("parse");
        let contract = parse_contract(module).expect("contract");
        let output = zkir_emitter::emit_contract(&contract);
        let circuit = &output.circuits[0];
        let ir = &circuit.ir_source;
        print_zkir(&circuit.circuit_name, ir);

        // This circuit:
        // 1. PrivateInput for witness.choice
        // 2. if/else: both branches emit counter increment ops
        //    - votes_for.increment() → Idx(0x70, field=0) + Addi(1) + Ins
        //    - votes_against.increment() → Idx(0x70, field=1) + Addi(1) + Ins
        //
        // Since both branches execute in ZK, all ops are declared.
        // The private_transcript provides the choice boolean.
        let choice = Fr::from(true); // voting "yes"

        // With guards, only the active branch's ops are consumed from
        // public_transcript_inputs. When choice=true, only the then-branch
        // (votes_for.increment) is active. The else-branch ops are skipped
        // by pi_skip with guard=!cond (false).
        let public_transcript_inputs: Vec<Fr> = vec![
            // votes_for increment (active: guard=cond=true)
            Fr::from(0x70u64),
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(0u64),
            Fr::from(0x0eu64),
            Fr::from(1u64),
            Fr::from(0xa1u64),
            // votes_against increment: SKIPPED (guard=!cond=false)
        ];

        let preimage = ProofPreimage {
            inputs: vec![],
            private_transcript: vec![choice],
            public_transcript_inputs,
            public_transcript_outputs: vec![],
            binding_input: Fr::from(42u64),
            communications_commitment: if ir.do_communications_commitment {
                Some(comm_for(&[], &[]))
            } else {
                None
            },
            key_location: KeyLocation(std::borrow::Cow::Borrowed("test")),
        };

        match ir.check(&preimage) {
            Ok(pi_skips) => {
                println!(
                    "✓ Circuit '{}' satisfiable! pi_skips: {:?}",
                    circuit.circuit_name, pi_skips
                );
            }
            Err(e) => {
                let json = serde_json::to_string_pretty(ir).unwrap_or_default();
                panic!(
                    "Circuit '{}' check failed: {}\n\nZKIR:\n{}",
                    circuit.circuit_name, e, json
                );
            }
        }
    }

    #[test]
    fn circuit_with_public_arg_has_num_inputs() {
        let (name, ir) = compile_first_circuit(quote::quote! {
            mod setter {
                #[midnight(ledger)]
                pub struct State {
                    value: Counter,
                }
                impl State {
                    #[midnight(constructor)]
                    pub fn new() -> Self { Self { value: Counter::zero() } }
                    #[midnight(circuit)]
                    pub fn set_value(&mut self, amount: u64) {
                        // Use the amount argument (placeholder logic)
                        self.value.increment();
                    }
                }
            }
        });

        assert_eq!(
            ir.num_inputs, 1,
            "circuit with 1 public arg should have num_inputs=1"
        );
        println!("✓ Circuit '{name}' has num_inputs={}", ir.num_inputs);

        // The argument is at memory index 0, guard at index 1.
        // Public transcript inputs encode the counter increment ops.
        let public_transcript_inputs: Vec<Fr> = vec![
            Fr::from(0x70u64),
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(0u64),
            Fr::from(0x0eu64),
            Fr::from(1u64),
            Fr::from(0xa1u64),
        ];

        let preimage = ProofPreimage {
            inputs: vec![Fr::from(42u64)], // the public argument value
            private_transcript: vec![],
            public_transcript_inputs,
            public_transcript_outputs: vec![],
            binding_input: Fr::from(1u64),
            communications_commitment: if ir.do_communications_commitment {
                Some(comm_for(&[Fr::from(42u64)], &[]))
            } else {
                None
            },
            key_location: KeyLocation(std::borrow::Cow::Borrowed("test")),
        };

        match ir.check(&preimage) {
            Ok(pi_skips) => {
                println!("✓ Circuit '{name}' with arg satisfiable! pi_skips: {pi_skips:?}");
            }
            Err(e) => panic!("Circuit '{name}' check failed: {e}"),
        }
    }

    #[test]
    fn circuit_with_return_value_has_output() {
        let (name, ir) = compile_first_circuit(quote::quote! {
            mod reader {
                #[midnight(ledger)]
                pub struct State {
                    count: Counter,
                }
                impl State {
                    #[midnight(constructor)]
                    pub fn new() -> Self { Self { count: Counter::zero() } }
                    #[midnight(circuit)]
                    pub fn get_count(&self) -> u64 {
                        self.count.value()
                    }
                }
            }
        });

        assert!(
            ir.do_communications_commitment,
            "circuit with return value should have do_communications_commitment=true"
        );

        let has_output = ir
            .instructions
            .iter()
            .any(|i| matches!(i, midnight_zkir::Instruction::Output { .. }));
        assert!(
            has_output,
            "circuit with return value should have Output instruction"
        );

        println!("✓ Circuit '{name}' has output + communications commitment");
    }

    #[test]
    fn typed_params_emit_constraints() {
        let (name, ir) = compile_first_circuit(quote::quote! {
            mod typed {
                #[midnight(ledger)]
                pub struct State { x: Counter }
                impl State {
                    #[midnight(constructor)]
                    pub fn new() -> Self { Self { x: Counter::zero() } }
                    #[midnight(circuit)]
                    pub fn with_u64(&mut self, amount: u64) {
                        self.x.increment();
                    }
                }
            }
        });

        assert_eq!(ir.num_inputs, 1);

        let has_constrain_bits = ir.instructions.iter().any(|i| {
            matches!(
                i,
                midnight_zkir::Instruction::ConstrainBits { bits: 64, .. }
            )
        });
        assert!(
            has_constrain_bits,
            "u64 param should emit ConstrainBits(64)"
        );
        println!("✓ Circuit '{name}': u64 param has ConstrainBits(64)");
    }

    #[test]
    fn boolean_witness_constrained() {
        let (name, ir) = compile_first_circuit(quote::quote! {
            mod boolw {
                #[midnight(ledger)]
                pub struct State { x: Counter }
                #[midnight(witnesses)]
                pub struct W { flag: Boolean }
                impl State {
                    #[midnight(constructor)]
                    pub fn new() -> Self { Self { x: Counter::zero() } }
                    #[midnight(circuit)]
                    pub fn check(&mut self, witnesses: &W) {
                        let _f = witnesses.flag;
                    }
                }
            }
        });

        let has_constrain_bool = ir
            .instructions
            .iter()
            .any(|i| matches!(i, midnight_zkir::Instruction::ConstrainToBoolean { .. }));
        assert!(
            has_constrain_bool,
            "Boolean witness should emit ConstrainToBoolean"
        );
        println!("✓ Circuit '{name}': Boolean witness has ConstrainToBoolean");
    }

    #[test]
    fn assert_eq_circuit_is_satisfiable() {
        let (name, ir) = compile_first_circuit(quote::quote! {
            mod asserting {
                #[midnight(ledger)]
                pub struct State {
                    x: Counter,
                }
                impl State {
                    #[midnight(constructor)]
                    pub fn new() -> Self { Self { x: Counter::zero() } }
                    #[midnight(circuit)]
                    pub fn check_eq(&mut self) {
                        let a = 42;
                        let b = 42;
                        assert_eq!(a, b);
                    }
                }
            }
        });
        print_zkir(&name, &ir);

        // This circuit:
        // 1. LoadImm(42) → a
        // 2. LoadImm(42) → b
        // 3. ConstrainEq(a, b)
        // No declare_pub_input (no ledger ops), no private inputs.
        let preimage = ProofPreimage {
            inputs: vec![],
            private_transcript: vec![],
            public_transcript_inputs: vec![],
            public_transcript_outputs: vec![],
            binding_input: Fr::from(42u64),
            communications_commitment: if ir.do_communications_commitment {
                Some(comm_for(&[], &[]))
            } else {
                None
            },
            key_location: KeyLocation(std::borrow::Cow::Borrowed("test")),
        };

        match ir.check(&preimage) {
            Ok(pi_skips) => {
                println!("✓ Circuit '{name}' satisfiable! pi_skips: {pi_skips:?}");
            }
            Err(e) => {
                panic!("Circuit '{name}' check failed: {e}");
            }
        }
    }
}
