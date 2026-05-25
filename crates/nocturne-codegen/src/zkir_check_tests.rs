//! Tests that validate emitted ZKIR circuits are satisfiable by
//! constructing ProofPreimage and running IrSource::check().

#[cfg(test)]
mod tests {
    use crate::zkir_emitter;
    use nocturne_ir::parse_contract;
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
                    value: Cell<u64>,
                }
                impl State {
                    #[midnight(constructor)]
                    pub fn new() -> Self { Self { value: Cell::new(0u64) } }
                    #[midnight(circuit)]
                    pub fn read_value(&mut self) {
                        let _v = self.value.get();
                    }
                }
            }
        });
        print_zkir(&name, &ir);

        // Ledger read ops (typed Cell<u64> → 4-declare Popeq for u64 ≡ Bytes{8}):
        //   Dup{n:0}                                  → [0x30]
        //   Idx{cached:false, push_path:false, [f]}   → [0x50, 1, 1, field_idx]
        //   Popeq{cached:true, result: AlignedValue<u64>} → [0x0d, 1, 8, value]
        //
        // PublicInput reads the result Fr from public_transcript_outputs.
        let read_value = Fr::from(99u64);
        let public_transcript_inputs: Vec<Fr> = vec![
            Fr::from(0x30u64), // Dup
            Fr::from(0x50u64), // Idx opcode
            Fr::from(0x01u64), // alignment: segment_count
            Fr::from(0x01u64), // alignment: Bytes{1}
            Fr::from(0x00u64), // key: field 0
            Fr::from(0x0du64), // Popeq opcode (cached:true)
            Fr::from(0x01u64), // result alignment: segment_count
            Fr::from(0x08u64), // result alignment: Bytes{8} (u64 = 8 bytes)
            read_value,        // the read value, declared from PublicInput
        ];

        // The Popeq result value comes via PublicInput from transcript_outputs.
        let public_transcript_outputs: Vec<Fr> = vec![read_value];

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
        // 2. Ledger write (Push key + Push value + Ins) — the on-chain
        //    encoding shape produced by compactc 0.30.0 for `Cell::set(v)`.
        //
        // The PrivateInput reads from private_transcript.
        // The ledger write encodes as public_transcript_inputs.
        //
        // `stored: Cell` (no type argument) means `extract_cell_inner_type`
        // returns `None`, so the VALUE Push falls back to the legacy
        // 2-declare emission. The KEY Push uses the proper Bytes<1>
        // encoding (5 declares). This unit test only verifies the IR
        // accepts a matching ProofPreimage; full on-chain compatibility for
        // typed `Cell<T>` is exercised by `ledger_integration_test.rs`.
        let secret_value = Fr::from(777u64);

        let public_transcript_inputs: Vec<Fr> = vec![
            // Push(storage=false, Cell(Bytes<1>(0))) — KEY:
            //   [0x10, 1 (cell_disc), 1, 1 (alignment), 0 (field_idx)]
            Fr::from(0x10u64),
            Fr::from(0x01u64),
            Fr::from(0x01u64),
            Fr::from(0x01u64),
            Fr::from(0x00u64),
            // Push(storage=true) — VALUE (fallback, 2 declares for untyped Cell):
            //   [0x11, value]
            Fr::from(0x11u64),
            secret_value,
            // Ins(cached=false, n=1) = 0x91
            Fr::from(0x91u64),
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
    fn map_lookup_is_satisfiable() {
        // Verifies the IR shape for `Map<K, V>::lookup(&k) -> V`. Encoding
        // (matches compactc 0.30.0's lookup.zkir):
        //   Dup{n:0}                                                    → [0x30]
        //   Idx{cached:false, push_path:false, [Bytes<1>(field_idx)]}   → [0x50, 1, 1, field_idx]
        //   Idx{cached:false, push_path:false, [Key::Value(key)]}        → [0x50, 1, K-align, K-value]
        //   Popeq{cached:false, result: AlignedValue<V>}                 → [0x0c, 1, V-align, value]
        let (name, ir) = compile_first_circuit(quote::quote! {
            mod records {
                #[midnight(ledger)]
                pub struct State {
                    records: Map<Uint<64>, Uint<64>>,
                }
                #[midnight(witnesses)]
                pub struct W {
                    user_id: Uint<64>,
                }
                impl State {
                    #[midnight(constructor)]
                    pub fn new() -> Self { Self { records: Map::empty() } }
                    #[midnight(circuit)]
                    pub fn fetch(&self, witnesses: &W) {
                        let _v = self.records.lookup(&witnesses.user_id);
                    }
                }
            }
        });
        print_zkir(&name, &ir);

        let key_val = Fr::from(7u64);
        let stored_val = Fr::from(42u64);

        let public_transcript_inputs: Vec<Fr> = vec![
            Fr::from(0x30u64),
            // First Idx (field_idx)
            Fr::from(0x50u64),
            Fr::from(0x01u64),
            Fr::from(0x01u64),
            Fr::from(0x00u64),
            // Second Idx (key)
            Fr::from(0x50u64),
            Fr::from(0x01u64),
            Fr::from(0x08u64),
            key_val,
            // Popeq (V = u64)
            Fr::from(0x0cu64),
            Fr::from(0x01u64),
            Fr::from(0x08u64),
            stored_val,
        ];

        let preimage = ProofPreimage {
            inputs: vec![],
            private_transcript: vec![key_val],
            public_transcript_inputs,
            public_transcript_outputs: vec![stored_val],
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
                let json = serde_json::to_string_pretty(&ir).unwrap_or_default();
                panic!("Circuit '{name}' check failed: {e}\n\nZKIR:\n{json}");
            }
        }
    }

    #[test]
    fn map_remove_is_satisfiable() {
        // Verifies the IR shape for `Map<K, V>::remove(&k)`. Encoding:
        //   Idx{cached:false, push_path:true, [Bytes<1>(field_idx)]} → [0x70, 1, 1, field_idx]
        //   Push{storage:false, Cell(key)}                            → [0x10, 1, K-align, K-value]
        //   Rem{cached:false}                                          → [0x19]
        //   Ins{cached:true,  n:1}                                     → [0xa1]
        let (name, ir) = compile_first_circuit(quote::quote! {
            mod records {
                #[midnight(ledger)]
                pub struct State {
                    records: Map<Uint<64>, Uint<64>>,
                }
                #[midnight(witnesses)]
                pub struct W {
                    user_id: Uint<64>,
                }
                impl State {
                    #[midnight(constructor)]
                    pub fn new() -> Self { Self { records: Map::empty() } }
                    #[midnight(circuit)]
                    pub fn erase(&mut self, witnesses: &W) {
                        self.records.remove(&witnesses.user_id);
                    }
                }
            }
        });
        print_zkir(&name, &ir);

        let key_val = Fr::from(0xCCCCu64);

        let public_transcript_inputs: Vec<Fr> = vec![
            // Idx
            Fr::from(0x70u64),
            Fr::from(0x01u64),
            Fr::from(0x01u64),
            Fr::from(0x00u64),
            // Push key
            Fr::from(0x10u64),
            Fr::from(0x01u64),
            Fr::from(0x01u64),
            Fr::from(0x08u64),
            key_val,
            // Rem
            Fr::from(0x19u64),
            // Ins (restore parent)
            Fr::from(0xa1u64),
        ];

        let preimage = ProofPreimage {
            inputs: vec![],
            private_transcript: vec![key_val],
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
                let json = serde_json::to_string_pretty(&ir).unwrap_or_default();
                panic!("Circuit '{name}' check failed: {e}\n\nZKIR:\n{json}");
            }
        }
    }

    #[test]
    fn map_insert_is_satisfiable() {
        // Verifies the IR shape for `Map<K, V>::insert(k, v)`.
        // On-chain encoding (matches compactc 0.30.0):
        //   Idx{cached:false, push_path:true, [Bytes<1>(field_idx)]}  → [0x70, 1, 1, field_idx]
        //   Push{storage:false, Cell(key)}                             → [0x10, 1, K-align, K-value]
        //   Push{storage:true,  Cell(value)}                           → [0x11, 1, V-align, V-value]
        //   Ins{cached:false, n:1}                                      → [0x91]
        //   Ins{cached:true,  n:1}                                      → [0xa1]
        let (name, ir) = compile_first_circuit(quote::quote! {
            mod records {
                #[midnight(ledger)]
                pub struct State {
                    records: Map<Uint<64>, Uint<64>>,
                }
                #[midnight(witnesses)]
                pub struct W {
                    user_id: Uint<64>,
                    amount: Uint<64>,
                }
                impl State {
                    #[midnight(constructor)]
                    pub fn new() -> Self { Self { records: Map::empty() } }
                    #[midnight(circuit)]
                    pub fn record(&mut self, witnesses: &W) {
                        self.records.insert(witnesses.user_id, witnesses.amount);
                    }
                }
            }
        });
        print_zkir(&name, &ir);

        let key_val = Fr::from(0xAAAAu64);
        let amt_val = Fr::from(0xBBBBu64);

        let public_transcript_inputs: Vec<Fr> = vec![
            // Idx{cached:false, push_path:true, [Bytes<1>(0)]}
            Fr::from(0x70u64),
            Fr::from(0x01u64), // alignment segment_count
            Fr::from(0x01u64), // alignment Bytes{1} atom
            Fr::from(0x00u64), // field_idx
            // Push{storage:false, Cell(Uint<64>)} — KEY
            Fr::from(0x10u64),
            Fr::from(0x01u64), // Cell discriminant
            Fr::from(0x01u64), // alignment segment_count
            Fr::from(0x08u64), // alignment Bytes{8} atom
            key_val,
            // Push{storage:true,  Cell(Uint<64>)} — VALUE
            Fr::from(0x11u64),
            Fr::from(0x01u64),
            Fr::from(0x01u64),
            Fr::from(0x08u64),
            amt_val,
            // Ins{cached:false, n:1} → 0x91
            Fr::from(0x91u64),
            // Ins{cached:true,  n:1} → 0xa1
            Fr::from(0xa1u64),
        ];

        let preimage = ProofPreimage {
            inputs: vec![],
            private_transcript: vec![key_val, amt_val],
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
                let json = serde_json::to_string_pretty(&ir).unwrap_or_default();
                panic!("Circuit '{name}' check failed: {e}\n\nZKIR:\n{json}");
            }
        }
    }

    #[test]
    fn map_contains_is_satisfiable() {
        // Verifies the IR shape for `Map<K, V>::contains(k) -> bool`.
        // Encoding (matches compactc 0.30.0 emission for member):
        //   Dup{n:0}                                 → [0x30]
        //   Idx{cached:false, push_path:false, [f]}  → [0x50, 1, 1, field_idx]
        //   Push{storage:false, Cell(key)}           → [0x10, 1, 1, key_align_atom, key_val]
        //   Member                                    → [0x18]
        //   Popeq{cached:true, result: bool}         → [0x0d, 1, 1, bool]
        //
        // With Map<u64, bool> and a witness key of type Uint<64>, the key
        // alignment atom is 8 (Bytes{8}) and the value/result fit in a
        // single Fr each.
        let (name, ir) = compile_first_circuit(quote::quote! {
            mod membership {
                #[midnight(ledger)]
                pub struct State {
                    members: Map<u64, bool>,
                }
                #[midnight(witnesses)]
                pub struct W {
                    user_id: Uint<64>,
                }
                impl State {
                    #[midnight(constructor)]
                    pub fn new() -> Self { Self { members: Map::empty() } }
                    #[midnight(circuit)]
                    pub fn check_member(&mut self, witnesses: &W) {
                        let _exists = self.members.contains(&witnesses.user_id);
                    }
                }
            }
        });
        print_zkir(&name, &ir);

        let user_id_val = Fr::from(12345u64);
        let bool_result = Fr::from(true); // claim: present

        let public_transcript_inputs: Vec<Fr> = vec![
            // Dup{n:0}
            Fr::from(0x30u64),
            // Idx{cached:false, push_path:false, [Bytes<1>(field=0)]}
            Fr::from(0x50u64),
            Fr::from(0x01u64), // alignment segment_count
            Fr::from(0x01u64), // alignment Bytes{1} atom
            Fr::from(0x00u64), // field_idx
            // Push{storage:false, Cell(AlignedValue<Uint<64>>)} — KEY
            Fr::from(0x10u64),
            Fr::from(0x01u64), // Cell discriminant
            Fr::from(0x01u64), // alignment segment_count
            Fr::from(0x08u64), // alignment Bytes{8} atom
            user_id_val,
            // Member
            Fr::from(0x18u64),
            // Popeq{cached:true, result: AlignedValue<bool>}
            Fr::from(0x0du64),
            Fr::from(0x01u64), // alignment segment_count
            Fr::from(0x01u64), // alignment Bytes{1} atom
            bool_result,
        ];

        let preimage = ProofPreimage {
            inputs: vec![],
            private_transcript: vec![user_id_val],
            public_transcript_inputs,
            public_transcript_outputs: vec![bool_result],
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
                let json = serde_json::to_string_pretty(&ir).unwrap_or_default();
                panic!("Circuit '{name}' check failed: {e}\n\nZKIR:\n{json}");
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
