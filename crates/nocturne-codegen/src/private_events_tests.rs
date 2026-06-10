//! Parity tests between the canonical private-event walk
//! (`crate::private_events`) and the ZKIR emitter's actual `PrivateInput`
//! allocation. The transcript codegen derives its push positions from the
//! walk, so these tests pin the invariant that makes the two sides of the
//! private transcript agree: for every circuit, the emitter's ordered
//! `PrivateInput` sequence is exactly the walk's event sequence expanded
//! by each event's Fr width, with guard-ness matching the event's branch
//! context.

#[cfg(test)]
mod tests {
    use crate::private_events::body_private_events;
    use crate::zkir_emitter::{self, witness_fr_width};
    use midnight_zkir::Instruction;
    use nocturne_ir::parse_contract;

    /// For every circuit in `input`, assert the emitter's PrivateInput
    /// sequence == the canonical event walk expanded by Fr widths.
    fn assert_private_input_parity(input: proc_macro2::TokenStream) {
        let module: syn::ItemMod = syn::parse2(input).expect("parse module");
        let contract = parse_contract(module).expect("parse contract");

        let witness_fields: std::collections::HashMap<String, syn::Type> = contract
            .witnesses
            .as_ref()
            .map(|w| {
                w.fields
                    .iter()
                    .map(|f| (f.name.to_string(), f.ty.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let witness_methods: std::collections::HashMap<String, syn::Type> = contract
            .witnesses
            .as_ref()
            .map(|w| {
                w.methods
                    .iter()
                    .map(|m| (m.name.to_string(), m.return_type.clone()))
                    .collect()
            })
            .unwrap_or_default();

        let output = zkir_emitter::emit_contract(&contract);
        assert!(
            output.errors.is_empty(),
            "emission recorded unexpected errors: {:?}",
            output.errors
        );

        for circuit in &contract.circuits {
            let events = body_private_events(&circuit.body, &contract.user_structs);

            // Expand each event into (width, expect_guard) and flatten
            // into the expected per-PrivateInput guard-ness sequence.
            let mut expected_guards: Vec<bool> = Vec::new();
            for ev in &events {
                let ty = if ev.is_call {
                    witness_methods.get(&ev.name)
                } else {
                    witness_fields.get(&ev.name)
                }
                .unwrap_or_else(|| {
                    panic!(
                        "event `{}` (is_call={}) has no registered type",
                        ev.name, ev.is_call
                    )
                });
                let width = witness_fr_width(ty, &contract.user_structs, &contract.user_enums);
                assert!(width > 0, "witness type must occupy at least one Fr");
                expected_guards.extend(std::iter::repeat_n(ev.in_branch, width));
            }

            let emitted = output
                .circuits
                .iter()
                .find(|c| circuit.name == c.circuit_name)
                .unwrap_or_else(|| panic!("circuit `{}` not emitted", circuit.name));
            let actual_guards: Vec<bool> = emitted
                .ir_source
                .instructions
                .iter()
                .filter_map(|i| match i {
                    Instruction::PrivateInput { guard } => Some(guard.is_some()),
                    _ => None,
                })
                .collect();

            assert_eq!(
                actual_guards, expected_guards,
                "circuit `{}`: emitter PrivateInput sequence (guard-ness, in order) \
                 diverges from the canonical private-event walk; events = {:?}",
                circuit.name, events
            );
        }
    }

    /// Direct ledger-method arg: `self.cell.set(witnesses.v)` — the
    /// shape the old per-occurrence push logic missed entirely.
    #[test]
    fn direct_arg_cell_set_matches_walk() {
        assert_private_input_parity(quote::quote! {
            mod direct_arg {
                #[nocturne(ledger)]
                pub struct State { value: Cell<Uint<64>> }
                #[nocturne(witnesses)]
                pub struct W { pub v: Uint<64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { value: Cell::new(Uint::<64>::from(0u64)) } }
                    #[nocturne(circuit)]
                    pub fn store(&mut self, witnesses: &W) {
                        self.value.set(witnesses.v);
                    }
                }
            }
        });
    }

    /// Same field in the `if` condition (unguarded first touch, cached)
    /// and in the branch body (cache hit — no second PrivateInput, no
    /// second push).
    #[test]
    fn cond_then_body_reuse_matches_walk() {
        assert_private_input_parity(quote::quote! {
            mod cond_reuse {
                #[nocturne(ledger)]
                pub struct State { flag_cell: Cell<Boolean> }
                #[nocturne(witnesses)]
                pub struct W { pub flag: Boolean }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { flag_cell: Cell::new(Boolean::from(false)) } }
                    #[nocturne(circuit)]
                    pub fn maybe_store(&mut self, witnesses: &W) {
                        if witnesses.flag.value() {
                            self.flag_cell.set(witnesses.flag);
                        }
                    }
                }
            }
        });
    }

    /// Map insert with two witnesses: key event before value event,
    /// matching the emitter's left-to-right arg evaluation. The key is
    /// multi-Fr (`Bytes<32>` → 2 PrivateInputs).
    #[test]
    fn map_insert_key_value_order_matches_walk() {
        assert_private_input_parity(quote::quote! {
            mod kv_order {
                #[nocturne(ledger)]
                pub struct State { records: Map<Bytes<32>, Uint<64>> }
                #[nocturne(witnesses)]
                pub struct W { pub digest: Bytes<32>, pub amount: Uint<64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { records: Map::empty() } }
                    #[nocturne(circuit)]
                    pub fn record(&mut self, witnesses: &W) {
                        self.records.insert(witnesses.digest.clone(), witnesses.amount);
                    }
                }
            }
        });
    }

    /// Parametric witness call inside a branch: the call's PrivateInput
    /// is guarded; the condition's field read is not.
    #[test]
    fn witness_call_in_branch_matches_walk() {
        assert_private_input_parity(quote::quote! {
            mod call_in_branch {
                #[nocturne(ledger)]
                pub struct State { value: Cell<Uint<64>> }
                #[nocturne(witnesses)]
                pub struct W { pub flag: Boolean }
                impl W {
                    pub fn next_nonce(&self) -> Uint<64> { Uint::<64>::from(7u64) }
                }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self { Self { value: Cell::new(Uint::<64>::from(0u64)) } }
                    #[nocturne(circuit)]
                    pub fn maybe_roll(&mut self, witnesses: &W) {
                        if witnesses.flag.value() {
                            self.value.set(witnesses.next_nonce());
                        }
                    }
                }
            }
        });
    }

    /// Witness nested in a ledger-method arg inside an `if` condition
    /// (`if self.m.contains(&witnesses.k)`): the key's event fires
    /// before the branch guard activates.
    #[test]
    fn contains_cond_key_matches_walk() {
        assert_private_input_parity(quote::quote! {
            mod contains_cond {
                #[nocturne(ledger)]
                pub struct State { members: Map<Uint<64>, Boolean>, hits: Counter }
                #[nocturne(witnesses)]
                pub struct W { pub k: Uint<64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { members: Map::empty(), hits: Counter::zero() }
                    }
                    #[nocturne(circuit)]
                    pub fn tally(&mut self, witnesses: &W) {
                        if self.members.contains(&witnesses.k) {
                            self.hits.increment();
                        }
                    }
                }
            }
        });
    }

    /// Let-hoisted witness reused across both branches: one unguarded
    /// PrivateInput, later uses are cache hits.
    #[test]
    fn hoisted_witness_reuse_matches_walk() {
        assert_private_input_parity(quote::quote! {
            mod hoisted {
                #[nocturne(ledger)]
                pub struct State { a: Cell<Uint<64>>, b: Cell<Uint<64>> }
                #[nocturne(witnesses)]
                pub struct W { pub flag: Boolean, pub x: Uint<64> }
                impl State {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self {
                            a: Cell::new(Uint::<64>::from(0u64)),
                            b: Cell::new(Uint::<64>::from(0u64)),
                        }
                    }
                    #[nocturne(circuit)]
                    pub fn route(&mut self, witnesses: &W) {
                        let x = witnesses.x;
                        if witnesses.flag.value() {
                            self.a.set(x);
                        } else {
                            self.b.set(x);
                        }
                    }
                }
            }
        });
    }
}
