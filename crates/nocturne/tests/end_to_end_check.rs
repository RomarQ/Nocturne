//! End-to-end test: build transcript ops → compute field repr →
//! match against ZKIR → verify with IrSource::check().
//!
//! This proves the complete pipeline: Rust contract → ZKIR + transcript → satisfiable proof.

use nocturne::runtime::transient_crypto::curve::Fr;
use nocturne::runtime::transient_crypto::hash::transient_commit;
use nocturne::runtime::transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use nocturne::runtime::transient_crypto::repr::FieldRepr;
use nocturne::types::*;

#[nocturne::contract]
mod counter {
    use super::*;

    #[nocturne(ledger)]
    pub struct CounterState {
        count: Counter,
    }

    impl CounterState {
        #[nocturne(constructor)]
        pub fn new() -> Self {
            Self {
                count: Counter::zero(),
            }
        }

        #[nocturne(circuit)]
        pub fn increment(&mut self) {
            self.count.increment();
        }
    }
}

#[nocturne::test]
fn end_to_end_counter_increment() {
    // Step 1: Build transcript ops using generated transcript builder.
    let transcript = counter::transcript::build_increment_transcript();
    assert_eq!(transcript.ops.len(), 3, "expected Idx + Addi + Ins");

    // Step 2: Compute the field representation of the transcript ops.
    // This is what gets submitted on-chain and must match the ZKIR's
    // declared public inputs.
    let mut public_transcript_inputs: Vec<Fr> = Vec::new();
    for op in &transcript.ops {
        op.field_repr(&mut public_transcript_inputs);
    }

    println!(
        "Transcript ops field repr ({} fields):",
        public_transcript_inputs.len()
    );
    for (i, fr) in public_transcript_inputs.iter().enumerate() {
        println!("  [{i}]: {fr:?}");
    }

    // Step 3: Build ProofPreimage with matching public inputs.
    // The ZKIR is compiled at macro time; we reconstruct it here to test.
    // In a real system, the ZKIR would be loaded from the .zkir file.
    let ir = {
        use nocturne_codegen::zkir_emitter;
        let module: syn::ItemMod = syn::parse_quote! {
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
        };
        let contract = nocturne_ir::parse_contract(module).expect("parse");
        let output = zkir_emitter::emit_contract(&contract);
        output.circuits.into_iter().next().unwrap().ir_source
    };

    let preimage = ProofPreimage {
        inputs: vec![],
        private_transcript: transcript.private_transcript,
        public_transcript_inputs,
        public_transcript_outputs: vec![],
        binding_input: Fr::from(42u64),
        communications_commitment: if ir.do_communications_commitment {
            let opening = Fr::from(0u64);
            Some((transient_commit::<[Fr]>(&[], opening), opening))
        } else {
            None
        },
        key_location: KeyLocation(std::borrow::Cow::Borrowed("test")),
    };

    // Step 4: Verify the circuit is satisfiable.
    match ir.check(&preimage) {
        Ok(pi_skips) => {
            println!("✓ End-to-end check passed! pi_skips: {pi_skips:?}");
        }
        Err(e) => {
            panic!("End-to-end check failed: {e}");
        }
    }
}
