//! End-to-end proof generation test.
//!
//! This is the ultimate validation: write a contract in Rust → emit ZKIR →
//! generate keys → build transcript → create ProofPreimage → generate
//! actual Plonk ZK proof → verify it passes.

use midnight::runtime::transient_crypto::curve::Fr;
use midnight::runtime::transient_crypto::hash::transient_commit;
use midnight::runtime::transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight::runtime::transient_crypto::repr::FieldRepr;
use midnight::types::*;
use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

#[midnight::contract]
mod counter {
    use super::*;

    #[midnight(ledger)]
    pub struct CounterState {
        pub count: Counter,
    }

    impl CounterState {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self {
                count: Counter::zero(),
            }
        }

        #[midnight(circuit)]
        pub fn increment(&mut self) {
            self.count.increment();
        }
    }
}

#[tokio::test]
async fn generate_and_verify_proof() {
    // Step 1: Emit ZKIR from the contract.
    let ir = {
        use midnight_codegen::zkir_emitter;
        let module: syn::ItemMod = syn::parse_quote! {
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
        };
        let contract = midnight_ir::parse_contract(module).expect("parse");
        let output = zkir_emitter::emit_contract(&contract);
        output.circuits.into_iter().next().unwrap().ir_source
    };

    println!(
        "Step 1: ZKIR emitted (k={}, rows={})",
        ir.model().k(),
        ir.model().rows()
    );

    // Step 2: Build transcript ops using the generated transcript builder.
    let transcript = counter::transcript::build_increment_transcript();
    assert_eq!(transcript.ops.len(), 3);

    // Step 3: Compute public_transcript_inputs from transcript ops' field repr.
    let mut public_transcript_inputs: Vec<Fr> = Vec::new();
    for op in &transcript.ops {
        op.field_repr(&mut public_transcript_inputs);
    }
    println!(
        "Step 2: Transcript built ({} ops, {} public input fields)",
        transcript.ops.len(),
        public_transcript_inputs.len()
    );

    // Step 4: Verify circuit is satisfiable first (cheap check).
    let preimage = ProofPreimage {
        inputs: vec![],
        private_transcript: vec![],
        public_transcript_inputs: public_transcript_inputs.clone(),
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

    let pi_skips = ir.check(&preimage).expect("check should pass");
    println!("Step 3: IrSource::check() passed (pi_skips: {pi_skips:?})");

    // Step 5: Generate prover/verifier keys.
    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");

    let (pk, _vk) = ir.keygen(&pp).await.expect("keygen");
    println!("Step 4: Plonk keygen complete");

    // Step 6: Generate actual ZK proof!
    let rng = rand::thread_rng();
    let (proof, pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

    println!("Step 5: ZK proof generated!");
    println!("  Proof size: {} bytes", proof.0.len());
    println!("  Public inputs: {} fields", pis.len());
    println!("  Skips: {skips:?}");

    // Step 6b: The on-chain ledger constructs verifier inputs as
    //   [binding_input, communication_commitment, ..transcript.field_repr()]
    // (see midnight_ledger::verify::ContractCall::public_inputs). Reconstruct
    // them the same way and assert the proof's pis match. This is the
    // regression guard for the do_communications_commitment-class of bugs:
    // any divergence between the circuit's PI layout and the ledger's
    // unconditional 2-slot prefix would fail this assertion long before it
    // would reach an on-chain verifier.
    let (comm, _opening) = preimage
        .communications_commitment
        .expect("circuit must opt in to communications commitment");
    let mut expected_pis: Vec<Fr> = vec![preimage.binding_input, comm];
    expected_pis.extend(public_transcript_inputs.iter().copied());
    assert_eq!(
        pis, expected_pis,
        "prove returned PIs that don't match the ledger's public_inputs() layout; \
         verify on-chain would fail with a PI count mismatch"
    );

    // Step 7: Verify the proof!
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;

    _vk.verify(&PARAMS_VERIFIER, &proof, pis.into_iter())
        .expect("proof verification should succeed");

    println!("Step 6: Proof VERIFIED ✓");
    println!();
    println!("✓ End-to-end proof generation + verification successful!");
    println!("  Contract: counter");
    println!("  Circuit: increment");
    println!("  Pipeline: Rust → ZKIR → keygen → transcript → prove → verify ✓");
}
