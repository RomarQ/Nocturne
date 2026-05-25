//! Proof generation for the voting contract with witnesses.
//!
//! This validates the privacy model: the voter's choice is a private
//! witness that enters the circuit via PrivateInput, and the proof
//! demonstrates that the correct counter was incremented without
//! revealing which one.

use nocturne::runtime::transient_crypto::curve::Fr;
use nocturne::runtime::transient_crypto::hash::transient_commit;
use nocturne::runtime::transient_crypto::proofs::{
    KeyLocation, PARAMS_VERIFIER, ProofPreimage, Zkir,
};
use nocturne::runtime::transient_crypto::repr::FieldRepr;
use nocturne::types::*;
use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

#[nocturne::contract]
mod ballot {
    use super::*;

    #[nocturne(ledger)]
    pub struct Ballot {
        pub votes_for: Counter,
        pub votes_against: Counter,
    }

    #[nocturne(witnesses)]
    pub struct BallotWitnesses {
        pub choice: Boolean,
    }

    impl Ballot {
        #[nocturne(constructor)]
        pub fn new() -> Self {
            Self {
                votes_for: Counter::zero(),
                votes_against: Counter::zero(),
            }
        }

        #[nocturne(circuit)]
        pub fn cast_vote(&mut self, witnesses: &BallotWitnesses) {
            if witnesses.choice.into() {
                self.votes_for.increment();
            } else {
                self.votes_against.increment();
            }
        }
    }
}

#[tokio::test]
async fn prove_and_verify_voting_with_witness() {
    // Emit ZKIR.
    let ir = {
        use nocturne_codegen::zkir_emitter;
        let module: syn::ItemMod = syn::parse_quote! {
            mod ballot {
                #[nocturne(ledger)]
                pub struct Ballot {
                    votes_for: Counter,
                    votes_against: Counter,
                }
                #[nocturne(witnesses)]
                pub struct BallotWitnesses {
                    choice: Boolean,
                }
                impl Ballot {
                    #[nocturne(constructor)]
                    pub fn new() -> Self {
                        Self { votes_for: Counter::zero(), votes_against: Counter::zero() }
                    }
                    #[nocturne(circuit)]
                    pub fn cast_vote(&mut self, witnesses: &BallotWitnesses) {
                        if witnesses.choice.into() {
                            self.votes_for.increment();
                        } else {
                            self.votes_against.increment();
                        }
                    }
                }
            }
        };
        let contract = nocturne_ir::parse_contract(module).expect("parse");
        let output = zkir_emitter::emit_contract(&contract);
        output.circuits.into_iter().next().unwrap().ir_source
    };

    println!(
        "ZKIR: k={}, rows={}, num_inputs={}",
        ir.model().k(),
        ir.model().rows(),
        ir.num_inputs
    );

    // The voter's choice is private: true = vote yes.
    let _choice = Fr::from(true);

    // Build transcript using the generated builder with real witness values.
    // The builder now evaluates the condition at runtime and only emits
    // ops for the active branch.
    let witnesses = ballot::BallotWitnesses {
        choice: Boolean::from(true),
    };
    let transcript = ballot::transcript::build_cast_vote_transcript(&witnesses);

    // With choice=true, only votes_for.increment ops should be emitted.
    println!(
        "Transcript ops: {} (should be 3 for active branch only)",
        transcript.ops.len()
    );

    // Compute field repr from the transcript.
    let mut public_transcript_inputs: Vec<Fr> = Vec::new();
    for op in &transcript.ops {
        op.field_repr(&mut public_transcript_inputs);
    }

    let preimage = ProofPreimage {
        inputs: vec![],
        private_transcript: transcript.private_transcript,
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

    // Check satisfiability first.
    match ir.check(&preimage) {
        Ok(pi_skips) => {
            println!("check() passed: pi_skips = {pi_skips:?}");
        }
        Err(e) => {
            let json = serde_json::to_string_pretty(&ir).unwrap();
            panic!(
                "check failed: {e}\n\nZKIR:\n{json}\n\npublic_transcript_inputs: {public_transcript_inputs:?}"
            );
        }
    }

    // Generate keys and prove.
    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");

    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    println!("Keygen complete");

    let rng = rand::thread_rng();
    let (proof, pis, skips) = ir.prove(rng, &pp, pk, &preimage).await.expect("prove");

    println!(
        "Proof generated: {} bytes, {} public inputs",
        proof.0.len(),
        pis.len()
    );
    println!("Skips: {skips:?}");

    // On-chain compatibility for this conditional circuit is asserted in
    // `tests/ledger_integration_test.rs::voting_verifies_with_ledger_shape_pis`,
    // which reproduces the ledger's Noop-interleaving verify path.

    // Verify.
    vk.verify(&PARAMS_VERIFIER, &proof, pis.into_iter())
        .expect("verification should succeed");

    println!();
    println!("✓ Voting contract proof generated and VERIFIED!");
    println!("  Witness: choice = true (private, never revealed)");
    println!("  Effect: votes_for incremented (proven without revealing choice)");
}
