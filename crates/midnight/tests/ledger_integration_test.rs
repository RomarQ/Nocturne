//! Integration test against midnight-ledger.
//!
//! Drives Nocturne-emitted circuits through the canonical ledger code path:
//! build a `ContractCallPrototype` → `ProofPreimage::construct_proof` → run
//! the resulting preimage through `IrSource::check` / `prove` / `verify`.
//!
//! This is the highest-fidelity on-chain compatibility check we can run
//! without standing up a Midnight node: if a circuit accepts a `ProofPreimage`
//! built by the same code path the on-chain `ContractCall` pipeline uses,
//! it's structurally compatible with the ledger.

use std::borrow::Cow;

use midnight::runtime::transient_crypto::curve::Fr;
use midnight::runtime::transient_crypto::hash::transient_commit;
use midnight::runtime::transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight::types::*;

use midnight_coin_structure::contract::ContractAddress;
use midnight_ledger::construct::{ContractCallExt, ContractCallPrototype};
use midnight_ledger::structure::ProofPreimageVersioned;
use midnight_ledger_storage::db::InMemoryDB;
use midnight_base_crypto::cost_model::RunningCost;
use midnight_onchain_runtime::context::Effects;
use midnight_onchain_runtime::ops::Op;
use midnight_onchain_runtime::result_mode::ResultModeVerify;
use midnight_onchain_runtime::state::{ContractOperation, EntryPointBuf};
use midnight_onchain_runtime::transcript::{Transcript, TranscriptVersion};
use midnight_ledger_storage::arena::Sp;

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
            Self { count: Counter::zero() }
        }

        #[midnight(circuit)]
        pub fn increment(&mut self) {
            self.count.increment();
        }
    }
}

#[midnight::contract]
mod ballot {
    use super::*;

    #[midnight(ledger)]
    pub struct Ballot {
        pub votes_for: Counter,
        pub votes_against: Counter,
    }

    #[midnight(witnesses)]
    pub struct BallotWitnesses {
        pub choice: Boolean,
    }

    impl Ballot {
        #[midnight(constructor)]
        pub fn new() -> Self {
            Self { votes_for: Counter::zero(), votes_against: Counter::zero() }
        }

        #[midnight(circuit)]
        pub fn cast_vote(&mut self, witnesses: &BallotWitnesses) {
            if witnesses.choice.value() {
                self.votes_for.increment();
            } else {
                self.votes_against.increment();
            }
        }
    }
}

fn build_counter_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod counter {
            #[midnight(ledger)]
            pub struct CounterState { count: Counter }
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
}

fn build_cast_vote_ir() -> midnight_zkir::IrSource {
    use midnight_codegen::zkir_emitter;
    let module: syn::ItemMod = syn::parse_quote! {
        mod ballot {
            #[midnight(ledger)]
            pub struct Ballot {
                pub votes_for: Counter,
                pub votes_against: Counter,
            }
            #[midnight(witnesses)]
            pub struct BallotWitnesses { pub choice: Boolean }
            impl Ballot {
                #[midnight(constructor)]
                pub fn new() -> Self {
                    Self { votes_for: Counter::zero(), votes_against: Counter::zero() }
                }
                #[midnight(circuit)]
                pub fn cast_vote(&mut self, witnesses: &BallotWitnesses) {
                    if witnesses.choice.value() {
                        self.votes_for.increment();
                    } else {
                        self.votes_against.increment();
                    }
                }
            }
        }
    };
    let contract = midnight_ir::parse_contract(module).expect("parse");
    let output = zkir_emitter::emit_contract(&contract);
    output
        .circuits
        .into_iter()
        .find(|c| c.circuit_name == "cast_vote")
        .unwrap()
        .ir_source
}

/// Build a canonical `ProofPreimage` for a given circuit by going through
/// `<ProofPreimage as ContractCallExt>::construct_proof` — the same code
/// path used by `Intent::add_call` when building an on-chain transaction.
fn canonical_preimage(
    ir_circuit_name: &str,
    active_ops: Vec<Op<ResultModeVerify, InMemoryDB>>,
    private_transcript_outputs: Vec<midnight::runtime::base_crypto::fab::AlignedValue>,
) -> ProofPreimage {
    let rand = Fr::from(0xdeadu64);
    let input = ().into();
    let output = ().into();

    let prototype: ContractCallPrototype<InMemoryDB> = ContractCallPrototype {
        address: ContractAddress(Default::default()),
        entry_point: EntryPointBuf(ir_circuit_name.as_bytes().into()),
        op: ContractOperation::new(None),
        guaranteed_public_transcript: Some(wrap_transcript(active_ops)),
        fallible_public_transcript: None,
        private_transcript_outputs,
        input,
        output,
        communication_commitment_rand: rand,
        key_location: KeyLocation(Cow::Owned(format!("test::{ir_circuit_name}"))),
    };

    use midnight::runtime::transient_crypto::repr::FieldRepr;
    let mut io_repr: Vec<Fr> = Vec::new();
    midnight::runtime::transient_crypto::fab::ValueReprAlignedValue(prototype.input.clone())
        .field_repr(&mut io_repr);
    midnight::runtime::transient_crypto::fab::ValueReprAlignedValue(prototype.output.clone())
        .field_repr(&mut io_repr);
    let comm_comm = transient_commit::<[Fr]>(&io_repr, rand);

    let preimage_v = <ProofPreimage as ContractCallExt<InMemoryDB>>::construct_proof(
        &prototype, comm_comm,
    );
    match preimage_v {
        ProofPreimageVersioned::V2(p) => (*p).clone(),
        _ => panic!("unexpected ProofPreimageVersioned variant"),
    }
}

/// Wrap a vector of Ops in a minimal Transcript usable as
/// `guaranteed_public_transcript`. Gas and effects are defaults — the
/// `construct_proof` path only inspects the program.
fn wrap_transcript(ops: Vec<Op<ResultModeVerify, InMemoryDB>>) -> Transcript<InMemoryDB> {
    Transcript {
        gas: RunningCost::default(),
        effects: Effects::<InMemoryDB>::default(),
        program: ops.into(),
        version: Some(Sp::new(TranscriptVersion { major: 2, minor: 3 })),
    }
}


#[tokio::test]
async fn counter_ledger_constructed_preimage_satisfies_circuit() {
    let ir = build_counter_ir();
    let nocturne_transcript = counter::transcript::build_increment_transcript();
    let preimage = canonical_preimage("increment", nocturne_transcript.ops, vec![]);
    ir.check(&preimage)
        .expect("Nocturne counter circuit must accept a ledger-constructed ProofPreimage");
}

#[tokio::test]
async fn counter_ledger_constructed_preimage_proves_and_verifies() {
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_counter_ir();
    let nocturne_transcript = counter::transcript::build_increment_transcript();
    let preimage = canonical_preimage("increment", nocturne_transcript.ops, vec![]);

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, pis, _skips) = ir
        .prove(rng, &pp, pk, &preimage)
        .await
        .expect("prove");

    vk.verify(&PARAMS_VERIFIER, &proof, pis.into_iter())
        .expect("ledger-constructed preimage must verify end-to-end");
}

/// Demonstrates the conditional-branch on-chain incompatibility through the
/// canonical ledger code path. The active-branch-only transcript is what
/// every on-chain submission carries; for a conditional circuit, prove
/// returns more PIs than would result from `[binding, comm, ..field_repr(active)]`
/// alone, because Nocturne's emitter has DeclarePubInputs for both branches.
#[tokio::test]
async fn voting_pi_count_diverges_from_active_transcript() {
    use midnight::runtime::base_crypto::fab::AlignedValue;
    use midnight::runtime::transient_crypto::proofs::PARAMS_VERIFIER;
    use midnight::runtime::transient_crypto::repr::FieldRepr;
    use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};

    let ir = build_cast_vote_ir();
    let witnesses = ballot::BallotWitnesses { choice: Boolean::from(true) };
    let nocturne_transcript = ballot::transcript::build_cast_vote_transcript(&witnesses);

    let private_outputs: Vec<AlignedValue> = vec![AlignedValue::from(true)];
    let preimage = canonical_preimage("cast_vote", nocturne_transcript.ops.clone(), private_outputs);

    let pp = MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, vec![])
        .expect("data provider");
    let (pk, vk) = ir.keygen(&pp).await.expect("keygen");
    let rng = rand::thread_rng();
    let (proof, prove_pis, skips) = ir
        .prove(rng, &pp, pk, &preimage)
        .await
        .expect("prove");

    let mut ledger_pis: Vec<Fr> = vec![
        preimage.binding_input,
        preimage
            .communications_commitment
            .expect("commitment must be set")
            .0,
    ];
    for op in &nocturne_transcript.ops {
        op.field_repr(&mut ledger_pis);
    }

    assert!(
        prove_pis.len() > ledger_pis.len(),
        "prove returned {} PIs; ledger-shape would feed {} — \
         on-chain verify will fail with PI count mismatch",
        prove_pis.len(),
        ledger_pis.len(),
    );
    let total_skipped: usize = skips.iter().filter_map(|s| *s).sum();
    assert_eq!(
        prove_pis.len(),
        ledger_pis.len() + total_skipped,
        "prove pis = ledger active pis + sum(skip counts)"
    );

    // Local verify with prove's PIs still passes — this is the gap between
    // local prove+verify success and on-chain verify failure.
    vk.verify(&PARAMS_VERIFIER, &proof, prove_pis.iter().copied())
        .expect("local verify with prove's PIs passes");
}
